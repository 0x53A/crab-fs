use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use aes::{Aes256, cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit}};
use xts_mode::Xts128;
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::entropy;
use crate::errors::MyResult;
use crate::io::fs::{Capabilities, FS, Finalize, Len, SetLen};

const BLOCK_SIZE: usize = 4096; // Use 4KB blocks for optimal performance

type Aes256Xts = Xts128<Aes256>;

// stateless en-/decryption engine
struct EncryptionEngine {
    cipher: Aes256Xts,
    key_hash: [u8; 32], // Store key hash for file headers
}

impl EncryptionEngine {
    fn new(password: &[u8]) -> Self {
        // Derive a 512-bit key (two 256-bit keys required by AES-XTS)
        let mut hasher = Sha256::new();
        hasher.update(password);
        let key1 = hasher.finalize();
        
        let mut hasher = Sha256::new();
        hasher.update(&key1);
        let key2 = hasher.finalize();
        
        // Create two separate Aes256 instances for XTS
        let cipher_1 = Aes256::new_from_slice(&key1).expect("Valid key length");
        let cipher_2 = Aes256::new_from_slice(&key2).expect("Valid key length");
        
        // Create XTS cipher from the two AES instances
        let cipher = Xts128::new(cipher_1, cipher_2);
        
        // Store key hash for file validation
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(b"fs-validation");
        let key_hash = hasher.finalize();
        
        Self {
            cipher,
            key_hash: key_hash.into(),
        }
    }
    
    // Encrypt a single block with its position as tweak value
    fn encrypt_block(&self, block_idx: u64, data: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::from(data);
        
        // Create tweak as a fixed size array from block index
        let mut tweak = [0u8; 16];
        let idx_bytes = block_idx.to_le_bytes();
        tweak[..8].copy_from_slice(&idx_bytes);
        // Rest of tweak remains zero
        
        // Encrypt in place with updated API
        self.cipher.encrypt_sector(&mut buffer, tweak);
        
        buffer
    }
    
    // Decrypt a single block with its position as tweak value
    fn decrypt_block(&self, block_idx: u64, encrypted_data: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::from(encrypted_data);
        
        // Create tweak as a fixed size array
        let mut tweak = [0u8; 16];
        let idx_bytes = block_idx.to_le_bytes();
        tweak[..8].copy_from_slice(&idx_bytes);
        // Rest of tweak remains zero
        
        // Decrypt in place with updated API
        self.cipher.decrypt_sector(&mut buffer, tweak);
        
        buffer
    }
    
    // Get key hash for validation
    fn get_key_hash(&self) -> &[u8; 32] {
        &self.key_hash
    }
}

// Encrypted file wrapper that handles on-the-fly encryption/decryption

struct EncryptedFileContent<F> {
    inner_file: F,
    block_buffer: Vec<u8>,      // Buffer for partial block operations
    current_block_idx: u64,     // Current block index (position/BLOCK_SIZE)
    buffer_position: usize,     // Position within the current block buffer
    buffer_valid: bool,         // Whether buffer contains valid data
    buffer_modified: bool,      // Whether buffer has been modified and needs writing
    file_length: u64,           // Actual file length without header
}

pub struct EncryptedFile<F> {
    engine: Arc<EncryptionEngine>,
    content: RefCell<EncryptedFileContent<F>>
}

impl<F> EncryptedFile<F> 
where 
    F: Read + Write + Seek + Len + SetLen + Finalize
{
    fn new(mut inner_file: F, engine: Arc<EncryptionEngine>) -> MyResult<Self> {
        // Check if file is new or existing
        let file_length = inner_file.len()?;
        
        // For new files, write header with key validation hash
        if file_length == 0 {
            // Write file header with key hash for validation
            inner_file.write_all(engine.get_key_hash())?;
            inner_file.flush()?;
        } else {
            // For existing files, validate key hash
            let mut header = [0u8; 32];
            inner_file.seek(SeekFrom::Start(0))?;
            inner_file.read_exact(&mut header)?;
            
            if header != *engine.get_key_hash() {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Invalid encryption key").into());
            }
        }
        
        // Position file after header
        inner_file.seek(SeekFrom::Start(32))?;

        let content = EncryptedFileContent {
            inner_file,
            block_buffer: vec![0; BLOCK_SIZE],
            current_block_idx: 0,
            buffer_position: 0,
            buffer_valid: false,
            buffer_modified: false,
            file_length: if file_length > 32 { file_length - 32 } else { 0 },
        };
        
        Ok(Self {
            engine,
            content: RefCell::new(content),
        })
    }
    
    // Load a block from the file into the buffer
    fn load_block(&self, block_idx: u64) -> io::Result<()> {
        let mut content = self.content.borrow_mut();
        
        // If the current block is modified, write it back first
        if content.buffer_modified {
            self.flush_buffer()?;
        }
        
        // Calculate file position for this block
        let file_pos = 32 + (block_idx * BLOCK_SIZE as u64);
        content.inner_file.seek(SeekFrom::Start(file_pos))?;
        
        // Read the block or partial block
        let mut bytes_read = 0;
        content.block_buffer.fill(0); // Clear buffer for partially filled blocks
        
        // Read block data (might be less than BLOCK_SIZE near EOF)
        while bytes_read < BLOCK_SIZE {
            let mut buffer = vec![];
            std::mem::swap(&mut content.block_buffer, &mut buffer);
            let inner_file = &mut content.inner_file;
            let result = inner_file.read(&mut buffer[bytes_read..]);
            std::mem::swap(&mut content.block_buffer, &mut buffer);
            match result {
                Ok(0) => break, // EOF
                Ok(n) => bytes_read += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        
        // If we read any data, decrypt it
        if bytes_read > 0 {
            let decrypted = self.engine.decrypt_block(block_idx, &content.block_buffer[..bytes_read]);
            content.block_buffer[..decrypted.len()].copy_from_slice(&decrypted);
        }
        
        // Update state
        content.current_block_idx = block_idx;
        content.buffer_valid = true;
        content.buffer_modified = false;
        
        Ok(())
    }
    
    // Flush the current buffer to disk if modified
    fn flush_buffer(&self) -> io::Result<()> {
        let mut content = self.content.borrow_mut();
        
        if !content.buffer_modified {
            return Ok(());
        }
        
        // Calculate how much of the buffer is valid data (might be less than BLOCK_SIZE)
        let valid_data_size = std::cmp::min(
            BLOCK_SIZE,
            (content.file_length - (content.current_block_idx * BLOCK_SIZE as u64)) as usize
        );
        
        let encrypted = self.engine.encrypt_block(
            content.current_block_idx, 
            &content.block_buffer[..valid_data_size]
        );
        
        // Write encrypted block back to file
        let file_pos = 32 + (content.current_block_idx * BLOCK_SIZE as u64);
        content.inner_file.seek(SeekFrom::Start(file_pos))?;
        content.inner_file.write_all(&encrypted)?;
        
        content.buffer_modified = false;
        Ok(())
    }
    
    // Get current file position
    fn position(&self) -> u64 {
        let content = self.content.borrow();
        (content.current_block_idx * BLOCK_SIZE as u64) + content.buffer_position as u64
    }
}

impl<F: Read + Write + Seek + Len + SetLen + Finalize> Read for EncryptedFile<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self as &EncryptedFile<F>).read(buf)
    }
}

impl<F: Read + Write + Seek + Len + SetLen + Finalize> Read for &EncryptedFile<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read = 0;
        
        while bytes_read < buf.len() {
            // Access content through RefCell - must drop borrow before loading block
            let load_block_needed = {
                let content = self.content.borrow();
                !content.buffer_valid || content.buffer_position >= BLOCK_SIZE
            };
            
            // If buffer is not valid for current block, load it
            if load_block_needed {
                let next_block = {
                    let content = self.content.borrow();
                    let block = content.current_block_idx;
                    if content.buffer_position >= BLOCK_SIZE {
                        block + 1
                    } else {
                        block
                    }
                };
                
                self.load_block(next_block)?;
                
                // Reset buffer position if needed
                if next_block > self.content.borrow().current_block_idx - 1 {
                    self.content.borrow_mut().buffer_position = 0;
                }
            }
            
            // Now work with the loaded buffer
            let (can_read, content_buffer_pos) = {
                let content = self.content.borrow();
                
                // Calculate how much we can read from current buffer
                let remaining_in_buffer = BLOCK_SIZE - content.buffer_position;
                let remaining_in_file = content.file_length - self.position();
                let can_read = std::cmp::min(
                    std::cmp::min(remaining_in_buffer, buf.len() - bytes_read),
                    remaining_in_file as usize
                );
                
                (can_read, content.buffer_position)
            };
            
            // If nothing left to read, we're at EOF
            if can_read == 0 {
                break;
            }
            
            // Copy data from buffer to output
            {
                let content = self.content.borrow();
                buf[bytes_read..(bytes_read + can_read)].copy_from_slice(
                    &content.block_buffer[content_buffer_pos..(content_buffer_pos + can_read)]
                );
            }
            
            // Update buffer position
            self.content.borrow_mut().buffer_position += can_read;
            bytes_read += can_read;
        }
        
        Ok(bytes_read)
    }
}

impl<F: Read + Write + Seek + Len + SetLen + Finalize> Write for EncryptedFile<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
       (&self as &EncryptedFile<F>).write(buf)
    }
    
    fn flush(&mut self) -> io::Result<()> {
        (&self as &EncryptedFile<F>).flush()
    }
}

impl<F: Read + Write + Seek + Len + SetLen + Finalize> Write for &EncryptedFile<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written = 0;
        
        while bytes_written < buf.len() {
            // Check if we need to load a block (need to drop borrow before calling load_block)
            let load_params = {
                let content = self.content.borrow();
                if !content.buffer_valid || content.buffer_position >= BLOCK_SIZE {
                    let next_block = content.current_block_idx;
                    let advanced = content.buffer_position >= BLOCK_SIZE;
                    Some((next_block, advanced))
                } else {
                    None
                }
            };
            
            // If buffer is not valid for current block, load it
            if let Some((next_block, advanced)) = load_params {
                if advanced {
                    self.load_block(next_block + 1)?;
                    self.content.borrow_mut().buffer_position = 0;
                } else {
                    self.load_block(next_block)?;
                }
            }
            
            // Calculate how much we can write and copy data
            let can_write = {
                let content = self.content.borrow();
                let remaining_in_buffer = BLOCK_SIZE - content.buffer_position;
                std::cmp::min(remaining_in_buffer, buf.len() - bytes_written)
            };
            
            // Copy data from input to buffer
            {
                let mut content = self.content.borrow_mut();
                let begin = content.buffer_position;
                let end = content.buffer_position + can_write;
                content.block_buffer[begin..end]
                    .copy_from_slice(&buf[bytes_written..(bytes_written + can_write)]);
                
                // Update pointers
                content.buffer_position += can_write;
                content.buffer_modified = true;
                
                // Update file length if necessary
                let current_position = self.position();
                if current_position > content.file_length {
                    content.file_length = current_position;
                }
            }
            
            bytes_written += can_write;
        }
        
        Ok(bytes_written)
    }
    
    fn flush(&mut self) -> io::Result<()> {
        // Write current buffer if modified
        let buffer_modified = self.content.borrow().buffer_modified;
        if buffer_modified {
            self.flush_buffer()?;
        }
        self.content.borrow_mut().inner_file.flush()
    }
}


impl<F: Read + Write + Seek + Len + SetLen + Finalize> Seek for EncryptedFile<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        (&self as &EncryptedFile<F>).seek(pos)
    }
}

impl<F: Read + Write + Seek + Len + SetLen + Finalize> Seek for &EncryptedFile<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Calculate the absolute position
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset > 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Cannot seek past end of file"));
                }
                let file_length = self.content.borrow().file_length;
                file_length.checked_add_signed(offset).unwrap_or(0)
            },
            SeekFrom::Current(offset) => {
                let current_pos = self.position();
                if offset >= 0 {
                    current_pos.checked_add(offset as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "Seek position overflow")
                    })?
                } else {
                    current_pos.checked_add_signed(offset).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "Seek before start of file")
                    })?
                }
            }
        };
        
        // If current buffer is modified, flush it
        let buffer_modified = self.content.borrow().buffer_modified;
        if buffer_modified {
            self.flush_buffer()?;
        }
        
        // Calculate new block index and position within the block
        let new_block_idx = new_pos / BLOCK_SIZE as u64;
        let new_buffer_position = (new_pos % BLOCK_SIZE as u64) as usize;
        
        // Check if we need to load a new block
        let need_new_block = {
            let content = self.content.borrow();
            !content.buffer_valid || new_block_idx != content.current_block_idx
        };
        
        // If different block, load the new block
        if need_new_block {
            self.load_block(new_block_idx)?;
        }
        
        // Update buffer position
        self.content.borrow_mut().buffer_position = new_buffer_position;
        
        Ok(new_pos)
    }
}

impl<F: Read + Write + Seek + Len + SetLen + Finalize> Len for EncryptedFile<F> {
    fn len(&mut self) -> MyResult<u64> {
        Ok(self.content.borrow().file_length)
    }
}

impl<F: Read + Write + Seek + Len + SetLen + Finalize> SetLen for EncryptedFile<F> {
    fn set_len(&mut self, size: u64) -> MyResult<()> {
        // If current buffer is modified, flush it
        let buffer_modified = self.content.borrow().buffer_modified;
        if buffer_modified {
            self.flush_buffer()?;
        }
        
        // Get current position and set length of underlying file
        {
            let mut content = self.content.borrow_mut();
            
            // Set length of underlying file (accounting for header)
            content.inner_file.set_len(size + 32)?;
            content.file_length = size;
            
            // If we're currently positioned past the new end, adjust position
            let current_position = self.position();
            if current_position > size {
                let new_block_idx = size / BLOCK_SIZE as u64;
                let new_buffer_position = (size % BLOCK_SIZE as u64) as usize;
                
                if new_block_idx != content.current_block_idx {
                    content.buffer_valid = false; // Force reload on next operation
                }
                
                content.current_block_idx = new_block_idx;
                content.buffer_position = new_buffer_position;
            }
        }
        
        Ok(())
    }
}

impl<F: Read + Write + Seek + Len + SetLen + Finalize> Finalize for EncryptedFile<F> {
    fn finalize(&mut self) -> MyResult<()> {
        // Flush any pending changes
        let buffer_modified = self.content.borrow().buffer_modified;
        if buffer_modified {
            self.flush_buffer()?;
        }
        self.content.borrow_mut().inner_file.finalize()
    }
}

// The main encrypted filesystem wrapper
#[derive(Clone)]
pub struct EncryptedFS<T: FS> {
    inner: T,
    engine: Arc<EncryptionEngine>,
}

impl<T: FS> EncryptedFS<T> {
    pub fn new(inner: T, password: &[u8]) -> Self {
        Self {
            inner,
            engine: Arc::new(EncryptionEngine::new(password)),
        }
    }
}

impl<T: FS + Capabilities> Capabilities for EncryptedFS<T> {
    fn can_mutate(&self) -> bool {
        self.inner.can_mutate()
    }
    
    fn can_truncate(&self) -> bool {
        self.inner.can_truncate()
    }
    
    fn can_rename(&self) -> bool {
        self.inner.can_rename()
    }
    
    fn can_append(&self) -> bool {
        self.inner.can_append()
    }
}

impl<T: FS> FS for EncryptedFS<T> {
    type File = EncryptedFile<T::File>;
    
    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()> {
        self.inner.create_dir_all(path)
    }
    
    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()> {
        self.inner.rename(from, to)
    }
    
    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let inner_file = self.inner.create(path)?;
        EncryptedFile::new(inner_file, self.engine.clone())
    }
    
    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let inner_file = self.inner.open_read(path)?;
        EncryptedFile::new(inner_file, self.engine.clone())
    }
    
    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let inner_file = self.inner.open_write(path)?;
        EncryptedFile::new(inner_file, self.engine.clone())
    }
    
    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        // We need to implement this directly since the inner zero_file_range
        // would corrupt our encryption
        
        // Save current position
        let current_pos = file.position();
        
        let zeros = vec![0u8; std::cmp::min(len as usize, BLOCK_SIZE)];
        let mut remaining = len;
        
        // Use normal write operations instead of direct manipulation
        // This goes through our encryption path
        let mut pos = offset;
        while remaining > 0 {
            // Create a temporary mutable reference
            let mut file_ref = &*file;
            
            // Seek to correct position
            file_ref.seek(SeekFrom::Start(pos))?;
            
            // Write zeros
            let write_size = std::cmp::min(remaining as usize, zeros.len());
            match file_ref.write(&zeros[..write_size]) {
                Ok(bytes_written) => {
                    remaining -= bytes_written as u64;
                    pos += bytes_written as u64;
                }
                Err(e) => return Err(e.into()),
            }
        }
        
        // Restore original position
        (&*file).seek(SeekFrom::Start(current_pos))?;
        
        Ok(())
    }
    
    fn copy_file_range(
        &self,
        src_file: &Self::File,
        src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64> {
        // Save current positions to restore later
        let src_pos = src_file.position();
        let dst_pos = dst_file.position();
        
        let mut buffer = vec![0u8; std::cmp::min(len as usize, BLOCK_SIZE)];
        let mut remaining = len;
        let mut copied = 0u64;
        
        while remaining > 0 {
            // Create temporary mutable references
            let mut src_file_ref = &*src_file;
            let mut dst_file_ref = &*dst_file;
            
            // Seek source file to read position
            src_file_ref.seek(SeekFrom::Start(src_offset + copied))?;
            
            // Read data
            let read_size = std::cmp::min(remaining as usize, buffer.len());
            let bytes_read = match src_file_ref.read(&mut buffer[..read_size]) {
                Ok(n) => n,
                Err(e) => return Err(e.into()),
            };
            
            if bytes_read == 0 {
                break; // EOF
            }
            
            // Seek destination file to write position
            dst_file_ref.seek(SeekFrom::Start(dst_offset + copied))?;
            
            // Write data
            match dst_file_ref.write(&buffer[..bytes_read]) {
                Ok(bytes_written) => {
                    remaining -= bytes_written as u64;
                    copied += bytes_written as u64;
                }
                Err(e) => return Err(e.into()),
            }
        }
        
        // Restore original positions
        (&*src_file).seek(SeekFrom::Start(src_pos))?;
        (&*dst_file).seek(SeekFrom::Start(dst_pos))?;
        
        Ok(copied)
    }
}
