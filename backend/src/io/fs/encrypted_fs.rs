use std::cell::RefCell;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes256,
};
use sha2::{Digest, Sha256};
use xts_mode::Xts128;

use crab_fs_common::errors::MyResult;
use crab_fs_common::io::fs::{Capabilities, Finalize, Len, SetLen, FS};

use crab_fs_common::io::fs::{Snapshottable, TFile};

const BLOCK_SIZE: usize = 4096; // Use 4KB blocks for optimal performance

type Aes256Xts = Xts128<Aes256>;

/// File Format Specification
/// -----------------------
/// Header (32 bytes):
///   - Key validation hash
///
/// For each 4KB block:
///   - Length prefix (4 bytes, little-endian u32)
///   - Encrypted data (multiple of 16 bytes, AES blocks)
///
/// Each AES block uses a unique tweak derived from:
///   - Block index
///   - Sub-block index within 4KB block

mod spec {

    struct DataBlock {
        length: u32,
        data: [u8; super::BLOCK_SIZE],
    }

    struct Header {
        key_validation_hash: [u8; 32],
    }

    struct File {
        header: Header,
        blocks: [DataBlock; 0],
    }
}

struct EncryptionEngine {
    cipher: Aes256Xts,
    key_hash: [u8; 32], // Store key hash for file headers
}

pub const AES_BLOCK_SIZE: usize = 16;

impl EncryptionEngine {
    fn new(password: &[u8]) -> Self {
        // Derive a 512-bit key (two 256-bit keys required by AES-XTS)
        let mut hasher = Sha256::new();
        hasher.update(password);
        let key1 = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(key1);
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

    fn encrypt_block(&self, block_idx: u64, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }

        // Store original length
        let original_len = data.len();
        let mut result = Vec::with_capacity(
            4 + original_len + (AES_BLOCK_SIZE - (original_len % AES_BLOCK_SIZE)),
        );
        result.extend_from_slice(&(original_len as u32).to_le_bytes());

        // Process data in AES blocks
        let num_blocks = (original_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
        for i in 0..num_blocks {
            let mut buffer = vec![0u8; AES_BLOCK_SIZE];
            let start = i * AES_BLOCK_SIZE;
            let end = std::cmp::min(start + AES_BLOCK_SIZE, original_len);
            buffer[..end - start].copy_from_slice(&data[start..end]);

            // Create unique tweak for each AES block
            let mut tweak = [0u8; 16];
            let block_num = block_idx * (BLOCK_SIZE as u64 / AES_BLOCK_SIZE as u64) + i as u64;
            tweak[..8].copy_from_slice(&block_num.to_le_bytes());

            self.cipher.encrypt_sector(&mut buffer, tweak);
            result.extend(buffer);
        }

        result
    }

    fn decrypt_block(&self, block_idx: u64, encrypted_data: &[u8]) -> Vec<u8> {
        if encrypted_data.len() < 4 {
            return Vec::new();
        }

        // Get original length
        let original_len = u32::from_le_bytes([
            encrypted_data[0],
            encrypted_data[1],
            encrypted_data[2],
            encrypted_data[3],
        ]) as usize;

        let mut result = Vec::with_capacity(original_len);
        let encrypted_blocks = &encrypted_data[4..];

        // Process each AES block
        for (i, chunk) in encrypted_blocks.chunks(AES_BLOCK_SIZE).enumerate() {
            if chunk.len() != AES_BLOCK_SIZE {
                break;
            }

            let mut buffer = vec![0u8; AES_BLOCK_SIZE];
            buffer.copy_from_slice(chunk);

            // Create unique tweak for each AES block
            let mut tweak = [0u8; 16];
            let block_num = block_idx * (BLOCK_SIZE as u64 / AES_BLOCK_SIZE as u64) + i as u64;
            tweak[..8].copy_from_slice(&block_num.to_le_bytes());

            self.cipher.decrypt_sector(&mut buffer, tweak);
            result.extend(
                &buffer[..std::cmp::min(
                    AES_BLOCK_SIZE,
                    original_len.saturating_sub(i * AES_BLOCK_SIZE),
                )],
            );
        }

        result.truncate(original_len);
        result
    }

    // Get key hash for validation
    fn get_key_hash(&self) -> &[u8; 32] {
        &self.key_hash
    }
}

// Encrypted file wrapper that handles on-the-fly encryption/decryption

struct EncryptedFileContent<F> {
    inner_file: F,
    block_buffer: Vec<u8>,  // Buffer for partial block operations
    current_block_idx: u64, // Current block index (position/BLOCK_SIZE)
    buffer_position: usize, // Position within the current block buffer
    buffer_valid: bool,     // Whether buffer contains valid data
    buffer_modified: bool,  // Whether buffer has been modified and needs writing
    file_length: u64,       // Actual file length without header
}

pub struct EncryptedFile<F: TFile> {
    engine: Arc<EncryptionEngine>,
    content: RefCell<EncryptedFileContent<F>>,
}

impl<F: TFile> TFile for EncryptedFile<F> {}

impl<F: TFile> EncryptedFile<F> {
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
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Invalid encryption key",
                )
                .into());
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
            file_length: if file_length > 32 {
                file_length - 32
            } else {
                0
            },
        };

        Ok(Self {
            engine,
            content: RefCell::new(content),
        })
    }

    // Load a block from the file into the buffer
    fn load_block(&self, block_idx: u64) -> io::Result<()> {
        // Check if we need to flush first without holding the borrow
        let needs_flush = {
            let content = self.content.borrow();
            content.buffer_modified
        };

        // Flush if needed (without holding borrow)
        if needs_flush {
            self.flush_buffer()?;
        }

        // Now borrow mutably for the rest of the operation
        let mut content = self.content.borrow_mut();

        // Calculate file position for this block
        let file_pos = 32 + (block_idx * BLOCK_SIZE as u64);
        content.inner_file.seek(SeekFrom::Start(file_pos))?;

        // Read the block
        let mut bytes_read = 0;
        content.block_buffer.fill(0);

        while bytes_read < BLOCK_SIZE {
            let mut buf = vec![];
            std::mem::swap(&mut buf, &mut content.block_buffer);
            let result = content.inner_file.read(&mut buf[bytes_read..]);
            std::mem::swap(&mut buf, &mut content.block_buffer);
            match result {
                Ok(0) => break, // EOF
                Ok(n) => bytes_read += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        // If we read any data, decrypt it
        if bytes_read > 0 {
            let decrypted = self
                .engine
                .decrypt_block(block_idx, &content.block_buffer[..bytes_read]);
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

        // Calculate valid data size
        let valid_data_size = std::cmp::min(
            BLOCK_SIZE,
            (content.file_length - (content.current_block_idx * BLOCK_SIZE as u64)) as usize,
        );

        let encrypted = self.engine.encrypt_block(
            content.current_block_idx,
            &content.block_buffer[..valid_data_size],
        );

        // Write encrypted block back to file
        let file_pos = 32 + (content.current_block_idx * BLOCK_SIZE as u64);
        content.inner_file.seek(SeekFrom::Start(file_pos))?;
        content.inner_file.write_all(&encrypted)?;

        content.buffer_modified = false;
        Ok(())
    }

    /// Get current file position
    /// ```
    /// let content = self.content.borrow();
    /// let position = self.position(&content);
    /// ```
    fn position(&self, content: &EncryptedFileContent<F>) -> u64 {
        // assert!(self.content == content);
        (content.current_block_idx * BLOCK_SIZE as u64) + content.buffer_position as u64
    }
}

impl<F: TFile> Read for EncryptedFile<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (self as &EncryptedFile<F>).read(buf)
    }
}

impl<F: TFile> Read for &EncryptedFile<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read = 0;

        while bytes_read < buf.len() {
            // Get needed values under a single borrow
            let (need_load, block_idx, pos, current_pos, file_length) = {
                let content = self.content.borrow();
                (
                    !content.buffer_valid || content.buffer_position >= BLOCK_SIZE,
                    content.current_block_idx,
                    content.buffer_position,
                    self.position(&content),
                    content.file_length,
                )
            };

            // If at EOF, break
            if current_pos >= file_length {
                break;
            }

            // Load new block if needed
            if need_load {
                self.load_block(block_idx + (pos >= BLOCK_SIZE) as u64)?;
                self.content.borrow_mut().buffer_position = 0;
            }

            // Copy data under a single borrow
            let n = {
                let content = self.content.borrow();
                let available = BLOCK_SIZE - content.buffer_position;
                let remaining_in_file = content.file_length.saturating_sub(current_pos);
                let can_read = std::cmp::min(
                    std::cmp::min(available, buf.len() - bytes_read),
                    remaining_in_file as usize,
                );

                buf[bytes_read..bytes_read + can_read].copy_from_slice(
                    &content.block_buffer
                        [content.buffer_position..content.buffer_position + can_read],
                );
                can_read
            };

            // Update position
            self.content.borrow_mut().buffer_position += n;
            bytes_read += n;
        }

        Ok(bytes_read)
    }
}

impl<F: TFile> Write for EncryptedFile<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (self as &EncryptedFile<F>).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (self as &EncryptedFile<F>).flush()
    }
}

impl<F: TFile> Write for &EncryptedFile<F> {
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
                let current_position = self.position(&content);
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

impl<F: TFile> Seek for EncryptedFile<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        (self as &EncryptedFile<F>).seek(pos)
    }
}

impl<F: TFile> Seek for &EncryptedFile<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Calculate the absolute position
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset > 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Cannot seek past end of file",
                    ));
                }
                let file_length = self.content.borrow().file_length;
                file_length.checked_add_signed(offset).unwrap_or(0)
            }
            SeekFrom::Current(offset) => {
                let current_pos = self.position(&self.content.borrow());
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

impl<F: TFile> Len for EncryptedFile<F> {
    fn len(&mut self) -> MyResult<u64> {
        Ok(self.content.borrow().file_length)
    }
}

impl<F: TFile> SetLen for EncryptedFile<F> {
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
            let current_position = self.position(&content);
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

impl<F: TFile> Finalize for EncryptedFile<F> {
    fn finalize(&mut self) -> MyResult<()> {
        // Flush any pending changes
        let buffer_modified = self.content.borrow().buffer_modified;
        if buffer_modified {
            self.flush_buffer()?;
        }
        self.content.borrow_mut().inner_file.finalize()
    }
}

impl<F: TFile> Drop for EncryptedFile<F> {
    fn drop(&mut self) {
        let _ = self.finalize();
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
        // Try to open existing file first
        match self.inner.open_read(path.as_ref()) {
            Ok(mut existing) => {
                // Read and validate header
                let mut header = [0u8; 32];
                existing.read_exact(&mut header)?;
                drop(existing); // Close read handle

                // Now open for writing
                let inner_file = self.inner.open_write(path)?;
                EncryptedFile::new(inner_file, self.engine.clone())
            }
            Err(_) => {
                // File doesn't exist, create new
                let inner_file = self.inner.create(path)?;
                EncryptedFile::new(inner_file, self.engine.clone())
            }
        }
    }

    fn zero_file_range(&self, mut file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        // We need to implement this directly since the inner zero_file_range
        // would corrupt our encryption

        // Save current position
        let current_pos = file.position(&file.content.borrow());

        let zeros = vec![0u8; std::cmp::min(len as usize, BLOCK_SIZE)];
        let mut remaining = len;

        // Use normal write operations instead of direct manipulation
        // This goes through our encryption path
        let mut pos = offset;
        while remaining > 0 {
            // Create a temporary mutable reference
            let mut file_ref = file;

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
        file.seek(SeekFrom::Start(current_pos))?;

        Ok(())
    }

    fn copy_file_range(
        &self,
        mut src_file: &Self::File,
        src_offset: u64,
        mut dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64> {
        // Save current positions to restore later
        let src_pos = src_file.position(&src_file.content.borrow());
        let dst_pos = dst_file.position(&dst_file.content.borrow());

        let mut buffer = vec![0u8; std::cmp::min(len as usize, BLOCK_SIZE)];
        let mut remaining = len;
        let mut copied = 0u64;

        while remaining > 0 {
            // Create temporary mutable references
            let mut src_file_ref = src_file;
            let mut dst_file_ref = dst_file;

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
        src_file.seek(SeekFrom::Start(src_pos))?;
        dst_file.seek(SeekFrom::Start(dst_pos))?;

        Ok(copied)
    }
}

impl<T: Snapshottable + FS> Snapshottable for EncryptedFS<T> {
    type Snapshot = T::Snapshot;

    fn create_snapshot(&self) -> Self::Snapshot {
        self.inner.create_snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::fs::InMemoryFS;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn test_encrypted_fs_small_files() {
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"test password");

        // Test with very small file (smaller than AES block)
        let mut file = encrypted.create("small.txt").unwrap();
        file.write_all(b"Hello").unwrap();
        file.finalize().unwrap();

        let mut read_file = encrypted.open_read("small.txt").unwrap();
        let mut content = Vec::new();
        read_file.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"Hello");
    }

    #[test]
    fn test_encrypted_fs_empty_files() {
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"test password");

        // Empty files should work
        let mut file = encrypted.create("empty.txt").unwrap();
        file.finalize().unwrap();

        let mut read_file = encrypted.open_read("empty.txt").unwrap();
        let mut content = Vec::new();
        read_file.read_to_end(&mut content).unwrap();
        assert_eq!(content.len(), 0);
    }

    #[test]
    fn test_encrypted_fs_handles_truncation() {
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"test password");

        // Create and truncate
        let mut file = encrypted.create("truncate.txt").unwrap();
        file.write_all(b"This is some text that will be truncated")
            .unwrap();
        file.set_len(10).unwrap();
        file.finalize().unwrap();

        let mut read_file = encrypted.open_read("truncate.txt").unwrap();
        let mut content = Vec::new();
        read_file.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"This is so");
    }

    #[test]
    fn test_encrypted_fs_append() {
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"test password");

        // Create initial file
        let mut file = encrypted.create("append.txt").unwrap();
        file.write_all(b"Initial").unwrap();
        file.finalize().unwrap();

        // Append to it
        let mut file = encrypted.open_write("append.txt").unwrap();
        file.seek(SeekFrom::End(0)).unwrap();
        file.write_all(b" content").unwrap();
        file.finalize().unwrap();

        // Read back complete content
        let mut read_file = encrypted.open_read("append.txt").unwrap();
        let mut content = Vec::new();
        read_file.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"Initial content");
    }

    #[test]
    fn test_encrypted_fs_partial_block_update() {
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"test password");

        // Write some data
        let mut file = encrypted.create("partial.txt").unwrap();
        file.write_all(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();

        // Seek to middle and update
        file.seek(SeekFrom::Start(10)).unwrap();
        file.write_all(b"XYZ").unwrap();
        file.finalize().unwrap();

        // Verify content
        let mut read_file = encrypted.open_read("partial.txt").unwrap();
        let mut content = Vec::new();
        read_file.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"ABCDEFGHIJXYZMNOPQRSTUVWXYZ");
    }

    #[test]
    fn test_encrypted_fs_block_aligned_file() {
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"test password");

        // Test with exactly 16 bytes (AES block size)
        let mut file = encrypted.create("block.txt").unwrap();
        file.write_all(b"0123456789ABCDEF").unwrap();
        file.finalize().unwrap();

        let mut read_file = encrypted.open_read("block.txt").unwrap();
        let mut content = Vec::new();
        read_file.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"0123456789ABCDEF");
    }

    #[test]
    fn test_encrypted_fs_large_file() {
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"test password");

        // Create a file larger than block size
        let mut file = encrypted.create("large.txt").unwrap();
        let data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        file.finalize().unwrap();

        // Read it back
        let mut read_file = encrypted.open_read("large.txt").unwrap();
        let mut content = Vec::new();
        read_file.read_to_end(&mut content).unwrap();
        assert_eq!(content, data);
    }

    #[test]
    fn test_encrypted_fs_wrong_password() {
        let memory = InMemoryFS::new();

        // Create a file with one password
        let encrypted1 = EncryptedFS::new(memory.clone(), b"password1");
        let mut file = encrypted1.create("secret.txt").unwrap();
        file.write_all(b"0123456789ABCDEF").unwrap();
        file.finalize().unwrap();

        // Try to open with wrong password
        let encrypted2 = EncryptedFS::new(memory, b"password2");
        let result = encrypted2.open_read("secret.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_fs_seek_and_read() {
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"test password");

        // Create file with some content
        let mut file = encrypted.create("seek.txt").unwrap();
        file.write_all(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
        file.finalize().unwrap();

        // Open for reading
        let mut read_file = encrypted.open_read("seek.txt").unwrap();

        // Seek to different positions and read
        read_file.seek(SeekFrom::Start(10)).unwrap();
        let mut buf = [0u8; 5];
        read_file.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"KLMNO");

        // Seek from current position
        read_file.seek(SeekFrom::Current(2)).unwrap();
        read_file.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"RSTUV");

        // Seek from end
        read_file.seek(SeekFrom::End(-4)).unwrap();
        read_file.read_exact(&mut buf[0..4]).unwrap();
        assert_eq!(&buf[0..4], b"WXYZ");
    }

    #[test]
    fn test_encrypted_fs_read_write_chunks() {
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"test password");

        // Create a file
        let mut file = encrypted.create("chunks.txt").unwrap();

        // Write data in chunks that span across blocks
        let chunk1 = vec![1u8; 3000];
        let chunk2 = vec![2u8; 3000];
        let chunk3 = vec![3u8; 3000];

        file.write_all(&chunk1).unwrap();
        file.write_all(&chunk2).unwrap();
        file.write_all(&chunk3).unwrap();
        file.finalize().unwrap();

        // Read in chunks and verify
        let mut read_file = encrypted.open_read("chunks.txt").unwrap();
        let mut buf = vec![0u8; 3500];

        // Read first chunk (overlapping into second)
        let bytes_read = read_file.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 3500);
        assert!(buf[0..3000].iter().all(|&b| b == 1));
        assert!(buf[3000..3500].iter().all(|&b| b == 2));

        // Read second part
        let bytes_read = read_file.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 3500);
        assert!(buf[0..2500].iter().all(|&b| b == 2));
        assert!(buf[2500..3500].iter().all(|&b| b == 3));

        // Read final part
        let bytes_read = read_file.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 2000);
        assert!(buf[0..2000].iter().all(|&b| b == 3));
    }

    #[test]
    fn test_encrypted_fs_modify_existing_file() {
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"test password");

        // Create initial file
        let mut file = encrypted.create("modify.txt").unwrap();
        file.write_all(b"Original content that will be partially modified")
            .unwrap();
        file.finalize().unwrap();

        // Open for writing, modify middle portion
        let mut file = encrypted.open_write("modify.txt").unwrap();
        file.seek(SeekFrom::Start(16)).unwrap();
        file.write_all(b"MODIFIED").unwrap();
        file.finalize().unwrap();

        // Verify content
        let mut read_file = encrypted.open_read("modify.txt").unwrap();
        let mut content = Vec::new();
        read_file.read_to_end(&mut content).unwrap();
        assert_eq!(
            content,
            b"Original content MODIFIEDt will be partially modified"
        );
    }
}

#[cfg(test)]
mod additional_tests {
    use crate::io::fs::InMemoryFS;

    use super::*;

    #[test]
    fn test_encrypted_fs_exact_block_size() {
        // Test writing a file that exactly fills one block (4096 bytes)
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"exact block");
        let data = vec![0xAB; BLOCK_SIZE]; // exactly 4096 bytes with 0xAB
        let mut file = encrypted.create("exact.txt").unwrap();
        file.write_all(&data).unwrap();
        file.finalize().unwrap();

        let mut read_file = encrypted.open_read("exact.txt").unwrap();
        let mut content = Vec::new();
        read_file.read_to_end(&mut content).unwrap();
        assert_eq!(content, data);
    }

    #[test]
    fn test_encrypted_fs_multiple_block_modification() {
        // Write a file spanning three blocks and then modify the middle block
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"multiple block");
        let data_block1 = vec![1u8; BLOCK_SIZE];
        let data_block2 = vec![2u8; BLOCK_SIZE];
        let data_block3 = vec![3u8; BLOCK_SIZE];

        let mut file = encrypted.create("multi.txt").unwrap();
        file.write_all(&data_block1).unwrap();
        file.write_all(&data_block2).unwrap();
        file.write_all(&data_block3).unwrap();
        file.finalize().unwrap();

        // Open for writing and override the second block
        let mut file = encrypted.open_write("multi.txt").unwrap();
        file.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
        let new_block = vec![9u8; BLOCK_SIZE];
        file.write_all(&new_block).unwrap();
        file.finalize().unwrap();

        // Read back and check for modifications
        let mut read_file = encrypted.open_read("multi.txt").unwrap();
        let mut content = Vec::new();
        read_file.read_to_end(&mut content).unwrap();
        assert_eq!(&content[0..BLOCK_SIZE], &data_block1[..]);
        assert_eq!(&content[BLOCK_SIZE..2 * BLOCK_SIZE], &new_block[..]);
        assert_eq!(&content[2 * BLOCK_SIZE..], &data_block3[..]);
    }

    #[test]
    fn test_encrypted_fs_random_access_read_write() {
        // Create a two-block file and perform random modifications across blocks
        let memory = InMemoryFS::new();
        let encrypted = EncryptedFS::new(memory, b"random access");

        let original_data: Vec<u8> = (0..(2 * BLOCK_SIZE)).map(|i| (i % 256) as u8).collect();
        let mut file = encrypted.create("random.txt").unwrap();
        file.write_all(&original_data).unwrap();
        file.finalize().unwrap();

        // Open for writing and perform random writes
        let mut file = encrypted.open_write("random.txt").unwrap();
        // Overwrite bytes 100..200 in the first block with 0xFF
        file.seek(SeekFrom::Start(100)).unwrap();
        let patch1 = vec![0xFF; 100];
        file.write_all(&patch1).unwrap();

        // Overwrite bytes (BLOCK_SIZE + 50) .. (BLOCK_SIZE + 150) in the second block with 0xEE
        file.seek(SeekFrom::Start(BLOCK_SIZE as u64 + 50)).unwrap();
        let patch2 = vec![0xEE; 100];
        file.write_all(&patch2).unwrap();
        file.finalize().unwrap();

        // Read entire file back and verify changes
        let mut read_file = encrypted.open_read("random.txt").unwrap();
        let mut modified_data = Vec::new();
        read_file.read_to_end(&mut modified_data).unwrap();

        // Check first block modification
        for i in 100..200 {
            assert_eq!(modified_data[i], 0xFF);
        }
        // Check second block modification
        for i in (BLOCK_SIZE + 50)..(BLOCK_SIZE + 150) {
            assert_eq!(modified_data[i], 0xEE);
        }
        // Validate that unmodified areas remain intact
        for i in 0..100 {
            assert_eq!(modified_data[i], original_data[i]);
        }
        for i in 200..BLOCK_SIZE {
            assert_eq!(modified_data[i], original_data[i]);
        }
        for i in (BLOCK_SIZE)..(BLOCK_SIZE + 50) {
            assert_eq!(modified_data[i], original_data[i]);
        }
        for i in (BLOCK_SIZE + 150)..(2 * BLOCK_SIZE) {
            assert_eq!(modified_data[i], original_data[i]);
        }
    }
}
