// this file contains the on-disk serialized structures.
// MUST NOT be changed, instead, create repository_v2

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

//---------------------
use log::{debug, warn};
use log::{error, LevelFilter};
use std::cmp::min;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
#[cfg(target_os = "linux")]
use std::os::unix::io::IntoRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs, io};

use std::collections::HashMap;
use std::sync::RwLock;

use rand::{RngCore, SeedableRng};
//-------------------

use blake3::Hasher;

use crate::errors::{MyResult, ErrorKinds};
// use bincode_maxsize_derive::BincodeMaxSize;


/*
  /inodes
  |-1: dir([entries])
  |-2: file(attrs, inline-content)
  |-3: file(attrs, [contents])
  |-...

  /contents (note: one file can consist of multiple contents)
    /blocks (content adressed chunks, containing linear data)
    |-0xabcd: block(header(size), [bytes])
    |-0xefg
    |-...
    /in-progress (not content addressed, instead named by a uuid. file operation in progress, will be hashed on file close)
    |-a
    |-b
    |-c
*/

pub type OsStringBytes = Vec<u8>;

pub type Inode = u64;
/// the bytes of an OsString
pub type EntryName = OsStringBytes;
pub type DirectoryDescriptor = BTreeMap<EntryName, (Inode, FileKind)>;

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
}


// #[derive(BincodeMaxSize)]
#[derive(Serialize, Deserialize)]
pub struct InodeAttributes {
    pub inode: Inode,
    // pub open_file_handles: u64, // Ref count of open file handles to this inode
    pub size: u64,
    pub last_accessed: (i64, u32),
    pub last_modified: (i64, u32),
    pub last_metadata_changed: (i64, u32),
    pub kind: FileKind,
    // Permissions and special mode bits
    pub mode: u16,
    pub hardlinks: u32,
    pub uid: u32,
    pub gid: u32,
    pub xattrs: BTreeMap<EntryName, Vec<u8>>,
}


/// note: in the case of block chunks, this is the hash of the block.
///       in the case of an in-progress chunk, this is a random uuid
pub type ChunkId = [u8;16];

const SIZE_OF_CHUNK_ID : usize = 16;

#[cfg(test)]
#[test]
pub fn test_size_of_chunk_id() {
    let id: ChunkId = [0; 16];
    assert_eq!(bincode::serialize(&id).unwrap().len(), SIZE_OF_CHUNK_ID);
}


#[derive(Serialize, Deserialize)]
pub struct BlockChunk {
    /// note: the id is the hash of the content
    pub id: ChunkId,
    pub data: Vec<u8>
}

// #[derive(Serialize, Deserialize)]
// pub enum VersionedBlockChunk {
//     V1(BlockChunk)
// }

// note: the way bincode works, 'len' in this struct maps to the length of the vector 'data' in the serialized representation of BlockChunk
#[derive(Serialize, Deserialize, Clone)]
pub struct BlockChunkHeader {
    pub id: ChunkId,
    pub len: u64,
}

impl BlockChunkHeader {
    const SIZE : usize = 24;
}

impl BlockChunk {
    const OFFSET_OF_ACTUAL_DATA : usize = BlockChunkHeader::SIZE;
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_offset_of_data() {
        let chunk = BlockChunk {
            id: [0; 16],
            data: vec![0x53, 0xa0]
        };
        let serialized = bincode::serialize(&chunk).unwrap();
        assert_eq!(serialized.len(), BlockChunkHeader::SIZE + 2);
        assert_eq!(serialized[BlockChunk::OFFSET_OF_ACTUAL_DATA], 0x53);
        assert_eq!(serialized[BlockChunk::OFFSET_OF_ACTUAL_DATA + 1], 0xa0);
    }

    #[test]
    pub fn test_size_of() {
        let header = BlockChunkHeader {
            id: [0; 16],
            len: 0,
        };
        assert_eq!(bincode::serialize(&header).unwrap().len(), BlockChunkHeader::SIZE);
    }
}


#[derive(Serialize, Deserialize, Clone)]
pub struct Range {
    pub offset: u64,
    pub len: u64
}

// #[derive(Serialize, Deserialize, Clone)]
// pub struct SparseBlockPart {
    
// }

// #[derive(Serialize, Deserialize, Clone)]
// pub struct SparseBlockHeader {

// }

// #[derive(Serialize, Deserialize, Clone)]
// pub struct SparseBlock {
//     pub header: SparseBlockHeader,
//     pub parts: SparseBlockPart
// }

// /// Example:
// /// You have a base-chunk with the following data: B=[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A].
// /// You have an Overlay Chunk referencing this chunk.
// ///   OverlayChunk X:
// ///     header:
// ///       { base_chunk_ref: B, base_chunk_range: (0, 10), offset: 0 }
// ///     modified_buffers:
// ///       [ (5, [0xff])]
// ///   Result:
// ///     X= [0x01, 0x02, 0x03, 0x04, 0x05, 0xff, 0x07, 0x08, 0x09, 0x0A]
// ///     (a single byte has been replaced)
// #[derive(Serialize, Deserialize)]
// pub struct OverlayChunkHeader {
//     pub hash: ChunkId,
//     /// the size of this chunk, can be longer or shorter than the base chunk
//     pub len: usize,
// }

// /// a Chunk that references one base chunk and contains one or more modified ranges.
// /// Note: modified ranges may not overlap each other!
// #[derive(Serialize, Deserialize)]
// pub struct OverlayChunk {
//     header: OverlayChunkHeader,

//     pub base_chunk_ref: ChunkRef,
//     /// which part of the base Chunk to project into out Chunk
//     pub base_chunk_range: Range,

//     // a list of ranges that have been zeroed
//     zeroed_ranges: Vec<Range>,

//     // these two vecs are the same length. Each buffer is splatted over the base chunk at the 'offset' position.
//     // A buffer can either overlap the base chunk, or be appended to its end, but the whole OverlayChunk must be continuous, that is, there must not be any holes.
//     modified_offsets: Vec<usize>,
//     modified_buffers: Vec<Vec<u8>>
// }

// #[derive(Serialize, Deserialize)]
// pub struct ChunkRef {
//     /// the hash of the data chunk, or 0 if ChunkKind::Zero
//     pub id: ChunkId,
//     /// note: this len MUST match exactly with the length of the chunk that is referenced.
//     /// It is duplicated here so we don't need to actually open the chunk to find out the length.
//     pub len: usize,
//     pub kind: ChunkKind
// }

// // allow sparse inline files
// #[derive(Serialize, Deserialize)]
// pub enum InlineChunk {
//     Data(Vec<u8>),
//     Null(usize)
// }

// #[derive(Serialize, Deserialize)]
// impl InlineChunk {
//     fn len(&self) -> usize {
//         match self {
//             InlineChunk::Data(bytes) => bytes.len(),
//             InlineChunk::Null(size) => *size,
//         }
//     }
// }

#[derive(Serialize, Deserialize, Clone)]
pub struct BlockChunkRef {
    /// the hash of the data chunk
    pub id: ChunkId,
    /// note: this len MUST match exactly with the length of the chunk that is referenced.
    /// It is duplicated here so we don't need to actually open the chunk to find out the length.
    pub len: u64,    
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WindowedChunkRef {
    pub base: BlockChunkRef,
    pub range: Range,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InProgressBlockChunkRef {
    pub id: ChunkId,
    pub len: u64,
}


#[derive(Serialize, Deserialize, Clone)]
pub enum ChunkRef {
    Zero(u64),
    Inline(Vec<u8>),
    /// a content addressed, immutable, raw block of data. One Block can be referenced multiple times, either directly, or through a 'Window'
    Block(BlockChunkRef),
    /// a reference into a 'Block' chunk
    Window(WindowedChunkRef),
    /// a mutable, raw block of data. Must only be referenced once.
    InProgressBlock(InProgressBlockChunkRef),
}

impl ChunkRef {
    pub fn len(&self) -> u64 {
        match self {
            ChunkRef::Zero(size) => *size,
            ChunkRef::Inline(data) => data.len() as u64,
            ChunkRef::Block(block_ref) => block_ref.len,
            ChunkRef::Window(windowed_ref) => windowed_ref.range.len,
            ChunkRef::InProgressBlock(in_progress_ref) => in_progress_ref.len,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum FileContent {
    Chunks(Vec<ChunkRef>),
    // note: an empty file would be represented as "Chunks([])"
}

// note: required for a std::mem::take in the FS
impl Default for FileContent {
    fn default() -> Self {
        FileContent::Chunks(vec![])
    }
}

impl FileContent {

    pub const EMPTY: FileContent = FileContent::Chunks(vec![]);

    pub fn chunks<'a>(&'a self) -> &'a Vec<ChunkRef> {
        let FileContent::Chunks(chunks) = self;
        chunks
    }

    pub fn len(&self) -> u64 {
        self.chunks().iter()
            .map(|chunk| chunk.len())
            .sum()
    }

}


#[derive(Serialize, Deserialize)]
pub enum InodeContent {
    File(FileContent),
    Directory(DirectoryDescriptor),
    Symlink(OsStringBytes)
}

impl InodeContent {
    pub const EMPTY_FILE : InodeContent = InodeContent::File(FileContent::EMPTY);
}

#[derive(Serialize, Deserialize)]
pub struct InodeEntry {
    pub attrs: InodeAttributes,
    pub content: InodeContent

}


// ------------------------

#[cfg(target_os = "linux")]
fn zero_file_range_linux(file: &File, offset: u64, len: u64) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    
    let ret = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset as libc::off_t,
            len as libc::off_t
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// Fallback implementation for other platforms or if fallocate fails
fn zero_file_range_fallback(file: &File, offset: u64, len: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    
    // Write in chunks to avoid large allocations
    const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
    let zeros = vec![0u8; CHUNK_SIZE];
    
    let mut remaining = len;
    let mut current_offset = offset;
    
    while remaining > 0 {
        let write_size = std::cmp::min(remaining, CHUNK_SIZE as u64) as usize;
        file.write_at(&zeros[..write_size], current_offset)?;
        remaining -= write_size as u64;
        current_offset += write_size as u64;
    }
    
    Ok(())
}

// Combined function that tries fallocate first, then falls back
fn zero_file_range(file: &File, offset: u64, len: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        match zero_file_range_linux(file, offset, len) {
            Ok(()) => return Ok(()),
            Err(_) => {} // Fall through to fallback
        }
    }
    
    zero_file_range_fallback(file, offset, len)
}

// ------------------------

#[cfg(target_os = "linux")]
fn copy_file_range_linux(
    src_file: &File,
    src_offset: u64,
    dst_file: &File,
    dst_offset: u64,
    len: u64,
) -> io::Result<u64> {
    use std::os::unix::io::AsRawFd;
    
    let mut src_off = src_offset as i64;
    let mut dst_off = dst_offset as i64;
    let ret = unsafe {
        libc::copy_file_range(
            src_file.as_raw_fd(),
            &mut src_off,
            dst_file.as_raw_fd(),
            &mut dst_off,
            len as usize,
            0  // flags
        )
    };

    if ret >= 0 {
        Ok(ret as u64)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn copy_file_range(
    mut src_file: &File,
    src_offset: u64,
    mut dst_file: &File,
    dst_offset: u64,
    len: u64,
) -> io::Result<u64> {
    #[cfg(target_os = "linux")]
    {
        match copy_file_range_linux(src_file, src_offset, dst_file, dst_offset, len) {
            Ok(n) => return Ok(n),
            Err(_) => {} // Fall through to fallback
        }
    }

    // Fallback implementation
    let mut buffer = vec![0u8; std::cmp::min(len as usize, 64 * 1024)]; // 64KB chunks
    let mut total_copied = 0u64;
    let mut remaining = len;

    while remaining > 0 {
        let to_copy = std::cmp::min(remaining, buffer.len() as u64);
        src_file.seek(SeekFrom::Start(src_offset + total_copied))?;
        src_file.read_exact(&mut buffer[..to_copy as usize])?;
        
        dst_file.seek(SeekFrom::Start(dst_offset + total_copied))?;
        dst_file.write_all(&buffer[..to_copy as usize])?;
        
        total_copied += to_copy;
        remaining -= to_copy;
    }

    Ok(total_copied)
}

// ------------------------

pub struct BlockChunkWriter {
    file: File
}

impl BlockChunkWriter {
    pub fn new(file: File) -> Self {
        Self { file }
    }

    pub fn read_header(&mut self) -> Result<BlockChunkHeader, ErrorKinds> {
        let mut buffer = [0u8;BlockChunkHeader::SIZE];
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_exact(&mut buffer)?;
        let header: BlockChunkHeader = bincode::deserialize(&buffer)?;

        // if debug?
        {
            let file_size = self.file.metadata()?.len();
            let header_size = header.len;
            assert_eq!(file_size, header_size + BlockChunk::OFFSET_OF_ACTUAL_DATA as u64);
        }

        return Ok(header);
    }

    pub fn read_data(&mut self, offset: u64, buffer: &mut [u8]) -> MyResult<()> {
        self.file.seek(SeekFrom::Start(BlockChunk::OFFSET_OF_ACTUAL_DATA as u64 + offset))?;
        self.file.read_exact(buffer)?;
        Ok(())
    }

    pub fn write_header(&mut self, header: &BlockChunkHeader) -> Result<(), ErrorKinds> {
        let serialized = bincode::serialize(header)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&serialized)?;
        Ok(())
    }

    /// note: it is allowed to write past the end of the current file, but then it is the responsibility of the caller to update the header!
    pub fn write_data(&mut self, offset: u64, buffer: &[u8]) -> MyResult<()> {
        self.file.seek(SeekFrom::Start(BlockChunk::OFFSET_OF_ACTUAL_DATA as u64 + offset))?;
        self.file.write_all(buffer)?;
        Ok(())
    }

    /// calculates the hash of the content
    pub fn calculate_hash(&mut self) -> MyResult<ChunkId> {
        let hash: ChunkId = todo!();

        Ok(hash)
    }

    /// resize the file. this does not update the header!
    /// Call write_header afterwards!
    pub fn resize_data(&mut self, new_len: u64) -> MyResult<()> {
        let new_total_len = BlockChunkHeader::SIZE as u64 + new_len;
        self.file.set_len(new_total_len)?;
        Ok(())
    }

    pub fn write_data_zero_range(&self, offset: u64, size: u64) -> Result<(), ErrorKinds> {
        zero_file_range(&self.file, BlockChunk::OFFSET_OF_ACTUAL_DATA as u64 + offset, size)?;
        Ok(())
    }
}

// ------------------------

pub struct FilesystemWriter {
    data_dir: PathBuf,
    rng: rand::rngs::StdRng
}

impl FilesystemWriter {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            rng: rand::rngs::StdRng::from_entropy()
        }
    }

    /// idempotent, can be called multiple times
    pub fn init(&self) -> MyResult<()> {
        fs::create_dir_all(Path::new(&self.data_dir).join("meta"))?;
        fs::create_dir_all(Path::new(&self.data_dir).join("inodes"))?;
        fs::create_dir_all(Path::new(&self.data_dir).join("contents"))?;

        fs::create_dir_all(Path::new(&self.data_dir).join("contents").join("blocks"))?;
        fs::create_dir_all(Path::new(&self.data_dir).join("contents").join("in-progress"))?;

        Ok(())
    }

    /// can be destructive!
    pub fn create_new_fs(&self) -> MyResult<()> {
        let path = self.get_meta_path(Self::META_NEXT_INODE);
        let tmp_path = path.with_added_extension(".tmp");
        let writer = self.create(&tmp_path)?;
        bincode::serialize_into(writer, &(1))?;
        fs::rename(tmp_path, path)?;
        Ok(())
    }

    // --------------------------------------------------------------

    fn hash_to_pathsegment(id: &ChunkId) -> PathBuf {
        PathBuf::from(format!("{:x?}", id))
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<File> {
        let file = OpenOptions::new().read(true).open(path.as_ref())?;
        return Ok(file);
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<File> {
        let file = OpenOptions::new().write(true).open(path.as_ref())?;
        return Ok(file);
    }

    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<File> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.as_ref())?;
        return Ok(file);
    }

    fn inode_path(&self, inode: Inode) -> PathBuf {
        let path = Path::new(&self.data_dir)
            .join("inodes")
            .join(inode.to_string());
        return path;
    }

    fn get_uuid(&mut self) -> ChunkId {
        let mut bytes = [0u8; SIZE_OF_CHUNK_ID];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }

    // --------------------------------------------------------------

    pub fn get_inode(&self, inode: Inode) -> MyResult<InodeEntry> {
        let path = self.inode_path(inode);
        let file = self.open_read(path)?;
        Ok(bincode::deserialize_from(file).unwrap())
    }

    pub fn write_inode(&self, ino: Inode, content: &InodeEntry) -> MyResult<()>  {
        assert!(ino == content.attrs.inode);
        let path = self.inode_path(ino);
        let file = self.open_write(path)?;
        bincode::serialize_into(file, content).unwrap();
        Ok(())
    }

    // --------------------------------------------------------------

    fn block_path(&self, is_in_progress:bool, id: &ChunkId) -> PathBuf {
        let subdir = if is_in_progress { "" } else { "" };
        let path = Path::new(&self.data_dir)
            .join("contents")
            .join(subdir)
            .join(Self::hash_to_pathsegment(id));
        return path;
    }

    // Blocks
    // ----------------------

    pub fn read_block(&self, is_in_progress:bool, id: &ChunkId) -> MyResult<BlockChunkWriter> {
        let path = self.block_path(is_in_progress, id);
        let file = self.open_read(path)?;
        Ok(BlockChunkWriter::new(file))
    }

    pub fn write_block(&self, is_in_progress: bool, id: &ChunkId) -> MyResult<BlockChunkWriter> {        
        let path = self.block_path(is_in_progress, id);
        let file = self.open_write(path)?;
        Ok(BlockChunkWriter::new(file))
    }
    
    /// note: the block is completely empty even without a header!
    pub fn create_in_progress_block(&mut self) -> MyResult<(ChunkId, BlockChunkWriter)> {
        let uuid : ChunkId = self.get_uuid();
        let path = self.block_path(true, &uuid);
        let file = self.create(path)?;
        let writer = BlockChunkWriter::new(file);
        Ok((uuid, writer))
    }

    // --------------------------------------------------------------



    pub fn get_meta_path(&self, key: &str) -> PathBuf {
        Path::new(&self.data_dir).join("meta").join(key)
    }

    pub fn get_meta(&self, key: &str) -> Vec<u8> {
        todo!()
    }

    pub fn set_meta(&self, key: &str, value: Vec<u8>) {
        todo!()
    }

    const META_NEXT_INODE : &str = "next_inode";

    pub fn meta_get_next_inode(&self) -> Result<Inode, ErrorKinds> {

        let path = self.get_meta_path(Self::META_NEXT_INODE);

        // note: if the file becomes corrupt, no more inodes can be allocated, so no new files or directories can be created.
        //       at the very least, an expressive error message should be bubbled up to the user, and a "repair" command be added to the cli
        //       which would just scan the whole filesystem and reset it to the highest found value.
        let current_inode: Inode = bincode::deserialize_from(self.open_read(&path)?)?;

        // do an atomic replace of the file
        let tmp_path = path.with_added_extension(".tmp");
        let writer = self.create(&tmp_path)?;
        bincode::serialize_into(writer, &(current_inode + 1))?;
        fs::rename(tmp_path, path)?;

        Ok(current_inode + 1)
    }

}


#[cfg(test)]
mod FilesystemWriter_tests {
    use super::*;
    #[test]
    pub fn test_hash_to_pathsegment() {
        let testcases = vec![
            ([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f], "0010102030405060708090a0b0c0d0e0f")
        ];

        for tc in testcases {
            let (input, expected) = tc;
            let actual = FilesystemWriter::hash_to_pathsegment(&input);
            assert_eq!(actual.to_str().unwrap(), expected);
        }
    }
}

// ------------------------

pub struct RepositoryOptions {
    pub max_inline_content_size: usize,

}

pub struct RepositoryV1 {
    options: RepositoryOptions,
    writer: FilesystemWriter
}

impl RepositoryV1 {
    pub fn new(data_dir: PathBuf, options: RepositoryOptions) -> Self {
        Self {
            options,
            writer: FilesystemWriter::new(data_dir)
        }
    }

    /// idempotent, can be called multiple times
    pub fn init(&self) -> MyResult<()> {
        self.writer.init()
    }

    /// can be destructive!
    pub fn create_new_fs(&self) -> MyResult<()> {
        self.writer.create_new_fs()
    }


    pub fn get_inode(&self, ino: Inode) -> MyResult<InodeEntry> {
        self.writer.get_inode(ino)
    }

    pub fn write_inode(&self, ino: Inode, content: &InodeEntry) -> MyResult<()>  {
        self.writer.write_inode(ino, content)
    }

    fn truncate_chunk(&self, chunk: ChunkRef, truncated_size: u64) -> Result<ChunkRef, ErrorKinds> {

        if truncated_size == chunk.len() {
            return Ok(chunk);
        }
        assert!(truncated_size < chunk.len());

        match chunk {
            ChunkRef::Zero(_) => {
                return Ok(ChunkRef::Zero(truncated_size));
            },
            ChunkRef::Inline(data) => {
                return Ok(ChunkRef::Inline(data[..truncated_size as usize].to_vec()));
            },
            ChunkRef::Block(block_chunk_ref) => {
                return Ok(ChunkRef::Window(WindowedChunkRef { base: block_chunk_ref, range: Range { offset: 0, len: truncated_size } }));
            },
            ChunkRef::Window(window_chunk_ref) => {
                return Ok(ChunkRef::Window(WindowedChunkRef { base: window_chunk_ref.base, range: Range { offset: window_chunk_ref.range.offset, len: truncated_size } }));
            },
            ChunkRef::InProgressBlock(in_progress_block_ref) => {
                let mut block_writer = self.writer.write_block(true, &in_progress_block_ref.id)?;
                let mut block_header = block_writer.read_header()?;
                assert_eq!(block_header.id, in_progress_block_ref.id);
                block_writer.resize_data(truncated_size);
                block_header.len = truncated_size;
                block_writer.write_header(&block_header);

                return Ok(ChunkRef::InProgressBlock(in_progress_block_ref));
            },
        }
    }

    pub fn change_content_len(&self, mut old_content: FileContent, new_length: u64) -> Result<FileContent, ErrorKinds> {
        if new_length == old_content.len() {
            return Ok(old_content);
        } else if new_length == 0 {
            return Ok(FileContent::Chunks(vec![]));
        } else if new_length > old_content.len() {
            // expand
            let expand_by = new_length - old_content.len();
            let FileContent::Chunks(chunks) = &mut old_content;
            chunks.push(ChunkRef::Zero(expand_by));
            return Ok(old_content); //note: old_content has been mutated in-place
        } else /* new length < old length */ {
            // shrink
            let FileContent::Chunks(old_chunks) = old_content;
            let mut accumulated_len = 0;
            let mut new_chunks = Vec::new();
            
            // Keep chunks until we reach the new length
            for chunk in old_chunks {
                let chunk_len = chunk.len();
                
                if accumulated_len + chunk_len > new_length {
                    // This chunk needs to be truncated
                    let truncated_len = new_length - accumulated_len;
                    let truncated_chunk = self.truncate_chunk(chunk, truncated_len)?;
                    new_chunks.push(truncated_chunk);
                    break;
                } else {
                    // Keep this chunk as-is
                    new_chunks.push(chunk);
                }
                
                accumulated_len += chunk_len;
                assert!(accumulated_len <= new_length);
                if accumulated_len == new_length {
                    break;
                }
            }
            
            return Ok(FileContent::Chunks(new_chunks));
        }
    }

    pub fn allocate_next_inode(&self) -> Result<Inode, ErrorKinds> {
        self.writer.meta_get_next_inode()
    }

    pub fn read_from_chunk(&self, chunk: &ChunkRef, chunk_offset: u64, buffer: &mut [u8]) -> MyResult<()> {
        match chunk {
            ChunkRef::Zero(_) => {
                // Fill with zeros
                for i in 0..buffer.len() {
                    buffer[i] = 0;
                }
            },
            ChunkRef::Inline(data) => {
                let start = chunk_offset as usize;
                let end = start + buffer.len();
                buffer.copy_from_slice(&data[start..end]);
            },
            ChunkRef::Block(block_ref) => {
                let mut chunk_writer = self.writer.read_block(false, &block_ref.id)?;
                chunk_writer.read_data(chunk_offset, buffer)?;
            },
            ChunkRef::Window(windowed_ref) => {
                let mut chunk_writer = self.writer.read_block(false, &windowed_ref.base.id)?;
                let actual_offset = windowed_ref.range.offset + chunk_offset;
                chunk_writer.read_data(actual_offset, buffer)?;
            },
            ChunkRef::InProgressBlock(block_ref) => {
                let mut chunk_writer = self.writer.read_block(true, &block_ref.id)?;
                chunk_writer.read_data(chunk_offset, buffer)?;
            }
        }
        Ok(())
    }
    
    pub fn read(&self, fc: &FileContent, offset: u64, buffer: &mut [u8]) -> MyResult<()> {
        let mut buffer_offset = 0;
        let mut file_offset = 0u64;
        let mut bytes_remaining = buffer.len();
    
        // Get all chunks
        let FileContent::Chunks(chunks) = fc;
    
        // Find the starting chunk and offset within that chunk
        for chunk in chunks {
            let chunk_len = chunk.len();
            
            // Skip chunks before our offset
            if file_offset + chunk_len <= offset {
                file_offset += chunk_len;
                continue;
            }
    
            // Calculate where to start reading in this chunk
            let chunk_offset = if file_offset < offset {
                offset - file_offset
            } else {
                0
            };
    
            // Calculate how many bytes we can read from this chunk
            let available_in_chunk = chunk_len - chunk_offset;
            let to_read = std::cmp::min(available_in_chunk, bytes_remaining as u64);
    
            if to_read == 0 {
                break;
            }
    
            // Read the bytes from this chunk
            self.read_from_chunk(chunk, chunk_offset, &mut buffer[buffer_offset..buffer_offset + to_read as usize])?;
    
            buffer_offset += to_read as usize;
            bytes_remaining -= to_read as usize;
            file_offset += chunk_len;
    
            if bytes_remaining == 0 {
                break;
            }
        }
    
        // If we couldn't read all requested bytes, return an error
        if bytes_remaining > 0 {
            return Err(libc::EINVAL.into());
        }
    
        Ok(())
    }
    
    /// writes to a chunk. The chunk can be extended if offset+buffer > chunk.len.
    /// Depending on the type of the chunk, it can be fragmented and multiple chunks be returned.
    pub fn write_to_chunk(&mut self, chunk: &ChunkRef, offset: u64, buffer: &[u8]) -> MyResult<Vec<ChunkRef>> {
        let chunk_len = chunk.len();
        let write_end_excl = offset + buffer.len() as u64;
        
        // Calculate the parts we need to keep from original chunk
        let keep_at_beginning = if offset > 0 { offset } else { 0 };
        let keep_at_tail = if write_end_excl < chunk_len { chunk_len - write_end_excl } else { 0 };
        let size_to_write = buffer.len() as u64;
        
        match chunk {
            ChunkRef::InProgressBlock(block_ref) => {
                let mut block_writer = self.writer.write_block(true, &block_ref.id)?;
                
                // If write extends beyond current block, extend it
                if write_end_excl > chunk_len {
                    let new_size = write_end_excl;
                    block_writer.write_data(offset, buffer)?;
                    block_writer.write_header(&BlockChunkHeader { 
                        id: block_ref.id, 
                        len: new_size 
                    })?;
                    
                    Ok(vec![ChunkRef::InProgressBlock(InProgressBlockChunkRef {
                        id: block_ref.id,
                        len: new_size,
                    })])
                } else {
                    // Normal case - just write into existing block
                    block_writer.write_data(offset, buffer)?;
                    Ok(vec![chunk.clone()])
                }
            },
    
            // For other types, convert to InProgressBlock if write is large enough
            _ => {
                if size_to_write > 1024 { // threshold for creating new block
                    // Create new InProgressBlock
                    let (uuid, mut block_writer) = self.writer.create_in_progress_block()?;
                    let total_size = std::cmp::max(chunk_len, write_end_excl);
    
                    // Copy existing data if needed
                    if keep_at_beginning > 0 {
                        let mut beginning_buffer = vec![0u8; keep_at_beginning as usize];
                        self.read_from_chunk(chunk, 0, &mut beginning_buffer)?;
                        block_writer.write_data(0, &beginning_buffer)?;
                    }
    
                    // Write new data
                    block_writer.write_data(offset, buffer)?;
    
                    if keep_at_tail > 0 {
                        let mut tail_buffer = vec![0u8; keep_at_tail as usize];
                        self.read_from_chunk(chunk, chunk_len - keep_at_tail, &mut tail_buffer)?;
                        block_writer.write_data(write_end_excl, &tail_buffer)?;
                    }
    
                    block_writer.write_header(&BlockChunkHeader {
                        id: uuid,
                        len: total_size,
                    })?;
    
                    Ok(vec![ChunkRef::InProgressBlock(InProgressBlockChunkRef {
                        id: uuid,
                        len: total_size,
                    })])
                } else {
                    // For small writes, create an Inline chunk
                    let mut inline_data = Vec::with_capacity(std::cmp::max(chunk_len, write_end_excl) as usize);
    
                    if keep_at_beginning > 0 {
                        let mut beginning_buffer = vec![0u8; keep_at_beginning as usize];
                        self.read_from_chunk(chunk, 0, &mut beginning_buffer)?;
                        inline_data.extend_from_slice(&beginning_buffer);
                    }
    
                    inline_data.extend_from_slice(buffer);
    
                    if keep_at_tail > 0 {
                        let mut tail_buffer = vec![0u8; keep_at_tail as usize];
                        self.read_from_chunk(chunk, chunk_len - keep_at_tail, &mut tail_buffer)?;
                        inline_data.extend_from_slice(&tail_buffer);
                    }
    
                    Ok(vec![ChunkRef::Inline(inline_data)])
                }
            }
        }
    }

    pub fn write(&mut self, fc: &FileContent, offset: u64, buffer: &[u8]) -> MyResult<FileContent> {
        let FileContent::Chunks(chunks) = fc;
        let mut new_chunks = Vec::new();
        let mut current_offset = 0u64;
        let write_end_excl = offset + buffer.len() as u64;
        
        // Handle all chunks
        for chunk in chunks {
            let chunk_begin = current_offset;
            let chunk_len = chunk.len();
            let chunk_end_excl = current_offset + chunk_len;
    
            if chunk_end_excl <= offset {
                // This chunk is entirely before the write range
                new_chunks.push(chunk.clone());
                current_offset = chunk_end_excl;
                continue;
            }
    
            if chunk_begin >= write_end_excl {
                // This chunk is entirely after the write range
                new_chunks.push(chunk.clone());
                current_offset = chunk_end_excl;
                continue;
            }
    
            // Calculate overlap
            let keep_at_beginning = if offset > chunk_begin { offset - chunk_begin } else { 0 };
            let keep_at_tail = if write_end_excl < chunk_end_excl { chunk_end_excl - write_end_excl } else { 0 };
            let write_offset_in_buffer = if chunk_begin > offset { chunk_begin - offset } else { 0 };
            let size_to_write = chunk_len - keep_at_beginning - keep_at_tail;
            
            match chunk {
                ChunkRef::InProgressBlock(block_ref) => {
                    let mut block_writer = self.writer.write_block(true, &block_ref.id)?;
                    
                    // If this is the last chunk and write extends beyond it, extend the block
                    if current_offset + chunk_len == fc.len() && write_end_excl > chunk_end_excl {
                        let new_size = keep_at_beginning + (write_end_excl - chunk_begin);
                        block_writer.resize_data(new_size)?;
                        block_writer.write_header(&BlockChunkHeader { 
                            id: block_ref.id, 
                            len: new_size 
                        })?;
                        
                        // Write the data, including the extension
                        let buffer_slice = &buffer[write_offset_in_buffer as usize..];
                        block_writer.write_data(keep_at_beginning, buffer_slice)?;
                        
                        new_chunks.push(ChunkRef::InProgressBlock(InProgressBlockChunkRef {
                            id: block_ref.id,
                            len: new_size,
                        }));
                        current_offset = write_end_excl; // Important: update this so we don't add another chunk
                    } else {
                        // Normal case - just write into existing block
                        let buffer_slice = &buffer[write_offset_in_buffer as usize..][..size_to_write as usize];
                        block_writer.write_data(keep_at_beginning, buffer_slice)?;
                        new_chunks.push(chunk.clone());
                        current_offset = chunk_end_excl;
                    }
                },

                // For other types, convert to InProgressBlock if write is large enough
                other_chunk => {
                    if size_to_write > 1024 { // threshold for creating new block
                        // Create new InProgressBlock
                        let (uuid, mut block_writer) = self.writer.create_in_progress_block()?;
                        let total_size = keep_at_beginning + size_to_write + keep_at_tail;

                        // Copy existing data if needed
                        if keep_at_beginning > 0 {
                            let mut beginning_buffer = vec![0u8; keep_at_beginning as usize];
                            self.read_from_chunk(other_chunk, 0, &mut beginning_buffer)?;
                            block_writer.write_data(0, &beginning_buffer)?;
                        }

                        // Write new data
                        let buffer_slice = &buffer[write_offset_in_buffer as usize..][..size_to_write as usize];
                        block_writer.write_data(keep_at_beginning, buffer_slice)?;

                        if keep_at_tail > 0 {
                            let mut tail_buffer = vec![0u8; keep_at_tail as usize];
                            self.read_from_chunk(other_chunk, chunk_len - keep_at_tail, &mut tail_buffer)?;
                            block_writer.write_data(keep_at_beginning + size_to_write, &tail_buffer)?;
                        }

                        block_writer.write_header(&BlockChunkHeader {
                            id: uuid,
                            len: total_size,
                        })?;

                        new_chunks.push(ChunkRef::InProgressBlock(InProgressBlockChunkRef {
                            id: uuid,
                            len: total_size,
                        }));
                    } else {
                        // For small writes, just create an Inline chunk
                        let mut inline_data = Vec::with_capacity(chunk_len as usize);

                        if keep_at_beginning > 0 {
                            let mut beginning_buffer = vec![0u8; keep_at_beginning as usize];
                            self.read_from_chunk(other_chunk, 0, &mut beginning_buffer)?;
                            inline_data.extend_from_slice(&beginning_buffer);
                        }

                        // Add new inline data
                        let buffer_slice = &buffer[write_offset_in_buffer as usize..][..size_to_write as usize];
                        inline_data.extend_from_slice(buffer_slice);

                        if keep_at_tail > 0 {
                            let mut tail_buffer = vec![0u8; keep_at_tail as usize];
                            self.read_from_chunk(other_chunk, chunk_len - keep_at_tail, &mut tail_buffer)?;
                            inline_data.extend_from_slice(&tail_buffer);
                        }

                        new_chunks.push(ChunkRef::Inline(inline_data));
                    }
                    current_offset = chunk_end_excl;
                }
            }
            
            current_offset = chunk_end_excl;
        }
        
        // Handle write extending past end of file
        // Only do this if we haven't already handled it by extending an InProgressBlock
        if current_offset < write_end_excl {
            let remaining = write_end_excl - current_offset;
            let buffer_offset = buffer.len() - remaining as usize;
            new_chunks.push(ChunkRef::Inline(buffer[buffer_offset..].to_vec()));
        }
        
        Ok(FileContent::Chunks(new_chunks))
    }



    pub fn copy_range(&self, from: &FileContent, to: &FileContent, src_offset: u64, dest_offset: u64, size: u64) -> Result<FileContent, ErrorKinds> {
        let FileContent::Chunks(from_chunks) = from;
        let FileContent::Chunks(to_chunks) = to;
        
        let mut new_chunks = Vec::new();
        let mut src_pos = 0u64;
        let mut dst_pos = 0u64;
        let mut src_remaining = size;
        let src_end = src_offset + size;
        let dst_end = dest_offset + size;

        // Copy over chunks before the destination offset
        for chunk in to_chunks {
            let chunk_len = chunk.len();
            if dst_pos + chunk_len <= dest_offset {
                new_chunks.push(chunk.clone());
                dst_pos += chunk_len;
                continue;
            }
            break;
        }

        // Process chunks that overlap with the copy range
        while src_remaining > 0 && dst_pos < dst_end {
            // Find current source chunk
            let mut src_chunk = None;
            let mut src_chunk_start = 0u64;
            for chunk in from_chunks {
                let chunk_len = chunk.len();
                if src_chunk_start + chunk_len > src_pos {
                    src_chunk = Some(chunk);
                    break;
                }
                src_chunk_start += chunk_len;
            }

            // Find current destination chunk
            let mut dst_chunk = None;
            let mut dst_chunk_start = dst_pos;
            for chunk in to_chunks {
                let chunk_len = chunk.len();
                if dst_chunk_start + chunk_len > dst_pos {
                    dst_chunk = Some(chunk);
                    break;
                }
                dst_chunk_start += chunk_len;
            }

            match (src_chunk, dst_chunk) {
                (Some(src_chunk), Some(ChunkRef::InProgressBlock(dst_block))) => {
                    // Try efficient copy if source is a Block or InProgressBlock
                    match src_chunk {
                        ChunkRef::Block(BlockChunkRef {id:src_block_id, len: src_block_len}) | ChunkRef::InProgressBlock(InProgressBlockChunkRef {id:src_block_id, len: src_block_len}) => {
                            let src_writer = self.writer.read_block(matches!(src_chunk, ChunkRef::InProgressBlock(_)), src_block_id)?;
                            let dst_writer = self.writer.write_block(true, &dst_block.id)?;
                            
                            let src_chunk_offset = src_offset - src_chunk_start;
                            let dst_chunk_offset = dest_offset - dst_chunk_start;
                            let copy_size = std::cmp::min(
                                src_remaining,
                                std::cmp::min(
                                    src_block_len - src_chunk_offset,
                                    dst_block.len - dst_chunk_offset
                                )
                            );

                            copy_file_range(
                                &src_writer.file,
                                BlockChunk::OFFSET_OF_ACTUAL_DATA as u64 + src_chunk_offset,
                                &dst_writer.file,
                                BlockChunk::OFFSET_OF_ACTUAL_DATA as u64 + dst_chunk_offset,
                                copy_size
                            )?;

                            new_chunks.push(ChunkRef::InProgressBlock(dst_block.clone()));
                            src_remaining -= copy_size;
                            src_pos += copy_size;
                            dst_pos += copy_size;
                        },
                        _ => {
                            // Fallback to read+write for other source chunk types
                            let mut buffer = vec![0u8; src_remaining as usize];
                            self.read_from_chunk(src_chunk, src_offset - src_chunk_start, &mut buffer)?;
                            let new_chunks = self.write_to_chunk(dst_chunk, dest_offset - dst_chunk_start, &buffer)?;
                            for c in new_chunks {
                                new_chunks.push(c);
                            }
                            src_remaining = 0;
                            break;
                        }
                    }
                },
                (Some(_), Some(_)) => {
                    // Neither chunk is an InProgressBlock, fallback to buffer copy
                    let mut buffer = vec![0u8; src_remaining as usize];
                    self.read(from, src_offset, &mut buffer)?;
                    let new_content = self.write(to, dest_offset, &buffer)?;
                    return Ok(new_content);
                },
                _ => break, // Ran out of source or destination chunks
            }
        }

        // Copy remaining chunks after the copy range
        for chunk in to_chunks {
            let chunk_len = chunk.len();
            if dst_pos >= dst_end {
                new_chunks.push(chunk.clone());
            }
            dst_pos += chunk_len;
        }



        Ok(FileContent::Chunks(new_chunks))
    }

    pub fn zero_range(&self, file: &FileContent, offset: u64, size: u64) -> Result<FileContent, ErrorKinds> {

        // zero a range in a File. The File may consist of multiple Chunks.
        // If the range intersects with an `InProgressBlock`, then:
        //   * if the range overlaps the tail end of the block, trim the size of the block.
        //   * if it overlaps with the front, or the middle of the block, just zero the range inside the InProgressBlock.
        //
        //   (rz = range-to-zero)
        //
        //   [---][--InProgressBlock--]
        //     [-rz-----]
        //  =[--0][00000--------------]

        //   (rz = range-to-zero)
        //   [---][--InProgressBlock--]
        //            [-rz-----]
        //  =[---][----00000000-------]


        //   (rz = range-to-zero)
        //   [---][--InProgressBlock--]
        //                       [-rz-----]
        //  =[---][-------------][00000000]
        //  (InProgress-Block is shrunk, "Zero" block is appended)


        let FileContent::Chunks(chunks) = file;
        let mut new_chunks = Vec::new();
        let mut current_offset = 0u64;
        // range end !exclusive!
        let range_end_excl = offset + size;

        for chunk in chunks {
            let chunk_begin = current_offset;
            let chunk_len = chunk.len();
            let chunk_end_excl = current_offset + chunk_len;

            if chunk_end_excl <= offset {
                // This chunk is entirely before the zero range
                new_chunks.push(chunk.clone());
                current_offset = chunk_end_excl;
                continue;
            }

            if current_offset >= range_end_excl {
                // This chunk is entirely after the zero range
                new_chunks.push(chunk.clone());
                current_offset = chunk_end_excl;
                continue;
            }

            if chunk_begin >= offset && chunk_end_excl <= range_end_excl {
                // this chunk is entirely inside the range to zero, discard it
                new_chunks.push(ChunkRef::Zero(chunk_len));
                current_offset = chunk_end_excl;
                // todo: if it is a file-based chunk, decrement the ref count or delete it
                continue;
            }

            // we have a partial overlap. As drawn at the beginning, there are three cases, range overlaps the beginning, range overlaps the middle, range overlaps the end
            let keep_at_beginning = if offset > chunk_begin { offset - chunk_begin } else { 0 };
            let keep_at_tail = if range_end_excl < chunk_end_excl { chunk_end_excl - range_end_excl } else { 0 };
            // how much of the zero-range overlaps with this chunk
            let size_of_overlapping_zero_range = std::cmp::min(range_end_excl, chunk_end_excl) - std::cmp::max(offset, chunk_begin);

            match chunk {
                ChunkRef::Zero(_) => {
                    // zero overlapping zero is zero
                    new_chunks.push(ChunkRef::Zero(chunk_len));
                    current_offset += chunk_len;
                },
                ChunkRef::Inline(data) => {
                    if keep_at_beginning > 0 {
                        new_chunks.push(ChunkRef::Inline(data[..keep_at_beginning as usize].to_vec()));
                    }

                    new_chunks.push(ChunkRef::Zero(size_of_overlapping_zero_range));

                    if keep_at_tail > 0 {
                        new_chunks.push(ChunkRef::Inline(data[(chunk_len - keep_at_tail) as usize ..].to_vec()));
                    }
                    current_offset += chunk_len;
                },
                ChunkRef::Block(block_ref) => {

                    if keep_at_beginning > 0 {
                        new_chunks.push(ChunkRef::Window(WindowedChunkRef{base: block_ref.clone(), range: Range { offset: 0, len: keep_at_beginning }}));
                    }

                    new_chunks.push(ChunkRef::Zero(size_of_overlapping_zero_range));

                    if keep_at_tail > 0 {
                        new_chunks.push(ChunkRef::Window(WindowedChunkRef{base: block_ref.clone(), range: Range { offset: chunk_len - keep_at_tail, len: keep_at_tail }}));
                    }
                    current_offset += chunk_len;
                },
                ChunkRef::Window(windowed_ref) => {
                    if keep_at_beginning > 0 {
                        new_chunks.push(ChunkRef::Window(WindowedChunkRef{
                            base: windowed_ref.base.clone(),
                            range: Range { 
                                offset: windowed_ref.range.offset,
                                len: keep_at_beginning
                            }
                        }));
                    }

                    new_chunks.push(ChunkRef::Zero(size_of_overlapping_zero_range));

                    if keep_at_tail > 0 {
                        new_chunks.push(ChunkRef::Window(WindowedChunkRef{
                            base: windowed_ref.base.clone(),
                            range: Range { 
                                offset: windowed_ref.range.offset + (chunk_len - keep_at_tail),
                                len: keep_at_tail
                            }
                        }));
                    }
                    current_offset += chunk_len;
                },
                ChunkRef::InProgressBlock(block_ref) => {
                    let mut block_writer = self.writer.write_block(true, &block_ref.id)?;
                    // if the range-to-be-zeroed extends over the end of the block ..
                    if keep_at_tail == 0 {
                        // keep the beginning of the chunk, and just trim off the end
                        block_writer.resize_data(keep_at_beginning)?;
                        block_writer.write_header(&BlockChunkHeader { id: block_ref.id, len: keep_at_beginning })?;
                        new_chunks.push(ChunkRef::InProgressBlock(InProgressBlockChunkRef { id: block_ref.id, len: keep_at_beginning }));
                        new_chunks.push(ChunkRef::Zero(size_of_overlapping_zero_range));
                        current_offset += chunk_len;
                    } else {
                        // write the zero-range directly into the block
                        block_writer.write_data_zero_range(keep_at_beginning, size_of_overlapping_zero_range)?;
                        new_chunks.push(ChunkRef::InProgressBlock(block_ref.clone()));
                        current_offset += chunk_len;
                    }
                }
            }
        }

        // If the zero range extends beyond the end of the file, add a final zero chunk
        if current_offset < range_end_excl {
            new_chunks.push(ChunkRef::Zero(range_end_excl - current_offset));
        }

        Ok(FileContent::Chunks(new_chunks))
    }

    /// merge adjacent Zero ranges, merge adjacent Inline chunks
    pub fn optimize_file(&self, file: &FileContent) -> MyResult<FileContent> {
        let FileContent::Chunks(chunks) = file;
        if chunks.is_empty() {
            return Ok(FileContent::Chunks(vec![]));
        }

        let mut optimized = Vec::new();
        let mut current_chunk: Option<ChunkRef> = None;

        for chunk in chunks {
            match (&current_chunk, chunk) {
                // Merge adjacent Zero chunks
                (Some(ChunkRef::Zero(current_size)), ChunkRef::Zero(additional_size)) => {
                    current_chunk = Some(ChunkRef::Zero(current_size + additional_size));
                },
                
                // Merge adjacent Inline chunks
                (Some(ChunkRef::Inline(current_data)), ChunkRef::Inline(additional_data)) => {
                    let mut merged_data = current_data.clone();
                    merged_data.extend_from_slice(additional_data);
                    current_chunk = Some(ChunkRef::Inline(merged_data));
                },
                
                // Handle transition to new chunk
                (Some(previous_chunk), current) => {
                    optimized.push(previous_chunk.clone());
                    current_chunk = Some(current.clone());
                },
                
                // Handle first chunk
                (None, current) => {
                    current_chunk = Some(current.clone());
                }
            }
        }

        // Don't forget to push the last chunk
        if let Some(last_chunk) = current_chunk {
            optimized.push(last_chunk);
        }

        Ok(FileContent::Chunks(optimized))
    }

}

// ------------------------

