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

// #[derive(Serialize, Deserialize)]
// pub enum ChunkKind {
//     Block,
//     Overlay,
//     /// Important Note: an in-progress chunk will be modified in-place and must not be shared between different files!
//     InProgress,
//     /// note: a zero chunk is not actually written to disk
//     Zero
// }

// impl ChunkKind {
//     pub fn to_path_segment(&self) -> &str {
//         match &self {
//             ChunkKind::Block => "blocks",
//             ChunkKind::Overlay => "overlays",
//             ChunkKind::InProgress => "in-progress",
//             ChunkKind::Zero => {
//                 error!("'to_path_segment' is being called for a 'zero' chunk. This does not make sense, zero chunks are never written to disk.");
//                 "zero"
//             }
//         }
//     }
// }

// #[derive(Serialize, Deserialize)]
// pub struct ModifiedRange {
//     pub offset: usize,
//     pub buffer: Vec<u8>
// }

// /// Important Note: an in-progress chunk will be modified in-place and must not be shared between different files!
// #[derive(Serialize, Deserialize)]
// pub enum InProgressChunk{
//     Raw(Vec<u8>),
//     Overlay(ChunkRef, Vec<ModifiedRange>)
// }



#[derive(Serialize, Deserialize)]
pub struct BlockChunk {
    /// note: the id is the hash of the content
    pub id: ChunkId,
    pub data: Vec<u8>
}

// note: the way bincode works, 'len' in this struct maps to the length of the vector 'data' in the serialized representation of BlockChunk
#[derive(Serialize, Deserialize)]
pub struct BlockChunkHeader {
    pub id: ChunkId,
    pub len: usize,
}

impl BlockChunkHeader {
    const SIZE : usize = 24;

    #[cfg(test)]
    #[test]
    pub fn test_size_of() {
        let header = BlockChunkHeader {
            id: [0; 16],
            len: 0,
        };
        assert_eq!(bincode::serialize(&header).unwrap().len(), SIZE);
    }
}

impl BlockChunk {
    const OFFSET_OF_ACTUAL_DATA : usize = BlockChunkHeader::SIZE;

    
    #[cfg(test)]
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
}

// #[derive(Serialize, Deserialize)]
// pub struct InProgressChunkHeader {
//     /// random uuid
//     pub id: ChunkId,
//     pub len: usize,
//     /// just for informational purposes
//     pub owning_inode: Inode
// }

// impl InProgressChunkHeader {
//     const SIZE : usize = 32;

//     #[cfg(test)]
//     #[test]
//     pub fn test_size_of() {
//         let header = InProgressChunkHeader {
//             id: [0; 16],
//             len: 0,
//             owning_inode: 0
//         };
//         assert_eq!(bincode::serialize(&header).unwrap().len(), SIZE);
//     }
// }

// #[derive(Serialize, Deserialize)]
// pub struct InProgressChunk {
//     pub header: InProgressChunkHeader,
//     pub data: Vec<u8>
// }

// impl InProgressChunk {
//     const OFFSET_OF_DATA_FIELD : usize = InProgressChunkHeader::SIZE;
//     const SIZE_OF_DATA_FIELD_LENGTH : usize = 8; // a Vec<T> is serialized as first 8 bytes (64 bit) length, then the content
//     const OFFSET_OF_ACTUAL_DATA : usize = OFFSET_OF_DATA_FIELD + SIZE_OF_DATA_LENGTH;
// }

#[derive(Serialize, Deserialize)]
pub struct Range {
    pub offset: usize,
    pub len: usize
}

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

#[derive(Serialize, Deserialize)]
pub struct BlockChunkRef {
    /// the hash of the data chunk
    pub id: ChunkId,
    /// note: this len MUST match exactly with the length of the chunk that is referenced.
    /// It is duplicated here so we don't need to actually open the chunk to find out the length.
    pub len: usize,    
}

#[derive(Serialize, Deserialize)]
pub struct WindowedChunkRef {
    pub base: BlockChunkRef,
    pub range: Range,
}

pub struct InProgressBlockChunkRef {
    pub block_id: ChunkId,
    pub len: usize,
}

#[derive(Serialize, Deserialize)]
pub enum ChunkRef {
    Zero(usize),
    Inline(Vec<u8>),
    Block(BlockChunkRef),
    Window(WindowedChunkRef),
    InProgressBlock(BlockChunkRef)
}

impl ChunkRef {
    pub fn len(&self) -> usize {
        match self {
            ChunkRef::Zero(size) => *size,
            ChunkRef::Inline(data) => data.len(),
            ChunkRef::Block(block_ref) => block_ref.len,
            ChunkRef::Window(windowed_ref) => windowed_ref.range.len,
            ChunkRef::InProgressBlock(in_progress_ref) => in_progress_ref.len,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum FileContent {
    Chunks(Vec<ChunkRef>),
    // note: an empty file would be represented as "Chunks([])"
}

impl FileContent {

    pub const EMPTY: FileContent = FileContent::Chunks(vec![]);

    pub fn chunks<'a>(&'a self) -> &'a Vec<ChunkRef> {
        let FileContent::Chunks(chunks) = self;
        chunks
    }

    pub fn len(&self) -> usize {
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

pub enum RepositoryError {
    IOError(io::Error),
    DeserializationError(bincode::ErrorKind)
}

impl From<io::Error> for RepositoryError {
    fn from(error: io::Error) -> Self {
        RepositoryError::IOError(error)
    }
}

impl From<bincode::ErrorKind> for RepositoryError {
    fn from(error: bincode::ErrorKind) -> Self {
        RepositoryError::DeserializationError(error)
    }
}

impl From<Box<bincode::ErrorKind>> for RepositoryError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        RepositoryError::DeserializationError(*error)
    }
}

pub struct BlockChunkWriter {
    file: File
}

impl BlockChunkWriter {
    pub fn new(file: File) -> Self {
        Self { file }
    }

    pub fn read_header(&mut self) -> Result<BlockChunkHeader, RepositoryError> {
        let mut buffer = [0u8;BlockChunkHeader::SIZE];
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_exact(&buffer)?;
        let header: BlockChunkHeader = bincode::deserialize(&buffer)?;

        // if debug?
        {
            let file_size = self.file.metadata()?.len();
            let header_size = header.len;
            assert_eq!(file_size as usize, header_size + BlockChunk::OFFSET_OF_ACTUAL_DATA);
        }

        return Ok(header);
    }

    pub fn read_data(&mut self, offset: usize, buffer: &mut [u8]) -> Result<(), io::Error> {
        self.file.seek(SeekFrom::Start((BlockChunk::OFFSET_OF_ACTUAL_DATA + offset) as u64))?;
        self.file.read_exact(buffer)?;
        Ok(())
    }

    pub fn write_header(&mut self, header: &BlockChunkHeader) -> Result<(), RepositoryError> {
        let serialized = bincode::serialize(header)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&serialized)?;
        Ok(())
    }

    pub fn write_data(&mut self, offset: usize, buffer: &[u8]) -> Result<(), io::Error> {
        self.file.seek(SeekFrom::Start((BlockChunk::OFFSET_OF_ACTUAL_DATA + offset) as u64))?;
        self.file.write_all(buffer)?;
        Ok(())
    }

    pub fn calculate_hash(&mut self) -> io::Result<ChunkId> {
        let hash: ChunkId = todo!();

        Ok(hash)
    }

    /// resize the file. this does not update the header!
    /// Call write_header afterwards!
    pub fn resize_data(&mut self, new_len: usize) -> io::Result<()> {
        let new_total_len = BlockChunkHeader::SIZE + new_len;
        self.file.set_len(new_total_len as u64)?;
        Ok(())
    }
}

// ------------------------

pub struct FilesystemWriter {
    data_dir: PathBuf
}

impl FilesystemWriter {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir
        }
    }

    pub fn init(&self) -> io::Result<()> {
        fs::create_dir_all(Path::new(&self.data_dir).join("meta"))?;
        fs::create_dir_all(Path::new(&self.data_dir).join("inodes"))?;
        fs::create_dir_all(Path::new(&self.data_dir).join("contents"))?;

        fs::create_dir_all(Path::new(&self.data_dir).join("contents").join("blocks"))?;
        fs::create_dir_all(Path::new(&self.data_dir).join("contents").join("in-progress"))?;

        Ok(())
    }

    // --------------------------------------------------------------

    fn hash_to_pathsegment(id: &ChunkId) -> PathBuf {
        PathBuf::from(format!("{:x?}", id))
    }

    #[cfg(test)]
    #[test]
    pub fn test_hash_to_pathsegment() {
        let testcases = vec![
            ([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f], "0010102030405060708090a0b0c0d0e0f")
        ];

        for tc in testcases {
            let (input, expected) = tc;
            let actual = Self::hash_to_pathsegment(&input);
            assert_eq!(actual, expected);
        }
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        OpenOptions::new().read(true).open(path.as_ref())
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        OpenOptions::new().write(true).open(path.as_ref())
    }

    fn create<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.as_ref())
    }

    fn inode_path(&self, inode: Inode) -> PathBuf {
        let path = Path::new(&self.data_dir)
            .join("inodes")
            .join(inode.to_string());
        return path;
    }

    // --------------------------------------------------------------

    pub fn get_inode(&self, inode: Inode) -> io::Result<InodeEntry> {
        let path = self.inode_path(inode);
        let file = self.open_read(path)?;
        Ok(bincode::deserialize_from(file).unwrap())
    }

    pub fn write_inode(&self, ino: Inode, content: &InodeEntry) -> io::Result<()>  {
        assert!(ino == content.attrs.inode);
        let path = self.inode_path(ino);
        let file = self.open_write(path)?;
        bincode::serialize_into(file, content).unwrap();
        Ok(())
    }

    // --------------------------------------------------------------

    fn block_path(&self, is_in_progress:bool, cref: &BlockChunkRef) -> PathBuf {
        let subdir = if is_in_progress { "" } else { "" };
        let path = Path::new(&self.data_dir)
            .join("contents")
            .join(subdir)
            .join(Self::hash_to_pathsegment(&cref.id));
        return path;
    }

    // Blocks
    // ----------------------

    pub fn read_block(&self, is_in_progress:bool, cref: &BlockChunkRef) -> io::Result<BlockChunkWriter> {
        let path = self.block_path(is_in_progress, cref);
        let file = self.open_read(path)?;
        Ok(BlockChunkWriter::new(file))
    }

    pub fn write_block(&self, is_in_progress: bool, cref: &BlockChunkRef) -> io::Result<BlockChunkWriter> {        
        let path = self.block_path(is_in_progress, cref);
        let file = self.open_write(path)?;
        Ok(BlockChunkWriter::new(file))
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

    pub fn meta_get_next_inode(&self) -> Result<Inode, RepositoryError> {

        let path = self.get_meta_path(Self::META_NEXT_INODE);

        let current_inode: Inode =
            match self.open_read(&path) {
                Ok(file) => bincode::deserialize_from(file)?,
                Err(err) => {
                    match err.kind() {
                        ErrorKind::NotFound => 1,
                        // note: if the file becomes corrupt, no more inodes can be allocated, so no new files or directories can be created.
                        //       at the very least, an expressive error message should be bubbled up to the user, and a "repair" command be added to the cli
                        //       which would just scan the whole filesystem and reset it to the highest found value
                        _ => return Err(err.into())
                    }
                }
            };


        // do an atomic replace of the file
        let tmp_path = path.with_added_extension(".tmp");
        let writer = self.create(&tmp_path)?;
        bincode::serialize_into(writer, &(current_inode + 1))?;
        fs::rename(tmp_path, path)?;

        Ok(current_inode + 1)
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
            writer: FilesystemWriter{data_dir}
        }
    }

    pub fn init(&self) {
        self.writer.init();
    }


    pub fn get_inode(&self, ino: Inode) -> io::Result<InodeEntry> {
        self.writer.get_inode(ino)
    }

    pub fn write_inode(&self, ino: Inode, content: &InodeEntry) -> io::Result<()>  {
        self.writer.write_inode(ino, content)
    }

    fn truncate_chunk(&self, chunk: &ChunkRef, truncated_size: u64) -> Result<ChunkRef, RepositoryError> {
        if truncated_size == chunk.len() {
            return Ok(*chunk);
        }
        assert!(truncated_size < chunk.len());

        match chunk {
            ChunkRef::Zero(_) => {
                return Ok(ChunkRef::Zero(truncated_size));
            },
            ChunkRef::Inline(data) => {
                return Ok(ChunkRef::Inline(data[..truncated_size].to_vec()));
            },
            ChunkRef::Block(block_chunk_ref) => {
                return Ok(ChunkRef::Window(WindowedChunkRef { base: *block_chunk_ref, range: Range { offset: 0, len: truncated_size } }));
            },
            ChunkRef::Window(window_chunk_ref) => {
                return Ok(ChunkRef::Window(WindowedChunkRef { base: window_chunk_ref.base, range: Range { offset: window_chunk_ref.range.offset, len: truncated_size } }));
            },
            ChunkRef::InProgressBlock(in_progress_block_ref) => {
                let mut block_writer = self.writer.write_block(true, in_progress_block_ref)?;
                let mut block_header = block_writer.read_header()?;
                assert_eq!(block_header.id, in_progress_block_ref.id);
                block_writer.resize_data(truncated_size);
                block_header.len = truncated_size;
                block_writer.write_header(&block_header);

                return Ok(ChunkRef::InProgressBlock(*in_progress_block_ref));
            },
        }
    }

    pub fn change_content_len(&self, old_content: FileContent, new_length: u64) -> Result<FileContent, RepositoryError> {
        if new_length == old_content.len() {
            return Ok(old_content);
        } else if new_length == 0 {
            return Ok(FileContent::Chunks(vec![]));
        } else if new_length > old_content.len() {
            // expand
            let expand_by = new_length - old_content.len();
            let mut new_chunks = old_content.chunks().clone();
            new_chunks.push(ChunkRef::Zero(expand_by));
            return Ok(FileContent::Chunks(new_chunks));
        } else /* new length < old length */ {
            // shrink
            let mut accumulated_len = 0;
            let mut new_chunks = Vec::new();
            
            // Keep chunks until we reach the new length
            for chunk in old_content.chunks() {
                let chunk_len = chunk.len();
                
                if accumulated_len + chunk_len > new_length {
                    // This chunk needs to be truncated
                    let truncated_len = new_length - accumulated_len;
                    let truncated_chunk = self.truncate_chunk(chunk, truncated_len)?;
                    new_chunks.push(truncated_chunk);
                    break;
                } else {
                    // Keep this chunk as-is
                    new_chunks.push(chunk.clone());
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

    pub fn allocate_next_inode(&self) -> io::Result<Inode> {
        self.writer.meta_get_next_inode()
    }

    pub fn read(&self, fc: &FileContent, offset: u64, buffer: &[u8]) -> io::Result<()> {
        todo!()
    }

    pub fn write(&self, fc: &FileContent, offset: u64, buffer: &[u8]) -> io::Result<FileContent> {
        todo!()
    }

    pub fn copy_range(&self, from: &FileContent, to: &FileContent,         src_offset: i64,
        dest_offset: i64,
        size: u64) -> Result<FileContent, RepositoryError> {
            todo!()
        }
}

// ------------------------

