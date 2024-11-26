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
    /overlays (content adressed chunks, containing a reference to another content and a set of modified areas)
    |-0xcde: ref(header(size), block-ref, modifications)
    |-0xab1
    |-...
*/

pub type OsStringBytes = Vec<u8>;

pub type Inode = u64;
/// the bytes of an OsString
pub type EntryName = OsStringBytes;
pub type DirectoryDescriptor = BTreeMap<EntryName, (Inode, FileKind)>;

pub type ChunkId = [u8;16];

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
}


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

#[derive(Serialize, Deserialize)]
pub enum ChunkKind {
    Block,
    Overlay
}

impl ChunkKind {
    pub fn to_path_segment(&self) -> &str {
        match &self {
            ChunkKind::Block => "blocks",
            ChunkKind::Overlay => "overlays"
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ChunkRef{
    /// the hash of the data chunk
    pub id: ChunkId,
    pub len: usize,
    pub kind: ChunkKind
}

#[derive(Serialize, Deserialize)]
pub enum FileContent {
    Inline(Vec<u8>),
    Chunks(Vec<ChunkRef>)
}


#[derive(Serialize, Deserialize)]
pub enum InodeContent {
    File(FileContent),
    Directory(DirectoryDescriptor),
    Symlink(OsStringBytes)
}

#[derive(Serialize, Deserialize)]
pub struct InodeEntry {
    pub attrs: InodeAttributes,
    pub content: InodeContent

}


// ------------------------

pub struct FilesystemWriter {
    data_dir: PathBuf
}

impl FilesystemWriter {
    pub fn new(data_dir: PathBuf) {
        Self {
            data_dir
        }
    }

    pub fn init(&self) {
        fs::create_dir_all(Path::new(&self.data_dir).join("inodes")).unwrap();
        fs::create_dir_all(Path::new(&self.data_dir).join("contents")).unwrap();
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        OpenOptions::new().read(true).open(path.as_ref())
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
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
    
    pub fn get_inode(&self, inode: Inode) -> io::Result<InodeEntry> {
        let path = self.inode_path(inode);
        let file = self.open_read(path)?;
        Ok(bincode::deserialize_from(file).unwrap())
    }
    
    pub fn write_inode(&self, ino: Inode, content: &InodeEntry) -> io::Result<()>  {
        assert(ino == content.attrs.inode);
        let path = self.inode_path(ino);
        let file = self.open_write(path)?;
        bincode::serialize_into(file, content).unwrap();
        Ok(())
    }

    fn content_path(&self, cref: ChunkRef) -> PathBuf {
        let path = Path::new(&self.data_dir)
            .join("contents")
            .join(cref.kind.to_path_segment())
            .join(cref.id);
        return path;
    }

    pub fn read_chunk(&self, cref: ChunkRef, offset: usize, buffer: &mut [u8]) -> io::Result<()> {
        let path = self.content_path(cref);
        let file = self.open_read(path)?;
        file.seek(offset);
        file.read_exact(buffer);
        Ok(())
    }
}


// ------------------------

pub struct RepositoryV1 {
    writer: FilesystemWriter
}

impl RepositoryV1 {
    pub fn new(data_dir: PathBuf) {
        Self {
            writer: FilesystemWriter{data_dir}
        }
    }

    pub fn init(&self) {
        self.writer.init();
    }

    
    pub fn get_inode(&self, ino: Inode) -> io::Result<InodeEntry> {
        self.writer.get_inode(inode)
    }

    pub fn write_inode(&self, ino: Inode, content: &InodeEntry) -> io::Result<()>  {
        self.writer.write_inode(ino, content)
    }


    pub fn change_content_len(&self, old_content: FileContent, new_length: u64) -> io::Result<FileContent> {
        todo!();
    }

    pub fn allocate_next_inode(&self) -> Inode {
        
        let path = Path::new(&self.data_dir).join("superblock");
        let current_inode = if let Ok(file) = File::open(&path) {
            bincode::deserialize_from(file).unwrap()
        } else {
            fuser::FUSE_ROOT_ID
        };

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        bincode::serialize_into(file, &(current_inode + 1)).unwrap();

        current_inode + 1
    }

    pub fn exists(&self, parent: Inode, name: &OsStr) -> bool {
        let ic = self.writer.get_inode(parent);

    }
}

// ------------------------


struct ContentStore {
    /// note: the base path *of the content store*, that is, this is <repo>/content
    base_path: PathBuf
}

impl ContentStore {
    fn new(base_path: PathBuf) -> Self {
        Self {
            base_path
        }
    }

    fn store(&mut self, data: &[u8]) -> String {
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize().to_hex();
        
        // Create path with hash prefix directories for better filesystem performance
        // e.g., "abc123" -> "ab/c1/23"
        let path = self.hash_to_path(&hash);
        
        // Store the data
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, data).unwrap();
        
        // Update index
        self.index.insert(hash.clone(), path);
        
        hash
    }

    fn get(&self, hash: &str) -> Option<Vec<u8>> {
        self.index.get(hash)
            .and_then(|path| std::fs::read(path).ok())
    }

    fn hash_to_path(&self, hash: &str) -> PathBuf {
        let mut path = self.base_path.clone();
        path.push(&hash[0..2]);
        path.push(&hash[2..4]);
        path.push(&hash[4..]);
        path
    }
}