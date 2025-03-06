use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::errors::{MyError, MyResult};

pub trait Len {
    fn len(&mut self) -> MyResult<u64>;
}

pub trait SetLen {
    fn set_len(&mut self, size: u64) -> MyResult<()>;
}

pub trait Finalize {
    fn finalize(&mut self) -> MyResult<()>;
}

pub trait Capabilities {
    /// can files be mutated? This includes writing data in the middle.
    fn can_mutate(&self) -> bool;
    /// can files be truncated?
    fn can_truncate(&self) -> bool;
    /// can files be renamed? This is probably implemented using 'move'.
    fn can_rename(&self) -> bool;
    /// can data be appended at the end?
    fn can_append(&self) -> bool;
}

pub trait TFile: Read + Write + Seek + Len + SetLen + Finalize {}

pub trait FS: Clone + Capabilities {
    type File: TFile;

    /// create all missing directories in the path, it does not fail if the dir already exists
    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()>;
    /// renames a file or directory, undefined behavior if `to` already exists.
    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()>;
    /// create a new file, truncating it if it already exists. The parent folder must already exist.
    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File>;
    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File>;
    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File>;

    /// zero a file range, extending the file if necessary, but failing if the start offset is after the current end of the file.
    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()>;
    /// copy data from the other file into this file
    fn copy_file_range(
        &self,
        src_file: &Self::File,
        src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64>;
}

// ------------------------------------------------------------------------------------------------------------------------

pub trait Snapshot {
    fn get_files(&self) -> Box<[Box<Path>]>;
    fn get_dirs(&self) -> Box<[Box<Path>]>;
    fn get_file_content(&self, path: &Box<Path>) -> MyResult<&Box<[u8]>>;
}

pub trait Snapshottable {
    type Snapshot: Snapshot;
    fn create_snapshot(&self) -> Self::Snapshot;
}

#[derive(PartialEq, Eq, Debug)]
pub struct SimpleSnapshot {
    files: HashMap<Box<Path>, Box<[u8]>>,
    dirs: Box<[Box<Path>]>,
}

impl SimpleSnapshot {
    pub fn new(files: HashMap<Box<Path>, Box<[u8]>>, dirs: Box<[Box<Path>]>) -> Self {
        Self { files, dirs }
    }
}

impl Snapshot for SimpleSnapshot {
    fn get_files(&self) -> Box<[Box<Path>]> {
        self.files
            .keys()
            .map(|k| k.clone())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    fn get_dirs(&self) -> Box<[Box<Path>]> {
        self.dirs.clone()
    }

    fn get_file_content(&self, path: &Box<Path>) -> MyResult<&Box<[u8]>> {
        match self.files.get(path) {
            Some(content) => Ok(content),
            None => Err(MyError::new_io(io::ErrorKind::NotFound, "File not found")),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum Change {
    CreatedFile(Box<Path>),
    RemovedFile(Box<Path>),
    ModifiedFile(Box<Path>),
    CreatedDir(Box<Path>),
    RemovedDir(Box<Path>),
}

pub fn get_snapshot_delta(before: &dyn Snapshot, after: &dyn Snapshot) -> Box<[Change]> {
    let mut changes = Vec::new();

    let before_files: HashSet<_> = before.get_files().iter().map(|p| p.clone()).collect();
    let after_files: HashSet<_> = after.get_files().iter().map(|p| p.clone()).collect();
    let before_dirs: HashSet<_> = before.get_dirs().iter().map(|p| p.clone()).collect();
    let after_dirs: HashSet<_> = after.get_dirs().iter().map(|p| p.clone()).collect();

    for file in before_files.difference(&after_files) {
        changes.push(Change::RemovedFile((*file).clone()));
    }

    for file in after_files.difference(&before_files) {
        changes.push(Change::CreatedFile((*file).clone()));
    }

    for file in before_files.intersection(&after_files) {
        let (before_content, after_content) = (
            before.get_file_content(file).unwrap(),
            after.get_file_content(file).unwrap(),
        );
        if *before_content != *after_content {
            changes.push(Change::ModifiedFile((*file).clone()));
        }
    }

    for dir in before_dirs.difference(&after_dirs) {
        changes.push(Change::RemovedDir((*dir).clone()));
    }

    for dir in after_dirs.difference(&before_dirs) {
        changes.push(Change::CreatedDir((*dir).clone()));
    }

    changes.into_boxed_slice()
}

// ------------------------------------------------------------------------------------------------------------------------

// pub trait DynCompatibleFS : Capabilities {
//     /// create all missing directories in the path, it does not fail if the dir already exists
//     fn create_dir_all(&self, path: &dyn AsRef<Path>) -> MyResult<()>;
//     /// renames a file or directory, undefined behavior if `to` already exists.
//     fn rename(&self, from: &dyn AsRef<Path>, to: &dyn AsRef<Path>) -> MyResult<()>;
//     /// create a new file, truncating it if it already exists. The parent folder must already exist.
//     fn create(&self, path: &dyn AsRef<Path>) -> MyResult<Box<Self::File>>;

//     fn open_read(&self, path: &dyn AsRef<Path>) -> MyResult<Box<Self::File>>;
//     fn open_write(&self, path: &dyn AsRef<Path>) -> MyResult<Box<Self::File>>;

//     /// zero a file range, extending the file if necessary, but failing if the start offset is after the current end of the file.
//     fn zero_file_range(&self, file: &Box<dyn TFile>, offset: u64, len: u64) -> MyResult<()>;
//     /// copy data from the other file into this file
//     fn copy_file_range(
//         &self,
//         src_file: &Box<dyn TFile>,
//         src_offset: u64,
//         dst_file: &Box<dyn TFile>,
//         dst_offset: u64,
//         len: u64,
//     ) -> MyResult<u64>;
// }

// pub struct DynWrapper<F:FS> {
//     fs: F
// }

// impl DynCompatibleFS for DynWrapper {

// }

// fn dummy_FS_dyn(fs: Box<dyn DynCompatibleFS>) {

// }
