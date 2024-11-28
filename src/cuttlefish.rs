// Note: this is modified from https://github.com/cberner/fuser/blob/d675c07ecb8e826467d53dc00b45a67c731d5b85/examples/simple.rs
// Copyright of the original: Christopher Berner and contributors to https://github.com/cberner/fuser
// License: MIT


#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)] // libc::S_* are u16 or u32 depending on the platform


use entropy::entropy_from_os;

use fuser::consts::FOPEN_DIRECT_IO;
#[cfg(feature = "abi-7-26")]
use fuser::consts::FUSE_HANDLE_KILLPRIV;
// #[cfg(feature = "abi-7-31")]
// use fuser::consts::FUSE_WRITE_KILL_PRIV;
use fuser::TimeOrNow::Now;
use fuser::{
    Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow,
    FileAttr,
    FUSE_ROOT_ID,
};
#[cfg(feature = "abi-7-26")]
use log::info;
use log::{debug, warn};
use log::{error, LevelFilter};
use serde::{Deserialize, Serialize};
use std::cmp::min;
use std::collections::BTreeMap;
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

use std::ops::Deref;

const BLOCK_SIZE: u64 = 512;
const MAX_NAME_LENGTH: u32 = 10_000;
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024; // 1 TB

const FMODE_EXEC: i32 = 0x20;

const ENCRYPTION_KEY_LENGTH: usize = 16;

use crate::repository;
use crate::crypt;
use crate::entropy;

use repository::repository_v1::*;

impl From<FileKind> for fuser::FileType {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::File => fuser::FileType::RegularFile,
            FileKind::Directory => fuser::FileType::Directory,
            FileKind::Symlink => fuser::FileType::Symlink,
        }
    }
}

#[derive(Debug)]
enum XattrNamespace {
    Security,
    System,
    Trusted,
    User,
}

fn parse_xattr_namespace(key: &[u8]) -> Result<XattrNamespace, c_int> {
    let user = b"user.";
    if key.len() < user.len() {
        return Err(libc::ENOTSUP);
    }
    if key[..user.len()].eq(user) {
        return Ok(XattrNamespace::User);
    }

    let system = b"system.";
    if key.len() < system.len() {
        return Err(libc::ENOTSUP);
    }
    if key[..system.len()].eq(system) {
        return Ok(XattrNamespace::System);
    }

    let trusted = b"trusted.";
    if key.len() < trusted.len() {
        return Err(libc::ENOTSUP);
    }
    if key[..trusted.len()].eq(trusted) {
        return Ok(XattrNamespace::Trusted);
    }

    let security = b"security";
    if key.len() < security.len() {
        return Err(libc::ENOTSUP);
    }
    if key[..security.len()].eq(security) {
        return Ok(XattrNamespace::Security);
    }

    return Err(libc::ENOTSUP);
}

fn clear_suid_sgid(attr: &mut InodeAttributes) {
    attr.mode &= !libc::S_ISUID as u16;
    // SGID is only suppose to be cleared if XGRP is set
    if attr.mode & libc::S_IXGRP as u16 != 0 {
        attr.mode &= !libc::S_ISGID as u16;
    }
}

fn creation_gid(parent: &InodeAttributes, gid: u32) -> u32 {
    if parent.mode & libc::S_ISGID as u16 != 0 {
        return parent.gid;
    }

    gid
}

fn xattr_access_check(
    key: &[u8],
    access_mask: i32,
    inode_attrs: &InodeAttributes,
    request: &Request<'_>,
) -> Result<(), c_int> {
    match parse_xattr_namespace(key)? {
        XattrNamespace::Security => {
            if access_mask != libc::R_OK && request.uid() != 0 {
                return Err(libc::EPERM);
            }
        }
        XattrNamespace::Trusted => {
            if request.uid() != 0 {
                return Err(libc::EPERM);
            }
        }
        XattrNamespace::System => {
            if key.eq(b"system.posix_acl_access") {
                if !check_access(
                    inode_attrs.uid,
                    inode_attrs.gid,
                    inode_attrs.mode,
                    request.uid(),
                    request.gid(),
                    access_mask,
                ) {
                    return Err(libc::EPERM);
                }
            } else if request.uid() != 0 {
                return Err(libc::EPERM);
            }
        }
        XattrNamespace::User => {
            if !check_access(
                inode_attrs.uid,
                inode_attrs.gid,
                inode_attrs.mode,
                request.uid(),
                request.gid(),
                access_mask,
            ) {
                return Err(libc::EPERM);
            }
        }
    }

    Ok(())
}

fn time_now() -> (i64, u32) {
    time_from_system_time(&SystemTime::now())
}

fn system_time_from_time(secs: i64, nsecs: u32) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs)
    } else {
        UNIX_EPOCH - Duration::new((-secs) as u64, nsecs)
    }
}

fn time_from_system_time(system_time: &SystemTime) -> (i64, u32) {
    // Convert to signed 64-bit time with epoch at 0
    match system_time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs() as i64, duration.subsec_nanos()),
        Err(before_epoch_error) => (
            -(before_epoch_error.duration().as_secs() as i64),
            before_epoch_error.duration().subsec_nanos(),
        ),
    }
}


impl From<InodeAttributes> for fuser::FileAttr {
    fn from(attrs: InodeAttributes) -> Self {
        fuser::FileAttr {
            ino: attrs.inode,
            size: attrs.size,
            blocks: (attrs.size + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: system_time_from_time(attrs.last_accessed.0, attrs.last_accessed.1),
            mtime: system_time_from_time(attrs.last_modified.0, attrs.last_modified.1),
            ctime: system_time_from_time(
                attrs.last_metadata_changed.0,
                attrs.last_metadata_changed.1,
            ),
            crtime: SystemTime::UNIX_EPOCH, // todo(macos)
            kind: attrs.kind.into(),
            perm: attrs.mode,
            nlink: attrs.hardlinks,
            uid: attrs.uid,
            gid: attrs.gid,
            rdev: 0, // todo(??)
            blksize: BLOCK_SIZE as u32,
            flags: 0, // todo(macos)
        }
    }
}

#[derive(Clone, Copy)]
struct FilePermissions {
    can_read: bool,
    can_write: bool,
}

#[derive(Clone, Copy)]
struct FileHandleEntry {
    inode: Inode,
    permissions: FilePermissions,
}

pub struct SimpleFsOptions {
    /// DANGEROUS
    pub create_fs_automatically_if_not_exist: bool,
    pub permutate_handle_values: bool,
    pub direct_io: bool,
    #[cfg(feature = "abi-7-26")]
    pub suid_support: bool,
}

impl SimpleFsOptions {
    pub fn default() -> Self {
        Self {
            create_fs_automatically_if_not_exist: false,
            permutate_handle_values: true,
            direct_io: false,
            #[cfg(feature = "abi-7-26")]
            suid_support: false
        }
    }
}

struct SimpleFsState {
    next_file_handle: AtomicU64,
    /// (optionally) run the file handle through a feistel network so the values are random and not continuous.
    fh_feistel: crypt::feistel::FeistelNetwork<u64, u32>,

    open_file_handles: RwLock<HashMap<u64, FileHandleEntry>>,

    global_lock: RwLock<()>,
}


pub struct SimpleFS {
    options: SimpleFsOptions,
    state: SimpleFsState,
    encryption_key: [u8;ENCRYPTION_KEY_LENGTH],
    repository: RepositoryV1,
}

impl SimpleFS {
    pub fn new(
        options: SimpleFsOptions,
        encryption_key: [u8;ENCRYPTION_KEY_LENGTH],
        data_dir: String,
    ) -> SimpleFS {

        let state = {
            let ent = entropy::entropy_from_os();
            let mut rng = entropy::rng_from_entropy(ent);
            let key = rng.next_u32();
            SimpleFsState {
                fh_feistel: crypt::feistel::FeistelNetwork::new(1, vec![key]),
                next_file_handle: AtomicU64::new(1),
                open_file_handles: RwLock::new(HashMap::new()),
                global_lock: RwLock::new(()),
            }
        };

        let repository_options = RepositoryOptions {
            max_inline_content_size: 1024*1024, // 1MB
        };
        let repository = RepositoryV1::new(data_dir.into(), repository_options);


        #[cfg(feature = "abi-7-26")]
        {
            SimpleFS {
                options,
                state,
                encryption_key,
                data_dir,
                direct_io,
                suid_support,
            }
        }
        #[cfg(not(feature = "abi-7-26"))]
        {
            SimpleFS {
                options,
                state,
                encryption_key,
                repository,
            }
        }
    }

    fn creation_mode(&self, mode: u32) -> u16 {
        #[cfg(feature = "abi-7-26")]
        let suid_support = self.suid_support;
        #[cfg(not(feature = "abi-7-26"))]
        let suid_support = false;

        if !suid_support {
            (mode & !(libc::S_ISUID | libc::S_ISGID) as u32) as u16
        } else {
            mode as u16
        }
    }

    fn allocate_next_file_handle(&self, inode: Inode, read: bool, write: bool) -> u64 {

        let mut fh = self.state.next_file_handle.fetch_add(1, Ordering::SeqCst);
        // Assert that we haven't run out of file handles
        assert!(fh < u64::MAX);

        if self.options.permutate_handle_values {
            // permutate fh so you can't guess the next handle (or previous ones)
            fh = self.state.fh_feistel.encrypt(fh);
        }

        // Store the permissions
        let mut handles = self.state.open_file_handles.write().unwrap();
        handles.insert(fh, FileHandleEntry { inode, permissions: FilePermissions { can_read: read, can_write: write }});

        fh
    }

    fn check_file_handle_read(&self, file_handle: u64, inode: Inode) -> bool {
        self.state.open_file_handles.read()
            .unwrap()
            .get(&file_handle)
            .map(|perms| perms.inode == inode && perms.permissions.can_read)
            .unwrap_or(false)
    }

    fn check_file_handle_write(&self, file_handle: u64, inode: Inode) -> bool {
        self.state.open_file_handles.read()
            .unwrap()
            .get(&file_handle)
            .map(|perms| perms.inode == inode && perms.permissions.can_write)
            .unwrap_or(false)
    }

    /// just a wrapper over 'repository.get_inode' that convers the io::Error into an error code
    fn get_inode(&self, inode: Inode) -> Result<InodeEntry, c_int> {
        return
          self.repository
            .get_inode(inode)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::ENOENT));
    }

    // Check whether a file should be removed from storage. Should be called after decrementing
    // the link count, or closing a file handle
    fn gc_inode(&self, inode: &InodeAttributes) -> bool {

        todo!();
        return false;
    }

    fn truncate(
        &self,
        ie: &mut InodeEntry,
        new_length: u64,
        uid: u32,
        gid: u32,
    ) -> Result<(), crate::errors::ErrorKinds> {
        if new_length > MAX_FILE_SIZE {
            Err(libc::EFBIG)?;
        }
        let mut attrs = &mut ie.attrs;

        if !check_access(attrs.uid, attrs.gid, attrs.mode, uid, gid, libc::W_OK) {
            Err(libc::EACCES)?;
        }

        let InodeContent::File(file_content) = &ie.content else {
             Err(libc::EISDIR)?
        };

        let new_content = self.repository.change_content_len(file_content, new_length)?;

        attrs.size = new_length;
        attrs.last_metadata_changed = time_now();
        attrs.last_modified = time_now();

        // Clear SETUID & SETGID on truncate
        clear_suid_sgid(&mut attrs);

        ie.content = InodeContent::File(new_content);
        self.repository.write_inode(ie.attrs.inode, &ie);

        Ok(())
    }

    fn try_find_directory_entry<'a>(parent: &'a DirectoryDescriptor,  name: &OsStr) -> Option<&'a (Inode, FileKind)> {
        parent.get(name.as_bytes())
    }

    #[must_use]
    fn assume_directory<'a>(content: &'a InodeContent) -> Result<&'a DirectoryDescriptor, c_int> {
        match content {
            InodeContent::File(_) | InodeContent::Symlink(_) => {
                return Err(libc::ENOTDIR);
            },
            InodeContent::Directory(dir_content) => {
                return Ok(dir_content);
            }
        };
    }

    #[must_use]
    fn assume_file<'a>(content: &'a InodeContent) -> Result<&'a FileContent, c_int> {
        match content {
            InodeContent::Directory(_) | InodeContent::Symlink(_) => {
                return Err(libc::EISDIR);
            },
            InodeContent::File(file_content) => {
                return Ok(file_content);
            }
        };
    }
    #[must_use]
    fn assume_directory_mut<'a>(content: &'a mut InodeContent) -> Result<&'a mut DirectoryDescriptor, c_int> {
        match content {
            InodeContent::File(_) | InodeContent::Symlink(_) => {
                return Err(libc::ENOTDIR);
            },
            InodeContent::Directory(dir_content) => {
                return Ok(dir_content);
            }
        };
    }

    #[must_use]
    fn assume_file_mut<'a>(content: &'a mut InodeContent) -> Result<&'a mut FileContent, c_int> {
        match content {
            InodeContent::Directory(_) | InodeContent::Symlink(_) => {
                return Err(libc::EISDIR);
            },
            InodeContent::File(file_content) => {
                return Ok(file_content);
            }
        };
    }

    #[must_use]
    fn require_not_exist(parent: &DirectoryDescriptor, name: &OsStr) -> Result<(), c_int> {
        if Self::try_find_directory_entry(parent, name).is_some() {
            return Err(libc::EEXIST);
        }
        return Ok(());
    }


    fn insert_link(
        &self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        inode: u64,
        kind: FileKind,
    ) -> Result<(), c_int> {
        let mut parent_node = self.get_inode(parent)?;
        let parent_attrs = &mut parent_node.attrs;

        let mut dir_content: &mut BTreeMap<Vec<u8>, (u64, FileKind)> = Self::assume_directory_mut(&mut parent_node.content)?;

        Self::require_not_exist(dir_content, name)?;


        check_access_rq(parent_attrs, req, libc::W_OK)?;


        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();

        dir_content.insert(name.as_bytes().to_vec(), (inode, kind));

        self.repository.write_inode(inode, &parent_node);

        Ok(())
    }
}


impl SimpleFS {
    pub fn create_fs(&mut self) -> Result<(), c_int> {
        self.repository.init();

        let existing_root_node = self.get_inode(FUSE_ROOT_ID);
        
        match existing_root_node {
            Ok(_) => {
                // fs already exists
                return Err(libc::EEXIST);
            },
            Err(libc::ENOENT) => {
                // file not found - great! let's create the repository

                // Initialize with empty filesystem
                let root_attr = InodeAttributes {
                    inode: FUSE_ROOT_ID,
                    // open_file_handles: 0,
                    size: 0,
                    last_accessed: time_now(),
                    last_modified: time_now(),
                    last_metadata_changed: time_now(),
                    kind: FileKind::Directory,
                    mode: 0o777, // ???
                    hardlinks: 2, // todo ???
                    uid: 0,
                    gid: 0,
                    xattrs: Default::default(),
                };
                let mut entries = BTreeMap::new();
                entries.insert(b".".to_vec(), (FUSE_ROOT_ID, FileKind::Directory));
                // todo: what about ".." ?
                let root_node = InodeEntry {attrs: root_attr, content: InodeContent::Directory(entries) };
                self.repository.write_inode(FUSE_ROOT_ID, &root_node);
                return Ok(())
            },
            Err(e) => return Err(e)
        };

    }
}

//
// -------------------------------------------------------------------------------------------------------------

impl Filesystem for SimpleFS {
    fn init(
        &mut self,
        _req: &Request,
        #[allow(unused_variables)] config: &mut KernelConfig,
    ) -> Result<(), c_int> {
        #[cfg(feature = "abi-7-26")]
        config.add_capabilities(FUSE_HANDLE_KILLPRIV).unwrap();

        self.repository.init();

        let existing_root_node = self.get_inode(FUSE_ROOT_ID);

        if let Err(e) = existing_root_node {
            
            if e == libc::ENOENT && self.options.create_fs_automatically_if_not_exist {
                self.create_fs()?;
            } else {
                return Err(e);
            }
        }

        Ok(())
    }

    fn lookup(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.lookup_syn(req, parent, name) {
            Ok(ok) => reply.entry(&ok.ttl, &ok.attrs, ok.generation),
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn forget(&mut self, _req: &Request, _ino: u64, _nlookup: u64) {}

    fn getattr(&mut self, _req: &Request, inode: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.repository.get_inode(inode) {
            Ok(ie) => reply.attr(&Duration::new(0, 0), &ie.attrs.into()),
            Err(error_code) => reply.error(*error_code),
        }
    }

    fn setattr(
        &mut self,
        req: &Request,
        inode: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        match self.setattr_syn(req, inode, mode, uid, gid, size, atime, mtime, _ctime, fh, _crtime, _chgtime, _bkuptime, _flags) {
            Ok(ok) => reply.attr(&ok.ttl, &ok.attrs),
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn readlink(&mut self, _req: &Request, inode: u64, reply: ReplyData) {
        debug!("readlink() called on {:?}", inode);
        let path = self.content_path(inode);
        if let Ok(mut file) = File::open(path) {
            let file_size = file.metadata().unwrap().len();
            let mut buffer = vec![0; file_size as usize];
            file.read_exact(&mut buffer).unwrap();
            reply.data(&buffer);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn mknod(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        match self.mknod_syn(req, parent, name, mode, _umask, _rdev) {
            Ok(ok) => {
                reply.entry(&ok.ttl, &ok.attrs, ok.generation);
            },
            Err(err_code) => {
                reply.error(err_code);
            }
        }
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        match self.mkdir_syn(req, parent, name, mode, _umask) {
            Ok(ok) => reply.entry(&ok.ttl, &ok.attrs, ok.generation),
            Err(error_code) => reply.error(*error_code)
        }
    }
    fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.unlink_syn(req, parent, name) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.rmdir_syn(req, parent, name) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn symlink(
        &mut self,
        req: &Request,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        match self.symlink_syn(req, parent, link_name, target) {
            Ok(ok) => {
                reply.entry(&ok.ttl, &ok.attrs, ok.generation);
            },
            Err(err_code) => {
                reply.error(err_code);
            }
        }
    }

    fn rename(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        match self.rename_syn(req, parent, name, new_parent, new_name, flags) {
            Ok(()) => {
                reply.ok();
            },
            Err(err_code) => {
                reply.error(err_code);
            }
        }
    }

    fn link(
        &mut self,
        req: &Request,
        inode: u64,
        new_parent: u64,
        new_name: &OsStr,
        reply: ReplyEntry,
    ) {
        match self.link_syn(req, inode, new_parent, new_name) {
            Ok(ok) => {
                reply.entry(&ok.ttl, &ok.attrs, ok.generation);
            },
            Err(err_code) => {
                reply.error(err_code);
            }
        }
    }

    fn open(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {

        match self.open_syn(req, inode, flags) {
            Ok(ok) => {
                reply.opened(ok.fh, ok.flags);
            },
            Err(err_code) => {
                reply.error(err_code);
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        match self.read_syn(_req, inode, fh, offset, size, _flags, _lock_owner) {
            Ok(ok) => {
                reply.data(&ok.buffer);
            },
            Err(err_code) => {
                reply.error(err_code);
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        match self.write_syn(_req, inode, fh, offset, data, _write_flags, flags, _lock_owner) {
            Ok(ok) => reply.written(ok.written),
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // Clean up file handle permissions when file is closed
        self.file_handles.write().unwrap().remove(&fh);

        if let Ok(mut attrs) = self.get_inode(inode) {
            attrs.open_file_handles -= 1;
        }
        reply.ok();
    }

    fn opendir(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        match self.opendir_syn(req, inode, flags) {
            Ok(ok) => reply.opened(ok.fh, ok.flags),
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        // Clean up file handle permissions when file is closed
        self.file_handles.write().unwrap().remove(&fh);

        debug!("readdir() called with {:?}", inode);
        assert!(offset >= 0);
        let entries = match self.get_directory_content(inode) {
            Ok(entries) => entries,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        for (index, entry) in entries.iter().skip(offset as usize).enumerate() {
            let (name, (inode, file_type)) = entry;

            let buffer_full: bool = reply.add(
                *inode,
                offset + index as i64 + 1,
                (*file_type).into(),
                OsStr::from_bytes(name),
            );

            if buffer_full {
                break;
            }
        }

        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        if let Ok(mut attrs) = self.get_inode(inode) {
            attrs.open_file_handles -= 1;
        }
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        warn!("statfs() implementation is a stub");
        // TODO: real implementation of this
        reply.statfs(
            10_000,
            10_000,
            10_000,
            1,
            10_000,
            BLOCK_SIZE as u32,
            MAX_NAME_LENGTH,
            BLOCK_SIZE as u32,
        );
    }

    fn setxattr(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
        value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        match self.setxattr_syn(request, inode, key, value, _flags, _position) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn getxattr(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        match self.getxattr_syn(request, inode, key, size) {
            Ok(ok) => {
                match ok {
                    ReplyXattrOk::Size(size) => reply.size(size),
                    ReplyXattrOk::Data(data) => reply.data(&data)
                }
            },
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn listxattr(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        size: u32,
        reply: ReplyXattr
    ) {
        match self.listxattr_syn(_req, inode, size) {
            Ok(ok) => {
                match ok {
                    ReplyXattrOk::Size(size) => reply.size(size),
                    ReplyXattrOk::Data(data) => reply.data(&data)
                }
            },
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn removexattr(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
        reply: ReplyEmpty
    ) {
        match self.removexattr_syn(request, inode, key) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn access(
        &mut self,
        req: &Request,
        inode: u64,
        mask: i32,
        reply: ReplyEmpty
    ) {
        match self.access_syn(req, inode, mask) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        match self.create_syn(req, parent, name, mode, _umask, flags) {
            Ok(ok) => reply.created(
                &ok.ttl,
                &ok.attrs,
                ok.generation,
                ok.fh,
                ok.flags
            ),
            Err(error_code) => reply.error(*error_code)
        }
    }

    #[cfg(target_os = "linux")]
    fn fallocate(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        _fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        match self.fallocate_syn(_req, inode, _fh, offset, length, mode) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(*error_code)
        }
    }

    fn copy_file_range(
        &mut self,
        _req: &Request<'_>,
        src_inode: u64,
        src_fh: u64,
        src_offset: i64,
        dest_inode: u64,
        dest_fh: u64,
        dest_offset: i64,
        size: u64,
        _flags: u32,
        reply: ReplyWrite,
    ) {
        match self.copy_file_range_syn(_req, src_inode, src_fh, src_offset, dest_inode, dest_fh, dest_offset, size, _flags) {
            Ok(ok) => reply.written(ok.written),
            Err(error_code) => reply.error(*error_code)
        }
    }
}
// ------------------------------------------------------------------------------------------
// impl Syn





type ReplyResult<T> = Result<T, ErrorKinds>;

struct ReplyEntryOk {
    ttl: Duration,
    attrs: FileAttr,
    generation: u64
}
type ReplyEntryResult = ReplyResult<ReplyEntryOk>;

type ReplyEmptyResult = ReplyResult<()>;

struct ReplyCreateOk {
    ttl: Duration,
    attrs: FileAttr,
    generation: u64,
    fh: u64,
    flags: u32
}
type ReplyCreateResult = ReplyResult<ReplyCreateOk>;

struct ReplyOpenOk {
    fh: u64,
    flags: u32
}
type ReplyOpenResult = ReplyResult<ReplyOpenOk>;

struct ReplyDataOk {
    buffer: Vec<u8>
}
type ReplyDataResult = ReplyResult<ReplyDataOk>;

struct ReplyAttrOk {
    ttl: Duration,
    attrs: FileAttr
}
type ReplyAttrResult = ReplyResult<ReplyAttrOk>;

struct ReplyWriteOk {
    written: u32
}
type ReplyWriteResult = ReplyResult<ReplyWriteOk>;

enum ReplyXattrOk {
    Size(u32),
    Data(Vec<u8>)
}
type ReplyXattrResult = ReplyResult<ReplyXattrOk>;


impl SimpleFS {

fn lookup_syn(&mut self, req: &Request, parent: u64, name: &OsStr) -> ReplyEntryResult {
    if name.len() > MAX_NAME_LENGTH as usize {
        return Err(libc::ENAMETOOLONG);
    }

    let parent_node = self.repository.get_inode(parent)?;
    let parent_attrs = parent_node.attrs;

    if !check_access(
        parent_attrs.uid,
        parent_attrs.gid,
        parent_attrs.mode,
        req.uid(),
        req.gid(),
        libc::X_OK,
    ) {
        return Err(libc::EACCES);
    }

    match parent_node.content {
        InodeContent::Symlink(_) |
        InodeContent::File(_) => {
            return Err(libc::ENOTDIR);
        },
        InodeContent::Directory(dir_content) => {
            if let Some((inode, _)) = dir_content.get(name.as_bytes()) {
                let ic = self.repository.get_inode(inode)?;
                Ok(ReplyEntryOk {
                    ttl: Duration::new(0, 0),
                    attrs: ic.attrs.into(),
                    generation: 0
                })
            } else {
                Err(libc::ENOENT)
            }
        }
    }
}

fn setattr_syn(
    &mut self,
    req: &Request,
    inode: u64,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    size: Option<u64>,
    atime: Option<TimeOrNow>,
    mtime: Option<TimeOrNow>,
    _ctime: Option<SystemTime>,
    fh: Option<u64>,
    _crtime: Option<SystemTime>,
    _chgtime: Option<SystemTime>,
    _bkuptime: Option<SystemTime>,
    _flags: Option<u32>,
) -> ReplyAttrResult {
    let mut ie = self.get_inode(inode)?;
    let mut attrs = &ie.attrs;

    if let Some(mode) = mode {
        debug!("chmod() called with {:?}, {:o}", inode, mode);
        if req.uid() != 0 && req.uid() != attrs.uid {
            return Err(libc::EPERM);
        }
        if req.uid() != 0
            && req.gid() != attrs.gid
            && !get_groups(req.pid()).contains(&attrs.gid)
        {
            // If SGID is set and the file belongs to a group that the caller is not part of
            // then the SGID bit is suppose to be cleared during chmod
            attrs.mode = (mode & !libc::S_ISGID as u32) as u16;
        } else {
            attrs.mode = mode as u16;
        }
        attrs.last_metadata_changed = time_now();
        assert!(&ie.attrs == attrs);
        self.repository.write_inode(inode, &ie)?;
        return Ok(ReplyAttrOk {
            ttl: Duration::new(0, 0),
            attrs: attrs.into()
        });
    }

    if uid.is_some() || gid.is_some() {
        debug!("chown() called with {:?} {:?} {:?}", inode, uid, gid);
        if let Some(gid) = gid {
            // Non-root users can only change gid to a group they're in
            if req.uid() != 0 && !get_groups(req.pid()).contains(&gid) {
                return Err(libc::EPERM.into());
            }
        }
        if let Some(uid) = uid {
            if req.uid() != 0
                // but no-op changes by the owner are not an error
                && !(uid == attrs.uid && req.uid() == attrs.uid)
            {
                return Err(libc::EPERM.into());
            }
        }
        // Only owner may change the group
        if gid.is_some() && req.uid() != 0 && req.uid() != attrs.uid {
            return Err(libc::EPERM.into());
        }

        if attrs.mode & (libc::S_IXUSR | libc::S_IXGRP | libc::S_IXOTH) as u16 != 0 {
            // SUID & SGID are suppose to be cleared when chown'ing an executable file
            clear_suid_sgid(&mut attrs);
        }

        if let Some(uid) = uid {
            attrs.uid = uid;
            // Clear SETUID on owner change
            attrs.mode &= !libc::S_ISUID as u16;
        }
        if let Some(gid) = gid {
            attrs.gid = gid;
            // Clear SETGID unless user is root
            if req.uid() != 0 {
                attrs.mode &= !libc::S_ISGID as u16;
            }
        }
        attrs.last_metadata_changed = time_now();
        assert!(&ie.attrs == attrs);
        self.repository.write_inode(inode, &ie)?;
        return Ok(ReplyAttrOk {
            ttl: Duration::new(0, 0),
            attrs: attrs.into()
        });
    }

    if let Some(size) = size {
        debug!("truncate() called with {:?} {:?}", inode, size);
        if let Some(handle) = fh {
            // If the file handle is available, check access locally.
            // This is important as it preserves the semantic that a file handle opened
            // with W_OK will never fail to truncate, even if the file has been subsequently
            // chmod'ed
            if self.check_file_handle_write(handle, inode) {
                ie = self.truncate(inode, size, 0, 0)?;
            } else {
                return Err(libc::EACCES);
            }
        } else {
            ie = self.truncate(inode, size, req.uid(), req.gid())?;
        }
    }

    let now = time_now();
    if let Some(atime) = atime {
        debug!("utimens() called with {:?}, atime={:?}", inode, atime);

        if attrs.uid != req.uid() && req.uid() != 0 && atime != Now {
            return Err(libc::EPERM);
        }

        if attrs.uid != req.uid()
            && !check_access(
                attrs.uid,
                attrs.gid,
                attrs.mode,
                req.uid(),
                req.gid(),
                libc::W_OK,
            )
        {
            return Err(libc::EACCES);
        }

        attrs.last_accessed = match atime {
            TimeOrNow::SpecificTime(time) => time_from_system_time(&time),
            Now => now,
        };
        attrs.last_metadata_changed = now;
        self.repository.write_inode(inode, &InodeEntry { attrs: attrs, content: ie.content })?;
    }
    if let Some(mtime) = mtime {
        debug!("utimens() called with {:?}, mtime={:?}", inode, mtime);

        if attrs.uid != req.uid() && req.uid() != 0 && mtime != Now {
            return Err(libc::EPERM);
        }

        if attrs.uid != req.uid()
            && !check_access(
                attrs.uid,
                attrs.gid,
                attrs.mode,
                req.uid(),
                req.gid(),
                libc::W_OK,
            )
        {
            return Err(libc::EACCES);
        }

        attrs.last_modified = match mtime {
            TimeOrNow::SpecificTime(time) => time_from_system_time(&time),
            Now => now,
        };
        attrs.last_metadata_changed = now;
        self.repository.write_inode(inode, &InodeEntry { attrs: attrs, content: ie.content })?;
    }

    let attrs = self.get_inode(inode)?;
    Ok(ReplyAttrOk {
        ttl: Duration::new(0, 0),
        attrs: attrs.into()
    })
}


    fn mknod_syn(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        _rdev: u32,
     ) -> ReplyEntryResult {
        let file_type = mode & libc::S_IFMT as u32;

        if file_type != libc::S_IFREG as u32
            && file_type != libc::S_IFLNK as u32
            && file_type != libc::S_IFDIR as u32
        {
            // TODO
            warn!("mknod() implementation is incomplete. Only supports regular files, symlinks, and directories. Got {:o}", mode);
            return Err(libc::ENOSYS);
        }

        let mut parent_ie = self.get_inode(parent)?;
        let mut parent_dir_content = Self::assume_directory(&parent_ie)?;
        Self::require_not_exist(parent_dir_content, name)?;
        let mut parent_attrs = &parent_ie.attrs;

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            return Err(libc::EACCES);
        }

        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }

        let inode = self.repository.allocate_next_inode()?;
        let attrs = InodeAttributes {
            inode,
            // open_file_handles: 0,
            size: 0,
            last_accessed: time_now(),
            last_modified: time_now(),
            last_metadata_changed: time_now(),
            kind: as_file_kind(mode),
            mode: self.creation_mode(mode),
            hardlinks: 1,
            uid: req.uid(),
            gid: creation_gid(&parent_attrs, req.gid()),
            xattrs: Default::default(),
        };

        let content = 
            match as_file_kind(mode) {
                FileKind::Directory => {
                    let mut entries = BTreeMap::new();
                    entries.insert(b".".to_vec(), (inode, FileKind::Directory));
                    entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
                    InodeContent::Directory(entries)
                },
                FileKind::File => {
                    InodeContent::File(FileContent::EMPTY)
                },
                _ => {
                    // not sure what target to point a symlink at etc
                    return Err(libc::ENOSYS);
                }
            };

        let ie = InodeEntry { attrs, content };
        self.repository.write_inode(inode,&ie);


        parent_dir_content.insert(name.as_bytes().to_vec(), (inode, attrs.kind));
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.repository.write_inode(parent, &parent_ie);

        // TODO: implement flags
        Ok(ReplyEntryOk {
            ttl: Duration::new(0, 0),
            attrs: attrs.into(),
            generation: 0
        })
     }



     fn mkdir_syn(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
    ) -> ReplyEntryResult {
        debug!("mkdir() called with {:?} {:?} {:o}", parent, name, mode);

        let mut parent_node = self.get_inode(parent)?;
        let mut parent_dir_content = Self::assume_directory(&parent_node)?;
        Self::require_not_exist(parent_dir_content, name)?;
        let mut parent_attrs = &mut parent_node.attrs;
        check_access_rq(&parent_attrs, req, libc::W_OK)?;

        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }
        if parent_attrs.mode & libc::S_ISGID as u16 != 0 {
            mode |= libc::S_ISGID as u32;
        }

        let inode = self.repository.allocate_next_inode()?;
        let attrs = InodeAttributes {
            inode,
            size: BLOCK_SIZE,
            last_accessed: time_now(),
            last_modified: time_now(),
            last_metadata_changed: time_now(),
            kind: FileKind::Directory,
            mode: self.creation_mode(mode),
            hardlinks: 2, // Directories start with link count of 2, since they have a self link
            uid: req.uid(),
            gid: creation_gid(&parent_attrs, req.gid()),
            xattrs: Default::default(),
        };

        let mut entries = BTreeMap::new();
        entries.insert(b".".to_vec(), (inode, FileKind::Directory));
        entries.insert(b"..".to_vec(), (parent, FileKind::Directory));

        let ie = InodeEntry { attrs: attrs.clone(), content: InodeContent::Directory(entries) };
        self.repository.write_inode(inode, &ie)?;


        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();

        parent_dir_content.insert(name.as_bytes().to_vec(), (inode, FileKind::Directory));
        self.repository.write_inode(parent, &parent_node)?;

        Ok(ReplyEntryOk {
            ttl: Duration::new(0, 0),
            attrs: attrs.into(),
            generation: 0
        })
    }



    fn unlink_syn(&mut self, req: &Request, parent: u64, name: &OsStr) -> ReplyEmptyResult {
        debug!("unlink() called with {:?} {:?}", parent, name);
        let mut attrs = self.lookup_name(parent, name)?;

        let mut parent_attrs = self.get_inode(parent)?;

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            return Err(libc::EACCES);
        }

        let uid = req.uid();
        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && uid != 0
            && uid != parent_attrs.uid
            && uid != attrs.uid
        {
            return Err(libc::EACCES);
        }

        parent_attrs.last_metadata_changed = time_now();
        parent_attrs.last_modified = time_now();
        self.write_inode(&parent_attrs);

        attrs.hardlinks -= 1;
        attrs.last_metadata_changed = time_now();
        self.write_inode(&attrs);
        self.gc_inode(&attrs);

        let mut entries = self.get_directory_content(parent)?;
        entries.remove(name.as_bytes());
        self.write_directory_content(parent, entries);

        Ok(())
    }



    fn rmdir_syn(&mut self, req: &Request, parent: u64, name: &OsStr) -> ReplyEmptyResult {
        debug!("rmdir() called with {:?} {:?}", parent, name);
        let mut attrs = self.lookup_name(parent, name)?;

        let mut parent_attrs = self.get_inode(parent)?;

        // Directories always have a self and parent link
        if self.get_directory_content(attrs.inode)?.len() > 2 {
            return Err(libc::ENOTEMPTY);
        }

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            return Err(libc::EACCES);
        }

        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && req.uid() != 0
            && req.uid() != parent_attrs.uid
            && req.uid() != attrs.uid
        {
            return Err(libc::EACCES);
        }

        parent_attrs.last_metadata_changed = time_now();
        parent_attrs.last_modified = time_now();
        self.write_inode(&parent_attrs);

        attrs.hardlinks = 0;
        attrs.last_metadata_changed = time_now();
        self.write_inode(&attrs);
        self.gc_inode(&attrs);

        let mut entries = self.get_directory_content(parent)?;
        entries.remove(name.as_bytes());
        self.write_directory_content(parent, entries);

        Ok(())
    }


    fn symlink_syn(
        &mut self,
        req: &Request,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
    ) -> ReplyEntryResult {
        debug!(
            "symlink() called with {:?} {:?} {:?}",
            parent, link_name, target
        );
        let mut parent_node = self.get_inode(parent)?;

        check_access_rq(&parent_node.attrs, req, libc::W_OK)?;
        let mut dir_content = Self::assume_directory(&parent_node)?;

        Self::require_not_exist(dir_content, link_name)?;

        let inode = self.repository.allocate_next_inode();
        let attrs = InodeAttributes {
            inode,
            size: target.as_os_str().as_bytes().len() as u64,
            last_accessed: time_now(),
            last_modified: time_now(),
            last_metadata_changed: time_now(),
            kind: FileKind::Symlink,
            mode: 0o777,
            hardlinks: 1,
            uid: req.uid(),
            gid: creation_gid(&parent_node.attrs, req.gid()),
            xattrs: Default::default(),
        };

        let ie = InodeEntry {
            attrs: attrs.clone(),
            content: InodeContent::Symlink(target.as_os_str().as_bytes().to_vec())
        };
        self.repository.write_inode(inode, &ie)?;


        parent_node.attrs.last_modified = time_now();
        parent_node.attrs.last_metadata_changed = time_now();
        dir_content.insert(link_name.as_bytes().to_vec(), (inode, FileKind::Symlink));
        self.repository.write_inode(parent, &parent_node)?;

        Ok(ReplyEntryOk {
            ttl: Duration::new(0, 0),
            attrs: attrs.into(),
            generation: 0
        })
    }

    fn rename_syn(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        flags: u32,
    ) -> ReplyEmptyResult {
        debug!(
            "rename() called with: source {parent:?} {name:?}, \
            destination {new_parent:?} {new_name:?}, flags {flags:#b}",
        );
        let mut inode_attrs = match self.lookup_name(parent, name) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                return Err(error_code);
            }
        };

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                return Err(error_code);
            }
        };

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            return Err(libc::EACCES);
        }

        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && req.uid() != 0
            && req.uid() != parent_attrs.uid
            && req.uid() != inode_attrs.uid
        {
            return Err(libc::EACCES);
        }

        let mut new_parent_attrs = match self.get_inode(new_parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                return Err(error_code);
            }
        };

        if !check_access(
            new_parent_attrs.uid,
            new_parent_attrs.gid,
            new_parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            return Err(libc::EACCES);
        }

        // "Sticky bit" handling in new_parent
        if new_parent_attrs.mode & libc::S_ISVTX as u16 != 0 {
            if let Ok(existing_attrs) = self.lookup_name(new_parent, new_name) {
                if req.uid() != 0
                    && req.uid() != new_parent_attrs.uid
                    && req.uid() != existing_attrs.uid
                {
                    return Err(libc::EACCES);
                }
            }
        }

        #[cfg(target_os = "linux")]
        if flags & libc::RENAME_EXCHANGE as u32 != 0 {
            let mut new_inode_attrs = match self.lookup_name(new_parent, new_name) {
                Ok(attrs) => attrs,
                Err(error_code) => {
                    return Err(error_code);
                }
            };

            let mut entries = self.get_directory_content(new_parent).unwrap();
            entries.insert(
                new_name.as_bytes().to_vec(),
                (inode_attrs.inode, inode_attrs.kind),
            );
            self.write_directory_content(new_parent, entries);

            let mut entries = self.get_directory_content(parent).unwrap();
            entries.insert(
                name.as_bytes().to_vec(),
                (new_inode_attrs.inode, new_inode_attrs.kind),
            );
            self.write_directory_content(parent, entries);

            parent_attrs.last_metadata_changed = time_now();
            parent_attrs.last_modified = time_now();
            self.write_inode(&parent_attrs);
            new_parent_attrs.last_metadata_changed = time_now();
            new_parent_attrs.last_modified = time_now();
            self.write_inode(&new_parent_attrs);
            inode_attrs.last_metadata_changed = time_now();
            self.write_inode(&inode_attrs);
            new_inode_attrs.last_metadata_changed = time_now();
            self.write_inode(&new_inode_attrs);

            if inode_attrs.kind == FileKind::Directory {
                let mut entries = self.get_directory_content(inode_attrs.inode).unwrap();
                entries.insert(b"..".to_vec(), (new_parent, FileKind::Directory));
                self.write_directory_content(inode_attrs.inode, entries);
            }
            if new_inode_attrs.kind == FileKind::Directory {
                let mut entries = self.get_directory_content(new_inode_attrs.inode).unwrap();
                entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
                self.write_directory_content(new_inode_attrs.inode, entries);
            }

            return Ok(());
        }

        // Only overwrite an existing directory if it's empty
        if let Ok(new_name_attrs) = self.lookup_name(new_parent, new_name) {
            if new_name_attrs.kind == FileKind::Directory
                && self
                    .get_directory_content(new_name_attrs.inode)
                    .unwrap()
                    .len()
                    > 2
            {
                return Err(libc::ENOTEMPTY);
            }
        }

        // Only move an existing directory to a new parent, if we have write access to it,
        // because that will change the ".." link in it
        if inode_attrs.kind == FileKind::Directory
            && parent != new_parent
            && !check_access(
                inode_attrs.uid,
                inode_attrs.gid,
                inode_attrs.mode,
                req.uid(),
                req.gid(),
                libc::W_OK,
            )
        {
            return Err(libc::EACCES);
        }

        // If target already exists decrement its hardlink count
        if let Ok(mut existing_inode_attrs) = self.lookup_name(new_parent, new_name) {
            let mut entries = self.get_directory_content(new_parent).unwrap();
            entries.remove(new_name.as_bytes());
            self.write_directory_content(new_parent, entries);

            if existing_inode_attrs.kind == FileKind::Directory {
                existing_inode_attrs.hardlinks = 0;
            } else {
                existing_inode_attrs.hardlinks -= 1;
            }
            existing_inode_attrs.last_metadata_changed = time_now();
            self.write_inode(&existing_inode_attrs);
            self.gc_inode(&existing_inode_attrs);
        }

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.remove(name.as_bytes());
        self.write_directory_content(parent, entries);

        let mut entries = self.get_directory_content(new_parent).unwrap();
        entries.insert(
            new_name.as_bytes().to_vec(),
            (inode_attrs.inode, inode_attrs.kind),
        );
        self.write_directory_content(new_parent, entries);

        parent_attrs.last_metadata_changed = time_now();
        parent_attrs.last_modified = time_now();
        self.write_inode(&parent_attrs);
        new_parent_attrs.last_metadata_changed = time_now();
        new_parent_attrs.last_modified = time_now();
        self.write_inode(&new_parent_attrs);
        inode_attrs.last_metadata_changed = time_now();
        self.write_inode(&inode_attrs);

        if inode_attrs.kind == FileKind::Directory {
            let mut entries = self.get_directory_content(inode_attrs.inode).unwrap();
            entries.insert(b"..".to_vec(), (new_parent, FileKind::Directory));
            self.write_directory_content(inode_attrs.inode, entries);
        }

        Ok(())
    }


    fn link_syn(
      &mut self,
      req: &Request,
      inode: u64,
      new_parent: u64,
      new_name: &OsStr,) -> ReplyEntryResult {

        debug!(
            "link() called for {}, {}, {:?}",
            inode, new_parent, new_name
        );
        let mut ie = self.get_inode(inode)?;

        self.insert_link(req, new_parent, new_name, inode, ie.attrs.kind)?;

        ie.attrs.hardlinks += 1;
        ie.attrs.last_metadata_changed = time_now();
        self.repository.write_inode(inode, &ie)?;

        Ok(ReplyEntryOk {
            ttl: Duration::new(0, 0),
            attrs: ie.attrs.into(),
            generation: 0
        })
    }

    fn open_syn(&mut self, req: &Request, inode: u64, flags: i32) -> ReplyOpenResult {
        debug!("open() called for {:?}", inode);
        let (access_mask, read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC != 0 {
                    return Err(libc::EACCES.into());
                }
                if flags & FMODE_EXEC != 0 {
                    // Open is from internal exec syscall
                    (libc::X_OK, true, false)
                } else {
                    (libc::R_OK, true, false)
                }
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(libc::EINVAL.into());
            }
        };

        let ic = self.get_inode(inode)?;

        check_access_rq(&ic.attrs, req, access_mask)?;

        let fh = self.allocate_next_file_handle(inode, read, write);
        let open_flags = if self.options.direct_io { FOPEN_DIRECT_IO } else { 0 };

        Ok(ReplyOpenOk {
            fh,
            flags: open_flags
        })
    }

    fn read_syn(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,) -> ReplyDataResult {
            debug!(
                "read() called on {:?} offset={:?} size={:?}",
                inode, offset, size
            );
            assert!(offset >= 0);
            if !self.check_file_handle_read(fh, inode) {
                return Err(libc::EACCES.into());
            }

            let ie = self.get_inode(inode)?;
            let file_content = Self::assume_file(&ie)?;

            if ie.attrs.size <= offset { return Err(libc::EOF.into()); }
            let read_size: usize = min(size as usize, ie.attrs.size - offset);
            let mut buffer = vec![0u8; read_size];
            self.repository.read(file_content, offset, &mut buffer)?;

            Ok(ReplyDataOk { buffer })

    }



    fn write_syn(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        #[allow(unused_variables)] flags: i32,
        _lock_owner: Option<u64>,
    ) -> ReplyWriteResult {
        debug!("write() called with {:?} size={:?}", inode, data.len());
        assert!(offset >= 0);

        if !self.check_file_handle_write(fh, inode) {
            return Err(libc::EACCES.into());
        }

        let mut ic = self.get_inode(inode)?;
        let file_content = Self::assume_file(&ic)?;

        // Update file content
        let new_content = self.repository.write(file_content, offset, data)?;

        ic.attrs.last_metadata_changed = time_now();
        ic.attrs.last_modified = time_now();
        if data.len() + offset as usize > ic.attrs.size as usize {
            ic.attrs.size = (data.len() + offset as usize) as u64;
        }

        ic.content = new_content;

        // #[cfg(feature = "abi-7-31")]
        // if flags & FUSE_WRITE_KILL_PRIV as i32 != 0 {
        //     clear_suid_sgid(&mut attrs);
        // }
        // XXX: In theory we should only need to do this when WRITE_KILL_PRIV is set for 7.31+
        // However, xfstests fail in that case
        clear_suid_sgid(&mut ic.attrs);

        self.repository.write_inode(inode, &ic)?;

        Ok(ReplyWriteOk {
            written: data.len() as u32
        })
    }


    fn opendir_syn(&mut self, req: &Request, inode: u64, flags: i32) -> ReplyOpenResult {
        debug!("opendir() called on {:?}", inode);
        let (access_mask, read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC != 0 {
                    return Err(libc::EACCES.into());
                }
                (libc::R_OK, true, false)
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(libc::EINVAL.into());
            }
        };

        let mut ic = self.get_inode(inode)?;
        let dir_content = Self::assume_directory(&ic)?;

        if !check_access(
            ic.attrs.uid,
            ic.attrs.gid,
            ic.attrs.mode,
            req.uid(),
            req.gid(),
            access_mask,
        ) {
            return Err(libc::EACCES.into());
        }

        let open_flags = if self.options.direct_io { FOPEN_DIRECT_IO } else { 0 };
        let fh = self.allocate_next_file_handle(inode, read, write);
        Ok(ReplyOpenOk {
            fh,
            flags: open_flags
        })
    }


    fn getxattr_syn(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
        size: u32,
    ) -> ReplyXattrResult {
        let attrs = self.get_inode(inode)?;

        xattr_access_check(key.as_bytes(), libc::R_OK, &attrs.attrs, request)?;

        if let Some(data) = attrs.attrs.xattrs.get(key.as_bytes()) {
            if size == 0 {
                Ok(ReplyXattrOk::Size(data.len() as u32))
            } else if data.len() <= size as usize {
                Ok(ReplyXattrOk::Data(data.clone()))
            } else {
                Err(libc::ERANGE.into())
            }
        } else {
            #[cfg(target_os = "linux")]
            return Err(libc::ENODATA.into());
            #[cfg(not(target_os = "linux"))]
            return Err(libc::ENOATTR.into());
        }
    }

    fn setxattr_syn(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
        value: &[u8],
        _flags: i32,
        _position: u32,
    ) -> ReplyEmptyResult {
        let mut ie = self.get_inode(inode)?;

        xattr_access_check(key.as_bytes(), libc::W_OK, &ie.attrs, request)?;

        ie.attrs.xattrs.insert(key.as_bytes().to_vec(), value.to_vec());
        ie.attrs.last_metadata_changed = time_now();
        self.repository.write_inode(inode, &ie)?;

        Ok(())
    }

    fn listxattr_syn(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        size: u32,
    ) -> ReplyXattrResult {
        let attrs = self.get_inode(inode)?;

        let mut bytes = vec![];
        // Convert to concatenated null-terminated strings
        for key in attrs.attrs.xattrs.keys() {
            bytes.extend(key);
            bytes.push(0);
        }

        if size == 0 {
            Ok(ReplyXattrOk::Size(bytes.len() as u32))
        } else if bytes.len() <= size as usize {
            Ok(ReplyXattrOk::Data(bytes))
        } else {
            Err(libc::ERANGE.into())
        }
    }

    fn removexattr_syn(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
    ) -> ReplyEmptyResult {
        let mut ie = self.get_inode(inode)?;

        xattr_access_check(key.as_bytes(), libc::W_OK, &ie.attrs, request)?;

        if ie.attrs.xattrs.remove(key.as_bytes()).is_none() {
            #[cfg(target_os = "linux")]
            return Err(libc::ENODATA.into());
            #[cfg(not(target_os = "linux"))]
            return Err(libc::ENOATTR.into());
        }

        ie.attrs.last_metadata_changed = time_now();
        self.repository.write_inode(inode, &ie)?;

        Ok(())
    }

    fn access_syn(
        &mut self,
        req: &Request,
        inode: u64,
        mask: i32,
    ) -> ReplyEmptyResult {
        debug!("access() called with {:?} {:?}", inode, mask);
        let attr = self.get_inode(inode)?;

        if check_access(
            attr.attrs.uid,
            attr.attrs.gid,
            attr.attrs.mode,
            req.uid(),
            req.gid(),
            mask
        ) {
            Ok(())
        } else {
            Err(libc::EACCES.into())
        }
    }



    fn create_syn(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        flags: i32,
    ) -> ReplyCreateResult {
        debug!("create() called with {:?} {:?}", parent, name);

        let mut parent_ie = self.get_inode(parent)?;
        let mut parent_dir_content = Self::assume_directory(&parent_ie)?;
        Self::require_not_exist(parent_dir_content, name)?;
        let mut parent_attrs = &parent_ie.attrs;

        let (read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => (true, false),
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(libc::EINVAL.into());
            }
        };

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            return Err(libc::EACCES.into());
        }

        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }

        let inode = self.repository.allocate_next_inode()?;
        let attrs = InodeAttributes {
            inode,
            size: 0,
            last_accessed: time_now(),
            last_modified: time_now(),
            last_metadata_changed: time_now(),
            kind: as_file_kind(mode),
            mode: self.creation_mode(mode),
            hardlinks: 1,
            uid: req.uid(),
            gid: creation_gid(&parent_attrs, req.gid()),
            xattrs: Default::default(),
        };

        let content = 
        match as_file_kind(mode) {
            FileKind::Directory => {
                let mut entries = BTreeMap::new();
                entries.insert(b".".to_vec(), (inode, FileKind::Directory));
                entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
                InodeContent::Directory(entries)
            },
            FileKind::File => {
                InodeContent::File(FileContent::EMPTY)
            },
            _ => {
                // not sure what target to point a symlink at etc
                return Err(libc::ENOSYS.into());
            }
        };
        let ie = InodeEntry { attrs, content };
        self.repository.write_inode(inode,&ie);

        parent_dir_content.insert(name.as_bytes().to_vec(), (inode, attrs.kind));
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.repository.write_inode(parent, &parent_ie);

        let fh = self.allocate_next_file_handle(inode, read, write);
        // TODO: implement flags
        Ok(ReplyCreateOk {
            ttl: Duration::new(0, 0),
            attrs: attrs.into(),
            generation: 0,
            fh,
            flags: 0
        })
    }


    #[cfg(target_os = "linux")]
    fn fallocate_syn(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        _fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
    ) -> ReplyEmptyResult {
        let mut ic = self.get_inode(inode)?;
        let file_content = Self::assume_file(&ic)?;

        todo!();
        // todo: repository fallocate or sth
        // unsafe {
        //     libc::fallocate64(file.into_raw_fd(), mode, offset, length);
        // }

        if mode & libc::FALLOC_FL_KEEP_SIZE == 0 {
            ic.attrs.last_metadata_changed = time_now();
            ic.attrs.last_modified = time_now();
            if (offset + length) as u64 > ic.attrs.size {
                ic.attrs.size = (offset + length) as u64;
            }
            self.repository.write_inode(inode, &ic)?;
        }

        Ok(())
    }



    fn copy_file_range_syn(
        &mut self,
        _req: &Request<'_>,
        src_inode: u64,
        src_fh: u64,
        src_offset: i64,
        dest_inode: u64,
        dest_fh: u64,
        dest_offset: i64,
        size: u64,
        _flags: u32,
    ) -> ReplyWriteResult {
        debug!(
            "copy_file_range() called with src ({}, {}, {}) dest ({}, {}, {}) size={}",
            src_fh, src_inode, src_offset, dest_fh, dest_inode, dest_offset, size
        );

        if !self.check_file_handle_read(src_fh, src_inode) {
            return Err(libc::EACCES.into());
        }
        if !self.check_file_handle_write(dest_fh, dest_inode) {
            return Err(libc::EACCES.into());
        }

        let src_ie = self.get_inode(src_inode)?;
        let src_content = Self::assume_file(&src_ie)?;

        let mut dest_ie = self.get_inode(dest_inode)?;
        let dest_content = Self::assume_file(&dest_ie)?;

        // Could underflow if file length is less than local_start
        let read_size = min(size, src_ie.attrs.size.saturating_sub(src_offset as u64));

        let updated_dest_content = self.repository.copy_range(&src_content, &dest_content, src_offset, dest_offset, size)?;
        dest_ie.content = InodeContent::File(updated_dest_content);
        dest_ie.attrs.size = updated_dest_content.len() as u64;
        dest_ie.attrs.last_metadata_changed = time_now();
        dest_ie.attrs.last_modified = time_now();
        self.repository.write_inode(dest_inode, &dest_ie)?;


        Ok(ReplyWriteOk {
            written: read_size as u32
        })
    }
}



// -------------------------------------------------------------------------------------------

pub fn check_access(
    file_uid: u32,
    file_gid: u32,
    file_mode: u16,
    uid: u32,
    gid: u32,
    mut access_mask: i32,
) -> bool {
    // F_OK tests for existence of file
    if access_mask == libc::F_OK {
        return true;
    }
    let file_mode = i32::from(file_mode);

    // root is allowed to read & write anything
    if uid == 0 {
        // root only allowed to exec if one of the X bits is set
        access_mask &= libc::X_OK;
        access_mask -= access_mask & (file_mode >> 6);
        access_mask -= access_mask & (file_mode >> 3);
        access_mask -= access_mask & file_mode;
        return access_mask == 0;
    }

    if uid == file_uid {
        access_mask -= access_mask & (file_mode >> 6);
    } else if gid == file_gid {
        access_mask -= access_mask & (file_mode >> 3);
    } else {
        access_mask -= access_mask & file_mode;
    }

    return access_mask == 0;
}

#[must_use]
pub fn check_access_rq(attrs: &InodeAttributes, req: &Request, access_mask: i32) -> Result<(), c_int> {
    if !check_access(
        attrs.uid,
        attrs.gid,
        attrs.mode,
        req.uid(),
        req.gid(),
        access_mask,
    ) {
        Err(libc::EACCES)
    } else {
        Ok(())
    }
}

fn as_file_kind(mut mode: u32) -> FileKind {
    mode &= libc::S_IFMT as u32;

    if mode == libc::S_IFREG as u32 {
        return FileKind::File;
    } else if mode == libc::S_IFLNK as u32 {
        return FileKind::Symlink;
    } else if mode == libc::S_IFDIR as u32 {
        return FileKind::Directory;
    } else {
        unimplemented!("{}", mode);
    }
}

fn get_groups(pid: u32) -> Vec<u32> {
    if cfg!(not(target_os = "macos")) {
        let path = format!("/proc/{pid}/task/{pid}/status");
        let file = File::open(path).unwrap();
        for line in BufReader::new(file).lines() {
            let line = line.unwrap();
            if line.starts_with("Groups:") {
                return line["Groups: ".len()..]
                    .split(' ')
                    .filter(|x| !x.trim().is_empty())
                    .map(|x| x.parse::<u32>().unwrap())
                    .collect();
            }
        }
    }

    vec![]
}
