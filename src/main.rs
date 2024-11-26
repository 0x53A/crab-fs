// Note: this is modified from https://github.com/cberner/fuser/blob/d675c07ecb8e826467d53dc00b45a67c731d5b85/examples/simple.rs
// Copyright of the original: Christopher Berner and contributors to https://github.com/cberner/fuser
// License: MIT


#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)] // libc::S_* are u16 or u32 depending on the platform

pub mod crypt;
pub mod entropy;

use clap::{crate_version, Arg, ArgAction, Command};
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

const BLOCK_SIZE: u64 = 512;
const MAX_NAME_LENGTH: u32 = 10_000;
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024; // 1 TB

const FMODE_EXEC: i32 = 0x20;

const ENCRYPTION_KEY_LENGTH: usize = 16;

pub mod repository;

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

struct SimpleFsOptions {
    permutate_handle_values: bool,
    direct_io: bool,
    #[cfg(feature = "abi-7-26")]
    suid_support: bool,
}

impl SimpleFsOptions {
    fn default() -> Self {
        Self {
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

// Stores inode metadata data in "$data_dir/inodes" and file contents in "$data_dir/contents"
// Directory data is stored in the file's contents, as a serialized DirectoryDescriptor
struct SimpleFS {
    options: SimpleFsOptions,
    state: SimpleFsState,
    encryption_key: [u8;ENCRYPTION_KEY_LENGTH],
    repository: RepositoryV1,
}

impl SimpleFS {
    fn new(
        options: SimpleFsOptions,
        encryption_key: [u8;ENCRYPTION_KEY_LENGTH],
        data_dir: String,
    ) -> SimpleFS {

        let state = {
            let ent = entropy::entropy_from_os();
            let rng = entropy::rng_from_entropy(key);
            let key = rng.next_u32();
            SimpleFsState {
                fh_feistel: crypt::feistel::FeistelNetwork::new(1, vec![key]),
                next_file_handle: AtomicU64::new(1),
                open_file_handles: RwLock::new(HashMap::new()),
                global_lock: RwLock::new(HashMap::new()),
            }
        };

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
                repository: RepositoryV1::new(data_dir.into()),
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

    fn allocate_next_inode(&self) -> Inode {
        self.repository.allocate_next_inode()
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

    fn check_file_handle_read(&self, file_handle: u64) -> bool {
        self.state.open_file_handles.read()
            .unwrap()
            .get(&file_handle)
            .map(|perms| perms.can_read)
            .unwrap_or(false)
    }

    fn check_file_handle_write(&self, file_handle: u64) -> bool {
        self.state.open_file_handles.read()
            .unwrap()
            .get(&file_handle)
            .map(|perms| perms.can_write)
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
        ie: &InodeEntry,
        new_length: u64,
        uid: u32,
        gid: u32,
    ) -> Result<(), c_int> {
        if new_length > MAX_FILE_SIZE {
            return Err(libc::EFBIG);
        }
        let mut attrs = &ie.attrs;

        if !check_access(attrs.uid, attrs.gid, attrs.mode, uid, gid, libc::W_OK) {
            return Err(libc::EACCES);
        }

        let FileContent(file_content) = ie.content else {
             return Err(libc::EISDIR);
        };

        let new_content = self.repository.change_content_len(file_content, new_length);

        attrs.size = new_length;
        attrs.last_metadata_changed = time_now();
        attrs.last_modified = time_now();

        // Clear SETUID & SETGID on truncate
        clear_suid_sgid(&mut attrs);

        assert!(&ic.attrs == &attrs);
        ic.content = new_content;
        self.repository.write_inode(ie.attrs.inode, &ie);

        Ok(())
    }

    fn try_find_directory_entry(parent: &DirectoryDescriptor,  name: &OsStr) -> Option<(Inode, FileKind)> {
        parent.get(name.as_bytes())
    }

    fn lookup_name(&self, parent: u64, name: &OsStr) -> Result<InodeAttributes, c_int> {
        let entries = self.get_directory_content(parent)?;
        if let Some((inode, _)) = entries.get(name.as_bytes()) {
            return self.get_inode(*inode);
        } else {
            return Err(libc::ENOENT);
        }
    }
    
    #[must_use]
    fn assume_directory<'a>(ie: &'a InodeEntry) -> Result<&'a DirectoryDescriptor, c_int> {
        match &parent_node.content {
            InodeContent::File(_) | InodeContent::Symlink(_) => {
                return Err(libc::ENOTDIR);
            },
            InodeContent::Directory(dir_content) => {
                dir_content
            }
        };
    }

    #[must_use]
    fn assume_file<'a>(ie: &'a InodeEntry) -> Result<&'a FileContent, c_int> {
        match &parent_node.content {
            InodeContent::Directory(_) | InodeContent::Symlink(_) => {
                return Err(libc::EISDIR);
            },
            InodeContent::File(file_content) => {
                file_content
            }
        };
    }

    #[must_use]
    fn require_not_exist(parent: &DirectoryDescriptor, name: &OsStr) -> Result<(), c_int> {        
        if Self::try_find_directory_entry(parent, dir_content).is_some() {
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

        let mut dir_content = Self::assume_directory(&parent_node)?;

        Self::require_not_exist(dir_content, name)?;

        let mut parent_attrs = &parent_node.attrs;

        check_access_rq(parent_attrs, req, libc::W_OK)?;


        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();

        dir_content.insert(name.as_bytes().to_vec(), (inode, kind));
        assert(parent_node.content == InodeContent::Directory(dir_content));

        self.repository.write_inode(inode, &parent_node);

        Ok(())
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

        if self.get_inode(FUSE_ROOT_ID).is_err() {
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
            let root_node = InodeEntry {attrs: root_attr, content: entries};
            self.repository.write_inode(FUSE_ROOT_ID, &root_node);
        }
        Ok(())
    }

    fn lookup(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.lookup_syn(req, parent, name) {
            Ok(ok) => reply.entry(&ok.ttl, &ok.attrs, ok.generation),
            Err(error_code) => reply.error(error_code)
        }
    }

    fn forget(&mut self, _req: &Request, _ino: u64, _nlookup: u64) {}

    fn getattr(&mut self, _req: &Request, inode: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.repository.get_inode(inode) {
            Ok(ie) => reply.attr(&Duration::new(0, 0), &ie.attrs.into()),
            Err(error_code) => reply.error(error_code),
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
            Err(error_code) => reply.error(error_code)
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
            Err(error_code) => reply.error(error_code)
        }
    }
    fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.unlink_syn(req, parent, name) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(error_code)
        }
    }

    fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.rmdir_syn(req, parent, name) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(error_code)
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
        match self.rename_syn(req, parent, name, new_parent, new_name, flags) {
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
            Err(error_code) => reply.error(error_code)
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
            Err(error_code) => reply.error(error_code)
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
            Err(error_code) => reply.error(error_code)
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
            Err(error_code) => reply.error(error_code)
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
            Err(error_code) => reply.error(error_code)
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
            Err(error_code) => reply.error(error_code)
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
            Err(error_code) => reply.error(error_code)
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
            Err(error_code) => reply.error(error_code)
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
        let path = self.content_path(inode);
        if let Ok(file) = OpenOptions::new().write(true).open(path) {
            unsafe {
                libc::fallocate64(file.into_raw_fd(), mode, offset, length);
            }
            if mode & libc::FALLOC_FL_KEEP_SIZE == 0 {
                let mut attrs = self.get_inode(inode).unwrap();
                attrs.last_metadata_changed = time_now();
                attrs.last_modified = time_now();
                if (offset + length) as u64 > attrs.size {
                    attrs.size = (offset + length) as u64;
                }
                self.write_inode(&attrs);
            }
            reply.ok();
        } else {
            reply.error(libc::ENOENT);
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
        debug!(
            "copy_file_range() called with src ({}, {}, {}) dest ({}, {}, {}) size={}",
            src_fh, src_inode, src_offset, dest_fh, dest_inode, dest_offset, size
        );
        if !self.check_file_handle_read(src_fh) {
            reply.error(libc::EACCES);
            return;
        }
        if !self.check_file_handle_write(dest_fh) {
            reply.error(libc::EACCES);
            return;
        }

        let src_path = self.content_path(src_inode);
        if let Ok(file) = File::open(src_path) {
            let file_size = file.metadata().unwrap().len();
            // Could underflow if file length is less than local_start
            let read_size = min(size, file_size.saturating_sub(src_offset as u64));

            let mut data = vec![0; read_size as usize];
            file.read_exact_at(&mut data, src_offset as u64).unwrap();

            let dest_path = self.content_path(dest_inode);
            if let Ok(mut file) = OpenOptions::new().write(true).open(dest_path) {
                file.seek(SeekFrom::Start(dest_offset as u64)).unwrap();
                file.write_all(&data).unwrap();

                let mut attrs = self.get_inode(dest_inode).unwrap();
                attrs.last_metadata_changed = time_now();
                attrs.last_modified = time_now();
                if data.len() + dest_offset as usize > attrs.size as usize {
                    attrs.size = (data.len() + dest_offset as usize) as u64;
                }
                self.write_inode(&attrs);

                reply.written(data.len() as u32);
            } else {
                reply.error(libc::EBADF);
            }
        } else {
            reply.error(libc::ENOENT);
        }
    }
}

// ------------------------------------------------------------------------------------------
// impl Syn

struct ReplyEntryOk {
    ttl: Duration,
    attrs: FileAttr,
    generation: u64
}
type ReplyEntryResult = Result<ReplyEntryOk, c_int>;

type ReplyEmptyResult = Result<(), c_int>;

struct ReplyOpenOk {
    fh: u64,
    flags: u32
}
type ReplyOpenResult = Result<ReplyOpenOk, c_int>;

struct ReplyDataOk {
    buffer: Vec<u8>
}
type ReplyDataResult = Result<ReplyDataOk, c_int>;

struct ReplyAttrOk {
    ttl: Duration,
    attrs: FileAttr
}
type ReplyAttrResult = Result<ReplyAttrOk, c_int>;

struct ReplyWriteOk {
    written: u32
}
type ReplyWriteResult = Result<ReplyWriteOk, c_int>;

enum ReplyXattrOk {
    Size(u32),
    Data(Vec<u8>)
}
type ReplyXattrResult = Result<ReplyXattrOk, c_int>;


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
            if let Some((inode, _)) = entries.get(name.as_bytes()) {
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
        assert(&ie.attrs == attrs);
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
                return Err(libc::EPERM);
            }
        }
        if let Some(uid) = uid {
            if req.uid() != 0
                // but no-op changes by the owner are not an error
                && !(uid == attrs.uid && req.uid() == attrs.uid)
            {
                return Err(libc::EPERM);
            }
        }
        // Only owner may change the group
        if gid.is_some() && req.uid() != 0 && req.uid() != attrs.uid {
            return Err(libc::EPERM);
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
        assert(&ie.attrs == attrs);
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
            if self.check_file_handle_write(handle) {
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
     
        if self.lookup_name(parent, name).is_ok() {
            return Err(libc::EEXIST);
        }
     
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
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.write_inode(&parent_attrs);
     
        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }
     
        let inode = self.allocate_next_inode();
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
        self.write_inode(&attrs);
        File::create(self.content_path(inode)).unwrap();
     
        if as_file_kind(mode) == FileKind::Directory {
            let mut entries = BTreeMap::new();
            entries.insert(b".".to_vec(), (inode, FileKind::Directory));
            entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
            self.write_directory_content(inode, entries);
        }
     
        let mut entries = self.get_directory_content(parent).unwrap();
        entries.insert(name.as_bytes().to_vec(), (inode, attrs.kind));
        self.write_directory_content(parent, entries);
     
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
        if self.lookup_name(parent, name).is_ok() {
            return Err(libc::EEXIST);
        }
    
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
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.write_inode(&parent_attrs);
    
        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }
        if parent_attrs.mode & libc::S_ISGID as u16 != 0 {
            mode |= libc::S_ISGID as u32;
        }
    
        let inode = self.allocate_next_inode();
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
        self.write_inode(&attrs);
    
        let mut entries = BTreeMap::new();
        entries.insert(b".".to_vec(), (inode, FileKind::Directory));
        entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
        self.write_directory_content(inode, entries);
    
        let mut entries = self.get_directory_content(parent).unwrap();
        entries.insert(name.as_bytes().to_vec(), (inode, FileKind::Directory));
        self.write_directory_content(parent, entries);
    
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
    
        Self::require_not_exist(dir_content, name)?;
    
        let inode = self.allocate_next_inode();
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
                    return Err(libc::EACCES);
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
                return Err(libc::EINVAL);
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
            if !self.check_file_handle_read(fh) {
                return Err(libc::EACCES);
            }

            let ie = self.get_inode(inode)?;
            let file_content = Self::assume_file(&ie)?;

            if ie.attrs.size <= offset { return Err(libc::EOF); }
            let read_size = min(size, ie.attrs.size - offset);
            let buffer = self.repository.read_buffer(file_content, offset, read_size);

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
        
        if !self.check_file_handle_write(fh) {
            return Err(libc::EACCES);
        }
    
        let mut ic = self.get_inode(inode)?;
        let file_content = Self::assume_file(&ic)?;
    
        // Update file content
        let new_content = self.repository.write_buffer(file_content, offset, data)?;
        
        ic.attrs.last_metadata_changed = time_now();
        ic.attrs.last_modified = time_now();
        if data.len() + offset as usize > ic.attrs.size as usize {
            ic.attrs.size = (data.len() + offset as usize) as u64;
        }
        
            // #[cfg(feature = "abi-7-31")]
            // if flags & FUSE_WRITE_KILL_PRIV as i32 != 0 {
            //     clear_suid_sgid(&mut attrs);
            // }
            // XXX: In theory we should only need to do this when WRITE_KILL_PRIV is set for 7.31+
            // However, xfstests fail in that case
            clear_suid_sgid(&mut attrs);
            
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
                    return Err(libc::EACCES);
                }
                (libc::R_OK, true, false)
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(libc::EINVAL);
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
            return Err(libc::EACCES);
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
                Err(libc::ERANGE)
            }
        } else {
            #[cfg(target_os = "linux")]
            return Err(libc::ENODATA);
            #[cfg(not(target_os = "linux"))]
            return Err(libc::ENOATTR);
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
            Err(libc::ERANGE)
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
            return Err(libc::ENODATA);
            #[cfg(not(target_os = "linux"))]
            return Err(libc::ENOATTR);
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
            Err(libc::EACCES)
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
    ) -> Result<ReplyCreateOk, c_int> {
        debug!("create() called with {:?} {:?}", parent, name);
        if self.lookup_name(parent, name).is_ok() {
            return Err(libc::EEXIST);
        }
    
        let (read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => (true, false),
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(libc::EINVAL);
            }
        };
    
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
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.write_inode(&parent_attrs);
    
        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }
    
        let inode = self.allocate_next_inode();
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
        self.write_inode(&attrs);
        
        File::create(self.content_path(inode)).unwrap();

        if as_file_kind(mode) == FileKind::Directory {
            let mut entries = BTreeMap::new();
            entries.insert(b".".to_vec(), (inode, FileKind::Directory));
            entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
            self.write_directory_content(inode, entries);
        }
    
        let mut entries = self.get_directory_content(parent)?;
        entries.insert(name.as_bytes().to_vec(), (inode, attrs.kind));
        self.write_directory_content(parent, entries);
    
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

fn fuse_allow_other_enabled() -> io::Result<bool> {
    let file = File::open("/etc/fuse.conf")?;
    for line in BufReader::new(file).lines() {
        if line?.trim_start().starts_with("user_allow_other") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn main() {

    let gen_key_cmd = Command::new("gen-key");

    let matches = Command::new("Crab-FS")
        .version(crate_version!())
        .author("Lukas Rieger")
        .arg(
            Arg::new("encryption-key")
                .long("encryption-key")
                .short('k')
                .value_name("KEY")
                .help("The key used to en-/decrypt the repository"),
        )
        .arg(
            Arg::new("data-dir")
                .long("data-dir")
                .short('d')
                .value_name("DIR")
                .help("Set local directory used to store data"),
        )
        .arg(
            Arg::new("mount-point")
                .long("mount-point")
                .short('m')
                .value_name("MOUNT_POINT")
                .help("Act as a client, and mount FUSE at given path"),
        )
        .arg(
            Arg::new("direct-io")
                .long("direct-io")
                .action(ArgAction::SetTrue)
                .requires("mount-point")
                .help("Mount FUSE with direct IO"),
        )
        .arg(
            Arg::new("fsck")
                .long("fsck")
                .action(ArgAction::SetTrue)
                .help("Run a filesystem check"),
        )
        .arg(
            Arg::new("suid")
                .long("suid")
                .action(ArgAction::SetTrue)
                .help("Enable setuid support when run as root"),
        )
        .arg(
            Arg::new("v")
                .short('v')
                .action(ArgAction::Count)
                .help("Sets the level of verbosity"),
        )
        .subcommand(gen_key_cmd)
        .get_matches();

    if matches.subcommand_matches("gen-key").is_some() {
        let entropy_keyboard = entropy::entropy_from_keyboard();
        let entropy_os = entropy::entropy_from_os();
        let mut rng = entropy::rng_from_entropy(vec![entropy_keyboard, entropy_os ].concat());

        let mut key : [u8;ENCRYPTION_KEY_LENGTH] = [0u8; ENCRYPTION_KEY_LENGTH];
        rng.fill_bytes(&mut key);

        let key_string = base64::encode(key);
        println!("Key:");        
        println!("    {}", key_string);
        println!("");
        return;
    }

    let verbosity = matches.get_count("v");
    let log_level = match verbosity {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();

    let mut options = vec![MountOption::FSName("crab-fs".to_string())];


    #[cfg(feature = "abi-7-26")]
    {
        if matches.get_flag("suid") {
            info!("setuid bit support enabled");
            options.push(MountOption::Suid);
        } else {
            options.push(MountOption::AutoUnmount);
        }
    }
    #[cfg(not(feature = "abi-7-26"))]
    {
        options.push(MountOption::AutoUnmount);
    }
    if let Ok(enabled) = fuse_allow_other_enabled() {
        if enabled {
            options.push(MountOption::AllowOther);
        }
    } else {
        eprintln!("Unable to read /etc/fuse.conf");
    }

    let key_string = matches.get_one::<String>("encryption-key").unwrap().to_string();
    let key: [u8;ENCRYPTION_KEY_LENGTH] = base64::decode(key_string).unwrap().try_into().expect("incorrect base64 encryption key length");

    let data_dir = matches.get_one::<String>("data-dir").unwrap().to_string();

    let mountpoint: String = matches
        .get_one::<String>("mount-point")
        .unwrap()
        .to_string();

    debug!("calling [fuser::mount2] with options={options:?}");

    let fs_options = SimpleFsOptions {
        direct_io: matches.get_flag("direct-io"),         
        #[cfg(feature = "abi-7-26")]
        suid_support: matches.get_flag("suid"),
        ..SimpleFsOptions::default()
    };

    let result = fuser::mount2(
        SimpleFS::new(
            fs_options,
            key,
            data_dir,
        ),
        mountpoint,
        &options,
    );
    if let Err(e) = result {
        // Return a special error code for permission denied, which usually indicates that
        // "user_allow_other" is missing from /etc/fuse.conf
        if e.kind() == ErrorKind::PermissionDenied {
            error!("{}", e.to_string());
            std::process::exit(2);
        }
    }
}