// Note: this is modified from https://github.com/cberner/fuser/blob/d675c07ecb8e826467d53dc00b45a67c731d5b85/examples/simple.rs
// Copyright of the original: Christopher Berner and contributors to https://github.com/cberner/fuser
// License: MIT

#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)] // libc::S_* are u16 or u32 depending on the platform

use fuser::consts::FOPEN_DIRECT_IO;
#[cfg(feature = "abi-7-26")]
use fuser::consts::FUSE_HANDLE_KILLPRIV;
// #[cfg(feature = "abi-7-31")]
// use fuser::consts::FUSE_WRITE_KILL_PRIV;
use fuser::TimeOrNow::Now;
use fuser::{
    FileAttr, Filesystem, KernelConfig, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow,
    FUSE_ROOT_ID,
};
#[cfg(feature = "abi-7-26")]
use log::info;
use log::{debug, trace, warn};
use std::cmp::min;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::collections::HashMap;
use std::sync::RwLock;

use rand::RngCore;

const BLOCK_SIZE: u64 = 512;
const MAX_NAME_LENGTH: u32 = 10_000;
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024 * 1024; // 10 TB

const FMODE_EXEC: i32 = 0x20;

const ENCRYPTION_KEY_LENGTH: usize = 16;

use crate::crypt;
use crate::entropy;
use crate::errors::MyResult;
use crate::io::fs::FS;
use crate::repository;

// ------------------------------------------
// Naming rules
//   inode: Inode [u64]
//   ie: InodeEntry, always refers to `inode`
//   attrs: InodeAttributes, always refers to `ie`
//
// Many functions also handle a parent child relationship, in that case
//   parent: Inode [u64]
//   parent_ie: InodeEntry, always refers to `parent`
//   parent_attrs: InodeAttributes, always refers to `parent_ie`
//

use repository::repository_v1::*;

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
            suid_support: false,
        }
    }
}

struct SimpleFsState {
    next_file_handle: AtomicU64,
    /// (optionally) run the file handle through a feistel network so the values are random and not continuous.
    fh_feistel: crypt::feistel::FeistelNetwork<u64, u32>,

    open_file_handles: RwLock<HashMap<u64, FileHandleEntry>>,
}

pub struct SimpleFS<F: FS> {
    options: SimpleFsOptions,
    state: SimpleFsState,
    encryption_key: [u8; ENCRYPTION_KEY_LENGTH],
    repository: RepositoryV1<F>,
}

impl<F: FS> SimpleFS<F> {
    pub fn new(
        fs: F,
        options: SimpleFsOptions,
        encryption_key: [u8; ENCRYPTION_KEY_LENGTH],
    ) -> SimpleFS<F> {
        let state = {
            let ent = entropy::entropy_from_os();
            let mut rng = entropy::rng_from_entropy(&ent);
            let key = rng.next_u32();
            SimpleFsState {
                fh_feistel: crypt::feistel::FeistelNetwork::new(1, vec![key]),
                next_file_handle: AtomicU64::new(1),
                open_file_handles: RwLock::new(HashMap::new()),
            }
        };

        let repository_options = RepositoryOptions {
            max_inline_content_size: 1024 * 1024, // 1MB
        };
        let repository = RepositoryV1::new(fs, repository_options);

        #[cfg(feature = "abi-7-26")]
        {
            SimpleFS {
                options,
                state,
                encryption_key,
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
            assert!(mode < u16::MAX as u32);
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
        handles.insert(
            fh,
            FileHandleEntry {
                inode,
                permissions: FilePermissions {
                    can_read: read,
                    can_write: write,
                },
            },
        );

        fh
    }

    fn check_file_handle_read(&self, file_handle: u64, inode: Inode) -> bool {
        self.state
            .open_file_handles
            .read()
            .unwrap()
            .get(&file_handle)
            .map(|perms| perms.inode == inode && perms.permissions.can_read)
            .unwrap_or(false)
    }

    fn check_file_handle_write(&self, file_handle: u64, inode: Inode) -> bool {
        self.state
            .open_file_handles
            .read()
            .unwrap()
            .get(&file_handle)
            .map(|perms| perms.inode == inode && perms.permissions.can_write)
            .unwrap_or(false)
    }

    // Check whether a file should be removed from storage. Should be called after decrementing
    // the link count, or closing a file handle
    fn gc_inode(&self, inode: &InodeEntry) -> bool {
        //todo!();
        return false;
    }

    fn truncate(&self, ie: &mut InodeEntry, new_length: u64, uid: u32, gid: u32) -> MyResult<()> {
        if new_length > MAX_FILE_SIZE {
            Err(libc::EFBIG)?;
        }
        let attrs = &mut ie.attrs;

        if !check_access(attrs.uid, attrs.gid, attrs.mode, uid, gid, libc::W_OK) {
            Err(libc::EACCES)?;
        }

        let InodeContent::File(file_content) = &mut ie.content else {
            Err(libc::EISDIR)?
        };

        let old_content = std::mem::take(file_content);
        let new_content = self
            .repository
            .change_content_len(old_content, new_length)?;
        *file_content = new_content;

        attrs.size = new_length;
        attrs.last_metadata_changed = time_now();
        attrs.last_modified = time_now();

        // Clear SETUID & SETGID on truncate
        clear_suid_sgid(attrs);

        self.repository.write_inode(ie.attrs.inode, ie)?;

        Ok(())
    }

    fn try_find_directory_entry<'a>(
        parent: &'a DirectoryDescriptor,
        name: &OsStr,
    ) -> Option<&'a (Inode, FileKind)> {
        parent.get(name.as_bytes())
    }

    fn try_get_child_inode(&self, parent: &InodeContent, name: &OsStr) -> Option<Inode> {
        let Ok(parent_dir_content) = Self::assume_directory(parent) else {
            return None;
        };
        let Some((inode, _)) = Self::try_find_directory_entry(parent_dir_content, name) else {
            return None;
        };
        return Some(*inode);
    }

    #[must_use]
    fn assume_directory(content: &InodeContent) -> Result<&DirectoryDescriptor, c_int> {
        match content {
            InodeContent::File(_) | InodeContent::Symlink(_) => {
                return Err(libc::ENOTDIR);
            }
            InodeContent::Directory(dir_content) => {
                return Ok(dir_content);
            }
        };
    }

    #[must_use]
    fn assume_file(content: &InodeContent) -> Result<&FileContent, c_int> {
        match content {
            InodeContent::Directory(_) | InodeContent::Symlink(_) => {
                return Err(libc::EISDIR);
            }
            InodeContent::File(file_content) => {
                return Ok(file_content);
            }
        };
    }
    #[must_use]
    fn assume_directory_mut(content: &mut InodeContent) -> Result<&mut DirectoryDescriptor, c_int> {
        match content {
            InodeContent::File(_) | InodeContent::Symlink(_) => {
                return Err(libc::ENOTDIR);
            }
            InodeContent::Directory(dir_content) => {
                return Ok(dir_content);
            }
        };
    }

    #[must_use]
    fn assume_file_mut(content: &mut InodeContent) -> Result<&mut FileContent, c_int> {
        match content {
            InodeContent::Directory(_) | InodeContent::Symlink(_) => {
                return Err(libc::EISDIR);
            }
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
    ) -> MyResult<()> {
        let mut parent_node = self.repository.get_inode(parent)?;
        let parent_attrs = &mut parent_node.attrs;

        let dir_content: &mut BTreeMap<Vec<u8>, (u64, FileKind)> =
            Self::assume_directory_mut(&mut parent_node.content)?;

        Self::require_not_exist(dir_content, name)?;

        check_access_rq(parent_attrs, req, libc::W_OK)?;

        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();

        dir_content.insert(name.as_bytes().to_vec(), (inode, kind));

        self.repository.write_inode(inode, &parent_node)?;

        Ok(())
    }
}

impl<F: FS> SimpleFS<F> {
    pub fn create_fs(&mut self) -> MyResult<()> {
        self.repository.init()?;

        let existing_root_node = self.repository.get_inode(FUSE_ROOT_ID);

        match existing_root_node {
            Ok(_) => {
                // fs already exists
                return Err(libc::EEXIST.into());
            }
            Err(e) => {
                if *e == libc::ENOENT {
                    // file not found - great! let's create the repository

                    self.repository.create_new_fs()?;

                    // Initialize with empty filesystem
                    let now = time_now();
                    let root_attr = InodeAttributes {
                        inode: FUSE_ROOT_ID,
                        size: 0,
                        last_accessed: now,
                        last_modified: now,
                        last_metadata_changed: now,
                        kind: FileKind::Directory,
                        mode: 0o777,
                        hardlinks: 2,
                        uid: 0,
                        gid: 0,
                        xattrs: Default::default(),
                    };
                    let mut entries = BTreeMap::new();
                    entries.insert(b".".to_vec(), (FUSE_ROOT_ID, FileKind::Directory));
                    entries.insert(b"..".to_vec(), (FUSE_ROOT_ID, FileKind::Directory));
                    let root_node = InodeEntry {
                        attrs: root_attr,
                        content: InodeContent::Directory(entries),
                    };
                    self.repository.write_inode(FUSE_ROOT_ID, &root_node)?;
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
        };
    }
}

//
// -------------------------------------------------------------------------------------------------------------

impl<F: FS> Filesystem for SimpleFS<F> {
    fn init(
        &mut self,
        _req: &Request,
        #[allow(unused_variables)] config: &mut KernelConfig,
    ) -> Result<(), c_int> {
        #[cfg(feature = "abi-7-26")]
        config.add_capabilities(FUSE_HANDLE_KILLPRIV).unwrap();

        // Add other useful capabilities
        #[cfg(feature = "abi-7-23")]
        if let Err(e) = config.add_capabilities(FUSE_BIG_WRITES) {
            warn!("Failed to set FUSE_BIG_WRITES capability: {:?}", e);
            // Non-fatal, continue
        }

        self.repository.init().map_err(|e| *e)?;

        let existing_root_node = self.repository.get_inode(FUSE_ROOT_ID);

        if let Err(e) = existing_root_node {
            if *e == libc::ENOENT && self.options.create_fs_automatically_if_not_exist {
                self.create_fs().map_err(|e| *e)?;
            } else {
                return Err(*e);
            }
        }

        Ok(())
    }

    fn lookup(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.lookup_syn(req, parent, name) {
            Ok(ok) => reply.entry(&ok.ttl, &ok.attrs, ok.generation),
            Err(error_code) => reply.error(*error_code),
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
        match self.setattr_syn(
            req, inode, mode, uid, gid, size, atime, mtime, _ctime, fh, _crtime, _chgtime,
            _bkuptime, _flags,
        ) {
            Ok(ok) => reply.attr(&ok.ttl, &ok.attrs),
            Err(error_code) => reply.error(*error_code),
        }
    }

    fn readlink(&mut self, _req: &Request, inode: u64, reply: ReplyData) {
        match self.readlink_syn(_req, inode) {
            Ok(ok) => reply.data(&ok.buffer),
            Err(error_code) => reply.error(*error_code),
        }
    }

    fn mknod(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        match self.mknod_syn(req, parent, name, mode, _umask, _rdev) {
            Ok(ok) => {
                reply.entry(&ok.ttl, &ok.attrs, ok.generation);
            }
            Err(err_code) => {
                reply.error(*err_code);
            }
        }
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        match self.mkdir_syn(req, parent, name, mode, _umask) {
            Ok(ok) => reply.entry(&ok.ttl, &ok.attrs, ok.generation),
            Err(error_code) => reply.error(*error_code),
        }
    }
    fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.unlink_syn(req, parent, name) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(*error_code),
        }
    }

    fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.rmdir_syn(req, parent, name) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(*error_code),
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
            }
            Err(err_code) => {
                reply.error(*err_code);
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
            }
            Err(err_code) => {
                reply.error(*err_code);
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
            }
            Err(err_code) => {
                reply.error(*err_code);
            }
        }
    }

    fn open(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        match self.open_syn(req, inode, flags) {
            Ok(ok) => {
                reply.opened(ok.fh, ok.flags);
            }
            Err(err_code) => {
                reply.error(*err_code);
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
            }
            Err(err_code) => {
                reply.error(*err_code);
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
        match self.write_syn(
            _req,
            inode,
            fh,
            offset,
            data,
            _write_flags,
            flags,
            _lock_owner,
        ) {
            Ok(ok) => reply.written(ok.written),
            Err(error_code) => reply.error(*error_code),
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
        self.state.open_file_handles.write().unwrap().remove(&fh);
        reply.ok();
    }

    fn opendir(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        match self.opendir_syn(req, inode, flags) {
            Ok(ok) => reply.opened(ok.fh, ok.flags),
            Err(error_code) => reply.error(*error_code),
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
        debug!("readdir() called with {:?}", inode);
        assert!(offset >= 0);

        let result: MyResult<()> = (|| {
            if !self.check_file_handle_read(fh, inode) {
                return Err(libc::EACCES.into());
            }

            let ie = self.repository.get_inode(inode)?;
            let entries = Self::assume_directory(&ie.content)?;

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
            Ok(())
        })();

        match result {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(*e),
        }
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        self.state.open_file_handles.write().unwrap().remove(&fh);
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
            Err(error_code) => reply.error(*error_code),
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
            Ok(ok) => match ok {
                ReplyXattrOk::Size(size) => reply.size(size),
                ReplyXattrOk::Data(data) => reply.data(&data),
            },
            Err(error_code) => reply.error(*error_code),
        }
    }

    fn listxattr(&mut self, _req: &Request<'_>, inode: u64, size: u32, reply: ReplyXattr) {
        match self.listxattr_syn(_req, inode, size) {
            Ok(ok) => match ok {
                ReplyXattrOk::Size(size) => reply.size(size),
                ReplyXattrOk::Data(data) => reply.data(&data),
            },
            Err(error_code) => reply.error(*error_code),
        }
    }

    fn removexattr(&mut self, request: &Request<'_>, inode: u64, key: &OsStr, reply: ReplyEmpty) {
        match self.removexattr_syn(request, inode, key) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(*error_code),
        }
    }

    fn access(&mut self, req: &Request, inode: u64, mask: i32, reply: ReplyEmpty) {
        match self.access_syn(req, inode, mask) {
            Ok(()) => reply.ok(),
            Err(error_code) => reply.error(*error_code),
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
            Ok(ok) => reply.created(&ok.ttl, &ok.attrs, ok.generation, ok.fh, ok.flags),
            Err(error_code) => reply.error(*error_code),
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
            Err(error_code) => reply.error(*error_code),
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
        match self.copy_file_range_syn(
            _req,
            src_inode,
            src_fh,
            src_offset,
            dest_inode,
            dest_fh,
            dest_offset,
            size,
            _flags,
        ) {
            Ok(ok) => reply.written(ok.written),
            Err(error_code) => reply.error(*error_code),
        }
    }
}
// ------------------------------------------------------------------------------------------
// impl Syn

type ReplyResult<T> = MyResult<T>;

struct ReplyEntryOk {
    ttl: Duration,
    attrs: FileAttr,
    generation: u64,
}
type ReplyEntryResult = ReplyResult<ReplyEntryOk>;

type ReplyEmptyResult = ReplyResult<()>;

struct ReplyCreateOk {
    ttl: Duration,
    attrs: FileAttr,
    generation: u64,
    fh: u64,
    flags: u32,
}
type ReplyCreateResult = ReplyResult<ReplyCreateOk>;

struct ReplyOpenOk {
    fh: u64,
    flags: u32,
}
type ReplyOpenResult = ReplyResult<ReplyOpenOk>;

struct ReplyDataOk {
    buffer: Vec<u8>,
}
type ReplyDataResult = ReplyResult<ReplyDataOk>;

struct ReplyAttrOk {
    ttl: Duration,
    attrs: FileAttr,
}
type ReplyAttrResult = ReplyResult<ReplyAttrOk>;

struct ReplyWriteOk {
    written: u32,
}
type ReplyWriteResult = ReplyResult<ReplyWriteOk>;

enum ReplyXattrOk {
    Size(u32),
    Data(Vec<u8>),
}
type ReplyXattrResult = ReplyResult<ReplyXattrOk>;

impl<F: FS> SimpleFS<F> {
    fn lookup_syn(&mut self, req: &Request, parent: u64, name: &OsStr) -> ReplyEntryResult {
        trace!("lookup() called for parent={} name={:?}", parent, name);

        if name.len() > MAX_NAME_LENGTH as usize {
            Err(libc::ENAMETOOLONG)?;
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
            Err(libc::EACCES)?;
        }

        match parent_node.content {
            InodeContent::Symlink(_) | InodeContent::File(_) => {
                return Err(libc::ENOTDIR.into());
            }
            InodeContent::Directory(dir_content) => {
                if let Some((inode, _)) = dir_content.get(name.as_bytes()) {
                    let ic = self.repository.get_inode(*inode)?;
                    Ok(ReplyEntryOk {
                        ttl: Duration::new(0, 0),
                        attrs: ic.attrs.into(),
                        generation: 0,
                    })
                } else {
                    Err(libc::ENOENT.into())
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
        let mut ie = self.repository.get_inode(inode)?;
        let now = time_now();

        if let Some(mode) = mode {
            debug!("chmod() called with {:?}, {:o}", inode, mode);
            let attrs = &mut ie.attrs;

            // only owner or root can change mod
            if req.uid() != 0 && req.uid() != attrs.uid {
                Err(libc::EPERM)?;
            }

            if req.uid() != 0
                && req.gid() != attrs.gid
                && !get_groups(req.pid()).contains(&attrs.gid)
            {
                // If SGID is set and the file belongs to a group that the caller is not part of
                // then the SGID bit is suppose to be cleared during chmod
                attrs.mode = (mode & !(libc::S_ISUID | libc::S_ISGID) as u32) as u16;
            } else {
                attrs.mode = mode as u16;
            }
            attrs.last_metadata_changed = now;
            self.repository.write_inode(inode, &ie)?;
        }

        if uid.is_some() || gid.is_some() {
            debug!("chown() called with {:?} {:?} {:?}", inode, uid, gid);
            let attrs = &mut ie.attrs;
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
                clear_suid_sgid(attrs);
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
            attrs.last_metadata_changed = now;
            self.repository.write_inode(inode, &ie)?;
        }

        if let Some(size) = size {
            debug!("truncate() called with {:?} {:?}", inode, size);
            if let Some(handle) = fh {
                // If the file handle is available, check access locally.
                // This is important as it preserves the semantic that a file handle opened
                // with W_OK will never fail to truncate, even if the file has been subsequently
                // chmod'ed
                if self.check_file_handle_write(handle, inode) {
                    self.truncate(&mut ie, size, 0, 0)?;
                } else {
                    return Err(libc::EACCES.into());
                }
            } else {
                self.truncate(&mut ie, size, req.uid(), req.gid())?;
            }
        }

        if let Some(atime) = atime {
            let attrs = &mut ie.attrs;
            debug!("utimens() called with {:?}, atime={:?}", inode, atime);

            if attrs.uid != req.uid() && req.uid() != 0 && atime != Now {
                return Err(libc::EPERM.into());
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
                return Err(libc::EACCES.into());
            }

            attrs.last_accessed = match atime {
                TimeOrNow::SpecificTime(time) => time_from_system_time(&time),
                Now => now,
            };
            attrs.last_metadata_changed = now;
            self.repository.write_inode(inode, &ie)?;
        }

        if let Some(mtime) = mtime {
            let attrs = &mut ie.attrs;
            debug!("utimens() called with {:?}, mtime={:?}", inode, mtime);

            if attrs.uid != req.uid() && req.uid() != 0 && mtime != Now {
                return Err(libc::EPERM.into());
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
                return Err(libc::EACCES.into());
            }

            attrs.last_modified = match mtime {
                TimeOrNow::SpecificTime(time) => time_from_system_time(&time),
                Now => now,
            };
            attrs.last_metadata_changed = now;
            self.repository.write_inode(inode, &ie)?;
        }

        Ok(ReplyAttrOk {
            ttl: Duration::new(0, 0),
            attrs: ie.attrs.into(),
        })
    }

    fn readlink_syn(&mut self, _req: &Request, inode: u64) -> ReplyDataResult {
        debug!("readlink() called on {:?}", inode);
        let ie = self.repository.get_inode(inode)?;

        match &ie.content {
            InodeContent::Symlink(target) => Ok(ReplyDataOk {
                buffer: target.clone(),
            }),
            _ => Err(libc::EINVAL.into()),
        }
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
            warn!("mknod() implementation is incomplete. Only supports regular files, symlinks, and directories. Got {:o}", mode);
            return Err(libc::ENOSYS.into());
        }

        let mut parent_ie = self.repository.get_inode(parent)?;
        let parent_dir_content = Self::assume_directory_mut(&mut parent_ie.content)?;
        Self::require_not_exist(parent_dir_content, name)?;
        let parent_attrs = &mut parent_ie.attrs;

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

        let now = time_now();
        let inode = self.repository.allocate_next_inode()?;
        let attrs = InodeAttributes {
            inode,
            // open_file_handles: 0,
            size: 0,
            last_accessed: now,
            last_modified: now,
            last_metadata_changed: now,
            kind: as_file_kind(mode),
            mode: self.creation_mode(mode),
            hardlinks: 1,
            uid: req.uid(),
            gid: creation_gid(parent_attrs, req.gid()),
            xattrs: Default::default(),
        };

        let content = match as_file_kind(mode) {
            FileKind::Directory => {
                let mut entries = BTreeMap::new();
                entries.insert(b".".to_vec(), (inode, FileKind::Directory));
                entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
                InodeContent::Directory(entries)
            }
            FileKind::File => InodeContent::File(FileContent::EMPTY),
            _ => {
                // not sure what target to point a symlink at etc
                return Err(libc::ENOSYS.into());
            }
        };

        let ie = InodeEntry { attrs, content };
        self.repository.write_inode(inode, &ie)?;

        parent_dir_content.insert(name.as_bytes().to_vec(), (inode, ie.attrs.kind));
        parent_attrs.last_modified = now;
        parent_attrs.last_metadata_changed = now;
        self.repository.write_inode(parent, &parent_ie)?;

        // TODO: implement flags
        Ok(ReplyEntryOk {
            ttl: Duration::new(0, 0),
            attrs: ie.attrs.into(),
            generation: 0,
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

        let mut parent_node = self.repository.get_inode(parent)?;
        let parent_dir_content = Self::assume_directory_mut(&mut parent_node.content)?;
        Self::require_not_exist(parent_dir_content, name)?;
        let parent_attrs = &mut parent_node.attrs;
        check_access_rq(parent_attrs, req, libc::W_OK)?;

        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }
        if parent_attrs.mode & libc::S_ISGID as u16 != 0 {
            mode |= libc::S_ISGID as u32;
        }

        let now = time_now();
        let inode = self.repository.allocate_next_inode()?;
        let attrs = InodeAttributes {
            inode,
            size: BLOCK_SIZE,
            last_accessed: now,
            last_modified: now,
            last_metadata_changed: now,
            kind: FileKind::Directory,
            mode: self.creation_mode(mode),
            hardlinks: 2, // Directories start with link count of 2, since they have a self link
            uid: req.uid(),
            gid: creation_gid(parent_attrs, req.gid()),
            xattrs: Default::default(),
        };

        let mut entries = BTreeMap::new();
        entries.insert(b".".to_vec(), (inode, FileKind::Directory));
        entries.insert(b"..".to_vec(), (parent, FileKind::Directory));

        let ie = InodeEntry {
            attrs,
            content: InodeContent::Directory(entries),
        };
        self.repository.write_inode(inode, &ie)?;

        parent_attrs.last_modified = now;
        parent_attrs.last_metadata_changed = now;

        parent_dir_content.insert(name.as_bytes().to_vec(), (inode, FileKind::Directory));
        self.repository.write_inode(parent, &parent_node)?;

        Ok(ReplyEntryOk {
            ttl: Duration::new(0, 0),
            attrs: ie.attrs.into(),
            generation: 0,
        })
    }

    fn unlink_syn(&mut self, req: &Request, parent: u64, name: &OsStr) -> ReplyEmptyResult {
        debug!("unlink() called with {:?} {:?}", parent, name);
        let mut parent_ie = self.repository.get_inode(parent)?;
        let parent_attrs = &mut parent_ie.attrs;

        let parent_content = Self::assume_directory_mut(&mut parent_ie.content)?;
        let (inode, kind) =
            *Self::try_find_directory_entry(parent_content, name).ok_or(libc::ENOENT)?;
        let mut ie = self.repository.get_inode(inode)?;
        let attrs = &mut ie.attrs;

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

        let uid = req.uid();
        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && uid != 0
            && uid != parent_attrs.uid
            && uid != attrs.uid
        {
            return Err(libc::EACCES.into());
        }

        let now = time_now();

        parent_attrs.last_metadata_changed = now;
        parent_attrs.last_modified = now;
        parent_content.remove(name.as_bytes());
        self.repository.write_inode(parent, &parent_ie)?;

        attrs.hardlinks -= 1;
        attrs.last_metadata_changed = now;
        self.repository.write_inode(inode, &ie)?;
        self.gc_inode(&ie);

        Ok(())
    }

    fn rmdir_syn(&mut self, req: &Request, parent: u64, name: &OsStr) -> ReplyEmptyResult {
        debug!("rmdir() called with {:?} {:?}", parent, name);

        let mut parent_ie = self.repository.get_inode(parent)?;
        let parent_attrs = &mut parent_ie.attrs;
        let parent_content = Self::assume_directory_mut(&mut parent_ie.content)?;

        let (inode, kind) =
            *Self::try_find_directory_entry(parent_content, name).ok_or(libc::ENOENT)?;
        let mut ie = self.repository.get_inode(inode)?;
        let attrs = &mut ie.attrs;

        if kind != FileKind::Directory {
            return Err(libc::ENOTDIR.into());
        }

        let dir_content = Self::assume_directory(&ie.content)?;
        if dir_content.len() > 2 {
            return Err(libc::ENOTEMPTY.into());
        }

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

        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && req.uid() != 0
            && req.uid() != parent_attrs.uid
            && req.uid() != attrs.uid
        {
            return Err(libc::EACCES.into());
        }

        let now = time_now();

        parent_attrs.last_metadata_changed = now;
        parent_attrs.last_modified = now;
        parent_content.remove(name.as_bytes());
        self.repository.write_inode(parent, &parent_ie)?;

        attrs.hardlinks -= 1;
        attrs.last_metadata_changed = now;
        self.repository.write_inode(inode, &ie)?;
        self.gc_inode(&ie);

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
        let mut parent_node = self.repository.get_inode(parent)?;

        check_access_rq(&parent_node.attrs, req, libc::W_OK)?;
        let dir_content = Self::assume_directory_mut(&mut parent_node.content)?;

        Self::require_not_exist(dir_content, link_name)?;

        let now = time_now();

        let inode = self.repository.allocate_next_inode()?;
        let attrs = InodeAttributes {
            inode,
            size: target.as_os_str().as_bytes().len() as u64,
            last_accessed: now,
            last_modified: now,
            last_metadata_changed: now,
            kind: FileKind::Symlink,
            mode: 0o777,
            hardlinks: 1,
            uid: req.uid(),
            gid: creation_gid(&parent_node.attrs, req.gid()),
            xattrs: Default::default(),
        };

        let ie = InodeEntry {
            attrs,
            content: InodeContent::Symlink(target.as_os_str().as_bytes().to_vec()),
        };
        self.repository.write_inode(inode, &ie)?;

        parent_node.attrs.last_modified = now;
        parent_node.attrs.last_metadata_changed = now;
        dir_content.insert(link_name.as_bytes().to_vec(), (inode, FileKind::Symlink));
        self.repository.write_inode(parent, &parent_node)?;

        Ok(ReplyEntryOk {
            ttl: Duration::new(0, 0),
            attrs: ie.attrs.into(),
            generation: 0,
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

        let now: (i64, u32) = time_now();

        // important note: there's a good chance parent and new_parent are the same!
        // this can be ignored if we only read the inode entry, but as soon as the entry is written, it needs to be taken into account!

        let mut parent_ie = self.repository.get_inode(parent)?;
        let parent_content = Self::assume_directory_mut(&mut parent_ie.content)?;
        let (inode, kind) =
            *Self::try_find_directory_entry(parent_content, name).ok_or(libc::ENOENT)?;
        let mut source_ie = self.repository.get_inode(inode)?;

        check_access_rq(&parent_ie.attrs, req, libc::W_OK)?;

        // "Sticky bit" handling
        if parent_ie.attrs.mode & libc::S_ISVTX as u16 != 0
            && req.uid() != 0
            && req.uid() != parent_ie.attrs.uid
            && req.uid() != source_ie.attrs.uid
        {
            return Err(libc::EACCES.into());
        }

        let new_parent_ie = self.repository.get_inode(new_parent)?;
        check_access_rq(&new_parent_ie.attrs, req, libc::W_OK)?;

        let existing_target_inode = self.try_get_child_inode(&new_parent_ie.content, new_name);
        let mut existing_target_ie: Option<InodeEntry> = {
            match existing_target_inode {
                None => None,
                Some(ino) => Some(self.repository.get_inode(ino)?),
            }
        };
        // "Sticky bit" handling in new_parent
        if new_parent_ie.attrs.mode & libc::S_ISVTX as u16 != 0 {
            if let Some(existing_ie) = &existing_target_ie {
                if req.uid() != 0
                    && req.uid() != new_parent_ie.attrs.uid
                    && req.uid() != existing_ie.attrs.uid
                {
                    return Err(libc::EACCES.into());
                }
            }
        }

        #[cfg(target_os = "linux")]
        fn handle_exchange_rename<F: FS>(
            _self: &mut SimpleFS<F>,
            _req: &Request,
            mut parent_ie: InodeEntry,
            name: &OsStr,
            new_parent_ie: InodeEntry,
            new_name: &OsStr,
            mut source_ie: InodeEntry,
            now: (i64, u32),
        ) -> ReplyEmptyResult {
            let parent_content = SimpleFS::<F>::assume_directory_mut(&mut parent_ie.content)?;
            let new_parent_content = SimpleFS::<F>::assume_directory(&new_parent_ie.content)?;

            // Get target inode entry
            let (target_ino, target_kind) =
                *SimpleFS::<F>::try_find_directory_entry(new_parent_content, new_name)
                    .ok_or(libc::ENOENT)?;
            let mut target_ie = _self.repository.get_inode(target_ino)?;

            // there's a change old parent and new parent are the same - then we have two references to the same inode, and writing both would overwrite the previous

            if parent_ie.attrs.inode != new_parent_ie.attrs.inode {
                // different inodes
                let mut new_parent_ie = new_parent_ie;
                let new_parent_content =
                    SimpleFS::<F>::assume_directory_mut(&mut new_parent_ie.content)?;

                parent_content.insert(name.as_bytes().to_vec(), (target_ino, target_kind));
                new_parent_content.insert(
                    new_name.as_bytes().to_vec(),
                    (source_ie.attrs.inode, source_ie.attrs.kind),
                );

                // Update ".." entries if directories are involved
                if source_ie.attrs.kind == FileKind::Directory {
                    let dir_content = SimpleFS::<F>::assume_directory_mut(&mut source_ie.content)?;
                    dir_content.insert(
                        b"..".to_vec(),
                        (new_parent_ie.attrs.inode, FileKind::Directory),
                    );
                }

                if target_kind == FileKind::Directory {
                    let dir_content = SimpleFS::<F>::assume_directory_mut(&mut target_ie.content)?;
                    dir_content
                        .insert(b"..".to_vec(), (parent_ie.attrs.inode, FileKind::Directory));
                }

                // Update timestamps

                parent_ie.attrs.last_metadata_changed = now;
                parent_ie.attrs.last_modified = now;

                new_parent_ie.attrs.last_metadata_changed = now;
                new_parent_ie.attrs.last_modified = now;

                source_ie.attrs.last_metadata_changed = now;

                target_ie.attrs.last_metadata_changed = now;

                // Write all changes
                _self
                    .repository
                    .write_inode(parent_ie.attrs.inode, &parent_ie)?;
                _self
                    .repository
                    .write_inode(new_parent_ie.attrs.inode, &new_parent_ie)?;
                _self
                    .repository
                    .write_inode(source_ie.attrs.inode, &source_ie)?;
                _self
                    .repository
                    .write_inode(target_ie.attrs.inode, &target_ie)?;
            } else {
                // same inode
                // ignore `new_parent_ie` since it points to the same inode as `parent_ie`

                parent_content.insert(name.as_bytes().to_vec(), (target_ino, target_kind));
                parent_content.insert(
                    new_name.as_bytes().to_vec(),
                    (source_ie.attrs.inode, source_ie.attrs.kind),
                );

                // Update timestamps
                parent_ie.attrs.last_metadata_changed = now;
                parent_ie.attrs.last_modified = now;

                source_ie.attrs.last_metadata_changed = now;

                target_ie.attrs.last_metadata_changed = now;

                // Write all changes
                _self
                    .repository
                    .write_inode(parent_ie.attrs.inode, &parent_ie)?;
                _self
                    .repository
                    .write_inode(source_ie.attrs.inode, &source_ie)?;
                _self
                    .repository
                    .write_inode(target_ie.attrs.inode, &target_ie)?;
            }

            Ok(())
        }

        #[cfg(target_os = "linux")]
        if flags & libc::RENAME_EXCHANGE as u32 != 0 {
            return handle_exchange_rename(
                self,
                req,
                parent_ie,
                name,
                new_parent_ie,
                new_name,
                source_ie,
                now,
            );
        }

        // Only overwrite an existing directory if it's empty
        if let Some(existing_target_ie) = &mut existing_target_ie {
            if let Ok(dir_content) = Self::assume_directory(&existing_target_ie.content) {
                if dir_content.len() > 2 {
                    return Err(libc::ENOTEMPTY.into());
                }
            }
        }

        // Only move an existing directory to a new parent, if we have write access to it,
        // because that will change the ".." link in it
        if kind == FileKind::Directory
            && parent != new_parent
            && !check_access(
                source_ie.attrs.uid,
                source_ie.attrs.gid,
                source_ie.attrs.mode,
                req.uid(),
                req.gid(),
                libc::W_OK,
            )
        {
            return Err(libc::EACCES.into());
        }

        // If target already exists decrement its hardlink count
        if let Some(existing_target_ie) = &mut existing_target_ie {
            if existing_target_ie.attrs.kind == FileKind::Directory {
                existing_target_ie.attrs.hardlinks = 0;
            } else {
                existing_target_ie.attrs.hardlinks -= 1;
            }
            existing_target_ie.attrs.last_metadata_changed = now;
            self.repository
                .write_inode(existing_target_ie.attrs.inode, existing_target_ie)?;
            self.gc_inode(existing_target_ie);
        }

        // now we need to take care of whether this is a rename with the same parents or not
        if parent_ie.attrs.inode != new_parent_ie.attrs.inode {
            // different parents
            let mut new_parent_ie = new_parent_ie;
            let new_parent_content = Self::assume_directory_mut(&mut new_parent_ie.content)?;

            // remove from old parent
            parent_content.remove(name.as_bytes());

            // add to new parent, potentially overwriting an existing entry
            new_parent_content.insert(new_name.as_bytes().to_vec(), (inode, kind));

            parent_ie.attrs.last_metadata_changed = now;
            parent_ie.attrs.last_modified = now;
            new_parent_ie.attrs.last_metadata_changed = now;
            new_parent_ie.attrs.last_modified = now;
            source_ie.attrs.last_metadata_changed = now;

            // if the node being moved is a dir, update ".."
            if let Ok(dir_content) = Self::assume_directory_mut(&mut source_ie.content) {
                dir_content.insert(b"..".to_vec(), (new_parent, FileKind::Directory));
            }

            self.repository.write_inode(inode, &source_ie)?;
            self.repository.write_inode(parent, &parent_ie)?;
            self.repository.write_inode(new_parent, &new_parent_ie)?;
        } else {
            // same parents
            parent_content.remove(name.as_bytes());
            parent_content.insert(new_name.as_bytes().to_vec(), (inode, kind));

            parent_ie.attrs.last_metadata_changed = now;
            parent_ie.attrs.last_modified = now;
            source_ie.attrs.last_metadata_changed = now;

            self.repository.write_inode(inode, &source_ie)?;
            self.repository.write_inode(parent, &parent_ie)?;
        }

        Ok(())
    }

    fn link_syn(
        &mut self,
        req: &Request,
        inode: u64,
        new_parent: u64,
        new_name: &OsStr,
    ) -> ReplyEntryResult {
        debug!(
            "link() called for {}, {}, {:?}",
            inode, new_parent, new_name
        );
        let mut ie = self.repository.get_inode(inode)?;

        self.insert_link(req, new_parent, new_name, inode, ie.attrs.kind)?;

        ie.attrs.hardlinks += 1;
        ie.attrs.last_metadata_changed = time_now();
        self.repository.write_inode(inode, &ie)?;

        Ok(ReplyEntryOk {
            ttl: Duration::new(0, 0),
            attrs: ie.attrs.into(),
            generation: 0,
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

        let ic = self.repository.get_inode(inode)?;

        check_access_rq(&ic.attrs, req, access_mask)?;

        let fh = self.allocate_next_file_handle(inode, read, write);
        let open_flags = if self.options.direct_io {
            FOPEN_DIRECT_IO
        } else {
            0
        };

        Ok(ReplyOpenOk {
            fh,
            flags: open_flags,
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
        _lock_owner: Option<u64>,
    ) -> ReplyDataResult {
        debug!(
            "read() called on {:?} offset={:?} size={:?}",
            inode, offset, size
        );
        assert!(offset >= 0);
        let offset: u64 = offset as u64;

        if !self.check_file_handle_read(fh, inode) {
            return Err(libc::EACCES.into());
        }

        let ie = self.repository.get_inode(inode)?;
        let file_content = Self::assume_file(&ie.content)?;

        if ie.attrs.size <= offset {
            return Err(libc::EOF.into());
        }
        let read_size = min(size as u64, ie.attrs.size - offset);
        let mut buffer = vec![0u8; read_size as usize];
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
        let offset: u64 = offset as u64;

        if !self.check_file_handle_write(fh, inode) {
            return Err(libc::EACCES.into());
        }

        let mut ic = self.repository.get_inode(inode)?;
        let file_content = Self::assume_file(&ic.content)?;

        // Update file content
        let now = time_now();

        let new_content = self.repository.write(file_content, offset, data)?;

        ic.attrs.last_metadata_changed = now;
        ic.attrs.last_modified = now;
        if data.len() + offset as usize > ic.attrs.size as usize {
            ic.attrs.size = (data.len() + offset as usize) as u64;
        }

        ic.content = InodeContent::File(new_content);

        // #[cfg(feature = "abi-7-31")]
        // if flags & FUSE_WRITE_KILL_PRIV as i32 != 0 {
        //     clear_suid_sgid(&mut attrs);
        // }
        // XXX: In theory we should only need to do this when WRITE_KILL_PRIV is set for 7.31+
        // However, xfstests fail in that case
        clear_suid_sgid(&mut ic.attrs);

        self.repository.write_inode(inode, &ic)?;

        Ok(ReplyWriteOk {
            written: data.len() as u32,
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

        let ic = self.repository.get_inode(inode)?;
        let dir_content = Self::assume_directory(&ic.content)?;

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

        let open_flags = if self.options.direct_io {
            FOPEN_DIRECT_IO
        } else {
            0
        };
        let fh = self.allocate_next_file_handle(inode, read, write);
        Ok(ReplyOpenOk {
            fh,
            flags: open_flags,
        })
    }

    fn getxattr_syn(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
        size: u32,
    ) -> ReplyXattrResult {
        let ie = self.repository.get_inode(inode)?;

        xattr_access_check(key.as_bytes(), libc::R_OK, &ie.attrs, request)?;

        if let Some(data) = ie.attrs.xattrs.get(key.as_bytes()) {
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
        flags: i32,
        _position: u32,
    ) -> ReplyEmptyResult {
        let mut ie = self.repository.get_inode(inode)?;

        xattr_access_check(key.as_bytes(), libc::W_OK, &ie.attrs, request)?;

        // Handle creation flags
        let key_exists = ie.attrs.xattrs.contains_key(key.as_bytes());
        if flags & libc::XATTR_CREATE as i32 != 0 && key_exists {
            return Err(libc::EEXIST.into());
        }
        if flags & libc::XATTR_REPLACE as i32 != 0 && !key_exists {
            return Err(libc::ENODATA.into());
        }

        ie.attrs
            .xattrs
            .insert(key.as_bytes().to_vec(), value.to_vec());
        ie.attrs.last_metadata_changed = time_now();
        self.repository.write_inode(inode, &ie)?;

        Ok(())
    }

    fn listxattr_syn(&mut self, _req: &Request<'_>, inode: u64, size: u32) -> ReplyXattrResult {
        let attrs = self.repository.get_inode(inode)?;

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
        let mut ie = self.repository.get_inode(inode)?;

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

    fn access_syn(&mut self, req: &Request, inode: u64, mask: i32) -> ReplyEmptyResult {
        debug!("access() called with {:?} {:?}", inode, mask);
        let ie = self.repository.get_inode(inode)?;

        if check_access(
            ie.attrs.uid,
            ie.attrs.gid,
            ie.attrs.mode,
            req.uid(),
            req.gid(),
            mask,
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

        let mut parent_ie = self.repository.get_inode(parent)?;
        let parent_dir_content = Self::assume_directory_mut(&mut parent_ie.content)?;
        Self::require_not_exist(parent_dir_content, name)?;
        let parent_attrs = &mut parent_ie.attrs;

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
        let now = time_now();
        let inode = self.repository.allocate_next_inode()?;
        let attrs = InodeAttributes {
            inode,
            size: 0,
            last_accessed: now,
            last_modified: now,
            last_metadata_changed: now,
            kind: as_file_kind(mode),
            mode: self.creation_mode(mode),
            hardlinks: 1,
            uid: req.uid(),
            gid: creation_gid(parent_attrs, req.gid()),
            xattrs: Default::default(),
        };

        let content = match as_file_kind(mode) {
            FileKind::Directory => {
                let mut entries = BTreeMap::new();
                entries.insert(b".".to_vec(), (inode, FileKind::Directory));
                entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
                InodeContent::Directory(entries)
            }
            FileKind::File => InodeContent::File(FileContent::EMPTY),
            _ => {
                // not sure what target to point a symlink at etc
                return Err(libc::ENOSYS.into());
            }
        };
        let ie = InodeEntry { attrs, content };
        self.repository.write_inode(inode, &ie)?;

        parent_dir_content.insert(name.as_bytes().to_vec(), (inode, ie.attrs.kind));
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.repository.write_inode(parent, &parent_ie)?;

        let fh = self.allocate_next_file_handle(inode, read, write);
        // TODO: implement flags
        Ok(ReplyCreateOk {
            ttl: Duration::new(0, 0),
            attrs: ie.attrs.into(),
            generation: 0,
            fh,
            flags: 0,
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
        assert!(offset >= 0);
        assert!(length >= 0);
        let offset = offset as u64;
        let length = length as u64;

        let mut ie = self.repository.get_inode(inode)?;
        let file_content = Self::assume_file_mut(&mut ie.content)?;

        let new_size = if mode & libc::FALLOC_FL_KEEP_SIZE != 0 {
            // Don't extend file size
            ie.attrs.size
        } else {
            // Extend if needed
            std::cmp::max(ie.attrs.size, offset + length)
        };

        let zero_length = std::cmp::min(length, new_size - offset);

        if zero_length > 0 {
            let new_content = self
                .repository
                .zero_range(file_content, offset, zero_length)?;
            ie.content = InodeContent::File(new_content);
        }

        ie.attrs.size = new_size;
        ie.attrs.last_metadata_changed = time_now();
        ie.attrs.last_modified = time_now();
        self.repository.write_inode(inode, &ie)?;

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

        assert!(src_offset >= 0);
        assert!(dest_offset >= 0);
        let src_offset: u64 = src_offset as u64;
        let dest_offset: u64 = dest_offset as u64;

        if !self.check_file_handle_read(src_fh, src_inode) {
            return Err(libc::EACCES.into());
        }
        if !self.check_file_handle_write(dest_fh, dest_inode) {
            return Err(libc::EACCES.into());
        }

        let src_ie = self.repository.get_inode(src_inode)?;
        let src_content = Self::assume_file(&src_ie.content)?;

        let mut dest_ie = self.repository.get_inode(dest_inode)?;
        let dest_content = Self::assume_file(&dest_ie.content)?;

        // Could underflow if file length is less than local_start
        let read_size = min(size, src_ie.attrs.size.saturating_sub(src_offset));

        let updated_dest_content =
            self.repository
                .copy_range(src_content, dest_content, src_offset, dest_offset, size)?;
        dest_ie.attrs.size = updated_dest_content.len() as u64;
        dest_ie.attrs.last_metadata_changed = time_now();
        dest_ie.attrs.last_modified = time_now();
        dest_ie.content = InodeContent::File(updated_dest_content);
        self.repository.write_inode(dest_inode, &dest_ie)?;

        Ok(ReplyWriteOk {
            written: read_size as u32,
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
pub fn check_access_rq(
    attrs: &InodeAttributes,
    req: &Request,
    access_mask: i32,
) -> Result<(), c_int> {
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
