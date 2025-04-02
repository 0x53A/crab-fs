use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{self, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use std::vec;

use crab_fs_common::errors::{MyError, MyResult};
use crab_fs_common::io::fs::{
    Capabilities, Finalize, Len, SetLen, SimpleSnapshot, Snapshot, Snapshottable, TFile, FS,
};

type InMemoryPathSegment = Box<[u8]>;
type InMemoryPath = [InMemoryPathSegment];

// Helper function to convert Path to InMemoryPath segments
fn path_to_segments<P: AsRef<Path>>(path: P) -> Vec<InMemoryPathSegment> {
    path.as_ref()
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(
                s.to_string_lossy()
                    .into_owned()
                    .into_bytes()
                    .into_boxed_slice(),
            ),
            _ => None,
        })
        .collect()
}

pub struct FileEntry {
    pub data: Vec<u8>,
    pub created: SystemTime,
    pub last_modified: SystemTime,
}

impl FileEntry {
    fn new() -> Self {
        let now = SystemTime::now();
        FileEntry {
            data: Vec::new(),
            created: now,
            last_modified: now,
        }
    }

    fn update_modified_time(&mut self) {
        self.last_modified = SystemTime::now();
    }
}

pub struct DirectoryEntry {
    files: HashMap<InMemoryPathSegment, FileEntry>,
    directories: HashMap<InMemoryPathSegment, DirectoryEntry>,
}

impl DirectoryEntry {
    fn new() -> Self {
        DirectoryEntry {
            files: HashMap::new(),
            directories: HashMap::new(),
        }
    }
}

pub enum Entry {
    Directory(DirectoryEntry),
    FileEntry(FileEntry),
}

pub struct InMemoryFsData {
    root: DirectoryEntry,
    open_handles: HashMap<u32, InMemoryFileHandleData>,
    next_handle_id: u32,
}

impl InMemoryFsData {
    fn get_file_entry(&self, path: &[InMemoryPathSegment]) -> MyResult<&FileEntry> {
        if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Path is empty").into());
        }

        let dir_path = &path[0..path.len() - 1];
        let file_name = &path[path.len() - 1];

        let dir = self.get_directory_entry(dir_path)?;

        dir.files
            .get(file_name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File not found").into())
    }

    fn get_file_entry_mut(&mut self, path: &[InMemoryPathSegment]) -> MyResult<&mut FileEntry> {
        if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Path is empty").into());
        }

        let dir_path = &path[0..path.len() - 1];
        let file_name = &path[path.len() - 1];

        let dir = self.get_directory_entry_mut(dir_path)?;

        dir.files
            .get_mut(file_name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File not found").into())
    }

    fn get_directory_entry(&self, path: &[InMemoryPathSegment]) -> MyResult<&DirectoryEntry> {
        if path.is_empty() {
            return Ok(&self.root);
        }

        let mut current_dir = &self.root;

        for segment in path {
            current_dir = current_dir
                .directories
                .get(segment)
                .ok_or_else(|| MyError::new_io(io::ErrorKind::NotFound, "Directory not found"))?;
        }

        Ok(current_dir)
    }

    fn get_directory_entry_mut(
        &mut self,
        path: &[InMemoryPathSegment],
    ) -> MyResult<&mut DirectoryEntry> {
        if path.is_empty() {
            return Ok(&mut self.root);
        }

        let mut current_dir = &mut self.root;

        for segment in path {
            current_dir = current_dir
                .directories
                .get_mut(segment)
                .ok_or_else(|| MyError::new_io(io::ErrorKind::NotFound, "Directory not found"))?;
        }

        Ok(current_dir)
    }

    // Create directories recursively
    fn create_directories(&mut self, path: &[InMemoryPathSegment]) -> MyResult<()> {
        if path.is_empty() {
            return Ok(());
        }

        let mut current_dir = &mut self.root;

        for segment in path {
            current_dir = current_dir
                .directories
                .entry(segment.clone())
                .or_insert_with(DirectoryEntry::new);
        }

        Ok(())
    }

    fn create_file(&mut self, path: &[InMemoryPathSegment]) -> MyResult<&mut FileEntry> {
        if path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot create file with empty path",
            )
            .into());
        }

        let dir_path = &path[0..path.len() - 1];
        let file_name = &path[path.len() - 1];

        // Get the parent directory
        let dir = self.get_directory_entry_mut(dir_path)?;

        // Create the file if it doesn't exist
        let mut file_entry = dir.files.entry(file_name.clone());

        match &mut file_entry {
            std::collections::hash_map::Entry::Occupied(ref mut occupied_entry) => {
                let entry = occupied_entry.get_mut();
                entry.data.clear();
                entry.update_modified_time();
            }
            std::collections::hash_map::Entry::Vacant(_) => {}
        };

        Ok(file_entry.or_insert_with(FileEntry::new))
    }

    // Rename a file from one path to another
    fn rename_file(
        &mut self,
        from_path: &[InMemoryPathSegment],
        to_path: &[InMemoryPathSegment],
    ) -> MyResult<()> {
        if from_path.is_empty() || to_path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot rename with empty path",
            )
            .into());
        }

        // Extract the file entry from the source
        let file_entry = {
            let from_dir_path = &from_path[0..from_path.len() - 1];
            let from_file_name = &from_path[from_path.len() - 1];

            let from_dir = self.get_directory_entry_mut(from_dir_path)?;

            // Remove the file from source
            from_dir
                .files
                .remove(from_file_name)
                .ok_or_else(|| MyError::new_io(io::ErrorKind::NotFound, "Source file not found"))?
        };

        // Create the destination's parent directories if needed
        let to_dir_path = &to_path[0..to_path.len() - 1];
        let to_file_name = &to_path[to_path.len() - 1];

        // Get the destination directory and insert the file
        let to_dir = self.get_directory_entry_mut(to_dir_path)?;

        // Check if destination already exists
        if to_dir.files.contains_key(to_file_name) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Destination file already exists",
            )
            .into());
        }

        to_dir.files.insert(to_file_name.clone(), file_entry);

        Ok(())
    }
}

pub struct FileHandlePermissions {
    pub read: bool,
    pub write: bool,
}

#[derive(Clone)]
pub struct InMemoryFS {
    fs_data: Arc<Mutex<InMemoryFsData>>,
}

struct InMemoryFileHandleData {
    path: Vec<InMemoryPathSegment>,
    position: u64,
    permissions: FileHandlePermissions,
}

pub struct InMemoryFileHandle {
    id: u32,
    fs: Arc<Mutex<InMemoryFS>>,
}

impl InMemoryFS {
    pub fn new() -> Self {
        let root = DirectoryEntry::new();
        let fs_data = InMemoryFsData {
            root,
            open_handles: HashMap::new(),
            next_handle_id: 0,
        };

        InMemoryFS {
            fs_data: Arc::new(Mutex::new(fs_data)),
        }
    }
}

impl InMemoryFS {
    fn read(&mut self, handle_id: u32, buf: &mut [u8]) -> io::Result<usize> {
        let mut fs_data = self
            .fs_data
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        let handle_data = fs_data
            .open_handles
            .get(&handle_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        if !handle_data.permissions.read {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File not opened for reading",
            ));
        }

        let position = handle_data.position;
        let path = &handle_data.path;

        let file = fs_data
            .get_file_entry(path)
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "File not found"))?;

        let available = if position >= file.data.len() as u64 {
            0
        } else {
            file.data.len() as u64 - position
        };

        let bytes_to_read = std::cmp::min(available as usize, buf.len());

        if bytes_to_read > 0 {
            let start = position as usize;
            let end = start + bytes_to_read;
            buf[..bytes_to_read].copy_from_slice(&file.data[start..end]);

            // Update position
            let handle_data = fs_data.open_handles.get_mut(&handle_id).unwrap();
            handle_data.position += bytes_to_read as u64;
        }

        Ok(bytes_to_read)
    }

    fn write(&mut self, handle_id: u32, buf: &[u8]) -> io::Result<usize> {
        let mut fs_data = self
            .fs_data
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        let handle_data = fs_data
            .open_handles
            .get(&handle_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        if !handle_data.permissions.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File not opened for writing",
            ));
        }

        let position = handle_data.position;
        let path = &handle_data.path.clone();

        let file = fs_data
            .get_file_entry_mut(path)
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "File not found"))?;

        // Ensure file size is adequate
        if position > file.data.len() as u64 {
            file.data.resize(position as usize, 0);
        }

        let start = position as usize;
        let end = start + buf.len();

        // If writing past end of file, resize it
        if end > file.data.len() {
            file.data.resize(end, 0);
        }

        // Write the data
        file.data[start..end].copy_from_slice(buf);

        // Update modified time
        file.update_modified_time();

        // Update position
        let handle_data = fs_data.open_handles.get_mut(&handle_id).unwrap();
        handle_data.position += buf.len() as u64;

        Ok(buf.len())
    }

    fn seek(&mut self, handle_id: u32, pos: SeekFrom) -> io::Result<u64> {
        let mut fs_data = self
            .fs_data
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        let handle_data = fs_data
            .open_handles
            .get_mut(&handle_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        let path = &handle_data.path.clone();
        let current_pos = handle_data.position;

        let file = fs_data
            .get_file_entry(path)
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "File not found"))?;

        let file_len = file.data.len() as u64;

        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset > 0 {
                    file_len + offset as u64
                } else if offset.unsigned_abs() > file_len {
                    0
                } else {
                    file_len - offset.unsigned_abs()
                }
            }
            SeekFrom::Current(offset) => {
                if offset >= 0 {
                    current_pos + offset as u64
                } else if offset.unsigned_abs() > current_pos {
                    0
                } else {
                    current_pos - offset.unsigned_abs()
                }
            }
        };

        // Update position in handle data
        let handle_data = fs_data
            .open_handles
            .get_mut(&handle_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid handle"))?;
        handle_data.position = new_pos;

        Ok(new_pos)
    }

    fn len(&mut self, handle_id: u32) -> MyResult<u64> {
        let fs_data = self.fs_data.lock()?;
        let handle_data = fs_data
            .open_handles
            .get(&handle_id)
            .ok_or_else(|| MyError::new_io(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        let path = &handle_data.path;

        let file = fs_data.get_file_entry(path)?;

        Ok(file.data.len() as u64)
    }

    fn set_len(&mut self, handle_id: u32, size: u64) -> MyResult<()> {
        let mut fs_data = self.fs_data.lock()?;
        let handle_data = fs_data
            .open_handles
            .get(&handle_id)
            .ok_or_else(|| MyError::new_io(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        if !handle_data.permissions.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File not opened for writing",
            )
            .into());
        }

        let path = &handle_data.path.clone();

        let file = fs_data.get_file_entry_mut(path)?;

        file.data.resize(size as usize, 0);
        file.update_modified_time();

        Ok(())
    }
}

impl Read for InMemoryFileHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut fs = self
            .fs
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        fs.read(self.id, buf)
    }
}

impl Write for InMemoryFileHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut fs = self
            .fs
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        fs.write(self.id, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        // No buffering in this implementation, so flush is a no-op
        Ok(())
    }
}

impl Seek for InMemoryFileHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut fs = self
            .fs
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        fs.seek(self.id, pos)
    }
}

impl Len for InMemoryFileHandle {
    fn len(&mut self) -> MyResult<u64> {
        let mut fs = self.fs.lock()?;
        fs.len(self.id)
    }
}

impl SetLen for InMemoryFileHandle {
    fn set_len(&mut self, size: u64) -> MyResult<()> {
        let mut fs = self.fs.lock()?;
        fs.set_len(self.id, size)
    }
}

impl Finalize for InMemoryFileHandle {
    fn finalize(&mut self) -> MyResult<()> {
        // Could implement cleanup here, but we'll keep it simple for now
        Ok(())
    }
}

impl Drop for InMemoryFileHandle {
    fn drop(&mut self) {
        let _ = self.finalize();
    }
}

impl TFile for InMemoryFileHandle {}

impl Capabilities for InMemoryFS {
    fn can_mutate(&self) -> bool {
        true
    }
    fn can_truncate(&self) -> bool {
        true
    }
    fn can_rename(&self) -> bool {
        true
    }
    fn can_append(&self) -> bool {
        true
    }
}

impl FS for InMemoryFS {
    type File = InMemoryFileHandle;

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()> {
        let segments = path_to_segments(path);
        let mut fs_data = self.fs_data.lock()?;
        fs_data.create_directories(&segments)
    }

    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()> {
        let from_segments = path_to_segments(from);
        let to_segments = path_to_segments(to);

        let mut fs_data = self.fs_data.lock()?;
        fs_data.rename_file(&from_segments, &to_segments)
    }

    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let segments = path_to_segments(path);
        let mut fs_data = self.fs_data.lock()?;

        // Create the file
        fs_data.create_file(&segments)?;

        // Get next handle ID
        let handle_id = fs_data.next_handle_id;
        fs_data.next_handle_id += 1;

        // Create handle data
        fs_data.open_handles.insert(
            handle_id,
            InMemoryFileHandleData {
                path: segments,
                position: 0,
                permissions: FileHandlePermissions {
                    read: true,
                    write: true,
                },
            },
        );

        Ok(InMemoryFileHandle {
            id: handle_id,
            fs: Arc::new(Mutex::new(self.clone())),
        })
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let segments = path_to_segments(path);
        let mut fs_data = self.fs_data.lock()?;

        // Verify file exists
        let _ = fs_data.get_file_entry(&segments)?;

        // Get next handle ID
        let handle_id = fs_data.next_handle_id;
        fs_data.next_handle_id += 1;

        // Create handle data
        fs_data.open_handles.insert(
            handle_id,
            InMemoryFileHandleData {
                path: segments,
                position: 0,
                permissions: FileHandlePermissions {
                    read: true,
                    write: false,
                },
            },
        );

        Ok(InMemoryFileHandle {
            id: handle_id,
            fs: Arc::new(Mutex::new(self.clone())),
        })
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let segments = path_to_segments(path);
        let mut fs_data = self.fs_data.lock()?;

        // Verify file exists
        let _ = fs_data.get_file_entry(&segments)?;

        // Get next handle ID
        let handle_id = fs_data.next_handle_id;
        fs_data.next_handle_id += 1;

        // Create handle data
        fs_data.open_handles.insert(
            handle_id,
            InMemoryFileHandleData {
                path: segments,
                position: 0,
                permissions: FileHandlePermissions {
                    read: true,
                    write: true,
                },
            },
        );

        Ok(InMemoryFileHandle {
            id: handle_id,
            fs: Arc::new(Mutex::new(self.clone())),
        })
    }

    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        let mut fs_data = self.fs_data.lock()?;
        let handle_id = file.id;

        // Get handle data
        let handle_data = fs_data
            .open_handles
            .get(&handle_id)
            .ok_or_else(|| MyError::new_io(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        if !handle_data.permissions.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File not opened for writing",
            )
            .into());
        }

        let path = &handle_data.path.clone();

        // Get file and zero range
        let file = fs_data.get_file_entry_mut(path)?;

        let end_offset = offset + len;

        // Ensure file is large enough
        if file.data.len() < end_offset as usize {
            file.data.resize(end_offset as usize, 0);
        }

        // Zero the range
        for i in offset..end_offset {
            file.data[i as usize] = 0;
        }

        file.update_modified_time();

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
        let mut fs_data = self.fs_data.lock()?;

        // Get source handle data
        let src_handle_data = fs_data
            .open_handles
            .get(&src_file.id)
            .ok_or_else(|| MyError::new_io(io::ErrorKind::InvalidInput, "Invalid source handle"))?;

        if !src_handle_data.permissions.read {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Source file not opened for reading",
            )
            .into());
        }

        // Get dest handle data
        let dst_handle_data = fs_data.open_handles.get(&dst_file.id).ok_or_else(|| {
            MyError::new_io(io::ErrorKind::InvalidInput, "Invalid destination handle")
        })?;

        if !dst_handle_data.permissions.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Destination file not opened for writing",
            )
            .into());
        }

        let src_path = &src_handle_data.path.clone();
        let dst_path = &dst_handle_data.path.clone();

        // Get files and copy range
        let src_file = fs_data.get_file_entry(src_path)?;
        let src_len = src_file.data.len() as u64;

        // Calculate how much we can copy
        if src_offset >= src_len {
            return Ok(0); // Source offset is past EOF
        }

        let available = src_len - src_offset;
        let bytes_to_copy = std::cmp::min(available, len);

        if bytes_to_copy == 0 {
            return Ok(0);
        }

        // Get the source data
        let src_data =
            &src_file.data[src_offset as usize..(src_offset + bytes_to_copy) as usize].to_vec();

        // Get destination file
        let dst_file = fs_data.get_file_entry_mut(dst_path)?;

        // Ensure destination file is large enough
        let dst_end = dst_offset + bytes_to_copy;
        if dst_file.data.len() < dst_end as usize {
            dst_file.data.resize(dst_end as usize, 0);
        }

        // Copy the data
        dst_file.data[dst_offset as usize..(dst_offset + bytes_to_copy) as usize]
            .copy_from_slice(src_data);

        dst_file.update_modified_time();

        Ok(bytes_to_copy)
    }
}

impl Snapshottable for InMemoryFS {
    type Snapshot = SimpleSnapshot;

    fn create_snapshot(&self) -> Self::Snapshot {
        let fs_data = self.fs_data.lock().unwrap();

        let mut files = HashMap::new();
        let mut dirs = Vec::new();

        // Recursively collect all files and directories
        Self::collect_snapshot_data(&fs_data.root, PathBuf::new(), &mut files, &mut dirs);

        SimpleSnapshot::new(files, dirs.into_boxed_slice())
    }
}

impl InMemoryFS {
    fn collect_snapshot_data(
        dir: &DirectoryEntry,
        current_path: PathBuf,
        files: &mut HashMap<Box<Path>, Box<[u8]>>,
        dirs: &mut Vec<Box<Path>>,
    ) {
        // Process all files in the current directory
        for (name, file_entry) in &dir.files {
            let name_str = String::from_utf8_lossy(name).into_owned();
            let file_path = current_path.join(name_str);
            files.insert(
                file_path.into_boxed_path(),
                file_entry.data.clone().into_boxed_slice(),
            );
        }

        // Process all subdirectories
        for (name, subdir) in &dir.directories {
            let name_str = String::from_utf8_lossy(name).into_owned();
            let subdir_path = current_path.join(&name_str);
            dirs.push(subdir_path.clone().into_boxed_path());
            Self::collect_snapshot_data(subdir, subdir_path, files, dirs);
        }
    }
}

#[test]
pub fn test_snapshot() {
    let fs: InMemoryFS = InMemoryFS::new();

    let dirs: Vec<_> = vec!["a", "a/b", "a/b/c"]
        .into_iter()
        .map(|p| Path::new(p).to_path_buf())
        .collect();

    let files = vec![
        ("root.txt", b"root content"),
        ("a/f.txt", b"file content"),
        ("a/b/mid.txt", b"midl content"),
        ("a/b/c/deep.txt", b"deep content"),
    ];

    // Create directory structure
    fs.create_dir_all("a/b/c").unwrap();

    // Create files at different levels
    for f in &files {
        fs.create(f.0).unwrap().write_all(f.1).unwrap();
    }

    // Create snapshot
    let snapshot = fs.create_snapshot();

    // Verify all directories are captured
    let actual_dirs = snapshot.get_dirs();
    assert!(dirs.len() == actual_dirs.len());

    // Verify all files are captured with correct content
    let actual_files = snapshot.get_files();
    assert!(files.len() == actual_files.len());

    for f in files {
        let path = Path::new(f.0);
        let content = snapshot.get_file_content(&path.into()).unwrap();
        assert!(**content == *f.1);
    }
}
