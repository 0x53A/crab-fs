use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

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

pub trait FS: Clone + Capabilities {
    type File: Read + Write + Seek + Len + SetLen + Finalize;

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()>;
    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()>;
    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File>;
    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File>;
    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File>;

    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()>;
    fn copy_file_range(
        &self,
        src_file: &Self::File,
        src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64>;
}

// ------------------------

#[cfg(target_os = "linux")]
fn zero_file_range_linux(file: &File, offset: u64, len: u64) -> io::Result<()> {
    use std::{fs::File, io, os::unix::io::AsRawFd};

    let ret = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset as libc::off_t,
            len as libc::off_t,
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
            0, // flags
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

#[derive(Copy, Clone)]
pub struct PhysicalFS;

impl Len for std::fs::File {
    fn len(&mut self) -> MyResult<u64> {
        return Ok(self.metadata()?.len());
    }
}

impl SetLen for std::fs::File {
    fn set_len(&mut self, size: u64) -> MyResult<()> {
        self.set_len(size)?;
        Ok(())
    }
}

impl Finalize for std::fs::File {
    fn finalize(&mut self) -> MyResult<()> {
        self.flush()?;
        Ok(())
    }
}

impl Capabilities for PhysicalFS {
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

impl FS for PhysicalFS {
    type File = std::fs::File;

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()> {
        fs::create_dir_all(path)?;
        Ok(())
    }

    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()> {
        fs::rename(from, to)?;
        Ok(())
    }

    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(file)
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let file = OpenOptions::new().read(true).open(path)?;
        Ok(file)
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let file = OpenOptions::new().write(true).open(path)?;
        Ok(file)
    }

    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        return Ok(zero_file_range(file, offset, len)?);
    }

    fn copy_file_range(
        &self,
        src_file: &Self::File,
        src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64> {
        return Ok(copy_file_range(
            src_file, src_offset, dst_file, dst_offset, len,
        )?);
    }
}

// -------------------------------

#[derive(Clone)]
pub struct DummyFile {}

impl DummyFile {
    fn new() -> Self {
        Self {}
    }
}

impl Read for DummyFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))
    }
}

impl Write for DummyFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))
    }
}

impl Seek for DummyFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))
    }
}

impl Len for DummyFile {
    fn len(&mut self) -> MyResult<u64> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))?
    }
}

impl SetLen for DummyFile {
    fn set_len(&mut self, size: u64) -> MyResult<()> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))?
    }
}

impl Finalize for DummyFile {
    fn finalize(&mut self) -> MyResult<()> {
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct DummyFS;

impl Capabilities for DummyFS {
    fn can_mutate(&self) -> bool {
        false
    }

    fn can_truncate(&self) -> bool {
        false
    }

    fn can_rename(&self) -> bool {
        false
    }

    fn can_append(&self) -> bool {
        false
    }
}

impl FS for DummyFS {
    type File = DummyFile;

    fn create_dir_all<P: AsRef<Path>>(&self, _path: P) -> MyResult<()> {
        Ok(())
    }

    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, _from: P, _to: Q) -> MyResult<()> {
        Ok(())
    }

    fn create<P: AsRef<Path>>(&self, _path: P) -> MyResult<Self::File> {
        Ok(DummyFile::new())
    }

    fn open_read<P: AsRef<Path>>(&self, _path: P) -> MyResult<Self::File> {
        Ok(DummyFile::new())
    }

    fn open_write<P: AsRef<Path>>(&self, _path: P) -> MyResult<Self::File> {
        Ok(DummyFile::new())
    }

    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        Ok(())
    }

    fn copy_file_range(
        &self,
        _src_file: &Self::File,
        _src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64> {
        Ok(len)
    }
}

// ---------------------------------------------------

use remotefs::fs::{Metadata, ReadStream, UnixPex, WriteStream};
use remotefs::RemoteFs;

pub struct RemoteFsFile<F: RemoteFs> {
    path: PathBuf,
    read_stream: Option<ReadStream>,
    write_stream: Option<WriteStream>,
    fs: RefCell<F>,
}

impl<F: RemoteFs> Read for RemoteFsFile<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.read_stream {
            Some(stream) => stream.read(buf),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "File not opened for reading",
            )),
        }
    }
}

impl<F: RemoteFs> Write for RemoteFsFile<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.write_stream {
            Some(stream) => stream.write(buf),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "File not opened for writing",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.write_stream {
            Some(stream) => stream.flush(),
            None => Ok(()),
        }
    }
}

impl<F: RemoteFs> Seek for RemoteFsFile<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if let Some(stream) = self.write_stream.as_mut() {
            return stream.seek(pos);
        } else if let Some(stream) = self.read_stream.as_mut() {
            return stream.seek(pos);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "File not opened for reading or writing",
            ));
        }
    }
}

impl<F: RemoteFs> Len for RemoteFsFile<F> {
    fn len(&mut self) -> MyResult<u64> {
        Ok(self.fs.borrow_mut().stat(&self.path)?.metadata.size)
    }
}

impl<F: RemoteFs + Capabilities> SetLen for RemoteFsFile<F> {
    /// note: the file system must support mov and append
    /// TODO: check capabilities, implement fallback
    fn set_len(&mut self, size: u64) -> MyResult<()> {
        let current_len = self.len()?;
        let mut fs = self.fs.borrow_mut();

        if current_len == size {
            return Ok(());
        }

        if current_len > size {
            // Need to truncate
            // we need to copy the file
            let temp_path = self.path.with_extension("temp");

            // Create new file with desired size
            let metadata = Metadata {
                size,
                ..fs.stat(&self.path)?.metadata
            };

            let mut temp_write = fs.create(&temp_path, &metadata)?;
            let mut temp_read = fs.open(&self.path)?;

            // Copy only up to the new size
            io::copy(&mut (&mut temp_read).take(size), &mut temp_write)?;

            fs.on_written(temp_write)?;
            fs.on_read(temp_read)?;

            // Replace original with truncated version
            fs.remove_file(&self.path)?;
            fs.mov(&temp_path, &self.path)?;
        } else {
            // Need to grow the file
            if !fs.can_append() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Cannot grow file - append not supported",
                )
                .into());
            }

            // Open for append
            let metadata = fs.stat(&self.path)?.metadata;
            let mut writer = fs.append(&self.path, &metadata)?;

            // Write zeros to pad to desired length
            const write_chunk_size: usize = 8192;
            let zeros = vec![0u8; write_chunk_size]; // Write in 8KB chunks
            let mut remaining = size - current_len;

            while remaining > 0 {
                let to_write = std::cmp::min(remaining as usize, zeros.len());
                writer.write_all(&zeros[..to_write])?;
                remaining -= to_write as u64;
            }

            fs.on_written(writer)?;
        }

        Ok(())
    }
}

impl<F: RemoteFs> Drop for RemoteFsFile<F> {
    fn drop(&mut self) {
        if let Some(stream) = self.write_stream.take() {
            let _ = self.fs.borrow_mut().on_written(stream);
        }
        if let Some(stream) = self.read_stream.take() {
            let _ = self.fs.borrow_mut().on_read(stream);
        }
    }
}

impl<F: RemoteFs> Finalize for RemoteFsFile<F> {
    fn finalize(&mut self) -> MyResult<()> {
        if let Some(stream) = self.write_stream.take() {
            self.fs.borrow_mut().on_written(stream)?;
        }
        if let Some(stream) = self.read_stream.take() {
            self.fs.borrow_mut().on_read(stream)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RemoteFsAdapter<T: RemoteFs> {
    /// important: the inner file system should have been connected prior to being passed into the adapter
    inner: RefCell<T>,
}

impl<T: RemoteFs + Capabilities> Capabilities for RemoteFsAdapter<T> {
    fn can_mutate(&self) -> bool {
        self.inner.borrow().can_mutate()
    }

    fn can_truncate(&self) -> bool {
        self.inner.borrow().can_truncate()
    }

    fn can_rename(&self) -> bool {
        self.inner.borrow().can_rename()
    }

    fn can_append(&self) -> bool {
        self.inner.borrow().can_append()
    }
}

impl<T: RemoteFs + Copy + Capabilities> FS for RemoteFsAdapter<T> {
    type File = RemoteFsFile<T>;

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()> {
        // RemoteFs only has create_dir with mode, so we need to handle parent directories
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if parent.as_os_str().len() > 0 {
                self.create_dir_all(parent)?;
            }
        }

        // Create the final directory with default permissions
        match self
            .inner
            .borrow_mut()
            .create_dir(path, UnixPex::from(0o755))
        {
            Ok(_) => Ok(()),
            Err(e) if e.kind == remotefs::RemoteErrorType::DirectoryAlreadyExists => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()> {
        self.inner.borrow_mut().mov(from.as_ref(), to.as_ref())?;
        Ok(())
    }

    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let metadata = Metadata::default();

        let write_stream = Some(self.inner.borrow_mut().create(path.as_ref(), &metadata)?);

        Ok(RemoteFsFile {
            path: path.as_ref().to_path_buf(),
            read_stream: None,
            write_stream,
            fs: self.inner.clone(),
        })
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let read_stream = Some(self.inner.borrow_mut().open(path.as_ref())?);

        Ok(RemoteFsFile {
            path: path.as_ref().to_path_buf(),
            read_stream,
            write_stream: None,
            fs: self.inner.clone(),
        })
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let metadata = self.inner.borrow_mut().stat(path.as_ref())?.metadata;
        let write_stream = Some(self.inner.borrow_mut().append(path.as_ref(), &metadata)?);

        Ok(RemoteFsFile {
            path: path.as_ref().to_path_buf(),
            read_stream: None,
            write_stream,
            fs: self.inner.clone(),
        })
    }

    /// note: requires seek
    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        let mut fs = self.inner.borrow_mut();

        // Open file for writing using existing metadata
        let metadata = fs.stat(&file.path)?.metadata;
        let mut writer = fs.create(&file.path, &metadata)?;

        // Seek to the offset
        writer.seek(SeekFrom::Start(offset))?;

        // Write zeros in chunks to avoid large allocations
        const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
        let zeros = vec![0u8; CHUNK_SIZE];

        let mut remaining = len;
        while remaining > 0 {
            let write_size = std::cmp::min(remaining, CHUNK_SIZE as u64) as usize;
            writer.write_all(&zeros[..write_size])?;
            remaining -= write_size as u64;
        }

        // Finalize the write
        fs.on_written(writer)?;

        Ok(())
    }

    /// note: requires seek
    fn copy_file_range(
        &self,
        src_file: &Self::File,
        src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64> {
        let mut fs = self.inner.borrow_mut();

        // Get metadata for source and destination files
        let dst_metadata = fs.stat(&dst_file.path)?.metadata;

        // Open source for reading and destination for writing
        let mut src = fs.open(&src_file.path)?;
        let mut dst = fs.create(&dst_file.path, &dst_metadata)?;

        // Seek to the required positions
        src.seek(SeekFrom::Start(src_offset))?;
        dst.seek(SeekFrom::Start(dst_offset))?;

        // Copy data in chunks
        const BUFFER_SIZE: usize = 64 * 1024; // 64KB buffer
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut remaining = len;
        let mut total_copied = 0u64;

        while remaining > 0 {
            let to_copy = std::cmp::min(remaining as usize, BUFFER_SIZE);

            // Read chunk from source
            let bytes_read = src.read(&mut buffer[..to_copy])?;
            if bytes_read == 0 {
                assert!(remaining == 0);
                break; // EOF reached
            }

            // Write chunk to destination
            dst.write_all(&buffer[..bytes_read])?;

            total_copied += bytes_read as u64;
            remaining -= bytes_read as u64;
        }

        // Finalize both streams
        fs.on_read(src)?;
        fs.on_written(dst)?;

        Ok(total_copied)
    }
}
