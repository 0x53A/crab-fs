use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{self, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use std::vec;

use crab_fs_common::errors::{MyError, MyResult};
use crab_fs_common::io::fs::{Capabilities, Finalize, Len, SetLen, Snapshot, FS};

use crab_fs_common::io::fs::SimpleSnapshot;
use crab_fs_common::io::fs::Snapshottable;

type InMemoryPathSegment = Box<[u8]>;
type InMemoryPath = [InMemoryPathSegment];

use crab_fs_backend::io::fs::InMemoryFS;

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_create_and_read_file() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create and write to a file
        let mut file = fs.create("test.txt")?;
        file.write_all(b"Hello, World!")?;
        file.finalize()?;

        // Read the file back
        let mut file = fs.open_read("test.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "Hello, World!");
        Ok(())
    }

    #[test]
    fn test_seek_and_partial_read() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create test data
        let mut file = fs.create("seek_test.txt")?;
        file.write_all(b"0123456789")?;
        file.finalize()?;

        // Test seeking and partial reading
        let mut file = fs.open_read("seek_test.txt")?;
        file.seek(SeekFrom::Start(5))?;

        let mut buffer = [0u8; 3];
        file.read_exact(&mut buffer)?;

        assert_eq!(&buffer, b"567");
        Ok(())
    }

    #[test]
    fn test_create_directory_structure() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create nested directories
        fs.create_dir_all("a/b/c")?;

        // Create a file in the nested directory
        let mut file = fs.create("a/b/c/test.txt")?;
        file.write_all(b"test content")?;
        file.finalize()?;

        // Read it back
        let mut file = fs.open_read("a/b/c/test.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "test content");
        Ok(())
    }

    #[test]
    fn test_file_length() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create a file with known content
        let mut file = fs.create("length_test.txt")?;
        file.write_all(b"12345")?;

        assert_eq!(file.len()?, 5);

        // Extend the file
        file.set_len(10)?;
        assert_eq!(file.len()?, 10);

        // Truncate the file
        file.set_len(3)?;
        assert_eq!(file.len()?, 3);

        Ok(())
    }

    #[test]
    fn test_rename_file() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create and write to a file
        let mut file = fs.create("old.txt")?;
        file.write_all(b"content")?;
        file.finalize()?;

        // Rename the file
        fs.rename("old.txt", "new.txt")?;

        // Try to read from old path (should fail)
        assert!(fs.open_read("old.txt").is_err());

        // Read from new path
        let mut file = fs.open_read("new.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "content");
        Ok(())
    }

    #[test]
    fn test_zero_file_range() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create a file with known content
        let mut file = fs.create("zero_test.txt")?;
        file.write_all(b"Hello World!")?;

        // Zero out "World"
        fs.zero_file_range(&file, 6, 5)?;

        // Read the content back
        let mut file = fs.open_read("zero_test.txt")?;
        let mut contents = vec![0u8; 12];
        file.read_exact(&mut contents)?;

        assert_eq!(&contents[0..6], b"Hello ");
        assert_eq!(&contents[6..11], &[0, 0, 0, 0, 0]);
        assert_eq!(contents[11], b'!');

        Ok(())
    }

    #[test]
    fn test_copy_file_range() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create source file
        let mut src_file = fs.create("source.txt")?;
        src_file.write_all(b"Hello World!")?;

        // Create destination file
        let mut dst_file = fs.create("dest.txt")?;
        dst_file.write_all(b"XXXXXXXXXXXXX")?;

        // Copy "World" from source to destination
        fs.copy_file_range(&src_file, 6, &dst_file, 3, 5)?;

        // Read destination content
        let mut file = fs.open_read("dest.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "XXXWorldXXXXX");
        Ok(())
    }

    #[test]
    fn test_concurrent_access() -> MyResult<()> {
        use std::thread;

        let fs = InMemoryFS::new();
        let fs_clone = fs.clone();

        // Create initial file
        let mut file = fs.create("concurrent.txt")?;
        file.write_all(b"Initial")?;
        file.finalize()?;

        // Spawn thread to modify file
        let handle = thread::spawn(move || -> MyResult<()> {
            let mut file = fs_clone.open_write("concurrent.txt")?;
            file.write_all(b" Content")?;
            file.finalize()?;
            Ok(())
        });

        // Wait for thread to complete
        handle.join().unwrap()?;

        // Read final content
        let mut file = fs.open_read("concurrent.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "Initial Content");
        Ok(())
    }

    #[test]
    fn test_capabilities() {
        let fs = InMemoryFS::new();

        assert!(fs.can_mutate());
        assert!(fs.can_truncate());
        assert!(fs.can_rename());
        assert!(fs.can_append());
    }

    #[test]
    fn test_large_file() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create a large file (1MB)
        let mut file = fs.create("large.txt")?;
        let data = vec![b'X'; 1_000_000];
        file.write_all(&data)?;

        assert_eq!(file.len()?, 1_000_000);

        // Read back in chunks
        let mut file = fs.open_read("large.txt")?;
        let mut buffer = vec![0u8; 1024];
        let mut total_read = 0;

        loop {
            match file.read(&mut buffer)? {
                0 => break,
                n => {
                    total_read += n;
                    assert!(buffer[..n].iter().all(|&b| b == b'X'));
                }
            }
        }

        assert_eq!(total_read, 1_000_000);
        Ok(())
    }

    #[test]
    fn test_error_cases() {
        let fs = InMemoryFS::new();

        // Try to read non-existent file
        assert!(fs.open_read("nonexistent.txt").is_err());

        // Try to rename non-existent file
        assert!(fs.rename("nonexistent.txt", "new.txt").is_err());

        // Try to create file in non-existent directory
        assert!(fs.create("nonexistent_dir/file.txt").is_err());
    }
}

#[cfg(test)]
mod additional_tests {
    use super::*;

    #[test]
    fn test_write_at_offset() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create a file with initial content
        let mut file = fs.create("offset_write.txt")?;
        file.write_all(b"Hello, Rust")?;
        file.seek(SeekFrom::Start(7))?;
        file.write_all(b"World!")?;
        file.finalize()?;

        // Read the file back
        let mut file = fs.open_read("offset_write.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "Hello, World!");
        Ok(())
    }

    #[test]
    fn test_read_beyond_eof() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create a file with some content
        let mut file = fs.create("small.txt")?;
        file.write_all(b"abc")?;
        file.finalize()?;

        // Try to read beyond EOF
        let mut file = fs.open_read("small.txt")?;
        file.seek(SeekFrom::Start(5))?; // Beyond EOF

        let mut buffer = [0u8; 10];
        let bytes_read = file.read(&mut buffer)?;

        assert_eq!(bytes_read, 0); // Should read 0 bytes
        Ok(())
    }

    #[test]
    fn test_file_truncate() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create a file with content
        let mut file = fs.create("truncate.txt")?;
        file.write_all(b"1234567890")?;

        // Truncate to shorter length
        file.set_len(5)?;

        // Read back and verify
        let mut file = fs.open_read("truncate.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "12345");

        // Truncate to longer length (should zero-fill)
        let mut file = fs.open_write("truncate.txt")?;
        file.set_len(8)?;

        // Read back and verify
        let mut file = fs.open_read("truncate.txt")?;
        let mut buffer = vec![0u8; 8];
        file.read_exact(&mut buffer)?;

        assert_eq!(&buffer[0..5], b"12345");
        assert_eq!(&buffer[5..8], &[0, 0, 0]);

        Ok(())
    }

    #[test]
    fn test_append_mode() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create a file with initial content
        let mut file = fs.create("append.txt")?;
        file.write_all(b"Hello")?;
        file.finalize()?;

        // Open file for writing and move to end
        let mut file = fs.open_write("append.txt")?;
        file.seek(SeekFrom::End(0))?;
        file.write_all(b" World")?;
        file.finalize()?;

        // Read and verify
        let mut file = fs.open_read("append.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "Hello World");
        Ok(())
    }

    #[test]
    fn test_nested_directory_creation() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create deeply nested directories
        fs.create_dir_all("a/b/c/d/e/f/g")?;

        // Create a file in the deepest directory
        let mut file = fs.create("a/b/c/d/e/f/g/test.txt")?;
        file.write_all(b"deep file")?;
        file.finalize()?;

        // Read it back
        let mut file = fs.open_read("a/b/c/d/e/f/g/test.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "deep file");
        Ok(())
    }

    #[test]
    fn test_multiple_handles_same_file() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create file
        let mut file1 = fs.create("shared.txt")?;
        file1.write_all(b"Initial content")?;

        // Open another handle to the same file
        let mut file2 = fs.open_read("shared.txt")?;

        // Read from second handle
        let mut contents = String::new();
        file2.read_to_string(&mut contents)?;
        assert_eq!(contents, "Initial content");

        // Modify file through first handle
        file1.seek(SeekFrom::Start(0))?;
        file1.write_all(b"Modified")?;

        // Read through second handle should see the changes
        file2.seek(SeekFrom::Start(0))?;
        contents.clear();
        file2.read_to_string(&mut contents)?;
        assert_eq!(contents, "Modified");

        Ok(())
    }

    #[test]
    fn test_create_with_parent_dirs() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Try creating a file with parent directories that don't exist yet
        let mut file = fs.create("parent/dir/structure/file.txt")?;
        file.write_all(b"test content")?;
        file.finalize()?;

        // Read it back
        let mut file = fs.open_read("parent/dir/structure/file.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "test content");
        Ok(())
    }

    #[test]
    fn test_overwrite_file() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create initial file
        let mut file = fs.create("overwrite.txt")?;
        file.write_all(b"initial content")?;
        file.finalize()?;

        // Create with same name to overwrite
        let mut file = fs.create("overwrite.txt")?;
        file.write_all(b"overwritten")?;
        file.finalize()?;

        // Verify content was overwritten
        let mut file = fs.open_read("overwrite.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "overwritten");
        Ok(())
    }

    #[test]
    fn test_seek_current_negative() -> MyResult<()> {
        let fs = InMemoryFS::new();

        let mut file = fs.create("seek_test.txt")?;
        file.write_all(b"0123456789")?;

        // Seek forward, then backward
        file.seek(SeekFrom::Start(7))?;
        file.seek(SeekFrom::Current(-5))?;

        // Read and verify position
        let mut buf = [0u8; 1];
        file.read_exact(&mut buf)?;
        assert_eq!(buf[0], b'2');

        Ok(())
    }
}
