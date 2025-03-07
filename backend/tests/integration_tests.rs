use crab_fs_backend::io::fs::{EncryptedFS, InMemoryFS, PhysicalFS};
use crab_fs_common::{
    errors::MyError,
    io::fs::{get_snapshot_delta, Finalize, SetLen, Snapshottable, FS},
};

use std::io::{Read, Seek, SeekFrom, Write};

mod common;

fn get_steps<F: FS>() -> Vec<Box<dyn Fn(&F) -> Result<(), MyError>>> {
    vec![
        Box::new(|fs: &F| scenario_truncate_then_write(fs)),
        Box::new(|fs: &F| scenario_basic_file_operations(fs)),
        Box::new(|fs: &F| scenario_append_to_file(fs)),
        Box::new(|fs: &F| scenario_overwrite_in_middle(fs)),
        Box::new(|fs: &F| scenario_create_multiple_files(fs)),
        Box::new(|fs: &F| scenario_nested_directories(fs)),
        Box::new(|fs: &F| scenario_rename_file(fs)),
        Box::new(|fs: &F| scenario_large_file(fs)),
    ]
}

// Original scenario
fn scenario_truncate_then_write(fs: &impl FS) -> Result<(), MyError> {
    let mut file = fs.create("test.txt")?;
    file.write_all(b"abcdefghij")?;
    SetLen::set_len(&mut file, 5)?;
    file.write_all(b"x")?;
    file.finalize()?;
    Ok(())
}

// Basic file operations
fn scenario_basic_file_operations(fs: &impl FS) -> Result<(), MyError> {
    // Create a new file
    let mut file = fs.create("basic.txt")?;
    file.write_all(b"Hello world")?;
    file.finalize()?;

    // Read the file back
    let mut file = fs.open_read("basic.txt")?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    assert_eq!(b"Hello world", &content[..]);

    Ok(())
}

// Append to an existing file
fn scenario_append_to_file(fs: &impl FS) -> Result<(), MyError> {
    // Create initial content
    let mut file = fs.create("append.txt")?;
    file.write_all(b"Initial content")?;
    file.finalize()?;

    // Append to the file
    let mut file = fs.open_write("append.txt")?;
    file.seek(SeekFrom::End(0))?;
    file.write_all(b", appended text")?;
    file.finalize()?;

    Ok(())
}

// Overwrite in the middle of file
fn scenario_overwrite_in_middle(fs: &impl FS) -> Result<(), MyError> {
    let mut file = fs.create("overwrite.txt")?;
    file.write_all(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")?;
    file.seek(SeekFrom::Start(10))?;
    file.write_all(b"INSERTED")?;
    file.finalize()?;

    Ok(())
}

// Create multiple files
fn scenario_create_multiple_files(fs: &impl FS) -> Result<(), MyError> {
    let mut file1 = fs.create("file1.txt")?;
    file1.write_all(b"Content of file 1")?;
    file1.finalize()?;

    let mut file2 = fs.create("file2.txt")?;
    file2.write_all(b"Content of file 2")?;
    file2.finalize()?;

    let mut file3 = fs.create("file3.txt")?;
    file3.write_all(b"Content of file 3")?;
    file3.finalize()?;

    Ok(())
}

// Create nested directory structure
fn scenario_nested_directories(fs: &impl FS) -> Result<(), MyError> {
    fs.create_dir_all("dir1/dir2/dir3")?;

    let mut file = fs.create("dir1/dir2/dir3/nested.txt")?;
    file.write_all(b"File in nested directory")?;
    file.finalize()?;

    Ok(())
}

// Rename a file
fn scenario_rename_file(fs: &impl FS) -> Result<(), MyError> {
    let mut file = fs.create("original.txt")?;
    file.write_all(b"This file will be renamed")?;
    file.finalize()?;

    fs.rename("original.txt", "renamed.txt")?;

    Ok(())
}

// Create a large file with sparse writes
fn scenario_large_file(fs: &impl FS) -> Result<(), MyError> {
    let mut file = fs.create("large.txt")?;

    // Write at the beginning
    file.write_all(b"Start of file")?;

    // Seek to 10KB and write
    file.seek(SeekFrom::Start(10_000))?;
    file.write_all(b"Middle of file")?;

    // Seek to 20KB and write
    file.seek(SeekFrom::Start(20_000))?;
    file.write_all(b"End of file")?;

    file.finalize()?;

    Ok(())
}

#[test]
fn equality_between_physical_and_memory() -> Result<(), MyError> {
    let memory = InMemoryFS::new();

    let temp_dir = tempfile::tempdir().unwrap();
    let physical = PhysicalFS::new(temp_dir.into_path().into_boxed_path());

    let encrypted = {
        let memory = InMemoryFS::new();
        EncryptedFS::new(memory, b"hello world")
    };

    let steps_in_memory = get_steps::<InMemoryFS>();
    let steps_in_physical = get_steps::<PhysicalFS>();
    let steps_in_encrypted = get_steps::<EncryptedFS<_>>();

    let cnt = steps_in_memory.len();

    for i in 0..cnt {
        steps_in_memory[i](&memory)?;
        steps_in_physical[i](&physical)?;
        steps_in_encrypted[i](&encrypted)?;

        let snapshot_memory = memory.create_snapshot();
        let snapshot_physical = physical.create_snapshot();
        let snapshot_encrypted = encrypted.create_snapshot();

        let delta_memory_physical = get_snapshot_delta(&snapshot_memory, &snapshot_physical);
        assert_eq!(vec![].into_boxed_slice(), delta_memory_physical);

        let delta_memory_encrypted = get_snapshot_delta(&snapshot_memory, &snapshot_encrypted);
        assert_eq!(vec![].into_boxed_slice(), delta_memory_encrypted);

        //assert_eq!(snapshot_memory, snapshot_physical);
    }

    Ok(())
}
