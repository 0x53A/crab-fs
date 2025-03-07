// ---------------------------------------

use mailboxxy::{MailboxContext, ReplyChannel};

use crab_fs_common::errors::{MyError, MyResult};
use crab_fs_common::io::fs::{Capabilities, Finalize, Len, SetLen, TFile, FS};
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(PartialEq, Eq, Hash, Copy, Clone)]
pub struct FileHandle {
    id: u64,
}

pub enum FSCommandMsg {
    // create all missing directories in the path
    CreateDirAll {
        path: PathBuf,
        reply: ReplyChannel<MyResult<()>>,
    },

    // rename a file or directory
    Rename {
        from: PathBuf,
        to: PathBuf,
        reply: ReplyChannel<MyResult<()>>,
    },

    // create a new file
    Create {
        path: PathBuf,
        reply: ReplyChannel<MyResult<Arc<FileHandle>>>,
    },

    // open a file for reading
    OpenRead {
        path: PathBuf,
        reply: ReplyChannel<MyResult<Arc<FileHandle>>>,
    },

    // open a file for writing
    OpenWrite {
        path: PathBuf,
        reply: ReplyChannel<MyResult<Arc<FileHandle>>>,
    },

    // zero a file range
    ZeroFileRange {
        file: FileHandle,
        offset: u64,
        len: u64,
        reply: ReplyChannel<MyResult<()>>,
    },

    // copy data from one file to another
    CopyFileRange {
        src_file: FileHandle,
        src_offset: u64,
        dst_file: FileHandle,
        dst_offset: u64,
        len: u64,
        reply: ReplyChannel<MyResult<u64>>,
    },
}

fn run<T>(rc: mailboxxy::ReplyChannel<T>, f: impl FnOnce() -> T) {
    rc.reply(f());
}

async fn mailbox_fn<F: FS>(fs: Arc<Mutex<F>>, ctx: MailboxContext<FSCommandMsg>) {
    let mut files = HashMap::new();
    let mut next_handle_id = 1;

    loop {
        let msg: FSCommandMsg = ctx.dequeue().await;

        let fs = fs.lock().unwrap();

        match msg {
            FSCommandMsg::CreateDirAll { path, reply } => {
                run(reply, || fs.create_dir_all(path));
            }
            FSCommandMsg::Rename { from, to, reply } => {
                run(reply, || fs.rename(from, to));
            }
            FSCommandMsg::Create { path, reply } => {
                run(reply, || {
                    fs.create(path).map(|file: F::File| {
                        let handle = FileHandle { id: next_handle_id };
                        next_handle_id += 1;
                        files.insert(handle, file);
                        Arc::new(handle)
                    })
                });
            }
            FSCommandMsg::OpenRead { path, reply } => {
                run(reply, || {
                    fs.open_read(path).map(|file: F::File| {
                        let handle = FileHandle { id: next_handle_id };
                        next_handle_id += 1;
                        files.insert(handle, file);
                        Arc::new(handle)
                    })
                });
            }
            FSCommandMsg::OpenWrite { path, reply } => {
                run(reply, || {
                    fs.open_write(path).map(|file: F::File| {
                        let handle = FileHandle { id: next_handle_id };
                        next_handle_id += 1;
                        files.insert(handle, file);
                        Arc::new(handle)
                    })
                });
            }
            FSCommandMsg::ZeroFileRange {
                file,
                offset,
                len,
                reply,
            } => {
                run(reply, || {
                    let file = (|handle: &FileHandle| {
                        files.get(handle).ok_or(MyError::new_io(
                            io::ErrorKind::InvalidData,
                            "invalid file handle id",
                        ))
                    })(&file)?;
                    fs.zero_file_range(file, offset, len)
                });
            }
            FSCommandMsg::CopyFileRange {
                src_file,
                src_offset,
                dst_file,
                dst_offset,
                len,
                reply,
            } => {
                run(reply, || {
                    let src_file = (|handle: &FileHandle| {
                        files.get(handle).ok_or(MyError::new_io(
                            io::ErrorKind::InvalidData,
                            "invalid file handle id",
                        ))
                    })(&src_file)?;
                    let dst_file = (|handle: &FileHandle| {
                        files.get(handle).ok_or(MyError::new_io(
                            io::ErrorKind::InvalidData,
                            "invalid file handle id",
                        ))
                    })(&dst_file)?;
                    fs.copy_file_range(src_file, src_offset, dst_file, dst_offset, len)
                });
            }
        }
    }
}

pub fn wrap_fs_in_mailbox<F: FS + Send + 'static>(
    fs: Arc<Mutex<F>>,
) -> mailboxxy::MailBox<FSCommandMsg, std::thread::JoinHandle<()>> {
    mailboxxy::start_mailbox_on_thread(mailboxxy::MailboxBounds::Unbounded, |ctx| {
        mailbox_fn(fs, ctx)
    })
}
