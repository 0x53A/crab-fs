// Note: this is modified from https://github.com/cberner/fuser/blob/d675c07ecb8e826467d53dc00b45a67c731d5b85/examples/simple.rs
// Copyright of the original: Christopher Berner and contributors to https://github.com/cberner/fuser
// License: MIT


#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)] // libc::S_* are u16 or u32 depending on the platform

#![feature(path_add_extension)]
#![feature(let_chains)]


pub mod crypt;
pub mod entropy;
pub mod repository;
pub mod cuttlefish;
mod errors;

use cuttlefish::{SimpleFS, SimpleFsOptions};

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

const BLOCK_SIZE: u64 = 512;
const MAX_NAME_LENGTH: u32 = 10_000;
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024; // 1 TB

const FMODE_EXEC: i32 = 0x20;

const ENCRYPTION_KEY_LENGTH: usize = 16;



// -------------------------------------------------------------------------------------
// Main


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

    // Common Args

    let arg_key = Arg::new("encryption-key")
        .long("encryption-key")
        .short('k')
        .value_name("KEY")
        .help("The key used to en-/decrypt the repository");

    let arg_dir = Arg::new("data-dir")
        .long("data-dir")
        .short('d')
        .value_name("DIR")
        .help("Set local directory used to store data");


    // CMDs

    let init_cmd = Command::new("init")
        .arg(arg_key.clone())
        .arg(arg_dir.clone());

    let mount_cmd = Command::new("mount")
    .arg(arg_key)
    .arg(arg_dir)
    .arg(
        Arg::new("direct-io")
            .long("direct-io")
            .action(ArgAction::SetTrue)
            .requires("mount-point")
            .help("Mount FUSE with direct IO"),
    )
    .arg(
        Arg::new("suid")
            .long("suid")
            .action(ArgAction::SetTrue)
            .help("Enable setuid support when run as root"),
    );

    
    let matches = Command::new("Crab-FS")
        .version(crate_version!())
        .author("Lukas Rieger")
        .arg(
            Arg::new("v")
                .short('v')
                .action(ArgAction::Count)
                .help("Sets the level of verbosity"),
        )
        .subcommand(gen_key_cmd)
        .subcommand(init_cmd)
        .subcommand(mount_cmd)
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
