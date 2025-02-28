// Note: this is modified from https://github.com/cberner/fuser/blob/d675c07ecb8e826467d53dc00b45a67c731d5b85/examples/simple.rs
// Copyright of the original: Christopher Berner and contributors to https://github.com/cberner/fuser
// License: MIT

#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)] // libc::S_* are u16 or u32 depending on the platform
#![feature(path_add_extension)]
#![feature(let_chains)]

pub mod crypt;
pub mod cuttlefish;
pub mod entropy;
mod errors;
pub mod io;
pub mod repository;

use cuttlefish::{SimpleFS, SimpleFsOptions};

use clap::{crate_version, Arg, ArgAction, Command};
#[cfg(feature = "abi-7-26")]
use fuser::consts::FUSE_HANDLE_KILLPRIV;
// #[cfg(feature = "abi-7-31")]
// use fuser::consts::FUSE_WRITE_KILL_PRIV;
use fuser::{
    Filesystem, MountOption,
};
use io::fs::PhysicalFS;
#[cfg(feature = "abi-7-26")]
use log::info;
use log::debug;
use log::{error, LevelFilter};
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind};
use std::env;


use rand::RngCore;

const BLOCK_SIZE: u64 = 512;
const MAX_NAME_LENGTH: u32 = 10_000;
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024; // 1 TB

const FMODE_EXEC: i32 = 0x20;

const ENCRYPTION_KEY_LENGTH: usize = 16;

// -------------------------------------------------------------------------------------
// Main

fn fuse_allow_other_enabled() -> std::io::Result<bool> {
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
        let mut rng = entropy::rng_from_entropy(&[entropy_keyboard, entropy_os].concat());

        let mut key: [u8; ENCRYPTION_KEY_LENGTH] = [0u8; ENCRYPTION_KEY_LENGTH];
        rng.fill_bytes(&mut key);

        let key_string = base64::encode(key);
        println!("Key:");
        println!("    {}", key_string);
        println!();
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

    if let Some(init) = matches.subcommand_matches("init") {
        let key_string = init
            .get_one::<String>("encryption-key")
            .unwrap()
            .to_string();
        let key: [u8; ENCRYPTION_KEY_LENGTH] = base64::decode(key_string)
            .unwrap()
            .try_into()
            .expect("incorrect base64 encryption key length");

        let data_dir = init.get_one::<String>("data-dir").unwrap().to_string();
        let backing_fs = PhysicalFS {};
        let mut fs = SimpleFS::new(backing_fs, SimpleFsOptions::default(), key, data_dir);
        match fs.create_fs() {
            Ok(_) => {
                println!("Successfully created filesystem");
            }
            Err(err) => {
                println!("Error: {:?}", err);
            }
        }
        return;
    }

    if let Some(mount) = matches.subcommand_matches("mount") {
        let key_string = mount
            .get_one::<String>("encryption-key")
            .unwrap()
            .to_string();
        let key: [u8; ENCRYPTION_KEY_LENGTH] = base64::decode(key_string)
            .unwrap()
            .try_into()
            .expect("incorrect base64 encryption key length");

        let data_dir = mount.get_one::<String>("data-dir").unwrap().to_string();

        let mountpoint: String = mount.get_one::<String>("mount-point").unwrap().to_string();

        let mut options = vec![MountOption::FSName("cuttlefish-fs".to_string())];

        #[cfg(feature = "abi-7-26")]
        {
            if mount.get_flag("suid") {
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

        debug!("calling [fuser::mount2] with options={options:?}");

        let fs_options = SimpleFsOptions {
            direct_io: mount.get_flag("direct-io"),
            #[cfg(feature = "abi-7-26")]
            suid_support: mount.get_flag("suid"),
            ..SimpleFsOptions::default()
        };

        let backing_fs = PhysicalFS {};
        let result = fuser::mount2(
            SimpleFS::new(backing_fs, fs_options, key, data_dir),
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
}
