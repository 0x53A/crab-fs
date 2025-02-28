# CLI

```
crab-fs gen-key
```

generates a new encryption key based on interactive keyboard input.

```
crab-fs init
```

initializes a **new** filesystem, errors if one already exists at the location.

```
crab-fs mount
```

mounts an **existing** filesystem


# Backends

At the moment, a backend needs to be able to **mutate** files, so something like S3, where objects can not be edited after creation doesn't work.

On a technical level, a backend is a ``FS`` trait implementation.

## In-Memory

There's a simple in-memory implementation that can be used for testing.

## Local

Stores data in a local folder.

## remote-fs

An adapter which enables the use of any [remote-fs](https://github.com/remotefs-rs/remotefs-rs) client which supports the following capabilities:

\<todo\>

# Frontends

At the moment there's a FUSE frontend for linux.

it would be interesting to add a [FsKit](https://developer.apple.com/documentation/fskit) implementation for macOS and a [Projected Filesystem](https://learn.microsoft.com/en-us/windows/win32/projfs/projected-file-system) implementation for Windows.

Alternatively a WebDAV frontend should work for all OSes.