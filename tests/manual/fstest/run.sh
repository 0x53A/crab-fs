docker build -t fstest .

docker run -it --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
  -v /path/to/your/rust/fs:/usr/local/bin/your-fs fstest

docker run -it --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
  -v /path/to/your/rust/fs:/usr/local/bin/your-fs fstest  