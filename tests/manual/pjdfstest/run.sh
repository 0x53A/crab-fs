# build rust

docker build -t pjdfs-test .


docker run -it --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
  -v /path/to/your/rust/fs:/usr/local/bin/your-fs pjdfs-test