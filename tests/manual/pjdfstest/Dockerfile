FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    pkg-config \
    python3 \
    libtool \
    automake \
    libfuse-dev \
    fuse

# Clone and build pjdfstest
RUN git clone https://github.com/pjd/pjdfstest.git \
    && cd pjdfstest \
    && autoreconf -ifs \
    && ./configure \
    && make \
    && make install

# Create mount point
RUN mkdir /mnt/fuse

# Set working directory
WORKDIR /mnt/fuse

# The FUSE filesystem binary should be mounted into the container
# Example run command:
# docker run -it --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
#   -v /path/to/your/fuse/binary:/usr/local/bin/you