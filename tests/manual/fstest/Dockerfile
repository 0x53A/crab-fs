FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    pkg-config \
    libfuse-dev \
    fuse \
    perl

# Clone fstest
RUN git clone https://github.com/zfsonlinux/fstest.git \
    && cd fstest \
    && make

# Create mount point
RUN mkdir /mnt/fuse

# Set working directory
WORKDIR /mnt/fuse

# Add fstest to PATH
ENV PATH="/fstest:${PATH}"

# The FUSE filesystem binary should be mounted into the container
# Example run command:
# docker run -it --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
#   -v /path/to/your/fuse/binary:/usr/local/bin/your-fs your-image-name