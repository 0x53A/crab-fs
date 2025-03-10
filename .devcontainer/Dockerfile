FROM ubuntu:latest

# Install basic dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    libfuse-dev \
    libssl-dev \
    smbclient \
    libsmbclient \
    libsmbclient-dev \
    git \
    pkg-config

# Install Rust using rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Add cargo to PATH
ENV PATH="/root/.cargo/bin:${PATH}"

RUN rustup toolchain install nightly
