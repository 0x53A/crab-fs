FROM ubuntu:latest

# Install basic dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    fuse \
    libfuse-dev \
    libssl-dev \
    smbclient \
    libsmbclient \
    libsmbclient-dev \
    git \
    pkg-config

# ---------------------------------------------------

# Install Rust using rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Add cargo to PATH
ENV PATH="/root/.cargo/bin:${PATH}"

RUN rustup toolchain install nightly


# ---------------------------------------------------

RUN apt-get install -y \
    unzip

# # Download and install fnm:
# RUN curl -o- https://fnm.vercel.app/install | bash
# ENV PATH="/root/.local/share/fnm:${PATH}"
# # Download and install Node.js:
# RUN fnm install 23

# # Use fnm to create node and npm symlinks in a known location
# RUN mkdir -p /usr/local/bin/nodejs && \
#     bash -c "source /root/.bashrc && fnm use 23 && \
#     ln -s \$(which node) /usr/local/bin/nodejs/node && \
#     ln -s \$(which npm) /usr/local/bin/nodejs/npm"

# # Add the symlinks directory to PATH
# ENV PATH="/usr/local/bin/nodejs:${PATH}"

# # Verify the Node.js version: (# Should print "v23.10.0".)
# RUN node -v
# # Verify npm version: (# Should print "10.9.2".)
# RUN npm -v

# # Download and install Node.js directly
# RUN curl -fsSL https://nodejs.org/dist/v23.10.0/node-v23.10.0-linux-x64.tar.xz -o /tmp/node.tar.xz \
#     && mkdir -p /usr/local/lib/nodejs \
#     && tar -xJf /tmp/node.tar.xz -C /usr/local/lib/nodejs \
#     && mv /usr/local/lib/nodejs/node-v23.10.0-linux-x64 /usr/local/lib/nodejs/node \
#     && ln -s /usr/local/lib/nodejs/node/bin/node /usr/local/bin/node \
#     && ln -s /usr/local/lib/nodejs/node/bin/npm /usr/local/bin/npm \
#     && ln -s /usr/local/lib/nodejs/node/bin/npx /usr/local/bin/npx \
#     && rm /tmp/node.tar.xz

# # Verify the Node.js version: (# Should print "v23.10.0".)
# RUN node -v
# # Verify npm version: (# Should print "10.9.2".)
# RUN npm -v

# # ---------------------------------------------------

# RUN npm install -g @anthropic-ai/claude-code