# Copyright 2018 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

FROM debian:stretch
LABEL description="Test crosvm using a command like the following: \
docker run --privileged -v /dev/log:/dev/log -v <path to crosvm>:/platform/crosvm:ro <crosvm base image>"

RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    curl \
    gcc \
    g++ \
    git \
    libcap-dev \
    libdbus-1-dev \
    libdrm-dev \
    libfdt-dev \
    libegl1-mesa-dev \
    libgl1-mesa-dev \
    libgles1-mesa-dev \
    libgles2-mesa-dev \
    libssl1.0-dev \
    libtool \
    libusb-1.0-0-dev \
    libwayland-dev \
    make \
    nasm \
    ninja-build \
    pkg-config \
    protobuf-compiler \
    python3

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.33.0 \
    RUSTFLAGS='--cfg hermetic'

# Debian usually has an old rust version in the repository. Instead of using that, we use rustup to
# pull in a toolchain versions of our choosing.
RUN curl -LO "https://static.rust-lang.org/rustup/archive/1.14.0/x86_64-unknown-linux-gnu/rustup-init" \
    && echo "0077ff9c19f722e2be202698c037413099e1188c0c233c12a2297bf18e9ff6e7 *rustup-init" | sha256sum -c - \
    && chmod +x rustup-init \
    && ./rustup-init -y --no-modify-path --default-toolchain $RUST_VERSION \
    && rustup component add rustfmt-preview \
    && rm rustup-init \
    && chmod -R a+w $RUSTUP_HOME $CARGO_HOME \
    && rustup --version \
    && cargo --version \
    && rustc --version

# Warms up the cargo registry cache for future cargo runs. Cargo will still update the cache using a
# git pull, but it only needs to download files that were changed since this image was built.
RUN cargo install thisiznotarealpackage -q || true

# Used /scratch for building dependencies which are too new or don't exist on Debian stretch.
WORKDIR /scratch

# minijail does not exist in upstream linux distros.
RUN git clone https://android.googlesource.com/platform/external/minijail \
    && cd minijail \
    && make -j24 \
    && cp libminijail.so /usr/lib/x86_64-linux-gnu/

# The gbm used by upstream linux distros is not compatible with crosvm, which must use Chrome OS's
# minigbm.
RUN dpkg --force-depends -r libgbm1
RUN git clone https://chromium.googlesource.com/chromiumos/platform/minigbm \
    && cd minigbm \
    && sed 's/-Wall/-Wno-maybe-uninitialized/g' -i Makefile \
    && make install -j24

# New libepoxy requires newer meson than is in Debian stretch.
RUN git clone https://github.com/mesonbuild/meson \
    && cd meson \
    && git checkout 0a5ff338012a00f32c3aa9d8773835accc3e4e5b \
    && ln -s $PWD/meson.py /usr/bin/meson

# New libepoxy has EGL_KHR_DEBUG entry points needed by crosvm.
RUN git clone https://github.com/anholt/libepoxy.git \
    && cd libepoxy \
    && git checkout 707f50e680ab4f1861b1e54ca6e2907aaca56c12 \
    && mkdir build \
    && cd build \
    && meson \
    && ninja install

# virglrenderer is under heavy development on master and we want the very latest.
RUN git clone https://gitlab.freedesktop.org/virgl/virglrenderer.git \
    && cd virglrenderer \
    && ./autogen.sh \
    && make install -j24

# Install libtpm2 so that tpm2-sys/build.rs does not try to build it in place in
# the read-only source directory.
RUN git clone https://chromium.googlesource.com/chromiumos/third_party/tpm2 \
    && cd tpm2 \
    && git checkout 15260c8cd98eb10b4976d2161cd5cb9bc0c3adac \
    && make -j24 \
    && cp build/libtpm2.a /lib

# Install librendernodehost
RUN git clone https://chromium.googlesource.com/chromiumos/platform2 \
    && cd platform2 \
    && git checkout 226fc35730a430344a68c34d7fe7d613f758f417 \
    && cd rendernodehost \
    && gcc -c src.c -o src.o \
    && ar rcs librendernodehost.a src.o \
    && cp librendernodehost.a /lib

# Set up sysroot from which system_api proto files are built.
ENV SYSROOT=/sysroot
RUN mkdir -p $SYSROOT/usr/include/chromeos/dbus/trunks \
    && cp platform2/trunks/interface.proto \
        $SYSROOT/usr/include/chromeos/dbus/trunks

# Inform pkg-config where libraries we install are placed.
COPY pkgconfig/* /usr/lib/pkgconfig

# Reduces image size and prevents accidentally using /scratch files
RUN rm -r /scratch /usr/bin/meson

# The manual installation of shared objects requires an ld.so.cache refresh.
RUN ldconfig

# Pull down repositories that crosvm depends on to cros checkout-like locations.
ENV CROS_ROOT=/
ENV THIRD_PARTY_ROOT=$CROS_ROOT/third_party
RUN mkdir -p $THIRD_PARTY_ROOT
ENV PLATFORM_ROOT=$CROS_ROOT/platform
RUN mkdir -p $PLATFORM_ROOT

# Pull the cras library for audio access.
RUN git clone https://chromium.googlesource.com/chromiumos/third_party/adhd $THIRD_PARTY_ROOT/adhd

# The /build directory is used so that the bind mounted /platform/crosvm volume
# does not get scribbled on.
ENV CARGO_TARGET_DIR=/build
RUN mkdir -p $CARGO_TARGET_DIR
WORKDIR /platform/crosvm
CMD rustup default "$(cat rust-toolchain)" && \
    rustup component add rustfmt-preview && \
    cargo --version && rustc --version && rustfmt --version && \
    echo "Running cargo test" && \
    cargo test --no-fail-fast --features plugin,default-no-sandbox,wl-dmabuf,gpu,tpm,gpu-forward \
    --all --exclude aarch64 $TEST_FLAGS -- \
    --test-threads=1 $TEST_RUNNER_FLAGS && \
    echo "Running cargo fmt" && \
    bin/fmt --check
