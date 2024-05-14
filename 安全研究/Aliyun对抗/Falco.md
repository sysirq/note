# install

### Install the dependencies

    apt install git cmake build-essential pkg-config autoconf libtool libelf-dev -y

<!---->

    apt install libssl-dev libc-ares-dev libprotobuf-dev protobuf-compiler libjq-dev libgrpc++-dev protobuf-compiler-grpc libcurl4-openssl-dev libyaml-cpp-dev

### Build Falco

    git clone https://github.com/falcosecurity/falco.git
    cd falco
    mkdir -p build
    cd build
    cmake ..
    make falco

### Build kernel module driver

Kernel headers are required to build the driver.

    apt install linux-headers-$(uname -r)

In the build directory:

    make driver

### Build eBPF driver (optional)

If you do not want to use the kernel module driver you can, alternatively, build the eBPF driver as follows.

In the build directory:

    apt install llvm clang
    cmake -DBUILD_BPF=ON ..
    make bpf

### Build results

Once Falco is built, the three interesting things that you will find in your build folder are:

*   userspace/falco/falco: the actual Falco binary
*   driver/src/falco.ko: the Falco kernel driver
*   driver/bpf/falco.o: if you built Falco with BPF support

==If you'd like to build a debug version, run cmake as cmake -DCMAKE\_BUILD\_TYPE=Debug .. instead==

### Run falco

==Once Falco is built and the kernel module is loaded==, assuming you are in the build dir, you can run falco as:

    sudo ./userspace/falco/falco -c ../falco.yaml -r ../rules/falco_rules.yaml

# 

# TODO

Trace Me If You can:Bypassing Linux Syscall Tracing

https://i.blackhat.com/USA-22/Wednesday/US-22-Guo-Trace-me-if-you-can.pdf


# 资料

<https://falco.org/docs/install-operate/source/#cmake-options>

https://github.com/blackberry/Falco-bypasses

Adaptive Syscalls Selection in Falco

https://falco.org/blog/adaptive-syscalls-selection

Monitoring new syscalls with Falco

https://falco.org/blog/falco-monitoring-new-syscalls/

