# xdp-csum-rs

Some WIP code to try out calls to the `bpf_csum_diff` helper for IPv4 and ICMP
packets.

Currently the program has a hardcoded ICMP length of 64 bytes. This happens to work with the default `ping` on macOS, e.g.:
```shell
ping -c 1 xxx.xxx.xxx.xxx
```

Which makes the program print something like this:
```shell
[INFO  xdp_csum_rs] ip_hdr_len: 20
[INFO  xdp_csum_rs] icmp_offset: 34
[INFO  xdp_csum_rs] ip_total_len: 84
[INFO  xdp_csum_rs] original IPv4 checksum: 0xfad6
[INFO  xdp_csum_rs] recalculated IPv4 checkum: 0xfad6
[INFO  xdp_csum_rs] IP checksum is valid
[INFO  xdp_csum_rs] icmp_len: 64
[INFO  xdp_csum_rs] original ICMP checksum: 0xeffa
[INFO  xdp_csum_rs] ICMP recalculated checksum: 0xeffa
[INFO  xdp_csum_rs] ICMP checksum is valid
```

You can try pinging with some other size and this will just be ignored:
```shell
ping -s 67 -c 1 xxx.xxx.xxx.xxx
```

... resulting in:
```shell
[INFO  xdp_csum_rs] ip_hdr_len: 20
[INFO  xdp_csum_rs] icmp_offset: 34
[INFO  xdp_csum_rs] ip_total_len: 95
[INFO  xdp_csum_rs] original IPv4 checksum: 0x1485
[INFO  xdp_csum_rs] recalculated IPv4 checkum: 0x1485
[INFO  xdp_csum_rs] IP checksum is valid
[INFO  xdp_csum_rs] icmp_len: 75
[INFO  xdp_csum_rs] icmp_len (75) is larger than expected ICMP len (64)
```

In order to test other lengths (e.g. to check the code handling lengths not a multiple of 4), modify `xdp-csum-rs-ebpf/src/main.rs` and set
```rust
const EXPECTED_ICMP_LEN: usize = 64;
```
... to whatever is printed in `icmp_len`, so in this case you would set it to
`75`, which will then handle that specific length (which also happens to
trigger the code that deals with `bpf_csum_diff` expecting lengths
being a multiple of 4:
```
[INFO  xdp_csum_rs] ip_hdr_len: 20
[INFO  xdp_csum_rs] icmp_offset: 34
[INFO  xdp_csum_rs] ip_total_len: 95
[INFO  xdp_csum_rs] original IPv4 checksum: 0x60bd
[INFO  xdp_csum_rs] recalculated IPv4 checkum: 0x60bd
[INFO  xdp_csum_rs] IP checksum is valid
[INFO  xdp_csum_rs] icmp_len: 75
[INFO  xdp_csum_rs] original ICMP checksum: 0x6d10
[INFO  xdp_csum_rs] icmp_len is not a multiple of 4, remainder 3
[INFO  xdp_csum_rs] initial remainder buf: [0,0,0,0]
[INFO  xdp_csum_rs] iterating over remainder at 0, offset: 72
[INFO  xdp_csum_rs] icmphdr_remainder_byte: 40
[INFO  xdp_csum_rs] iterating over remainder at 1, offset: 73
[INFO  xdp_csum_rs] icmphdr_remainder_byte: 41
[INFO  xdp_csum_rs] iterating over remainder at 2, offset: 74
[INFO  xdp_csum_rs] icmphdr_remainder_byte: 42
[INFO  xdp_csum_rs] filled in remainder buf: [64,65,66,0]
[INFO  xdp_csum_rs] ICMP recalculated checksum: 0x6d10
[INFO  xdp_csum_rs] ICMP checksum is valid
```

Something else worth noting here is that at some point (I saw it at an
`icmp_len` above `515`) `bpf_csum_diff` will start returning `-22`
(`-EINVAL`) so more work is needed to handle larger packets. But at this point
the main thing to fix would be to make the verifier happy with a dynamically
calculated payload length so it does not need to hardcoded as it is now.

For reference, triggering the `-EINVAL` can be done by setting `const
EXPECTED_ICMP_LEN: usize = 516;` and doing
```shell
ping -s 508 -c 1 xxx.xxx.xxx.xxx
```

... resulting in:
```
[INFO  xdp_csum_rs] ip_hdr_len: 20
[INFO  xdp_csum_rs] icmp_offset: 34
[INFO  xdp_csum_rs] ip_total_len: 536
[INFO  xdp_csum_rs] original IPv4 checksum: 0x8462
[INFO  xdp_csum_rs] recalculated IPv4 checkum: 0x8462
[INFO  xdp_csum_rs] IP checksum is valid
[INFO  xdp_csum_rs] icmp_len: 516
[INFO  xdp_csum_rs] original ICMP checksum: 0x7cf0
[INFO  xdp_csum_rs] invalid call to bpf_csum_diff for ICMP packet: -22
```

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- --iface eth0
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package xdp-csum-rs --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/xdp-csum-rs` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, xdp-csum-rs is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
