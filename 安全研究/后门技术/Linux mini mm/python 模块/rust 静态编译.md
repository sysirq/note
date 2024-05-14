在Rust中编译静态链接的可执行文件

https://blog.ckylin.site/study/rust-linux-static-linked-executable.md

```
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-musl
```