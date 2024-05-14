Linux下静态编译

```
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

```toml
openssl = { version = "0.10", features = ["vendored"] }
```

# openssl

某天，群里有人交叉编译依赖了openssl的东西也失败了，然后大佬问"开启vendored了吗"，他表示没有，然后去试了下，回来说成功了

因此，我去谷歌搜了好多关于vendored关键字的内容，辅以rust/cargo等字眼，最终一无所获

因为编译失败的是openssl，于是我去看了一下它的文档https://crates.io/crates/openssl-sys/0.9.36，其中一段描述引起了我的注意

```toml
Vendored
[dependencies]
openssl = { version = "0.10", features = ["vendored"] }
```

这可不就是我在谷歌上没找到的东西嘛，先把这一段往依赖里加再说，于是Cargo.toml就变成这样

```toml
[package]
name = "hello"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
reqwest = { version = "0.11.18", features = ["json", "blocking"] }
openssl = { version = "0.10", features = ["vendored"] }
```

编译走起，它终于编译成功了！

### 结论

经过一番讨论研究，我项目并没有直接依赖openssl但是为了引入了依赖的方式并不够直观和优雅，通过查看reqwest的features发现它其实提供了native-tls-vendored将openssl的vendored给暴露了出来

于是，Cargo.toml就应该是这样

```toml
[package]
name = "hello"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
reqwest = { version = "0.11.18", features = ["json", "blocking", "native-tls-vendored"] }
```

如此就直观多了，如果遇到依赖了openssl但是没有暴露它的features的方案，可以使用上面那种并不直观的方式，追加一个openssl的直接依赖去修改

# 资料

解决rust编译目标为musl时openssl报错

https://www.cnblogs.com/buringstraw/p/16128325.html

记一次Rust静态编译

https://blog.xco.moe/posts/rust_build_musl/