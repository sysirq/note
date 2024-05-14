```toml
[profile.release]
panic = 'abort'
lto = true
opt-level = 'z'
codegen-units = 1
strip = true
```

# 资料

优化 Rust 程序编译体积

https://www.aloxaf.com/2018/09/reduce_rust_size/#%E5%BC%80%E5%90%AF-lto

rust stable 切换 nightly

https://www.cnblogs.com/yxi-liu/p/10648372.html