```log
error[E0554]: `#![feature]` may not be used on the stable release channel                                                                   
   --> C:\Users\hanhancat\.cargo\registry\src\index.crates.io-6f17d22bba15001f\printf-compat-0.1.1\src\lib.rs:116:1
    |
116 | #![feature(c_variadic)]
```

解决

```
This error message states, you cannot compile that code with stable Rust. You need to install nightly Rust and then use it to compile the program. You can use the following commands to run the code.

To install nightly version: rustup install nightly

To set nightly version as default: rustup default nightly

At anytime if you want to switch back to stable Rust: rustup default stable

The nightly version is updated very frequently, so you might want to update it every week or more often. To do so, you need to run this command: rustup update

I am closing this issue as it has been solved. If the problem persists, please comment and the issue will be reopened if appropriate
```