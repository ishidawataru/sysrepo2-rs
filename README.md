sysrepo2-rs
---

Rust bindings for the [sysrepo2] library.

For raw FFI bindings for sysrepo2, see [sysrepo2-sys].

[sysrepo2]: https://github.com/sysrepo/sysrepo
[sysrepo2-sys]: https://github.com/ishidawataru/sysrepo2-rs/tree/master/sysrepo2-sys

### How to test

#### Prerequisite

- Docker

```bash
$ git clone https://github.com/ishidawataru/sysrepo2-rs.git
$ cd sysrepo2-rs
$ git submodule --upgrade --init
$ make builder # build the container image for the build
$ make bash # start the image
root@af871b859f5f:/data# make test # run cargo test
```

### License

This project is licensed under the [MIT license].

[MIT license]: https://github.com/ishidawataru/sysrepo2-rs/blob/master/LICENSE
