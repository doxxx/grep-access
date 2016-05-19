# grep-access

A grep-like tool for filtering Apache httpd access logs. It supports both the Common and Combined log formats.

## Building

Install [Rust](http://rust-lang.org/) and then execute:

```sh
cargo build
```

This should download and compile all dependencies and finally produce an `grep-access` executable in `targets/debug`.

## Usage

Executing `grep-access --help` will display a summary of the options available.
