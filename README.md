# Reflective PE COFF DLL loader

[![Crates.io](https://img.shields.io/crates/v/reflective_pe_dll_loader)](https://crates.io/crates/reflective_pe_dll_loader)
[![Downloads](https://img.shields.io/crates/d/reflective_pe_dll_loader.svg)](https://crates.io/crates/reflective_pe_dll_loader)
[![Documentation](https://docs.rs/reflective_pe_dll_loader/badge.svg)](https://docs.rs/reflective_pe_dll_loader)
[![License](https://img.shields.io/crates/l/reflective_pe_dll_loader)](https://crates.io/crates/reflective_pe_dll_loader)
[![Dependency Status](https://deps.rs/repo/github/JohnScience/reflective_pe_dll_loader/status.svg)](https://deps.rs/repo/github/JohnScience/reflective_pe_dll_loader)

A loader is a program that loads some executable code (e.g. in ELF, PE COFF, or Mach-O formats) into memory so that it can be executed.

A reflective loader is such a loader that loads the executable code from a memory buffer, rather than from a file on disk.

```rust
use reflective_pe_dll_loader::{PeDll, Symbol};

let bytes: &[u8] = include_bytes!("../test-dlls/hello_world_lib.dll");
let pe_dll = PeDll::new(&bytes).unwrap();

let add: Symbol<extern "C" fn(i32, i32) -> i32> = {
    let symbol = pe_dll.get_symbol_by_name("add").unwrap();
    unsafe { symbol.assume_type() }
};

assert_eq!(add(1, 2), 3);
```

## Recommendations

This crate has limited use cases. If you can avoid building a dynamic library that you'd embed in your executable and instead create an object file that you'd statically link with your executable, you should do that.

## Credits

It is largely based on the code from <https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/>.

**Note**: the tutorial is incomplete and, for example, does not cover TLS callbacks. This may be a problem for some DLLs but may be fixed in the future.
