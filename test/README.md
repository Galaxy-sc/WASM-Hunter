# WASM-Hunter Target Labs

This directory contains target WebAssembly binaries compiled from different languages (Go, Rust, and C/C++). These labs are specifically designed to evaluate and validate WASM-Hunter's String-Pointer Splitting algorithm, Memory Architecture Agnosticism, and Noise Filtering capabilities.

To prevent compilers from applying aggressive Dead Code Elimination (DCE) to the hardcoded secrets, all labs implement FFI (Foreign Function Interface) or native bindings to pass sensitive data into JavaScript/Web environments.

## Build Instructions

If you want to rebuild the test binaries from the source, follow the instructions below for each language:

### 1. Golang Lab (`golang-wasm.wasm`)
Compiles the Go target using `syscall/js` and `net/http` to simulate real-world browser usage and prevent DCE.

**Prerequisites:** Go 1.21+

~~~powershell
cd go_lab
$env:GOOS="js"; $env:GOARCH="wasm"; go build -ldflags="-s -w" -o golang-wasm.wasm .\golang-wasm.go
$env:GOOS=""; $env:GOARCH=""
~~~

### 2. Rust Lab (`wasm_lab.wasm`)
Compiles the Rust target using `wasm-bindgen` to test the scanner against LLVM's aggressive memory optimization.

**Prerequisites:** Rust, Cargo, and `wasm32-unknown-unknown` target.

~~~powershell
cd rust_lab
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
~~~

### 3. C/C++ Lab (`clang_wasm.wasm`)
Compiles the C target using Emscripten to validate the scanner's ability to filter out severe binary hallucinations and compiler artifacts (e.g., libc, emsdk noise).

**Prerequisites:** Emscripten SDK (emsdk)

~~~powershell
cd c_lab
emcc.exe .\clang_wasm.c -O3 -s WASM=1 -s STANDALONE_WASM=1 -o clang_wasm.wasm
~~~