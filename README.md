# WASM-Hunter

WASM-Hunter is a high-performance, zero-dependency static analysis tool designed specifically for Attack Surface Mapping (ASM) of WebAssembly (`.wasm`) binaries. 

As more organizations compile their sensitive logic, cryptographic routines, and enterprise integrations into WebAssembly, `.wasm` files have become a significant blind spot in modern web security. WASM-Hunter natively parses WebAssembly binaries to extract exposed/hidden functions, internal API endpoints, and hardcoded secrets without the overhead or false positives associated with traditional secret scanners.

## The Problem with Traditional Scanners
Standard secret scanners and binary analysis tools typically fail when analyzing WebAssembly files due to:
1. **Memory Limits & Overhead:** General-purpose secret scanners often treat `.wasm` files as raw monolithic binaries, frequently crashing (OOM) or hitting string-read caps.
2. **Architecture Blindness:** Traditional tools cannot parse WASM linear memory or bypass internal fragmentation (like Go's `pclntab`), leaving business logic and internal endpoints completely hidden.
3. **Binary Hallucinations (False Positives):** Extracting raw strings from `.wasm` files yields massive amounts of garbage data and compiler glue code, which regular regex engines misinterpret as valid tokens.

## The WASM-Hunter Solution
WASM-Hunter avoids decompiling the execution logic. Instead, it utilizes a custom, lightweight LEB128 parser written in pure Go to surgically extract the **Import Section (2)**, **Export Section (7)**, and **Data Section (11)** of the WebAssembly binary.

- **Polyglot Function Extraction:** Maps the attack surface by extracting standard W3C Imports/Exports for C/C++ and Rust, while using advanced heuristics to recover hidden internal functions in Go-compiled binaries.
- **Zero-Dependency:** Written in pure Go. No need to install external decompilers like `wasm-tools` or `wabt`.
- **High Precision:** Implements strict compiler artifact filtering (WASI, Emscripten, wasm-bindgen), Shannon Entropy checks, and IP validation to eliminate binary hallucinations.
- **CI/CD Ready:** Outputs clean, modular JSON lines (`stdout`) while routing informational logs to `stderr`, making it perfect for pipeline integrations.

## Installation

**Method 1: Using Go (Recommended)**
If you have Go installed, you can easily download and install WASM-Hunter globally:

```sh
go install https://github.com/Galaxy-sc/WASM-Hunter/cmd/wasm-hunter@latest
```

**Method 2: Build from Source**
You can also clone the repository and compile the tool directly:

```sh
git clone https://github.com/Galaxy-sc/WASM-Hunter.git
cd WASM-Hunter
go build -ldflags="-s -w" -o wasm-hunter ./cmd/wasm-hunter/main.go
```

## Usage

WASM-Hunter operates as a standalone CLI tool. You can feed it a single `.wasm` file, a direct URL, a directory containing thousands of files, or a `.txt` list of targets.

```sh
Usage of wasm-hunter:
  -compiler
        Include the compiler used for the WASM file(s) in output
  -data-only
        Extract only secrets, IPs, and URLs (skip functions)
  -debug
        Enable hex dump and memory debugging
  -funcs-only
        Extract only function names (imports, exports, hidden) and skip secrets
  -i string
        Target .wasm file, directory, URL, or .txt list of targets (Required)
  -o string
        Output JSONL file (Optional. Prints to stdout if omitted)
  -v    Verbose mode: print progress and informational logs to stderr
  -w int
        Number of concurrent workers (default 12)
```

### Examples

**1. Scan a single local file:**
```sh
wasm-hunter -i target_module.wasm
```

**2. Fast-Path Architecture Mapping (Functions only):**
```sh
wasm-hunter -i target_module.wasm -funcs-only
```

**3. Scan a direct URL with verbose logging:**
```sh
wasm-hunter -i https://example.com/app.wasm -v
```

**4. Bulk scan for secrets using a text file (mixed URLs and local paths):**
```sh
wasm-hunter -i urls.txt -o results.jsonl -w 12 -data-only
```

### Output Format
The tool generates clean, modular JSON Lines (`.jsonl`). It distinctly separates the architectural attack surface (`functions`) from data exposures (`indicators`), ensuring perfect compatibility with automated DevSecOps pipelines like `jq`.

```json
{
  "target_file": "test_nested.wasm",
  "compiler": "Go",
  "functions": {
    "Go Hidden Functions": [
      "main.invokeSecureActionWrapper",
      "wasm-target/internal/auth.VerifyAdminPrivileges",
      "wasm-target/internal/core.ExecuteAdminAction",
      "wasm-target/internal/api.DispatchSecurePayload"
    ]
  },
  "indicators": {
    "AWS Access Key": [
      "AKIAIOSFODNN7EXAMPLE"
    ],
    "Absolute URL": [
      "https://api.internal.corp"
    ],
    "Relative API Endpoint": [
      "/v1/action"
    ],
    "JWT Token": [
      "eyJhbGciOiJIUzI1NiIsInR5..."
    ]
  }
}
```

## Extracted Data Categories
WASM-Hunter targets and extracts the following assets for comprehensive Attack Surface Mapping:
- **Architectural Mapping:** Wasm Exported Functions, Wasm Imported Functions, and Go Hidden Functions.
- **Infrastructure Mapping:** Absolute URLs, Relative API Endpoints, Public IPv4 Addresses.
- **Hardcoded Credentials:** AWS Keys, GCP API Keys, Stripe Keys, Slack Tokens, Discord Tokens, Telegram Bot Tokens, GitHub Personal Access Tokens.
- **Database URIs:** MongoDB, PostgreSQL, Redis connection strings.
- **Cryptographic Assets:** JWT Tokens, Private Keys (RSA/EC/SSH).

## License
This project is licensed under the Apache License 2.0.
