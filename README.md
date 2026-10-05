# WASM-Hunter

WASM-Hunter is a high-performance, zero-dependency static analysis tool designed specifically for Attack Surface Mapping (ASM) of WebAssembly (`.wasm`) binaries. 

As more organizations compile their sensitive logic, cryptographic routines, and enterprise integrations into WebAssembly, `.wasm` files have become a significant blind spot in modern web security. WASM-Hunter natively parses WebAssembly binaries to extract hidden endpoints, internal IPs, and hardcoded secrets without the overhead or false positives associated with traditional secret scanners.

## The Problem with Traditional Scanners
Standard secret scanners and binary analysis tools typically fail when analyzing WebAssembly files due to:
1. **Memory Limits & Overhead:** General-purpose secret scanners often treat `.wasm` files as raw monolithic binaries, frequently crashing (OOM) or hitting string-read caps (e.g., 64MB limits).
2. **Binary Hallucinations (False Positives):** Extracting raw strings from `.wasm` files yields massive amounts of garbage data and compiled framework artifacts (like C++ or .NET namespaces), which regular regex engines misinterpret as valid tokens or endpoints.
3. **Dependency Hell:** Relying on external decompilers (like WABT) via OS-level processes introduces severe bottlenecks when scanning thousands of files simultaneously.

## The WASM-Hunter Solution
WASM-Hunter avoids decompiling the execution logic. Instead, it utilizes a custom, lightweight LEB128 parser written in pure Go to surgically extract the **Data Section (11)** and **Export Section (7)** of the WebAssembly binary.

* **Zero-Dependency:** Written in pure Go. No need to install `wasm-tools`, `wabt`, or any external parsers.
* **Blazing Fast:** Designed with concurrent workers. It can parse and extract high-fidelity intelligence from thousands of `.wasm` files in seconds.
* **High Precision:** Implements Shannon Entropy checks, IP validation (ignoring local/broadcast addresses), and framework noise-reduction filters to eliminate binary hallucinations.

## Installation

**Method 1: Using Go (Recommended)**
If you have Go installed, you can easily download and install WASM-Hunter globally:

```bash
go install github.com/Galaxy-sc/WASM-Hunter/cmd/wasm-hunter@latest
```

**Method 2: Build from Source**
You can also clone the repository and compile the tool directly:

```bash
git clone https://github.com/Galaxy-sc/WASM-Hunter.git
cd WASM-Hunter
go build ./cmd/wasm-hunter/main.go
```

## Usage

WASM-Hunter operates as a standalone CLI tool. You can feed it a single `.wasm` file, a direct URL, a directory containing thousands of files, or a `.txt` list of targets.

```bash
Usage of wasm-hunter:
  -compiler
        Only identify and print the compiler used for the WASM file(s)
  -debug
        Enable hex dump and memory debugging
  -i string
        Target .wasm file, directory, URL, or .txt list of targets (Required)
  -o string
        Output JSONL file (Optional. Prints to stdout if omitted)
  -w int
        Number of concurrent workers (default 12)
```

### Examples

**1. Scan a single local file:**
```bash
wasm-hunter -i target_module.wasm
```

**2. Scan a direct URL (automatically downloads, scans, and cleans up):**
```bash
wasm-hunter -i https://example.com/app.wasm
```

**3. Bulk scan using a text file (mixed URLs and local paths):**
```bash
wasm-hunter -i urls.txt -o results.jsonl -w 12
```

**4. Fast-Path Compiler Identification (skips deep extraction):**
```bash
wasm-hunter -i target_module.wasm -compiler
```

### Output Format
The tool generates clean JSON Lines (`.jsonl`), ensuring consistent audit logs for every scanned file (including the detected compiler). It is perfect for piping into `jq` or integrating into your automated reconnaissance pipelines.

```json
{
  "target_file": "app_core.wasm",
  "compiler": "Rust",
  "findings": {
    "Absolute URL": [
      "https://securitymgmt.staging.unifiedapis.example.com",
      "https://qa.auth.api.example.com/auth/v1/jwt"
    ],
    "Relative API Endpoint": [
      "/v1/jwt",
      "/v1/jwthttps"
    ],
    "IPv4 Address": [
      "52.5.4.72",
      "4.32.5.4"
    ]
  }
}
```

## Extracted Data Categories
WASM-Hunter currently targets and extracts the following assets for Attack Surface Mapping:
* **Infrastructure Mapping:** Absolute URLs, Relative API Endpoints, Public IPv4 Addresses.
* **Hardcoded Credentials:** AWS Keys, GCP API Keys, Stripe Keys, Slack Tokens, Discord Tokens, Telegram Bot Tokens, GitHub Personal Access Tokens.
* **Database URIs:** MongoDB, PostgreSQL, Redis connection strings.
* **Cryptographic Assets:** JWT Tokens, Private Keys (RSA/EC/SSH).

## License
This project is licensed under the Apache License 2.0.
