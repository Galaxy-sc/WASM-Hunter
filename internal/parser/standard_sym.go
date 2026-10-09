package parser

import (
	"os"
	"strings"

	"github.com/Galaxy-sc/WASM-Hunter/internal/utils"
)

// WasmSymbols holds the extracted standard WebAssembly imports and exports
type WasmSymbols struct {
	Imports []string
	Exports []string
}

// noiseWasmPrefixes filters out compiler-generated glue code (Emscripten, WASI, Rust wasm-bindgen)
var noiseWasmPrefixes = []string{
	"wasi_snapshot_", "wasi_unstable", "__wbindgen_", "__wbg_",
	"invoke_", "dynCall_", "stack", "__cxa_", "emscripten_",
	"__data_", "__heap_", "dlsetjmp", "setTempRet0", "getTempRet0",
	"__externref_",
}

// noiseWasmExact filters out standard memory, table, and initialization exports
var noiseWasmExact = map[string]bool{
	"memory": true, "table": true, "__indirect_function_table": true,
	"__wasm_call_ctors": true, "_initialize": true, "__errno_location": true,
	"malloc": true, "free": true, "calloc": true, "realloc": true, "fflush": true,
}

// ExtractStandardWasmFunctions parses Section 2 (Imports) and Section 7 (Exports) from any Wasm binary
func ExtractStandardWasmFunctions(filePath string) (WasmSymbols, error) {
	var symbols WasmSymbols
	data, err := os.ReadFile(filePath)
	if err != nil {
		return symbols, err
	}

	if len(data) < 8 || string(data[:4]) != "\x00asm" {
		return symbols, nil
	}

	offset := 8
	for offset < len(data) {
		secID := data[offset]
		offset++
		if offset >= len(data) {
			break
		}

		secLen, n := utils.ReadLEB128(data[offset:])
		if n == 0 {
			break
		}
		offset += n
		end := offset + int(secLen)
		if end > len(data) {
			break
		}

		if secID == 2 {
			parseImports(data[offset:end], &symbols)
		} else if secID == 7 {
			parseExports(data[offset:end], &symbols)
		}

		offset = end
	}

	return symbols, nil
}

func parseImports(payload []byte, symbols *WasmSymbols) {
	idx := 0
	count, n := utils.ReadLEB128(payload[idx:])
	idx += n

	for i := 0; i < int(count); i++ {
		if idx >= len(payload) {
			break
		}

		modLen, n := utils.ReadLEB128(payload[idx:])
		idx += n
		if idx+int(modLen) > len(payload) {
			break
		}
		modName := string(payload[idx : idx+int(modLen)])
		idx += int(modLen)

		fieldLen, n := utils.ReadLEB128(payload[idx:])
		idx += n
		if idx+int(fieldLen) > len(payload) {
			break
		}
		fieldName := string(payload[idx : idx+int(fieldLen)])
		idx += int(fieldLen)

		kind := payload[idx]
		idx++

		if kind == 0 {
			_, n = utils.ReadLEB128(payload[idx:])
			idx += n
			
			fullName := modName + "." + fieldName
			if !isWasmNoise(fieldName) && !isWasmNoise(modName) {
				symbols.Imports = append(symbols.Imports, fullName)
			}
		} else if kind == 1 || kind == 2 {
			idx++
			flags := payload[idx-1]
			_, n = utils.ReadLEB128(payload[idx:])
			idx += n
			if flags == 1 {
				_, n = utils.ReadLEB128(payload[idx:])
				idx += n
			}
		} else if kind == 3 {
			idx += 2
		}
	}
}

func parseExports(payload []byte, symbols *WasmSymbols) {
	idx := 0
	count, n := utils.ReadLEB128(payload[idx:])
	idx += n

	for i := 0; i < int(count); i++ {
		if idx >= len(payload) {
			break
		}

		nameLen, n := utils.ReadLEB128(payload[idx:])
		idx += n
		if idx+int(nameLen) > len(payload) {
			break
		}
		name := string(payload[idx : idx+int(nameLen)])
		idx += int(nameLen)

		kind := payload[idx]
		idx++

		if kind == 0 {
			_, n = utils.ReadLEB128(payload[idx:])
			idx += n
			if !isWasmNoise(name) {
				symbols.Exports = append(symbols.Exports, name)
			}
		} else {
			_, n = utils.ReadLEB128(payload[idx:])
			idx += n
		}
	}
}

// isWasmNoise checks if the function name is a known compiler-generated artifact
func isWasmNoise(name string) bool {
	if noiseWasmExact[name] {
		return true
	}
	for _, prefix := range noiseWasmPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}