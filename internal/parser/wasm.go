package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"wasm-hunter/internal/models"
	"wasm-hunter/internal/utils"
)

func DetectCompiler(data []byte) string {
	if bytes.Contains(data, []byte("wasi_snapshot_preview1")) || bytes.Contains(data, []byte("wasi_unstable")) {
		if bytes.Contains(data, []byte("rust_panic")) || bytes.Contains(data, []byte("__rust_")) {
			return "Rust (WASI)"
		}
		if bytes.Contains(data, []byte("zig_panic")) || bytes.Contains(data, []byte("panicking.zig")) {
			return "Zig (WASI)"
		}
		return "C/C++ (WASI)"
	}

	if bytes.Contains(data, []byte("__wbindgen_")) || bytes.Contains(data, []byte("__wbg_")) {
		return "Rust (wasm-bindgen)"
	}
	if bytes.Contains(data, []byte("rustc")) || bytes.Contains(data, []byte("__rust_alloc")) || bytes.Contains(data, []byte("rust_eh_personality")) {
		return "Rust"
	}

	if bytes.Contains(data, []byte("emscripten_resize_heap")) || bytes.Contains(data, []byte("emscripten_notify_memory_growth")) {
		return "C/C++ (Emscripten)"
	}
	if bytes.Contains(data, []byte("invoke_ii")) || bytes.Contains(data, []byte("invoke_vi")) || bytes.Contains(data, []byte("invoke_iiii")) {
		return "C/C++ (Emscripten)"
	}
	if bytes.Contains(data, []byte("_ZSt")) || bytes.Contains(data, []byte("_ZNSt")) {
		return "C/C++ (Emscripten)"
	}

	if bytes.Contains(data, []byte("runtime.wasmExit")) || bytes.Contains(data, []byte("runtime.gopanic")) || bytes.Contains(data, []byte("Go build ID")) {
		return "Go"
	}
	if bytes.Contains(data, []byte("tinygo")) || bytes.Contains(data, []byte("io_get_stdout")) {
		return "TinyGo"
	}

	if bytes.Contains(data, []byte("mono_wasm_")) || bytes.Contains(data, []byte("dotnet")) || bytes.Contains(data, []byte("System.Private.CoreLib")) {
		return ".NET/Blazor"
	}

	if bytes.Contains(data, []byte("~lib/rt/")) || bytes.Contains(data, []byte("~lib/string/")) || bytes.Contains(data, []byte("~lib/memory/")) {
		return "AssemblyScript"
	}

	if bytes.Contains(data, []byte("SwiftRuntime")) || bytes.Contains(data, []byte("swift_panic")) {
		return "Swift"
	}
	if bytes.Contains(data, []byte("kotlin")) || bytes.Contains(data, []byte("kotlin-native")) {
		return "Kotlin"
	}

	if bytes.Contains(data, []byte("sqlite3_")) || bytes.Contains(data, []byte("draco_")) || bytes.Contains(data, []byte("TessBaseAPI")) || bytes.Contains(data, []byte("tesseract_")) || bytes.Contains(data, []byte("avcodec_")) || bytes.Contains(data, []byte("avformat_")) || bytes.Contains(data, []byte("ffmpeg_")) || bytes.Contains(data, []byte("ort_")) || bytes.Contains(data, []byte("onnx_")) {
		return "C/C++"
	}

	if bytes.Contains(data, []byte("_malloc")) && bytes.Contains(data, []byte("_free")) {
		return "C/C++"
	}

	return "Unknown"
}

func IsAddressInSegments(addr int64, segments []models.DataSegment) bool {
	for _, seg := range segments {
		if addr >= seg.MemoryOffset && addr < seg.MemoryOffset+int64(len(seg.Data)) {
			return true
		}
	}
	return false
}

func ExtractPrintableWithOffset(data []byte, baseOffset int64, minLen int) []models.ExtractedString {
	var res []models.ExtractedString
	var current strings.Builder
	var startOffset int64 = -1

	for i, b := range data {
		r := rune(b)
		if r >= 32 && r <= 126 {
			if current.Len() == 0 {
				startOffset = baseOffset + int64(i)
			}
			current.WriteRune(r)
		} else {
			if current.Len() >= minLen {
				res = append(res, models.ExtractedString{Text: current.String(), Offset: startOffset})
			}
			current.Reset()
		}
	}
	if current.Len() >= minLen {
		res = append(res, models.ExtractedString{Text: current.String(), Offset: startOffset})
	}
	return res
}

func ParseWasmDataSections(filePath string, minLength int) ([]models.ExtractedString, []models.DataSegment, string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, "Error", err
	}

	if len(data) < 8 || string(data[:4]) != "\x00asm" {
		return nil, nil, "Invalid", fmt.Errorf("not a valid wasm file")
	}

	compiler := DetectCompiler(data)

	var dataSegments []models.DataSegment
	var codePayload []byte

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

		if end > len(data) || end < offset {
			break
		}

		if secID == 10 {
			codePayload = data[offset:end]
		} else if secID == 11 {
			payload := data[offset:end]
			if len(payload) > 0 {
				count, n := utils.ReadLEB128(payload)
				idx := n
				for j := 0; j < int(count); j++ {
					if idx >= len(payload) {
						break
					}
					tag, n := utils.ReadLEB128(payload[idx:])
					idx += n

					if tag == 0 {
						if idx >= len(payload) {
							break
						}
						op := payload[idx]
						idx++
						var memOffset int64
						if op == 0x41 || op == 0x42 {
							if idx >= len(payload) {
								break
							}
							memOffset, n = utils.ReadSLEB128(payload[idx:])
							idx += n
						}

						if idx < len(payload) && payload[idx] == 0x0B {
							idx++
							if idx >= len(payload) {
								break
							}
							size, n := utils.ReadLEB128(payload[idx:])
							idx += n
							if idx+int(size) <= len(payload) {
								dataSegments = append(dataSegments, models.DataSegment{
									MemoryOffset: memOffset,
									Data:         payload[idx : idx+int(size)],
								})
							}
							idx += int(size)
						}
					} else if tag == 1 {
						if idx >= len(payload) {
							break
						}
						size, n := utils.ReadLEB128(payload[idx:])
						idx += n + int(size)
					} else if tag == 2 {
						if idx >= len(payload) {
							break
						}
						_, n = utils.ReadLEB128(payload[idx:])
						idx += n
						if idx >= len(payload) {
							break
						}
						op := payload[idx]
						idx++
						if op == 0x41 || op == 0x42 {
							if idx >= len(payload) {
								break
							}
							_, n = utils.ReadSLEB128(payload[idx:])
							idx += n
						}
						if idx < len(payload) && payload[idx] == 0x0B {
							idx++
							if idx >= len(payload) {
								break
							}
							size, n := utils.ReadLEB128(payload[idx:])
							idx += n + int(size)
						}
					}
				}
			}
		}
		offset = end
	}

	var pointers []int64

	if len(codePayload) > 5 {
		for i := 0; i < len(codePayload)-5; i++ {
			op := codePayload[i]
			if op == 0x41 {
				val, n := utils.ReadSLEB128(codePayload[i+1:])
				pointers = append(pointers, int64(uint32(val)))
				i += n
			} else if op == 0x42 {
				val, n := utils.ReadSLEB128(codePayload[i+1:])
				pointers = append(pointers, val)
				i += n
			}
		}
	}

	// -------------------------------------------------------------
	// OPTIMIZATION 1: Bounding Box for Memory Segments
	// -------------------------------------------------------------
	var minAddr int64 = math.MaxInt64
	var maxAddr int64 = -1
	for _, seg := range dataSegments {
		if seg.MemoryOffset < minAddr {
			minAddr = seg.MemoryOffset
		}
		endOffset := seg.MemoryOffset + int64(len(seg.Data))
		if endOffset > maxAddr {
			maxAddr = endOffset
		}
	}

	// Go string heuristic parsing
	if compiler == "Go" || compiler == "Unknown" {
		for _, seg := range dataSegments {
			if len(seg.Data) < 16 {
				continue
			}
			for i := 0; i <= len(seg.Data)-16; i += 8 {
				addr := int64(binary.LittleEndian.Uint64(seg.Data[i : i+8]))
				length := binary.LittleEndian.Uint64(seg.Data[i+8 : i+16])

				// Fast-Fail check against bounding box before doing the heavy O(S) loop
				if length > 1 && length < 5000 && addr >= minAddr && addr <= maxAddr {
					if IsAddressInSegments(addr, dataSegments) {
						pointers = append(pointers, addr)
						pointers = append(pointers, addr+int64(length))
					}
				}
			}
		}
	}

	for _, seg := range dataSegments {
		pointers = append(pointers, seg.MemoryOffset)
		pointers = append(pointers, seg.MemoryOffset+int64(len(seg.Data)))
	}

	sort.Slice(pointers, func(i, j int) bool { return pointers[i] < pointers[j] })
	
	var uniquePointers []int64
	var last int64 = -1
	for _, p := range pointers {
		if p != last {
			uniquePointers = append(uniquePointers, p)
			last = p
		}
	}

	var stringsList []models.ExtractedString
	seen := make(map[string]bool)

	for _, seg := range dataSegments {
		segStart := seg.MemoryOffset
		segEnd := seg.MemoryOffset + int64(len(seg.Data))

		// -------------------------------------------------------------
		// OPTIMIZATION 2: Binary Search instead of full loop
		// -------------------------------------------------------------
		startIdx := sort.Search(len(uniquePointers), func(i int) bool {
			return uniquePointers[i] >= segStart
		})

		var segPtrs []int64
		for i := startIdx; i < len(uniquePointers); i++ {
			p := uniquePointers[i]
			if p > segEnd {
				break // Stop searching once we pass the current segment
			}
			segPtrs = append(segPtrs, p)
		}

		// Iterate over sliced segments to extract clean strings
		for i := 0; i < len(segPtrs)-1; i++ {
			start := segPtrs[i] - segStart
			end := segPtrs[i+1] - segStart

			if end-start >= int64(minLength) && end <= int64(len(seg.Data)) {
				chunk := seg.Data[start:end]
				cleanStrings := ExtractPrintableWithOffset(chunk, segStart+start, minLength)
				for _, s := range cleanStrings {
					if !seen[s.Text] {
						stringsList = append(stringsList, s)
						seen[s.Text] = true
					}
				}
			}
		}
	}

	return stringsList, dataSegments, compiler, nil
}