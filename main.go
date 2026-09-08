package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Noisy domains to filter out
var noisyDomains = []string{
	"w3.org", "wikipedia.org", "schema.org", "github.com", "docs.rs",
	"opensource.org", "apache.org", "apple.com", "microsoft.com",
	"aka.ms", "pris.ly", "xmlsoap.org", "1password.com", "bitwarden.com",
	"unicode.org", "go.dev", "cambridgesoft.com", "sil.org", "cairographics.org",
	"nvidia.com", "ieee.org", "arxiv.org", "scipy.org", "play.rust-lang.org",
	"fonts.googleapis.com", "fonts.gstatic.com", "publicsuffix.org", "iana.org",
	"mcafee.com", "mcafeewebadvisor.com", "yahoo.com", "tawk.to", "office.com",
	"libretro.com", "retroachievements.org", "wencodeURIComponent",
}

// Extensions typically associated with noise rather than valid endpoints
var noisyExtensions = []string{
	".rs", ".cpp", ".c", ".h", ".hpp", ".cc", ".go", ".ts", ".js",
	".proto", ".md", ".txt", ".xml", ".xsd", ".dtd", ".html",
	".css", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".wasm",
}

// Common framework and system keywords to ignore
var noisyEndpointKeywords = []string{
	"__", "system.text", "system.net", "system.io", "system.collections",
}

// Regular expressions to identify and filter out common compiler artifacts
var compilerArtifactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:/opt/emsdk/|emsdk/upstream/|/musl/src/|/libcxxabi/)`),
	regexp.MustCompile(`(?i)(?:\.cargo/registry/|\.cargo/git/|\.rustup/toolchains/)`),
	regexp.MustCompile(`(?i)(?:/home/runner/work/|/home/runner/\.cache/)`),
	regexp.MustCompile(`(?i)(?:/usr/share/zoneinfo/|/etc/zoneinfo/|/etc/localtime)`),
	regexp.MustCompile(`(?i)(?:/tmp/lept/|/tmp/wvj/|/var/folders/|/opt/homebrew/)`),
	regexp.MustCompile(`(?i)(?:/usr/local/go/src/|/tinygo/src/)`),
	regexp.MustCompile(`(?i)(?:__rustc)oxy`),
}

var jsPropertyPattern = regexp.MustCompile(`^(?:[a-zA-Z_$][0-9a-zA-Z_$]*\.)+[a-zA-Z_$][0-9a-zA-Z_$]*$`)

// Core regex patterns for finding secrets, tokens, and endpoints
var patterns = map[string]*regexp.Regexp{
	"AWS Access Key":           regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
	"AWS Session Token":        regexp.MustCompile(`(ASIA[0-9A-Z]{16})`),
	"GCP API Key":              regexp.MustCompile(`(AIza[0-9A-Za-z\-_]{35})`),
	"Azure Storage Account":    regexp.MustCompile(`([a-z0-9-]+\.blob\.core\.windows\.net)`),
	"AWS S3 Bucket":            regexp.MustCompile(`([a-z0-9.-]+\.s3\.amazonaws\.com)`),
	"Slack Bot Token":          regexp.MustCompile(`(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})`),
	"Slack Webhook":            regexp.MustCompile(`(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24})`),
	"Discord Bot Token":        regexp.MustCompile(`(MT[0-9A-Za-z_-]{22,23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27})`),
	"Telegram Bot Token":       regexp.MustCompile(`(?:^|[^0-9])([0-9]{8,10}:[a-zA-Z0-9_-]{35})(?:$|[^a-zA-Z0-9_-])`),
	"Stripe Standard Key":      regexp.MustCompile(`((?:sk|rk)_(?:test|live)_[a-zA-Z0-9]{24,})`),
	"GitHub Personal Token":    regexp.MustCompile(`((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9_]{36})`),
	"MongoDB URI":              regexp.MustCompile(`(mongodb(?:\+srv)?://[a-zA-Z0-9_.-]+:[^@\s]+@[a-zA-Z0-9_.-]+)`),
	"PostgreSQL URI":           regexp.MustCompile(`(postgres(?:ql)?://[a-zA-Z0-9_.-]+:[^@\s]+@[a-zA-Z0-9_.-]+:[0-9]{2,5})`),
	"Redis URI":                regexp.MustCompile(`(redis(?:s)?://(?:[a-zA-Z0-9_.-]+:)?([^@\s]+)@[a-zA-Z0-9_.-]+:[0-9]{2,5})`),
	"JWT Token":                regexp.MustCompile(`(eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{10,})`),
	"Private Key (RSA/EC/SSH)": regexp.MustCompile(`(-----BEGIN [A-Z ]+ PRIVATE KEY-----[A-Za-z0-9+/=]{64,}-----END [A-Z ]+ PRIVATE KEY-----)`),
	"Generic Secret/Token":     regexp.MustCompile(`(?i)(?:password|api[_-]?key|secret|token|auth[_-]?token|client[_-]?(?:secret|id)|access[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_=]{16,64})["']?`),
	"IPv4 Address":             regexp.MustCompile(`((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))`),
	"Absolute URL":             regexp.MustCompile(`(https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?::[0-9]+)?(?:/[a-zA-Z0-9_/\-\.?=&%]+)?)`),
	"Relative API Endpoint":    regexp.MustCompile(`(/(?:api|v[1-9][0-9]*)/[a-zA-Z0-9_/\-\.?=&]+)`),
	"GraphQL Query":            regexp.MustCompile(`(?i)(query\s+[A-Za-z0-9_]*\s*\{|mutation\s+[A-Za-z0-9_]*\s*\{)`),
	"URL/Form Parameters":      regexp.MustCompile(`[?&]([a-zA-Z0-9_.-]+)=`),
	"Sensitive JSON Keys":      regexp.MustCompile(`"(?i)(password|token|secret|api_?key|private_?key)"\s*:`),
	"HTTP Headers":             regexp.MustCompile(`(?i)(X-[a-zA-Z0-9_-]+|Authorization|Bearer|Cookie|Set-Cookie)\s*:`),
}

// Minimum entropy levels required to validate certain generic or unstructured tokens
var entropyThresholds = map[string]float64{
	"Generic Secret/Token": 4.1,
	"JWT Token":            4.0,
	"GCP API Key":          3.8,
}

var (
	fileMutex  sync.Mutex
	outputPath string
	debugMode  bool
)

// Calculates the Shannon entropy of a given string to determine its randomness
func shannonEntropy(data string) float64 {
	if len(data) == 0 { return 0 }
	counts := make(map[rune]float64)
	for _, r := range data { counts[r]++ }
	var entropy float64
	length := float64(len(data))
	for _, count := range counts {
		px := count / length
		entropy -= px * math.Log2(px)
	}
	return entropy
}

// Parses an Unsigned Little Endian Base 128 integer from a byte slice
func readLEB128(data []byte) (uint32, int) {
	var result uint32
	var shift uint
	var bytesRead int
	for {
		if bytesRead >= len(data) { break }
		b := data[bytesRead]
		bytesRead++
		result |= uint32(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 { break }
	}
	return result, bytesRead
}

// Parses a Signed Little Endian Base 128 integer from a byte slice
func readSLEB128(data []byte) (int64, int) {
	var result int64
	var shift uint
	var bytesRead int
	var b byte
	for {
		if bytesRead >= len(data) { break }
		b = data[bytesRead]
		bytesRead++
		result |= (int64(b&0x7f) << shift)
		shift += 7
		if b&0x80 == 0 { break }
	}
	if (shift < 64) && (b&0x40 != 0) { result |= -(1 << shift) }
	return result, bytesRead
}

// Represents a distinct block of memory parsed from the wasm data sections
type DataSegment struct {
	MemoryOffset int64
	Data         []byte
}

// Holds an extracted string along with its corresponding memory offset
type ExtractedString struct {
	Text   string
	Offset int64
}

// Checks if a given memory address falls within the boundaries of known memory segments
func isAddressInSegments(addr int64, segments []DataSegment) bool {
	for _, seg := range segments {
		if addr >= seg.MemoryOffset && addr < seg.MemoryOffset+int64(len(seg.Data)) { return true }
	}
	return false
}

// Extracts printable strings from byte sequences and records their offsets
func extractPrintableWithOffset(data []byte, baseOffset int64, minLen int) []ExtractedString {
	var res []ExtractedString
	var current strings.Builder
	var startOffset int64 = -1

	for i, b := range data {
		r := rune(b)
		if r >= 32 && r <= 126 {
			if current.Len() == 0 { startOffset = baseOffset + int64(i) }
			current.WriteRune(r)
		} else {
			if current.Len() >= minLen {
				res = append(res, ExtractedString{Text: current.String(), Offset: startOffset})
			}
			current.Reset()
		}
	}
	if current.Len() >= minLen {
		res = append(res, ExtractedString{Text: current.String(), Offset: startOffset})
	}
	return res
}

// Pointer-Splitting Algorithm: Identifies all memory pointers and splits memory segments to uncover hidden strings
func parseWasmDataSections(filePath string, minLength int) ([]ExtractedString, []DataSegment, error) {
	data, err := os.ReadFile(filePath)
	if err != nil { return nil, nil, err }
	
	if len(data) < 8 || string(data[:4]) != "\x00asm" {
		return nil, nil, fmt.Errorf("not a valid wasm file")
	}

	var dataSegments []DataSegment
	var codePayload []byte

	offset := 8
	for offset < len(data) {
		secID := data[offset]
		offset++
		
		if offset >= len(data) { break }
		secLen, n := readLEB128(data[offset:])
		if n == 0 { break }
		offset += n
		end := offset + int(secLen)

		// Prevention mechanism against panics on corrupted or manually tampered wasm files
		if end > len(data) || end < offset {
			break
		}

		if secID == 10 {
			codePayload = data[offset:end]
		} else if secID == 11 {
			payload := data[offset:end]
			if len(payload) > 0 {
				count, n := readLEB128(payload)
				idx := n
				for j := 0; j < int(count); j++ {
					if idx >= len(payload) { break }
					tag, n := readLEB128(payload[idx:])
					idx += n

					if tag == 0 {
						if idx >= len(payload) { break }
						op := payload[idx]
						idx++
						var memOffset int64
						if op == 0x41 || op == 0x42 {
							if idx >= len(payload) { break }
							memOffset, n = readSLEB128(payload[idx:])
							idx += n
						}
						
						if idx < len(payload) && payload[idx] == 0x0B {
							idx++
							if idx >= len(payload) { break }
							size, n := readLEB128(payload[idx:])
							idx += n
							if idx+int(size) <= len(payload) {
								dataSegments = append(dataSegments, DataSegment{
									MemoryOffset: memOffset,
									Data:         payload[idx : idx+int(size)],
								})
							}
							idx += int(size)
						}
					} else if tag == 1 { // Passive Segment
						if idx >= len(payload) { break }
						size, n := readLEB128(payload[idx:])
						idx += n + int(size)
					} else if tag == 2 { // Memory Index Segment
						if idx >= len(payload) { break }
						_, n = readLEB128(payload[idx:])
						idx += n
						if idx >= len(payload) { break }
						op := payload[idx]
						idx++
						if op == 0x41 || op == 0x42 {
							if idx >= len(payload) { break }
							_, n = readSLEB128(payload[idx:])
							idx += n
						}
						if idx < len(payload) && payload[idx] == 0x0B {
							idx++
							if idx >= len(payload) { break }
							size, n := readLEB128(payload[idx:])
							idx += n + int(size)
						}
					}
				}
			}
		}
		offset = end
	}

	var pointers []int64

	// 1. Scan the Code Section for pointer instructions (e.g., i32.const, i64.const)
	if len(codePayload) > 5 {
		for i := 0; i < len(codePayload)-5; i++ {
			op := codePayload[i]
			if op == 0x41 { 
				val, n := readSLEB128(codePayload[i+1:])
				pointers = append(pointers, int64(uint32(val)))
				i += n
			} else if op == 0x42 {
				val, n := readSLEB128(codePayload[i+1:])
				pointers = append(pointers, val)
				i += n
			}
		}
	}

	// 2. Scan the Data Section to extract string headers (specifically handling Go-style memory layouts)
	for _, seg := range dataSegments {
		if len(seg.Data) < 16 { continue }
		for i := 0; i <= len(seg.Data)-16; i += 8 {
			addr := binary.LittleEndian.Uint64(seg.Data[i : i+8])
			length := binary.LittleEndian.Uint64(seg.Data[i+8 : i+16])
			
			if isAddressInSegments(int64(addr), dataSegments) && length > 1 && length < 5000 {
				pointers = append(pointers, int64(addr))
				pointers = append(pointers, int64(addr)+int64(length))
			}
		}
	}

	for _, seg := range dataSegments {
		pointers = append(pointers, seg.MemoryOffset)
		pointers = append(pointers, seg.MemoryOffset+int64(len(seg.Data)))
	}

	// Deduplicate and sort pointers to safely slice the memory later
	sort.Slice(pointers, func(i, j int) bool { return pointers[i] < pointers[j] })
	var uniquePointers []int64
	var last int64 = -1
	for _, p := range pointers {
		if p != last {
			uniquePointers = append(uniquePointers, p)
			last = p
		}
	}

	var stringsList []ExtractedString
	seen := make(map[string]bool)

	for _, seg := range dataSegments {
		var segPtrs []int64
		for _, p := range uniquePointers {
			if p >= seg.MemoryOffset && p <= seg.MemoryOffset+int64(len(seg.Data)) {
				segPtrs = append(segPtrs, p)
			}
		}

		// Iterate over sliced segments to extract clean strings
		for i := 0; i < len(segPtrs)-1; i++ {
			start := segPtrs[i] - seg.MemoryOffset
			end := segPtrs[i+1] - seg.MemoryOffset
			
			if end-start >= int64(minLength) && end <= int64(len(seg.Data)) {
				chunk := seg.Data[start:end]
				cleanStrings := extractPrintableWithOffset(chunk, seg.MemoryOffset+start, minLength)
				for _, s := range cleanStrings {
					if !seen[s.Text] {
						stringsList = append(stringsList, s)
						seen[s.Text] = true
					}
				}
			}
		}
	}

	return stringsList, dataSegments, nil
}

// Renders a visual memory hex dump to facilitate manual debugging and auditing
func printHexDump(segments []DataSegment, targetOffset int64, matchLen int) {
	fmt.Printf("\n[DEBUG MEMORY DUMP] Match found at Offset: %d (0x%X)\n", targetOffset, targetOffset)
	for _, seg := range segments {
		if targetOffset >= seg.MemoryOffset && targetOffset < seg.MemoryOffset+int64(len(seg.Data)) {
			localOffset := targetOffset - seg.MemoryOffset
			start := localOffset - 20
			if start < 0 { start = 0 }
			end := localOffset + int64(matchLen) + 20
			if end > int64(len(seg.Data)) { end = int64(len(seg.Data)) }

			fmt.Printf("Memory Segment Base: %d (0x%X)\n", seg.MemoryOffset, seg.MemoryOffset)
			fmt.Println("-------------------------------------------------------------------------")
			for i := start; i < end; i += 16 {
				fmt.Printf("0x%08X: ", seg.MemoryOffset+i)
				for j := int64(0); j < 16; j++ {
					if i+j < end {
						if i+j >= localOffset && i+j < localOffset+int64(matchLen) {
							fmt.Printf("[%02X]", seg.Data[i+j])
						} else {
							fmt.Printf(" %02X ", seg.Data[i+j])
						}
					} else {
						fmt.Print("    ")
					}
				}
				fmt.Print(" | ")
				for j := int64(0); j < 16; j++ {
					if i+j < end {
						c := seg.Data[i+j]
						if c >= 32 && c <= 126 { fmt.Printf("%c", c) } else { fmt.Print(".") }
					}
				}
				fmt.Println()
			}
			fmt.Println("-------------------------------------------------------------------------\n")
			return
		}
	}
}

// Marshals and writes the filtered findings securely to the output target
func processFindings(filename string, findings map[string][]string) {
	record := map[string]interface{}{
		"target_file": filename,
		"findings":    findings,
	}
	jsonData, err := json.Marshal(record)
	if err != nil { return }
	
	fileMutex.Lock()
	defer fileMutex.Unlock()
	
	if outputPath != "" {
		f, _ := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		f.Write(jsonData)
		f.WriteString("\n")
		f.Close()
	} else {
		fmt.Println(string(jsonData))
	}
}

// Concurrent worker handling individual file processing lifecycle
func worker(files <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for filePath := range files {
		rawStrings, segments, _ := parseWasmDataSections(filePath, 5)
		if len(rawStrings) == 0 { continue }
		
		findings := make(map[string]map[string]bool)

		// Regex matching loop across all extracted strings
		for _, item := range rawStrings {
			for category, regex := range patterns {
				matches := regex.FindAllStringSubmatch(item.Text, -1)
				for _, match := range matches {
					matchStr := match[0]
					if len(match) > 1 && match[1] != "" { matchStr = match[1] }
					matchStr = strings.Trim(matchStr, " '\"\n\r\t")
					lowerMatch := strings.ToLower(matchStr)

					isArtifact := false
					for _, artifactRegex := range compilerArtifactPatterns {
						if artifactRegex.MatchString(matchStr) { isArtifact = true; break }
					}
					if isArtifact { continue }

					if category == "Telegram Bot Token" && strings.Contains(lowerMatch, "rustc") { continue }
					if category == "URL/Form Parameters" {
						if len(matchStr) < 3 || jsPropertyPattern.MatchString(matchStr) { continue }
					}
					if threshold, exists := entropyThresholds[category]; exists && shannonEntropy(matchStr) < threshold { continue }
					
					if category == "IPv4 Address" {
						ip := net.ParseIP(matchStr)
						if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsMulticast() { continue }
						if strings.HasSuffix(matchStr, ".0") || strings.HasSuffix(matchStr, ".255") { continue }
						if strings.HasPrefix(matchStr, "8.0.") || strings.HasPrefix(matchStr, "9.0.") { continue }
					}

					if category == "Absolute URL" {
						isNoise := false
						for _, domain := range noisyDomains {
							if strings.Contains(lowerMatch, domain) { isNoise = true; break }
						}
						if isNoise { continue }
					}

					if category == "Relative API Endpoint" {
						isNoise := false
						for _, ext := range noisyExtensions {
							if strings.HasSuffix(lowerMatch, ext) || strings.Contains(lowerMatch, ext+"?") { isNoise = true; break }
						}
						for _, keyword := range noisyEndpointKeywords {
							if strings.Contains(lowerMatch, keyword) { isNoise = true; break }
						}
						if len(lowerMatch) < 6 || isNoise { continue }
					}

					if findings[category] == nil { findings[category] = make(map[string]bool) }
					findings[category][matchStr] = true

					// Output hex dump for matches when debug mode is enabled
					if debugMode {
						fmt.Printf("[!] FOUND: [%s] -> %s\n", category, matchStr)
						idxInStr := strings.Index(item.Text, matchStr)
						actualOffset := item.Offset + int64(idxInStr)
						printHexDump(segments, actualOffset, len(matchStr))
					}
				}
			}
		}

		// Aggregate and export results for the current file
		if len(findings) > 0 {
			cleanFindings := make(map[string][]string)
			for cat, items := range findings {
				for item := range items {
					cleanFindings[cat] = append(cleanFindings[cat], item)
				}
			}
			processFindings(filepath.Base(filePath), cleanFindings)
		}
	}
}

func main() {
	targetPtr := flag.String("i", "", "Target .wasm file or directory (Required)")
	outPtr := flag.String("o", "", "Output JSONL file (Optional)")
	workersPtr := flag.Int("w", 12, "Number of concurrent workers")
	debugPtr := flag.Bool("debug", false, "Enable hex dump and memory debugging")

	flag.Parse()
	debugMode = *debugPtr

	if *targetPtr == "" {
		fmt.Println("WASM-Hunter: Attack Surface Mapping for WebAssembly (Advanced String-Pointer Splitting)")
		flag.PrintDefaults()
		os.Exit(1)
	}
	outputPath = *outPtr

	if outputPath != "" {
		os.WriteFile(outputPath, []byte(""), 0644)
	}

	var filesToScan []string
	info, err := os.Stat(*targetPtr)
	if err != nil { os.Exit(1) }

	if info.IsDir() {
		filepath.WalkDir(*targetPtr, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".wasm") {
				filesToScan = append(filesToScan, path)
			}
			return nil
		})
	} else if strings.HasSuffix(strings.ToLower(info.Name()), ".wasm") {
		filesToScan = append(filesToScan, *targetPtr)
	}

	if len(filesToScan) == 0 {
		fmt.Println("[-] No .wasm files found.")
		os.Exit(0)
	}

	// Initialize worker pool for parallel processing
	filesChan := make(chan string, len(filesToScan))
	var wg sync.WaitGroup

	for i := 0; i < *workersPtr; i++ {
		wg.Add(1)
		go worker(filesChan, &wg)
	}
	for _, file := range filesToScan { filesChan <- file }
	close(filesChan)
	wg.Wait()
}
