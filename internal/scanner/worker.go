package scanner

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Galaxy-sc/WASM-Hunter/internal/config"
	"github.com/Galaxy-sc/WASM-Hunter/internal/parser"
	"github.com/Galaxy-sc/WASM-Hunter/internal/reporter"
	"github.com/Galaxy-sc/WASM-Hunter/internal/utils"
)

// Worker handles concurrent individual file processing lifecycle
func Worker(files <-chan string, wg *sync.WaitGroup, debugMode bool, outputPath string) {
	defer wg.Done()
	for filePath := range files {
		rawStrings, segments, compiler, _ := parser.ParseWasmDataSections(filePath, 5)

		if len(rawStrings) == 0 {
			reporter.ProcessFindings(filepath.Base(filePath), make(map[string][]string), compiler, false, outputPath)
			continue
		}

		findings := make(map[string]map[string]bool)

		// Extract hidden Go functions if the compiler is detected as Go
		if compiler == "Go" {
			hiddenFuncs := parser.ExtractGoFunctions(rawStrings)
			if len(hiddenFuncs) > 0 {
				findings["Go Hidden Functions"] = make(map[string]bool)
				for _, fn := range hiddenFuncs {
					findings["Go Hidden Functions"][fn] = true
				}
			}
		} else {
			// Extract Standard Imports/Exports for Rust, C/C++, Zig, AssemblyScript, etc.
			stdSymbols, err := parser.ExtractStandardWasmFunctions(filePath)
			if err == nil {
				if len(stdSymbols.Exports) > 0 {
					findings["Wasm Exported Functions"] = make(map[string]bool)
					for _, fn := range stdSymbols.Exports {
						findings["Wasm Exported Functions"][fn] = true
					}
				}
				if len(stdSymbols.Imports) > 0 {
					findings["Wasm Imported Functions"] = make(map[string]bool)
					for _, fn := range stdSymbols.Imports {
						findings["Wasm Imported Functions"][fn] = true
					}
				}
			}
		}

		// Regex matching loop across all extracted strings
		for _, item := range rawStrings {
			for category, regex := range config.Patterns {
				matches := regex.FindAllStringSubmatch(item.Text, -1)
				for _, match := range matches {
					matchStr := match[0]
					if len(match) > 1 && match[1] != "" {
						matchStr = match[1]
					}
					matchStr = strings.Trim(matchStr, " '\"\n\r\t")
					lowerMatch := strings.ToLower(matchStr)

					isArtifact := false
					for _, artifactRegex := range config.CompilerArtifactPatterns {
						if artifactRegex.MatchString(matchStr) {
							isArtifact = true
							break
						}
					}
					if isArtifact {
						continue
					}

					if category == "Telegram Bot Token" && strings.Contains(lowerMatch, "rustc") {
						continue
					}
					if category == "URL/Form Parameters" {
						if len(matchStr) < 3 || config.JsPropertyPattern.MatchString(matchStr) {
							continue
						}
					}
					if threshold, exists := config.EntropyThresholds[category]; exists && utils.ShannonEntropy(matchStr) < threshold {
						continue
					}

					if category == "IPv4 Address" {
						ip := net.ParseIP(matchStr)
						if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsMulticast() {
							continue
						}
						if strings.HasSuffix(matchStr, ".0") || strings.HasSuffix(matchStr, ".255") {
							continue
						}
						if strings.HasPrefix(matchStr, "8.0.") || strings.HasPrefix(matchStr, "9.0.") {
							continue
						}
					}

					if category == "Absolute URL" {
						isNoise := false
						for _, domain := range config.NoisyDomains {
							if strings.Contains(lowerMatch, domain) {
								isNoise = true
								break
							}
						}
						if isNoise {
							continue
						}
					}

					if category == "Relative API Endpoint" {
						isNoise := false
						for _, ext := range config.NoisyExtensions {
							if strings.HasSuffix(lowerMatch, ext) || strings.Contains(lowerMatch, ext+"?") {
								isNoise = true
								break
							}
						}
						for _, keyword := range config.NoisyEndpointKeywords {
							if strings.Contains(lowerMatch, keyword) {
								isNoise = true
								break
							}
						}
						if len(lowerMatch) < 6 || isNoise {
							continue
						}
					}

					if findings[category] == nil {
						findings[category] = make(map[string]bool)
					}
					findings[category][matchStr] = true

					// Output hex dump for matches when debug mode is enabled
					if debugMode {
						fmt.Printf("[!] FOUND: [%s] -> %s\n", category, matchStr)
						idxInStr := strings.Index(item.Text, matchStr)
						actualOffset := item.Offset + int64(idxInStr)
						reporter.PrintHexDump(segments, actualOffset, len(matchStr))
					}
				}
			}
		}

		cleanFindings := make(map[string][]string)
		for cat, items := range findings {
			for item := range items {
				cleanFindings[cat] = append(cleanFindings[cat], item)
			}
		}

		reporter.ProcessFindings(filepath.Base(filePath), cleanFindings, compiler, false, outputPath)
	}
}