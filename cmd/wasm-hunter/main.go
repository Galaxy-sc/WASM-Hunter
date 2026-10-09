package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Galaxy-sc/WASM-Hunter/internal/parser"
	"github.com/Galaxy-sc/WASM-Hunter/internal/reporter"
	"github.com/Galaxy-sc/WASM-Hunter/internal/scanner"
)

// Helper function to download WASM from a URL
func downloadWasm(targetUrl string) (string, string, error) {
	fmt.Printf("[*] Downloading WASM from URL: %s\n", targetUrl)
	resp, err := http.Get(targetUrl)
	if err != nil {
		return "", "", fmt.Errorf("failed to download: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	parsedUrl, err := url.Parse(targetUrl)
	var fileName string
	if err == nil {
		fileName = filepath.Base(parsedUrl.Path)
	}
	if !strings.HasSuffix(strings.ToLower(fileName), ".wasm") {
		fileName = "downloaded.wasm"
	}

	tmpDir, err := os.MkdirTemp("", "wasm-hunter-dl-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp dir: %v", err)
	}

	tmpFilePath := filepath.Join(tmpDir, fileName)
	tmpFile, err := os.Create(tmpFilePath)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("failed to save file: %v", err)
	}

	return tmpFilePath, tmpDir, nil
}

func main() {
	targetPtr := flag.String("i", "", "Target .wasm file, directory, URL, or .txt list of targets (Required)")
	outPtr := flag.String("o", "", "Output JSONL file (Optional)")
	workersPtr := flag.Int("w", 12, "Number of concurrent workers")
	debugPtr := flag.Bool("debug", false, "Enable hex dump and memory debugging")
	compilerOnlyPtr := flag.Bool("compiler", false, "Only identify and print the compiler used for the WASM file(s)")
	funcsOnlyPtr := flag.Bool("funcs-only", false, "Extract only function names (imports, exports, hidden) and skip secret scanning")

	flag.Parse()
	debugMode := *debugPtr
	compilerOnly := *compilerOnlyPtr
	funcsOnly := *funcsOnlyPtr
	target := *targetPtr
	outputPath := *outPtr

	if target == "" {
		fmt.Println("WASM-Hunter: Attack Surface Mapping for WebAssembly")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if outputPath != "" && !compilerOnly {
		os.WriteFile(outputPath, []byte(""), 0644)
	}

	var filesToScan []string
	var tempDirs []string

	defer func() {
		for _, dir := range tempDirs {
			os.RemoveAll(dir)
		}
	}()

	// 1. Check if target is a direct URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		tmpFilePath, tmpDir, err := downloadWasm(target)
		if err != nil {
			fmt.Printf("[-] %v\n", err)
			return
		}
		tempDirs = append(tempDirs, tmpDir)
		filesToScan = append(filesToScan, tmpFilePath)

	// 2. Check if target is a .txt file containing a list of URLs/paths
	} else if strings.HasSuffix(strings.ToLower(target), ".txt") {
		file, err := os.Open(target)
		if err != nil {
			fmt.Printf("[-] Failed to open list file: %v\n", err)
			return
		}
		defer file.Close()

		fmt.Printf("[*] Reading targets from list: %s\n", target)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Skip empty lines or comments starting with #
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				tmpFilePath, tmpDir, err := downloadWasm(line)
				if err != nil {
					fmt.Printf("[-] Skipping %s: %v\n", line, err)
					continue
				}
				tempDirs = append(tempDirs, tmpDir)
				filesToScan = append(filesToScan, tmpFilePath)
			} else {
				info, err := os.Stat(line)
				if err == nil && !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".wasm") {
					filesToScan = append(filesToScan, line)
				} else {
					fmt.Printf("[-] Skipping invalid local target in list: %s\n", line)
				}
			}
		}

	// 3. Existing local file/directory logic
	} else {
		info, err := os.Stat(target)
		if err != nil {
			fmt.Printf("[-] Target not found: %s\n", target)
			return
		}

		if info.IsDir() {
			filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".wasm") {
					filesToScan = append(filesToScan, path)
				}
				return nil
			})
		} else if strings.HasSuffix(strings.ToLower(info.Name()), ".wasm") {
			filesToScan = append(filesToScan, target)
		}
	}

	if len(filesToScan) == 0 {
		fmt.Println("[-] No valid .wasm targets found to scan.")
		return
	}

	// FAST PATH: If the flag is set, identify the compiler and output as standard JSONL
	if compilerOnly {
		for _, file := range filesToScan {
			data, err := os.ReadFile(file)
			if err == nil {
				compiler := parser.DetectCompiler(data)
				emptyFindings := make(map[string][]string)
				reporter.ProcessFindings(filepath.Base(file), emptyFindings, compiler, false, outputPath)
			}
		}
		return
	}

	filesChan := make(chan string, len(filesToScan))
	var wg sync.WaitGroup

	for i := 0; i < *workersPtr; i++ {
		wg.Add(1)
		go scanner.Worker(filesChan, &wg, debugMode, funcsOnly, outputPath)
	}
	for _, file := range filesToScan {
		filesChan <- file
	}
	close(filesChan)
	wg.Wait()
}