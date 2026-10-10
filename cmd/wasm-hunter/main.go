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

func downloadWasm(targetUrl string, verbose bool) (string, string, error) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[*] Downloading WASM from URL: %s\n", targetUrl)
	}
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
	compilerOnlyPtr := flag.Bool("compiler", false, "Include the compiler used for the WASM file(s) in output")
	funcsOnlyPtr := flag.Bool("funcs-only", false, "Include function names (imports, exports, hidden) in output")
	dataOnlyPtr := flag.Bool("data-only", false, "Include secrets, IPs, and URLs in output")
	verbosePtr := flag.Bool("v", false, "Verbose mode: print progress and informational logs")

	flag.Parse()
	debugMode := *debugPtr
	compFlag := *compilerOnlyPtr
	funcsFlag := *funcsOnlyPtr
	dataFlag := *dataOnlyPtr
	verbose := *verbosePtr
	target := *targetPtr
	outputPath := *outPtr

	if target == "" {
		fmt.Fprintf(os.Stderr, "WASM-Hunter: Attack Surface Mapping for WebAssembly\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if outputPath != "" && !(compFlag && !funcsFlag && !dataFlag) {
		os.WriteFile(outputPath, []byte(""), 0644)
	}

	var filesToScan []string
	var tempDirs []string

	defer func() {
		for _, dir := range tempDirs {
			os.RemoveAll(dir)
		}
	}()

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		tmpFilePath, tmpDir, err := downloadWasm(target, verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			return
		}
		tempDirs = append(tempDirs, tmpDir)
		filesToScan = append(filesToScan, tmpFilePath)
	} else if strings.HasSuffix(strings.ToLower(target), ".txt") {
		file, err := os.Open(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open list file: %v\n", err)
			return
		}
		defer file.Close()

		if verbose {
			fmt.Fprintf(os.Stderr, "[*] Reading targets from list: %s\n", target)
		}
		
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") { continue }

			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				tmpFilePath, tmpDir, err := downloadWasm(line, verbose)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[-] Skipping %s: %v\n", line, err)
					continue
				}
				tempDirs = append(tempDirs, tmpDir)
				filesToScan = append(filesToScan, tmpFilePath)
			} else {
				info, err := os.Stat(line)
				if err == nil && !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".wasm") {
					filesToScan = append(filesToScan, line)
				} else {
					fmt.Fprintf(os.Stderr, "[-] Skipping invalid local target in list: %s\n", line)
				}
			}
		}
	} else {
		info, err := os.Stat(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Target not found: %s\n", target)
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
		fmt.Fprintf(os.Stderr, "[-] No valid .wasm targets found to scan.\n")
		return
	}

	if compFlag && !funcsFlag && !dataFlag {
		for _, file := range filesToScan {
			data, err := os.ReadFile(file)
			if err == nil {
				compiler := parser.DetectCompiler(data)
				reporter.ProcessFindings(filepath.Base(file), nil, nil, compiler, compFlag, funcsFlag, dataFlag, outputPath)
			}
		}
		return
	}

	filesChan := make(chan string, len(filesToScan))
	var wg sync.WaitGroup

	for i := 0; i < *workersPtr; i++ {
		wg.Add(1)
		go scanner.Worker(filesChan, &wg, debugMode, compFlag, funcsFlag, dataFlag, outputPath)
	}
	for _, file := range filesToScan {
		filesChan <- file
	}
	close(filesChan)
	wg.Wait()
}