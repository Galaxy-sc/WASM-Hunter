package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"wasm-hunter/internal/scanner"
)

func main() {
	targetPtr := flag.String("i", "", "Target .wasm file or directory (Required)")
	outPtr := flag.String("o", "", "Output JSONL file (Optional)")
	workersPtr := flag.Int("w", 12, "Number of concurrent workers")
	debugPtr := flag.Bool("debug", false, "Enable hex dump and memory debugging")
	detectPtr := flag.Bool("detect", false, "Print the detected compiler language for the target WASM file(s)")

	flag.Parse()
	debugMode := *debugPtr
	detectMode := *detectPtr

	if *targetPtr == "" {
		fmt.Println("WASM-Hunter: Attack Surface Mapping for WebAssembly (Advanced String-Pointer Splitting)")
		flag.PrintDefaults()
		os.Exit(1)
	}
	outputPath := *outPtr

	if outputPath != "" {
		os.WriteFile(outputPath, []byte(""), 0644)
	}

	var filesToScan []string
	info, err := os.Stat(*targetPtr)
	if err != nil {
		os.Exit(1)
	}

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

	filesChan := make(chan string, len(filesToScan))
	var wg sync.WaitGroup

	for i := 0; i < *workersPtr; i++ {
		wg.Add(1)
		// Now we pass detectMode to the Worker
		go scanner.Worker(filesChan, &wg, debugMode, detectMode, outputPath)
	}
	for _, file := range filesToScan {
		filesChan <- file
	}
	close(filesChan)
	wg.Wait()
}