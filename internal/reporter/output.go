package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/Galaxy-sc/WASM-Hunter/internal/models"
)

var fileMutex sync.Mutex

// PrintHexDump renders a visual memory hex dump to facilitate manual debugging and auditing
func PrintHexDump(segments []models.DataSegment, targetOffset int64, matchLen int) {
	fmt.Printf("\n[DEBUG MEMORY DUMP] Match found at Offset: %d (0x%X)\n", targetOffset, targetOffset)
	for _, seg := range segments {
		if targetOffset >= seg.MemoryOffset && targetOffset < seg.MemoryOffset+int64(len(seg.Data)) {
			localOffset := targetOffset - seg.MemoryOffset
			start := localOffset - 20
			if start < 0 {
				start = 0
			}
			end := localOffset + int64(matchLen) + 20
			if end > int64(len(seg.Data)) {
				end = int64(len(seg.Data))
			}

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
						if c >= 32 && c <= 126 {
							fmt.Printf("%c", c)
						} else {
							fmt.Print(".")
						}
					}
				}
				fmt.Println()
			}
			fmt.Println("-------------------------------------------------------------------------\n")
			return
		}
	}
}

// ProcessFindings marshals and writes the filtered findings securely to the output target
func ProcessFindings(filename string, findings map[string][]string, compiler string, detectMode bool, outputPath string) {
	record := map[string]interface{}{
		"target_file": filename,
		"compiler":    compiler,
		"findings":    findings,
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		return
	}

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