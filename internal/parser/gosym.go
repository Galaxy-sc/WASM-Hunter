package parser

import (
	"regexp"
	"strings"

	"github.com/Galaxy-sc/WASM-Hunter/internal/models"
)

// goFuncRegex matches standard Go function and method signatures (e.g., pkg/path.funcName or pkg.(*Type).funcName)
var goFuncRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\./]+\.(?:\(\*[a-zA-Z0-9_\-\.]+\)\.)?[a-zA-Z0-9_]+$`)

// stdLibPrefixes contains core Go standard library packages to filter out runtime noise
var stdLibPrefixes = []string{
	"runtime", "sync", "math", "reflect", "os", "fmt", "crypto", "net",
	"encoding", "unicode", "strconv", "syscall", "internal", "strings", 
	"bytes", "io", "bufio", "path", "mime", "log", "context", "errors", 
	"hash", "compress", "sort", "regexp", "time", "database", "archive", 
	"flag", "testing", "unsafe", "slices", "maps", "weak", "unique", 
	"iter", "cmp", "plugin", "arena", "html", "image", "synctest",
}

// noiseKeywords catches truncated internal paths, vendor libraries, and obfuscated runtime variables
var noiseKeywords = []string{
	"vendor/", "golang.org/", "mSpan", "cTrigger", "markBits", 
	"go.shape", "go1.", "Value.", "HTTP/", "ternal/", "al/", "nal/", 
	"untime", "ntime", "me.", "e.", "i.", "jL.", "wRo.", "7ik.", "LG.", "_.", "ason.",
	"mheap", "ps/", "l/runtime", "MapIter", "mspan", "eq.", "ime.",
}

// ExtractGoFunctions extracts Go function names using heuristics directly from the pre-extracted raw strings
func ExtractGoFunctions(rawStrings []models.ExtractedString) []string {
	var funcNames []string
	seen := make(map[string]bool)

	for _, item := range rawStrings {
		text := item.Text

		// Fast fail for strings without a dot, containing spaces/newlines, or overly long tokens
		if !strings.Contains(text, ".") || strings.ContainsAny(text, " \n\t\r") || len(text) > 75 {
			continue
		}

		if goFuncRegex.MatchString(text) {
			if isFalsePositive(text) {
				continue
			}

			if isStandardGoPackage(text) {
				continue
			}

			// Filter compiler-generated type metadata and special directives
			if strings.HasPrefix(text, "type.") || strings.HasPrefix(text, "go:") {
				continue
			}

			if !seen[text] {
				funcNames = append(funcNames, text)
				seen[text] = true
			}
		}
	}
	return funcNames
}

// isFalsePositive prevents URLs, files, tokens, and common text endpoints from being flagged as Go functions
func isFalsePositive(s string) bool {
	lower := strings.ToLower(s)
	exts := []string{".com", ".net", ".org", ".io", ".js", ".html", ".css", ".wasm", ".json", ".xml", ".txt", ".md", ".go", ".png", ".types"}
	
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "www.") {
		return true
	}

	// Filter out absolute file paths (e.g., /etc/mime.types) or truncated memory pointers starting with /
	if strings.HasPrefix(s, "/") {
		return true
	}

	// Filter potential tokens by checking if the package name segment is unusually long
	dotIdx := strings.Index(s, ".")
	if dotIdx > 20 && !strings.Contains(s[:dotIdx], "/") {
		return true
	}
	
	return false
}

// isStandardGoPackage checks if the extracted string belongs to a default Go library or known noise
func isStandardGoPackage(name string) bool {
	for _, noise := range noiseKeywords {
		if strings.HasPrefix(name, noise) || strings.Contains(name, "/"+noise) {
			return true
		}
	}

	for _, prefix := range stdLibPrefixes {
		if strings.HasPrefix(name, prefix+".") || strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	
	return false
}