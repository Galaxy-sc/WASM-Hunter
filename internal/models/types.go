package models

// DataSegment represents a distinct block of memory parsed from the wasm data sections
type DataSegment struct {
	MemoryOffset int64
	Data         []byte
}

// ExtractedString holds an extracted string along with its corresponding memory offset
type ExtractedString struct {
	Text   string
	Offset int64
}