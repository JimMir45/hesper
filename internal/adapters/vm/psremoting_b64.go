package vm

import (
	"encoding/base64"
	"encoding/binary"
	"unicode/utf16"
)

// base64UTF16 encodes s the way PowerShell -EncodedCommand expects:
// UTF-16LE bytes, base64-wrapped.
func base64UTF16(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func base64Std(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBase64Std(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
