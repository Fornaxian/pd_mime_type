package pdmimetype

import (
	"net/http"
	"unicode/utf8"
)

type typeMatcher interface {
	match(header []byte) (fileType string)
}

var types = []typeMatcher{
	// 12 bytes
	masked{[]byte("\x00\x00\x00\x00ftypMSNV"), []byte("000011111111"), "video/mp4"},
	masked{[]byte("\x00\x00\x00\x00ftypisom"), []byte("000011111111"), "video/mp4"},

	// 6 bytes
	exact{[]byte("\x37\x7A\xBC\xAF\x27\x1C"), "application/7z-compressed"},

	// 5 bytes

	// 4 bytes
	exact{[]byte("fLaC"), "audio/flac"},
	exact{[]byte("OggS"), "application/ogg"},

	// 3 bytes
	exact{[]byte("\x49\x44\x33"), "audio/mp3"},

	// 2 bytes
	exact{[]byte("\xFF\xFB"), "audio/mp3"},
}

// ContentType detects the content type of a file
func ContentType(buf []byte) (mimeType string) {
	// Manual magic byte detection
	if mimeType == "application/octet-stream" || mimeType == "" {
		for _, v := range types {
			if mimeType = v.match(buf); mimeType != "" {
				return mimeType
			}
		}
	}

	// First we try the mime type detection from the http package
	mimeType = http.DetectContentType(buf)

	// If that doesn't work we check if the mime type is valid UTF-8
	if mimeType == "application/octet-stream" || mimeType == "" {
		if utf8.Valid(buf) {
			mimeType = "text/plain; charset=utf-8"
		}
	}

	// Mime type is still unknown, we fall back to the default type
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	return mimeType
}

type exact struct {
	sig []byte
	typ string
}

func (e exact) match(head []byte) (contentType string) {
	if string(e.sig) == string(head[:len(e.sig)]) {
		return e.typ
	}
	return ""
}

type masked struct {
	sig  []byte
	mask []byte
	typ  string
}

func (e masked) match(head []byte) (contentType string) {
	if len(head) < len(e.sig) {
		return ""
	}
	for i, v := range e.mask {
		// If the mask is high and the bytes don't match the test fails
		if v == '1' && e.sig[i] != head[i] {
			return ""
		}
	}
	return e.typ
}

