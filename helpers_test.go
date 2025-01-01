package httptunnel

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCheckSameOrigin(t *testing.T) {
	r := &http.Request{}
	r.Header = make(http.Header)
	if !checkSameOrigin(r) {
		t.Fatal("should return true for empty origin")
	}
	urlString := "http://test.com/a/b/c"
	r.Header.Set("Origin", urlString)
	u, err := url.Parse(urlString)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = u.Host
	if !checkSameOrigin(r) {
		t.Fatal("should return true for matching origin")
	}
	r.Header.Set("Origin", "http://not-test.com/c")
	if checkSameOrigin(r) {
		t.Fatal("should return false for mismatching origin")
	}
}

var equalASCIIFoldTests = []struct {
	t, s string
	eq   bool
}{
	{"Alpha", "alpha", true},
	{"bravo", "Bravo", true},
	{"Charlie", "charly", false},
	{"delta", "detla", false},
}

func TestEqualASCIIFold(t *testing.T) {
	for _, tt := range equalASCIIFoldTests {
		eq := equalASCIIFold(tt.s, tt.t)
		if eq != tt.eq {
			t.Errorf("equalASCIIFold(%q, %q) = %v, want %v", tt.s, tt.t, eq, tt.eq)
		}
	}
}
