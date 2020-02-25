package vegeta

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
	"github.com/valyala/fasthttp"
)

// Target is an HTTP request blueprint.
//
//go:generate go run ../internal/cmd/jsonschema/main.go -type=Target -output=target.schema.json
type Target struct {
	Method string                 `json:"method"`
	URL    string                 `json:"url"`
	Body   []byte                 `json:"body,omitempty"`
	Header fasthttp.RequestHeader `json:"header,omitempty"`
}

// Request creates an *http.Request out of Target and returns it along with an
// error in case of failure.
func (t *Target) Request() (*fasthttp.Request, error) {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(t.URL)
	req.Header.SetMethod(t.Method)
	req.SetBody(t.Body)
	t.Header.CopyTo(&req.Header)
	if host := req.Header.Host(); len(host) != 0 {
		req.SetHostBytes(host)
	}
	return req, nil
}

// Equal returns true if the target is equal to the other given target.
func (t *Target) Equal(other *Target) bool {
	switch {
	case t == other:
		return true
	case t == nil || other == nil:
		return false
	default:
		equal := t.Method == other.Method &&
			t.URL == other.URL &&
			bytes.Equal(t.Body, other.Body) &&
			t.Header.Len() == other.Header.Len()

		if !equal {
			return false
		}

		t.Header.VisitAll(func(k, left []byte) {
			right := t.Header.PeekBytes(k)
			if len(left) != len(right) {
				equal = false
				return
			}
			if bytes.Equal(left, right) != true {
				equal = false
				return
			}
		})

		return true
	}
}

var (
	// ErrNoTargets is returned when not enough Targets are available.
	ErrNoTargets = errors.New("no targets to attack")
	// ErrNilTarget is returned when the passed Target pointer is nil.
	ErrNilTarget = errors.New("nil target")
	// ErrNoMethod is returned by JSONTargeter when a parsed Target has
	// no method.
	ErrNoMethod = errors.New("target: required method is missing")
	// ErrNoURL is returned by JSONTargeter when a parsed Target has no
	// URL.
	ErrNoURL = errors.New("target: required url is missing")
	// TargetFormats contains the canonical list of the valid target
	// format identifiers.
	TargetFormats = []string{HTTPTargetFormat, JSONTargetFormat}
)

const (
	// HTTPTargetFormat is the human readable identifier for the HTTP target format.
	HTTPTargetFormat = "http"
	// JSONTargetFormat is the human readable identifier for the JSON target format.
	JSONTargetFormat = "json"
)

// A Targeter decodes a Target or returns an error in case of failure.
// Implementations must be safe for concurrent use.
type Targeter func(*Target) error

// Decode is a convenience method that calls the underlying Targeter function.
func (tr Targeter) Decode(t *Target) error {
	return tr(t)
}

// NewJSONTargeter returns a new targeter that decodes one Target from the
// given io.Reader on every invocation. Each target is one JSON object in its own line.
//
// The method and url fields are required. If present, the body field must be base64 encoded.
// The generated [JSON Schema](lib/target.schema.json) defines the format in detail.
//
//    {"method":"POST", "url":"https://goku/1", "header":{"Content-Type":["text/plain"], "body": "Rk9P"}
//    {"method":"GET",  "url":"https://goku/2"}
//
// body will be set as the Target's body if no body is provided in each target definiton.
// hdr will be merged with the each Target's headers.
//
func NewJSONTargeter(src io.Reader, body []byte, header *fasthttp.RequestHeader) Targeter {
	type reader struct {
		*bufio.Reader
		sync.Mutex
	}
	rd := reader{Reader: bufio.NewReader(src)}

	return func(tgt *Target) (err error) {
		if tgt == nil {
			return ErrNilTarget
		}

		var jl jlexer.Lexer

		rd.Lock()
		for len(jl.Data) == 0 {
			if jl.Data, err = rd.ReadBytes('\n'); err != nil {
				break
			}
			jl.Data = bytes.TrimSpace(jl.Data) // Skip empty lines
		}
		rd.Unlock()

		if err != nil {
			if err == io.EOF {
				err = ErrNoTargets
			}
			return err
		}

		var t jsonTarget
		t.decode(&jl)

		if err = jl.Error(); err != nil {
			return err
		} else if t.Method == "" {
			return ErrNoMethod
		} else if t.URL == "" {
			return ErrNoURL
		}

		tgt.Method = t.Method
		tgt.URL = t.URL
		if tgt.Body = body; len(t.Body) > 0 {
			tgt.Body = t.Body
		}

		header.VisitAll(func(k, v []byte) {
			tgt.Header.AddBytesKV(k, v)
		})

		t.Header.VisitAll(func(k, v []byte) {
			tgt.Header.AddBytesKV(k, v)
		})

		return nil
	}
}

// A TargetEncoder encodes a Target in a format that can be read by a Targeter.
type TargetEncoder func(*Target) error

// Encode is a convenience method that calls the underlying TargetEncoder function.
func (enc TargetEncoder) Encode(t *Target) error {
	return enc(t)
}

// NewJSONTargetEncoder returns a TargetEncoder that encods Targets in the JSON format.
func NewJSONTargetEncoder(w io.Writer) TargetEncoder {
	var jw jwriter.Writer
	return func(t *Target) error {
		(*jsonTarget)(t).encode(&jw)
		if jw.Error != nil {
			return jw.Error
		}
		jw.RawByte('\n')
		_, err := jw.DumpTo(w)
		return err
	}
}

// NewStaticTargeter returns a Targeter which round-robins over the passed
// Targets.
func NewStaticTargeter(tgts ...Target) Targeter {
	i := int64(-1)
	return func(tgt *Target) error {
		if tgt == nil {
			return ErrNilTarget
		}
		*tgt = tgts[atomic.AddInt64(&i, 1)%int64(len(tgts))]
		return nil
	}
}

// ReadAllTargets eagerly reads all Targets out of the provided Targeter.
func ReadAllTargets(t Targeter) (tgts []Target, err error) {
	for {
		var tgt Target
		if err = t(&tgt); err == ErrNoTargets {
			break
		} else if err != nil {
			return nil, err
		}
		tgts = append(tgts, tgt)
	}

	if len(tgts) == 0 {
		return nil, ErrNoTargets
	}

	return tgts, nil
}

// NewHTTPTargeter returns a new Targeter that decodes one Target from the
// given io.Reader on every invocation. The format is as follows:
//
//    GET https://foo.bar/a/b/c
//    Header-X: 123
//    Header-Y: 321
//    @/path/to/body/file
//
//    POST https://foo.bar/b/c/a
//    Header-X: 123
//
// body will be set as the Target's body if no body is provided.
// hdr will be merged with the each Target's headers.
func NewHTTPTargeter(src io.Reader, body []byte, hdr *fasthttp.RequestHeader) Targeter {
	var mu sync.Mutex
	sc := peekingScanner{src: bufio.NewScanner(src)}
	return func(tgt *Target) (err error) {
		mu.Lock()
		defer mu.Unlock()

		if tgt == nil {
			return ErrNilTarget
		}

		var line string
		for {
			if !sc.Scan() {
				return ErrNoTargets
			}
			line = strings.TrimSpace(sc.Text())

			if len(line) != 0 && line[0] != '#' {
				break
			}
		}

		tgt.Body = body
		tgt.Header = fasthttp.RequestHeader{}
		hdr.CopyTo(&tgt.Header)

		tokens := strings.SplitN(line, " ", 2)
		if len(tokens) < 2 {
			return fmt.Errorf("bad target: %s", line)
		}
		if !startsWithHTTPMethod(line) {
			return fmt.Errorf("bad method: %s", tokens[0])
		}
		tgt.Method = tokens[0]
		if _, err = url.ParseRequestURI(tokens[1]); err != nil {
			return fmt.Errorf("bad URL: %s", tokens[1])
		}
		tgt.URL = tokens[1]
		line = strings.TrimSpace(sc.Peek())
		if line == "" || startsWithHTTPMethod(line) {
			return nil
		}
		for sc.Scan() {
			if line = strings.TrimSpace(sc.Text()); line == "" {
				break
			} else if strings.HasPrefix(line, "#") {
				continue
			} else if strings.HasPrefix(line, "@") {
				if tgt.Body, err = ioutil.ReadFile(line[1:]); err != nil {
					return fmt.Errorf("bad body: %s", err)
				}
				break
			}
			tokens = strings.SplitN(line, ":", 2)
			if len(tokens) < 2 {
				return fmt.Errorf("bad header: %s", line)
			}
			for i := range tokens {
				if tokens[i] = strings.TrimSpace(tokens[i]); tokens[i] == "" {
					return fmt.Errorf("bad header: %s", line)
				}
			}
			// Add key/value directly to the http.Header (map[string][]string).
			// http.Header.Add() canonicalizes keys but vegeta is used
			// to test systems that require case-sensitive headers.
			// tgt.Header[tokens[0]] = append(tgt.Header[tokens[0]], tokens[1])
		}
		if err = sc.Err(); err != nil {
			return ErrNoTargets
		}
		return nil
	}
}

var httpMethodChecker = regexp.MustCompile(`^[A-Z]+\s`)

// A line starts with an http method when the first word is uppercase ascii
// followed by a space.
func startsWithHTTPMethod(t string) bool {
	return httpMethodChecker.MatchString(t)
}

// Wrap a Scanner so we can cheat and look at the next value and react accordingly,
// but still have it be around the next time we Scan() + Text()
type peekingScanner struct {
	src    *bufio.Scanner
	peeked string
}

func (s *peekingScanner) Err() error {
	return s.src.Err()
}

func (s *peekingScanner) Peek() string {
	if !s.src.Scan() {
		return ""
	}
	s.peeked = s.src.Text()
	return s.peeked
}

func (s *peekingScanner) Scan() bool {
	if s.peeked == "" {
		return s.src.Scan()
	}
	return true
}

func (s *peekingScanner) Text() string {
	if s.peeked == "" {
		return s.src.Text()
	}
	t := s.peeked
	s.peeked = ""
	return t
}
