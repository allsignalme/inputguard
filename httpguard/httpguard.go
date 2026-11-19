// Package httpguard runs an inputguard.Guard on incoming HTTP requests: the JSON body, and optionally query
// parameters and selected headers.
//
// A body is treated as JSON when its Content-Type says so or when it starts (after whitespace) with { or [:
// handlers decode JSON whatever the header says. A JSON body that does not parse is answered with 400 (a decoder
// that reads only the first value would otherwise see what the guard could not). Clean mode replaces the body (and
// query) with the cleaned version before the handler reads it; a rejected request gets a 400 response listing the
// rules and fields, never the values.
package httpguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/allsignalme/inputguard"
)

// Config configures Middleware.
type Config struct {
	// Guard inspects the request. Required.
	Guard *inputguard.Guard
	// MaxBodyBytes: a larger JSON body is answered with 413 without being read further (a larger body that is not
	// JSON passes untouched). 0 means 1 MiB; a negative value means no limit.
	MaxBodyBytes int64
	// Query: also inspect URL query parameters, each classified by its name.
	Query bool
	// Headers: request headers to inspect, in the header context (CR/LF, control characters, markup).
	Headers []string
	// Skip: requests for which it returns true are passed through untouched (health checks, uploads…).
	Skip func(r *http.Request) bool
	// OnReport is called for every request with findings, including cleaned ones. The report never holds values.
	OnReport func(r *http.Request, rep inputguard.Report)
	// OnReject writes the response for a rejected request. Default: WriteRejection.
	OnReject func(w http.ResponseWriter, r *http.Request, rep inputguard.Report)
}

const defaultMaxBody = 1 << 20

// Middleware returns the guard as net/http middleware.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	if cfg.Guard == nil {
		panic("httpguard: Config.Guard is nil")
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = defaultMaxBody
	}
	if cfg.OnReject == nil {
		cfg.OnReject = WriteRejection
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Skip != nil && cfg.Skip(r) {
				next.ServeHTTP(w, r)
				return
			}
			var all inputguard.Report
			if len(cfg.Headers) > 0 {
				merge(&all, cfg.headers(r))
			}
			if cfg.Query && r.URL.RawQuery != "" {
				merge(&all, cfg.query(r))
			}
			if r.Body != nil && r.Body != http.NoBody {
				rep, status := cfg.body(r)
				switch status {
				case 0:
				case http.StatusBadRequest:
					writeError(w, "invalid_json", "request body is not valid JSON")
					return
				default:
					http.Error(w, http.StatusText(status), status)
					return
				}
				merge(&all, rep)
			}
			if len(all.Findings) > 0 || all.LimitExceeded {
				if cfg.OnReport != nil {
					cfg.OnReport(r, all)
				}
			}
			if all.Rejected {
				cfg.OnReject(w, r, all)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// body processes the body when it is JSON. A non-zero status means the request must be answered with it.
func (cfg Config) body(r *http.Request) (inputguard.Report, int) {
	orig := r.Body
	var reader io.Reader = orig
	if cfg.MaxBodyBytes > 0 {
		reader = io.LimitReader(orig, cfg.MaxBodyBytes+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		_ = orig.Close()
		return inputguard.Report{}, http.StatusRequestEntityTooLarge
	}
	declared, looks := declaredJSON(r), looksLikeJSON(data)
	if cfg.MaxBodyBytes > 0 && int64(len(data)) > cfg.MaxBodyBytes {
		if declared || looks || onlySpace(data) {
			_ = orig.Close()
			return inputguard.Report{}, http.StatusRequestEntityTooLarge
		}
		// Not JSON (an upload…): hand the handler what was read and the rest.
		r.Body = readCloser{io.MultiReader(bytes.NewReader(data), orig), orig}
		return inputguard.Report{}, 0
	}
	_ = orig.Close()
	if (declared || looks) && !onlySpace(data) {
		out, rep := cfg.Guard.ProcessJSON(data)
		if rep.InvalidJSON {
			return rep, http.StatusBadRequest
		}
		if rep.Changed {
			data = out
		}
		defer setBody(r, data)
		return rep, 0
	}
	setBody(r, data)
	return inputguard.Report{}, 0
}

func setBody(r *http.Request, data []byte) {
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
	r.Header.Set("Content-Length", strconv.Itoa(len(data)))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
}

type readCloser struct {
	io.Reader
	io.Closer
}

// looksLikeJSON: the first non-whitespace byte opens an object or array.
func looksLikeJSON(b []byte) bool {
	t := bytes.TrimLeft(b, " \t\r\n")
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

func onlySpace(b []byte) bool { return len(bytes.TrimLeft(b, " \t\r\n")) == 0 }

func (cfg Config) query(r *http.Request) inputguard.Report {
	// ParseQuery skips the pairs it cannot parse but returns the others; handlers see the same pairs.
	values, _ := url.ParseQuery(r.URL.RawQuery)
	var all inputguard.Report
	changed := false
	for name, vs := range values {
		for i, v := range vs {
			out, rep := cfg.Guard.ProcessField(name, v)
			prefix(&rep, "query."+safeName(name))
			merge(&all, rep)
			if rep.Changed {
				vs[i], changed = out, true
			}
		}
	}
	if changed && !all.Rejected {
		r.URL.RawQuery = values.Encode()
		r.RequestURI = r.URL.RequestURI()
	}
	return all
}

func (cfg Config) headers(r *http.Request) inputguard.Report {
	var all inputguard.Report
	for _, name := range cfg.Headers {
		vs := r.Header.Values(name)
		for i, v := range vs {
			out, rep := cfg.Guard.ProcessString(v, inputguard.CtxHeader)
			prefix(&rep, "header."+http.CanonicalHeaderKey(name))
			merge(&all, rep)
			if rep.Changed && !rep.Rejected {
				vs[i] = out
			}
		}
	}
	return all
}

func declaredJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// merge appends src's findings and flags to dst.
func merge(dst *inputguard.Report, src inputguard.Report) {
	dst.Findings = append(dst.Findings, src.Findings...)
	dst.Changed = dst.Changed || src.Changed
	dst.Rejected = dst.Rejected || src.Rejected
	dst.Truncated = dst.Truncated || src.Truncated
	dst.InvalidJSON = dst.InvalidJSON || src.InvalidJSON
	dst.LimitExceeded = dst.LimitExceeded || src.LimitExceeded
}

func prefix(rep *inputguard.Report, p string) {
	for i := range rep.Findings {
		if rep.Findings[i].Path == "" {
			rep.Findings[i].Path = p
		} else {
			rep.Findings[i].Path = p + "." + rep.Findings[i].Path
		}
	}
}

// safeName: a parameter name as it may appear in a path (names that could carry a payload become "[key]").
func safeName(n string) string {
	if p := inputguard.FormatPath([]inputguard.PathSeg{{Key: n, Index: -1}}); p != "" {
		return p
	}
	return "[key]"
}

// Rejection is the JSON body WriteRejection sends.
type Rejection struct {
	Error RejectionError `json:"error"`
}

// RejectionError describes a rejected request.
type RejectionError struct {
	Code    string           `json:"code"`
	Message string           `json:"message"`
	Fields  []RejectionField `json:"fields,omitempty"`
}

// RejectionField is one rejected field.
type RejectionField struct {
	Path string `json:"path"`
	Rule string `json:"rule"`
}

// WriteRejection answers 400 with a JSON body naming the rejected rules and fields, never the values.
func WriteRejection(w http.ResponseWriter, _ *http.Request, rep inputguard.Report) {
	body := Rejection{Error: RejectionError{Code: "input_rejected", Message: "input rejected"}}
	var rejected *inputguard.RejectedError
	if err := rep.Err(); errors.As(err, &rejected) {
		body.Error.Message = err.Error()
	}
	for _, f := range rep.Findings {
		if f.Action == inputguard.ActionReject {
			body.Error.Fields = append(body.Error.Fields, RejectionField{Path: f.Path, Rule: string(f.Rule)})
		}
	}
	writeJSON(w, body)
}

func writeError(w http.ResponseWriter, code, message string) {
	writeJSON(w, Rejection{Error: RejectionError{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, body Rejection) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(body)
}
