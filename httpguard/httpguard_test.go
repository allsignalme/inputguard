package httpguard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/allsignalme/inputguard"
)

type seen struct {
	body   string
	query  string
	header string
	called bool
}

func echo(s *seen) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.body, s.query, s.header, s.called = string(b), r.URL.RawQuery, r.Header.Get("User-Agent"), true
		if r.ContentLength != int64(len(b)) {
			http.Error(w, "content length", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func do(t *testing.T, h http.Handler, method, target, ctype, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCleanBody(t *testing.T) {
	var s seen
	var reports []inputguard.Report
	h := Middleware(Config{
		Guard:    inputguard.MustNew(),
		OnReport: func(_ *http.Request, r inputguard.Report) { reports = append(reports, r) },
	})(echo(&s))
	rec := do(t, h, "POST", "/e", "application/json; charset=utf-8", `{"name":"ok <script>x</script>","n":1}`, nil)
	if rec.Code != 204 || s.body != `{"name":"ok","n":1}` || len(reports) != 1 {
		t.Fatalf("code %d body %q reports %d", rec.Code, s.body, len(reports))
	}
	// Clean bodies pass untouched and are not reported.
	do(t, h, "POST", "/e", "application/vnd.api+json", `{"name":"ok"}`, nil)
	if s.body != `{"name":"ok"}` || len(reports) != 1 {
		t.Fatalf("clean body: %q, reports %d", s.body, len(reports))
	}
	// Non-JSON bodies are not inspected; JSON is recognised by its first byte whatever the Content-Type says.
	do(t, h, "POST", "/e", "text/plain", `<script>`, nil)
	if s.body != `<script>` {
		t.Fatalf("text body: %q", s.body)
	}
	do(t, h, "POST", "/e", "text/plain", ` {"a":"x<script>"}`, nil)
	if s.body != ` {"a":"x"}` {
		t.Fatalf("JSON sent as text/plain: %q", s.body)
	}
	// An empty or whitespace-only JSON body is passed on for the handler to judge.
	if rec := do(t, h, "POST", "/e", "application/json", "  ", nil); rec.Code != 204 {
		t.Fatalf("blank body: %d", rec.Code)
	}
}

// A body that does not parse is answered 400: a decoder reading only its first value would see what the guard
// could not.
func TestInvalidJSON(t *testing.T) {
	var s seen
	h := Middleware(Config{Guard: inputguard.MustNew(inputguard.WithMode(inputguard.ModeReject))})(echo(&s))
	for _, body := range []string{`{"name":"<script>alert(1)</script>"} x`, `{"a":1}{"b":"<script>"}`, `{"a":"<b>"`} {
		rec := do(t, h, "POST", "/e", "application/json", body, nil)
		if rec.Code != 400 || s.called || !strings.Contains(rec.Body.String(), "invalid_json") {
			t.Fatalf("%q: %d %v", body, rec.Code, s.called)
		}
	}
}

// Pairs joined by ";" are inspected too (a handler behind http.AllowQuerySemicolons sees them).
func TestQuerySemicolons(t *testing.T) {
	var s seen
	h := Middleware(Config{Guard: inputguard.MustNew(inputguard.WithMode(inputguard.ModeReject)), Query: true})(
		http.AllowQuerySemicolons(echo(&s)))
	if rec := do(t, h, "GET", "/p?a=1;q=%3Cscript%3Ealert(1)%3C/script%3E", "", "", nil); rec.Code != 400 {
		t.Fatalf("code %d", rec.Code)
	}
	var c seen
	hc := Middleware(Config{Guard: inputguard.MustNew(), Query: true})(echo(&c))
	do(t, hc, "GET", "/p?a=1;q=x%3Cscript%3E&%3Cb%3E=1&z=2", "", "", nil)
	if c.query != "a=1;q=x&&z=2" {
		t.Fatalf("query %q", c.query)
	}
}

func TestNDJSON(t *testing.T) {
	var s seen
	h := Middleware(Config{Guard: inputguard.MustNew()})(echo(&s))
	body := "{\"msg\":\"a<b>c</b>\"}\n\n{\"b\":2}\n"
	if rec := do(t, h, "POST", "/bulk", "application/x-ndjson", body, nil); rec.Code != 204 || s.body != "{\"msg\":\"a\"}\n\n{\"b\":2}\n" {
		t.Fatalf("code %d body %q", rec.Code, s.body)
	}
	if rec := do(t, h, "POST", "/bulk", "application/x-ndjson", "{\"a\":\"<b>\"\n", nil); rec.Code != 400 {
		t.Fatalf("broken line: %d", rec.Code)
	}
}

// A query pair that does not parse does not stop the others from being inspected.
func TestQueryWithBadPair(t *testing.T) {
	var s seen
	h := Middleware(Config{Guard: inputguard.MustNew(), Query: true})(echo(&s))
	do(t, h, "GET", "/p?q=%3Cscript%3Ealert(1)%3C/script%3E&x=%zz", "", "", nil)
	if strings.Contains(s.query, "script") {
		t.Fatalf("query %q", s.query)
	}
}

func TestReject(t *testing.T) {
	var s seen
	h := Middleware(Config{Guard: inputguard.MustNew(inputguard.WithMode(inputguard.ModeReject))})(echo(&s))
	rec := do(t, h, "PUT", "/e", "application/json", `{"title":"{{7*7}}","ok":"fine"}`, nil)
	if rec.Code != 400 || s.called {
		t.Fatalf("code %d called %v", rec.Code, s.called)
	}
	var body Rejection
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "input_rejected" || len(body.Error.Fields) != 1 || body.Error.Fields[0].Path != "title" ||
		strings.Contains(rec.Body.String(), "7*7") {
		t.Fatalf("response %s", rec.Body.String())
	}
}

func TestQueryAndHeaders(t *testing.T) {
	var s seen
	h := Middleware(Config{Guard: inputguard.MustNew(inputguard.WithRules(inputguard.RuleHeaderCRLF)), Query: true,
		Headers: []string{"User-Agent"}})(echo(&s))
	rec := do(t, h, "GET", "/p?q=shoes&ref=%3Cscript%3E&redirect_url=https%3A%2F%2Fshop.example.com%2F", "", "",
		map[string]string{"User-Agent": "Mozilla/5.0 <svg onload=alert(1)>"})
	// Only the dirty pair changes; the others keep their order and spelling.
	if rec.Code != 204 || s.query != "q=shoes&ref=&redirect_url=https%3A%2F%2Fshop.example.com%2F" ||
		s.header != "Mozilla/5.0" {
		t.Fatalf("code %d query %q header %q", rec.Code, s.query, s.header)
	}
}

func TestLimitsAndSkip(t *testing.T) {
	var s seen
	h := Middleware(Config{Guard: inputguard.MustNew(), MaxBodyBytes: 10,
		Skip: func(r *http.Request) bool { return r.URL.Path == "/health" }})(echo(&s))
	if rec := do(t, h, "POST", "/e", "application/json", `{"a":"0123456789"}`, nil); rec.Code != 413 {
		t.Fatalf("over limit: %d", rec.Code)
	}
	// A large body that is not JSON (an upload) passes whole.
	upload := "--x\r\n" + strings.Repeat("y", 64)
	if rec := do(t, h, "POST", "/e", "multipart/form-data; boundary=x", upload, nil); rec.Code != 204 || s.body != upload {
		t.Fatalf("upload: %d %d bytes", rec.Code, len(s.body))
	}
	if rec := do(t, h, "POST", "/health", "application/json", `{"a":"<script>"}`, nil); rec.Code != 204 ||
		s.body != `{"a":"<script>"}` {
		t.Fatalf("skip: %d %q", rec.Code, s.body)
	}
	// Chunked body (unknown length) over the limit.
	req := httptest.NewRequest("POST", "/e", io.MultiReader(strings.NewReader(`{"a":"`), strings.NewReader(strings.Repeat("x", 20)+`"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Fatalf("chunked over limit: %d", rec.Code)
	}
}

func TestMiddlewarePanicsWithoutGuard(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	Middleware(Config{})
}
