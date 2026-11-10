package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestValidateBaseURL(t *testing.T) {
	ok := []string{"https://api.snappyfeet.org", "https://api.example.com/base/", "http://127.0.0.1:8080", "http://localhost:3000"}
	bad := []string{"http://api.snappyfeet.org", "ftp://x", "https://user:pw@api.x", "https://api.x/?a=1", "not a url", ""}
	for _, u := range ok {
		if _, err := ValidateBaseURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range bad {
		if _, err := ValidateBaseURL(u); err == nil {
			t.Errorf("%s should be rejected", u)
		}
	}
}

func TestCheckBatchesAndRetries(t *testing.T) {
	var (
		mu       sync.Mutex
		calls    int
		keys     = map[string]int{}
		failOnce = true
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if r.URL.Path != "/api/package/npm" || r.Method != "POST" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer cohen_live_test" {
			t.Errorf("auth header %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Client") != "mantis/test" || r.Header.Get("X-Project") != "appX-Evil: 1" || len(r.Header.Values("X-Evil")) != 0 {
			t.Errorf("headers %v", r.Header)
		}
		keys[r.Header.Get("Idempotency-Key")]++
		if failOnce {
			failOnce = false
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(503)
			io.WriteString(w, `{"error":"verdict_store_unavailable","message":"down"}`)
			return
		}
		var body struct {
			Versions     []string `json:"versions"`
			QueueUnknown bool     `json:"queue_unknown"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.QueueUnknown {
			t.Error("queue_unknown must default to false")
		}
		resp := map[string]any{
			"scan":    fmt.Sprintf("scan-%d", calls),
			"counts":  map[string]int{"clean": len(body.Versions) - 1, "review": 1},
			"review":  []map[string]string{{"name": "bad", "version": "1.0.0", "verdict": "review"}},
			"unknown": []map[string]string{},
			"queued":  []map[string]string{},
		}
		w.WriteHeader(207)
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c, err := New(srv.URL, "cohen_live_test", "mantis-test", WithHTTPClient(srv.Client()), WithBatchSize(2), WithNoSleep())
	if err != nil {
		t.Fatal(err)
	}
	vs := []string{"a@1", "b@1", "c@1", "d@1", "e@1"}
	res, err := c.Check(context.Background(), vs, CheckOptions{Project: "app\r\nX-Evil: 1", Client: "mantis/test"})
	if err == nil && len(res.Scans) != 3 {
		t.Fatalf("scans %v", res.Scans)
	}
	if err != nil {
		t.Fatal(err)
	}
	if res.Counts.Review != 3 || res.Counts.Clean != 2 || len(res.Review) != 3 {
		t.Fatalf("merged counts %+v", res.Counts)
	}
	// 3 batches + 1 retry. The retried batch must reuse its idempotency key.
	if calls != 4 || len(keys) != 3 {
		t.Fatalf("calls=%d distinct keys=%d (%v)", calls, len(keys), keys)
	}
}

func TestAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid_key","message":"That key is not valid."}`)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "x", "t", WithHTTPClient(srv.Client()), WithNoSleep())
	_, err := c.Key(context.Background())
	if !IsAuth(err) || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("got %v", err)
	}
}

func TestNoCrossHostRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("credential forwarded to another host")
		}
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "localhost", 1)+"/steal", http.StatusFound)
	}))
	defer srv.Close()
	hc := NewHTTPClient(0)
	c, _ := New(srv.URL, "cohen_live_secret", "t", WithHTTPClient(hc), WithNoSleep())
	if _, err := c.Key(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect refusal, got %v", err)
	}
}

func TestSanitizeHeader(t *testing.T) {
	if got := sanitizeHeader("a\r\nb\x00c", 10); got != "abc" {
		t.Fatalf("%q", got)
	}
}

func TestQuotaErrorsAreNotRetried(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(429)
		w.Write([]byte(`{"error":"daily_cap","message":"This project has 368 packages and your free key has 100 of 100 lookups left today."}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "cohen_live_test", "t", WithHTTPClient(srv.Client()), WithNoSleep())
	_, err := c.Check(context.Background(), []string{"a@1.0.0"}, CheckOptions{})
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != "daily_cap" || atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("err %v after %d requests; quota errors must fail fast", err, hits)
	}
}
