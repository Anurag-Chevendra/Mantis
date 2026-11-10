package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func noSleep(context.Context, time.Duration) error { return nil }

// fakeConsole answers pending, then slow_down, then a token.
func fakeConsole(t *testing.T, verify string, final func(w http.ResponseWriter)) (*httptest.Server, *int32) {
	t.Helper()
	var polls int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("bad form request")
		}
		if r.Form.Get("client_id") != ClientID {
			t.Errorf("client_id %q", r.Form.Get("client_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/device/code":
			v := verify
			if v == "" {
				v = srv.URL + "/device"
			}
			json.NewEncoder(w).Encode(DeviceCode{DeviceCode: "dev-123", UserCode: "WDJB-MJHT", VerificationURI: v, ExpiresIn: 600, Interval: 1})
		case "/oauth/token":
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.Form.Get("device_code") != "dev-123" {
				t.Errorf("bad token request %v", r.Form)
			}
			n := atomic.AddInt32(&polls, 1)
			switch n {
			case 1:
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"authorization_pending"}`))
			case 2:
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"slow_down"}`))
			default:
				final(w)
			}
		case "/oauth/revoke":
			if r.Form.Get("token") == "" {
				t.Error("revoke without token")
			}
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	return srv, &polls
}

func flow(t *testing.T, srv *httptest.Server) *Flow {
	u, _ := url.Parse(srv.URL)
	return &Flow{Console: u, HTTP: srv.Client(), UserAgent: "test", Sleep: noSleep}
}

func TestDeviceFlowSuccess(t *testing.T) {
	srv, polls := fakeConsole(t, "", func(w http.ResponseWriter) {
		w.Write([]byte(`{"access_token":"cohen_live_abcdefghijklmnopqrstuvwxyz","token_type":"Bearer","scope":"read queue"}`))
	})
	defer srv.Close()
	f := flow(t, srv)
	dc, err := f.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dc.UserCode != "WDJB-MJHT" {
		t.Fatalf("user code %q", dc.UserCode)
	}
	tok, err := f.Wait(context.Background(), dc)
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "cohen_live_abcdefghijklmnopqrstuvwxyz" || *polls != 3 {
		t.Fatalf("token %+v after %d polls", tok, *polls)
	}
	if err := f.Revoke(context.Background(), tok.AccessToken); err != nil {
		t.Fatal(err)
	}
}

func TestSlowDownIncreasesInterval(t *testing.T) {
	srv, _ := fakeConsole(t, "", func(w http.ResponseWriter) {
		w.Write([]byte(`{"access_token":"cohen_live_x0000000000000000","token_type":"bearer"}`))
	})
	defer srv.Close()
	f := flow(t, srv)
	var waits []time.Duration
	f.Sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	dc, _ := f.Start(context.Background())
	if _, err := f.Wait(context.Background(), dc); err != nil {
		t.Fatal(err)
	}
	if len(waits) != 3 || waits[2] != waits[0]+5*time.Second {
		t.Fatalf("waits %v: slow_down must add 5s", waits)
	}
}

func TestDenied(t *testing.T) {
	srv, _ := fakeConsole(t, "", func(w http.ResponseWriter) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"access_denied"}`))
	})
	defer srv.Close()
	f := flow(t, srv)
	dc, _ := f.Start(context.Background())
	if _, err := f.Wait(context.Background(), dc); !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestRejectsForeignVerificationURL(t *testing.T) {
	srv, _ := fakeConsole(t, "https://console-snappyfeet.evil.example/device", nil)
	defer srv.Close()
	if _, err := flow(t, srv).Start(context.Background()); err == nil {
		t.Fatal("a verification URL on another host must be refused")
	}
}

func TestRejectsBadToken(t *testing.T) {
	srv, _ := fakeConsole(t, "", func(w http.ResponseWriter) {
		w.Write([]byte(`{"access_token":"has space\r\nX: y","token_type":"bearer"}`))
	})
	defer srv.Close()
	f := flow(t, srv)
	dc, _ := f.Start(context.Background())
	if _, err := f.Wait(context.Background(), dc); err == nil {
		t.Fatal("malformed token must be refused")
	}
}

func TestFileStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mantis", "credentials.json")
	s := File{Path: p}
	if _, err := s.Get("api.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store: %v", err)
	}
	c := &Credential{Host: "api.example", Token: "cohen_live_secretsecretsecret", CreatedAt: time.Now()}
	if err := s.Set(c); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(p)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("credentials file mode %o, want 600", info.Mode().Perm())
		}
		dir, _ := os.Stat(filepath.Dir(p))
		if dir.Mode().Perm() != 0o700 {
			t.Fatalf("credentials dir mode %o, want 700", dir.Mode().Perm())
		}
		// A file opened up to other users must be refused, like ssh does.
		os.Chmod(p, 0o644)
		if _, err := s.Get("api.example"); err == nil {
			t.Fatal("world readable credentials file must be refused")
		}
		os.Chmod(p, 0o600)
	}
	got, err := s.Get("api.example")
	if err != nil || got.Token != c.Token {
		t.Fatalf("get: %+v %v", got, err)
	}
	if got.Prefix() == got.Token {
		t.Fatal("Prefix must not reveal the whole key")
	}
	if err := s.Delete("api.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("empty store should remove the file")
	}
}

// A connection dropped mid poll (server keep alive racing the poll interval,
// a proxy restart) must not end the login.
func TestDroppedConnectionDuringPollIsRetried(t *testing.T) {
	var polls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Close != true && r.Header.Get("Connection") != "close" {
			t.Errorf("OAuth requests should not reuse connections")
		}
		if atomic.AddInt32(&polls, 1) <= 2 {
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			c.Close() // EOF for the client
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"cohen_live_abcdefghijklmnopqrstuvwxyz","token_type":"Bearer"}`))
	}))
	defer srv.Close()
	f := flow(t, srv)
	tok, err := f.Wait(context.Background(), &DeviceCode{DeviceCode: "d", Interval: 1, ExpiresIn: 60})
	if err != nil || tok.AccessToken == "" {
		t.Fatalf("login ended on a dropped connection: %v", err)
	}
}
