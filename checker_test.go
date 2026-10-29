package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func responseClient(body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" {
			return nil, fmt.Errorf("expected HTTPS, got %s", r.URL.Scheme)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
}

func TestExitCountryUsesObservedIP(t *testing.T) {
	for _, country := range []string{"DE", "RU", ""} {
		t.Run(country, func(t *testing.T) {
			var lookedUp string
			ip, geo, ok := verifyProxyExit(context.Background(), responseClient(`{"ip":"8.8.8.8"}`),
				func(ip string) (geoInfo, bool) {
					lookedUp = ip
					return geoInfo{CountryCode: country}, country == "RU"
				})
			if lookedUp != "8.8.8.8" || ok != (country == "RU") {
				t.Fatalf("actual exit lookup=%q accepted=%v country=%q", lookedUp, ok, country)
			}
			if ok && (ip != "8.8.8.8" || geo.CountryCode != "RU") {
				t.Fatal("exit evidence missing")
			}
		})
	}
}

func TestExitCannotBePrivateOrUnverified(t *testing.T) {
	for _, body := range []string{`{"ip":"127.0.0.1"}`, `{"ip":"10.0.0.1"}`, `{"ip":"not-an-ip"}`, `{"ip":`, strings.Repeat("x", 32769)} {
		_, _, ok := verifyProxyExit(context.Background(), responseClient(body), func(string) (geoInfo, bool) {
			t.Fatal("invalid address reached geolocation")
			return geoInfo{}, false
		})
		if ok {
			t.Fatalf("accepted invalid exit response %q", body[:min(len(body), 40)])
		}
	}
}

func TestGeoFailsClosed(t *testing.T) {
	info, ok := lookupGeo(context.Background(), responseClient(`{"success":true,"ip":"8.8.8.8","country_code":"RU","city":"Москва","connection":{"isp":"Test"}}`), "8.8.8.8")
	if !ok || info.CountryCode != "RU" || info.City != "Москва" || info.ISP != "Test" {
		t.Fatalf("valid geo response rejected: %+v %v", info, ok)
	}
	for _, body := range []string{`{"success":false}`, `{"success":true,"ip":"1.1.1.1","country_code":"RU"}`, `{"success":true,"ip":"8.8.8.8"}`, `not-json`} {
		if _, ok := lookupGeo(context.Background(), responseClient(body), "8.8.8.8"); ok {
			t.Fatalf("unverified geo accepted: %s", body)
		}
	}
	broken := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}
	if _, ok := lookupGeo(context.Background(), broken, "8.8.8.8"); ok {
		t.Fatal("unavailable geo service must not imply RU")
	}
}

type brokenBody struct{ sent bool }

func (b *brokenBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, io.ErrUnexpectedEOF
	}
	b.sent = true
	return copy(p, "<html>"+strings.Repeat("x", 900)), nil
}
func (*brokenBody) Close() error { return nil }

func TestTruncatedBodyIsNotSuccessful(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: &brokenBody{}, Header: make(http.Header)}, nil
	})}
	if _, ok := testTargetURL(client, "https://mos-gorsud.ru"); ok {
		t.Fatal("truncated HTML passed target check")
	}
	var result any
	if readJSON(context.Background(), client, "https://api.ipify.org", &result) == nil {
		t.Fatal("truncated body passed JSON check")
	}
}

func TestProxyHTTPSRejectsUntrustedCertificate(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 1024))
	}))
	defer target.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", 405)
			return
		}
		upstream, err := net.DialTimeout("tcp", strings.TrimPrefix(target.URL, "https://"), time.Second)
		if err != nil {
			t.Error(err)
			return
		}
		downstream, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			t.Error(err)
			return
		}
		defer downstream.Close()
		defer upstream.Close()
		fmt.Fprint(downstream, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go io.Copy(upstream, downstream)
		io.Copy(downstream, upstream)
	}))
	defer proxy.Close()
	client, err := buildProxyHTTPClient(strings.TrimPrefix(proxy.URL, "http://"), "http", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if resp, err := client.Get(target.URL); err == nil {
		resp.Body.Close()
		t.Fatal("untrusted HTTPS certificate accepted through proxy")
	}
}

func TestSOCKSHandshakeDeadlineDoesNotExpireTunnel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(conn, greeting); err != nil {
			done <- err
			return
		}
		conn.Write([]byte{5, 0})
		request := make([]byte, 10) // IPv4 request to 8.8.8.8:443
		if _, err = io.ReadFull(conn, request); err != nil {
			done <- err
			return
		}
		conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		time.Sleep(300 * time.Millisecond)
		_, err = conn.Write([]byte("alive"))
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	conn, err := dialSOCKS5(ctx, listener.Addr().String(), "8.8.8.8:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	// A separate write after the original handshake deadline must still succeed.
	time.Sleep(200 * time.Millisecond)
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("handshake deadline leaked into tunnel: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "alive" {
		t.Fatalf("established tunnel failed: %q %v", buf, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
