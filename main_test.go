// Copyright (c) 2026 sinascorpion. SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testUID = "0123456789abcdef0123456789abcdef"
const testPassword = "test-only-password-change-me"

func appForTest(t *testing.T) *App {
	t.Helper()
	a, e := newApp(t.TempDir(), testPassword, "https://panel.example.com", testUID)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func request(a *App, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Origin", a.publicURL)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func loginForTest(t *testing.T, a *App) (*http.Cookie, string) {
	t.Helper()
	w := request(a, "POST", a.base+"/api/login", `{"password":"`+testPassword+`"}`, nil, "")
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var b map[string]string
	json.Unmarshal(w.Body.Bytes(), &b)
	return w.Result().Cookies()[0], b["csrf"]
}
func TestPasswordAndUIDRequirements(t *testing.T) {
	for _, password := range []string{"", "admin", "12345678901"} {
		if _, e := newApp(t.TempDir(), password, "https://panel.example.com", testUID); e == nil {
			t.Fatal("weak password accepted")
		}
	}
	for _, origin := range []string{"http://panel.example.com", "https://user:pass@panel.example.com", "https://panel.example.com/admin", "https://panel.example.com?q=x"} {
		if _, e := newApp(t.TempDir(), testPassword, origin, testUID); e == nil {
			t.Fatal("invalid PUBLIC_URL accepted", origin)
		}
	}
	if _, e := newApp(t.TempDir(), testPassword, "https://panel.example.com", "abc/../admin"); e == nil {
		t.Fatal("invalid UID accepted")
	}
}
func TestPublicPageDoesNotExposePanel(t *testing.T) {
	a := appForTest(t)
	w := request(a, "GET", "/", "", nil, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), testUID) || strings.Contains(w.Body.String(), "sinascorpion") || strings.Contains(w.Body.String(), "webproxy") {
		t.Fatal("public page reveals management details")
	}
	if request(a, "GET", "/admin", "", nil, "").Code != 404 {
		t.Fatal("unexpected public admin route")
	}
}
func TestAdminRedirectAndAssetPaths(t *testing.T) {
	a := appForTest(t)
	w := request(a, "GET", a.base, "", nil, "")
	if w.Code != 302 || w.Header().Get("Location") != a.base+"/" {
		t.Fatal("relative asset paths would fail")
	}
	for _, path := range []string{"/", "/app.js", "/app.css"} {
		w = request(a, "GET", a.base+path, "", nil, "")
		if w.Code != 200 {
			t.Fatal("asset missing", path)
		}
	}
}
func TestAuthenticationCSRFAndLogout(t *testing.T) {
	a := appForTest(t)
	if request(a, "GET", a.base+"/api/state", "", nil, "").Code != 401 {
		t.Fatal("unauthenticated state disclosed")
	}
	cookie, csrf := loginForTest(t, a)
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != a.base {
		t.Fatal("insecure session cookie")
	}
	if request(a, "POST", a.base+"/api/secret", "{}", cookie, "").Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if request(a, "POST", a.base+"/api/secret", "{}", cookie, csrf).Code != 200 {
		t.Fatal("valid request rejected")
	}
	r := httptest.NewRequest("POST", a.base+"/api/secret", strings.NewReader("{}"))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("foreign origin accepted")
	}
	if request(a, "POST", a.base+"/api/logout", "{}", cookie, csrf).Code != 200 {
		t.Fatal("logout failed")
	}
	if request(a, "GET", a.base+"/api/state", "", cookie, "").Code != 401 {
		t.Fatal("logged-out session still valid")
	}
}
func TestLoginRateLimitAndExpiry(t *testing.T) {
	a := appForTest(t)
	for i := 0; i < 5; i++ {
		if request(a, "POST", a.base+"/api/login", `{"password":"wrong"}`, nil, "").Code != 401 {
			t.Fatal("unexpected login result")
		}
	}
	if request(a, "POST", a.base+"/api/login", `{"password":"wrong"}`, nil, "").Code != 429 {
		t.Fatal("no rate limit")
	}
	a.attempts = map[string]attempt{}
	cookie, _ := loginForTest(t, a)
	for k, s := range a.sessions {
		s.Expires = time.Now().Add(-time.Second)
		a.sessions[k] = s
	}
	if request(a, "GET", a.base+"/api/state", "", cookie, "").Code != 401 {
		t.Fatal("expired session accepted")
	}
}
func TestProfileValidation(t *testing.T) {
	good := Profile{Domain: " Proxy.Example.COM ", Secret: "dd" + strings.Repeat("AB", 16), Tag: strings.Repeat("12", 16)}
	ps, e := validateProfiles([]Profile{good})
	if e != nil || ps[0].Domain != "proxy.example.com" || ps[0].Secret != strings.Repeat("ab", 16) {
		t.Fatal("valid profile rejected", e)
	}
	cases := []Profile{{Domain: "https://example.com"}, {Domain: "a..example.com"}, {Domain: strings.Repeat("a", 64) + ".example.com"}, {Domain: "proxy.example.com", Secret: "ee" + strings.Repeat("ab", 16)}, {Domain: "proxy.example.com", Secret: strings.Repeat("ab", 16), Tag: "channel-name"}}
	for _, p := range cases {
		if _, e = validateProfiles([]Profile{p}); e == nil {
			t.Fatal("invalid profile accepted", p.Domain)
		}
	}
	ps, e = validateProfiles([]Profile{{Domain: "proxy.example.com"}})
	if e != nil || !hexPattern.MatchString(ps[0].Secret) {
		t.Fatal("secret generation failed")
	}
	same := []Profile{{Domain: "one.example.com", Secret: strings.Repeat("ab", 16)}, {Domain: "two.example.com", Secret: strings.Repeat("ab", 16), Tag: strings.Repeat("cd", 16)}}
	if _, e = validateProfiles(same); e == nil {
		t.Fatal("conflicting shared-secret tags accepted")
	}
}
func TestInvalidDeployDoesNotMutateState(t *testing.T) {
	a := appForTest(t)
	a.state = State{Profiles: []Profile{{Domain: "old.example.com", Secret: strings.Repeat("12", 16)}}}
	cookie, csrf := loginForTest(t, a)
	w := request(a, "POST", a.base+"/api/deploy", `{"profiles":[{"domain":"https://bad.example.com"}]}`, cookie, csrf)
	if w.Code != 400 || a.state.Profiles[0].Domain != "old.example.com" || a.job != "idle" {
		t.Fatal("invalid deploy changed configuration")
	}
}
func TestUIDAndStatePersistence(t *testing.T) {
	dir := t.TempDir()
	a, e := newApp(dir, testPassword, "https://panel.example.com", "")
	if e != nil {
		t.Fatal(e)
	}
	state := State{Profiles: []Profile{{Domain: "proxy.example.com", Secret: strings.Repeat("12", 16)}}, Enabled: false}
	b, _ := json.Marshal(state)
	if e = atomicWrite(filepath.Join(dir, "state.json"), b); e != nil {
		t.Fatal(e)
	}
	next, e := newApp(dir, testPassword, "https://panel.example.com", "")
	if e != nil || a.base != next.base || next.state.Enabled || len(next.state.Profiles) != 1 {
		t.Fatal("state/route not retained", e)
	}
	if b, e = os.ReadFile(filepath.Join(dir, "admin-path")); e != nil || strings.TrimSpace(string(b)) != strings.TrimPrefix(a.base, "/") {
		t.Fatal("route not persisted")
	}
}
func TestCoreAPINeverPublic(t *testing.T) {
	a := appForTest(t)
	for _, path := range []string{"/v1/runtime/web/status", "/v1/config", "/api/state"} {
		if request(a, "GET", path, "", nil, "").Code != 404 {
			t.Fatal("control API exposed", path)
		}
	}
}
func TestDeploymentSerialization(t *testing.T) {
	a := appForTest(t)
	if !a.beginJob("deploying") || a.beginJob("deploying") || a.beginJob("stopping") {
		t.Fatal("overlapping jobs allowed")
	}
	a.finishJob("deployed")
	if !a.beginJob("stopping") {
		t.Fatal("completed job still locked")
	}
}
