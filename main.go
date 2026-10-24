// Copyright (c) 2026 sinascorpion. SPDX-License-Identifier: MIT
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/*
var assets embed.FS

type Profile struct {
	Domain string `json:"domain"`
	Secret string `json:"secret"`
	Tag    string `json:"tag"`
}
type State struct {
	Profiles []Profile `json:"profiles"`
	Updated  string    `json:"updated"`
	Enabled  bool      `json:"enabled"`
}
type Session struct {
	CSRF    string
	Expires time.Time
}
type attempt struct {
	Count int
	Until time.Time
}
type App struct {
	dir, base, publicURL string
	password             [32]byte
	secure               bool
	mu                   sync.Mutex
	sessions             map[string]Session
	attempts             map[string]attempt
	state                State
	job                  string
	core                 *Core
	proxy                *httputil.ReverseProxy
}

var uidPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,80}$`)
var hexPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func atomicWrite(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func validDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, p := range strings.Split(s, ".") {
		if !labelPattern.MatchString(p) {
			return false
		}
	}
	return true
}
func validateProfiles(ps []Profile) ([]Profile, error) {
	if len(ps) == 0 || len(ps) > 16 {
		return nil, errors.New("Add between 1 and 16 profiles.")
	}
	seen := map[string]bool{}
	tags := map[string]string{}
	for i := range ps {
		p := &ps[i]
		p.Domain = strings.ToLower(strings.TrimSpace(p.Domain))
		p.Secret = strings.ToLower(strings.TrimSpace(p.Secret))
		p.Tag = strings.ToLower(strings.TrimSpace(p.Tag))
		if len(p.Secret) == 34 && strings.HasPrefix(p.Secret, "dd") {
			p.Secret = p.Secret[2:]
		}
		if !validDomain(p.Domain) {
			return nil, fmt.Errorf("Profile %d: enter a hostname without https://, a port or a path (63 characters per label).", i+1)
		}
		if p.Secret == "" {
			p.Secret = randomToken(16)
		}
		if !hexPattern.MatchString(p.Secret) {
			return nil, fmt.Errorf("Profile %d: Secret must be 32 hex characters, optionally prefixed by dd.", i+1)
		}
		if p.Tag != "" && !hexPattern.MatchString(p.Tag) {
			return nil, fmt.Errorf("Profile %d: sponsor tag must be 32 hex characters.", i+1)
		}
		key := p.Domain + ":" + p.Secret
		if seen[key] {
			return nil, errors.New("The same domain and Secret cannot appear twice.")
		}
		seen[key] = true
		if old, ok := tags[p.Secret]; ok && old != p.Tag {
			return nil, errors.New("A shared Secret must use the same sponsor tag across domains.")
		}
		tags[p.Secret] = p.Tag
	}
	return ps, nil
}
func newApp(dir, password, publicURL, uid string) (*App, error) {
	if len(password) < 12 {
		return nil, errors.New("Set ADMIN_PASSWORD to at least 12 characters in the host Environment.")
	}
	u, err := url.Parse(publicURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("PUBLIC_URL must be the HTTPS origin assigned in Domains, without a path.")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && !(local && u.Scheme == "http") {
		return nil, errors.New("PUBLIC_URL requires HTTPS (HTTP is only allowed on localhost).")
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "admin-path")
	if uid == "" {
		if b, e := os.ReadFile(path); e == nil {
			uid = strings.TrimSpace(string(b))
		} else if !os.IsNotExist(e) {
			return nil, e
		} else {
			uid = randomToken(16)
		}
	}
	if !uidPattern.MatchString(uid) {
		return nil, errors.New("ADMIN_UID must contain 16–80 letters, digits, underscores or hyphens.")
	}
	if err = atomicWrite(path, []byte(uid)); err != nil {
		return nil, err
	}
	a := &App{dir: dir, base: "/" + uid, publicURL: strings.TrimSuffix(publicURL, "/"), password: sha256.Sum256([]byte(password)), secure: u.Scheme == "https", sessions: map[string]Session{}, attempts: map[string]attempt{}, job: "idle"}
	if b, e := os.ReadFile(filepath.Join(dir, "state.json")); e == nil {
		if e = json.Unmarshal(b, &a.state); e != nil {
			return nil, errors.New("Stored state is invalid; restore a backup before starting.")
		}
		if _, e = validateProfiles(a.state.Profiles); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	a.core = newCore(dir)
	target, _ := url.Parse("http://127.0.0.1:" + a.core.port)
	a.proxy = httputil.NewSingleHostReverseProxy(target)
	original := a.proxy.Director
	a.proxy.Director = func(r *http.Request) {
		original(r)
		r.Header.Del("Forwarded")
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Real-IP")
	}
	a.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) { http.Error(w, "Temporarily unavailable", 503) }
	a.proxy.ErrorLog = log.New(io.Discard, "", 0)
	return a, nil
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func (a *App) file(w http.ResponseWriter, name, kind string) {
	b, _ := assets.ReadFile("web/" + name)
	w.Header().Set("Content-Type", kind)
	w.Write(b)
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.URL.Path == "/healthz" {
		respond(w, 200, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == a.base || strings.HasPrefix(r.URL.Path, a.base+"/") {
		a.admin(w, r)
		return
	}
	if r.URL.Path == "/" {
		if r.URL.Query().Has("bridge") && a.proxyHost(r.Host) && a.core.running() {
			a.proxy.ServeHTTP(w, r)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			http.NotFound(w, r)
			return
		}
		a.file(w, "public.html", "text/html; charset=utf-8")
		return
	}
	// The core control API is on a separate loopback port and is never forwarded.
	if strings.HasPrefix(r.URL.Path, "/api/v1/") {
		if a.proxyHost(r.Host) && a.core.running() {
			a.proxy.ServeHTTP(w, r)
			return
		}
	}
	http.NotFound(w, r)
}
func (a *App) proxyHost(host string) bool {
	host = strings.ToLower(strings.Split(host, ":")[0])
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.state.Profiles {
		if p.Domain == host {
			return true
		}
	}
	return false
}
func (a *App) admin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
	sub := strings.TrimPrefix(r.URL.Path, a.base)
	if r.Method == "GET" && sub == "" {
		http.Redirect(w, r, a.base+"/", http.StatusFound)
		return
	}
	if r.Method == "GET" && sub == "/" {
		a.file(w, "admin.html", "text/html; charset=utf-8")
		return
	}
	if r.Method == "GET" && sub == "/app.css" {
		a.file(w, "app.css", "text/css; charset=utf-8")
		return
	}
	if r.Method == "GET" && sub == "/app.js" {
		a.file(w, "app.js", "text/javascript; charset=utf-8")
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if r.Method == "POST" {
		if r.Header.Get("Origin") != a.publicURL {
			respond(w, 403, map[string]string{"error": "Request origin does not match PUBLIC_URL."})
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			respond(w, 415, map[string]string{"error": "JSON required"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	}
	if sub == "/api/login" && r.Method == "POST" {
		a.login(w, r)
		return
	}
	session, cookie := a.session(r)
	if cookie == "" {
		respond(w, 401, map[string]string{"error": "Sign in to continue."})
		return
	}
	if r.Method == "POST" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(session.CSRF)) != 1 {
		respond(w, 403, map[string]string{"error": "Session verification failed. Reload and sign in again."})
		return
	}
	switch {
	case sub == "/api/state" && r.Method == "GET":
		a.mu.Lock()
		s := a.state
		job := a.job
		a.mu.Unlock()
		respond(w, 200, map[string]any{"profiles": s.Profiles, "updated": s.Updated, "job": job, "running": a.core.running(), "csrf": session.CSRF, "public_url": a.publicURL, "version": coreVersion})
	case sub == "/api/secret" && r.Method == "POST":
		respond(w, 200, map[string]string{"secret": randomToken(16)})
	case sub == "/api/logout" && r.Method == "POST":
		a.mu.Lock()
		delete(a.sessions, cookie)
		a.mu.Unlock()
		a.setCookie(w, "", -1)
		respond(w, 200, map[string]bool{"ok": true})
	case sub == "/api/deploy" && r.Method == "POST":
		var body struct {
			Profiles []Profile `json:"profiles"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			respond(w, 400, map[string]string{"error": "Invalid configuration."})
			return
		}
		ps, err := validateProfiles(body.Profiles)
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if a.beginJob("deploying") {
			go a.deploy(ps)
			respond(w, 202, map[string]bool{"accepted": true})
		} else {
			respond(w, 409, map[string]string{"error": "A deployment is already in progress."})
		}
	case sub == "/api/stop" && r.Method == "POST":
		if a.beginJob("stopping") {
			go func() {
				a.core.stop()
				a.mu.Lock()
				a.state.Enabled = false
				b, _ := json.MarshalIndent(a.state, "", "  ")
				a.mu.Unlock()
				if err := atomicWrite(filepath.Join(a.dir, "state.json"), b); err != nil {
					a.finishJob("Deployment failed: disabled state could not be saved.")
				} else {
					a.finishJob("disabled")
				}
			}()
			respond(w, 202, map[string]bool{"accepted": true})
		} else {
			respond(w, 409, map[string]string{"error": "Wait for the current deployment."})
		}
	default:
		http.NotFound(w, r)
	}
}
func (a *App) setCookie(w http.ResponseWriter, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: "wh_session", Value: value, Path: a.base, Secure: a.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func (a *App) session(r *http.Request) (Session, string) {
	c, err := r.Cookie("wh_session")
	if err != nil {
		return Session{}, ""
	}
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(c.Value)))
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[key]
	if !ok {
		return Session{}, ""
	}
	if time.Now().After(s.Expires) {
		delete(a.sessions, key)
		return Session{}, ""
	}
	return s, key
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	a.mu.Lock()
	now := time.Now()
	limit := a.attempts[ip]
	global := a.attempts["*"]
	if now.Before(limit.Until) && limit.Count >= 5 || now.Before(global.Until) && global.Count >= 30 {
		a.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		respond(w, 429, map[string]string{"error": "Too many attempts. Try again in a minute."})
		return
	}
	if now.After(limit.Until) {
		limit = attempt{Until: now.Add(time.Minute)}
	}
	limit.Count++
	a.attempts[ip] = limit
	if now.After(global.Until) {
		global = attempt{Until: now.Add(time.Minute)}
	}
	global.Count++
	a.attempts["*"] = global
	// Bound memory even if request addresses vary.
	if len(a.attempts) > 1024 {
		for k, v := range a.attempts {
			if now.After(v.Until) {
				delete(a.attempts, k)
			}
		}
		if len(a.attempts) > 1024 {
			a.mu.Unlock()
			respond(w, 429, map[string]string{"error": "Try again later."})
			return
		}
	}
	a.mu.Unlock()
	var body struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		respond(w, 400, map[string]string{"error": "Invalid request."})
		return
	}
	sum := sha256.Sum256([]byte(body.Password))
	if subtle.ConstantTimeCompare(sum[:], a.password[:]) != 1 {
		respond(w, 401, map[string]string{"error": "Incorrect password."})
		return
	}
	token := randomToken(32)
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	s := Session{CSRF: randomToken(32), Expires: now.Add(8 * time.Hour)}
	a.mu.Lock()
	for k, v := range a.sessions {
		if now.After(v.Expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 64 {
		a.mu.Unlock()
		respond(w, 429, map[string]string{"error": "Too many active sessions. Restart the application to sign out all sessions."})
		return
	}
	a.sessions[key] = s
	a.mu.Unlock()
	a.setCookie(w, token, 8*60*60)
	respond(w, 200, map[string]string{"csrf": s.CSRF})
}
func (a *App) beginJob(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.job == "deploying" || a.job == "stopping" || a.job == "restoring" {
		return false
	}
	a.job = name
	return true
}
func (a *App) finishJob(name string) { a.mu.Lock(); a.job = name; a.mu.Unlock() }
func (a *App) deploy(ps []Profile) {
	a.mu.Lock()
	old := a.state
	a.mu.Unlock()
	if err := a.core.apply(ps); err != nil {
		a.finishJob("Deployment failed: " + err.Error())
		return
	}
	state := State{Profiles: ps, Updated: time.Now().UTC().Format(time.RFC3339), Enabled: true}
	b, _ := json.MarshalIndent(state, "", "  ")
	if err := atomicWrite(filepath.Join(a.dir, "state.json"), b); err != nil {
		a.core.stop()
		if old.Enabled && len(old.Profiles) > 0 {
			_ = a.core.apply(old.Profiles)
		}
		a.finishJob("Deployment failed: configuration could not be saved.")
		return
	}
	a.mu.Lock()
	a.state = state
	a.job = "deployed"
	a.mu.Unlock()
}
func env(name, fallback string) string {
	if s := os.Getenv(name); s != "" {
		return s
	}
	return fallback
}
func main() {
	a, err := newApp(env("DATA_DIR", "./data"), os.Getenv("ADMIN_PASSWORD"), os.Getenv("PUBLIC_URL"), os.Getenv("ADMIN_UID"))
	if err != nil {
		log.Fatal(err)
	}
	defer a.core.stop()
	a.core.port = env("CORE_PORT", "18080")
	a.core.api = env("CORE_API_PORT", "18082")
	target, _ := url.Parse("http://127.0.0.1:" + a.core.port)
	original := a.proxy.Director
	a.proxy.Director = func(r *http.Request) { original(r); r.URL.Host = target.Host }
	port := env("SERVER_PORT", env("PORT", "8080"))
	if !validPort(port) || !validPort(a.core.port) || !validPort(a.core.api) || port == a.core.port || port == a.core.api || a.core.port == a.core.api {
		log.Fatal("HTTP and private core ports must be distinct valid port numbers")
	}
	if a.state.Enabled && len(a.state.Profiles) > 0 {
		a.job = "restoring"
		go func() {
			if err := a.core.apply(a.state.Profiles); err != nil {
				a.finishJob("Restore failed: " + err.Error())
			} else {
				a.finishJob("deployed")
			}
		}()
	}
	server := &http.Server{Addr: net.JoinHostPort(env("HOST", "0.0.0.0"), port), Handler: a, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
	// No response write timeout: Telegram carriers include long polls and WebSockets.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		c, done := context.WithTimeout(context.Background(), 8*time.Second)
		defer done()
		server.Shutdown(c)
		a.core.stop()
	}()
	log.Printf("Webproxy Host listening on port %s", port)
	log.Printf("Admin panel: %s%s (password comes from ADMIN_PASSWORD)", a.publicURL, a.base)
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
