// Copyright (c) 2026 sinascorpion. SPDX-License-Identifier: MIT
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const coreVersion = "3.5.14"

var coreHashes = map[string]string{
	"amd64": "71c1454f79cf755edea0985500629daba553002f9863be754e8e38a418822773",
	"arm64": "21795430c4165cf964405459714d08eea319edaa5c9027beac4de373c356d84d",
}

type Core struct {
	mu             sync.Mutex
	dir, port, api string
	cmd            *exec.Cmd
	done           chan struct{}
	active         []Profile
	configPath     string
	live           atomic.Bool
}

func newCore(dir string) *Core { return &Core{dir: dir, port: "18080", api: "18082"} }
func validPort(s string) bool  { n, e := strconv.Atoi(s); return e == nil && n > 0 && n < 65536 }
func (c *Core) running() bool  { return c.live.Load() }
func (c *Core) alive() bool {
	if c.cmd == nil {
		return false
	}
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}
func (c *Core) stop() { c.mu.Lock(); defer c.mu.Unlock(); c.stopLocked() }
func (c *Core) stopLocked() {
	c.live.Store(false)
	if c.alive() {
		_ = c.cmd.Process.Signal(os.Interrupt)
		select {
		case <-c.done:
		case <-time.After(4 * time.Second):
			_ = c.cmd.Process.Kill()
			<-c.done
		}
	}
	c.cmd = nil
	if strings.HasPrefix(filepath.Base(c.configPath), "candidate-") {
		_ = os.Remove(c.configPath)
	}
	c.configPath = ""
}
func digest(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
func (c *Core) binary() (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("The proxy core requires a Linux amd64 or arm64 runtime.")
	}
	expected, ok := coreHashes[runtime.GOARCH]
	if !ok {
		return "", errors.New("Unsupported CPU architecture.")
	}
	dir := filepath.Join(c.dir, "bin")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	archive := filepath.Join(dir, "telemt-"+coreVersion+".tar.gz")
	sum, err := digest(archive)
	if err != nil || sum != expected {
		arch := "x86_64"
		if runtime.GOARCH == "arm64" {
			arch = "aarch64"
		}
		endpoint := fmt.Sprintf("https://github.com/telemt/telemt/releases/download/%s/telemt-%s-linux-musl.tar.gz", coreVersion, arch)
		client := &http.Client{Timeout: 150 * time.Second}
		r, e := client.Get(endpoint)
		if e != nil {
			return "", errors.New("Core download failed. Check outbound HTTPS access.")
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return "", fmt.Errorf("Core download returned HTTP %d.", r.StatusCode)
		}
		f, e := os.CreateTemp(dir, ".download-")
		if e != nil {
			return "", e
		}
		defer os.Remove(f.Name())
		_ = f.Chmod(0600)
		h := sha256.New()
		n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.Body, 80<<20))
		closeErr := f.Close()
		if e != nil || closeErr != nil || n >= 80<<20 {
			return "", errors.New("Core download was incomplete or too large.")
		}
		if fmt.Sprintf("%x", h.Sum(nil)) != expected {
			return "", errors.New("Core checksum mismatch; refusing to execute it.")
		}
		if e = os.Rename(f.Name(), archive); e != nil {
			return "", e
		}
	}
	// Re-extract from the checked archive; never trust an unchecked cached executable.
	f, e := os.Open(archive)
	if e != nil {
		return "", e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return "", e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
		if filepath.Base(header.Name) != "telemt" || header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size > 100<<20 {
			return "", errors.New("Invalid core archive.")
		}
		out, e := os.CreateTemp(dir, ".core-")
		if e != nil {
			return "", e
		}
		path := out.Name()
		defer os.Remove(path)
		if e = out.Chmod(0700); e == nil {
			_, e = io.CopyN(out, tr, header.Size)
		}
		if e == nil {
			e = out.Sync()
		}
		closeErr := out.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			return "", e
		}
		final := filepath.Join(dir, "telemt")
		if e = os.Rename(path, final); e != nil {
			return "", e
		}
		return final, nil
	}
	return "", errors.New("Executable not found in verified core archive.")
}
func resolveIPv4(domain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if e != nil {
		return "", fmt.Errorf("DNS lookup failed for %s. Add this hostname in the host Domains panel first.", domain)
	}
	for _, ip := range ips {
		if ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("%s needs a public IPv4 DNS record.", domain)
}
func (c *Core) config(ps []Profile) (string, error) {
	users := map[string]string{}
	domains := []string{}
	addresses := map[string]string{}
	tags := false
	for _, p := range ps {
		if _, ok := users[p.Secret]; !ok {
			users[p.Secret] = fmt.Sprintf("user%d", len(users)+1)
		}
		if p.Tag != "" {
			tags = true
		}
		if _, ok := addresses[p.Domain]; !ok {
			ip, e := resolveIPv4(p.Domain)
			if e != nil {
				return "", e
			}
			addresses[p.Domain] = ip
			domains = append(domains, p.Domain)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[general]\nuse_middle_proxy = %t\nlog_level = \"silent\"\nprefer_ipv6 = false\n[general.modes]\nclassic = false\nsecure = true\ntls = false\n[general.links]\nshow = []\n[network]\nipv4 = true\nprefer = 4\n[access.users]\n", tags)
	written := map[string]bool{}
	for _, p := range ps {
		if !written[p.Secret] {
			fmt.Fprintf(&b, "%s = %q\n", users[p.Secret], p.Secret)
			written[p.Secret] = true
		}
	}
	if tags {
		b.WriteString("[access.user_ad_tags]\n")
		written = map[string]bool{}
		for _, p := range ps {
			if p.Tag != "" && !written[p.Secret] {
				fmt.Fprintf(&b, "%s = %q\n", users[p.Secret], p.Tag)
				written[p.Secret] = true
			}
		}
	}
	fmt.Fprintf(&b, "[server.api]\nenabled = true\nlisten = \"127.0.0.1:%s\"\nwhitelist = [\"127.0.0.1/32\"]\n[[server.listeners]]\nip = \"127.0.0.1\"\nport = %s\ntransport = \"web\"\nproxy_protocol = false\nweb_client_ip_source = \"x_forwarded_for\"\nweb_trusted_proxy_cidrs = [\"127.0.0.1/32\"]\n[web]\nenabled = true\ncarrier = \"https\"\ncarriers = [\"websocket-lanes\", \"websocket\", \"https-lanes\", \"https\"]\ndecoy_fasttrack_mode = \"off\"\n[web.limits]\nmax_vhosts = 16\nmax_profiles = 16\n", c.api, c.port)
	site := filepath.Join(c.dir, "site")
	for _, d := range domains {
		fmt.Fprintf(&b, "[[web.vhosts]]\nhost = %q\npublic_addr = %q\n[web.vhosts.decoy]\nmode = \"static_directory\"\ndirectory = %q\nindex = \"index.html\"\n", d, addresses[d]+":443", filepath.ToSlash(site))
		for _, p := range ps {
			if p.Domain == d {
				fmt.Fprintf(&b, "[[web.vhosts.profiles]]\nuser = %q\nsecret_mode = \"dd\"\nmax_sessions = 64\nmax_streams = 2048\nmax_streams_per_session = 32\n", users[p.Secret])
			}
		}
	}
	return b.String(), nil
}
func (c *Core) ready() bool {
	client := &http.Client{Timeout: time.Second}
	r, e := client.Get("http://127.0.0.1:" + c.api + "/v1/runtime/web/status")
	if e != nil {
		return false
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return false
	}
	var body map[string]any
	if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body) != nil {
		return false
	}
	if data, ok := body["data"].(map[string]any); ok {
		body = data
	}
	if ingress, ok := body["ingress"].(map[string]any); ok {
		return ingress["accepting_connections"] == true
	}
	return false
}
func (c *Core) startLocked(bin, path string) error {
	cmd := exec.Command(bin, path)
	cmd.Dir = c.dir
	cmd.Env = append(os.Environ(), "RUST_LOG=off")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	// Do not leak admin credentials to the child core.
	clean := []string{}
	for _, e := range cmd.Env {
		if !strings.HasPrefix(e, "ADMIN_PASSWORD=") {
			clean = append(clean, e)
		}
	}
	cmd.Env = clean
	if e := cmd.Start(); e != nil {
		return errors.New("Could not execute the core in this runtime.")
	}
	c.cmd = cmd
	c.configPath = path
	c.live.Store(true)
	c.done = make(chan struct{})
	done := c.done
	go func() { _ = cmd.Wait(); c.live.Store(false); close(done) }()
	for deadline := time.Now().Add(40 * time.Second); time.Now().Before(deadline); {
		if !c.alive() {
			return errors.New("The core exited before becoming ready.")
		}
		if c.ready() {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("Core readiness timed out. Check runtime resources and outbound connectivity.")
}
func (c *Core) apply(ps []Profile) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	config, e := c.config(ps)
	if e != nil {
		return e
	}
	bin, e := c.binary()
	if e != nil {
		return e
	}
	site := filepath.Join(c.dir, "site")
	if e = os.MkdirAll(site, 0700); e != nil {
		return e
	}
	page, _ := assets.ReadFile("web/public.html")
	if e = atomicWrite(filepath.Join(site, "index.html"), page); e != nil {
		return e
	}
	candidate := filepath.Join(c.dir, "candidate-"+randomToken(8)+".toml")
	if e = atomicWrite(candidate, []byte(config)); e != nil {
		return e
	}
	oldPath := filepath.Join(c.dir, "active.toml")
	old, e := os.ReadFile(oldPath)
	hadOld := e == nil
	c.stopLocked()
	if e = c.startLocked(bin, candidate); e != nil {
		c.stopLocked()
		if hadOld {
			_ = c.startLocked(bin, oldPath)
		}
		return e
	}
	if e = atomicWrite(oldPath, []byte(config)); e != nil {
		c.stopLocked()
		if hadOld {
			_ = atomicWrite(oldPath, old)
			_ = c.startLocked(bin, oldPath)
		}
		return errors.New("Could not persist the active core configuration.")
	}
	c.active = append([]Profile(nil), ps...)
	return nil
}
