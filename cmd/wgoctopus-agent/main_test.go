package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/illmouse/wgoctopus/internal/state"
)

func TestParseConfig(t *testing.T) {
	keeperCfg, err := parseConfig([]string{"--listen", "127.0.0.1:80", "--token", "x", "--keeper-interval", "17s", "--keeper-disable"}, func(string) string { return "" })
	if err != nil || keeperCfg.KeeperInterval != 17*time.Second || !keeperCfg.KeeperDisable {
		t.Fatalf("keeper flags: %+v, %v", keeperCfg, err)
	}
	getenv := func(k string) string {
		if k == "WGOCTOPUS_TOKEN" {
			return "from-env"
		}
		return ""
	}
	t.Run("hop flag and environment", func(t *testing.T) {
		base := []string{"--listen", "127.0.0.1:80", "--token", "x"}
		c, err := parseConfig(append(base, "--hop-enabled"), func(string) string { return "" })
		if err != nil || !c.HopEnabled {
			t.Fatalf("flag config=%+v err=%v", c, err)
		}
		c, err = parseConfig(base, func(k string) string {
			if k == "WGOCTOPUS_HOP_ENABLED" {
				return "true"
			}
			return ""
		})
		if err != nil || !c.HopEnabled {
			t.Fatalf("env config=%+v err=%v", c, err)
		}
	})
	tests := []struct {
		name               string
		args               []string
		env                func(string) string
		wantErr, wantToken string
	}{
		{name: "missing token", args: []string{"--listen", "127.0.0.1:80"}, wantErr: "token is required"},
		{name: "env token", args: []string{"--listen", "127.0.0.1:80"}, env: getenv, wantToken: "from-env"},
		{name: "public refused", args: []string{"--listen", "0.0.0.0:80", "--token", "x"}, wantErr: "public listen"},
		{name: "public allowed", args: []string{"--listen", "[::]:80", "--allow-public-listen", "--token", "x"}, wantToken: "x"},
		{name: "bad level", args: []string{"--listen", "127.0.0.1:80", "--token", "x", "--log-level", "trace"}, wantErr: "invalid log level"},
		{name: "version", args: []string{"--version"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := func(k string) string {
				if tt.env != nil {
					return tt.env(k)
				}
				return ""
			}
			c, err := parseConfig(tt.args, e)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantToken != "" && string(c.Token) != tt.wantToken {
				t.Fatalf("token = %q", string(c.Token))
			}
			if tt.name == "version" && !c.ShowVersion {
				t.Fatal("version flag not set")
			}
		})
	}
	t.Run("token file trims newline", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(p, []byte("file-secret\n"), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := parseConfig([]string{"--listen", "127.0.0.1:80", "--token-file", p}, func(string) string { return "" })
		if err != nil || string(c.Token) != "file-secret" {
			t.Fatalf("config token %q, error %v", string(c.Token), err)
		}
	})
}

func TestParseConfigPull(t *testing.T) {
	base := []string{"--listen", "127.0.0.1:80", "--token", "x"}
	getenv := func(string) string { return "" }
	c, err := parseConfig(base, getenv)
	if err != nil || c.PullServer != "" {
		t.Fatalf("pull should be disabled by default: config=%+v err=%v", c, err)
	}

	server, user, keyFile := "pull.example:22", "pull-user-secret", "/secret/key-path"
	c, err = parseConfig(append(base, "--pull-server", server, "--pull-user", user, "--pull-key-file", keyFile), getenv)
	if err == nil || strings.Contains(err.Error(), server) || strings.Contains(err.Error(), user) || strings.Contains(err.Error(), keyFile) {
		t.Fatalf("missing pull settings should fail without echoing values: config=%+v err=%v", c, err)
	}

	fingerprint := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	args := append(append([]string{}, base...), "--pull-server", server, "--pull-user", user, "--pull-key-file", keyFile, "--pull-host-key", fingerprint)
	c, err = parseConfig(args, getenv)
	if err != nil || c.PullServer != server || c.PullUser != user || c.PullKeyFile != keyFile || c.PullHostKey != fingerprint {
		t.Fatalf("pull flags: config=%+v err=%v", c, err)
	}

	env := map[string]string{
		"WGOCTOPUS_PULL_SERVER":   server,
		"WGOCTOPUS_PULL_USER":     user,
		"WGOCTOPUS_PULL_KEY_FILE": keyFile,
		"WGOCTOPUS_PULL_HOST_KEY": fingerprint,
	}
	c, err = parseConfig(base, func(k string) string { return env[k] })
	if err != nil || c.PullServer != server || c.PullUser != user || c.PullKeyFile != keyFile || c.PullHostKey != fingerprint {
		t.Fatalf("pull environment: config=%+v err=%v", c, err)
	}
}

func TestParseConfigPullHostKeyFingerprint(t *testing.T) {
	base := []string{"--listen", "127.0.0.1:80", "--token", "x", "--pull-server", "server", "--pull-user", "user", "--pull-key-file", "key"}
	for _, tc := range []struct {
		fingerprint string
		valid       bool
	}{
		{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true},
		{"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"SHA256:!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", false},
	} {
		t.Run(tc.fingerprint, func(t *testing.T) {
			args := append(append([]string{}, base...), "--pull-host-key", tc.fingerprint)
			_, err := parseConfig(args, func(string) string { return "" })
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && (err == nil || !strings.Contains(err.Error(), "pull-host-key must be a SHA256 fingerprint") || strings.Contains(err.Error(), tc.fingerprint)) {
				t.Fatalf("invalid fingerprint error = %v", err)
			}
		})
	}
}

func TestSecretRedaction(t *testing.T) {
	const token, private, psk = "token-secret", "private-secret", "psk-secret"
	v := state.State{Interfaces: []state.Interface{{PrivateKey: private, Peers: []state.Peer{{PresharedKey: psk}}}}}
	var b bytes.Buffer
	_, _ = fmt.Fprintf(&b, "%v %+v %+v", secret(token), v, v.Interfaces[0].Peers[0])
	h := slog.New(slog.NewJSONHandler(&b, nil))
	h.Info("redaction", "token", secret(token), "state", v)
	for _, s := range []string{token, private, psk} {
		if strings.Contains(b.String(), s) {
			t.Fatalf("secret leaked: %s", b.String())
		}
	}
}
