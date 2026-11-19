package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/illmouse/wgoctopus/internal/state"
)

func TestParseConfig(t *testing.T) {
	getenv := func(k string) string {
		if k == "WGOCTOPUS_TOKEN" {
			return "from-env"
		}
		return ""
	}
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
