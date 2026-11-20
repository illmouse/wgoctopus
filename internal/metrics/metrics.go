package metrics

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/illmouse/wgoctopus/internal/hop"
	"github.com/illmouse/wgoctopus/internal/uapi"
)

// Collector gathers and renders Prometheus metrics for managed WireGuard interfaces.
type Collector struct {
	Interfaces      func() []string
	Device          func(name string) (uapi.Device, error)
	AppliedRevision func() int64
	Restarts        func(name string) uint64
	Now             func() time.Time
	Version         string
	GoVersion       string
	HopStats        func() hop.Stats
}

// Render returns metrics in Prometheus text exposition format 0.0.4.
// A peer's handshake age is emitted only after it has completed a handshake.
// A failed UAPI lookup marks that interface down and does not affect others.
func (c *Collector) Render(ctx context.Context) []byte {
	var b strings.Builder
	metricHeader(&b, "wg_interface_up", "gauge", "Whether the interface UAPI state could be read.")
	metricHeader(&b, "wg_interface_peers", "gauge", "Number of configured peers.")
	metricHeader(&b, "wg_peer_last_handshake_timestamp_seconds", "gauge", "Unix timestamp of the peer's last handshake, or zero if never.")
	metricHeader(&b, "wg_peer_handshake_age_seconds", "gauge", "Seconds since the peer's last handshake; omitted if never.")
	metricHeader(&b, "wg_peer_rx_bytes_total", "counter", "Bytes received from the peer.")
	metricHeader(&b, "wg_peer_tx_bytes_total", "counter", "Bytes sent to the peer.")
	metricHeader(&b, "wgoctopus_agent_applied_revision", "gauge", "Applied configuration revision.")
	metricHeader(&b, "wgoctopus_agent_build_info", "gauge", "Build information.")
	metricHeader(&b, "wgoctopus_daemon_restarts_total", "counter", "Daemon restarts for the interface.")
	if c.HopStats != nil {
		metricHeader(&b, "wgoctopus_hop_routes", "gauge", "Configured hop routes.")
		metricHeader(&b, "wgoctopus_hop_conntrack_flushed_total", "counter", "Conntrack entries flushed by hop reconciliation.")
		metricHeader(&b, "wgoctopus_hop_conntrack_flush_errors_total", "counter", "Conntrack flush errors during hop reconciliation.")
		metricHeader(&b, "wgoctopus_hop_apply_errors_total", "counter", "Hop reconciliation errors.")
	}

	if c.AppliedRevision != nil {
		fmt.Fprintf(&b, "wgoctopus_agent_applied_revision %d\n", c.AppliedRevision())
	}
	fmt.Fprintf(&b, "wgoctopus_agent_build_info{version=%s,go_version=%s} 1\n", quote(c.Version), quote(c.GoVersion))
	if c.HopStats != nil {
		s := c.HopStats()
		fmt.Fprintf(&b, "wgoctopus_hop_routes %d\nwgoctopus_hop_conntrack_flushed_total %d\nwgoctopus_hop_conntrack_flush_errors_total %d\nwgoctopus_hop_apply_errors_total %d\n", s.Routes, s.FlushedTotal, s.FlushErrorsTotal, s.ApplyErrorsTotal)
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	var interfaces []string
	if c.Interfaces != nil {
		interfaces = append(interfaces, c.Interfaces()...)
	}
	sort.Strings(interfaces)
	for _, name := range interfaces {
		live := uapi.Live{}
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		live, err := c.readLive(callCtx, name)
		cancel()
		up := 0
		if err == nil {
			up = 1
		}
		labels := "interface=" + quote(name)
		fmt.Fprintf(&b, "wg_interface_up{%s} %d\n", labels, up)
		fmt.Fprintf(&b, "wg_interface_peers{%s} %d\n", labels, len(live.Peers))
		if c.Restarts != nil {
			fmt.Fprintf(&b, "wgoctopus_daemon_restarts_total{%s} %d\n", labels, c.Restarts(name))
		}
		if err != nil {
			continue
		}
		keys := make([]string, 0, len(live.Peers))
		for key := range live.Peers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			peer := live.Peers[key]
			peerLabels := labels + ",public_key=" + quote(key)
			handshake := float64(peer.LastHandshakeSec) + float64(peer.LastHandshakeNSec)/1e9
			fmt.Fprintf(&b, "wg_peer_last_handshake_timestamp_seconds{%s} %g\n", peerLabels, handshake)
			if handshake > 0 {
				fmt.Fprintf(&b, "wg_peer_handshake_age_seconds{%s} %g\n", peerLabels, now.Sub(time.Unix(int64(peer.LastHandshakeSec), int64(peer.LastHandshakeNSec))).Seconds())
			}
			fmt.Fprintf(&b, "wg_peer_rx_bytes_total{%s} %d\n", peerLabels, peer.RxBytes)
			fmt.Fprintf(&b, "wg_peer_tx_bytes_total{%s} %d\n", peerLabels, peer.TxBytes)
		}
	}
	return []byte(b.String())
}

// WriteTo renders the metrics and writes them to w.
func (c *Collector) WriteTo(ctx context.Context, w io.Writer) (int64, error) {
	n, err := w.Write(c.Render(ctx))
	return int64(n), err
}

func (c *Collector) readLive(ctx context.Context, name string) (uapi.Live, error) {
	if err := ctx.Err(); err != nil {
		return uapi.Live{}, err
	}
	if c.Device == nil {
		return uapi.Live{}, fmt.Errorf("no device accessor")
	}
	result := make(chan struct {
		live uapi.Live
		err  error
	}, 1)
	go func() {
		device, err := c.Device(name)
		var live uapi.Live
		if err == nil {
			live, err = device.Get()
		}
		result <- struct {
			live uapi.Live
			err  error
		}{live, err}
	}()
	select {
	case <-ctx.Done():
		return uapi.Live{}, ctx.Err()
	case value := <-result:
		return value.live, value.err
	}
}

func metricHeader(b *strings.Builder, name, typ, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func quote(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
	return `"` + s + `"`
}
