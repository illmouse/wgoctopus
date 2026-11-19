// Package manager coordinates daemon, link, UAPI, firewall, and state-store operations.
package manager

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/illmouse/wgoctopus/internal/metrics"
	"github.com/illmouse/wgoctopus/internal/netsetup"
	"github.com/illmouse/wgoctopus/internal/reconcile"
	"github.com/illmouse/wgoctopus/internal/state"
	"github.com/illmouse/wgoctopus/internal/store"
	"github.com/illmouse/wgoctopus/internal/uapi"
)

// Supervisor operates managed daemons. SetOnRestart wires restart recovery.
type Supervisor interface {
	Start(context.Context, string) error
	Stop(string) error
	StopAll() error
	Names() []string
	Restarts(string) uint64
	SetOnRestart(func(string))
}

// Store persists the last completely applied state.
type Store interface {
	Load() (state.State, bool, error)
	Save(state.State) error
}

// DeviceFactory returns the UAPI device for an interface.
type DeviceFactory func(name string) uapi.Device

// Manager serializes all operations that mutate managed interfaces.
type Manager struct {
	Daemons   Supervisor
	Links     netsetup.Link
	Firewall  netsetup.Firewall
	Store     Store
	SocketDir string
	Device    DeviceFactory
	After     func(time.Duration) <-chan time.Time

	mu              sync.Mutex
	stateMu         sync.RWMutex
	desired         state.State
	appliedRevision int64
	checksum        string
}

// FileStore adapts the filesystem store to Manager's presence-aware store API.
type FileStore struct{ Store store.Store }

// Load reports whether a persisted state file exists.
func (s FileStore) Load() (state.State, bool, error) {
	v, err := s.Store.Load()
	if errors.Is(err, os.ErrNotExist) {
		return state.State{}, false, nil
	}
	return v, err == nil, err
}

// Save persists state using the production store.
func (s FileStore) Save(v state.State) error { return s.Store.Save(v) }

// Apply implements api.Applier.
func (m *Manager) Apply(v state.State, allowDangerous bool) error {
	return m.ApplyContext(context.Background(), v, allowDangerous)
}

// ApplyContext applies a complete desired state, honoring caller cancellation.
func (m *Manager) ApplyContext(ctx context.Context, v state.State, allowDangerous bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := v.Validate(); err != nil {
		return err
	}
	interfaces := append([]state.Interface(nil), v.Interfaces...)
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Name < interfaces[j].Name })
	wanted := make(map[string]bool, len(interfaces))
	var errs []error
	for _, in := range interfaces {
		wanted[in.Name] = true
		if err := m.applyInterface(ctx, in, allowDangerous); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", in.Name, err))
		}
	}
	if m.Daemons != nil {
		for _, name := range m.Daemons.Names() {
			if wanted[name] {
				continue
			}
			if m.Firewall != nil {
				if err := m.Firewall.Remove(name); err != nil {
					errs = append(errs, fmt.Errorf("%s firewall removal: %w", name, err))
					continue
				}
			}
			if m.Links != nil {
				if err := m.Links.Delete(name); err != nil {
					errs = append(errs, fmt.Errorf("%s link removal: %w", name, err))
					continue
				}
			}
			if err := m.Daemons.Stop(name); err != nil {
				errs = append(errs, fmt.Errorf("%s daemon stop: %w", name, err))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if m.Store != nil {
		if err := m.Store.Save(v); err != nil {
			return err
		}
	}
	m.stateMu.Lock()
	m.desired = v
	m.appliedRevision = int64(v.Revision)
	m.checksum = v.Checksum()
	m.stateMu.Unlock()
	return nil
}

func (m *Manager) applyInterface(ctx context.Context, in state.Interface, allow bool) error {
	if m.Daemons != nil {
		if err := m.Daemons.Start(ctx, in.Name); err != nil {
			return err
		}
	}
	if m.Links != nil {
		if err := m.Links.EnsureUp(in.Name, in.Address, in.MTU); err != nil {
			return err
		}
	}
	dev := uapi.Device(uapi.Client{Socket: filepath.Join(m.socketDir(), in.Name+".sock")})
	if m.Device != nil {
		dev = m.Device(in.Name)
	}
	if err := reconcile.Apply(dev, in, allow); err != nil {
		return err
	}
	if m.Firewall != nil {
		prefix, err := netip.ParsePrefix(in.Address)
		if err != nil {
			return err
		}
		err = m.Firewall.Ensure(netsetup.FirewallSpec{Name: in.Name, ClientSubnet: prefix.Masked().String(), EgressIface: in.EgressInterface, SNATIP: in.SNATIP})
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) socketDir() string {
	if m.SocketDir != "" {
		return m.SocketDir
	}
	return "/var/run/amneziawg"
}

// RegisterRestartHandler connects daemon restarts to targeted state reapplication.
func (m *Manager) RegisterRestartHandler() {
	if m.Daemons != nil {
		m.Daemons.SetOnRestart(m.OnRestart)
	}
}

// OnRestart reapplies the last successfully persisted configuration for name.
func (m *Manager) OnRestart(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, in := range m.desired.Interfaces {
		if in.Name == name {
			_ = m.applyInterface(context.Background(), in, false)
			return
		}
	}
}

// Boot loads persisted state and retries failed application until success or cancellation.
func (m *Manager) Boot(ctx context.Context, interval time.Duration) error {
	if m.Store == nil {
		return nil
	}
	v, found, err := m.Store.Load()
	if err != nil || !found {
		return err
	}
	// The persisted configuration is the desired state immediately, even while
	// the runtime is unavailable and application is being retried.
	m.stateMu.Lock()
	m.desired = v
	m.appliedRevision = int64(v.Revision)
	m.checksum = v.Checksum()
	m.stateMu.Unlock()
	for {
		if err := m.ApplyContext(ctx, v, true); err == nil {
			return nil
		}
		var wait <-chan time.Time
		if m.After != nil {
			wait = m.After(interval)
		} else {
			timer := time.NewTimer(interval)
			defer timer.Stop()
			wait = timer.C
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait:
		}
	}
}

// Shutdown stops daemons only. Firewall rules remain until idempotently rebuilt at boot.
func (m *Manager) Shutdown() error {
	if m.Daemons != nil {
		return m.Daemons.StopAll()
	}
	return nil
}

// AppliedRevision returns the desired revision, including persisted state being retried at boot.
func (m *Manager) AppliedRevision() int64 {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.appliedRevision
}

// Checksum returns the checksum of the last completely saved state.
func (m *Manager) Checksum() string { m.stateMu.RLock(); defer m.stateMu.RUnlock(); return m.checksum }

// Applied returns the last successfully applied state.
func (m *Manager) Applied() state.State {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.desired
}

// LiveSource adapts the configured device factory for metrics collection.
type LiveSource struct{ Device DeviceFactory }

// Live reads one interface's current device state.
func (s LiveSource) Live(name string) (uapi.Live, error) {
	if s.Device == nil {
		return uapi.Live{}, fmt.Errorf("no device factory")
	}
	return s.Device(name).Get()
}

// Collector builds the metrics collector with manager-backed inputs.
func (m *Manager) Collector() *metrics.Collector {
	return &metrics.Collector{Interfaces: func() []string {
		if m.Daemons == nil {
			return nil
		}
		return m.Daemons.Names()
	}, Device: func(name string) (uapi.Device, error) {
		if m.Device != nil {
			return m.Device(name), nil
		}
		return uapi.Client{Socket: filepath.Join(m.socketDir(), name+".sock")}, nil
	}, AppliedRevision: m.AppliedRevision, Restarts: func(name string) uint64 {
		if m.Daemons == nil {
			return 0
		}
		return m.Daemons.Restarts(name)
	}}
}
