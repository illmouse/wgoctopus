package store

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/illmouse/wgoctopus/internal/state"
)

type Store struct{ Dir string }

func (s Store) Save(v state.State) error {
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.Dir, ".state-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(name, filepath.Join(s.Dir, "state.json"))
}
func (s Store) Load() (state.State, error) {
	b, e := os.ReadFile(filepath.Join(s.Dir, "state.json"))
	if e != nil {
		return state.State{}, e
	}
	var v state.State
	e = json.Unmarshal(b, &v)
	return v, e
}
