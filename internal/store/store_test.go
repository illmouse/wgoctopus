package store

import (
	"github.com/illmouse/wgoctopus/internal/state"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	in := state.State{Revision: 7}
	if e := s.Save(in); e != nil {
		t.Fatal(e)
	}
	got, e := s.Load()
	if e != nil || got.Revision != 7 {
		t.Fatalf("got %#v, %v", got, e)
	}
}
