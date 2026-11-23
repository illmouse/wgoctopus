package state

import (
	"strings"
	"testing"
)

func TestValidateCPS(t *testing.T) {
	for _, value := range []string{"", "<r 10>", "<b 0xdeadbeef><r 5><t>", "<rc 8><rd 4><c><d><ds><dz>", "<b 0x>"} {
		t.Run("valid/"+value, func(t *testing.T) {
			if err := validateCPS("wg0", value); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, value := range []string{"abc", "<x>", "<r>", "<r 0>", "<r 70000>", "<b 0xABC>", "<r 1x>", "<r 5> trailing", strings.Repeat("x", 4097), "<zz-secret-marker>"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			err := validateCPS("wg0", value)
			if err == nil {
				t.Fatal("accepted invalid CPS")
			}
			if strings.Contains(err.Error(), value) {
				t.Fatal("error contains input value")
			}
		})
	}
}
