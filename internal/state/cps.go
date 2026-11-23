package state

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var cpsPattern = regexp.MustCompile(`^(<(b 0x([0-9a-fA-F]{2})*|t|c|r [0-9]+|rc [0-9]+|rd [0-9]+|d|ds|dz)>)+$`)

func validateCPS(name, value string) error {
	if value == "" {
		return nil
	}
	invalid := func() error { return fmt.Errorf("%s has invalid CPS syntax", name) }
	if len(value) > 4096 || !cpsPattern.MatchString(value) {
		return invalid()
	}
	for _, packet := range strings.Split(value[1:len(value)-1], "><") {
		parts := strings.SplitN(packet, " ", 2)
		if parts[0] == "r" || parts[0] == "rc" || parts[0] == "rd" {
			n, err := strconv.ParseUint(parts[1], 10, 16)
			if err != nil || n == 0 {
				return invalid()
			}
		}
	}
	return nil
}
