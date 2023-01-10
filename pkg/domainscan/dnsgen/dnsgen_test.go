package dnsgen

import "testing"

func TestRun(t *testing.T) {
	s := Dnsgen("2100w.cn", []string{"www", "test"})
	for i, i2 := range s {
		t.Log(i, i2)
	}
}
