package httpx

import "testing"

func TestRun(t *testing.T) {
	run([]string{"2100w.cn"}, "targetDomains.json")
}
