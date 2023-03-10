package main

import (
	"github.com/Cz07cring/ScanXR/core"
	"github.com/projectdiscovery/gologger"
)

var (
	targets []string
)

func main() {
	var domain = []string{
		"2100w.cn",
	}
	err := core.Domainscan_start(domain)
	if err != nil {
		gologger.Error().Msgf("domainscan.NewRunner() err, %v", err)
	}
}
