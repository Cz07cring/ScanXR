package main

import "github.com/Cz07cring/ScanXR/core"

var (
	targets []string
)

func main() {
	var domain = []string{
		"projectdiscovery.io",
	}
	core.Domainscan_start(domain)
}
