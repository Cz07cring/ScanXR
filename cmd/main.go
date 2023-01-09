package main

import (
	"ScanX/config"
	"ScanX/pkg/domainscan"
	"github.com/projectdiscovery/gologger"
)

var (
	targets []string
)

func workflow(domain []string) {
	options := domainscan.Options{ProviderConfig: config.Worker.Domainscan.ProviderFile}
	domainscanRunner, err := domainscan.NewRunner(&options)
	if err != nil {
		gologger.Error().Msgf("domainscan.NewRunner() err, %v", err)
		return
	}
	domainscanRunner.Run(domain)

}

func main() {
	var domain = []string{
		"2100w.cn",
	}
	workflow(domain)
}
