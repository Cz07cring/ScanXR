package main

import (
	"ScanX/config"
	"ScanX/pkg/domainscan/subfinder"
	"github.com/projectdiscovery/gologger"
)

var (
	targets []string
)

func workflow(domain []string) {
	options := Subfinder.Options{ProviderConfig: config.Worker.Domainscan.ProviderFile}
	domainscanRunner, err := Subfinder.NewRunner(&options)
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
