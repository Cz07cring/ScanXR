package Subfinder

import (
	//"ScanX/pkg/domainscan/subfinder"
	"fmt"
	"github.com/projectdiscovery/gologger"
)

type Options struct {
	ProviderConfig string
}
type Result struct {
	Domain string
	Ip     string
	Cdn    bool
}
type Runner struct {
	options *Options
}

func NewRunner(options *Options) (*Runner, error) {
	return &Runner{
		options: options,
	}, nil
}
func (r *Runner) Run(domains []string) (results []*Result) {
	for _, domain := range domains {
		results = append(results, r.RunEnumeration(domain)...)
	}
	return
}
func (r *Runner) RunEnumeration(domain string) (results []*Result) {
	gologger.Info().Msgf("开始子域名扫描: %v", domain)
	// 被动收集,subfinder
	gologger.Info().Msgf("被动收集...")
	domains, err := EnumerateSubdomains([]string{domain}, r.options.ProviderConfig)
	if err != nil {
		fmt.Println(err)
		return
	}
	gologger.Info().Msgf("subfinder: %v", domains)
	//	domains = append(domains, domain)
	return
}
