package Subfinder

import (
	"bufio"
	"bytes"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"io"
	"log"
	"strings"
)

type resultDomain struct {
	m []string
}

func (r *resultDomain) Write(p []byte) (n int, err error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(p))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		r.m = append(r.m, scanner.Text())
	}
	n = len(p)
	err = nil
	return
}
func (r *resultDomain) Output() (output []string) {
	return r.m
}

//调用subfinder 寻找域名
func EnumerateSubdomains(domain []string, ProviderConfig string) (output []string, err error) {
	options := runner.Options{
		Verbose:            true,
		ProviderConfig:     ProviderConfig,
		All:                true,
		Threads:            10,                       // Thread controls the number of threads to use for active enumerations
		Timeout:            30,                       // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10,                       // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers, // Use the default list of resolvers by marshaling it to the config
		ResultCallback: func(s *resolve.HostEntry) { // Callback function to execute for available host
			log.Println(s.Host, s.Source)
		},
	}
	err = runner.UnmarshalFrom(options.ProviderConfig)
	if err != nil {
		return
	}
	buf := resultDomain{}
	runnerInstance, err := runner.NewRunner(&options)
	if err != nil {
		return
	}
	err = runnerInstance.EnumerateMultipleDomains(strings.NewReader(strings.Join(domain, "\n")), []io.Writer{&buf})
	if err != nil {
		log.Fatal(err)
	}
	return buf.Output(), nil

}
