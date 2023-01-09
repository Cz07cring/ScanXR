package main

import (
	"pkg/domainscan/subfinder"
)

func workflow(domain string) {
	EnumerateSubdomains(domain)
}

func main() {
	var domain = []string{
		"baidu.com",
	}
	workflow(domain)
}
