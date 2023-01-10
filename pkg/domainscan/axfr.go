package domainscan

import (
	"errors"
	"github.com/miekg/dns"
	"strings"
)

// AXFR attempts a zone transfer for the domain.
// return dns server| result | error
func AXFR(serverAddr string, domain string) ([]string, map[string][]dns.RR, error) {
	servers, err := LookupNS(domain, serverAddr)
	if err != nil {
		return nil, nil, err
	}
	for i, s := range servers {
		servers[i] = strings.TrimRight(s, ".")
	}
	result := make(map[string][]dns.RR)
	for _, s := range servers {
		tr := dns.Transfer{}
		m := &dns.Msg{}
		m.SetAxfr(dns.Fqdn(domain))
		in, err := tr.In(m, s+":53")
		if err != nil {
			continue
		}
		for ex := range in {
			if len(ex.RR) > 0 {
				result[s] = ex.RR
			}
			//for _, a := range ex.RR {
			//	var hostname string
			//	fmt.Println(a.String())
			//	switch v := a.(type) {
			//	case *dns.A:
			//		hostname = v.Hdr.Name
			//	case *dns.AAAA:
			//		hostname = v.Hdr.Name
			//	case *dns.PTR:
			//		hostname = v.Ptr
			//	case *dns.NS:
			//		hostname = v.Ns
			//	case *dns.CNAME:
			//		hostname = v.Hdr.Name
			//	case *dns.SRV:
			//		hostname = v.Target
			//	default:
			//		continue
			//	}
			//	fmt.Println(strings.TrimRight(hostname, "."))
			//}
		}
	}
	return servers, result, nil
}

func GetAxfrReuults(m map[string][]dns.RR) []string {
	// 数组默认长度为map长度,后面append时,不需要重新申请内存和拷贝,效率很高
	j := 0
	keys := make([]string, len(m))
	for k := range m {
		keys[j] = k
		j++
	}
	return keys
}

// LookupNS returns the names servers for a domain.
func LookupNS(domain, serverAddr string) ([]string, error) {
	servers := []string{}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return servers, err
	}
	if len(in.Answer) < 1 {
		return servers, errors.New("no Answer")
	}
	for _, a := range in.Answer {
		if ns, ok := a.(*dns.NS); ok {
			servers = append(servers, ns.Ns)
		}
	}
	return servers, nil
}
