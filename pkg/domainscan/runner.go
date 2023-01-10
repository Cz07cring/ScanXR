package domainscan

import (
	//"github.com/Cz07cring/ScanXR/internal/utils"
	"github.com/Cz07cring/ScanXR/internal/utils"
	ksubdomain "github.com/Cz07cring/ScanXR/pkg/domainscan/ksudomain"
	"github.com/Cz07cring/ScanXR/pkg/domainscan/subfinder"
	//"ScanX/pkg/domainscan/subfinder"
	"fmt"
	"github.com/projectdiscovery/gologger"
)

//Options 配置文件
type Options struct {
	Layer          int
	ProviderConfig string
	SubdomainData  []string
	CdnIpData      []string
	CdnCnameData   []string
	SubnextData    []string
}

//返回结果
type Result struct {
	Domain string
	Ip     string
	Cdn    bool
}

//加载doaminscan配置文件
type Runner struct {
	options *Options
}

// 创建一个新的newrunner 实例
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

//domainscan run扫描主函数
func (r *Runner) RunEnumeration(domain string) (results []*Result) {

	// 被动收集,subfinder
	gologger.Info().Msgf("被动收集...")
	//调用subfinder的run函数
	domains, err := Subfinder.EnumerateSubdomains([]string{domain}, r.options.ProviderConfig)
	if err != nil {
		fmt.Println(err)
		return
	}
	gologger.Info().Msgf("subfinder: %v", domains)
	domains = append(domains, domain)
	var isWildcard bool
	if CheckWildcard(domain) {
		isWildcard = true
		gologger.Info().Msgf("存在泛解析: %v", domain)
	} else {
		for _, sub := range r.options.SubdomainData {
			domains = append(domains, sub+"."+domain)

		}
		domains = utils.RemoveDuplicate(domains)
		if r.options.Layer > 1 {
			domainss := domains
			for _, sub2 := range r.options.SubnextData {
				for _, d := range domainss {
					domains = append(domains, sub2+"."+d)
				}
			}
		}
	}
	gologger.Info().Msgf("开始DNS解析: %v", len(domains))
	result, err := ksubdomain.Run(domains, "500000k")
	gologger.Info().Msgf("ksubdomain结果: %v", len(result))
	if isWildcard {
		for _, r2 := range result {
			tmpRes := Result{
				Domain: r2.Host,
				Ip:     r2.IP,
				Cdn:    r.CheckCDN(r2.IP),
			}
			results = append(results, &tmpRes)
			gologger.Silent().Msgf(fmt.Sprintf("%v => %v => %v", tmpRes.Domain, tmpRes.Ip, tmpRes.Cdn))
		}
	}

	gologger.Info().Msgf("扫描结束")

	return
}
