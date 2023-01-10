//fork https://github.com/7dog7/RuleSubDomain
package dnsgen

import (
	"github.com/projectdiscovery/gologger"
	"strings"
	//"strings"
)

//根据域名新规则扩大攻击面
func Dnsgen(domain string, SubdomainData []string) []string {
	gologger.Info().Msgf("开始根据域名结合字典生产新数据扩大攻击面...")
	resultLists := []string{}
	domainIndex := strings.Index(domain, ".")
	ruleList := []string{"{sub}{domain}", "{domain}{sub}",
		"{sub}{rule}{domain}",
		"{domain}{rule}{sub}",
		"{domain}.{sub}",
		"{sub}.{domain}"} //规则列表
	ruleData := []string{"-", ".", "_"}
	//datum序号
	for datum := range SubdomainData {
		for s := range ruleList {
			for list := range ruleData {

				resultList := strings.Replace(ruleList[s], "{sub}", SubdomainData[datum], -1)
				resultList = strings.Replace(resultList, "{domain}", domain[:domainIndex], -1)
				resultList = strings.Replace(resultList, "{rule}", ruleData[list], -1)
				resultLists = append(resultLists, resultList)

			}
		}

	}
	gologger.Info().Msgf("域名字典生产完成...")
	return resultLists

}
