package core

import "fmt"
import (
	"github.com/Cz07cring/ScanXR/config"
	"github.com/Cz07cring/ScanXR/pkg/domainscan"
	"github.com/projectdiscovery/gologger"
)

func Domainscan_start(domain []string) {

	options := domainscan.Options{
		ProviderConfig: config.Worker.Domainscan.ProviderFile,  //加载subfinder配置文件
		SubdomainData:  config.Worker.Domainscan.SubdomainData, //加载子域名字典
	}
	domainscanRunner, err := domainscan.NewRunner(&options)
	if err != nil {
		gologger.Error().Msgf("domainscan.NewRunner() err, %v", err)
		return
	}
	results := domainscanRunner.Run(domain)
	for _, i2 := range results {
		fmt.Println(i2.Domain)
	}
}
