package core

import (
	"fmt"
	"github.com/Cz07cring/ScanXR/config"
	"github.com/Cz07cring/ScanXR/internal/utils"
	"github.com/Cz07cring/ScanXR/pkg/domainscan"
	"github.com/projectdiscovery/gologger"
)

//扫描domain
func Domainscan_start(domain []string) error {
	var err error
	if config.Worker.Domainscan.SubdomainData, err = utils.ReadLines(config.Worker.Domainscan.SubdomainFile); err != nil {
		return err
	}
	if config.Worker.Domainscan.SubdomainDataSmall, err = utils.ReadLines(config.Worker.Domainscan.SubdomainFileSmall); err != nil {
		return err
	}
	if config.Worker.Domainscan.SubnextData, err = utils.ReadLines(config.Worker.Domainscan.SubnextFile); err != nil {
		return err
	}
	options := domainscan.Options{
		Layer:              0,
		SubnextData:        config.Worker.Domainscan.SubnextData,
		ProviderConfig:     config.Worker.Domainscan.ProviderFile,  //加载subfinder配置文件
		SubdomainData:      config.Worker.Domainscan.SubdomainData, //加载子域名字典
		SubdomainDataSmall: config.Worker.Domainscan.SubdomainDataSmall,
	}
	//加载domainscan run配置文件
	domainscanRunner, err := domainscan.NewRunner(&options)
	if err != nil {
		gologger.Error().Msgf("domainscan.NewRunner() err, %v", err)
		return err
	}
	//加载domainscan 启动扫描并且返回results数据
	results := domainscanRunner.Run(domain)
	for _, i2 := range results {
		fmt.Println(i2.Domain)
	}
	return err
}
