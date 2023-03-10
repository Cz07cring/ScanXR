package config

import (
	"github.com/ysmood/leakless/pkg/utils"
	"gopkg.in/yaml.v2"
	"log"
)

//加载config配置文件（加载器）
type Config struct {
	Domainscan DomainScan `yaml:"domainscan"`
}

//加载config配置对应数据
type DomainScan struct {
	ProviderFile       string `yaml:"provider-file"`
	SubnextFile        string `yaml:"subnext-file"`
	SubdomainFile      string `yaml:"subdomain-file"`
	SubdomainFileSmall string `yaml:"subdomainsmall-file"` //扩大域名收集攻击面加载域名小字典防止报错
	SubdomainData      []string
	SubnextData        []string
	SubdomainDataSmall []string
}

//config文件配置
const configFile = "config.yaml"

var Worker Config

//初始化yaml配置文件
func init() {
	bytes, err := utils.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(bytes, &Worker)
	if err != nil {
		log.Fatal(err)
	}
}
