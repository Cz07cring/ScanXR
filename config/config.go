package config

import (
	"github.com/ysmood/leakless/pkg/utils"
	"gopkg.in/yaml.v2"
	"log"
)

type Config struct {
	Domainscan DomainScan `yaml:"domainscan"`
}
type DomainScan struct {
	ProviderFile  string `yaml:"provider-file"`
	SubdomainFile string `yaml:"subdomain-file"`
	SubdomainData []string
}

const configFile = "config.yaml"

var Worker Config

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
