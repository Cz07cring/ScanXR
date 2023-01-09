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
	//ProviderFile string "C:\\Users\\czhac\\.config\\subfinder\\provider-config.yaml"
	ProviderFile string `yaml:"provider-file"`
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
