package config

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"fmt"
	"time"
	"errors"
)

type Check struct {
	Name             string   `yaml:"name"`
	FollowRedirect   bool 	  `yaml:"follow_redirect"`
	RequestTo        []string `yaml:"request_to"`
	AllowedHosts     []string `yaml:"allowed_hosts"`
	Credentials      bool     `yaml:"credentials"`
	PreflightHeaders []string `yaml:"preflight_headers"`
	PreflightMethods []string `yaml:"preflight_methods"`
}

type Config struct {
	Checks              []Check       `yaml:"checks"`
	Timeout             time.Duration `yaml:"timeout"`
	ZbxHost             string        `yaml:"zbx_host"`
	ZbxPort             int           `yaml:"zbx_port"`
	ZbxHostReserve      string        `yaml:"zbx_host_reserve"`
	ZbxPortReserve      int           `yaml:"zbx_port_reserve" default:"10051" `
	ZbxDiscoveryHost    string        `yaml:"zbx_discovery_host" default:"virt.cors.checker"`
	ZbxDiscoveryKey     string        `yaml:"zbx_discovery_key" default:"disc.cors"`
	ZbxDiscoveryItemKey string        `yaml:"zbx_discovery_item_key" default:"cors.check"`
	ErrorIfUnavailable	bool		  `yaml:"error_if_unavailable"`
}

func LoadConfig(path *string) (*Config, error) {
	var err error
	if *path == "" {
		err = errors.New("Error while open config file. Filepath is empty")
		return nil, err
	}
	yamlFile, err := ioutil.ReadFile(*path)
	if err != nil {
		err = fmt.Errorf("Error while open config file %s. Error: %s", *path, err.Error())
		return nil, err
	}
	conf := Config{}
	err = yaml.Unmarshal(yamlFile, &conf)
	if err != nil {
		err = fmt.Errorf("Error while parse %s %s", *path, err.Error())
		return nil, err
	}
	if conf.ZbxDiscoveryHost == "" {
		conf.ZbxDiscoveryHost = "virt.cors.checker"
	}
	if conf.ZbxDiscoveryKey == "" {
		conf.ZbxDiscoveryKey = "disc.cors"
	}
	if conf.ZbxDiscoveryItemKey == "" {
		conf.ZbxDiscoveryItemKey = "cors.check"
	}
	if conf.ZbxPort == 0 {
		conf.ZbxPort = 10051
	}
	if conf.ZbxPortReserve == 0 {
		conf.ZbxPortReserve = 10051
	}
	return &conf, nil

}
