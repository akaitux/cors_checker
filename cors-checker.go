package main

import (
	"errors"
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/sirupsen/logrus"
	"github.com/hidnoiz/cors_checker/config"
	//"github.com/hidnoiz/cors_checker/go-zabbix"
	"encoding/json"
	"github.com/hidnoiz/go-zabbix.git"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

var SIMPLE_METHODS = []string{"GET", "POST", "HEAD"}

// Without content-type
var SIMPLE_HEADERS = []string{"Accept", "Accept-Language", "Content-Language", "DPR", "Downlink", "Save-Data", "Viewport-Width", "Width"}

type request struct {
	resp          *http.Response
	preflightResp *http.Response
	allowedOrigin string
	requestTo     string
	check         *check
}

func (req *request) init(chk *check, requestTo, allowedHost string) {
	req.check = chk
	req.allowedOrigin = allowedHost
	req.requestTo = requestTo
}

type check struct {
	requests *[]*request
	conf     *config.Check
	rootConf *config.Config
	isSimple bool
}

type zbxItemName struct {
	Check string `json:"{#CHECK}"`
}

type zbxDiscoveryData struct {
	Data []zbxItemName `json:"data"`
}

func (chk *check) init(conf *config.Check, rootConf *config.Config) {
	chk.conf = conf
	chk.rootConf = rootConf
	chk.isSimpleSet()
	if chk.conf.Name == "" {
		logrus.Fatalf("Empty 'name' field for one of checks: %v", chk.conf)
	}
	if !chk.isSimple {
		if conf.PreflightMethods == nil {
			logrus.Fatalf("%s: Error. Preflight Methods doesn't exists in config, but request is not simple", conf.RequestTo)
		}
		if conf.PreflightHeaders == nil {
			logrus.Fatalf("%s: Error. Preflight Headers doesn't exists in config, but request is not simple", conf.RequestTo)
		}
	}
	requests := make([]*request, 0, len(chk.conf.AllowedHosts) * len(chk.conf.RequestTo))
	for _, requestTo := range chk.conf.RequestTo {
		for _, allowedHost := range chk.conf.AllowedHosts {
			req := request{}
			req.init(chk, requestTo, allowedHost)
			requests = append(requests, &req)
		}
	}
	chk.requests = &requests
}

func (chk *check) String() string {
	return fmt.Sprintf("<Check %s>", chk.conf.RequestTo)
}

func searchStrSlice(slice *[]string, el string, isCase bool, isTrim bool) bool {
	// Search string in slice. isCase - case-insensitive search, isTrim - removed spaces and \n from strings
	for _, s := range *slice {
		if isCase == true {
			s = strings.ToLower(s)
			el = strings.ToLower(el)
		}
		if isTrim == true {
			s = strings.TrimSpace(s)
			s = strings.Trim(s, "\n")
			el = strings.TrimSpace(el)
			el = strings.Trim(el, "\n")
		}
		if el == s {
			return true
		}
	}
	return false
}

func isResponseValid(resp *http.Response) error {
	// Check if http response exists and status code is valid
	if resp == nil {
		return errors.New("Error in Response, host not available. See the logs above.")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s Response status code >= 400 (%v)", resp.Request.RemoteAddr, resp.StatusCode)
	}
	return nil
}

func isCorsGetValid(req *request) []error {
	// Check is CORS GET request valid. Returned slice of errors.

	// Access-Control-Allow-Origin check
	errs := make([]error, 0, 5)
	acaOrigin := req.resp.Header.Get("Access-Control-Allow-Origin")
	if acaOrigin == "" {
		errs = append(errs, errors.New("GET Access-Control-Allow-Origin is empty"))
	}
	if acaOrigin != req.allowedOrigin && acaOrigin != "*" {
		errs = append(errs, fmt.Errorf("GET Access-Control-Allow-Origin is not the same ('%s' != '%s')", acaOrigin, req.allowedOrigin))
	}
	// Access-Control-Allow-Credentials check
	if req.check.conf.Credentials == true {
		acaCreds := req.resp.Header.Get("Access-Control-Allow-Credentials")
		if acaCreds == "" {
			errs = append(errs, errors.New("GET Access-Control-Allow-Credentials is empty"))
		}
		if acaCreds != "true" {
			errs = append(errs, fmt.Errorf("GET Access-Control-Allow-Credentials is false (%s)", acaCreds))
		}
		if acaOrigin == "*" && acaCreds == "true" {
			errs = append(errs, errors.New("GET Access-Control-Allow-Credentials is true, but Access-Control-Allow-Origin is *"))
		}
	}
	return errs
}

func isCorsOptionsValid(req *request) []error {
	// Check is CORS OPTIONS request valid. Returned slice of errors.

	// Access-Control-Allow-Origin check
	errs := make([]error, 0, 6)
	acaOrigin := req.preflightResp.Header.Get("Access-Control-Allow-Origin")
	if acaOrigin == "" {
		errs = append(errs, errors.New("OPTIONS Access-Control-Allow-Origin is empty"))
	}
	if acaOrigin != req.allowedOrigin && acaOrigin != "*" {
		errs = append(errs, fmt.Errorf("OPTIONS Access-Control-Allow-Origin is not the same ('%s' != '%s')", acaOrigin, req.allowedOrigin))
	}
	// Access-Control-Allow-Credentials check
	if req.check.conf.Credentials == true {
		acaCreds := req.preflightResp.Header.Get("Access-Control-Allow-Credentials")
		if acaCreds == "" {
			errs = append(errs, errors.New("OPTIONS Access-Control-Allow-Credentials is empty"))
		}
		if acaCreds != "true" {
			errs = append(errs, fmt.Errorf("OPTIONS Access-Control-Allow-Credentials is false (%s)", acaCreds))
		}
		if acaOrigin == "*" && acaCreds == "true" {
			errs = append(errs, errors.New("OPTIONS Access-Control-Allow-Credentials is true, but Access-Control-Allow-Origin is *"))
		}
	}
	// Access-Control-Allow-Methods check
	acaMethods := req.preflightResp.Header.Get("Access-Control-Allow-Methods")
	if acaMethods == "" {
		errs = append(errs, errors.New("OPTIONS Access-Control-Allow-Methods is empty"))
	}
	chkMethods := req.check.conf.PreflightMethods
	if chkMethods != nil && acaMethods != "*" {
		acaMethodsSlice := strings.Split(acaMethods, ",")
		for _, method := range chkMethods {
			if !searchStrSlice(&acaMethodsSlice, method, true, true) {
				errs = append(errs, fmt.Errorf("Access-Control-Allow-Methods: method '%s' not in allowed methods (%s)", method, acaMethods))
			}
		}
	}
	// Access-Control-Allow-Headers check
	acaHeaders := req.preflightResp.Header.Get("Access-Control-Allow-Headers")
	if acaHeaders == "" {
		errs = append(errs, errors.New("OPTIONS Access-Control-Allow-Headers is empty"))
	}
	chkHeaders := req.check.conf.PreflightHeaders
	if chkHeaders != nil && acaHeaders != "*" {
		acaHeadersSlice := strings.Split(acaHeaders, ",")
		for _, header := range chkHeaders {
			if !searchStrSlice(&acaHeadersSlice, header, true, true) {
				errs = append(errs, fmt.Errorf("Access-Control-Allow-Headers: header '%s' not in allowed headers (%s)", header, acaHeaders))
			}
		}
	}
	return errs
}

func isValid(req *request) []error {
	// Main func for validating request, causes GET and OPTIONS validation and returned list with errors
	err := isResponseValid(req.resp)
	resultErrors := make([]error, 0, 20)
	if err != nil {
		msg := fmt.Sprintf("%s: %s %v", req.requestTo, req.allowedOrigin, err)
		logrus.Warningln(msg)
		if req.check.rootConf.ErrorIfUnavailable == true {
			resultErrors = append(resultErrors, errors.New(msg))
		}
	} else {
		errs := isCorsGetValid(req)
		if len(errs) != 0 {
			for _, err := range errs {
				logrus.Warningf("%s: %s %v", req.requestTo, req.allowedOrigin, err)
			}
			resultErrors = append(resultErrors, errs...)
		}
	}
	if req.preflightResp != nil {
		err := isResponseValid(req.preflightResp)
		if err != nil {
			msg := fmt.Sprintf("%s: %s %v", req.requestTo, req.allowedOrigin, err)
			logrus.Warningln(msg)
			if req.check.rootConf.ErrorIfUnavailable == true {
				resultErrors = append(resultErrors, errors.New(msg))
			}
		} else {
			errs := isCorsOptionsValid(req)
			for _, err := range errs {
				logrus.Warningf("%s: %s %v", req.requestTo, req.allowedOrigin, err)
			}
			resultErrors = append(resultErrors, errs...)
		}
	}
	return resultErrors
}

func (chk *check) isSimpleSet() {
	// Set check.isSimple variable. Simple request - request without OPTIONS validation
	chk.isSimple = false
	for _, method := range chk.conf.PreflightMethods {
		if !searchStrSlice(&SIMPLE_METHODS, method, true, true) {
			logrus.Debugf("%s Preflight needed. Method %s. Simple methods check", chk.conf.RequestTo, method)
			return
		}
	}
	for _, header := range chk.conf.PreflightHeaders {
		if !searchStrSlice(&SIMPLE_HEADERS, header, true, true) {
			logrus.Debugf("%s Preflight needed. Header: %s. Simple headers check", chk.conf.RequestTo, header)
			return
		}
	}
	chk.isSimple = true
}

func doGetReq(req *request, wg *sync.WaitGroup, goLimit chan struct{}) {
	// Doing GET request and save it to request.resp
	defer wg.Done()
	r, err := http.NewRequest("GET", req.requestTo, nil)
	client := &http.Client{Timeout: time.Second * req.check.rootConf.Timeout}
	if req.check.conf.FollowRedirect == false {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	r.Header.Add("Origin", req.allowedOrigin)
	logrus.Debugf("Request %s (allowedOrigin: %s) ...", req.requestTo, req.allowedOrigin)
	resp, err := client.Do(r)
	<- goLimit 
	if err != nil {
		logrus.Errorf("Error while GET request to '%s' with Origin: '%s'. Error: %v", req.requestTo, req.allowedOrigin, err)
		return
	}
	defer resp.Body.Close()
	req.resp = resp
}

func doOptionsReq(req *request, wg *sync.WaitGroup, goLimit chan struct{}) {
	// Doing OPTIONS request and save it to request.preflightResp
	defer wg.Done()
	r, err := http.NewRequest("OPTIONS", req.requestTo, nil)
	client := &http.Client{Timeout: time.Second * req.check.rootConf.Timeout}
	if req.check.conf.FollowRedirect == false {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	r.Header.Add("Origin", req.allowedOrigin)
	resp, err := client.Do(r)
	<- goLimit 
	if err != nil {
		logrus.Errorf("Error while OPTIONS request to '%s' with allowedOrigin '%s'. Error: %v", req.requestTo, req.allowedOrigin, err)
		return
	}
	defer resp.Body.Close()
	req.preflightResp = resp
}

func doRequests(checks *map[string]check) {
	// Main func for doing requests. Causes GET and POST for requests in check map.
	wg := new(sync.WaitGroup)
	goLimit := make(chan struct{}, 20)
	for _, chk := range *checks {
		for _, req := range *chk.requests {
			goLimit <- struct{}{}
			wg.Add(1)
			go doGetReq(req, wg, goLimit)
			if !chk.isSimple {
				goLimit <- struct{}{}
				wg.Add(1)
				go doOptionsReq(req, wg, goLimit)
			}
		}
	}
	wg.Wait()
}

func sendToZabbix(metrics []*zabbix.Metric, rootConf *config.Config) ([]byte, error) {
	packet := zabbix.NewPacket(metrics)
	zSender := zabbix.NewSender(rootConf.ZbxHost, rootConf.ZbxPort)
	zabbix.AddReserveSocket(zSender, rootConf.ZbxHostReserve, rootConf.ZbxPortReserve)
	res, err := zSender.Send(packet)
	return res, err

}

func zbxCreateDiscovery(checks *map[string]check) string {
	var discoveryData zbxDiscoveryData
	for _, chk := range *checks {
		dataItem := zbxItemName{chk.conf.Name}
		discoveryData.Data = append(discoveryData.Data, dataItem)
	}
	zbxDataJson, err := json.Marshal(discoveryData)
	if err != nil {
		logrus.Fatalf("Error occured while preparing to send zabbix discovery: %v", err)
	}
	return string(zbxDataJson)
}

func zbxSendDiscovery(checks *map[string]check, rootConf *config.Config) ([]byte, error) {
	var metrics []*zabbix.Metric
	discoveryHost := rootConf.ZbxDiscoveryHost
	discoveryKey := rootConf.ZbxDiscoveryKey
	if discoveryHost == "" || discoveryKey == "" {
		logrus.Fatalln("zbx_discovery_host or zbx_discovery_key is empty")
	}
	data := zbxCreateDiscovery(checks)
	metrics = append(metrics, zabbix.NewMetric(discoveryHost, discoveryKey, data))
	return sendToZabbix(metrics, rootConf)
}

//func zbxCreateDate(checks *map[string]check, rootConf *config.Config)

func zbxSendData(checks *map[string]check, rootConf *config.Config) ([]byte, error) {
	var metrics []*zabbix.Metric
	discoveryHost := rootConf.ZbxDiscoveryHost
	discoveryKey := rootConf.ZbxDiscoveryKey
	discoveryItemKey := rootConf.ZbxDiscoveryItemKey
	if discoveryHost == "" || discoveryKey == "" || discoveryItemKey == "" {
		logrus.Fatalln("zbx_discovery_host or zbx_discovery_key or zbx_discovery_item_key is empty")
	}
	//metrics = append(metrics, zabbix.NewMetric(discoveryHost, discoveryKey, data))
	for name, chk := range *checks {
		isErr := false
		requests := chk.requests
		for _, req := range *requests {
			errs := isValid(req)
			if len(errs) > 0 {
				isErr = true
			}
		}
		zbxKey := fmt.Sprintf("%s[%s]", discoveryItemKey, name)
		if isErr == true {
			metrics = append(metrics, zabbix.NewMetric(discoveryHost, zbxKey, "1"))
		} else {
			metrics = append(metrics, zabbix.NewMetric(discoveryHost, zbxKey, "0"))
		}
	}
	return sendToZabbix(metrics, rootConf)
}

func checkZbxResponse(res []byte) bool {
	if strings.Contains(string(res), "response\":\"failed") {
		return false
	}
	if strings.Contains(string(res), "processed: 0") {
		return false
	}
	return true
}

func cliCheck(checks *map[string]check) {
	errMap := make(map[*check][]error)
	for _, chk := range *checks {
		requests := chk.requests
		errorsRes := make([]error, 0, 50)
		for _, req := range *requests {
			errs := isValid(req)
			errorsRes = append(errorsRes, errs...)
		}
		chkP := chk
		errMap[&chkP] = errorsRes
	}
	fmt.Print("\n\n")
	for chk, errs := range errMap {
		fmt.Printf("Check: %s\n", chk.conf.Name)
		for _, requestTo := range chk.conf.RequestTo {
			if len(errs) != 0 {
					fmt.Printf("%s validation \033[0;31mFAILED\033[0m\nErrors:\n", requestTo)
					for _, err := range errs {
						fmt.Printf("\t%v\n", err)
					}
			} else {
				fmt.Printf("%s validation \033[0;32mOK\033[0m\n", requestTo) 
			}
		}
		fmt.Printf("\n\n")
	}
}

func configPathDiscovery() string {
	configPath := "config.yaml"
	if _, err := os.Stat(configPath); os.IsExist(err) {
		return configPath
	}
	exePath, _ := os.Executable()
	exePath = path.Dir(exePath)
	configPath = path.Join(exePath, "config.yaml")
	if _, err := os.Stat(configPath); err == nil {
		return configPath
	}
	exePath, _ = os.Getwd()
	configPath = path.Join(exePath, "config.yaml")
	if _, err := os.Stat(configPath); err == nil {
		return configPath
	}
	return ""
}


func filterRequests(conf config.Check, filter string) []string {
		filteredRequests := make([]string, 0, len(conf.RequestTo))
		for _, r := range conf.RequestTo {
			if r != filter {
				continue
			}
			filteredRequests = append(filteredRequests, r)
		}
		return filteredRequests
}

func main() {
	parser := argparse.NewParser("cors-checker", "")
	confPath := parser.String("c", "conf", &argparse.Options{Required: false, Help: "Path to config yaml file", Default: ""})
	nameFilter := parser.String("n", "name-filter", &argparse.Options{Required: false, Help: "Filter by name"})
	requestToFilter := parser.String("r", "request-to-filter", &argparse.Options{Required: false, Help: "Filter by request-to"})
	isSendToZabbix := parser.Flag("s", "send-to-zabbix", &argparse.Options{Required: false, Default: false})
	isZabbixDiscovery := parser.Flag("d", "zabbix-dicovery", &argparse.Options{Required: false, Default: false})
	isDebug := parser.Flag("", "debug", &argparse.Options{Required: false, Default: false})
	err := parser.Parse(os.Args)
	if err != nil {
		logrus.Fatal(parser.Usage(err))
	}

	if *isDebug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if *confPath == "" {
		*confPath = configPathDiscovery()
	}
	rootConf, err := config.LoadConfig(confPath)
	if err != nil {
		logrus.Fatal(err)
	}

	// Build request objects
	checks := make(map[string]check, len(rootConf.Checks))
	for _, conf := range rootConf.Checks {
		if *nameFilter != "" && *nameFilter!= conf.Name {
			logrus.Debugf("Pass %s", conf.RequestTo)
			continue
		}
		if *requestToFilter != "" {
			conf.RequestTo = filterRequests(conf, *requestToFilter)
		}
		chk := check{}
		confCopy := conf
		chk.init(&confCopy, rootConf)
		checks[conf.Name] = chk
	}

	var zbxAnswer []byte
	if *isSendToZabbix {
		doRequests(&checks)
		zbxAnswer, err = zbxSendData(&checks, rootConf)
	} else if *isZabbixDiscovery {
		zbxAnswer, err = zbxSendDiscovery(&checks, rootConf)
	} else {
		doRequests(&checks)
		cliCheck(&checks)
		return
	}
	logrus.Debugf("Zbx answer: %s", string(zbxAnswer))
	if err != nil || !checkZbxResponse(zbxAnswer) {
		logrus.Fatalf("Error while send data to zabbix, %s", string(zbxAnswer))
	}
}
