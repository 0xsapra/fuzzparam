package main

import (
	"bufio"
	"math/rand"
	"errors"
	"crypto/tls"
	"sync"
	"net/url"
	"os"
	"flag"
	"fmt"
	"net"
	"io/ioutil"
	"strings"
	"net/http"
	"time"
)

// usage
// echo "site.com\nomega.com" | go run fuzzparam.go -H "Cookie: cok" -H "X-F: 1" -X POST 
// go run fuzzparam.go -H "Cookie: cok" -H "X-Forward-For: 1" -H "Host: whtever.com" -X POST site.com 

type arrayFlags []string
func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var HttpHeaders arrayFlags // Http headers
var RequestMethod string // GET/POST
var WordlistPath string // path to wordlist
var ProxyUrl string // proxy url 
var Concurrency int
var ParametersList []string
var SiteLengthMap = map[string]int{} // {site: 0, site2: 1200} (content length)
// var SiteParamsMap = map[string][](map[string]string{}){} // {site: [{param1:val}, {param2:val} ... ] }
var SiteParamsMap =  make(map[string]map[string]string) // {site: [{param1:val}, {param2:val} ... ] }
var SiteStatusMap = make(map[string]string)
const letters = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const SITE_THREADS = 4

var correctStatus = map[string]bool{
	"200 OK": true,
	"400 ": true,
	"302 Found": true,
	"400 Bad Request": true,
	"500 " : true,
	"404 " : true,
	"404 Not Found": true,
}

func main() {
	var domains []string
	// Concurrency needed
	flag.IntVar(&Concurrency, "c", 20, "set the concurrency level (split equally between HTTPS and HTTP requests)")
	// Http headers
	flag.Var(&HttpHeaders, "H", "add extra http headers")
	// HTTP request method
	flag.StringVar(&RequestMethod, "X", "GET", "HTTP request method GET/POST/PUT")
	// Wordlist to use
	flag.StringVar(&WordlistPath, "w", "/usr/share/dict/words", "Location of wordlist")
	// proxy url
	flag.StringVar(&ProxyUrl, "x", "", "Proxy url in format-> http://127.0.0.1:8080")
	
	flag.Parse()
	
	if flag.NArg() > 0 {
		domains = []string{flag.Arg(0)}
	} else {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			domains = append(domains, s.Text())
		}
	}
	// start := time.Now()
	ParamMiner(domains, Concurrency, HttpHeaders, RequestMethod, WordlistPath);
	// elapsed := time.Since(start)
	// fmt.Println(elapsed)
}

func readWordlist (loction string) ([]string, error){
	file, err := os.Open(loction)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var lines []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }
    return lines, scanner.Err()
}

func ParamMiner(domains []string, concurrency int, headers []string, method string, wordlistPath string) {
	// fmt.Println(concurrency, headers, method, domains, wordlistPath)

	timeout := time.Duration(10000 * 1000000) // 10 seconds
	mainWG := &sync.WaitGroup{}
	findParamWG := &sync.WaitGroup{}
	channelDomain := make(chan string)
	ParametersList, err := readWordlist(wordlistPath)
	var tr *http.Transport;

	if err != nil {
		fmt.Println("Error! Wordlist file doesnt exist.")
		panic(err)
	}
	
	if ProxyUrl != "" {
		if proxyUrlParsed, err := url.Parse(ProxyUrl); err != nil || proxyUrlParsed.Scheme != "http" {
			fmt.Println("Invalid proxy url. Use format - http://127.0.0.1:8080 ")
			fmt.Println(err)
			os.Exit(1)

		} else {
			tr = &http.Transport{
				MaxIdleConns:      30,
				IdleConnTimeout:   time.Second,
				DisableKeepAlives: true,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				Proxy: http.ProxyURL(proxyUrlParsed),
				DialContext: (&net.Dialer{
					Timeout:   timeout,
					KeepAlive: time.Second,
				}).DialContext,
			}
		}
	} else {
		tr = &http.Transport{
			MaxIdleConns:      30,
			IdleConnTimeout:   time.Second,
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: time.Second,
			}).DialContext,
		}
	}
	

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       timeout,
	}
	// find stability and lengths of domains
	for _, domain := range(domains) {

		qs := getQueryString(domain) // map{string}{string}
		formattedDomain := formatDomain(domain)
		if formattedDomain == "" {
			fmt.Errorf("Error : Found invalid domain %s. Skipping it", domain)
			continue;
		}
		SiteParamsMap[formattedDomain] = qs

		mainWG.Add(1)

		go func (client *http.Client, domain string, method string, headers []string) {
			defer mainWG.Done()
			length, problem := checkStability(client, domain, method, headers)
			if problem {
				SiteLengthMap[domain] = -1
			} else {
				SiteLengthMap[domain] = length
			}
		}(client, formattedDomain, method, headers)
		
		mainWG.Wait()
	}

	// fmt.Println(SiteLengthMap)

	for i:=0; i < SITE_THREADS; i++ { // 4 websites at a time
		findParamWG.Add(1)

		go func () {
			for domain := range channelDomain {
				var params []string
				if SiteLengthMap[domain] != -1 {
					params = findParams( client, method, headers, domain, ParametersList)
				} else {
					params = make([]string, 0)
				}
				printParamsFound(domain, params)
			}
			findParamWG.Done()
		}()

	}
	for domain, _ := range(SiteLengthMap) {
		channelDomain <- domain
	}

	close(channelDomain)
	findParamWG.Wait()
}

func printParamsFound(domain string, params []string) {

	u, err := url.Parse(domain)
	if err != nil {
        panic(err)
	}
	q := u.Query()
	for param, value := range SiteParamsMap[domain] {
		q.Set(param, value)
	}
	for _, param := range params {
		q.Set(param, "1")
	}
	u.RawQuery = q.Encode()
	
	fmt.Println(u.String())
}

func findParams(client *http.Client, method string, headers []string,  domain string, completeParamList []string) []string {
	max_params := findMaxParams(client, method, headers, domain)
	multiParamFindSG := &sync.WaitGroup{}
	paramsSendChannel := make(chan []string)
	foundParams := []string{}
	mutex := &sync.Mutex{}

	if max_params == 0 {
		return make([]string, 0)
	}

	for i:=0; i<Concurrency/SITE_THREADS; i++ {
		multiParamFindSG.Add(1)

		go func() {
			for partialParamList := range paramsSendChannel {
				tempParamsFound := findParamsHelper(client, method, headers, domain, 0, len(partialParamList) - 1, partialParamList)
				if len(tempParamsFound) > 0 {
					mutex.Lock()
					foundParams = append(foundParams, tempParamsFound...)
					mutex.Unlock()
				}
			}
			multiParamFindSG.Done()
		}()
	}

	var i = 0
	for i=0; i<len(completeParamList)/max_params; i++ {
		paramsSendChannel <- completeParamList[i*max_params: (i+1)*max_params]
	}
	paramsSendChannel <- completeParamList[i*max_params: len(completeParamList)]

	close(paramsSendChannel)
	multiParamFindSG.Wait()

	return foundParams
	
}

func findMaxParams(client *http.Client, method string, headers []string,  domain string) int {
	tryNumberOfParams := []int{800, 700, 600, 500, 400, 300, 200, 100, 50, 25, 10};
	maxParams := 0

	for _, totalParams := range(tryNumberOfParams) {
		tempParamList := make([]string, totalParams)

		for i:=0; i<totalParams; i++ {
			tempParamList[i] = getRandomString(5)
		}

		tempDomain := addQueryParamsToURL(domain, tempParamList)
		if statusCode, err := HttpRequestGetResponseStatus(client, tempDomain, method, headers); err == nil {
			// if response == 414 continue
			// if response == 200 this is our max params. break
			// if response == other continue
			if statusCode == "414 Request-URI Too Long" {
				continue
			} else if value, found := SiteStatusMap[domain]; found && value == statusCode {
				maxParams = totalParams
				break
			} else {
				continue
			}
		}
	}
	return maxParams

}

func findParamsHelper(client *http.Client, method string, headers []string,  domain string, start, end int, paramList []string) []string {

	numElem := (end + start) + 1
	mid := numElem / 2

	var newLeft, newRight, newLeft1, newRight1 int
	var tempDomainLeft, tempDomainRight string
	resultRight := make([]string, 0)
	resultLeft :=  make([]string, 0)

	if start >= end {
		// tempDomain := addQueryParamsToURL(domain,  paramList[start:end+1])
		// fmt.Println("found>>",tempDomain)
		return paramList[start:end+1]
	}

	tempDomainLeft = addQueryParamsToURL(domain,  paramList[start:mid])
	tempDomainRight = addQueryParamsToURL(domain,  paramList[mid:end+1])

	if tempDomainLeftResult, err := requestAndFindParam(client, domain, tempDomainLeft, method, headers); tempDomainLeftResult && err == nil {
		newLeft = start
		newRight = mid-1
		resultLeft = findParamsHelper(client, method, headers, domain, newLeft, newRight, paramList)
	}
	
	if tempDomainRightResult, err := requestAndFindParam(client, domain, tempDomainRight, method, headers); tempDomainRightResult && err == nil {
		newLeft1 = mid
		newRight1 = end
		resultRight = findParamsHelper(client, method, headers, domain, newLeft1, newRight1, paramList)
	} 

	return append(resultLeft, resultRight...)
}

func requestAndFindParam(client *http.Client, domain, domainWithParams string, method string, headers []string) (bool, error) {
	if response, err := HttpRequest(client, domainWithParams, method, headers); err == nil {
		if len(response) == SiteLengthMap[domain] {
			return false, nil
		} else {
			return true , nil
		}
	} else {
		return false, err
	}

}

func checkStability(client *http.Client, domain string, method string, headers []string) (int, bool) {

	var errCount int = 0
	var domainLength int = 0
	var tempMaxCount int = 0
	tempDomainContenttypeCountMap := make(map[int]int)
	
	for i := 0; i <= 5; i++ {

		randomParams := []string{
			getRandomString(3+i),
			getRandomString(2+i),
			getRandomString(3+i),
			getRandomString(1+i),
			getRandomString(2+i),
		}
		
		randomParamDomain := addQueryParamsToURL(domain, randomParams);

		if response, err := HttpRequest(client, randomParamDomain, method, headers); err == nil {
			contentLength := len(response)
			if _, ok := tempDomainContenttypeCountMap[contentLength]; ok {
				tempDomainContenttypeCountMap[contentLength] = tempDomainContenttypeCountMap[contentLength] + 1
			} else {
				tempDomainContenttypeCountMap[contentLength] = 0
			}

		} else {
			fmt.Errorf("Could not request the url %s . Error -> %s", domain ,err.Error())
			errCount = errCount + 1
		}
	}

	if errCount > 2 {
		return 0, true 
	}

	for contenlength, count := range(tempDomainContenttypeCountMap) {
		if count > tempMaxCount {
			domainLength = contenlength
			tempMaxCount = count
		}
	}
	
	if tempMaxCount < 2 {
		// fmt.Println("Cannot Determine content length for ", domain, " getting new content type everytime.")
		// fmt.Println("Either Everything is reflected or site is sending junk in response")
		return 0, true
	} else {
		
		if status, err := HttpRequestGetResponseStatus(client, domain, method, headers); err == nil {
			SiteStatusMap[domain] = status
		} else {
			SiteStatusMap[domain] = "200 OK"
		}

		return domainLength , false
	}
	
}

func addQueryParamsToURL(domain string, params []string) string {

	u, err := url.Parse(domain)
	if err != nil {
        panic(err)
	}
	q := u.Query()
	for _, param := range(params) {
		q.Set(param, getRandomString(5))
	}
	u.RawQuery = q.Encode()
	return u.String()

}

func getRandomString(length int) string {
	b := make([]byte, length)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }
    return string(b)

}

func HttpRequest(client *http.Client, domain string, method string, headers []string) (string, error) {
	req, err := http.NewRequest(method, domain, nil)
	if err != nil {
		return "", err
	}

	for _, header := range(headers) {
		temp := strings.Split(header, ":")
		if temp[0] == "Host" {
			req.Host = strings.TrimSpace(temp[1])
		} else {
			req.Header.Set(strings.TrimSpace(temp[0]), strings.TrimSpace(temp[1]))
		}
	}

	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := client.Do(req)

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	_, found := correctStatus[resp.Status]
	// fmt.Println(resp.Status, found)
	if !found {
		// error in request
		return "", errors.New("Bad Request... Response:"+resp.Status)
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	bodyString := string(bytes)
	return bodyString, nil
}

func HttpRequestGetResponseStatus(client *http.Client, domain string, method string, headers []string) (string, error) {
	req, err := http.NewRequest(method, domain, nil)
	if err != nil {
		return "", err
	}

	for _, header := range(headers) {
		temp := strings.Split(header, ":")
		if temp[0] == "Host" {
			req.Host = strings.TrimSpace(temp[1])
		} else {
			req.Header.Set(strings.TrimSpace(temp[0]), strings.TrimSpace(temp[1]))
		}
	}

	req.Header.Add("Connection", "close")
	req.Close = true
	
	resp, err := client.Do(req)

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return resp.Status, nil
}

func formatDomain(domain string) string {
	// remove query strings if exist
	// add https default if no schema given
	if strings.HasPrefix(domain, "https://") {

	} else if strings.HasPrefix(domain, "http://") {

	} else {
		domain = "https://" + domain
	}

	u, err := url.Parse(domain)
	if err != nil {
        panic(err)
	}

	return u.Scheme + "://" + u.Host + u.Path
}

func getQueryString(domain string) map[string]string {
	u, err := url.Parse(domain)
	queryMap := make(map[string]string)

	if err != nil {
        panic(err)
	}
	
	qs, _ := url.ParseQuery(u.RawQuery)

	for key, elem := range qs {
		queryMap[key] = elem[0]
	}
	return queryMap

}