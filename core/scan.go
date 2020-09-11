package core

import (
	"fmt"
	"gochopchop/serverside/httpget"
	"net/http"
	"sync"

	"github.com/pkg/errors"
)

type SafeData struct {
	mux sync.Mutex
	out []Output
}

func (s *SafeData) Add(d Output) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.out = append(s.out, d)
}

type IFetcher interface {
	Fetch(insecure, url, followRedirects) (*http.Response, error)
}

type IScanner interface {
	Scan(signatures *Signatures, config *Config) ([]Output, error)
}

type Scanner struct {
	Fetcher IFetcher
}

// Scan of domain via url
func (s Scanner) Scan(signatures *Signatures, config *Config) ([]Output, error) {
	wg := new(sync.WaitGroup)
	safeData := new(SafeData)

	for _, domain := range config.Urls {
		url := fmt.Sprintf("%s://%s", config.Protocol, domain)
		fmt.Println("Testing domain : ", url)
		for _, plugin := range signatures.Plugins {
			fullURL := fmt.Sprintf("%s%s", url, plugin.URI)
			if plugin.QueryString != "" {
				fullURL += "?" + plugin.QueryString
			}
			wg.Add(1)
			go s.scanURL(config.Insecure, domain, fullURL, plugin, safeData, wg)
		}
	}
	wg.Wait()

	return safeData.out, nil
}

// func scanURL(config, options, fetcher, safedata, wg)
func (s Scanner) scanURL(insecure bool, domain string, url string, plugin Plugin, safeData *SafeData, wg *sync.WaitGroup) {
	defer wg.Done()

	// By default we follow HTTP redirects
	followRedirects := true
	// But for each plugin we can override and don't follow HTTP redirects
	if plugin.FollowRedirects != nil && *plugin.FollowRedirects == false {
		followRedirects = false
	}

	// TODO virer HTTPGet pour une interface passée en parametre
	httpResponse, err := s.Fetcher.Fetch(url, followRedirects)
	if err != nil {
		_ = errors.Wrap(err, "Timeout of HTTP Request")
	}
	if httpResponse == nil {
		fmt.Println("Server refused the connection for URL : " + url)
		return
	}

	swg := new(sync.WaitGroup)
	for _, check := range plugin.Checks {
		swg.Add(1)
		go scanHTTPResponse(httpResponse, url, domain, check, safeData, swg)
	}
	swg.Wait()
}

func scanHTTPResponse(httpResponse *httpget.HTTPResponse, url string, domain string, check Check, safeData *SafeData, swg *sync.WaitGroup) {
	defer swg.Done()
	match := ResponseAnalysis(httpResponse, check)
	if match {
		o := Output{
			Domain:      domain,
			PluginName:  check.PluginName,
			TestedURL:   url,
			Severity:    string(*check.Severity),
			Remediation: *check.Remediation,
		}
		safeData.Add(o)
	}
}
