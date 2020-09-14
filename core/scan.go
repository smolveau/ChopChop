package core

import (
	"fmt"
	"gochopchop/internal"
	"gochopchop/serverside/httpget"
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
	Fetch(url string, followRedirects bool) (*internal.HTTPResponse, error)
}

type IScanner interface {
	Scan(signatures *Signatures, config *Config) ([]Output, error)
}

type Scanner struct {
	Fetcher           IFetcher
	NoRedirectFetcher IFetcher
	safeData          *SafeData
}

func NewScanner(insecure bool) *Scanner {
	fetcher := httpget.NewFetcher(insecure)
	noRedirectFetcher := httpget.NewNoRedirectFetcher(insecure)
	safeData := new(SafeData)
	return &Scanner{
		Fetcher:           fetcher,
		NoRedirectFetcher: noRedirectFetcher,
		safeData:          safeData,
	}
}

// Scan of domain via url
func (s Scanner) Scan(signatures *Signatures, config *Config) ([]Output, error) {
	wg := new(sync.WaitGroup)

	// TODO Changer nom DOMAIN
	for _, url := range config.Urls {
		fmt.Println("Testing url : ", url)
		for _, plugin := range signatures.Plugins {
			fullURL := fmt.Sprintf("%s%s", url, plugin.URI)
			if plugin.QueryString != "" {
				fullURL += "?" + plugin.QueryString
			}
			wg.Add(1)
			go s.scanURL(url, fullURL, plugin, wg)
		}
	}
	wg.Wait()

	return s.safeData.out, nil
}

func (s Scanner) scanURL(domain string, url string, plugin Plugin, wg *sync.WaitGroup) {
	defer wg.Done()

	if plugin.FollowRedirects != nil && *plugin.FollowRedirects == false {
		httpResponse, err := s.NoRedirectFetcher.Fetch(url)
	} else {
		httpResponse, err := s.Fetcher.Fetch(url)
	}

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
		go s.analyseHTTPResponse(httpResponse, url, domain, check, swg)
	}
	swg.Wait()
}

func (s Scanner) analyseHTTPResponse(httpResponse *HTTPResponse, url string, domain string, check Check, swg *sync.WaitGroup) {
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
		s.safeData.Add(o)
	}
}
