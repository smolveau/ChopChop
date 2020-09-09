package core

import (
	"fmt"
	"gochopchop/serverside/httpget"
	"sync"

	"github.com/pkg/errors"
)

type SafeData struct {
	mux   sync.Mutex
	out   []Output
	block bool
}

func (s *SafeData) Add(d Output) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.out = append(s.out, d)
}

// Scan of domain via url
// Init struct before scan function with all flags (config.go)
// func Scan(config, options)
func Scan(signatures *Signatures, config *Config) ([]Output, bool, error) {
	// virer les dépendances à l'extérieur (os)
	wg := new(sync.WaitGroup)
	safeData := new(SafeData)

	for _, domain := range config.Urls {
		// TODO replace par un string formatter
		url := fmt.Sprintf("%s://%s", config.Protocol, domain)
		fmt.Println("Testing domain : ", url)
		for _, plugin := range signatures.Plugins {
			fullURL := url + fmt.Sprint(plugin.URI)
			if plugin.QueryString != "" {
				fullURL += "?" + plugin.QueryString
			}
			wg.Add(1)
			go scanURL(config.Block, config.Insecure, domain, fullURL, plugin, safeData, wg)
		}
	}
	wg.Wait() // blocking operation

	return safeData.out, safeData.block, nil
}

// Interface pour abstraction avec fonction scan
// Ou class fetcher instantiable avec variables populer
// https://tour.golang.org/concurrency/10

// func scanURL(config, options, fetcher, safedata, wg)
func scanURL(blockedFlag string, insecure bool, domain string, url string, plugin Plugin, safeData *SafeData, wg *sync.WaitGroup) {
	defer wg.Done()

	// By default we follow HTTP redirects
	followRedirects := true
	// But for each plugin we can override and don't follow HTTP redirects
	if plugin.FollowRedirects != nil && *plugin.FollowRedirects == false {
		followRedirects = false
	}

	// TODO virer HTTPGet pour une interface passée en parametre
	httpResponse, err := httpget.HTTPGet(insecure, url, followRedirects)
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
		go scanHTTPResponse(httpResponse, url, domain, blockedFlag, check, safeData, swg)
	}
	swg.Wait()
}

func scanHTTPResponse(httpResponse *httpget.HTTPResponse, url string, domain string, blockedFlag string, check Check, safeData *SafeData, swg *sync.WaitGroup) {
	defer swg.Done()
	match := ResponseAnalysis(httpResponse, check)
	if match {
		if BlockCI(blockedFlag, *check.Severity) {
			safeData.block = true
		}
		o := Output{
			Domain:      domain,
			PluginName:  check.PluginName,
			TestedURL:   url,
			Severity:    string(*check.Severity),
			Remediation: *check.Remediation,
		} // WARNING attention à la taille du tableau final, bcp de recopie d'infos
		safeData.Add(o)
	}
}

// BlockCI function will allow the user to return a different status code depending on the highest severity that has triggered
func BlockCI(severity string, severityType SeverityType) bool {
	switch severity {
	case "High":
		if severityType == High {
			return true
		}
	case "Medium":
		if severityType == High || severityType == Medium {
			return true
		}
	case "Low":
		if severityType == High || severityType == Medium || severityType == Low {
			return true
		}
	case "Informational":
		if severityType == High || severityType == Medium || severityType == Low || severityType == Informational {
			return true
		}
	}
	return false
}
