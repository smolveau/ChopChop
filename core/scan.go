package core

import (
	"fmt"
	"gochopchop/internal"
	"path"
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
	Fetch(url string) (*internal.HTTPResponse, error)
}

type IScanner interface {
	Scan(signatures *Signatures, urls []string) ([]Output, error)
}

type Scanner struct {
	Fetcher           IFetcher
	NoRedirectFetcher IFetcher
	safeData          *SafeData
}

func NewScanner(fetcher IFetcher, noRedirectFetcher IFetcher) *Scanner {
	safeData := new(SafeData)
	return &Scanner{
		Fetcher:           fetcher,
		NoRedirectFetcher: noRedirectFetcher,
		safeData:          safeData,
	}
}

// TODO move parameters in struct, refactor
func (s Scanner) Scan(signatures *Signatures, urls []string) ([]Output, error) {
	wg := new(sync.WaitGroup)

	for _, url := range urls {
		fmt.Println("Testing url : ", url)
		for _, plugin := range signatures.Plugins {
			endpoint := plugin.URI
			if plugin.QueryString != "" {
				endpoint = fmt.Sprintf("%s?%s", endpoint, plugin.QueryString)
			}
			fullURL := path.Join(url, endpoint)

			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := s.scanURL(fullURL, plugin)
				if err != nil {
					return
				}
				swg := new(sync.WaitGroup)
				for _, check := range plugin.Checks {
					swg.Add(1)
					go func() {
						defer swg.Done()
						if ResponseAnalysis(resp, check) {
							o := Output{
								URL:         fullURL,
								PluginName:  check.PluginName,
								Endpoint:    endpoint,
								Severity:    *check.Severity,
								Remediation: *check.Remediation,
							}
							s.safeData.Add(o)
						}
					}()
				}
				swg.Wait()
			}()
		}
	}
	wg.Wait()

	return s.safeData.out, nil
}

func (s Scanner) scanURL(url string, plugin Plugin) (*internal.HTTPResponse, error) {
	var httpResponse *internal.HTTPResponse
	var err error

	if plugin.FollowRedirects != nil && *plugin.FollowRedirects == false {
		httpResponse, err = s.NoRedirectFetcher.Fetch(url)
	} else {
		httpResponse, err = s.Fetcher.Fetch(url)
	}

	if err != nil {
		return nil, errors.Wrap(err, "Timeout of HTTP Request")
	}
	// weird case when both the error and the response are nil, caused by the server refusing the connection
	if httpResponse == nil {
		return nil, fmt.Errorf("Server refused the connection for : %s", url)
	}
	return httpResponse, nil
}
