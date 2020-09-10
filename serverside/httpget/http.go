package httpget

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type HTTPResponse struct {
	StatusCode int
	Body       string
	Header     http.Header
}

type IHTTPClient interface {
	Get(url string) (*http.Response, error)
}

type HTTPClient struct {
	Transport http.RoundTripper
	Timeout   time.Duration
}

type Fetcher struct {
	Netclient IHTTPClient
}

func NewFetcher(insecure bool) *Fetcher {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	var netClient = &http.Client{
		Transport: tr,
		Timeout:   time.Second * 3,
	}
	return &Fetcher{
		Netclient: netClient,
	}
}

func (s Fetcher) Fetch(url string, followRedirects bool) (*HTTPResponse, error) {
	// implements the core/IFetcher interface
	if followRedirects == false {
		// We tell the HTTP Client to don't follow them
		s.Netclient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	resp, err := s.Netclient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	bodyString := string(bodyBytes)

	var r = &HTTPResponse{
		Body:       bodyString,
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
	}

	return r, err
}
