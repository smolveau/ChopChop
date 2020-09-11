package httpget

import (
	"crypto/tls"
	"gochopchop/internal"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type IHTTPClient interface {
	Fetch(url string, followredirect bool) (*internal.HTTPResponse, error)
}

type HTTPClient struct {
	Transport http.RoundTripper
	Timeout   time.Duration
}

type Fetcher struct {
	Netclient IHTTPClient
}

func (s HTTPClient) Fetch(url string, followRedirects bool) (*internal.HTTPResponse, error) {

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

func (s Fetcher) Fetch(url string, followRedirects bool) (*internal.HTTPResponse, error) {
	// implements the core/IFetcher interface
	resp, err := s.Netclient.Fetch(url, false)
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

	var r = &internal.HTTPResponse{
		Body:       bodyString,
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
	}

	return r, err
}
