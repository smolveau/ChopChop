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

//HTTPGet return http response of http get request
func HTTPGet(insecure bool, url string, followRedirects bool) (*HTTPResponse, error) {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	var netClient = &http.Client{
		Transport: tr,
		Timeout:   time.Second * 3,
	}

	// If we don't want to follow HTTP redirects
	if followRedirects == false {
		// We tell the HTTP Client to don't follow them
		netClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	resp, err := netClient.Get(url)
	if err != nil {
		log.Println(err)
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
