package pkg

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
func HTTPGet(insecure bool, url string) (*HTTPResponse, error) {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	var netClient = &http.Client{
		Transport: tr,
		Timeout:   time.Second * 3, // TODO let the user choose the timeout
	}
	resp, err := netClient.Get(url)
	if err != nil {
		log.Println("If error unsupported protocol scheme encountered, try adding flag --prefix with http://, or add prefix directly in url list")
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
