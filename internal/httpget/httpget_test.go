package httpget_test

import (
	"fmt"
	"gochopchop/mock"
	"testing"
)

func TestFetch(t *testing.T) {
	var tests = map[string]struct {
		url    string
		nilErr bool
	}{
		"url return response":     {url: "url1", nilErr: true},
		"url return nil response": {url: "unknown", nilErr: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			resp, err := mock.FakeFetcher.Fetch(tc.url)
			fmt.Printf("%v - %v \n", resp, err)
			if tc.nilErr && err != nil {
				t.Errorf("expected a nil error, got : %v", err)
			}
			if !tc.nilErr && err == nil {
				t.Errorf("expected a non-nil error, got : %v", err)
			}
		})
	}
}

/*
func TestNewFetcher(t *testing.T) {
	var tests = map[string]struct {
		insecure        bool
		timeout         int
		fetcherReturned &httpget.Fetcher
	}{
		"NewFetcherInsecure": {insecure: true, timeout: 10, &httpget.Fetcher{
			Netclient: FakeNetClient{
				Transport: &http.Transport{TLSClientConfig:}
			},
		}},
		"NewFetcherSecure": {insecure: false, timeout: 10},
	}
}

func TestNewNoRedirectFetcher(t *testing.T) {
}
*/
