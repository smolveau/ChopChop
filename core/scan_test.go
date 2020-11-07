package core

import (
	"context"
	"fmt"
	"gochopchop/internal"
	"net/http"
	"testing"
	"time"
)

// TODO pas passer les signatures au new
var FakeScanner = NewScanner(MyFakeFetcher, MyFakeFetcher, FakeSignatures, 1)

type FakeFetcher map[string]*internal.HTTPResponse

func (f FakeFetcher) Fetch(url string) (*internal.HTTPResponse, error) {
	if res, ok := f[url]; ok {
		return res, nil
	}
	return nil, fmt.Errorf("could not fetch : %s", url)
}

var MyFakeFetcher = FakeFetcher{
	"http://problems/": &internal.HTTPResponse{
		StatusCode: 200,
		Body:       "MATCHONE lorem ipsum MATCHTWO",
		Header: http.Header{
			"Header": []string{"ok"},
		},
	},
	"http://noproblem/": &internal.HTTPResponse{
		StatusCode: 500,
		Body:       "NOTMATCH",
		Header: http.Header{
			"NoHeader": []string{"ok"},
		},
	},
	"http://nilhttpresp/": nil,
	"http://noproblem/?query=test": &internal.HTTPResponse{
		StatusCode: 500,
	},
}

func TestScan(t *testing.T) {
	var tests = map[string]struct {
		ctx    context.Context
		urls   []string
		output []Output
	}{
		"noproblem":        {ctx: context.Background(), urls: []string{"http://noproblem"}, output: []Output{}},
		"context problem":  {ctx: context.Background(), urls: []string{"http://noproblem"}, output: []Output{}},
		"fetcher problem":  {ctx: context.Background(), urls: []string{"http://unknown"}, output: []Output{}},
		"nil resp problem": {ctx: context.Background(), urls: []string{"http://nilhttpresp"}, output: []Output{}},
		"problems":         {ctx: context.Background(), urls: []string{"http://problems"}, output: FakeOutput},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {

			if name == "context problem" {
				ctx, cancel := context.WithDeadline(tc.ctx, time.Now().Add(-7*time.Hour))
				tc.ctx = ctx
				cancel()
			}

			output, _ := FakeScanner.Scan(tc.ctx, tc.urls)

			for _, haveOutput := range tc.output {
				found := false
				for _, wantOutput := range output {
					if found {
						break
					}
					if wantOutput.Name == haveOutput.Name {
						found = true
					}
				}
				if !found {
					t.Errorf("expected: %v, got: %v", tc.output, output)
				}
			}
		})
	}
}
