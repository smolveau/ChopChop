package core

import (
	"gochopchop/internal"
	"strings"
)

//ResponseAnalysis of HTTP Request with checks
func ResponseAnalysis(resp *internal.HTTPResponse, signature Check) bool {
	// TODO a refactor
	if signature.StatusCode != nil {
		if int32(resp.StatusCode) != *signature.StatusCode {
			return false
		}
	}
	// all element must be found
	if signature.AllMatch != nil {
		for _, match := range signature.AllMatch {
			if !strings.Contains(resp.Body, *match) {
				return false
			}
		}
	}

	// one element must be found
	if signature.Match != nil {
		found := false
		for _, match := range signature.Match {
			if strings.Contains(resp.Body, *match) {
				found = true
			}
		}
		if !found {
			return false
		}
	}

	// no element should match
	if signature.NoMatch != nil {
		for _, match := range signature.NoMatch {
			if strings.Contains(resp.Body, *match) {
				return false
			}
		}
	}
	if signature.Headers != nil {
		for _, header := range signature.Headers {
			// Parse headers
			pHeaders := strings.Split(*header, ":")
			if v, kFound := resp.Header[pHeaders[0]]; kFound {
				vFound := false
				for _, n := range v {
					if pHeaders[1] == n {
						vFound = true
					}
				}
				if !vFound {
					return false
				}
			} else {
				return false
			}
		}
	}
	return true
}
