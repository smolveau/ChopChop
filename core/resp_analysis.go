package core

import (
	"gochopchop/internal"
	"strings"
)

//ResponseAnalysis of HTTP Request with checks
func ResponseAnalysis(resp *internal.HTTPResponse, signature Check) bool {

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
					if strings.Contains(n, pHeaders[1]) {
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

	if signature.NoHeaders != nil {
		for _, header := range signature.NoHeaders {
			// Parse NoHeaders
			pNoHeaders := strings.Split(*header, ":")
			if v, kFound := resp.Header[pNoHeaders[0]]; kFound {
				return false
			} else if kFound && len(pNoHeaders) == 1 { // if the header has not been specified.
				return false
			} else {
				for _, n := range v {
					if strings.Contains(n, pNoHeaders[1]) {
						return false
					}
				}
			}
		}
	}

	return true
}
