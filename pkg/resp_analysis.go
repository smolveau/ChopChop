package pkg

import (
	"strings"
)

//ResponseAnalysis of HTTP Request with checks
func ResponseAnalysis(resp *HTTPResponse, statusCode *int, match []*string, allMatch []*string, noMatch []*string, headers []*string) bool {
	// TODO a refactor
	if statusCode != nil {
		if resp.StatusCode != *statusCode {
			return false
		}
	}
	// all element needs to be found
	if allMatch != nil {
		for i := 0; i < len(allMatch); i++ {
			if !strings.Contains(resp.Body, *allMatch[i]) {
				return false
			}
		}
	}

	// one elements needs to be found
	if match != nil {
		found := false
		for i := 0; i < len(match); i++ {
			if strings.Contains(resp.Body, *match[i]) {
				found = true
			}
		}
		if !found {
			return false
		}
	}

	// if 1 element of list is not found
	if noMatch != nil {
		for i := 0; i < len(noMatch); i++ {
			if strings.Contains(resp.Body, *noMatch[i]) {
				return false
			}
		}
	}
	if headers != nil {
		for i := 0; i < len(headers); i++ {
			// Parse headers
			pHeaders := strings.Split(*headers[i], ":")
			if v, kFound := resp.Header[pHeaders[0]]; kFound {
				// Key found - check value
				vFound := false
				for i, n := range v {
					if pHeaders[1] == n {
						_ = i
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
