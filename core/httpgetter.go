package core

type IHTTPGetter interface {
	HttpGet(url string)
}
