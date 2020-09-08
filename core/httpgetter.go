package core

type HTTPGetter interface {
	HttpGet(url string)
}
