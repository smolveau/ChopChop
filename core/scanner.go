package core

type Scanner interface {
	ScanURL(config Config) (body string, urls []string, err error)
}
