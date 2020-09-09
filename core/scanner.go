package core

type IScanner interface {
	ScanURL(config Config) (body string, urls []string, err error)
}
