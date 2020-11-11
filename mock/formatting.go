package mock

import (
	"fmt"
	"strings"
)

type FakeFile struct {
	output []string
}

func (f FakeFile) WriteString(input string) (n int, err error) {
	f.output = append(f.output, input)
	fmt.Printf("%q OK", f.output)
	return 0, nil
}

func (f FakeFile) Output() string {
	return strings.Join(f.output[:], "")
}

func NewFakeFile() *FakeFile {
	return &FakeFile{
		output: []string{},
	}
}
