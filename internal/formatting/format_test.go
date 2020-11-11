package formatting_test

import (
	"bytes"
	"gochopchop/core"
	"gochopchop/internal/formatting"
	"gochopchop/mock"
	"testing"

	"github.com/spf13/afero"
)

func TestFormatCSV(t *testing.T) {

	appfs := afero.Afero{Fs: afero.NewMemMapFs()}

	var tests = map[string]struct {
		output []core.Output
		want   string
	}{
		"correct formatting": {output: mock.FakeOutput, want: mock.FakeOutputFormatCSVString},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f, _ := appfs.Create("formatcsv")
			_ = formatting.ExportCSV(f, tc.output)
			contents, _ := appfs.ReadFile("formatcsv")
			got := string(contents)
			if got != tc.want {
				t.Errorf("want : %q, got : %q", tc.want, got)
			}
		})
	}
}
func TestFormatJSON(t *testing.T) {
	output := mock.FakeOutput
	var tests = map[string]struct {
		filename string
		nilErr   bool
	}{
		"empty filename":  {filename: "", nilErr: true},
		"normal filename": {filename: "file", nilErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := formatting.ExportJSON(tc.filename, output)
			if tc.nilErr && err != nil {
				t.Errorf("expected a nil error, got : %v", err)
			}
			if !tc.nilErr && err == nil {
				t.Errorf("expected a non-nil error, got : %v", err)
			}
		})
	}
}
func TestFormatOutputTable(t *testing.T) {
	mirror := new(bytes.Buffer)
	output := mock.FakeOutput
	formatting.PrintTable(output, mirror)
	got := mirror.String()
	want := mock.FakeOutputFormatTableString
	if got != want {
		t.Errorf("want : %q, got : %q", want, got)
	}
}
