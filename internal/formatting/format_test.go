package formatting_test

import (
	"bytes"
	"gochopchop/core"
	"gochopchop/internal/formatting"
	"gochopchop/mock"
	"testing"
)

func TestFormatCSV(t *testing.T) {

	file := mock.NewFakeFile()
	_ = formatting.ExportCSV(file, mock.FakeOutput)
	t.Log(file.Output())
	return

	var tests = map[string]struct {
		output []core.Output
		file   mock.FakeFile
		want   string
	}{
		"correct formatting": {output: mock.FakeOutput, file: mock.FakeFile{}, want: ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_ = formatting.ExportCSV(tc.file, tc.output)
			t.Log(tc.file.Output())
			if tc.file.Output() != tc.want {
				//t.Errorf("want : %q, got : %q", tc.want, tc.file.Output)
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
	want := "+-----------------+----------+---------------+---------------+-------------+\n| URL             | ENDPOINT | SEVERITY      | PLUGIN        | REMEDIATION |\n+-----------------+----------+---------------+---------------+-------------+\n| http://problems | /        | \x1b[31mHigh\x1b[0m          | Headers       | uninstall   |\n| http://problems | /        | \x1b[31mHigh\x1b[0m          | MustNotMatch  | uninstall   |\n| http://problems | /        | \x1b[32mLow\x1b[0m           | NoHeaders     | uninstall   |\n| http://problems | /        | \x1b[32mLow\x1b[0m           | MustMatchOne  | uninstall   |\n| http://problems | /        | \x1b[33mMedium\x1b[0m        | StatusCode200 | uninstall   |\n| http://problems | /        | \x1b[36mInformational\x1b[0m | MustMatchAll  | uninstall   |\n+-----------------+----------+---------------+---------------+-------------+\n"
	if got != want {
		t.Errorf("want : %q, got : %q", want, got)
	}
}
