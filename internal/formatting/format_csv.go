package formatting

import (
	"fmt"
	"gochopchop/core"
)

type IFile interface {
	WriteString(input string) (n int, err error)
}

// ExportCSV is a simple wrapper for CSV formatting
func ExportCSV(file IFile, out []core.Output) error {
	_, err := file.WriteString("url,endpoint,severity,checkName,remediation\n")
	if err != nil {
		return err
	}
	for _, output := range out {
		line := fmt.Sprintf("%s,%s,%s,%s,%s\n", output.URL, output.Endpoint, output.Severity, output.Name, output.Remediation)
		_, err := file.WriteString(line)
		if err != nil {
			return err
		}
	}

	return nil
}
