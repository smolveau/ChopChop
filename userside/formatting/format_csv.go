package formatting

import (
	"fmt"
	"gochopchop/core"
	"os"
	"time"
)

// ExportCSV is a simple wrapper for CSV formatting
func ExportCSV(out []core.Output) error {
	now := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("./gochopchop_%s.csv", now)

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString("url,endpoint,severity,pluginName,remediation\n")
	if err != nil {
		return err
	}
	for _, output := range out {
		line := fmt.Sprintf("%s,%s,%s,%s,%s\n", output.URL, output.Endpoint, output.Severity, output.PluginName, output.Remediation)
		_, err = f.Write([]byte(line))
		if err != nil {
			return err
		}
	}

	fmt.Printf("Output as csv : %s \n", filename)
	return nil
}
