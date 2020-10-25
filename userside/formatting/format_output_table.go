package formatting

import (
	"fmt"
	"gochopchop/core"
	"os"

	"github.com/jedib0t/go-pretty/table"
)

// PrintTable will render the data as a nice table
func PrintTable(out []core.Output) {
	colorReset := "\033[0m"
	colorRed := "\033[31m"
	colorGreen := "\033[32m"
	colorYellow := "\033[33m"
	colorCyan := "\033[36m"
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"URL", "Endpoint", "Severity", "Plugin", "Remediation"})
	for _, output := range out {
		severity := ""
		if output.Severity == "High" {
			severity = fmt.Sprint(string(colorRed), "High", string(colorReset))
		} else if output.Severity == "Medium" {
			severity = fmt.Sprint(string(colorYellow), "Medium", string(colorReset))
		} else if output.Severity == "Low" {
			severity = fmt.Sprint(string(colorGreen), "Low", string(colorReset))
		} else {
			severity = fmt.Sprint(string(colorCyan), "Informational", string(colorReset))
		}
		t.AppendRow([]interface{}{
			output.URL,
			output.Endpoint,
			severity,
			output.PluginName,
			output.Remediation,
		})
	}
	t.SortBy([]table.SortBy{
		{Name: "Severity", Mode: table.Asc},
	})
	t.Render()
}
