package formatting

import (
	"gochopchop/core"
	"os"

	"github.com/jedib0t/go-pretty/table"
)

// PrintTable will render the data as a nice table
func PrintTable(out []core.Output) {

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"URL", "Endpoint", "Severity", "Plugin", "Remediation"})
	for _, output := range out {
		t.AppendRow([]interface{}{
			output.URL,
			output.Endpoint,
			output.Severity,
			output.PluginName,
			output.Remediation,
		})
	}
	t.Render()
}
