package app

import (
	"os"

	"github.com/jedib0t/go-pretty/table"
)

type ListOptions struct {
	Severity string
}

// List checks of config file
func List(config *Config, options *ListOptions) {
	cpt := 0
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"URL", "Plugin Name", "Severity", "Description"})
	for _, plugin := range config.Plugins {
		for _, check := range plugin.Checks {
			if options.Severity == "" || options.Severity == string(*check.Severity) {
				t.AppendRow([]interface{}{plugin.URI, check.PluginName, *check.Severity, *check.Description})
				cpt++
			}
		}
	}
	t.AppendFooter(table.Row{"", "", "Total Checks", cpt})
	t.Render()
}
