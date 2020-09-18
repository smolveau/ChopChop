package core

// Output structure for each findings
type Output struct {
	// transformer directement en un array de struct
	URL         string `json:"url"`
	Endpoint    string `json:"endpoint"`
	PluginName  string `json:"plugin_name"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}