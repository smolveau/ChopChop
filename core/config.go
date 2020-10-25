package core

// Struct for config flags
type Config struct {
	// TODO couper partie HTTP du reste ?
	Insecure       bool
	MaxSeverity    string
	ExportFormats  []string
	Urls           []string
	Timeout        int
	ExportFilename string
	SeverityFilter string
	PluginFilter   string
}
