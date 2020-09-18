package core

// Struct for config flags
type Config struct {
	// TODO couper partie HTTP du reste ?
	Insecure    bool
	MaxSeverity string
	ExportCSV   bool
	ExportJSON  bool
	Urls        []string
	Timeout     int
}
