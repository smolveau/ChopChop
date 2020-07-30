package app

// SeverityType is basically an enum and values can be from Info, Low, Medium and High
type SeverityType string

// Config struct to load the configuration from the YAML file
type Config struct {
	Insecure bool     `yaml:"insecure"`
	Plugins  []Plugin `yaml:"plugins"`
}

type Plugin struct {
	URI    string  `yaml:"uri"`
	Checks []Check `yaml:"checks"`
}

type Check struct {
	Match       []*string     `yaml:"match"`
	AllMatch    []*string     `yaml:"all_match"`
	StatusCode  *int          `yaml:"status_code"`
	PluginName  string        `yaml:"name"`
	Remediation *string       `yaml:"remediation"`
	Severity    *SeverityType `yaml:"severity"`
	Description *string       `yaml:"description"`
	NoMatch     []*string     `yaml:"no_match"`
	Headers     []*string     `yaml:"headers"`
}

// NewConfig returns a new initialized Config
func NewConfig() *Config {
	return &Config{
		Insecure: false,
	}
}
