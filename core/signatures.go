package core

// Signature struct to load the plugins/rules from the YAML file
type Signatures struct {
	Plugins []Plugin `yaml:"plugins"`
}

type Plugin struct {
	URI             string  `yaml:"uri"`
	QueryString     string  `yaml:"query_string"`
	Checks          []Check `yaml:"checks"`
	FollowRedirects *bool   `yaml:"follow_redirects"`
}

// Check Signature
type Check struct {
	Match       []*string `yaml:"match"`
	AllMatch    []*string `yaml:"all_match"`
	StatusCode  *int32    `yaml:"status_code"`
	PluginName  string    `yaml:"name"`
	Remediation *string   `yaml:"remediation"`
	Severity    *string   `yaml:"severity"`
	Description *string   `yaml:"description"`
	NoMatch     []*string `yaml:"no_match"`
	Headers     []*string `yaml:"headers"`
}

// NewConfig returns a new initialized Signatures
func NewSignatures() *Signatures {
	return &Signatures{}
}
