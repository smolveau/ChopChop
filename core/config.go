package core

// Struct for config flags
type Config struct {
	// TODO couper partie HTTP du reste ?
	Insecure    bool
	MaxSeverity string
	Format      []string
	Urls        []string
	Timeout     int
}
