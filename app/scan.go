package app

import (
	"bufio"
	"fmt"
	"gochopchop/data"
	"gochopchop/pkg"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

// SeverityType is basically an enum and values can be from Info, Low, Medium and High
type SeverityType string

const (
	// Informational will be the default severityType
	Informational SeverityType = "Informational"
	// Low severity
	Low = "Low"
	// Medium severity
	Medium = "Medium"
	// High severity (highest rating)
	High = "High"
)

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

// Scan of domain via url
func Scan(cmd *cobra.Command, args []string) {
	url, _ := cmd.Flags().GetString("url")
	insecure, _ := cmd.Flags().GetBool("insecure")
	csv, _ := cmd.Flags().GetBool("csv")
	json, _ := cmd.Flags().GetBool("json")
	urlFile, _ := cmd.Flags().GetString("url-file")
	configFile, _ := cmd.Flags().GetString("config-file")
	suffix, _ := cmd.Flags().GetString("suffix")
	prefix, _ := cmd.Flags().GetString("prefix")
	blockedFlag, _ := cmd.Flags().GetString("block")

	cfg, err := os.Open(configFile)
	if err != nil {
		log.Fatal(err)
	}

	defer cfg.Close()
	dataCfg, err := ioutil.ReadAll(cfg)

	y := Config{}
	if err = yaml.Unmarshal([]byte(dataCfg), &y); err != nil {
		log.Fatal(err)
	}

	var urlList []string
	if url != "" {
		urlList = append(urlList, url)
	}

	if urlFile != "" {
		urlFileContent, err := os.Open(urlFile)
		if err != nil {
			log.Fatal(err)
		}
		defer urlFileContent.Close()

		scanner := bufio.NewScanner(urlFileContent)
		// TODO : why use bufio ?
		for scanner.Scan() {
			urlList = append(urlList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}

	// If flag insecure isn't specified, check yaml file if it's specified in it
	if insecure {
		fmt.Println("Launching scan without validating the SSL certificate")
	} else {
		insecure = y.Insecure
	}

	CheckStructFields(y)
	wg := new(sync.WaitGroup)
	safeData := SafeData{}

	for _, domain := range urlList {
		url := prefix+domain+suffix
		fmt.Println("Testing domain : ", url)
		for _, plugin := range y.Plugins {
			fullURL := url + fmt.Sprint(plugin.URI)
			wg.Add(1)
			go scanUrl(blockedFlag, insecure, domain, fullURL, plugin, &safeData, wg)
		}
	}
	wg.Wait() // blocking operation
	if len(safeData.out) > 0 {
		dateNow := time.Now().Format("2006-01-02_15-04-05")
		pkg.FormatOutputTable(safeData.out)
		if json {
			outputJSON := pkg.AddVulnToOutputJSON(safeData.out) // TODO refactor
			pkg.CreateFileJSON(dateNow, outputJSON)
		}
		if csv {
			pkg.FormatOutputCSV(dateNow, safeData.out)
		}
		if blockedFlag != "" {
			if block {
				os.Exit(1)
			}
			fmt.Println("No critical vulnerabilities found...")
			os.Exit(0)
		}
		os.Exit(1) // TODO pas d'exit danscette fonction, faire remonter au cli
	} else {
		fmt.Println("No vulnerabilities found. Exiting...")
		os.Exit(0)
	}
}

func scanUrl(blockedFlag string, insecure bool, domain string, url string, plugin Plugin, safeData *SafeData, wg *sync.WaitGroup){

		defer wg.Done()
		httpResponse, err := pkg.HTTPGet(insecure, url)
		if err != nil {
			return
		}
		if httpResponse == nil {
			fmt.Println("Server refused the connection for URL : " + url)
			return
		}
		swg := new(sync.WaitGroup)
		for _, check := range plugin.Checks {
			swg.Add(1)
			go scanHTTPResponse(httpResponse, domain, blockedFlag, check, safeData, wg)
		}
		swg.Wait()
}


func scanHTTPResponse(httpResponse *pkg.HTTPResponse, domain string, blockedFlag string, check Check, safeData *SafeData, wg *sync.WaitGroup) {
	block := false
	defer wg.Done()
	match := pkg.ResponseAnalysis(httpResponse, check.StatusCode, check.Match, check.AllMatch, check.NoMatch, check.Headers)
	if match {
		if BlockCI(blockedFlag, *check.Severity) {
			block = true
		}
		//TODO refactor rename out variable
		o := data.Output{
			Domain:      domain,
			PluginName:  check.PluginName,
			TestedURL:   url,
			Severity:    string(*check.Severity),
			Remediation: *check.Remediation,
		} // WARNING attention à la taille du tableau final, bcp de recopie d'infos
		safeData.Add(o)
	}
}

type SafeData struct {
	mux sync.Mutex
	out []data.Output
}

func (s *SafeData) Add(d data.Output) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.out = append(s.out, d)
}

// BlockCI function will allow the user to return a different status code depending on the highest severity that has triggered
// FIXME fausse explication
func BlockCI(severity string, severityType SeverityType) bool {
	// TODO rename function, dont export it
	switch severity {
	case "High":
		if severityType == High {
			return true
		}
	case "Medium":
		if severityType == High || severityType == Medium {
			return true
		}
	case "Low":
		if severityType == High || severityType == Medium || severityType == Low {
			return true
		}
	case "Informational":
		if severityType == High || severityType == Medium || severityType == Low || severityType == Informational {
			return true
		}
	}
	return false
}

// CheckStructFields will check the fields of YAML configuration file
func CheckStructFields(conf Config) {
	for _, plugin := range conf.Plugins {
		for _, check := range plugin.Checks {
			if check.Description == nil {
				// TODO remonter l'erreur plutot que fatal
				log.Fatal("Missing description field in " + check.PluginName + " plugin checks. Stopping execution.")
			}
			if check.Remediation == nil {
				log.Fatal("Missing remediation field in " + check.PluginName + " plugin checks. Stopping execution.")
			}
			if check.Severity == nil {
				log.Fatal("Missing severity field in " + check.PluginName + " plugin checks. Stopping execution.")
			}
			if err := SeverityType.IsValid(*check.Severity); err != nil {
				// TODO error not used
				log.Fatal(" ------ Unknown severity type : " + string(*check.Severity) + " . Only Informational / Low / Medium / High are valid severity types.")
			}
		}
	}
}

// IsValid will verify that the severityType is part of the enum previously declared
func (st SeverityType) IsValid() error {
	switch st {
	case Informational, Low, Medium, High:
		return nil
	}
	return errors.New("Invalid Severity type. Please Check yaml config file")
}