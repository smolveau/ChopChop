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

type SafeData struct {
	mux   sync.Mutex
	out   []data.Output
	block bool
}

func (s *SafeData) Add(d data.Output) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.out = append(s.out, d)
}

// Scan of domain via url
func Scan(cmd *cobra.Command, args []string) {
	timer := time.Now()

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
	y := data.Config{}
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
		for scanner.Scan() {
			urlList = append(urlList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}

	if insecure {
		fmt.Println("Launching scan without validating the SSL certificate")
	} else {
		insecure = y.Insecure
	}

	CheckStructFields(y)
	wg := new(sync.WaitGroup)
	safeData := new(SafeData)

	for _, domain := range urlList {
		url := prefix + domain + suffix
		fmt.Println("Testing domain : ", url)
		for _, plugin := range y.Plugins {
			fullURL := url + fmt.Sprint(plugin.URI)
			if plugin.QueryString != "" {
				fullURL += "?" + plugin.QueryString
			}
			wg.Add(1)
			go scanURL(blockedFlag, insecure, domain, fullURL, plugin, safeData, wg)
		}
	}
	wg.Wait() // blocking operation

	elapsed := time.Since(timer)
	log.Printf("Scan execution time: %s", elapsed)
	if len(safeData.out) > 0 {
		dateNow := time.Now().Format("2006-01-02_15-04-05")
		pkg.FormatOutputTable(safeData.out)
		if json {
			outputJSON := pkg.AddVulnToOutputJSON(safeData.out)
			pkg.CreateFileJSON(dateNow, outputJSON)
		}
		if csv {
			pkg.FormatOutputCSV(dateNow, safeData.out)
		}
		if blockedFlag != "" {
			fmt.Println("No critical vulnerabilities found...")
			os.Exit(0)
		}
		os.Exit(1)
	} else {
		fmt.Println("No vulnerabilities found. Exiting...")
		os.Exit(0)
	}
}

func scanURL(blockedFlag string, insecure bool, domain string, url string, plugin data.Plugin, safeData *SafeData, wg *sync.WaitGroup) {
	defer wg.Done()

	// By default we follow HTTP redirects
	followRedirects := true
	// But for each plugin we can override and don't follow HTTP redirects
	if plugin.FollowRedirects != nil && *plugin.FollowRedirects == false {
		followRedirects = false
	}

	httpResponse, err := pkg.HTTPGet(insecure, url, followRedirects)
	if err != nil {
		_ = errors.Wrap(err, "Timeout of HTTP Request")
	}
	if httpResponse == nil {
		fmt.Println("Server refused the connection for URL : " + url)
		return
	}

	swg := new(sync.WaitGroup)
	for _, check := range plugin.Checks {
		swg.Add(1)
		go scanHTTPResponse(httpResponse, url, domain, blockedFlag, check, safeData, swg)
	}
	swg.Wait()
}

func scanHTTPResponse(httpResponse *pkg.HTTPResponse, url string, domain string, blockedFlag string, check data.Check, safeData *SafeData, swg *sync.WaitGroup) {
	defer swg.Done()
	match := pkg.ResponseAnalysis(httpResponse, check)
	if match {
		if BlockCI(blockedFlag, *check.Severity) {
			safeData.block = true
		}
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

// BlockCI function will allow the user to return a different status code depending on the highest severity that has triggered
func BlockCI(severity string, severityType data.SeverityType) bool {
	switch severity {
	case "High":
		if severityType == data.High {
			return true
		}
	case "Medium":
		if severityType == data.High || severityType == data.Medium {
			return true
		}
	case "Low":
		if severityType == data.High || severityType == data.Medium || severityType == data.Low {
			return true
		}
	case "Informational":
		if severityType == data.High || severityType == data.Medium || severityType == data.Low || severityType == data.Informational {
			return true
		}
	}
	return false
}

// CheckStructFields will parse the YAML configuration file
func CheckStructFields(conf data.Config) {
	for index, plugin := range conf.Plugins {
		_ = index
		for index, check := range plugin.Checks {
			_ = index
			if check.Description == nil {
				log.Fatal("Missing description field in " + check.PluginName + " plugin checks. Stopping execution.")
			}
			if check.Remediation == nil {
				log.Fatal("Missing remediation field in " + check.PluginName + " plugin checks. Stopping execution.")
			}
			if check.Severity == nil {
				log.Fatal("Missing severity field in " + check.PluginName + " plugin checks. Stopping execution.")
			} else {
				if err := data.SeverityType.IsValid(*check.Severity); err != nil {
					log.Fatal(" ------ Unknown severity type : " + string(*check.Severity) + " . Only Informational / Low / Medium / High are valid severity types.")
				}
			}
		}
	}
}
