package core

import (
	"bufio"
	"fmt"
	"gochopchop/serverside/httpget"
	"gochopchop/userside/formatting"

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
	out   []Output
	block bool
}

func (s *SafeData) Add(d Output) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.out = append(s.out, d)
}

type Scanner interface {
	// Fetch returns the body of URL and
	// a slice of URLs found on that page.
	Scan(url string) (body string, urls []string, err error)
}

// Scan of domain via url
// Init struct before scan function with all flags (config.go)
// func Scan(config, options)
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
	// TODO TEST virer ce qui est au dessus de cette ligne
	// virer les dépendances à l'extérieur (os)
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
	// TODO Output and Timer as Presenters, CLI must do it
	if len(safeData.out) > 0 {
		dateNow := time.Now().Format("2006-01-02_15-04-05")
		formatting.FormatOutputTable(safeData.out)
		if json {
			outputJSON := formatting.AddVulnToOutputJSON(safeData.out)
			formatting.CreateFileJSON(dateNow, outputJSON)
		}
		if csv {
			formatting.FormatOutputCSV(dateNow, safeData.out)
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

// Interface pour abstraction avec fonction scan
// Ou class fetcher instantiable avec variables populer
// https://tour.golang.org/concurrency/10

// func scanURL(config, options, fetcher, safedata, wg)
func scanURL(blockedFlag string, insecure bool, domain string, url string, plugin Plugin, safeData *SafeData, wg *sync.WaitGroup) {
	defer wg.Done()

	// By default we follow HTTP redirects
	followRedirects := true
	// But for each plugin we can override and don't follow HTTP redirects
	if plugin.FollowRedirects != nil && *plugin.FollowRedirects == false {
		followRedirects = false
	}

	// virer HTTPGet pour une interface passée en parametre
	httpResponse, err := httpget.HTTPGet(insecure, url, followRedirects)
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

func scanHTTPResponse(httpResponse *httpget.HTTPResponse, url string, domain string, blockedFlag string, check Check, safeData *SafeData, swg *sync.WaitGroup) {
	defer swg.Done()
	match := ResponseAnalysis(httpResponse, check)
	if match {
		if BlockCI(blockedFlag, *check.Severity) {
			safeData.block = true
		}
		o := Output{
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
func BlockCI(severity string, severityType SeverityType) bool {
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

// CheckStructFields will parse the YAML configuration file
func CheckStructFields(conf Config) {
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
				if err := SeverityType.IsValid(*check.Severity); err != nil {
					log.Fatal(" ------ Unknown severity type : " + string(*check.Severity) + " . Only Informational / Low / Medium / High are valid severity types.")
				}
			}
		}
	}
}
