package cmd

import (
	"bufio"
	"fmt"
	"gochopchop/core"
	"gochopchop/userside/formatting"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func init() {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "scan URL endpoints to check if services/files/folders are exposed to the Internet",
		Args:  checkArgsAndFlags,
		RunE:  runScan,
	}
	addSignaturesFlag(scanCmd)

	scanCmd.Flags().StringP("url", "u", "", "url to scan")                                           // --url OU -u
	scanCmd.Flags().BoolP("insecure", "i", false, "Check SSL certificate")                           // --insecure ou -n
	scanCmd.Flags().StringP("url-file", "f", "", "path to a specified file containing urls to test") // --uri-file ou -f
	scanCmd.Flags().StringP("prefix", "p", "", "Add prefix to urls when flag url-file is specified") // --prefix ou -p
	// TODO changer le nom en max-severity
	scanCmd.Flags().StringP("max-severity", "b", "", "maxSeverity pipeline if severity is over or equal specified flag") // --max-severity ou -m
	// soit csv soit json via une liste genre --format json ou --format csv
	scanCmd.Flags().BoolP("csv", "", false, "output as a csv file") //--csv
	scanCmd.Flags().BoolP("json", "", false, "output as a json file")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	signatures, err := parseSignatures(cmd)
	if err != nil {
		return err
	}
	config, err := parseConfig(cmd)
	if err != nil {
		return err
	}
	// call core with struct
	begin := time.Now()
	// Scan doit return une struct populer output
	result, err := core.Scan(signatures, config)
	elapsed := time.Since(begin)
	log.Printf("Scan execution time: %s", elapsed)

	// TODO CHECK HERE IF FLAG MAX SEVERITY ASSIGNED AND IF BLOCK CI

	if len(result) > 0 {
		dateNow := time.Now().Format("2006-01-02_15-04-05")
		formatting.FormatOutputTable(result)

		if config.Json {
			outputJSON := formatting.AddVulnToOutputJSON(result)
			formatting.CreateFileJSON(dateNow, outputJSON)
		}
		if config.Csv {
			formatting.FormatOutputCSV(dateNow, result)
		}

		if config.MaxSeverity != "" {
			blocking := false
			for _, output := range result {
				for _, severity := range output.Severity {
					if BlockCI(config.MaxSeverity, severity) {
						block = true
					}
				}
			}
		}

		if !blocking {
			fmt.Println("No critical vulnerabilities found...")
			return nil
		}
		return fmt.Errorf("Blocking CI")
	} else {
		fmt.Println("No vulnerabilities found. Exiting...")
		return nil
	}
	return nil
}

func checkArgsAndFlags(cmd *cobra.Command, args []string) error {
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		return fmt.Errorf("invalid value for url: %v", err)
	}
	if url != "" {
		if !strings.HasPrefix(url, "http") {
			// If http or https not specified, return fatal log
			return fmt.Errorf("URL needs a specified prefix :  http:// or https://")
		}
	}
	urlFile, err := cmd.Flags().GetString("url-file")
	if err != nil {
		return fmt.Errorf("invalid value for urlFile: %v", err)
	}
	if urlFile != "" {
		if _, err := os.Stat(urlFile); os.IsNotExist(err) {
			return fmt.Errorf("filepath of url file is not valid")
		}
	}
	protocol, err := cmd.Flags().GetString("protocol")
	if err != nil {
		return fmt.Errorf("invalid value for prefix: %v", err)
	}
	if protocol != "" {
		if urlFile == "" {
			return fmt.Errorf("protocol flag can't be assigned if flag url-file is not specified")
		}
	}
	maxSeverity, err := cmd.Flags().GetString("maxSeverity")
	if err != nil {
		return fmt.Errorf("invalid value for maxSeverity: %v", err)
	}
	if maxSeverity != "" {
		if maxSeverity == "High" || maxSeverity == "Medium" || maxSeverity == "Low" || maxSeverity == "Informational" {
			fmt.Println("maxSeverity pipeline if severity is over or equal : " + maxSeverity)
		} else {
			log.Fatal(" ------ Unknown severity type : " + maxSeverity + " . Only Informational / Low / Medium / High are valid severity types.")
		}
	}
	if _, err = cmd.Flags().GetBool("insecure"); err != nil {
		return fmt.Errorf("invalid value for insecure: %v", err)
	}
	if _, err = cmd.Flags().GetBool("csv"); err != nil {
		return fmt.Errorf("invalid value for csv: %v", err)
	}
	if _, err = cmd.Flags().GetBool("json"); err != nil {
		return fmt.Errorf("invalid value for json: %v", err)
	}
	return nil
}

func parseConfig(cmd *cobra.Command) (*core.Config, error) {
	// TODO soit url soit une liste d'URL
	url, _ := cmd.Flags().GetString("url")
	insecure, _ := cmd.Flags().GetBool("insecure")
	urlFile, _ := cmd.Flags().GetString("url-file")
	protocol, _ := cmd.Flags().GetString("protocol")
	maxSeverity, _ := cmd.Flags().GetString("max-severity")
	csv, _ := cmd.Flags().GetBool("csv")
	json, _ := cmd.Flags().GetBool("json")

	var urls []string
	if url != "" {
		urls = append(urls, url)
	}
	if urlFile != "" {
		urlFileContent, err := os.Open(urlFile)
		if err != nil {
			return nil, err
		}
		defer urlFileContent.Close()
		scanner := bufio.NewScanner(urlFileContent)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	// Load config flags in config struct
	config := &core.Config{
		Insecure:    insecure,
		Protocol:    protocol,
		maxSeverity: maxSeverity,
		Csv:         csv,
		Json:        json,
		Urls:        urls,
	}

	return config, nil
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
