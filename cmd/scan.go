package cmd

import (
	"bufio"
	"fmt"
	"gochopchop/core"
	"gochopchop/userside/formatting"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func init() {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "scan endpoints to check if services/files/folders are exposed",
		RunE:  runScan,
	}
	addSignaturesFlag(scanCmd)

	scanCmd.Flags().StringP("url", "u", "", "url to scan")                                                               // --url OU -u
	scanCmd.Flags().BoolP("insecure", "k", false, "Check SSL certificate")                                               // --insecure ou -n
	scanCmd.Flags().StringP("input-file", "i", "", "path to a specified file containing urls to test")                   // --uri-file ou -f
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
	begin := time.Now()
	result, err := core.Scan(signatures, config)
	if err != nil {
		return err
	}

	log.Printf("Scan execution time: %s", time.Since(begin))

	if len(result) > 0 {
		
		// TODO renommer la fonction, genre PrintTable
		formatting.FormatOutputTable(result)

		if config.Json {
			formatting.ExportJSON(result)
		}
		if config.Csv {
			formatting.ExportCSV(result)
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

func parseConfig(cmd *cobra.Command) (*core.Config, error) {
	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return fmt.Errorf("invalid value for insecure: %v", err)
	}

	csv, err = cmd.Flags().GetBool("csv")
	if err != nil {
		return fmt.Errorf("invalid value for csv: %v", err)
	}

	json, err = cmd.Flags().GetBool("json")
	if err != nil {
		return fmt.Errorf("invalid value for json: %v", err)
	}

	var urls []string
	// TODO si URL seule alors la passer comme argument et non comme flag
	// TODO check si URL seule ou si liste d'URL - fail si les 2 sont present ? a discuter
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		return fmt.Errorf("invalid value for url: %v", err)
	}
	if url != "" && IsUrl(url) {
			urls = append(urls, url)
	} else {
		return nil, fmt.Errorf("URL is not valid")
	}

	
	inputFile, err := cmd.Flags().GetString("input-file")
	if err != nil {
		return fmt.Errorf("invalid value for input-file: %v", err)
	}
	if inputFile != "" {
		content, err := os.Open(inputFile)
		if err != nil {
			return nil, err
		}
		defer content.Close()
		scanner := bufio.NewScanner(content)
		for url := scanner.Scan() {
			if IsUrl(url) {
				urls = append(urls, url)
			} else {
				fmt.Printf("[WARN] url: %s - is not valid - skipping scan \n", url)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	maxSeverity, err := cmd.Flags().GetString("maxSeverity")
	if err != nil {
		return fmt.Errorf("invalid value for maxSeverity: %v", err)
	}
	if maxSeverity != "" {
		if maxSeverity != "High" || maxSeverity != "Medium" || maxSeverity != "Low" || maxSeverity != "Informational" {
			// TODO rework pour ne pas repeter les types de severity
			return nil, fmt.Errorf(" ------ Unknown severity type : %s . Only Informational / Low / Medium / High are valid severity types.", maxSeverity)
		}
	}

	config := &core.Config{
		Insecure:    insecure,
		maxSeverity: maxSeverity,
		Csv:         csv,
		Json:        json,
		Urls:        urls,
	}

	return config, nil
}

func IsUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
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
