package cmd

import (
	"bufio"
	"fmt"
	"gochopchop/core"
	"gochopchop/serverside/httpget"
	"gochopchop/userside/formatting"
	"net/url"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "scan endpoints to check if services/files/folders are exposed",
		RunE:  runScan,
	}
	addSignaturesFlag(scanCmd)

	scanCmd.Flags().StringP("url", "u", "", "url to scan")                                                                                      // --url OU -u
	scanCmd.Flags().BoolP("insecure", "k", false, "Check SSL certificate")                                                                      // --insecure ou -n
	scanCmd.Flags().StringP("input-file", "i", "", "path to a specified file containing urls to test")                                          // --uri-file ou -f
	scanCmd.Flags().StringP("max-severity", "b", "", "block the CI pipeline if severity is over or equal specified flag")                       // --max-severity ou -m
	scanCmd.Flags().StringSliceP("export-format", "e", []string{}, "export of the output (csv and json)")                                       //--export ou --e
	scanCmd.Flags().StringP("export-filename", "", "", "filename for export files")                                                             // --export-filename
	scanCmd.Flags().IntP("timeout", "t", 10, "Timeout for the HTTP requests (default: 10s)")                                                    // --timeout ou -ts
	scanCmd.Flags().StringP("severity-filter", "", "", "Filter by severity (engine will check for same severity checks)")                       // --severity-filter
	scanCmd.Flags().StringP("plugin-filter", "", "", "Filter by the name of the plugin (engine will only check for plugin with the same name)") // --plugin-filter
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	config, err := parseConfig(cmd, args)
	if err != nil {
		return err
	}

	signatures, err := parseSignatures(cmd, config.SeverityFilter, config.PluginFilter)
	if err != nil {
		return err
	}
	begin := time.Now()

	// serverside
	fetcher := httpget.NewFetcher(config.Insecure, config.Timeout)
	noRedirectFetcher := httpget.NewNoRedirectFetcher(config.Insecure, config.Timeout)
	// core
	scanner := core.NewScanner(fetcher, noRedirectFetcher, signatures)

	result, err := scanner.Scan(cmd.Context(), config.Urls)
	if err != nil {
		return err
	}

	log.Info("Scan execution time:", time.Since(begin))

	if len(result) > 0 {

		formatting.PrintTable(result)
		if contains(config.ExportFormats, "json") {
			formatting.ExportJSON(config.ExportFilename, result)
		}
		if contains(config.ExportFormats, "csv") {
			formatting.ExportCSV(config.ExportFilename, result)
		}

		if config.MaxSeverity != "" {
			for _, output := range result {
				if core.SeverityReached(config.MaxSeverity, output.Severity) {
					return fmt.Errorf("Max severity level reached, exiting with error code")
				}
			}
		}
	} else {
		log.Info("No vulnerabilities found. Exiting...")
	}
	return nil
}

func parseConfig(cmd *cobra.Command, args []string) (*core.Config, error) {

	inputFile, err := cmd.Flags().GetString("input-file")
	if err != nil {
		return nil, fmt.Errorf("invalid value for input-file: %v", err)
	}

	if inputFile != "" && len(args) >= 1 {
		// both input-file and url are set, abort
		return nil, fmt.Errorf("Can't specify url with url list flag")
	}
	if inputFile == "" && len(args) == 0 {
		// no input-file and no argument, abort
		return nil, fmt.Errorf("No url provided, please set the input-file flag or provide an url as an argument")
	}

	var urls []string
	if inputFile != "" {
		content, err := os.Open(inputFile)
		if err != nil {
			return nil, err
		}
		defer content.Close()
		scanner := bufio.NewScanner(content)
		for scanner.Scan() {
			url := scanner.Text()
			if !isURL(url) {
				log.Warn("url: %s - is not valid - skipping scan \n", url)
				continue
			}
			urls = append(urls, url)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	if len(args) > 1 {
		return nil, fmt.Errorf("Please provide only one URL")
	}

	if len(args) == 1 {
		url := args[0]
		if isURL(url) {
			urls = append(urls, url)
		} else {
			return nil, fmt.Errorf("Please provide a valid URL")
		}
	}

	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return nil, fmt.Errorf("invalid value for insecure: %v", err)
	}

	severityFilter, err := cmd.Flags().GetString("severity-filter")
	if err != nil {
		return nil, fmt.Errorf("invalid value for severity-filter: %v", err)
	}

	pluginFilter, err := cmd.Flags().GetString("plugin-filter")
	if err != nil {
		return nil, fmt.Errorf("invalid value for plugin-filter: %v", err)
	}

	exportFormats, err := cmd.Flags().GetStringSlice("export-format")
	if err != nil {
		return nil, fmt.Errorf("invalid value for export: %v", err)
	}

	if len(exportFormats) > 0 {
		for _, f := range exportFormats {
			if f != "csv" && f != "json" {
				return nil, fmt.Errorf("invalid value for export: %v , expected csv or json", f)
			}
		}
	}

	maxSeverity, err := cmd.Flags().GetString("max-severity")
	if err != nil {
		return nil, fmt.Errorf("invalid value for maxSeverity: %v", err)
	}

	exportFilename, err := cmd.Flags().GetString("export-filename")
	if err != nil {
		return nil, fmt.Errorf("invalid value for exportFilename: %v", err)
	}
	if exportFilename == "" {
		now := time.Now().Format("2006-01-02_15-04-05")
		exportFilename = fmt.Sprintf("./gochopchop_%s", now)
	}

	if maxSeverity != "" {
		if core.ValidSeverity(maxSeverity) {
			return nil, fmt.Errorf("Invalid severity level : %s. Please use : %s", maxSeverity, core.SeveritiesAsString())
		}
	}

	timeout, err := cmd.Flags().GetInt("timeout")
	if err != nil {
		return nil, fmt.Errorf("Invalid value for timeout: %v", err)
	}

	config := &core.Config{
		Insecure:       insecure,
		MaxSeverity:    maxSeverity,
		ExportFormats:  exportFormats,
		Urls:           urls,
		Timeout:        timeout,
		ExportFilename: exportFilename,
		SeverityFilter: severityFilter,
		PluginFilter:   pluginFilter,
	}

	return config, nil
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
