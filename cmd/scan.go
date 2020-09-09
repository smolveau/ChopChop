package cmd

import (
	"bufio"
	"fmt"
	"gochopchop/core"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("url", "u", "", "url to scan")                                                  // --url OU -u
	scanCmd.Flags().StringP("signature-file", "c", "chopchop.yml", "path to signature/data file")           // --signature-file ou -c
	scanCmd.Flags().BoolP("insecure", "i", false, "Check SSL certificate")                                  // --insecure ou -n
	scanCmd.Flags().StringP("url-file", "f", "", "path to a specified file containing urls to test")        // --uri-file ou -f
	scanCmd.Flags().StringP("suffix", "s", "", "Add suffix to urls when flag url-file is specified")        // --suffix ou -s
	scanCmd.Flags().StringP("prefix", "p", "", "Add prefix to urls when flag url-file is specified")        // --prefix ou -p
	scanCmd.Flags().StringP("block", "b", "", "Block pipeline if severity is over or equal specified flag") // --block ou -b
	scanCmd.Flags().BoolP("csv", "", false, "output as a csv file")                                         //--csv
	scanCmd.Flags().BoolP("json", "", false, "output as a json file")                                       //--json
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "scan URL endpoints to check if services/files/folders are exposed to the Internet",
	Args:  scanCheckArgsAndFlags,
	// TODO Add here loaded signature and config structs
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load Signatures into struct
		signatureFile, err := cmd.Flags().GetString("signature-file")
		if err != nil {
			return fmt.Errorf("invalid value for signatureFile: %v", err)
		}
		signatures, err := LoadSignature(signatureFile)
		if err != nil {
			return fmt.Errorf("", err)
		}
		CheckStructFields(signatures)

		// TODO Doit on recuperer tout les args et les fill ?
		config := fillConfig()
		return nil
	},
}

func scanCheckArgsAndFlags(cmd *cobra.Command, args []string) error {
	// TODO UNUSED THINGS
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		return fmt.Errorf("invalid value for url: %v", err)
	}
	signatureFile, err := cmd.Flags().GetString("signature-file")
	if err != nil {
		return fmt.Errorf("invalid value for signatureFile: %v", err)
	}
	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return fmt.Errorf("invalid value for insecure: %v", err)
	}
	urlFile, err := cmd.Flags().GetString("url-file")
	if err != nil {
		return fmt.Errorf("invalid value for urlFile: %v", err)
	}
	suffix, err := cmd.Flags().GetString("suffix")
	if err != nil {
		return fmt.Errorf("invalid value for suffix: %v", err)
	}
	prefix, err := cmd.Flags().GetString("prefix")
	if err != nil {
		return fmt.Errorf("invalid value for prefix: %v", err)
	}
	block, err := cmd.Flags().GetString("block")
	if err != nil {
		return fmt.Errorf("invalid value for block: %v", err)
	}
	csv, err := cmd.Flags().GetBool("csv")
	if err != nil {
		return fmt.Errorf("invalid value for csv: %v", err)
	}
	json, err := cmd.Flags().GetBool("json")
	if err != nil {
		return fmt.Errorf("invalid value for json: %v", err)
	}
	if url != "" {
		if !strings.HasPrefix(url, "http") {
			// If http or https not specified, return fatal log
			return fmt.Errorf("URL needs a specified prefix :  http:// or https://")
		}
	}
	if suffix != "" || prefix != "" {
		if urlFile == "" {
			return fmt.Errorf("suffix or prefix flags can't be assigned if flag url-file is not specified")
		}
	}
	if block != "" {
		if block == "High" || block == "Medium" || block == "Low" || block == "Informational" {
			fmt.Println("Block pipeline if severity is over or equal : " + block)
		} else {
			log.Fatal(" ------ Unknown severity type : " + block + " . Only Informational / Low / Medium / High are valid severity types.")
		}
	}
	if _, err := os.Stat(signatureFile); os.IsNotExist(err) {
		return fmt.Errorf("filepath of signature file is not valid")
	}
	if !strings.HasSuffix(signatureFile, ".yml") {
		return fmt.Errorf("signature file needs to be a yaml file")
	}
	if urlFile != "" {
		if _, err := os.Stat(urlFile); os.IsNotExist(err) {
			return fmt.Errorf("filepath of url file is not valid")
		}
	}
	if err := cmd.Flags().Set("signature-file", signatureFile); err != nil {
		return fmt.Errorf("error while setting filepath of signature file")
	}
	if err := cmd.Flags().Set("url-file", urlFile); err != nil {
		return fmt.Errorf("error while setting filepath of url file")
	}
	if err := cmd.Flags().Set("url", url); err != nil {
		return fmt.Errorf("error while setting url")
	}
	if err := cmd.Flags().Set("suffix", suffix); err != nil {
		return fmt.Errorf("error while setting suffix")
	}
	if err := cmd.Flags().Set("prefix", prefix); err != nil {
		return fmt.Errorf("error while setting prefix")
	}
	if err := cmd.Flags().Set("block", block); err != nil {
		return fmt.Errorf("error while setting block flag")
	}
	return nil
}

func fillConfig(url string, signatureFile string, insecure bool, urlFile string, suffix string, prefix string, block string, csv bool, json bool) core.Config {
	config := core.Config{}
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

	// Load config flags in config struct
	config = core.Config{
		Url:           url,
		SignatureFile: signatureFile,
		Insecure:      insecure,
		UrlFile:       urlFile,
		Suffix:        suffix,
		Prefix:        prefix,
		Block:         block,
		Csv:           csv,
		Json:          json,
		UrlList:       urlList,
	}

	return config
}

func LoadSignature(signatureFile string) (core.Signature, error) {
	y := core.Signature{}
	cfg, err := os.Open(signatureFile)
	if err != nil {
		return y, fmt.Errorf("error while opening yaml signature file : ", err)
	}

	defer cfg.Close()
	dataCfg, err := ioutil.ReadAll(cfg)

	if err = yaml.Unmarshal([]byte(dataCfg), &y); err != nil {
		return y, fmt.Errorf("error while unmarshal of yaml file : ", err)
	}
	return y, nil
}

// CheckStructFields will parse the YAML configuration file
func CheckStructFields(signatures core.Signature) {
	for index, plugin := range signatures.Plugins {
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
				if err := core.SeverityType.IsValid(*check.Severity); err != nil {
					log.Fatal(" ------ Unknown severity type : " + string(*check.Severity) + " . Only Informational / Low / Medium / High are valid severity types.")
				}
			}
		}
	}
}
