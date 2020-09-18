package cmd

import (
	"fmt"
	"gochopchop/core"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var signatureFlagName = "signatures"
var signatureFlagShorthand = "c"
var signatureDefaultFilename = "chopchop.yml"

func addSignaturesFlag(cmd *cobra.Command) error {
	cmd.Flags().StringP(signatureFlagName, signatureFlagShorthand, signatureDefaultFilename, "path to signature file") // --signature ou -c
	return nil
}

func parseSignatures(cmd *cobra.Command) (*core.Signatures, error) {

	signatureFile, err := cmd.Flags().GetString(signatureFlagName)
	if err != nil {
		return nil, fmt.Errorf("invalid value for signatureFile: %v", err)
	}
	if _, err := os.Stat(signatureFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("Path of signatures file is not valid")
	}

	file, err := os.Open(signatureFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	signatureData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	signatures := core.NewSignatures()

	err = yaml.Unmarshal([]byte(signatureData), signatures)
	if err != nil {
		return nil, err
	}

	for _, plugin := range signatures.Plugins {
		for _, check := range plugin.Checks {
			if check.Description == nil {
				return nil, fmt.Errorf("Missing description field in %s plugin checks. Stopping execution.", check.PluginName)
			}
			if check.Remediation == nil {
				return nil, fmt.Errorf("Missing remediation field in %s plugin checks. Stopping execution.", check.PluginName)
			}
			if check.Severity == nil {
				return nil, fmt.Errorf("Missing severity field in %s plugin checks. Stopping execution.", check.PluginName)
			}
			if !core.ValidSeverity(*check.Severity) {
				return nil, fmt.Errorf("Invalid severity : %s. Please use : %s", *check.Severity, core.SeveritiesAsString())
			}
		}
	}

	return signatures, nil
}
