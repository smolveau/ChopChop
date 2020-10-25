package cmd

import (
	"fmt"
	"gochopchop/core"
	"io/ioutil"
	"os"
	"strings"

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

func parseSignatures(cmd *cobra.Command, severityFilter string, nameFilter string) (*core.Signatures, error) {

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

	// Return only concerned signatures by severity filter
	if severityFilter != "" {
		if !core.ValidSeverity(severityFilter) {
			return nil, fmt.Errorf("Invalid severity : %s. Please use : %s", severityFilter, core.SeveritiesAsString())
		}
		signatures = FilterSignaturesBySeverity(signatures, severityFilter)
	}

	// Return only concerned by name filter
	if nameFilter != "" {
		signatures = FilterSignaturesByName(signatures, nameFilter)
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

func FilterSignaturesBySeverity(signatures *core.Signatures, severityFilter string) *core.Signatures {
	/*
		pour chaque plugin
			pour chaque check
			si severite == filtre severite
				si le plugin est deja gardé
				sinon ajouter le plugin
				ajouter le check
			sinon
				passer
	*/
	// TODO A changer - Voir si d'autres solutions
	filteredSignatures := core.NewSignatures()
	for _, plugin := range signatures.Plugins {
		filteredPlugin := plugin
		filteredChecks := []core.Check{}
		for _, check := range plugin.Checks {
			if *check.Severity == severityFilter {
				filteredChecks = append(filteredChecks, check)
			} else {
				continue
			}
		}
		if len(filteredChecks) > 0 {
			filteredPlugin.Checks = filteredChecks
			filteredSignatures.Plugins = append(filteredSignatures.Plugins, filteredPlugin)
		}
	}
	return filteredSignatures
}

func FilterSignaturesByName(signatures *core.Signatures, name string) *core.Signatures {
	// TODO A changer - Voir si d'autres solutions
	filteredSignatures := core.NewSignatures()
	for _, plugin := range signatures.Plugins {
		filteredPlugin := plugin
		filteredChecks := []core.Check{}
		for _, check := range plugin.Checks {
			if strings.Contains(check.PluginName, name) {
				filteredChecks = append(filteredChecks, check)
			} else {
				continue
			}
		}
		if len(filteredChecks) > 0 {
			filteredPlugin.Checks = filteredChecks
			filteredSignatures.Plugins = append(filteredSignatures.Plugins, filteredPlugin)
		}
	}
	return filteredSignatures
}
