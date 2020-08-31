package cmd

import (
	"fmt"
	"gochopchop/app"

	"github.com/spf13/cobra"
)

func init() {
	pluginCmd = &cobra.Command{
		Use:   "plugins",
		Short: "list checks of configuration file",
		RunE:  run,
	}
	addConfigFlag(pluginCmd)
	pluginCmd.Flags().StringP("severity", "s", "", "severity option for list tag") // --severity ou -s
	// prerun needed ?
	// pluginCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
	//     configureGlobalOptions()
	// }
	rootCmd.AddCommand(pluginCmd)
}

func run(cmd *cobra.Command, args []string) error {
	config, err := parseConfig(cmd)
	if err != nil {
		return err
	}
	options, err := parseOptions(cmd)
	if err != nil {
		return err
	}
	// call core with struct
	app.List(config, options)
	return nil
}

func parseOptions(cmd *cobra.Command) (*app.ListOptions, error) {
	//Validate severity input
	options := new(app.ListOptions)
	severity, err := cmd.Flags().GetString("severity")
	if err != nil {
		return nil, fmt.Errorf("invalid value for severity: %v", err)
	}
	if severity == "High" || severity == "Medium" || severity == "Low" || severity == "Informational" {
		options.Severity = severity
	} else {
		return nil, fmt.Errorf(" ------ Unknown severity type : %s . Only Informational / Low / Medium / High are valid severity types.", severity)
	}
	return options, nil
}
