package cmd

import (
	"fmt"
	"gochopchop/app"
	"log"

	"github.com/spf13/cobra"
)

func init() {
	pluginCmd = &cobra.Command{
		Use:   "plugins",
		Short: "list checks of configuration file",
		RunE:  run,
	}

	// TODO fonction qui recupere la config + la parse
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
		// no config found donc return err
	}
	// parse flags
	// call core with struct
	app.List()
	return nil
}

func pluginCheckArgsAndFlags(cmd *cobra.Command, args []string) error {
	//Validate severity input
	severity, err := cmd.Flags().GetString("severity")
	if err != nil {
		return fmt.Errorf("invalid value for severity: %v", err)
	}
	if severity != "" {
		if severity == "High" || severity == "Medium" || severity == "Low" || severity == "Informational" {
			fmt.Println("Display only check of severity : " + severity)
		} else {
			log.Fatal(" ------ Unknown severity type : " + severity + " . Only Informational / Low / Medium / High are valid severity types.")
		}
	}
	if err := cmd.Flags().Set("config-file", configFile); err != nil {
		return fmt.Errorf("error while setting filepath of config file")
	}
	return nil
}
