package cmd

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "chopchop",
	Short: "tool for dynamic application security testing on web applications",
	Long: `
 ________                 _________ .__                  _________ .__                    ._.
 /  _____/  ____           \_   ___ \|  |__   ____ ______ \_   ___ \|  |__   ____ ______   | |
/   \  ___ /  _ \   ______ /    \  \/|  |  \ /  _ \\____ \/    \  \/|  |  \ /  _ \\____ \  | |
\    \_\  (  <_> ) /_____/ \     \___|   Y  (  <_> )  |_> >     \___|   Y  (  <_> )  |_> >  \|
 \______  /\____/           \______  /___|  /\____/|   __/ \______  /___|  /\____/|   __/   __
		\/                         \/     \/       |__|           \/     \/       |__|      \/
Link: https://github.com/michelin/ChopChop`,
	SilenceUsage:      true,
	PersistentPreRunE: setupLogs,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.PersistentFlags().StringP("verbosity", "v", logrus.WarnLevel.String(), "Log level (debug, info, warn, error, fatal, panic)")
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func setupLogs(cmd *cobra.Command, args []string) error {
	logrus.SetOutput(os.Stdout)

	verbosity, err := cmd.Flags().GetString("verbosity")
	if err != nil {
		return fmt.Errorf("invalid value for verbosity: %v", err)
	}

	verboseLevel, err := logrus.ParseLevel(verbosity)
	if err != nil {
		return err
	}
	logrus.SetLevel(verboseLevel)
	return nil
}
