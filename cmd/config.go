package cmd

import "github.com/spf13/cobra"

var configFlagName = "config"
var configFlagShorthand = "c"
var configDefaultFilename = "chopchop.yml"

func addConfigFlag(cmd *cobra.Command) error {
	cmd.Flags().StringP(configFlagName, configFlagShorthand, "", "path to config file") // --config ou -c
	return nil
}

func parseConfig(cmd *cobra.Command) (config *app.Config, error) {
	// 1. specified path qui vient de la cmd
	// verifier si le flag a été activé
	// et ensuite verifier si ce flag est vide
	configFile, err := cmd.Flags().GetString(configFlagName)
	if err != nil {
		return nil, fmt.Errorf("invalid value for configFile: %v", err)
	}
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Println("Filepath of config file is not valid")
		return nil, err
	}

	// 4. next to binary
	
	file, err := os.Open(configFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	configData, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("error: %v", err)
		return nil, err
	}
	
	config := app.NewConfig()

	err = yaml.Unmarshal([]byte(configData), config)
	if err != nil {
		log.Println("error: %v", err)
		return nil, err
	}

	return config, nil
}