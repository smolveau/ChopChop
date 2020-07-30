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
		log.Println("Filepath of config file is not valid") // pas de fatal
		return nil, err
	}
	if !strings.HasSuffix(configFile, ".yml") {
		log.Println("Config file needs to be a yaml file") // pas de fatal
		return nil, err
	}

	// 2. si env XDG_DATA_HOME existe, verifier $XDG_DATA_HOME/chopchop/chopchop.yml
	// 3. $HOME/chopchop.yml
	// 4. next to binary

	// et qui va la parse dans une struct (importée du core) pour renvoyer une struct populée (ou une erreur)
	
	file, err := os.Open(configFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	configData, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("error: %v", err) // pas de fatal
		return nil, err
	}
	
	config := app.NewConfig()

	err = yaml.Unmarshal([]byte(configData), config)
	if err != nil {
		log.Println("error: %v", err) // pas de fatal
		return nil, err
	}

	return config, nil
}