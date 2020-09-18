package formatting

import (
	"encoding/json"
	"fmt"
	"gochopchop/core"
	"os"
	"time"
)

type result struct {
	checks []core.Output `json:"checks"`
}

// ExportJSON will save the output to a JSON file
func ExportJSON(out []core.Output) error {
	result := result{
		checks: out,
	}

	jsonstr, err := json.Marshal(result)
	if err != nil {
		return err
	}

	now := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("./gochopchop_%s.json", now)
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	if err != nil {
		return err
	}

	_, err = f.Write(jsonstr)
	if err != nil {
		return err
	}

	fmt.Printf("Output as json : %s", filename)

	return nil
}
