package formatting

import (
	"encoding/json"
	"fmt"
	"gochopchop/core"
	"os"
	"time"
)

// TODO REFACTOR NAMES OF JSON ( endpoints ? PAth ? url ? )
// faire la structure du JSON qui soit logique et ait du sens
// quest ce que chopchop fait rellement et quels sont les resultats attendus pour cette commande là
// comme on est dans un package a part en plus, eske cette structure de resultat est la meme pour toutes les commandes ?
type outputJSON struct {
	domains []domains `json:"domains"`
}

type domains struct {
	domain string `json:"domain"`
	urls   []urls `json:"urls"`
}

type urls struct {
	url         string `json:"url,omitempty"`
	pluginName  string `json:"plugin_name,omitempty"`
	severity    string `json:"severity,omitempty"`
	remediation string `json:"remediation,omitempty"`
}

// ExportJSON will save the output to a JSON file
func ExportJSON(out []core.Output) error {
	// FIXME refactor me

	jsonOut := outputJSON{}

	// TODO use range not compteur
	for output := range out {
		added := false
		// Check if domain already exist - if yes append infos
		for d := range jsonOut.domains {
			if d.domain == output.Domain {
				d.urls = append(d.urls, urls{
					url:         output.url,
					pluginName:  output.pluginName,
					severity:    output.severity,
					remediation: output.remediation,
				})
				added = true
			}
		}
		if !added {
			// If domain not found, create it
			jsonOut.domains = append(jsonOut.domains, domains{
				domain: output.Domain,
				urls:   nil,
			})
			jsonOut.domains[len(jsonOut.domains)-1].urls = append(jsonOut.domains[len(jsonOut.domains)-1].urls, urls{
				url:         output.url,
				pluginName:  output.pluginName,
				severity:    output.severity,
				remediation: output.remediation,
			})
		}
	}

	now := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("./gochopchop_%s.json", now)
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	file, _ := json.MarshalIndent(jsonOut, "", " ")

	_, err = f.Write([]byte(file))
	if err != nil {
		return err
	}
	fmt.Printf("Output as json : %s", filename)
	f.Close()
	return nil
}
