package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
)

// These 2 structures are used to parse trivy json results partially
type TrivyVulnerability struct {
	Severity string `json:"Severity"`
}

type TrivyResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

type TrivyResults struct {
	Results []TrivyResult `json:"Results"`
}

func TrivyScanImage(trivyserver string, trivypath string, image string, registries DockerAuths) (sum VulnSummary, err error) {
	sum = VulnSummary{}
	err = nil

	// Use either client-server mode or standalone
	var trivy *exec.Cmd
	trivy = exec.Command("/bin/sh", "-c", trivypath+" client --remote "+trivyserver+" -f json "+image+" | grep -v WARN")

	//If image needs an auth, add env vars for private registry
	trivy.Env = os.Environ()
	for reg := range registries.Auths {
		if strings.HasPrefix(image, reg) {
			log.Info().Str("Image", image).Str("Registry", reg).Msg("Image needs an auth for external registry")
			trivy.Env = append(trivy.Env, "TRIVY_USERNAME="+registries.Auths[reg].Username)
			trivy.Env = append(trivy.Env, "TRIVY_PASSWORD="+registries.Auths[reg].Password)
			break
		}
	}

	// https://github.com/aquasecurity/trivy/discussions/1050
	trivy.Env = append(trivy.Env, "TRIVY_NEW_JSON_SCHEMA=true")

	// Run the pipeline
	var output []byte
	output, err = trivy.Output()
	if err != nil {
		log.Error().Interface("Cmd", trivy).Msg("Error while executing trivy")
		return
	}

	// Unmarshal the JSON results
	var results TrivyResults
	err = json.Unmarshal(output, &results)
	if err != nil {
		log.Error().Str("Image", image).Bytes("stdout", output).Msg("Can't unmarshal trivy output")
		return
	}

	// Parse vulnerabilities and accumulate results in the image vulnerability summary
	for _, res := range results.Results {
		for _, vuln := range res.Vulnerabilities {
			sum = sum.Add(SummaryForSeverity(fmt.Sprintf("%v", vuln.Severity)))
		}
	}
	return
}
