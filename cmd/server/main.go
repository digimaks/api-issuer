// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

// Version holds the current application version.
var Version = "1.0.0-dev"

// RootCmd is the base command.
var RootCmd *cobra.Command

// Execute adds all child commands to the root command.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func initRootCmd() {
	if RootCmd != nil {
		return
	}

	RootCmd = &cobra.Command{
		Use:   "server",
		Short: "EUDIW PID Credential Issuer",
		Long: `EUDIW PID Credential Issuer implements OpenID4VCI pre-authorized code
  flow to issue PID credentials in mso_mdoc and SD-JWT-VC formats.`,
		RunE: runWeb,
	}
}

func main() {
	initRootCmd()

	RootCmd.Version = Version

	if _, ok := os.LookupEnv("SERVER_URLS"); !ok {
		_ = os.Setenv("SERVER_URLS", "http://0.0.0.0:8080")
	}

	Execute()
}
