/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "certveri",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		cmd.ParseFlags(args)
		cmd.Flags()
		err := verify(cmd)
		if err != nil {
			fmt.Printf("Verification failed with: %s\n", err)
		} else {
			fmt.Println("Verification complete and successful")
		}
	},
}

func verify(cmd *cobra.Command) error {
	ca, _ := cmd.Flags().GetString("ca")
	certFile, _ := cmd.Flags().GetString("cert")
	caContent, _ := os.ReadFile(ca)
	certPool := x509.NewCertPool()

	if _, err := os.Stat(ca); err != nil {
		return err
	}

	if _, err := os.Stat(certFile); err != nil {
		return err
	}

	if ok := certPool.AppendCertsFromPEM(caContent); !ok {
		return fmt.Errorf("Failed to load PEM file '%s'", ca)
	}

	certContent, _ := os.ReadFile(certFile)

	block, _ := pem.Decode([]byte(certContent))
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		Roots: certPool,
		// DNSName:       serverName,
		Intermediates: x509.NewCertPool(),
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: " + err.Error())
	}

	return nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.certveri.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().String("ca", "", "Certificate Authority")
	rootCmd.Flags().String("cert", "", "Certificate")
	rootCmd.Flags().StringP("toggle", "t", "", "Help message for toggle")
}
