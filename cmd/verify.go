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

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
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

func init() {
	verifyCmd.Flags().String("ca", "", "Certificate Authority")
	verifyCmd.Flags().String("cert", "", "Certificate")
	rootCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
