/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/enescakir/emoji"
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

type Certificate struct {
	*x509.Certificate
	Path string
}

func loadCert(path string) (*Certificate, error) {
	content, _ := os.ReadFile(path)
	block, _ := pem.Decode([]byte(content))
	cert, _ := x509.ParseCertificate(block.Bytes)
	return &Certificate{cert, path}, nil
}

func verify(cmd *cobra.Command) error {
	ca, _ := cmd.Flags().GetString("ca")
	certFile, _ := cmd.Flags().GetString("cert")
	intermediateFiles, _ := cmd.Flags().GetStringArray("int")

	certChain := make(map[string]*Certificate)

	caCert, _ := loadCert(ca)

	certChain[caCert.Subject.CommonName] = caCert

	for i := 0; i < len(intermediateFiles); i++ {
		cert, _ := loadCert(intermediateFiles[i])
		certChain[cert.Subject.CommonName] = cert
	}
	cert, _ := loadCert(certFile)
	certChain[cert.Subject.CommonName] = cert
	index := cert

	for {
		issuerCn := index.Issuer.CommonName

		if val, ok := certChain[issuerCn]; ok {
			fmt.Printf("%v %s\n", emoji.CheckMarkButton, index.Path)
			if issuerCn == caCert.Subject.CommonName {
				fmt.Printf("%v %s\n", emoji.CheckMarkButton, caCert.Path)
				return nil
			}
			index = val
		} else {
			fmt.Printf("%v %s\n", emoji.CrossMark, index.Path)
			return fmt.Errorf("failed to verify certificate")
		}
	}
}

func init() {
	verifyCmd.Flags().String("ca", "", "Certificate Authority")
	verifyCmd.Flags().String("cert", "", "Certificate")
	verifyCmd.Flags().StringArray("int", []string{}, "Intermediate certificate, can be more than one")
	verifyCmd.MarkFlagRequired("ca")
	verifyCmd.MarkFlagRequired("cert")
	rootCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
