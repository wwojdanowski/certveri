/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

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
		if err := cmd.ParseFlags(args); err != nil {
			fmt.Printf("Error parsing the command line flags %v\n", err)
			return

		}
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

type rule func(c *Certificate, chain map[string]*Certificate) error

type validations []error

func (r validations) String() string {
	var errorStrings []string

	for i := 0; i < len(r); i++ {
		errorStrings = append(errorStrings, r[i].Error())
	}

	return strings.Join(errorStrings, ", ")
}

func makeRules() []rule {
	rules := []rule{
		func(c *Certificate, chain map[string]*Certificate) error {
			now := time.Now()
			if now.Before(c.NotBefore) || now.After(c.NotAfter) {
				return errors.New("Certificate has expired")
			}
			return nil
		},
		func(c *Certificate, chain map[string]*Certificate) error {
			if parent, ok := chain[c.Issuer.CommonName]; !ok {
				return nil
			} else if !parent.BasicConstraintsValid || !parent.IsCA {
				return errors.New("Certificate signed by unauthorized issuer")
			}
			return nil
		},
		func(c *Certificate, chain map[string]*Certificate) error {
			if _, ok := chain[c.Issuer.CommonName]; !ok {
				return errors.New("Unknown certificate issuer")
			}
			return nil
		},
	}
	return rules
}

func verifyParticularCertificate(rules []rule, c *Certificate, chain map[string]*Certificate) (result validations) {

	result = validations{}

	for i := 0; i < len(rules); i++ {
		r := rules[i]
		if err := r(c, chain); err != nil {
			result = append(result, err)
		}
	}
	return
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

	verificationRules := makeRules()

	for {
		result := verifyParticularCertificate(verificationRules, certChain[index.Subject.CommonName], certChain)
		emojis := emoji.CheckMarkButton

		if len(result) > 0 {
			emojis = emoji.Warning
			fmt.Printf("%v %s %s\n", emojis, index.Path, result)
		} else {
			fmt.Printf("%v %s\n", emojis, index.Path)
		}
		issuerCn := index.Issuer.CommonName
		if val, ok := certChain[issuerCn]; ok {
			index = val
		} else {
			// fmt.Printf("%v %s\n", emoji.CrossMark, index.Path)
			return fmt.Errorf("failed to verify certificate")
		}
		if issuerCn == caCert.Subject.CommonName {
			fmt.Printf("%v %s\n", emoji.CheckMarkButton, caCert.Path)
			return nil
		}
	}
}

func init() {
	verifyCmd.Flags().String("ca", "", "Certificate Authority")
	verifyCmd.Flags().String("cert", "", "Certificate")
	verifyCmd.Flags().StringArray("int", []string{}, "Intermediate certificate, can be more than one")
	//nolint:errcheck
	verifyCmd.MarkFlagRequired("ca")
	//nolint:errcheck
	verifyCmd.MarkFlagRequired("cert")
	rootCmd.AddCommand(verifyCmd)
}
