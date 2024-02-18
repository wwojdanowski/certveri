/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// dumpCmd represents the dump command
var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		dump(cmd)
	},
}

func dump(cmd *cobra.Command) error {

	certFile, _ := cmd.Flags().GetString("cert")

	certContent, _ := os.ReadFile(certFile)

	block, _ := pem.Decode([]byte(certContent))
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: " + err.Error())
	}

	/*
		Version             int
		SerialNumber        *big.Int
		Issuer              pkix.Name
		Subject             pkix.Name
		NotBefore, NotAfter time.Time // Validity bounds.
		KeyUsage            KeyUsage
	*/

	fmt.Printf("Version: %d\n", cert.Version)

	if hexString, err := hexStringToBytesFormat(hex.EncodeToString(cert.SerialNumber.Bytes())); err == nil {
		fmt.Printf("Serial number: %s\n", hexString)
	} else {
		fmt.Printf("Serial number: %s\n", "--------")
	}

	fmt.Printf("Issuer: %s\n", cert.Issuer)
	fmt.Printf("Subjects: %s\n", cert.Subject)
	fmt.Printf("Usabillity time: %s - %s\n", cert.NotBefore, cert.NotAfter)

	return nil
}

func hexStringToBytesFormat(str string) (string, error) {
	if len(str)%2 != 0 {
		return "", errors.New("Unprocessable string")
	}

	var builder strings.Builder
	i := 0
	for ; i < len(str)-2; i += 2 {
		builder.WriteString(str[i : i+2])
		builder.WriteString(":")
	}
	builder.WriteString(str[i : i+2])

	return builder.String(), nil

}

func init() {
	dumpCmd.Flags().String("cert", "", "Certificate")
	rootCmd.AddCommand(dumpCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dumpCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dumpCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
