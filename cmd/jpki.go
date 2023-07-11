package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/ianmcmahon/encoding_ssh"
	"github.com/spf13/cobra"

	"github.com/jpki/myna/libmyna"
)

var jpkiCmd = &cobra.Command{
	Use:   "jpki",
	Short: "公的個人認証関連コマンド",
	Long: `公的個人認証関連コマンド
各種証明書の取得や署名・検証を行います
`,
}

var jpkiCertCmd = &cobra.Command{
	Use:   "cert auth|sign|authca|signca",
	Short: "JPKI証明書を表示",
	Long: `公的個人認証の証明書を表示します。

 - auth   利用者認証用証明書(スマホJPKIの場合PIN入力が必要)
 - authca 利用者認証用CA証明書
 - sign   電子署名用証明書(署名用パスワードが必要)
 - signca 電子署名用CA証明書
`,
	RunE: jpkiCert,
}

func jpkiCert(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		cmd.Help()
		return nil
	}
	var cert *x509.Certificate
	var err error
	var pin string
	reader, err := libmyna.NewReader(libmyna.OptionDebug)
	if err != nil {
		return err
	}
	defer reader.Finalize()
	err = reader.Connect()
	if err != nil {
		return err
	}

	jpkiAP, err := reader.SelectJPKIAP()
	if err != nil {
		return err
	}
	token, err := jpkiAP.ReadToken()
	if err != nil {
		return err
	}

	switch strings.ToUpper(args[0]) {
	case "AUTH":
		if token == "JPKIAPGPSETOKEN" {
			// スマホJPKI
			pin, err = cmd.Flags().GetString("pin")
			if pin == "" {
				pin, err = inputPin("認証用パスワード(4桁): ")
				if err != nil {
					return nil
				}
			}
			pin = strings.ToUpper(pin)
			err = jpkiAP.VerifyAuthPin(pin)
			if err != nil {
				return nil
			}
		}
		cert, err = jpkiAP.ReadAuthCert()
	case "AUTHCA":
		cert, err = jpkiAP.ReadAuthCACert()
	case "SIGN":
		pin, err = cmd.Flags().GetString("pin")
		if pin == "" {
			pin, err = inputPin("署名用パスワード(6-16桁): ")
			if err != nil {
				return nil
			}
		}
		pin = strings.ToUpper(pin)
		err = jpkiAP.VerifySignPin(pin)
		cert, err = jpkiAP.ReadSignCert()
	case "SIGNCA":
		cert, err = jpkiAP.ReadSignCACert()
	default:
		cmd.Usage()
		return nil
	}
	if err != nil {
		return err
	}

	err = outputCert(cert, cmd)
	if err != nil {
		return err
	}
	return nil
}

func outputCert(cert *x509.Certificate, cmd *cobra.Command) error {
	form, _ := cmd.Flags().GetString("form")
	jpkiCert := &libmyna.JPKICertificate{cert}
	switch form {
	case "text":
		println(jpkiCert.ToString())
	case "pem":
		printCertPem(cert)
	case "der":
		os.Stdout.Write(cert.Raw)
	case "ssh":
		printCertSsh(cert)
	default:
		cmd.Usage()
		return nil
	}
	return nil
}

func printCertPem(cert *x509.Certificate) {
	var block pem.Block
	block.Type = "CERTIFICATE"
	block.Bytes = cert.Raw
	pem.Encode(os.Stdout, &block)
}

func printCertSsh(cert *x509.Certificate) {
	rsaPubkey := cert.PublicKey.(*rsa.PublicKey)
	sshPubkey, _ := ssh.EncodePublicKey(*rsaPubkey, "")
	fmt.Println(sshPubkey)
}

func init() {
	jpkiCmd.AddCommand(jpkiCertCmd)
	jpkiCertCmd.Flags().StringP(
		"form", "f", "text", "出力形式(text|pem|der|ssh)")
	jpkiCertCmd.Flags().StringP(
		"pin", "p", "", "パスワード(署名用証明書のみ)")
}
