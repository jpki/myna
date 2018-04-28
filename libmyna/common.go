package libmyna

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

/*
func Ready() (*Reader, error) {
	reader, err := NewReader()
	if err != nil {
		return nil, err
	}
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return nil, err
	}
	return reader, nil
}
*/

func GetPinStatus() (map[string]int, error) {
	reader, err := NewReader()
	if err != nil {
		return nil, err
	}
	defer reader.Finalize()
	reader.SetDebug(Debug)
	err = reader.Connect()
	if err != nil {
		return nil, err
	}

	status := map[string]int{}

	reader.SelectCardInfoAP()
	reader.SelectEF("00 12")
	status["card_info_pin_a"] = reader.LookupPin()
	reader.SelectEF("00 13")
	status["card_info_pin_b"] = reader.LookupPin()
	reader.SelectCardInputHelperAP()
	reader.SelectEF("00 11")
	status["card_input_helper_pin"] = reader.LookupPin()
	reader.SelectEF("00 14")
	status["card_input_helper_pin_a"] = reader.LookupPin()
	reader.SelectEF("00 15")
	status["card_input_helper_pin_b"] = reader.LookupPin()

	reader.SelectJPKIAP()
	reader.SelectEF("00 18") // IEF for AUTH
	status["jpki_auth"] = reader.LookupPin()

	reader.SelectEF("00 1B") // IEF for SIGN
	status["jpki_sign"] = reader.LookupPin()

	reader.SelectAP("D3 92 10 00 31 00 01 01 01 00") // 謎AP
	reader.SelectEF("00 1C")
	status["unknown1"] = reader.LookupPin()

	reader.SelectAP("D3 92 10 00 31 00 01 01 04 01") // 謎AP
	reader.SelectEF("00 1C")
	status["unknown2"] = reader.LookupPin()
	return status, nil
}

var digestInfoPrefix = map[crypto.Hash][]byte{
	crypto.SHA1: {
		0x30, 0x21, // SEQUENCE {
		0x30, 0x09, // SEQUENCE {
		0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, // SHA1 OID
		0x05, 0x00, // NULL }
		0x04, 0x14, // OCTET STRING }
	},
	crypto.SHA256: {
		0x30, 0x31, // SEQUENCE {
		0x30, 0x0d, // SEQUENCE {
		0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // SHA256 OID
		0x05, 0x00, // NULL }
		0x04, 0x20, // OCTET STRING }
	},
	crypto.SHA384: {
		0x30, 0x41, // SEQUENCE {
		0x30, 0x0d, // SEQUENCE {
		0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, // SHA384 OID
		0x05, 0x00, // NULL }
		0x04, 0x30, // OCTET STRING }
	},
	crypto.SHA512: {
		0x30, 0x51, // SEQUENCE {
		0x30, 0x0d, // SEQUENCE {
		0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, // SHA512 OID
		0x05, 0x00, // NULL }
		0x04, 0x40, // OCTET STRING }
	},
}

func makeDigestInfo(hashid crypto.Hash, digest []byte) []byte {
	prefix := digestInfoPrefix[hashid]
	return append(prefix, digest...)
}

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

var oid2str = map[string]string{
	"2.5.4.3":  "CN",
	"2.5.4.6":  "C",
	"2.5.4.7":  "L",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
}

func Name2String(name pkix.Name) string {
	var dn []string
	for _, rdns := range name.ToRDNSequence() {
		for _, rdn := range rdns {
			value := rdn.Value.(string)
			if key, ok := oid2str[rdn.Type.String()]; ok {
				dn = append(dn, fmt.Sprintf("%s=%s", key, value))
			} else {
				dn = append(dn, fmt.Sprintf("%s=%s", rdn.Type.String(), value))
			}
		}
	}
	return strings.Join(dn, "/")
}
