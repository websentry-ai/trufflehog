package customdetectors

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func buildPrivateKeyDetector(t *testing.T) detectors.Detector {
	t.Helper()
	d, err := NewPrivateKey()
	require.NoError(t, err, "NewPrivateKey() must not return an error")
	return d
}

const fakeRSAPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END RSA PRIVATE KEY-----`

const fakeOpenSSHPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKE12345AAAA
-----END OPENSSH PRIVATE KEY-----`

func TestPrivateKeyDetector_Positive_RSA(t *testing.T) {
	d := buildPrivateKeyDetector(t)
	results := runDetector(t, d, fakeRSAPrivateKey)

	require.Len(t, results, 1, "expected exactly one finding for an RSA private key block")
	require.True(t, bytes.Equal(results[0].Raw, []byte(fakeRSAPrivateKey)),
		"Raw must equal the whole PEM block")
	require.Equal(t, PrivateKeyName, results[0].DetectorName)
}

func TestPrivateKeyDetector_Positive_OpenSSH(t *testing.T) {
	d := buildPrivateKeyDetector(t)
	results := runDetector(t, d, fakeOpenSSHPrivateKey)

	require.Len(t, results, 1, "expected exactly one finding for an OPENSSH private key block")
	require.True(t, bytes.Equal(results[0].Raw, []byte(fakeOpenSSHPrivateKey)),
		"Raw must equal the whole PEM block")
	require.Equal(t, PrivateKeyName, results[0].DetectorName)
}

func TestPrivateKeyDetector_Negative_PublicKey(t *testing.T) {
	d := buildPrivateKeyDetector(t)
	input := `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf
9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END PUBLIC KEY-----`
	results := runDetector(t, d, input)

	require.Empty(t, results,
		"a PUBLIC KEY block must not produce a finding; got: %v", rawStrings(results))
}
