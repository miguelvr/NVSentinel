// Copyright (c) 2025, NVIDIA CORPORATION.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certwatcher_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nvidia/nvsentinel/store-client/pkg/certwatcher"
)

// setupTestCerts creates test certificate files in a temporary directory
func setupTestCerts(t *testing.T) *testSetup {
	t.Helper()

	ca := generateTestCA(t)
	client := generateTestClientCert(t, ca)

	tmpDir, err := os.MkdirTemp("", "certwatcher-test-*")
	require.NoError(t, err)

	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")
	caPath := filepath.Join(tmpDir, "ca.crt")

	err = os.WriteFile(certPath, client.CertPEM, 0600)
	require.NoError(t, err)

	err = os.WriteFile(keyPath, client.KeyPEM, 0600)
	require.NoError(t, err)

	err = os.WriteFile(caPath, ca.CertPEM, 0600)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	return &testSetup{
		CertPath: certPath,
		KeyPath:  keyPath,
		CAPath:   caPath,
		TmpDir:   tmpDir,
		CA:       ca,
		Client:   client,
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		setupFn     func(t *testing.T, setup *testSetup) (certPath, keyPath, caPath string)
		wantErr     bool
		errContains string
		validateFn  func(t *testing.T, cw *certwatcher.CertWatcher)
	}{
		{
			name: "success_with_valid_certificates",
			setupFn: func(t *testing.T, setup *testSetup) (string, string, string) {
				return setup.CertPath, setup.KeyPath, setup.CAPath
			},
			wantErr: false,
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher) {
				cert, err := cw.GetClientCertificate(nil)
				require.NoError(t, err)
				require.NotNil(t, cert)

				pool := cw.GetCACertPool()
				require.NotNil(t, pool)
			},
		},
		{
			name: "error_missing_client_cert",
			setupFn: func(t *testing.T, setup *testSetup) (string, string, string) {
				return "/nonexistent/tls.crt", "/nonexistent/tls.key", setup.CAPath
			},
			wantErr:     true,
			errContains: "failed to load client certificate",
			validateFn:  nil,
		},
		{
			name: "error_missing_ca_cert",
			setupFn: func(t *testing.T, setup *testSetup) (string, string, string) {
				return setup.CertPath, setup.KeyPath, "/nonexistent/ca.crt"
			},
			wantErr:     true,
			errContains: "failed to load CA certificate",
			validateFn:  nil,
		},
		{
			name: "error_invalid_ca_cert",
			setupFn: func(t *testing.T, setup *testSetup) (string, string, string) {
				invalidCAPath := filepath.Join(setup.TmpDir, "invalid-ca.crt")
				err := os.WriteFile(invalidCAPath, []byte("not a valid certificate"), 0600)
				require.NoError(t, err)
				return setup.CertPath, setup.KeyPath, invalidCAPath
			},
			wantErr:     true,
			errContains: "failed to load CA certificate",
			validateFn:  nil,
		},
		{
			name: "error_mismatched_cert_key",
			setupFn: func(t *testing.T, setup *testSetup) (string, string, string) {
				// Generate a different client cert with different key
				otherClient := generateTestClientCert(t, setup.CA)
				otherKeyPath := filepath.Join(setup.TmpDir, "other.key")
				err := os.WriteFile(otherKeyPath, otherClient.KeyPEM, 0600)
				require.NoError(t, err)
				return setup.CertPath, otherKeyPath, setup.CAPath
			},
			wantErr:     true,
			errContains: "failed to load client certificate",
			validateFn:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTestCerts(t)
			certPath, keyPath, caPath := tt.setupFn(t, setup)

			cw, err := certwatcher.New(certPath, keyPath, caPath)

			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, cw)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, cw)
				if tt.validateFn != nil {
					tt.validateFn(t, cw)
				}
			}
		})
	}
}

func TestGetClientCertificate(t *testing.T) {
	tests := []struct {
		name       string
		validateFn func(t *testing.T, cw *certwatcher.CertWatcher)
	}{
		{
			name: "returns_correct_certificate",
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher) {
				cert, err := cw.GetClientCertificate(&tls.CertificateRequestInfo{})
				require.NoError(t, err)
				require.NotNil(t, cert)

				x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
				require.NoError(t, err)
				assert.Equal(t, "test-client", x509Cert.Subject.CommonName)
			},
		},
		{
			name: "returns_same_certificate_on_multiple_calls",
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher) {
				cert1, err := cw.GetClientCertificate(nil)
				require.NoError(t, err)

				cert2, err := cw.GetClientCertificate(nil)
				require.NoError(t, err)

				// Should be the same certificate
				assert.Equal(t, cert1.Certificate, cert2.Certificate)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTestCerts(t)
			cw, err := certwatcher.New(setup.CertPath, setup.KeyPath, setup.CAPath)
			require.NoError(t, err)

			tt.validateFn(t, cw)
		})
	}
}

func TestVerifyPeerCertificate(t *testing.T) {
	tests := []struct {
		name        string
		setupFn     func(t *testing.T, setup *testSetup) [][]byte
		wantErr     bool
		errContains string
		validateFn  func(t *testing.T, err error)
	}{
		{
			name: "success_valid_server_cert",
			setupFn: func(t *testing.T, setup *testSetup) [][]byte {
				server := generateTestServerCert(t, setup.CA)
				return [][]byte{server.Cert.Raw}
			},
			wantErr:    false,
			validateFn: nil,
		},
		{
			name: "error_cert_from_different_ca",
			setupFn: func(t *testing.T, setup *testSetup) [][]byte {
				differentCA := generateTestCA(t)
				server := generateTestServerCert(t, differentCA)
				return [][]byte{server.Cert.Raw}
			},
			wantErr:     true,
			errContains: "certificate verification failed",
			validateFn:  nil,
		},
		{
			name: "error_empty_certs",
			setupFn: func(t *testing.T, setup *testSetup) [][]byte {
				return [][]byte{}
			},
			wantErr:     true,
			errContains: "no certificates provided",
			validateFn:  nil,
		},
		{
			name: "error_invalid_cert_data",
			setupFn: func(t *testing.T, setup *testSetup) [][]byte {
				return [][]byte{[]byte("invalid certificate data")}
			},
			wantErr:     true,
			errContains: "failed to parse certificate",
			validateFn:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTestCerts(t)
			cw, err := certwatcher.New(setup.CertPath, setup.KeyPath, setup.CAPath)
			require.NoError(t, err)

			rawCerts := tt.setupFn(t, setup)
			err = cw.VerifyPeerCertificate(rawCerts, nil)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}

			if tt.validateFn != nil {
				tt.validateFn(t, err)
			}
		})
	}
}

func TestGetTLSConfig(t *testing.T) {
	tests := []struct {
		name       string
		validateFn func(t *testing.T, cw *certwatcher.CertWatcher, tlsConfig *tls.Config)
	}{
		{
			name: "has_required_callbacks",
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher, tlsConfig *tls.Config) {
				assert.NotNil(t, tlsConfig.GetClientCertificate)
				assert.NotNil(t, tlsConfig.VerifyPeerCertificate)
			},
		},
		{
			name: "has_root_cas",
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher, tlsConfig *tls.Config) {
				assert.NotNil(t, tlsConfig.RootCAs)
			},
		},
		{
			name: "enforces_tls12_minimum",
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher, tlsConfig *tls.Config) {
				assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
			},
		},
		{
			name: "client_cert_callback_works",
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher, tlsConfig *tls.Config) {
				cert, err := tlsConfig.GetClientCertificate(nil)
				require.NoError(t, err)
				require.NotNil(t, cert)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTestCerts(t)
			cw, err := certwatcher.New(setup.CertPath, setup.KeyPath, setup.CAPath)
			require.NoError(t, err)

			tlsConfig := cw.GetTLSConfig()
			require.NotNil(t, tlsConfig)

			tt.validateFn(t, cw, tlsConfig)
		})
	}
}

func TestStartAndStop(t *testing.T) {
	tests := []struct {
		name        string
		setupFn     func(t *testing.T, cw *certwatcher.CertWatcher) (context.Context, context.CancelFunc)
		postStartFn func(t *testing.T, ctx context.Context, cancel context.CancelFunc)
		validateFn  func(t *testing.T, cw *certwatcher.CertWatcher, startErr, stopErr error)
	}{
		{
			name: "start_and_stop_successfully",
			setupFn: func(t *testing.T, cw *certwatcher.CertWatcher) (context.Context, context.CancelFunc) {
				return context.Background(), nil
			},
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher, startErr, stopErr error) {
				require.NoError(t, startErr)
				require.NoError(t, stopErr)
			},
		},
		{
			name: "stop_without_start",
			setupFn: func(t *testing.T, cw *certwatcher.CertWatcher) (context.Context, context.CancelFunc) {
				return nil, nil // Signal to skip Start
			},
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher, startErr, stopErr error) {
				require.NoError(t, stopErr)
			},
		},
		{
			name: "context_cancellation",
			setupFn: func(t *testing.T, cw *certwatcher.CertWatcher) (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				return ctx, cancel
			},
			postStartFn: func(t *testing.T, ctx context.Context, cancel context.CancelFunc) {
				cancel()
			},
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher, startErr, stopErr error) {
				require.NoError(t, startErr)
				require.NoError(t, stopErr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTestCerts(t)
			cw, err := certwatcher.New(setup.CertPath, setup.KeyPath, setup.CAPath)
			require.NoError(t, err)

			ctx, cancel := tt.setupFn(t, cw)

			var startErr error
			if ctx != nil {
				startErr = cw.Start(ctx)
				require.Eventually(t, func() bool {
					return cw.Ready()
				}, 2*time.Second, 100*time.Millisecond,
					"CertWatcher did not become ready in time")
			}

			if tt.postStartFn != nil {
				tt.postStartFn(t, ctx, cancel)
			}

			stopErr := cw.Stop()

			tt.validateFn(t, cw, startErr, stopErr)
		})
	}
}

func TestCertificateRotation(t *testing.T) {
	tests := []struct {
		name       string
		rotateFn   func(t *testing.T, setup *testSetup)
		validateFn func(t *testing.T, cw *certwatcher.CertWatcher, setup *testSetup, initialCert *tls.Certificate)
	}{
		{
			name: "client_cert_rotation",
			rotateFn: func(t *testing.T, setup *testSetup) {
				newClient := generateTestClientCert(t, setup.CA)
				err := os.WriteFile(setup.CertPath, newClient.CertPEM, 0600)
				require.NoError(t, err)
				err = os.WriteFile(setup.KeyPath, newClient.KeyPEM, 0600)
				require.NoError(t, err)
			},
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher, setup *testSetup, initialCert *tls.Certificate) {
				// Parse initial certificate serial
				x509InitialCert, err := x509.ParseCertificate(initialCert.Certificate[0])
				require.NoError(t, err)
				initialSerial := x509InitialCert.SerialNumber

				// After rotation, serial should be different
				require.Eventually(t,
					func() bool {
						cert, err := cw.GetClientCertificate(nil)
						require.NoError(t, err)

						x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
						require.NoError(t, err)

						return initialSerial.Int64() != x509Cert.SerialNumber.Int64()
					},
					2*time.Second, 100*time.Millisecond,
					"Certificate did not rotate in time",
				)
			},
		},
		{
			name: "ca_cert_rotation",
			rotateFn: func(t *testing.T, setup *testSetup) {
				newCA := generateTestCA(t)
				err := os.WriteFile(setup.CAPath, newCA.CertPEM, 0600)
				require.NoError(t, err)
				// Store new CA for validation
				setup.CA = newCA
			},
			validateFn: func(t *testing.T, cw *certwatcher.CertWatcher, setup *testSetup, _ *tls.Certificate) {
				// Server cert signed by new CA should now verify
				newServer := generateTestServerCert(t, setup.CA)

				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					if err := cw.VerifyPeerCertificate([][]byte{newServer.Cert.Raw}, nil); err != nil {
						ct.Errorf("certificate did not rotate in time: %v", err)
					}
				}, 2*time.Second, 100*time.Millisecond)

			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTestCerts(t)
			cw, err := certwatcher.New(setup.CertPath, setup.KeyPath, setup.CAPath)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err = cw.Start(ctx)
			require.NoError(t, err)
			defer cw.Stop()

			// Wait for watcher to fully start
			require.Eventually(t,
				func() bool {
					return cw.Ready()
				},
				2*time.Second, 100*time.Millisecond,
				"CertWatcher did not become ready in time",
			)

			// Capture initial certificate BEFORE rotation
			initialCert, err := cw.GetClientCertificate(nil)
			require.NoError(t, err)

			// Perform rotation
			tt.rotateFn(t, setup)

			// Validate
			tt.validateFn(t, cw, setup, initialCert)
		})
	}
}

// testSetup holds the test environment
type testSetup struct {
	CertPath string
	KeyPath  string
	CAPath   string
	TmpDir   string
	CA       *TestCertificate
	Client   *TestCertificate
}

// TestCertificate holds generated test certificate data
type TestCertificate struct {
	CertPEM []byte
	KeyPEM  []byte
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
}

// generateTestCA creates a test CA certificate
func generateTestCA(t *testing.T) *TestCertificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return &TestCertificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Cert:    cert,
		Key:     key,
	}
}

// generateTestClientCert creates a test client certificate signed by the given CA
func generateTestClientCert(t *testing.T, ca *TestCertificate) *TestCertificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "test-client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return &TestCertificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Cert:    cert,
		Key:     key,
	}
}

// generateTestServerCert creates a test server certificate signed by the given CA
func generateTestServerCert(t *testing.T, ca *TestCertificate) *TestCertificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return &TestCertificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Cert:    cert,
		Key:     key,
	}
}
