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

// Package certwatcher provides a file-watching TLS certificate manager for automatic certificate rotation.
package certwatcher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
)

// CertWatcher watches certificate files and provides dynamic TLS configuration
// that automatically uses the latest certificates.
type CertWatcher struct {
	certPath   string
	keyPath    string
	caCertPath string

	ready atomic.Bool

	mu         sync.RWMutex
	clientCert *tls.Certificate
	caCertPool *x509.CertPool

	watcher *fsnotify.Watcher
	logger  *slog.Logger
}

// New creates a new CertWatcher that monitors the given certificate files.
// It performs an initial load of all certificates.
func New(certPath, keyPath, caCertPath string) (*CertWatcher, error) {
	cw := &CertWatcher{
		certPath:   certPath,
		keyPath:    keyPath,
		caCertPath: caCertPath,
		logger:     slog.Default(),
	}

	// Perform initial certificate load
	if err := cw.loadClientCertificate(); err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	if err := cw.loadCACertificate(); err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	return cw, nil
}

// Start begins watching certificate files for changes.
// It runs until the context is cancelled.
func (cw *CertWatcher) Start(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	cw.watcher = watcher

	// Watch the directories containing the certificate files
	// This handles cases where files are replaced atomically (e.g., Kubernetes secrets)
	dirs := make(map[string]struct{})

	for _, path := range []string{cw.certPath, cw.keyPath, cw.caCertPath} {
		dir := filepath.Dir(path)
		dirs[dir] = struct{}{}
	}

	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()

			return fmt.Errorf("failed to watch directory %s: %w", dir, err)
		}

		cw.logger.Info("Watching directory for certificate changes", "directory", dir)
	}

	go cw.watchLoop(ctx)

	return nil
}

// Ready returns true if the watcher has started processing events.
func (cw *CertWatcher) Ready() bool {
	return cw.ready.Load()
}

// Stop stops the certificate watcher.
func (cw *CertWatcher) Stop() error {
	cw.ready.Store(false)

	if cw.watcher != nil {
		return cw.watcher.Close()
	}

	return nil
}

func (cw *CertWatcher) watchLoop(ctx context.Context) {
	// Mark as ready on first iteration (atomic.Bool.Store is idempotent)
	cw.ready.Store(true)

	for {
		select {
		case <-ctx.Done():
			cw.logger.Info("Certificate watcher stopping due to context cancellation")
			return

		case event, ok := <-cw.watcher.Events:
			if !ok {
				cw.logger.Info("Certificate watcher channel closed")
				return
			}

			cw.handleFileEvent(event)

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}

			cw.logger.Error("File watcher error", "error", err)
		}
	}
}

func (cw *CertWatcher) handleFileEvent(event fsnotify.Event) {
	// Ignore chmod events - only handle content/path changes
	if event.Has(fsnotify.Chmod) {
		return
	}

	filename := filepath.Base(event.Name)

	// Reload on Write, Create, Remove, and Rename events.
	// This handles both direct file modifications and symlink-based rotations
	// (e.g., Kubernetes secrets). If reload fails (e.g., file temporarily
	// unavailable mid-rotation), we keep the previous certificate and the
	// next event will retry.
	switch filename {
	case filepath.Base(cw.certPath), filepath.Base(cw.keyPath):
		cw.logger.Info("Client certificate file changed, reloading",
			"file", event.Name, "event", event.Op.String())

		if err := cw.loadClientCertificate(); err != nil {
			cw.logger.Error("Failed to reload client certificate, keeping previous",
				"error", err)
		} else {
			cw.logger.Info("Successfully reloaded client certificate")
		}

	case filepath.Base(cw.caCertPath):
		cw.logger.Info("CA certificate file changed, reloading",
			"file", event.Name, "event", event.Op.String())

		if err := cw.loadCACertificate(); err != nil {
			cw.logger.Error("Failed to reload CA certificate, keeping previous",
				"error", err)
		} else {
			cw.logger.Info("Successfully reloaded CA certificate")
		}
	}
}

func (cw *CertWatcher) loadClientCertificate() error {
	cert, err := tls.LoadX509KeyPair(cw.certPath, cw.keyPath)
	if err != nil {
		return fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	cw.mu.Lock()
	cw.clientCert = &cert
	cw.mu.Unlock()

	return nil
}

func (cw *CertWatcher) loadCACertificate() error {
	caCert, err := os.ReadFile(cw.caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return errors.New("failed to append CA certificate to pool")
	}

	cw.mu.Lock()
	cw.caCertPool = caCertPool
	cw.mu.Unlock()

	return nil
}

// GetClientCertificate returns the current client certificate.
// This method is designed to be used as the GetClientCertificate callback in tls.Config.
func (cw *CertWatcher) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cw.mu.RLock()
	defer cw.mu.RUnlock()

	if cw.clientCert == nil {
		return nil, errors.New("no client certificate loaded")
	}

	return cw.clientCert, nil
}

// VerifyPeerCertificate verifies the server's certificate against the current CA pool.
// This method is designed to be used as the VerifyPeerCertificate callback in tls.Config.
func (cw *CertWatcher) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("no certificates provided by server")
	}

	cw.mu.RLock()
	caCertPool := cw.caCertPool
	cw.mu.RUnlock()

	if caCertPool == nil {
		return errors.New("no CA certificate pool loaded")
	}

	// Parse the server's certificate chain
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}

		certs[i] = cert
	}

	// Build intermediate pool from remaining certificates
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// Verify the leaf certificate
	opts := x509.VerifyOptions{
		Roots:         caCertPool,
		Intermediates: intermediates,
	}

	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// GetCACertPool returns the current CA certificate pool.
func (cw *CertWatcher) GetCACertPool() *x509.CertPool {
	cw.mu.RLock()
	defer cw.mu.RUnlock()

	return cw.caCertPool
}

// GetTLSConfig returns a tls.Config configured to use the certificate watcher
// for dynamic certificate loading.
func (cw *CertWatcher) GetTLSConfig() *tls.Config {
	cw.mu.RLock()
	caCertPool := cw.caCertPool
	cw.mu.RUnlock()

	return &tls.Config{
		// Use callback for client certificate to enable rotation
		GetClientCertificate: cw.GetClientCertificate,
		// Set RootCAs for initial handshake validation
		// VerifyPeerCertificate provides dynamic CA validation
		RootCAs: caCertPool,
		// Use custom verification to support CA rotation
		VerifyPeerCertificate: cw.VerifyPeerCertificate,
		// Enforce TLS 1.2 minimum
		MinVersion: tls.VersionTLS12,
	}
}
