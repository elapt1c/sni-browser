package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// trustCA makes the browser engine trust our MITM root CA.
//   - Windows: installs into the current-user "Root" store via certutil
//     (no admin required).
//   - Linux: installs into the system trust store via sudo (reliable); falls
//     back to a per-process GnuTLS/OpenSSL CA bundle if sudo is unavailable.
func trustCA(ca *CA) error {
	if runtime.GOOS == "windows" {
		return trustCAWindows(ca)
	}
	return trustCALinux(ca)
}

// trustCALinux installs the CA into /usr/local/share/ca-certificates and runs
// update-ca-certificates, then falls back to an env-var CA bundle.
func trustCALinux(ca *CA) error {
	tmpCert := filepath.Join(os.TempDir(), "sni-browser-ca.crt")
	if err := os.WriteFile(tmpCert, ca.certPEM(), 0o644); err != nil {
		return trustCAEnv(ca)
	}
	defer os.Remove(tmpCert)

	// Preferred: system trust store (needs root; sudo -n is non-interactive).
	install := exec.Command("sudo", "-n", "sh", "-c",
		fmt.Sprintf("cp %q /usr/local/share/ca-certificates/sni-browser.crt && update-ca-certificates", tmpCert))
	if out, err := install.CombinedOutput(); err == nil {
		log.Printf("[trust] CA installed into system trust store")
		return nil
	} else {
		log.Printf("[trust] system trust install unavailable (%v); falling back to env-var CA bundle", err)
		_ = out
	}

	// Running as root already?
	if err := os.WriteFile("/usr/local/share/ca-certificates/sni-browser.crt", ca.certPEM(), 0o644); err == nil {
		if exec.Command("update-ca-certificates").Run() == nil {
			log.Printf("[trust] CA installed into system trust store (root)")
			return nil
		}
	}

	return trustCAEnv(ca)
}

// trustCAEnv points GnuTLS/OpenSSL at a CA bundle containing the system roots
// plus our CA. Best-effort: glib-networking may or may not honour these.
func trustCAEnv(ca *CA) error {
	bundle := append([]byte(systemCABundle()), ca.certPEM()...)
	if len(bundle) == 0 {
		bundle = ca.certPEM()
	}

	dir := filepath.Join(os.TempDir(), "sni-browser")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	bundlePath := filepath.Join(dir, "ca-bundle.pem")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return err
	}

	os.Setenv("GTLS_SYSTEM_CA_FILE", bundlePath)
	os.Setenv("SSL_CERT_FILE", bundlePath)
	return nil
}

// systemCABundle returns the system CA bundle contents, or nil if none of the
// well-known locations exist.
func systemCABundle() []byte {
	candidates := []string{
		"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu
		"/etc/pki/tls/certs/ca-bundle.crt",                  // RHEL/Fedora
		"/etc/ssl/ca-bundle.pem",                            // SUSE/openSUSE
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7+
		"/etc/ssl/cert.pem",                                 // Alpine
	}
	for _, p := range candidates {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return b
		}
	}
	return nil
}

// trustCAWindows installs the CA into the current user's "Root" store via
// certutil. This is a no-admin, per-user trust that WebView2/SCHANNEL honours.
func trustCAWindows(ca *CA) error {
	dir := filepath.Join(os.TempDir(), "sni-browser")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPath, ca.certPEM(), 0o600); err != nil {
		return err
	}

	cmd := exec.Command("certutil", "-user", "-addstore", "Root", certPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("certutil: %v: %s", err, string(out))
	}
	return nil
}
