// Command keychaindiag probes whether the OS keychain (the Linux Secret
// Service, macOS Keychain, or Windows Credential Manager) is reachable and
// usable, using github.com/docker/secrets-engine.
//
// It constructs a keychain store under its own service name and performs a
// single Get for a key that does not exist. A healthy keychain returns
// store.ErrCredentialNotFound; anything else is the failure being diagnosed.
//
// Usage:
//
//	go run .
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
)

// diagServiceGroup and diagServiceName identify this probe's own throwaway
// keychain namespace, distinct from any real application's, so this tool can
// never read or collide with anything already stored in the keychain.
const (
	diagServiceGroup = "com.example.keychaindiag"
	diagServiceName  = "keychaindiag"
)

func main() {
	fmt.Println("keychaindiag: OS keychain (Secret Service) availability probe")
	fmt.Println()
	fmt.Printf("%-25s %s\n", "GOOS:", runtime.GOOS)
	printEnv("DBUS_SESSION_BUS_ADDRESS")
	printEnv("XDG_RUNTIME_DIR")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Println("Constructing keychain store (keychain.New)...")
	s, err := keychain.New(ctx, diagServiceGroup, diagServiceName, diagSecretFactory)
	if err != nil {
		report(err)
		os.Exit(1)
	}
	fmt.Println("  OK: keychain.New succeeded")
	fmt.Println()

	fmt.Println("Probing for a sentinel key that is never written...")
	probeID := store.MustParseID("keychaindiag/probe")
	_, err = s.Get(ctx, probeID)
	switch {
	case err == nil:
		fmt.Println("  unexpected: probe key already exists (leftover from a previous run?)")
	case errors.Is(err, store.ErrCredentialNotFound):
		fmt.Println("  OK: keychain is reachable and has a usable default collection")
	default:
		report(err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("RESULT: OS keychain is available and usable")
}

func printEnv(name string) {
	if v, ok := os.LookupEnv(name); ok {
		fmt.Printf("%-25s %s\n", name+":", v)
		return
	}
	fmt.Printf("%-25s (unset)\n", name+":")
}

// report prints the raw failure plus a classification into the known,
// recoverable OS-keychain failure modes -- the same shapes an application
// would need to distinguish before deciding whether it's safe to fall back
// to an alternate secret store.
func report(err error) {
	fmt.Printf("  FAILED: %v\n", err)
	fmt.Println()

	switch {
	case runtime.GOOS != "linux":
		fmt.Println("REASON: unexpected")
		fmt.Println("RESULT: the OS keychain is expected to work on " + runtime.GOOS + "; this is not a known, recoverable failure.")
	case errors.Is(err, keychain.ErrCollectionLocked):
		fmt.Println("REASON: collection_locked")
		fmt.Println("RESULT: the keychain collection exists but is locked and could not be unlocked.")
		return
	case errors.Is(err, keychain.ErrNoDefaultCollection):
		fmt.Println("REASON: no_default_collection")
		fmt.Println("RESULT: the Secret Service is reachable but has no default keychain collection.")
	case errors.Is(err, keychain.ErrKeychainUnavailable):
		msg := err.Error()
		switch {
		case strings.Contains(msg, "D-Bus session bus unavailable"):
			fmt.Println("REASON: no_session_bus")
			fmt.Println("RESULT: no D-Bus session bus is reachable (e.g. DBUS_SESSION_BUS_ADDRESS unset,")
			fmt.Println("        or nothing to spawn one, as on a headless host).")
		case strings.Contains(msg, "no org.freedesktop.secrets owner"):
			fmt.Println("REASON: no_secret_service_owner")
			fmt.Println("RESULT: the D-Bus session bus is reachable, but no Secret Service daemon owns")
			fmt.Println("        org.freedesktop.secrets (no gnome-keyring, kwallet, or similar is running).")
		default:
			fmt.Println("REASON: backend_unavailable")
			fmt.Println("RESULT: the Secret Service backend is unreachable for an unrecognized reason;")
			fmt.Println("        see the FAILED line above for the underlying cause.")
		}
	default:
		fmt.Println("REASON: unknown")
		fmt.Println("RESULT: an unrecognized failure; the FAILED line above has the full detail.")
	}
}

// diagSecretFactory implements store.Factory. It is only ever asked to
// materialize the sentinel probe key, which is never written, so its
// behavior is otherwise unexercised.
func diagSecretFactory(context.Context, store.ID) store.Secret {
	return &diagSecret{}
}

// diagSecret is a minimal store.Secret. It exists only to satisfy the
// interface keychain.New requires; this tool never marshals real secret data.
type diagSecret struct{ data []byte }

func (s *diagSecret) Marshal() ([]byte, error)            { return s.data, nil }
func (s *diagSecret) Unmarshal(data []byte) error         { s.data = data; return nil }
func (s *diagSecret) Metadata() map[string]string         { return nil }
func (s *diagSecret) SetMetadata(map[string]string) error { return nil }

var _ store.Secret = (*diagSecret)(nil)
