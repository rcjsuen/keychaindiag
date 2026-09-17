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
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
	"github.com/godbus/dbus/v5"
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
	printEnv("XDG_DATA_HOME")
	fmt.Println()
	printKeyringsDir()

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

	dumpSecretServiceState()

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

// printKeyringsDir lists the on-disk keyring files GNOME Keyring would load
// (names, sizes, permissions only -- never contents, which are encrypted
// secret data). GNOME Keyring resolves this directory as $XDG_DATA_HOME/keyrings,
// defaulting to ~/.local/share/keyrings when XDG_DATA_HOME is unset -- but
// when XDG_DATA_HOME IS set to something else, ~/.local/share/keyrings can
// still be the directory an earlier, differently-configured session actually
// used. To not miss either, this checks both locations (skipping the second
// if it's the same path as the first). Either being empty or missing is
// itself a diagnostic signal on an SSH-only account that never completed a
// real, PAM-driven login.
func printKeyringsDir() {
	if runtime.GOOS != "linux" {
		return
	}

	seen := make(map[string]bool)
	check := func(base string) {
		if base == "" || seen[base] {
			return
		}
		seen[base] = true
		printDirListing(filepath.Join(base, "keyrings"))
	}

	check(os.Getenv("XDG_DATA_HOME"))
	if home, err := os.UserHomeDir(); err == nil {
		check(filepath.Join(home, ".local", "share"))
	} else {
		fmt.Printf("could not resolve $HOME: %v\n\n", err)
	}
}

// printDirListing prints one directory's entries (name, size, permissions
// only -- never contents).
func printDirListing(dir string) {
	fmt.Printf("%s:\n", dir)
	entries, err := os.ReadDir(dir)
	switch {
	case err != nil:
		fmt.Printf("  %v\n", err)
	case len(entries) == 0:
		fmt.Println("  (empty)")
	default:
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				fmt.Printf("  %s\n", e.Name())
				continue
			}
			fmt.Printf("  %-9s %8d bytes  %s\n", info.Mode(), info.Size(), e.Name())
		}
	}
	fmt.Println()
}

const (
	secretServiceDest  = "org.freedesktop.secrets"
	secretServicePath  = dbus.ObjectPath("/org/freedesktop/secrets")
	secretServiceIface = "org.freedesktop.Secret.Service"
)

// dumpSecretServiceState prints the Secret Service's own live view of its
// collections and "default" alias, using the same two D-Bus calls
// store/keychain makes internally (the Collections property and ReadAlias) --
// see keychain.New's getDefaultCollection. It is strictly read-only: it never
// creates, unlocks, or assigns anything.
func dumpSecretServiceState() {
	if runtime.GOOS != "linux" {
		return
	}
	fmt.Println("Secret Service state (org.freedesktop.secrets over D-Bus):")

	conn, err := dbus.SessionBus()
	if err != nil {
		fmt.Printf("  could not connect to the session bus: %v\n\n", err)
		return
	}
	obj := conn.Object(secretServiceDest, secretServicePath)

	var collectionsVariant dbus.Variant
	var collections []dbus.ObjectPath
	if err := obj.Call("org.freedesktop.DBus.Properties.Get", 0, secretServiceIface, "Collections").Store(&collectionsVariant); err != nil {
		fmt.Printf("  could not read the Collections property: %v\n", err)
	} else if paths, ok := collectionsVariant.Value().([]dbus.ObjectPath); ok {
		collections = paths
		if len(paths) == 0 {
			fmt.Println("  collections: (none)")
		} else {
			fmt.Println("  collections:")
			for _, p := range paths {
				fmt.Printf("    %s\n", p)
			}
		}
	}

	var defaultAlias dbus.ObjectPath
	aliasErr := obj.Call(secretServiceIface+".ReadAlias", 0, "default").Store(&defaultAlias)
	if aliasErr != nil {
		fmt.Printf("  could not read the \"default\" alias: %v\n", aliasErr)
	} else if defaultAlias == "" || defaultAlias == "/" {
		fmt.Println(`  default alias: (not set)`)
	} else {
		fmt.Printf("  default alias: %s\n", defaultAlias)
	}

	// keychain.New resolves the collection to use the same way: it prefers a
	// literal "login" collection over the "default" alias (see
	// getDefaultCollection), so a missing alias does not necessarily mean
	// nothing will resolve -- print the actual effective outcome rather than
	// just the alias.
	const loginCollection = dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
	var effective dbus.ObjectPath
	switch {
	case slices.Contains(collections, loginCollection):
		effective = loginCollection
	case aliasErr == nil && defaultAlias != "" && defaultAlias != "/":
		effective = defaultAlias
	}
	if effective == "" {
		fmt.Println("  effective default collection: NONE -- no \"login\" collection and no \"default\" alias")
		fmt.Println("  this is what ErrNoDefaultCollection means.")
	} else {
		fmt.Printf("  effective default collection: %s\n", effective)
	}
	fmt.Println()
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
