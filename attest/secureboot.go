package attest

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-attestation/attest/internal"
)

// SecurebootState describes the secure boot status of a machine, as determined
// by processing its event log.
type SecurebootState struct {
	Enabled bool

	PlatformKeys      []x509.Certificate
	PlatformKeyHashes [][]byte

	ExchangeKeys      []x509.Certificate
	ExchangeKeyHashes [][]byte

	PermittedKeys   []x509.Certificate
	PermittedHashes [][]byte

	ForbiddenKeys   []x509.Certificate
	ForbiddenHashes [][]byte

	PreSeparatorAuthority  []x509.Certificate
	PostSeparatorAuthority []x509.Certificate
}

// ExtractSecurebootState parses a series of events to determine the
// configuration of secure boot on a device. An error is returned if
// the state cannot be determined, or if the event log is structured
// in such a way that it may have been tampered post-execution of
// platform firmware.
func ExtractSecurebootState(events []Event) (*SecurebootState, error) {
	// This algorithm verifies the following:
	// - All events in PCR 7 have event types which are expected in PCR 7.
	// - All events are parsable according to their event type.
	// - All events have digests values corresponding to their data/event type.
	// - No unverifiable events were present.
	// - All variables are specified before the separator and never duplicated.
	// - The SecureBoot variable has a value of 0 or 1.
	// - If SecureBoot was 1 (enabled), authority events were present indicating
	//   keys were used to perform verification.
	// - If SecureBoot was 1 (enabled), platform + exchange + database keys
	//   were specified.
	// - No UEFI debugger was attached.

	var (
		out           SecurebootState
		seenSeparator bool
		seenAuthority bool
		seenVars      = map[string]bool{}
	)

	for _, e := range events {
		if e.Index != 7 {
			continue
		}

		et, err := internal.ExtractEventType(uint32(e.Type))
		if err != nil {
			return nil, fmt.Errorf("unrecognised event type: %v", err)
		}

		digestVerify := e.digestEquals(e.Data)
		switch et {
		case internal.Separator:
			if seenSeparator {
				return nil, fmt.Errorf("duplicate separator at event %d", e.sequence)
			}
			seenSeparator = true
			if !bytes.Equal(e.Data, []byte{0, 0, 0, 0}) {
				return nil, fmt.Errorf("invalid separator data at event %d: %v", e.sequence, e.Data)
			}
			if err := e.digestEquals(e.Data); err != nil {
				return nil, fmt.Errorf("invalid separator digest at event %d: %v", e.sequence, err)
			}

		case internal.EFIAction:
			if string(e.Data) == "UEFI Debug Mode" {
				return nil, errors.New("a UEFI debugger was present during boot")
			}
			return nil, fmt.Errorf("event %d: unexpected EFI action event", e.sequence)

		case internal.EFIVariableDriverConfig:
			v, err := internal.ParseUEFIVariableData(bytes.NewReader(e.Data))
			if err != nil {
				return nil, fmt.Errorf("failed parsing EFI variable at event %d: %v", e.sequence, err)
			}
			if _, seenBefore := seenVars[v.VarName()]; seenBefore {
				return nil, fmt.Errorf("duplicate EFI variable %q at event %d", v.VarName(), e.sequence)
			}
			seenVars[v.VarName()] = true
			if seenSeparator {
				return nil, fmt.Errorf("event %d: variable %q specified after separator", e.sequence, v.VarName())
			}

			if digestVerify != nil {
				return nil, fmt.Errorf("invalid digest for variable %q on event %d: %v", v.VarName(), e.sequence, digestVerify)
			}

			switch v.VarName() {
			case "SecureBoot":
				if len(v.VariableData) != 1 {
					return nil, fmt.Errorf("event %d: SecureBoot data len is %d, expected 1", e.sequence, len(v.VariableData))
				}
				out.Enabled = v.VariableData[0] == 1
			case "PK":
				if out.PlatformKeys, out.PlatformKeyHashes, err = v.SignatureData(); err != nil {
					return nil, fmt.Errorf("event %d: failed parsing platform keys: %v", e.sequence, err)
				}
			case "KEK":
				if out.ExchangeKeys, out.ExchangeKeyHashes, err = v.SignatureData(); err != nil {
					return nil, fmt.Errorf("event %d: failed parsing key exchange keys: %v", e.sequence, err)
				}
			case "db":
				if out.PermittedKeys, out.PermittedHashes, err = v.SignatureData(); err != nil {
					return nil, fmt.Errorf("event %d: failed parsing signature database: %v", e.sequence, err)
				}
			case "dbx":
				if out.ForbiddenKeys, out.ForbiddenHashes, err = v.SignatureData(); err != nil {
					return nil, fmt.Errorf("event %d: failed parsing forbidden signature database: %v", e.sequence, err)
				}
			}

		case internal.EFIVariableAuthority:
			a, err := internal.ParseUEFIVariableAuthority(bytes.NewReader(e.Data))
			if err != nil {
				return nil, fmt.Errorf("failed parsing EFI variable authority at event %d: %v", e.sequence, err)
			}
			seenAuthority = true
			if digestVerify != nil {
				return nil, fmt.Errorf("invalid digest for authority on event %d: %v", e.sequence, digestVerify)
			}
			if !seenSeparator {
				out.PreSeparatorAuthority = append(out.PreSeparatorAuthority, a.Certs...)
			} else {
				out.PostSeparatorAuthority = append(out.PostSeparatorAuthority, a.Certs...)
			}

		default:
			return nil, fmt.Errorf("unexpected event type: %v", et)
		}
	}

	if out.Enabled {
		if !seenAuthority {
			return nil, errors.New("secure boot was enabled but no key was used")
		}
		if len(out.PlatformKeys) == 0 && len(out.PlatformKeyHashes) == 0 {
			return nil, errors.New("secure boot was enabled but no platform keys were known")
		}
		if len(out.ExchangeKeys) == 0 && len(out.ExchangeKeyHashes) == 0 {
			return nil, errors.New("secure boot was enabled but no key exchange keys were known")
		}
		if len(out.PermittedKeys) == 0 && len(out.PermittedHashes) == 0 {
			return nil, errors.New("secure boot was enabled but no keys or hashes were permitted")
		}
	}

	return &out, nil
}
