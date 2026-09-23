package tpmsim

// StandardEK returns EKOptions for a standard EK with TCG metadata and optional overrides.
func StandardEK(overrides ...EKOption) []EKOption {
	base := []EKOption{
		WithTCGSubjectAltName("id:FFFFFFFF", "vTPM", "id:0001"),
		WithTCGSubjectDirectoryAttributes("2.0", 0, 116),
	}
	return append(base, overrides...)
}

// StandardGCEEK returns EKOptions for a standard GCE VM EK with optional overrides.
func StandardGCEEK(gce *GCEInstanceID, overrides ...EKOption) []EKOption {
	return StandardEK(append([]EKOption{
		WithGCEInstance(gce),
	}, overrides...)...)
}

// DefaultProfile returns simulator Options for a default TPM with RSA 2048 and ECC P-256 EKs.
func DefaultProfile() []Option {
	return []Option{
		WithEK(StandardEK(WithRSAKey(2048))...),
		WithEK(StandardEK(WithEC256Key())...),
	}
}

// GCEProfile returns simulator Options for a GCE VM TPM with RSA 2048 and ECC P-256 EKs.
func GCEProfile(gce *GCEInstanceID) []Option {
	return []Option{
		WithEK(StandardGCEEK(gce, WithRSAKey(2048))...),
		WithEK(StandardGCEEK(gce, WithEC256Key())...),
	}
}
