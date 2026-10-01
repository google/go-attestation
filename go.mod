module github.com/google/go-attestation

go 1.26

require (
	github.com/google/go-cmp v0.7.0
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm-tools v0.4.10
	go.uber.org/multierr v1.11.0
	golang.org/x/sys v0.45.0
)

require github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20260915221818-a6c0685fb9fc // indirect

require (
	github.com/google/go-configfs-tsm v0.3.3 // indirect
	github.com/google/go-sev-guest v0.14.0 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.51.0
	google.golang.org/protobuf v1.36.12 // indirect
)
