// Package tpmsim provides a simulated TPM 2.0 interface with configurable
// Endorsement Key (EK) certificates for testing attestation workflows.

//go:build !localtest && cgo && !gofuzz
// +build !localtest,cgo,!gofuzz

// NOTE: simulator requires cgo, hence the build tag.
package tpmsim


import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/google/go-attestation/oid"
	"github.com/google/go-attestation/tcg"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	ekCertNvramAttr = tpm2.NVAttr(0x42072001)
)

func defaultEKConfig() *ekConfig {
	return &ekConfig{
		isRSA:   true,
		rsaBits: 2048,
	}
}

// SignerFunc is a custom callback used to sign an EK certificate template.
type SignerFunc func(template *x509.Certificate, pub crypto.PublicKey) ([]byte, error)

// ekConfig holds the configuration parameters for a single EK and its certificate.
type ekConfig struct {
	isRSA        bool
	rsaBits      int
	ecCurve      elliptic.Curve
	certHandle   tpmutil.Handle
	keyHandle    tpmutil.Handle
	noPersistKey bool
	signer       crypto.Signer
	issuerCert   *x509.Certificate
	signerFunc   SignerFunc
	gceInstance  *GCEInstanceID
	subject      *pkix.Name
	notBefore    time.Time
	notAfter     time.Time
	extensions   []pkix.Extension
	template     *x509.Certificate
}

// EKOption configures an individual EK and certificate on the simulated TPM.
type EKOption func(*ekConfig) error

// simulatorConfig holds top-level options for the TPM simulator instance.
type simulatorConfig struct {
	ekConfigs     []*ekConfig
	defaultSigner TestSigner
	noEK          bool
}

// Option configures the TPM simulator.
type Option func(*simulatorConfig) error

// WithoutEK configures the simulator to NOT provision any EK or certificate.
func WithoutEK() Option {
	return func(sc *simulatorConfig) error {
		sc.noEK = true
		return nil
	}
}

// WithEK adds an Endorsement Key and Certificate definition to the simulator.
func WithEK(opts ...EKOption) Option {
	return func(sc *simulatorConfig) error {
		cfg := defaultEKConfig()
		for _, opt := range opts {
			if err := opt(cfg); err != nil {
				return err
			}
		}
		sc.ekConfigs = append(sc.ekConfigs, cfg)
		return nil
	}
}

// WithOptions combines multiple simulator Options into a single Option.
func WithOptions(opts ...Option) Option {
	return func(sc *simulatorConfig) error {
		for _, opt := range opts {
			if err := opt(sc); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithDefaultSigner sets a fallback TestSigner for all EKs that don't specify their own.
func WithDefaultSigner(signer crypto.Signer, issuer *x509.Certificate) Option {
	return func(sc *simulatorConfig) error {
		sc.defaultSigner = TestSigner{Signer: signer, Cert: issuer}
		return nil
	}
}

// WithError returns a simulator Option that results in the specified error when evaluated.
func WithError(err error) Option {
	return func(*simulatorConfig) error {
		return err
	}
}

// --- Per-EK Option Functions ---

// WithECKey configures the EK to use an ECDSA key with the specified curve.
func WithECKey(curve elliptic.Curve) EKOption {
	return func(c *ekConfig) error {
		if curve == nil {
			return fmt.Errorf("elliptic.Curve cannot be nil")
		}
		c.isRSA = false
		c.ecCurve = curve
		return nil
	}
}

// WithEC256Key configures the EK to use an ECDSA key on the P-256 curve.
func WithEC256Key() EKOption {
	return WithECKey(elliptic.P256())
}

// WithEC384Key configures the EK to use an ECDSA key on the P-384 curve.
func WithEC384Key() EKOption {
	return WithECKey(elliptic.P384())
}

// WithEC521Key configures the EK to use an ECDSA key on the P-521 curve.
func WithEC521Key() EKOption {
	return WithECKey(elliptic.P521())
}

// WithRSAKey configures the EK to use an RSA key with the specified bit length.
func WithRSAKey(bits int) EKOption {
	return func(c *ekConfig) error {
		if bits <= 0 {
			return fmt.Errorf("RSA bits must be > 0, got %d", bits)
		}
		c.isRSA = true
		c.rsaBits = bits
		return nil
	}
}

// WithSigner sets a custom crypto.Signer and issuer certificate to sign the EK certificate.
func WithSigner(signer crypto.Signer, issuer *x509.Certificate) EKOption {
	return func(c *ekConfig) error {
		c.signer = signer
		c.issuerCert = issuer
		return nil
	}
}

// WithTestSigner sets a TestSigner to sign the EK certificate.
func WithTestSigner(ts TestSigner) EKOption {
	return func(c *ekConfig) error {
		c.signer = ts.Signer
		c.issuerCert = ts.Cert
		return nil
	}
}

// WithSignerFunc sets a custom SignerFunc to sign the EK certificate.
func WithSignerFunc(fn SignerFunc) EKOption {
	return func(c *ekConfig) error {
		c.signerFunc = fn
		return nil
	}
}

// WithKeyHandle overrides the persistent TPM handle where the EK key is stored.
func WithKeyHandle(handle tpmutil.Handle) EKOption {
	return func(c *ekConfig) error {
		c.keyHandle = handle
		return nil
	}
}

// WithoutPersistentKey configures the EK so that its certificate is written to
// NVRAM but the EK key itself is NOT persisted at a permanent handle. This
// simulates real-world TPMs where the EK is regenerated on demand via
// CreatePrimary. The EK cert is still written to NVRAM, and consumers such as
// attest.getEndorsementKeyHandle will recreate the key when needed.
func WithoutPersistentKey() EKOption {
	return func(c *ekConfig) error {
		c.noPersistKey = true
		return nil
	}
}

// WithCertHandle overrides the default NVRAM handle where the EK certificate is stored.
func WithCertHandle(handle tpmutil.Handle) EKOption {
	return func(c *ekConfig) error {
		c.certHandle = handle
		return nil
	}
}

// WithNVRAMHandle overrides the default NVRAM handle where the EK certificate is stored.
func WithNVRAMHandle(handle tpmutil.Handle) EKOption {
	return WithCertHandle(handle)
}

// WithGCEInstance embeds standard GCE Instance ID metadata in the EK certificate.
func WithGCEInstance(gce *GCEInstanceID) EKOption {
	return func(c *ekConfig) error {
		c.gceInstance = gce
		return nil
	}
}

// WithEKTemplate sets a base x509.Certificate template for the EK certificate.
//
// The template is treated as the base for the minted certificate: any field left
// at its zero value is backfilled from the built-in defaults (SerialNumber,
// validity window, KeyUsage, ExtKeyUsage, BasicConstraintsValid). Discrete
// options such as WithSubject, WithValidity, WithExtraExtensions and
// WithGCEInstance are applied on top and override the corresponding template
// fields. The template's public key is ignored; the EK public key generated by
// the TPM is always used instead. The caller's template is never mutated.
func WithEKTemplate(tmpl *x509.Certificate) EKOption {
	return func(c *ekConfig) error {
		if tmpl == nil {
			return fmt.Errorf("template cannot be nil")
		}
		c.template = tmpl
		return nil
	}
}

// WithSubject sets the Subject field of the EK certificate template.
func WithSubject(sub pkix.Name) EKOption {
	return func(c *ekConfig) error {
		c.subject = &sub
		return nil
	}
}

// WithValidity sets explicit NotBefore and NotAfter timestamps for the EK certificate.
func WithValidity(notBefore, notAfter time.Time) EKOption {
	return func(c *ekConfig) error {
		c.notBefore = notBefore
		c.notAfter = notAfter
		return nil
	}
}

// WithExtension adds a single X.509 extension to the EK certificate template.
func WithExtension(ext pkix.Extension) EKOption {
	return func(c *ekConfig) error {
		c.extensions = append(c.extensions, ext)
		return nil
	}
}

// WithExtraExtensions adds multiple X.509 extensions to the EK certificate template.
func WithExtraExtensions(exts []pkix.Extension) EKOption {
	return func(c *ekConfig) error {
		c.extensions = append(c.extensions, exts...)
		return nil
	}
}

// WithTCGSubjectAltName adds a TCG SubjectAltName extension to the EK certificate.
func WithTCGSubjectAltName(manufacturer, model, version string) EKOption {
	return func(c *ekConfig) error {
		ext, err := tcg.DefaultSubjectAltName(manufacturer, model, version)
		if err != nil {
			return fmt.Errorf("creating default subject alt name: %w", err)
		}
		c.extensions = append(c.extensions, ext)
		return nil
	}
}

// WithTCGSubjectDirectoryAttributes adds TCG SubjectDirectoryAttributes extension to the EK cert.
func WithTCGSubjectDirectoryAttributes(family string, level, revision int) EKOption {
	return func(c *ekConfig) error {
		ext, err := tcg.EncodeSubjectDirectoryAttributes(family, level, revision)
		if err != nil {
			return fmt.Errorf("encoding subject directory attributes: %w", err)
		}
		c.extensions = append(c.extensions, ext)
		return nil
	}
}

// --- Simulator Core Implementation ---

// Simulator encapsulates a simulated TPM 2.0 device with provisioned EK certificates.
type Simulator struct {
	tpm        *simulator.Simulator
	handles    []tpmutil.Handle
	keyHandles []tpmutil.Handle
}

// TPM returns the underlying TPM command channel interface.
func (s *Simulator) TPM() io.ReadWriteCloser {
	return s.tpm
}

// SimulatorTPM returns the underlying *simulator.Simulator instance.
func (s *Simulator) SimulatorTPM() *simulator.Simulator {
	return s.tpm
}

// Close shuts down the TPM simulator.
func (s *Simulator) Close() {
	s.tpm.Close()
}

// readEKCertFromNVRAM reads a DER-encoded EK certificate from the specified NVRAM handle.
func readEKCertFromNVRAM(tpm io.ReadWriter, handle tpmutil.Handle) ([]byte, error) {
	certDER, err := tpm2.NVReadEx(tpm, handle, handle, "", 0)
	if err != nil {
		return nil, fmt.Errorf("tpm2.NVReadEx(0x%x) failed: %w", handle, err)
	}
	return certDER, nil
}

// EKCert returns the DER-encoded EK certificate by reading directly from the TPM's NVRAM.
// Checks the standard RSA handle (0x1c00002), then ECC handle (0x1c0000a), or returns
// the first provisioned EK cert in sorted handle order.
func (s *Simulator) EKCert() []byte {
	if slices.Contains(s.handles, tcg.EKCertRSA2048Index) {
		if cert, err := readEKCertFromNVRAM(s.tpm, tcg.EKCertRSA2048Index); err == nil {
			return cert
		}
	}
	if slices.Contains(s.handles, tcg.EKCertECCP256Index) {
		if cert, err := readEKCertFromNVRAM(s.tpm, tcg.EKCertECCP256Index); err == nil {
			return cert
		}
	}
	if len(s.handles) == 0 {
		return nil
	}
	handles := append([]tpmutil.Handle(nil), s.handles...)
	slices.Sort(handles)
	for _, h := range handles {
		if cert, err := readEKCertFromNVRAM(s.tpm, h); err == nil {
			return cert
		}
	}
	return nil
}

// EKCertAt returns the DER-encoded EK certificate stored at the specified NVRAM handle by reading directly from the TPM.
func (s *Simulator) EKCertAt(handle tpmutil.Handle) ([]byte, error) {
	if !slices.Contains(s.handles, handle) {
		return nil, fmt.Errorf("no EK certificate provisioned at handle 0x%x", handle)
	}
	return readEKCertFromNVRAM(s.tpm, handle)
}

// EKCerts returns a map of all provisioned EK certificates read directly from the TPM NVRAM, keyed by NVRAM handle.
func (s *Simulator) EKCerts() map[tpmutil.Handle][]byte {
	res := make(map[tpmutil.Handle][]byte, len(s.handles))
	for _, h := range s.handles {
		if cert, err := readEKCertFromNVRAM(s.tpm, h); err == nil {
			res[h] = cert
		}
	}
	return res
}

// New constructs a new simulated TPM 2.0 device and provisions configured EK certificates.
func New(opts ...Option) (*Simulator, error) {
	sc := &simulatorConfig{}
	for _, opt := range opts {
		if err := opt(sc); err != nil {
			return nil, err
		}
	}

	tpm, err := simulator.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize simulator: %w", err)
	}

	sim := &Simulator{
		tpm: tpm,
	}

	// Default to a single RSA 2048 EK if no EKs were explicitly specified and noEK is false.
	if len(sc.ekConfigs) == 0 && !sc.noEK {
		sc.ekConfigs = append(sc.ekConfigs, defaultEKConfig())
	}

	for i, cfg := range sc.ekConfigs {
		if err := sim.provisionEK(cfg, sc.defaultSigner, i); err != nil {
			sim.Close()
			return nil, fmt.Errorf("failed to provision EK #%d: %w", i+1, err)
		}
	}

	return sim, nil
}

// NewT is a test helper that constructs a Simulator or calls t.Fatal if an error occurs.
func NewT(t *testing.T, opts ...Option) *Simulator {
	t.Helper()
	s, err := New(opts...)
	if err != nil {
		t.Fatalf("tpmsim.New() failed: %v", err)
	}
	return s
}

// defaultEKCertTemplate returns the built-in default EK certificate template.
func defaultEKCertTemplate(index int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(int64(1337 + index)),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oid.EKCertificate},
		BasicConstraintsValid: true,
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// mergeEKCertDefaults backfills any zero-valued fields of tmpl with the built-in
// defaults, so a sparse caller-provided template still produces a valid EK cert.
func mergeEKCertDefaults(tmpl *x509.Certificate, index int) {
	def := defaultEKCertTemplate(index)
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = def.SerialNumber
	}
	if tmpl.KeyUsage == 0 {
		tmpl.KeyUsage = def.KeyUsage
	}
	if len(tmpl.ExtKeyUsage) == 0 && len(tmpl.UnknownExtKeyUsage) == 0 {
		tmpl.ExtKeyUsage = def.ExtKeyUsage
		tmpl.UnknownExtKeyUsage = def.UnknownExtKeyUsage
	}
	if !tmpl.BasicConstraintsValid {
		tmpl.BasicConstraintsValid = def.BasicConstraintsValid
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = def.NotBefore
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = def.NotAfter
	}
}

// provisionEK generates an EK key in the TPM and writes its signed certificate into NVRAM.
func (s *Simulator) provisionEK(cfg *ekConfig, defaultSigner TestSigner, index int) error {
	// Assign default certHandle if not explicitly specified
	if cfg.certHandle == 0 {
		if cfg.isRSA {
			cfg.certHandle = tcg.EKCertRSA2048Index
		} else {
			cfg.certHandle = tcg.EKCertECCP256Index
		}
		// If certHandle is already in use by a previous EK, offset handle to prevent collision
		if slices.Contains(s.handles, cfg.certHandle) {
			cfg.certHandle = cfg.certHandle + tpmutil.Handle(index*0x10)
		}
	}

	// Assign default keyHandle if not explicitly specified
	if cfg.keyHandle == 0 {
		if cfg.isRSA {
			cfg.keyHandle = tcg.EKKeyRSA2048Handle
		} else {
			cfg.keyHandle = tcg.EKKeyECCP256Handle
		}
		// If keyHandle is already in use by a previous EK, offset handle to prevent collision
		if slices.Contains(s.keyHandles, cfg.keyHandle) {
			cfg.keyHandle = cfg.keyHandle + tpmutil.Handle(index*0x10)
		}
	}

	// 1. Generate EK Key in TPM with exact requested RSA bit size or ECC curve
	var tpmTmpl tpm2.Public
	var ekPub crypto.PublicKey
	if cfg.isRSA {
		bits := cfg.rsaBits
		if bits == 0 {
			bits = 2048
		}
		tpmTmpl = client.DefaultEKTemplateRSA()
		tpmTmpl.RSAParameters.KeyBits = uint16(bits)
	} else {
		curve := cfg.ecCurve
		if curve == nil {
			curve = elliptic.P256()
		}
		tpmTmpl = client.DefaultEKTemplateECC()
		switch curve.Params().Name {
		case elliptic.P384().Params().Name:
			tpmTmpl.ECCParameters.CurveID = tpm2.CurveNISTP384
			tpmTmpl.ECCParameters.Point = tpm2.ECPoint{XRaw: make([]byte, 48), YRaw: make([]byte, 48)}
		case elliptic.P521().Params().Name:
			tpmTmpl.ECCParameters.CurveID = tpm2.CurveNISTP521
			tpmTmpl.ECCParameters.Point = tpm2.ECPoint{XRaw: make([]byte, 66), YRaw: make([]byte, 66)}
		default: // P-256
			tpmTmpl.ECCParameters.CurveID = tpm2.CurveNISTP256
			tpmTmpl.ECCParameters.Point = tpm2.ECPoint{XRaw: make([]byte, 32), YRaw: make([]byte, 32)}
		}
	}

	if cfg.noPersistKey {
		// Create the key transiently (to extract the public key for the cert)
		// but do NOT persist it at any handle.
		ekKey, err := client.NewKey(s.tpm, tpm2.HandleEndorsement, tpmTmpl)
		if err != nil {
			return fmt.Errorf("client.NewKey() failed: %w", err)
		}
		ekPub = ekKey.PublicKey()
		ekKey.Close()
	} else {
		ekKey, err := client.NewCachedKey(s.tpm, tpm2.HandleEndorsement, tpmTmpl, cfg.keyHandle)
		if err != nil {
			return fmt.Errorf("client.NewCachedKey at 0x%x failed: %w", cfg.keyHandle, err)
		}
		ekPub = ekKey.PublicKey()
		ekKey.Close()
	}

	// 2. Build Certificate Template
	//
	// Start from a caller-provided template (copied so we never mutate it) or the
	// built-in default, then backfill any zero-valued fields from the defaults.
	tmpl := defaultEKCertTemplate(index)
	if cfg.template != nil {
		base := *cfg.template
		// Clone the extension slice so appends below never mutate the caller's template.
		base.ExtraExtensions = slices.Clone(cfg.template.ExtraExtensions)
		mergeEKCertDefaults(&base, index)
		tmpl = &base
	}

	// Discrete options override the corresponding template fields.
	if !cfg.notBefore.IsZero() {
		tmpl.NotBefore = cfg.notBefore
	}
	if !cfg.notAfter.IsZero() {
		tmpl.NotAfter = cfg.notAfter
	}
	if cfg.subject != nil {
		tmpl.Subject = *cfg.subject
	}

	// Process GCE Instance extension if requested
	if cfg.gceInstance != nil {
		ext, err := EncodeGCEInstanceID(cfg.gceInstance)
		if err != nil {
			return fmt.Errorf("EncodeGCEInstanceID: %w", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}

	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, cfg.extensions...)

	// 3. Mint Certificate
	var certDER []byte
	var err error

	if cfg.signerFunc != nil {
		certDER, err = cfg.signerFunc(tmpl, ekPub)
		if err != nil {
			return fmt.Errorf("signerFunc failed: %w", err)
		}
	} else {
		signer := cfg.signer
		issuerCert := cfg.issuerCert

		if signer == nil {
			if defaultSigner.Signer != nil {
				signer = defaultSigner.Signer
				issuerCert = defaultSigner.Cert
			} else {
				// Fallback to built-in fast test signer
				if cfg.isRSA {
					ts := DefaultTestSigner()
					signer = ts.Signer
					issuerCert = ts.Cert
				} else {
					ts := DefaultECTestSigner()
					signer = ts.Signer
					issuerCert = ts.Cert
				}
			}
		}

		if issuerCert == nil {
			issuerCert = tmpl // Self-signed
		}

		certDER, err = x509.CreateCertificate(rand.Reader, tmpl, issuerCert, ekPub, signer)
		if err != nil {
			return fmt.Errorf("x509.CreateCertificate failed: %w", err)
		}
	}

	// 4. Store Certificate in TPM NVRAM
	if err := writeEKCertToNVRAM(s.tpm, cfg.certHandle, certDER); err != nil {
		return fmt.Errorf("writeEKCertToNVRAM(0x%x) failed: %w", cfg.certHandle, err)
	}

	if !slices.Contains(s.handles, cfg.certHandle) {
		s.handles = append(s.handles, cfg.certHandle)
	}
	if !slices.Contains(s.keyHandles, cfg.keyHandle) {
		s.keyHandles = append(s.keyHandles, cfg.keyHandle)
	}
	return nil
}

func writeEKCertToNVRAM(tpm io.ReadWriter, handle tpmutil.Handle, certDER []byte) error {
	if len(certDER) > 65535 {
		return fmt.Errorf("certificate size %d exceeds max NVRAM size 65535", len(certDER))
	}
	if err := tpm2.NVDefineSpace(tpm, tpm2.HandlePlatform, handle, "", "", nil, ekCertNvramAttr, uint16(len(certDER))); err != nil {
		return fmt.Errorf("tpm2.NVDefineSpace failed: %w", err)
	}

	readBuff, _, err := tpm2.GetCapability(tpm, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.NVMaxBufferSize))
	if err != nil {
		return fmt.Errorf("GetCapability(TPM_PT_NV_BUFFER_MAX) failed: %w", err)
	}
	if len(readBuff) != 1 {
		return fmt.Errorf("could not determine NVRAM read/write buffer size")
	}

	bufSizeProperty, ok := readBuff[0].(tpm2.TaggedProperty)
	if !ok {
		return fmt.Errorf("GetCapability returned unexpected type: %T", readBuff[0])
	}

	chunkSize := int(bufSizeProperty.Value)
	if chunkSize <= 0 {
		return fmt.Errorf("invalid NVMaxBufferSize: %d", chunkSize)
	}

	for begin := 0; begin < len(certDER); begin += chunkSize {
		end := min(begin+chunkSize, len(certDER))
		if err := tpm2.NVWrite(tpm, tpm2.HandlePlatform, handle, "", certDER[begin:end], uint16(begin)); err != nil {
			return fmt.Errorf("tpm2.NVWrite failed: %w", err)
		}
	}

	return nil
}
