// Code generated by protoc-gen-go. DO NOT EDIT.
// source: verification.proto

package goattestation_verifier

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type AikVerificationResults struct {
	Succeeded                   bool     `protobuf:"varint,1,opt,name=succeeded,proto3" json:"succeeded,omitempty"`
	KeyTooSmall                 bool     `protobuf:"varint,2,opt,name=key_too_small,json=keyTooSmall,proto3" json:"key_too_small,omitempty"`
	CreationAttestationMismatch bool     `protobuf:"varint,3,opt,name=creation_attestation_mismatch,json=creationAttestationMismatch,proto3" json:"creation_attestation_mismatch,omitempty"`
	KeyNotTpmBound              bool     `protobuf:"varint,4,opt,name=key_not_tpm_bound,json=keyNotTpmBound,proto3" json:"key_not_tpm_bound,omitempty"`
	KeyUsageOverlyBroad         bool     `protobuf:"varint,5,opt,name=key_usage_overly_broad,json=keyUsageOverlyBroad,proto3" json:"key_usage_overly_broad,omitempty"`
	NameAttestationMismatch     bool     `protobuf:"varint,6,opt,name=name_attestation_mismatch,json=nameAttestationMismatch,proto3" json:"name_attestation_mismatch,omitempty"`
	SignatureMismatch           bool     `protobuf:"varint,7,opt,name=signature_mismatch,json=signatureMismatch,proto3" json:"signature_mismatch,omitempty"`
	RocaVulnerableKey           bool     `protobuf:"varint,8,opt,name=roca_vulnerable_key,json=rocaVulnerableKey,proto3" json:"roca_vulnerable_key,omitempty"`
	XXX_NoUnkeyedLiteral        struct{} `json:"-"`
	XXX_unrecognized            []byte   `json:"-"`
	XXX_sizecache               int32    `json:"-"`
}

func (m *AikVerificationResults) Reset()         { *m = AikVerificationResults{} }
func (m *AikVerificationResults) String() string { return proto.CompactTextString(m) }
func (*AikVerificationResults) ProtoMessage()    {}
func (*AikVerificationResults) Descriptor() ([]byte, []int) {
	return fileDescriptor_69b5d5d3b04d10d4, []int{0}
}

func (m *AikVerificationResults) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AikVerificationResults.Unmarshal(m, b)
}
func (m *AikVerificationResults) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AikVerificationResults.Marshal(b, m, deterministic)
}
func (m *AikVerificationResults) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AikVerificationResults.Merge(m, src)
}
func (m *AikVerificationResults) XXX_Size() int {
	return xxx_messageInfo_AikVerificationResults.Size(m)
}
func (m *AikVerificationResults) XXX_DiscardUnknown() {
	xxx_messageInfo_AikVerificationResults.DiscardUnknown(m)
}

var xxx_messageInfo_AikVerificationResults proto.InternalMessageInfo

func (m *AikVerificationResults) GetSucceeded() bool {
	if m != nil {
		return m.Succeeded
	}
	return false
}

func (m *AikVerificationResults) GetKeyTooSmall() bool {
	if m != nil {
		return m.KeyTooSmall
	}
	return false
}

func (m *AikVerificationResults) GetCreationAttestationMismatch() bool {
	if m != nil {
		return m.CreationAttestationMismatch
	}
	return false
}

func (m *AikVerificationResults) GetKeyNotTpmBound() bool {
	if m != nil {
		return m.KeyNotTpmBound
	}
	return false
}

func (m *AikVerificationResults) GetKeyUsageOverlyBroad() bool {
	if m != nil {
		return m.KeyUsageOverlyBroad
	}
	return false
}

func (m *AikVerificationResults) GetNameAttestationMismatch() bool {
	if m != nil {
		return m.NameAttestationMismatch
	}
	return false
}

func (m *AikVerificationResults) GetSignatureMismatch() bool {
	if m != nil {
		return m.SignatureMismatch
	}
	return false
}

func (m *AikVerificationResults) GetRocaVulnerableKey() bool {
	if m != nil {
		return m.RocaVulnerableKey
	}
	return false
}

type QuoteVerificationResults struct {
	Succeeded            bool     `protobuf:"varint,1,opt,name=succeeded,proto3" json:"succeeded,omitempty"`
	SignatureMismatch    bool     `protobuf:"varint,2,opt,name=signature_mismatch,json=signatureMismatch,proto3" json:"signature_mismatch,omitempty"`
	PcrDigest            []byte   `protobuf:"bytes,3,opt,name=pcr_digest,json=pcrDigest,proto3" json:"pcr_digest,omitempty"`
	PcrDigestMismatch    bool     `protobuf:"varint,4,opt,name=pcr_digest_mismatch,json=pcrDigestMismatch,proto3" json:"pcr_digest_mismatch,omitempty"`
	NonceMismatch        bool     `protobuf:"varint,5,opt,name=nonce_mismatch,json=nonceMismatch,proto3" json:"nonce_mismatch,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *QuoteVerificationResults) Reset()         { *m = QuoteVerificationResults{} }
func (m *QuoteVerificationResults) String() string { return proto.CompactTextString(m) }
func (*QuoteVerificationResults) ProtoMessage()    {}
func (*QuoteVerificationResults) Descriptor() ([]byte, []int) {
	return fileDescriptor_69b5d5d3b04d10d4, []int{1}
}

func (m *QuoteVerificationResults) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_QuoteVerificationResults.Unmarshal(m, b)
}
func (m *QuoteVerificationResults) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_QuoteVerificationResults.Marshal(b, m, deterministic)
}
func (m *QuoteVerificationResults) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QuoteVerificationResults.Merge(m, src)
}
func (m *QuoteVerificationResults) XXX_Size() int {
	return xxx_messageInfo_QuoteVerificationResults.Size(m)
}
func (m *QuoteVerificationResults) XXX_DiscardUnknown() {
	xxx_messageInfo_QuoteVerificationResults.DiscardUnknown(m)
}

var xxx_messageInfo_QuoteVerificationResults proto.InternalMessageInfo

func (m *QuoteVerificationResults) GetSucceeded() bool {
	if m != nil {
		return m.Succeeded
	}
	return false
}

func (m *QuoteVerificationResults) GetSignatureMismatch() bool {
	if m != nil {
		return m.SignatureMismatch
	}
	return false
}

func (m *QuoteVerificationResults) GetPcrDigest() []byte {
	if m != nil {
		return m.PcrDigest
	}
	return nil
}

func (m *QuoteVerificationResults) GetPcrDigestMismatch() bool {
	if m != nil {
		return m.PcrDigestMismatch
	}
	return false
}

func (m *QuoteVerificationResults) GetNonceMismatch() bool {
	if m != nil {
		return m.NonceMismatch
	}
	return false
}

type EkcertVerificationResults struct {
	Succeeded            bool                                     `protobuf:"varint,1,opt,name=succeeded,proto3" json:"succeeded,omitempty"`
	ChainVerified        bool                                     `protobuf:"varint,2,opt,name=chain_verified,json=chainVerified,proto3" json:"chain_verified,omitempty"`
	Chain                []*EkcertVerificationResults_CertSummary `protobuf:"bytes,3,rep,name=chain,proto3" json:"chain,omitempty"`
	VerificationError    string                                   `protobuf:"bytes,4,opt,name=verification_error,json=verificationError,proto3" json:"verification_error,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                 `json:"-"`
	XXX_unrecognized     []byte                                   `json:"-"`
	XXX_sizecache        int32                                    `json:"-"`
}

func (m *EkcertVerificationResults) Reset()         { *m = EkcertVerificationResults{} }
func (m *EkcertVerificationResults) String() string { return proto.CompactTextString(m) }
func (*EkcertVerificationResults) ProtoMessage()    {}
func (*EkcertVerificationResults) Descriptor() ([]byte, []int) {
	return fileDescriptor_69b5d5d3b04d10d4, []int{2}
}

func (m *EkcertVerificationResults) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EkcertVerificationResults.Unmarshal(m, b)
}
func (m *EkcertVerificationResults) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EkcertVerificationResults.Marshal(b, m, deterministic)
}
func (m *EkcertVerificationResults) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EkcertVerificationResults.Merge(m, src)
}
func (m *EkcertVerificationResults) XXX_Size() int {
	return xxx_messageInfo_EkcertVerificationResults.Size(m)
}
func (m *EkcertVerificationResults) XXX_DiscardUnknown() {
	xxx_messageInfo_EkcertVerificationResults.DiscardUnknown(m)
}

var xxx_messageInfo_EkcertVerificationResults proto.InternalMessageInfo

func (m *EkcertVerificationResults) GetSucceeded() bool {
	if m != nil {
		return m.Succeeded
	}
	return false
}

func (m *EkcertVerificationResults) GetChainVerified() bool {
	if m != nil {
		return m.ChainVerified
	}
	return false
}

func (m *EkcertVerificationResults) GetChain() []*EkcertVerificationResults_CertSummary {
	if m != nil {
		return m.Chain
	}
	return nil
}

func (m *EkcertVerificationResults) GetVerificationError() string {
	if m != nil {
		return m.VerificationError
	}
	return ""
}

type EkcertVerificationResults_CertSummary struct {
	IssuerCn             string   `protobuf:"bytes,1,opt,name=issuer_cn,json=issuerCn,proto3" json:"issuer_cn,omitempty"`
	IssuerOrg            string   `protobuf:"bytes,2,opt,name=issuer_org,json=issuerOrg,proto3" json:"issuer_org,omitempty"`
	Serial               string   `protobuf:"bytes,3,opt,name=serial,proto3" json:"serial,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EkcertVerificationResults_CertSummary) Reset()         { *m = EkcertVerificationResults_CertSummary{} }
func (m *EkcertVerificationResults_CertSummary) String() string { return proto.CompactTextString(m) }
func (*EkcertVerificationResults_CertSummary) ProtoMessage()    {}
func (*EkcertVerificationResults_CertSummary) Descriptor() ([]byte, []int) {
	return fileDescriptor_69b5d5d3b04d10d4, []int{2, 0}
}

func (m *EkcertVerificationResults_CertSummary) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EkcertVerificationResults_CertSummary.Unmarshal(m, b)
}
func (m *EkcertVerificationResults_CertSummary) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EkcertVerificationResults_CertSummary.Marshal(b, m, deterministic)
}
func (m *EkcertVerificationResults_CertSummary) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EkcertVerificationResults_CertSummary.Merge(m, src)
}
func (m *EkcertVerificationResults_CertSummary) XXX_Size() int {
	return xxx_messageInfo_EkcertVerificationResults_CertSummary.Size(m)
}
func (m *EkcertVerificationResults_CertSummary) XXX_DiscardUnknown() {
	xxx_messageInfo_EkcertVerificationResults_CertSummary.DiscardUnknown(m)
}

var xxx_messageInfo_EkcertVerificationResults_CertSummary proto.InternalMessageInfo

func (m *EkcertVerificationResults_CertSummary) GetIssuerCn() string {
	if m != nil {
		return m.IssuerCn
	}
	return ""
}

func (m *EkcertVerificationResults_CertSummary) GetIssuerOrg() string {
	if m != nil {
		return m.IssuerOrg
	}
	return ""
}

func (m *EkcertVerificationResults_CertSummary) GetSerial() string {
	if m != nil {
		return m.Serial
	}
	return ""
}

func init() {
	proto.RegisterType((*AikVerificationResults)(nil), "goattestation.verifier.AikVerificationResults")
	proto.RegisterType((*QuoteVerificationResults)(nil), "goattestation.verifier.QuoteVerificationResults")
	proto.RegisterType((*EkcertVerificationResults)(nil), "goattestation.verifier.EkcertVerificationResults")
	proto.RegisterType((*EkcertVerificationResults_CertSummary)(nil), "goattestation.verifier.EkcertVerificationResults.CertSummary")
}

func init() { proto.RegisterFile("verification.proto", fileDescriptor_69b5d5d3b04d10d4) }

var fileDescriptor_69b5d5d3b04d10d4 = []byte{
	// 493 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x93, 0xc1, 0x6e, 0xd3, 0x40,
	0x10, 0x86, 0xd5, 0x84, 0x86, 0x78, 0x42, 0x22, 0x65, 0x2b, 0x05, 0x97, 0x52, 0xa9, 0x8a, 0x54,
	0xa9, 0x1c, 0xc8, 0x81, 0xde, 0x90, 0x38, 0x34, 0xa5, 0x27, 0x04, 0x15, 0x4e, 0xc9, 0x75, 0xb5,
	0x59, 0x0f, 0xae, 0x65, 0x7b, 0x37, 0x9a, 0x5d, 0x47, 0xf2, 0xa3, 0xf0, 0x44, 0x3c, 0x05, 0xef,
	0x82, 0x76, 0xed, 0xc6, 0x3e, 0xa4, 0x87, 0x1e, 0xfd, 0xff, 0xdf, 0xcc, 0xce, 0xec, 0xef, 0x05,
	0xb6, 0x43, 0x4a, 0x7f, 0xa7, 0x52, 0xd8, 0x54, 0xab, 0xc5, 0x96, 0xb4, 0xd5, 0x6c, 0x96, 0x68,
	0x61, 0x2d, 0x1a, 0x5b, 0x8b, 0x35, 0x81, 0x34, 0xff, 0xd3, 0x87, 0xd9, 0x4d, 0x9a, 0xad, 0x3b,
	0x15, 0x11, 0x9a, 0x32, 0xb7, 0x86, 0xbd, 0x87, 0xc0, 0x94, 0x52, 0x22, 0xc6, 0x18, 0x87, 0x47,
	0x17, 0x47, 0x57, 0xc3, 0xa8, 0x15, 0xd8, 0x1c, 0xc6, 0x19, 0x56, 0xdc, 0x6a, 0xcd, 0x4d, 0x21,
	0xf2, 0x3c, 0xec, 0x79, 0x62, 0x94, 0x61, 0xf5, 0xa0, 0xf5, 0xca, 0x49, 0x6c, 0x09, 0xe7, 0x92,
	0xd0, 0x37, 0xe5, 0x9d, 0xd3, 0x79, 0x91, 0x9a, 0x42, 0x58, 0xf9, 0x18, 0xf6, 0x7d, 0xcd, 0xd9,
	0x13, 0x74, 0xd3, 0x32, 0xdf, 0x1b, 0x84, 0x7d, 0x80, 0xa9, 0x3b, 0x47, 0x69, 0xcb, 0xed, 0xb6,
	0xe0, 0x1b, 0x5d, 0xaa, 0x38, 0x7c, 0xe5, 0xeb, 0x26, 0x19, 0x56, 0x3f, 0xb4, 0x7d, 0xd8, 0x16,
	0x4b, 0xa7, 0xb2, 0x6b, 0x98, 0x39, 0xb4, 0x34, 0x22, 0x41, 0xae, 0x77, 0x48, 0x79, 0xc5, 0x37,
	0xa4, 0x45, 0x1c, 0x1e, 0x7b, 0xfe, 0x24, 0xc3, 0xea, 0x97, 0x33, 0xef, 0xbd, 0xb7, 0x74, 0x16,
	0xfb, 0x0c, 0xa7, 0x4a, 0x14, 0x78, 0x78, 0xbe, 0x81, 0xaf, 0x7b, 0xeb, 0x80, 0x43, 0xb3, 0x7d,
	0x04, 0x66, 0xd2, 0x44, 0x09, 0x5b, 0x12, 0xb6, 0x45, 0xaf, 0x7d, 0xd1, 0x74, 0xef, 0xec, 0xf1,
	0x05, 0x9c, 0x90, 0x96, 0x82, 0xef, 0xca, 0x5c, 0x21, 0x89, 0x4d, 0x8e, 0x3c, 0xc3, 0x2a, 0x1c,
	0xd6, 0xbc, 0xb3, 0xd6, 0x7b, 0xe7, 0x1b, 0x56, 0xf3, 0x7f, 0x47, 0x10, 0xfe, 0x2c, 0xb5, 0xc5,
	0x97, 0xa7, 0x73, 0x78, 0xb2, 0xde, 0x73, 0x93, 0x9d, 0x03, 0x6c, 0x25, 0xf1, 0x38, 0x4d, 0xd0,
	0x58, 0x9f, 0xca, 0x9b, 0x28, 0xd8, 0x4a, 0xfa, 0xea, 0x05, 0x37, 0x78, 0x6b, 0xb7, 0xed, 0xea,
	0x14, 0xa6, 0x7b, 0x6e, 0xdf, 0xee, 0x12, 0x26, 0x4a, 0x2b, 0xd9, 0x39, 0xb9, 0x0e, 0x60, 0xec,
	0xd5, 0x27, 0x6c, 0xfe, 0xb7, 0x07, 0xa7, 0x77, 0x99, 0x44, 0xb2, 0x2f, 0x5f, 0xf0, 0x12, 0x26,
	0xf2, 0x51, 0xa4, 0x8a, 0x37, 0x7f, 0x72, 0xdc, 0x2c, 0x37, 0xf6, 0xea, 0xba, 0x11, 0xd9, 0x0a,
	0x8e, 0xbd, 0x10, 0xf6, 0x2f, 0xfa, 0x57, 0xa3, 0x4f, 0x5f, 0x16, 0x87, 0x9f, 0xc1, 0xe2, 0xd9,
	0x31, 0x16, 0xb7, 0x48, 0x76, 0x55, 0x16, 0x85, 0xa0, 0x2a, 0xaa, 0x7b, 0xb9, 0xcb, 0xed, 0xbe,
	0x30, 0x8e, 0x44, 0x9a, 0xfc, 0x6d, 0x04, 0xd1, 0xb4, 0xeb, 0xdc, 0x39, 0xe3, 0x9d, 0x80, 0x51,
	0xa7, 0x09, 0x3b, 0x83, 0x20, 0x35, 0xa6, 0x44, 0xe2, 0x52, 0xf9, 0xbd, 0x82, 0x68, 0x58, 0x0b,
	0xb7, 0xca, 0x05, 0xd1, 0x98, 0x9a, 0x12, 0xbf, 0x52, 0x10, 0x35, 0xf8, 0x3d, 0x25, 0x6c, 0x06,
	0x03, 0x83, 0x94, 0x8a, 0xdc, 0x67, 0x14, 0x44, 0xcd, 0xd7, 0x66, 0xe0, 0x1f, 0xf9, 0xf5, 0xff,
	0x00, 0x00, 0x00, 0xff, 0xff, 0x0c, 0x69, 0xd6, 0x74, 0xfa, 0x03, 0x00, 0x00,
}
