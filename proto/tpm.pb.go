// Code generated by protoc-gen-go. DO NOT EDIT.
// source: tpm.proto

package go_attestation

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

type TpmVersion int32

const (
	TpmVersion_TPM_VERSION_UNSPECIFIED TpmVersion = 0
	TpmVersion_TPM_12                  TpmVersion = 1
	TpmVersion_TPM_20                  TpmVersion = 2
)

var TpmVersion_name = map[int32]string{
	0: "TPM_VERSION_UNSPECIFIED",
	1: "TPM_12",
	2: "TPM_20",
}

var TpmVersion_value = map[string]int32{
	"TPM_VERSION_UNSPECIFIED": 0,
	"TPM_12":                  1,
	"TPM_20":                  2,
}

func (x TpmVersion) String() string {
	return proto.EnumName(TpmVersion_name, int32(x))
}

func (TpmVersion) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{0}
}

type TpmInterface int32

const (
	TpmInterface_TPM_INTERFACE_UNSPECIFIED TpmInterface = 0
	TpmInterface_DIRECT                    TpmInterface = 1
	TpmInterface_KERNEL_MANAGED            TpmInterface = 2
	TpmInterface_DAEMON_MANAGED            TpmInterface = 3
)

var TpmInterface_name = map[int32]string{
	0: "TPM_INTERFACE_UNSPECIFIED",
	1: "DIRECT",
	2: "KERNEL_MANAGED",
	3: "DAEMON_MANAGED",
}

var TpmInterface_value = map[string]int32{
	"TPM_INTERFACE_UNSPECIFIED": 0,
	"DIRECT":                    1,
	"KERNEL_MANAGED":            2,
	"DAEMON_MANAGED":            3,
}

func (x TpmInterface) String() string {
	return proto.EnumName(TpmInterface_name, int32(x))
}

func (TpmInterface) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{1}
}

type EndorsementKey_DataType int32

const (
	EndorsementKey_DATA_TYPE_UNSPECIFIED EndorsementKey_DataType = 0
	EndorsementKey_PUBLIC_BLOB           EndorsementKey_DataType = 1
	EndorsementKey_X509_CERT_BLOB        EndorsementKey_DataType = 2
)

var EndorsementKey_DataType_name = map[int32]string{
	0: "DATA_TYPE_UNSPECIFIED",
	1: "PUBLIC_BLOB",
	2: "X509_CERT_BLOB",
}

var EndorsementKey_DataType_value = map[string]int32{
	"DATA_TYPE_UNSPECIFIED": 0,
	"PUBLIC_BLOB":           1,
	"X509_CERT_BLOB":        2,
}

func (x EndorsementKey_DataType) String() string {
	return proto.EnumName(EndorsementKey_DataType_name, int32(x))
}

func (EndorsementKey_DataType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{1, 0}
}

type ChallengeInfo_ChallengeType int32

const (
	ChallengeInfo_CHALLENGE_UNSPECIFIED ChallengeInfo_ChallengeType = 0
	ChallengeInfo_CHALLENGE_CA          ChallengeInfo_ChallengeType = 1
)

var ChallengeInfo_ChallengeType_name = map[int32]string{
	0: "CHALLENGE_UNSPECIFIED",
	1: "CHALLENGE_CA",
}

var ChallengeInfo_ChallengeType_value = map[string]int32{
	"CHALLENGE_UNSPECIFIED": 0,
	"CHALLENGE_CA":          1,
}

func (x ChallengeInfo_ChallengeType) String() string {
	return proto.EnumName(ChallengeInfo_ChallengeType_name, int32(x))
}

func (ChallengeInfo_ChallengeType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{5, 0}
}

// TpmInfo encapsulates version / device information
// about the TPM, and how the attestation client interfaces
// with it.
type TpmInfo struct {
	TpmVersion   TpmVersion   `protobuf:"varint,1,opt,name=tpm_version,json=tpmVersion,proto3,enum=go_attestation.TpmVersion" json:"tpm_version,omitempty"`
	Manufacturer string       `protobuf:"bytes,2,opt,name=manufacturer,proto3" json:"manufacturer,omitempty"`
	TpmInterface TpmInterface `protobuf:"varint,3,opt,name=tpm_interface,json=tpmInterface,proto3,enum=go_attestation.TpmInterface" json:"tpm_interface,omitempty"`
	// This number represents the version of the support code which
	// interfaces with the TPM.
	TpmInterfaceVersion uint32 `protobuf:"varint,4,opt,name=tpm_interface_version,json=tpmInterfaceVersion,proto3" json:"tpm_interface_version,omitempty"` // Deprecated: Do not use.
	// This is the string provided by the TPM.
	TpmOpaqueInfo string `protobuf:"bytes,5,opt,name=tpm_opaque_info,json=tpmOpaqueInfo,proto3" json:"tpm_opaque_info,omitempty"`
	// This is set if challenges must be generated
	// in TrouSerS format for TPM 1.2 devices.
	TrousersFormat       bool     `protobuf:"varint,6,opt,name=trousers_format,json=trousersFormat,proto3" json:"trousers_format,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TpmInfo) Reset()         { *m = TpmInfo{} }
func (m *TpmInfo) String() string { return proto.CompactTextString(m) }
func (*TpmInfo) ProtoMessage()    {}
func (*TpmInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{0}
}

func (m *TpmInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TpmInfo.Unmarshal(m, b)
}
func (m *TpmInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TpmInfo.Marshal(b, m, deterministic)
}
func (m *TpmInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TpmInfo.Merge(m, src)
}
func (m *TpmInfo) XXX_Size() int {
	return xxx_messageInfo_TpmInfo.Size(m)
}
func (m *TpmInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_TpmInfo.DiscardUnknown(m)
}

var xxx_messageInfo_TpmInfo proto.InternalMessageInfo

func (m *TpmInfo) GetTpmVersion() TpmVersion {
	if m != nil {
		return m.TpmVersion
	}
	return TpmVersion_TPM_VERSION_UNSPECIFIED
}

func (m *TpmInfo) GetManufacturer() string {
	if m != nil {
		return m.Manufacturer
	}
	return ""
}

func (m *TpmInfo) GetTpmInterface() TpmInterface {
	if m != nil {
		return m.TpmInterface
	}
	return TpmInterface_TPM_INTERFACE_UNSPECIFIED
}

// Deprecated: Do not use.
func (m *TpmInfo) GetTpmInterfaceVersion() uint32 {
	if m != nil {
		return m.TpmInterfaceVersion
	}
	return 0
}

func (m *TpmInfo) GetTpmOpaqueInfo() string {
	if m != nil {
		return m.TpmOpaqueInfo
	}
	return ""
}

func (m *TpmInfo) GetTrousersFormat() bool {
	if m != nil {
		return m.TrousersFormat
	}
	return false
}

type EndorsementKey struct {
	Datatype             EndorsementKey_DataType `protobuf:"varint,1,opt,name=datatype,proto3,enum=go_attestation.EndorsementKey_DataType" json:"datatype,omitempty"`
	Data                 []byte                  `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                `json:"-"`
	XXX_unrecognized     []byte                  `json:"-"`
	XXX_sizecache        int32                   `json:"-"`
}

func (m *EndorsementKey) Reset()         { *m = EndorsementKey{} }
func (m *EndorsementKey) String() string { return proto.CompactTextString(m) }
func (*EndorsementKey) ProtoMessage()    {}
func (*EndorsementKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{1}
}

func (m *EndorsementKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EndorsementKey.Unmarshal(m, b)
}
func (m *EndorsementKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EndorsementKey.Marshal(b, m, deterministic)
}
func (m *EndorsementKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EndorsementKey.Merge(m, src)
}
func (m *EndorsementKey) XXX_Size() int {
	return xxx_messageInfo_EndorsementKey.Size(m)
}
func (m *EndorsementKey) XXX_DiscardUnknown() {
	xxx_messageInfo_EndorsementKey.DiscardUnknown(m)
}

var xxx_messageInfo_EndorsementKey proto.InternalMessageInfo

func (m *EndorsementKey) GetDatatype() EndorsementKey_DataType {
	if m != nil {
		return m.Datatype
	}
	return EndorsementKey_DATA_TYPE_UNSPECIFIED
}

func (m *EndorsementKey) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

// Tpm20AikInfo describes an AIK using TPM 2.0 structures.
type Tpm20AikInfo struct {
	// This is a TPMT_PUBLIC structure.
	PublicBlob []byte `protobuf:"bytes,1,opt,name=public_blob,json=publicBlob,proto3" json:"public_blob,omitempty"`
	// This is a TPMS_CREATION_DATA structure.
	CreationData []byte `protobuf:"bytes,2,opt,name=creation_data,json=creationData,proto3" json:"creation_data,omitempty"`
	// This is a TPMU_ATTEST structure, with the dynamic section
	// containing a CREATION_INFO structure.
	AttestationData []byte `protobuf:"bytes,3,opt,name=attestation_data,json=attestationData,proto3" json:"attestation_data,omitempty"`
	// This is a TPMT_SIGNATURE structure.
	SignatureData        []byte   `protobuf:"bytes,4,opt,name=signature_data,json=signatureData,proto3" json:"signature_data,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Tpm20AikInfo) Reset()         { *m = Tpm20AikInfo{} }
func (m *Tpm20AikInfo) String() string { return proto.CompactTextString(m) }
func (*Tpm20AikInfo) ProtoMessage()    {}
func (*Tpm20AikInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{2}
}

func (m *Tpm20AikInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Tpm20AikInfo.Unmarshal(m, b)
}
func (m *Tpm20AikInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Tpm20AikInfo.Marshal(b, m, deterministic)
}
func (m *Tpm20AikInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Tpm20AikInfo.Merge(m, src)
}
func (m *Tpm20AikInfo) XXX_Size() int {
	return xxx_messageInfo_Tpm20AikInfo.Size(m)
}
func (m *Tpm20AikInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_Tpm20AikInfo.DiscardUnknown(m)
}

var xxx_messageInfo_Tpm20AikInfo proto.InternalMessageInfo

func (m *Tpm20AikInfo) GetPublicBlob() []byte {
	if m != nil {
		return m.PublicBlob
	}
	return nil
}

func (m *Tpm20AikInfo) GetCreationData() []byte {
	if m != nil {
		return m.CreationData
	}
	return nil
}

func (m *Tpm20AikInfo) GetAttestationData() []byte {
	if m != nil {
		return m.AttestationData
	}
	return nil
}

func (m *Tpm20AikInfo) GetSignatureData() []byte {
	if m != nil {
		return m.SignatureData
	}
	return nil
}

// Tpm12AikInfo describes an AIK using TPM 1.2 structures.
type Tpm12AikInfo struct {
	// This is a TPM_PUBKEY structure.
	PublicBlob []byte `protobuf:"bytes,1,opt,name=public_blob,json=publicBlob,proto3" json:"public_blob,omitempty"`
	// This is auxillary data, provided for the purpose of debugging.
	// on Windows devices, this represents the contents of PCP_ID_BINDING.
	Aux                  []byte   `protobuf:"bytes,2,opt,name=aux,proto3" json:"aux,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Tpm12AikInfo) Reset()         { *m = Tpm12AikInfo{} }
func (m *Tpm12AikInfo) String() string { return proto.CompactTextString(m) }
func (*Tpm12AikInfo) ProtoMessage()    {}
func (*Tpm12AikInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{3}
}

func (m *Tpm12AikInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Tpm12AikInfo.Unmarshal(m, b)
}
func (m *Tpm12AikInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Tpm12AikInfo.Marshal(b, m, deterministic)
}
func (m *Tpm12AikInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Tpm12AikInfo.Merge(m, src)
}
func (m *Tpm12AikInfo) XXX_Size() int {
	return xxx_messageInfo_Tpm12AikInfo.Size(m)
}
func (m *Tpm12AikInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_Tpm12AikInfo.DiscardUnknown(m)
}

var xxx_messageInfo_Tpm12AikInfo proto.InternalMessageInfo

func (m *Tpm12AikInfo) GetPublicBlob() []byte {
	if m != nil {
		return m.PublicBlob
	}
	return nil
}

func (m *Tpm12AikInfo) GetAux() []byte {
	if m != nil {
		return m.Aux
	}
	return nil
}

// AikInfo describes the public key, parameters, and creation information
// of an attestation identity key.
type AikInfo struct {
	// Types that are valid to be assigned to TpmAikInfo:
	//	*AikInfo_Tpm20
	//	*AikInfo_Tpm12
	TpmAikInfo           isAikInfo_TpmAikInfo `protobuf_oneof:"tpm_aik_info"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *AikInfo) Reset()         { *m = AikInfo{} }
func (m *AikInfo) String() string { return proto.CompactTextString(m) }
func (*AikInfo) ProtoMessage()    {}
func (*AikInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{4}
}

func (m *AikInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AikInfo.Unmarshal(m, b)
}
func (m *AikInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AikInfo.Marshal(b, m, deterministic)
}
func (m *AikInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AikInfo.Merge(m, src)
}
func (m *AikInfo) XXX_Size() int {
	return xxx_messageInfo_AikInfo.Size(m)
}
func (m *AikInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_AikInfo.DiscardUnknown(m)
}

var xxx_messageInfo_AikInfo proto.InternalMessageInfo

type isAikInfo_TpmAikInfo interface {
	isAikInfo_TpmAikInfo()
}

type AikInfo_Tpm20 struct {
	Tpm20 *Tpm20AikInfo `protobuf:"bytes,1,opt,name=tpm20,proto3,oneof"`
}

type AikInfo_Tpm12 struct {
	Tpm12 *Tpm12AikInfo `protobuf:"bytes,2,opt,name=tpm12,proto3,oneof"`
}

func (*AikInfo_Tpm20) isAikInfo_TpmAikInfo() {}

func (*AikInfo_Tpm12) isAikInfo_TpmAikInfo() {}

func (m *AikInfo) GetTpmAikInfo() isAikInfo_TpmAikInfo {
	if m != nil {
		return m.TpmAikInfo
	}
	return nil
}

func (m *AikInfo) GetTpm20() *Tpm20AikInfo {
	if x, ok := m.GetTpmAikInfo().(*AikInfo_Tpm20); ok {
		return x.Tpm20
	}
	return nil
}

func (m *AikInfo) GetTpm12() *Tpm12AikInfo {
	if x, ok := m.GetTpmAikInfo().(*AikInfo_Tpm12); ok {
		return x.Tpm12
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*AikInfo) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*AikInfo_Tpm20)(nil),
		(*AikInfo_Tpm12)(nil),
	}
}

// ChallengeInfo describes which challenge a nonce corresponds to.
type ChallengeInfo struct {
	Type                 ChallengeInfo_ChallengeType `protobuf:"varint,1,opt,name=type,proto3,enum=go_attestation.ChallengeInfo_ChallengeType" json:"type,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                    `json:"-"`
	XXX_unrecognized     []byte                      `json:"-"`
	XXX_sizecache        int32                       `json:"-"`
}

func (m *ChallengeInfo) Reset()         { *m = ChallengeInfo{} }
func (m *ChallengeInfo) String() string { return proto.CompactTextString(m) }
func (*ChallengeInfo) ProtoMessage()    {}
func (*ChallengeInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{5}
}

func (m *ChallengeInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ChallengeInfo.Unmarshal(m, b)
}
func (m *ChallengeInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ChallengeInfo.Marshal(b, m, deterministic)
}
func (m *ChallengeInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ChallengeInfo.Merge(m, src)
}
func (m *ChallengeInfo) XXX_Size() int {
	return xxx_messageInfo_ChallengeInfo.Size(m)
}
func (m *ChallengeInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_ChallengeInfo.DiscardUnknown(m)
}

var xxx_messageInfo_ChallengeInfo proto.InternalMessageInfo

func (m *ChallengeInfo) GetType() ChallengeInfo_ChallengeType {
	if m != nil {
		return m.Type
	}
	return ChallengeInfo_CHALLENGE_UNSPECIFIED
}

func init() {
	proto.RegisterEnum("go_attestation.TpmVersion", TpmVersion_name, TpmVersion_value)
	proto.RegisterEnum("go_attestation.TpmInterface", TpmInterface_name, TpmInterface_value)
	proto.RegisterEnum("go_attestation.EndorsementKey_DataType", EndorsementKey_DataType_name, EndorsementKey_DataType_value)
	proto.RegisterEnum("go_attestation.ChallengeInfo_ChallengeType", ChallengeInfo_ChallengeType_name, ChallengeInfo_ChallengeType_value)
	proto.RegisterType((*TpmInfo)(nil), "go_attestation.TpmInfo")
	proto.RegisterType((*EndorsementKey)(nil), "go_attestation.EndorsementKey")
	proto.RegisterType((*Tpm20AikInfo)(nil), "go_attestation.Tpm20AikInfo")
	proto.RegisterType((*Tpm12AikInfo)(nil), "go_attestation.Tpm12AikInfo")
	proto.RegisterType((*AikInfo)(nil), "go_attestation.AikInfo")
	proto.RegisterType((*ChallengeInfo)(nil), "go_attestation.ChallengeInfo")
}

func init() { proto.RegisterFile("tpm.proto", fileDescriptor_63ac7bc02f9d1279) }

var fileDescriptor_63ac7bc02f9d1279 = []byte{
	// 641 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x54, 0xdb, 0x6e, 0xda, 0x4a,
	0x14, 0x8d, 0x81, 0xdc, 0x36, 0xc6, 0x58, 0x73, 0x14, 0x1d, 0x72, 0x2e, 0x2a, 0x72, 0xd5, 0x86,
	0xa6, 0x12, 0x0a, 0xee, 0x45, 0xaa, 0x5a, 0xa9, 0x32, 0x66, 0x92, 0xb8, 0x21, 0x06, 0x4d, 0x9c,
	0xa8, 0x7d, 0xb2, 0x06, 0x32, 0xa4, 0x56, 0xf0, 0xa5, 0x66, 0xa8, 0x9a, 0x0f, 0xe8, 0x6b, 0x3f,
	0xa3, 0x7f, 0xd0, 0x7e, 0x5f, 0xe5, 0x31, 0x36, 0x86, 0xe6, 0xa1, 0x6f, 0xdb, 0x6b, 0xd6, 0xda,
	0xb3, 0xf6, 0x66, 0x0d, 0xb0, 0xcb, 0x23, 0xbf, 0x1d, 0xc5, 0x21, 0x0f, 0x91, 0x72, 0x13, 0xba,
	0x94, 0x73, 0x36, 0xe3, 0x94, 0x7b, 0x61, 0xa0, 0xfd, 0x2c, 0xc1, 0xb6, 0x13, 0xf9, 0x56, 0x30,
	0x09, 0xd1, 0x6b, 0xa8, 0xf2, 0xc8, 0x77, 0x3f, 0xb3, 0x78, 0xe6, 0x85, 0x41, 0x43, 0x6a, 0x4a,
	0x2d, 0x45, 0xff, 0xa7, 0xbd, 0xaa, 0x68, 0x3b, 0x91, 0x7f, 0x95, 0x32, 0x08, 0xf0, 0xbc, 0x46,
	0x1a, 0xc8, 0x3e, 0x0d, 0xe6, 0x13, 0x3a, 0xe6, 0xf3, 0x98, 0xc5, 0x8d, 0x52, 0x53, 0x6a, 0xed,
	0x92, 0x15, 0x0c, 0x19, 0x50, 0x4b, 0x2e, 0xf0, 0x02, 0xce, 0xe2, 0x09, 0x1d, 0xb3, 0x46, 0x59,
	0x5c, 0xf1, 0xdf, 0x3d, 0x57, 0x58, 0x19, 0x87, 0xc8, 0xbc, 0xf0, 0x85, 0x5e, 0xc2, 0xde, 0x4a,
	0x8b, 0xdc, 0x6d, 0xa5, 0x29, 0xb5, 0x6a, 0xdd, 0x52, 0x43, 0x22, 0x7f, 0x15, 0x05, 0x99, 0xbd,
	0xc7, 0x50, 0x4f, 0x74, 0x61, 0x44, 0x3f, 0xcd, 0x99, 0xeb, 0x05, 0x93, 0xb0, 0xb1, 0x29, 0x1c,
	0x26, 0x8e, 0x06, 0x02, 0x15, 0x3b, 0x38, 0x80, 0x3a, 0x8f, 0xc3, 0xf9, 0x8c, 0xc5, 0x33, 0x77,
	0x12, 0xc6, 0x3e, 0xe5, 0x8d, 0xad, 0xa6, 0xd4, 0xda, 0x21, 0x4a, 0x06, 0x1f, 0x0b, 0x54, 0xfb,
	0x21, 0x81, 0x82, 0x83, 0xeb, 0x30, 0x9e, 0x31, 0x9f, 0x05, 0xfc, 0x8c, 0xdd, 0x21, 0x13, 0x76,
	0xae, 0x29, 0xa7, 0xfc, 0x2e, 0x62, 0x8b, 0xe5, 0x1d, 0xac, 0x4f, 0xb6, 0xaa, 0x68, 0xf7, 0x28,
	0xa7, 0xce, 0x5d, 0xc4, 0x48, 0x2e, 0x44, 0x08, 0x2a, 0x49, 0x2d, 0xf6, 0x27, 0x13, 0x51, 0x6b,
	0xef, 0x60, 0x27, 0x63, 0xa2, 0x7d, 0xd8, 0xeb, 0x19, 0x8e, 0xe1, 0x3a, 0x1f, 0x86, 0xd8, 0xbd,
	0xb4, 0x2f, 0x86, 0xd8, 0xb4, 0x8e, 0x2d, 0xdc, 0x53, 0x37, 0x50, 0x1d, 0xaa, 0xc3, 0xcb, 0x6e,
	0xdf, 0x32, 0xdd, 0x6e, 0x7f, 0xd0, 0x55, 0x25, 0x84, 0x40, 0x79, 0xff, 0xe2, 0xe8, 0x95, 0x6b,
	0x62, 0xe2, 0xa4, 0x58, 0x49, 0xfb, 0x2e, 0x81, 0xec, 0x44, 0xbe, 0x7e, 0x64, 0x78, 0xb7, 0x62,
	0xe2, 0x07, 0x50, 0x8d, 0xe6, 0xa3, 0xa9, 0x37, 0x76, 0x47, 0xd3, 0x70, 0x24, 0x8c, 0xcb, 0x04,
	0x52, 0xa8, 0x3b, 0x0d, 0x47, 0xe8, 0x21, 0xd4, 0xc6, 0x31, 0x13, 0xfe, 0xdd, 0x82, 0x35, 0x39,
	0x03, 0x13, 0x6b, 0xe8, 0x09, 0xa8, 0x85, 0x39, 0x53, 0x5e, 0x59, 0xf0, 0xea, 0x05, 0x5c, 0x50,
	0x1f, 0x81, 0x32, 0xf3, 0x6e, 0x02, 0x9a, 0x64, 0x22, 0x25, 0x56, 0x04, 0xb1, 0x96, 0xa3, 0x09,
	0x4d, 0x33, 0x84, 0xcf, 0x8e, 0xfe, 0xc7, 0x3e, 0x55, 0x28, 0xd3, 0xf9, 0x97, 0x85, 0xbb, 0xa4,
	0xd4, 0xbe, 0x4a, 0xb0, 0x9d, 0xc9, 0x9f, 0xc3, 0x26, 0x4f, 0xc6, 0x16, 0xc2, 0xea, 0xbd, 0x99,
	0xcb, 0x77, 0x72, 0xba, 0x41, 0x52, 0xf2, 0x42, 0xd5, 0xd1, 0x45, 0xd7, 0xfb, 0x55, 0xb9, 0xc3,
	0x85, 0xaa, 0xa3, 0x77, 0x15, 0x48, 0x42, 0xeb, 0x52, 0xef, 0x56, 0x24, 0x4d, 0xfb, 0x26, 0x41,
	0xcd, 0xfc, 0x48, 0xa7, 0x53, 0x16, 0xdc, 0xa4, 0x31, 0x7b, 0x0b, 0x95, 0x42, 0x4c, 0x9e, 0xae,
	0xb7, 0x5d, 0x21, 0x2f, 0xbf, 0x44, 0x54, 0x84, 0x50, 0x7b, 0x53, 0xe8, 0x98, 0xe5, 0xc2, 0x3c,
	0x35, 0xfa, 0x7d, 0x6c, 0x9f, 0xac, 0xe7, 0x42, 0x05, 0x79, 0x79, 0x64, 0x1a, 0xaa, 0x74, 0x68,
	0x00, 0x2c, 0x9f, 0x31, 0xfa, 0x17, 0xfe, 0x76, 0x86, 0xe7, 0xee, 0x15, 0x26, 0x17, 0xd6, 0xc0,
	0x5e, 0x13, 0x03, 0x6c, 0x25, 0x87, 0x1d, 0x5d, 0x95, 0xb2, 0x5a, 0x3f, 0x52, 0x4b, 0x87, 0x54,
	0xfc, 0x3c, 0xcb, 0x87, 0xf9, 0x3f, 0xec, 0x27, 0x67, 0x96, 0xed, 0x60, 0x72, 0x6c, 0x98, 0xf8,
	0xf7, 0x36, 0x3d, 0x8b, 0x60, 0xd3, 0x49, 0x63, 0x79, 0x86, 0x89, 0x8d, 0xfb, 0xee, 0xb9, 0x61,
	0x1b, 0x27, 0xb8, 0xa7, 0x96, 0x12, 0xac, 0x67, 0xe0, 0xf3, 0x81, 0x9d, 0x63, 0xe5, 0xd1, 0x96,
	0xf8, 0xcb, 0x7a, 0xf6, 0x2b, 0x00, 0x00, 0xff, 0xff, 0xa5, 0x3e, 0xc2, 0xea, 0xbf, 0x04, 0x00,
	0x00,
}
