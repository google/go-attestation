package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

type efiDevicePathType uint8

const (
	hardwareDevicePath  efiDevicePathType = 0x01
	acpiDevicePath      efiDevicePathType = 0x02
	messagingDevicePath efiDevicePathType = 0x03
	mediaDevicePath     efiDevicePathType = 0x04
	bbsDevicePath       efiDevicePathType = 0x05
	endDevicePath       efiDevicePathType = 0x7f
)

type hwDPType uint8

const (
	pciHwDevicePath        hwDPType = 0x01
	pccardHwDevicePath     hwDPType = 0x02
	mmioHwDevicePath       hwDPType = 0x03
	vendorHwDevicePath     hwDPType = 0x04
	controllerHwDevicePath hwDPType = 0x05
	bmcHwDevicePath        hwDPType = 0x06
)

type acpiDPType uint8

const (
	normalACPIDevicePath   acpiDPType = 0x01
	expandedACPIDevicePath acpiDPType = 0x02
	adrACPIDevicePath      acpiDPType = 0x03
)

type messagingDPType uint8

const (
	atapiMessagingDevicePath      messagingDPType = 1
	scsiMessagingDevicePath       messagingDPType = 2
	fcMessagingDevicePath         messagingDPType = 3
	firewireMessagingDevicePath   messagingDPType = 4
	usbMessagingDevicePath        messagingDPType = 5
	i2oMessagingDevicePath        messagingDPType = 6
	infinibandMessagingDevicePath messagingDPType = 9
	vendorMessagingDevicePath     messagingDPType = 10
	macMessagingDevicePath        messagingDPType = 11
	ipv4MessagingDevicePath       messagingDPType = 12
	ipv6MessagingDevicePath       messagingDPType = 13
	uartMessagingDevicePath       messagingDPType = 14
	usbclassMessagingDevicePath   messagingDPType = 15
	usbwwidMessagingDevicePath    messagingDPType = 16
	lunMessagignDevicePath        messagingDPType = 17
	sataMessagingDevicePath       messagingDPType = 18
	iscsiMessagingDevicePath      messagingDPType = 19
	vlanMessagingDevicePath       messagingDPType = 20
	fcExMessagingDevicePath       messagingDPType = 21
	sasExMessagingDevicePath      messagingDPType = 22
	nvmMessagingDevicePath        messagingDPType = 23
	uriMessagingDevicePath        messagingDPType = 24
	ufsMessagingDevicePath        messagingDPType = 25
	sdMessagingDevicePath         messagingDPType = 26
	btMessagingDevicePath         messagingDPType = 27
	wifiMessagingDevicePath       messagingDPType = 28
	emmcMessagingDevicePath       messagingDPType = 29
	btleMessagingDevicePath       messagingDPType = 30
	dnsMessagingDevicePath        messagingDPType = 31
)

type mediaDPType uint8

const (
	hardDriveDevicePath     mediaDPType = 0x01
	cdDriveDevicePath       mediaDPType = 0x02
	vendorDevicePath        mediaDPType = 0x03
	filePathDevicePath      mediaDPType = 0x04
	mediaProtocolDevicePath mediaDPType = 0x05
	piwgFileDevicePath      mediaDPType = 0x06
	piwgVolumeDevicePath    mediaDPType = 0x07
	offsetDevicePath        mediaDPType = 0x08
	ramDiskDevicePath       mediaDPType = 0x09
)

type bbsDPType uint8

const (
	bbs101DevicePath bbsDPType = 0x01
)

type endDPType uint8

const (
	endThisDevicePath   endDPType = 0x01
	endEntireDevicePath endDPType = 0xff
)

// efiDevicePathHeader represents the EFI_DEVICE_PATH_PROTOCOL type.
// See section "10.2 EFI Device Path Protocol" in the specification for more information.
type efiDevicePathHeader struct {
	Type    efiDevicePathType
	SubType uint8
	Length  uint16
}

// The canonical representation of EFI Device Paths to text is Table
// 102 in section 10.6.1.6 of the spec. The reference implementation is
// https://github.com/tianocore/edk2/blob/master/MdePkg/Library/UefiDevicePathLib/DevicePathFromText.c
type efiPCIDevicePath struct {
	Function uint8
	Device   uint8
}

func (dp efiPCIDevicePath) String() string {
	return fmt.Sprintf("Pci(0x%x,0x%x)", dp.Device, dp.Function)
}

type efiMMIODevicePath struct {
	MemoryType   uint32
	StartAddress uint64
	EndAddress   uint64
}

func (dp efiMMIODevicePath) String() string {
	return fmt.Sprintf("MemoryMapped(0x%x,0x%x,0x%x)", dp.MemoryType, dp.StartAddress, dp.EndAddress)
}

type efiSignatureType uint8

const (
	mbr  efiSignatureType = 0x01
	guid efiSignatureType = 0x02
)

// efiLBA represents the EFI_LBA type.
// See section "2.3.1 Data Types" in the specification for more information.
type efiLBA uint64

type efiHardDriveDevicePath struct {
	Partition          uint32
	PartitionStart     efiLBA
	PartitionSize      efiLBA
	PartitionSignature [16]byte
	PartitionFormat    uint8
	SignatureType      efiSignatureType
}

func (dp efiHardDriveDevicePath) String() string {
	switch dp.SignatureType {
	case mbr:
		return fmt.Sprintf("HD(%d,MBR,0x%08x,0x%x,0x%x)", dp.Partition, dp.PartitionSignature, dp.PartitionStart, dp.PartitionSize)
	case guid:
		guid := efiGUID{}
		buf := bytes.NewReader(dp.PartitionSignature[:])
		binary.Read(buf, binary.LittleEndian, &guid)
		guidString := guid.String()
		return fmt.Sprintf("HD(%d,GPT,%s,0x%x,0x%x)", dp.Partition, guidString, dp.PartitionStart, dp.PartitionSize)
	default:
		return fmt.Sprintf("HD(%d,%d,0,0x%x,0x%x)", dp.Partition, dp.SignatureType, dp.PartitionStart, dp.PartitionSize)
	}
}

type efiMacMessagingDevicePath struct {
	MAC    [32]byte
	IfType byte
}

func (dp efiMacMessagingDevicePath) String() string {
	hwAddressSize := len(dp.MAC)
	if dp.IfType == 0x01 || dp.IfType == 0x00 {
		hwAddressSize = 6
	}

	output := "MAC("
	for i := 0; i < hwAddressSize; i++ {
		output += fmt.Sprintf("%02x", dp.MAC[i])
	}
	output += fmt.Sprintf(",0x%x)", dp.IfType)
	return output
}

type efiIpv4MessagingDevicePath struct {
	LocalAddress   [4]byte
	RemoteAddress  [4]byte
	LocalPort      uint16
	RemotePort     uint16
	Protocol       uint16
	StaticIP       byte
	GatewayAddress [4]byte
	SubnetMask     [4]byte
}

func (dp efiIpv4MessagingDevicePath) String() string {
	output := "IPv4("
	output += fmt.Sprintf("%d.%d.%d.%d:%d,", dp.RemoteAddress[0], dp.RemoteAddress[1], dp.RemoteAddress[2], dp.RemoteAddress[3], dp.RemotePort)
	if dp.Protocol == 6 {
		output += fmt.Sprintf("TCP,")
	} else if dp.Protocol == 17 {
		output += fmt.Sprintf("UDP,")
	} else {
		output += fmt.Sprintf("0x%x,", dp.Protocol)
	}
	if dp.StaticIP == 0 {
		output += fmt.Sprintf("DHCP,")
	} else {
		output += fmt.Sprintf("Static,")
	}
	output += fmt.Sprintf("%d.%d.%d.%d:%d,", dp.LocalAddress[0], dp.LocalAddress[1], dp.LocalAddress[2], dp.LocalAddress[3], dp.LocalPort)
	output += fmt.Sprintf("%d.%d.%d.%d,", dp.GatewayAddress[0], dp.GatewayAddress[1], dp.GatewayAddress[2], dp.GatewayAddress[3])
	output += fmt.Sprintf("%d.%d.%d.%d)", dp.SubnetMask[0], dp.SubnetMask[1], dp.SubnetMask[2], dp.SubnetMask[3])
	return output
}

type efiIpv6MessagingDevicePath struct {
	LocalAddress  [16]byte
	RemoteAddress [16]byte
	LocalPort     uint16
	RemotePort    uint16
	Protocol      uint16
	AddressOrigin byte
	PrefixLength  byte
	GatewayIP     [16]byte
}

func (dp efiIpv6MessagingDevicePath) String() string {
	output := "IPv6("
	output += fmt.Sprintf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x:%d,", dp.RemoteAddress[:2], dp.RemoteAddress[2:4], dp.RemoteAddress[4:6], dp.RemoteAddress[6:8], dp.RemoteAddress[8:10], dp.RemoteAddress[10:12], dp.RemoteAddress[12:14], dp.RemoteAddress[14:16], dp.RemotePort)
	if dp.Protocol == 6 {
		output += fmt.Sprintf("TCP,")
	} else if dp.Protocol == 17 {
		output += fmt.Sprintf("UDP,")
	} else {
		output += fmt.Sprintf("0x%x,", dp.Protocol)
	}
	switch dp.AddressOrigin {
	case 0:
		output += fmt.Sprintf("Static,")
	case 1:
		output += fmt.Sprintf("StatelessAutoConfigure,")
	default:
		output += fmt.Sprintf("StatefulAutoConfigure,")
	}
	output += fmt.Sprintf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x:%d,", dp.LocalAddress[0:2], dp.LocalAddress[2:4], dp.LocalAddress[4:6], dp.LocalAddress[6:8], dp.LocalAddress[8:10], dp.LocalAddress[10:12], dp.LocalAddress[12:14], dp.LocalAddress[14:16], dp.LocalPort)
	output += fmt.Sprintf("0x%x,", dp.PrefixLength)
	output += fmt.Sprintf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x)", dp.GatewayIP[0:2], dp.GatewayIP[2:4], dp.GatewayIP[4:6], dp.GatewayIP[6:8], dp.GatewayIP[8:10], dp.GatewayIP[10:12], dp.GatewayIP[12:14], dp.GatewayIP[14:16])
	return output
}

type efiUsbMessagingDevicePath struct {
	ParentPort byte
	Interface  byte
}

func (dp efiUsbMessagingDevicePath) String() string {
	return fmt.Sprintf("USB(0x%x,0x%x)", dp.ParentPort, dp.Interface)
}

type efiVendorMessagingDevicePath struct {
	GUID efiGUID
	Data []byte
}

type efiSataMessagingDevicePath struct {
	HBA            uint16
	PortMultiplier uint16
	LUN            uint16
}

func (dp efiSataMessagingDevicePath) String() string {
	return fmt.Sprintf("Sata(0x%x,0x%x,0x%x)", dp.HBA, dp.PortMultiplier, dp.LUN)
}

type efiNvmMessagingDevicePath struct {
	Namespace uint32
	EUI       [8]byte
}

func (dp efiNvmMessagingDevicePath) String() string {
	output := fmt.Sprintf("NVMe(0x%x,", dp.Namespace)
	for _, id := range dp.EUI {
		output += fmt.Sprintf("%02x-", id)
	}
	output = strings.TrimSuffix(output, "-")
	output += ")"
	return output
}

type efiACPIDevicePath struct {
	HID uint32
	UID uint32
}

func (dp efiACPIDevicePath) String() string {
	if (dp.HID & 0xffff) != 0x41d0 {
		return fmt.Sprintf("Acpi(0x%08x,0x%x)", dp.HID, dp.UID)
	}
	switch dp.HID >> 16 {
	case 0x0a03:
		return fmt.Sprintf("PciRoot(0x%x)", dp.UID)
	case 0x0a08:
		return fmt.Sprintf("PcieRoot(0x%x)", dp.UID)
	case 0x0604:
		return fmt.Sprintf("Floppy(0x%x)", dp.UID)
	case 0x0301:
		return fmt.Sprintf("Keyboard(0x%x)", dp.UID)
	case 0x0501:
		return fmt.Sprintf("Serial(0x%x)", dp.UID)
	case 0x0401:
		return fmt.Sprintf("ParallelPort(0x%x)", dp.UID)
	default:
		return fmt.Sprintf("Acpi(PNP%04x,0x%x)", dp.HID>>16, dp.UID)
	}
}

type efiExpandedACPIDevicePathFixed struct {
	HID uint32
	UID uint32
	CID uint32
}

type efiExpandedACPIDevicePath struct {
	Fixed  efiExpandedACPIDevicePathFixed
	HIDStr string
	UIDStr string
	CIDStr string
}

func (dp efiExpandedACPIDevicePath) String() string {
	if dp.Fixed.HID>>16 == 0x0a08 || dp.Fixed.CID>>16 == 0x0a08 {
		if dp.Fixed.UID == 0 {
			return fmt.Sprintf("PcieRoot(%s)", dp.UIDStr)
		}
		return fmt.Sprintf("PcieRoot(0x%x)", dp.Fixed.UID)
	}

	HID := fmt.Sprintf("%c%c%c%04x", ((dp.Fixed.HID>>10)&0x1f)+0x40,
		((dp.Fixed.HID>>5)&0x1f)+0x40,
		(dp.Fixed.HID&0x1f)+0x40,
		dp.Fixed.HID>>16)
	CID := fmt.Sprintf("%c%c%c%04x", ((dp.Fixed.CID>>10)&0x1f)+0x40,
		((dp.Fixed.CID>>5)&0x1f)+0x40,
		(dp.Fixed.CID&0x1f)+0x40,
		dp.Fixed.CID>>16)

	if dp.HIDStr == "" && dp.CIDStr == "" && dp.UIDStr == "" {
		if dp.Fixed.CID == 0 {
			return fmt.Sprintf("AcpiExp(%s,0,%s)", HID, dp.UIDStr)
		}
		return fmt.Sprintf("AcpiExp(%s,%s,%s)", HID, CID, dp.UIDStr)
	}

	return fmt.Sprintf("AcpiExp(%s, %s, 0x%x, %s, %s, %s)", HID, CID, dp.Fixed.UID, dp.HIDStr, dp.CIDStr, dp.UIDStr)
}

type efiAdrACPIDevicePath struct {
	ADRs []uint32
}

func (dp efiAdrACPIDevicePath) String() string {
	output := "AcpiAdr("
	for _, adr := range dp.ADRs {
		output += fmt.Sprintf("0x%x,", adr)
	}
	output = strings.TrimSuffix(output, ",")
	output += ")"
	return output
}

type efiPiwgFileDevicePath struct {
	GUID efiGUID
}

func (dp efiPiwgFileDevicePath) String() string {
	return fmt.Sprintf("FvFile(%s)", dp.GUID)
}

type efiPiwgVolumeDevicePath struct {
	GUID efiGUID
}

func (dp efiPiwgVolumeDevicePath) String() string {
	return fmt.Sprintf("Fv(%s)", dp.GUID)
}

type efiOffsetDevicePath struct {
	Reserved    uint32
	StartOffset uint64
	EndOffset   uint64
}

func (dp efiOffsetDevicePath) String() string {
	return fmt.Sprintf("Offset(0x%x, 0x%x)", dp.StartOffset, dp.EndOffset)
}

type efiBBSDevicePathFixed struct {
	DeviceType uint16
	Status     uint16
}

type efiBBSDevicePath struct {
	Fixed       efiBBSDevicePathFixed
	Description []byte
}

func (dp efiBBSDevicePath) String() string {
	output := "BBS("
	description := strings.TrimSuffix(string(dp.Description), string(0x00))
	switch dp.Fixed.DeviceType {
	case 0x01:
		output += fmt.Sprintf("Floppy,%s", description)
	case 0x02:
		output += fmt.Sprintf("HD,%s", description)
	case 0x03:
		output += fmt.Sprintf("CDROM,%s", description)
	case 0x04:
		output += fmt.Sprintf("PCMCIA,%s", description)
	case 0x05:
		output += fmt.Sprintf("USB,%s", description)
	case 0x06:
		output += fmt.Sprintf("Network,%s", description)
	default:
		output += fmt.Sprintf("0x%x,%s", dp.Fixed.DeviceType, description)
	}
	output += fmt.Sprintf(",0x%x)", dp.Fixed.Status)
	return output
}

func dumpEfiDevicePath(buf io.Reader, dp efiDevicePathHeader, prefix string) string {
	data := make([]byte, dp.Length-4)
	binary.Read(buf, binary.LittleEndian, &data)
	if prefix == "" {
		return fmt.Sprintf("Path(%d,%d,%02x)", dp.Type, dp.SubType, data[:])
	}
	return fmt.Sprintf("%s(%d,%02x)", prefix, dp.SubType, data[:])
}

// efiDevicePath translates an EFI Device Path into the canonical string representation
func efiDevicePath(b []byte) (string, error) {
	buf := bytes.NewReader(b)
	offset := 0
	dp := efiDevicePathHeader{}
	output := ""

	for offset < len(b) {
		buf.Seek(int64(offset), io.SeekStart)
		binary.Read(buf, binary.LittleEndian, &dp)
		offset += int(dp.Length)
		if offset == 0 || offset > len(b) {
			return "", fmt.Errorf("malformed device path")
		}
		switch dp.Type {
		case hardwareDevicePath:
			switch hwDPType(dp.SubType) {
			case pciHwDevicePath:
				path := efiPCIDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			case mmioHwDevicePath:
				path := efiMMIODevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			default:
				output += dumpEfiDevicePath(buf, dp, "HardwarePath")
			}
		case acpiDevicePath:
			switch acpiDPType(dp.SubType) {
			case normalACPIDevicePath:
				path := efiACPIDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			case expandedACPIDevicePath:
				path := efiExpandedACPIDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path.Fixed)
				data := make([]byte, dp.Length-16)
				buf.Read(data)
				path.HIDStr = string(data)
				path.UIDStr = string(data[len(path.HIDStr)+1:])
				path.CIDStr = string(data[len(path.HIDStr)+len(path.UIDStr)+2:])
				output += fmt.Sprintf("%s", path)
			case adrACPIDevicePath:
				path := efiAdrACPIDevicePath{}
				path.ADRs = make([]uint32, (dp.Length-4)/4)
				binary.Read(buf, binary.LittleEndian, &path.ADRs)
				output += fmt.Sprintf("%s", path)
			default:
				output += dumpEfiDevicePath(buf, dp, "AcpiPath")
			}
		case messagingDevicePath:
			switch messagingDPType(dp.SubType) {
			case usbMessagingDevicePath:
				path := efiUsbMessagingDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			case vendorMessagingDevicePath:
				path := efiVendorMessagingDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path.GUID)
				path.Data = make([]byte, dp.Length-20)
				buf.Read(path.Data)
				GUIDString := path.GUID.String()
				output += fmt.Sprintf("VenMsg(%s)", GUIDString)
			case macMessagingDevicePath:
				path := efiMacMessagingDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			case ipv4MessagingDevicePath:
				path := efiIpv4MessagingDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			case ipv6MessagingDevicePath:
				path := efiIpv6MessagingDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			case sataMessagingDevicePath:
				path := efiSataMessagingDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			case nvmMessagingDevicePath:
				path := efiNvmMessagingDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			default:
				output += dumpEfiDevicePath(buf, dp, "Msg")
			}
		case mediaDevicePath:
			switch mediaDPType(dp.SubType) {
			case hardDriveDevicePath:
				path := efiHardDriveDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			case filePathDevicePath:
				path := make([]uint16, (dp.Length-4)/2)
				binary.Read(buf, binary.LittleEndian, &path)
				filename := strings.TrimSuffix(string(utf16.Decode(path)), string(0x00))
				output += filename
			case piwgFileDevicePath:
				path := efiPiwgFileDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			case piwgVolumeDevicePath:
				path := efiPiwgVolumeDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			case offsetDevicePath:
				path := efiOffsetDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path)
				output += fmt.Sprintf("%s", path)
			default:
				output += dumpEfiDevicePath(buf, dp, "MediaPath")
			}
		case bbsDevicePath:
			switch bbsDPType(dp.SubType) {
			case bbs101DevicePath:
				path := efiBBSDevicePath{}
				binary.Read(buf, binary.LittleEndian, &path.Fixed)
				path.Description = make([]byte, dp.Length-8)
				buf.Read(path.Description)
				output += fmt.Sprintf("%s", path)
			default:
				output += dumpEfiDevicePath(buf, dp, "BbsPath")
			}
		case endDevicePath:
			switch endDPType(dp.SubType) {
			case endThisDevicePath:
				output += ","
			case endEntireDevicePath:
				output = strings.TrimSuffix(output, "/")
				output += ","
				continue
			default:
				output += fmt.Sprintf("Unknown end subtype %d",
					dp.SubType)
			}
		default:
			output += dumpEfiDevicePath(buf, dp, "")
		}
		output += "/"
	}

	output = strings.TrimSuffix(output, "/")
	return output, nil
}
