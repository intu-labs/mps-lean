// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: pkg/round/message.proto

package round

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	github_com_taurusgroup_cmp_ecdsa_pkg_party "github.com/taurusgroup/cmp-ecdsa/pkg/party"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Broadcast int32

const (
	Broadcast_None     Broadcast = 0
	Broadcast_Basic    Broadcast = 1
	Broadcast_Reliable Broadcast = 2
)

var Broadcast_name = map[int32]string{
	0: "None",
	1: "Basic",
	2: "Reliable",
}

var Broadcast_value = map[string]int32{
	"None":     0,
	"Basic":    1,
	"Reliable": 2,
}

func (x Broadcast) String() string {
	return proto.EnumName(Broadcast_name, int32(x))
}

func (Broadcast) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_4b57c71b12807c0e, []int{0}
}

type Header struct {
	From      github_com_taurusgroup_cmp_ecdsa_pkg_party.ID `protobuf:"bytes,1,opt,name=from,proto3,customtype=github.com/taurusgroup/cmp-ecdsa/pkg/party.ID" json:"from"`
	To        github_com_taurusgroup_cmp_ecdsa_pkg_party.ID `protobuf:"bytes,2,opt,name=to,proto3,customtype=github.com/taurusgroup/cmp-ecdsa/pkg/party.ID" json:"to"`
	Broadcast Broadcast                                     `protobuf:"varint,3,opt,name=broadcast,proto3,enum=round.Broadcast" json:"broadcast,omitempty"`
}

func (m *Header) Reset()         { *m = Header{} }
func (m *Header) String() string { return proto.CompactTextString(m) }
func (*Header) ProtoMessage()    {}
func (*Header) Descriptor() ([]byte, []int) {
	return fileDescriptor_4b57c71b12807c0e, []int{0}
}
func (m *Header) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Header) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *Header) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Header.Merge(m, src)
}
func (m *Header) XXX_Size() int {
	return m.Size()
}
func (m *Header) XXX_DiscardUnknown() {
	xxx_messageInfo_Header.DiscardUnknown(m)
}

var xxx_messageInfo_Header proto.InternalMessageInfo

func (m *Header) GetBroadcast() Broadcast {
	if m != nil {
		return m.Broadcast
	}
	return Broadcast_None
}

func init() {
	proto.RegisterEnum("round.Broadcast", Broadcast_name, Broadcast_value)
	proto.RegisterType((*Header)(nil), "round.Header")
}

func init() { proto.RegisterFile("pkg/round/message.proto", fileDescriptor_4b57c71b12807c0e) }

var fileDescriptor_4b57c71b12807c0e = []byte{
	// 283 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x90, 0x3d, 0x6b, 0xfb, 0x30,
	0x10, 0xc6, 0x2d, 0xff, 0x93, 0x10, 0x8b, 0x3f, 0xc5, 0x68, 0xa9, 0xe9, 0xa0, 0x84, 0x4e, 0x21,
	0x10, 0x09, 0x5a, 0xfa, 0x05, 0x4c, 0x0b, 0xc9, 0xd2, 0xc1, 0x63, 0x37, 0xd9, 0x56, 0x54, 0xd3,
	0x38, 0x27, 0xf4, 0x32, 0xf4, 0x5b, 0xf4, 0x63, 0x85, 0x4e, 0x19, 0x43, 0x87, 0x50, 0xec, 0x2f,
	0x52, 0xaa, 0xd2, 0x97, 0xb1, 0xd0, 0xed, 0x9e, 0xe7, 0xee, 0x1e, 0x7e, 0x77, 0xf8, 0x54, 0x3f,
	0x28, 0x6e, 0xc0, 0x6f, 0x6b, 0xde, 0x4a, 0x6b, 0x85, 0x92, 0x4c, 0x1b, 0x70, 0x40, 0x86, 0xc1,
	0x3c, 0x5b, 0xa8, 0xc6, 0xdd, 0xfb, 0x92, 0x55, 0xd0, 0x72, 0x05, 0x0a, 0x78, 0xe8, 0x96, 0x7e,
	0x1d, 0x54, 0x10, 0xa1, 0xfa, 0xd8, 0x3a, 0x7f, 0x46, 0x78, 0xb4, 0x94, 0xa2, 0x96, 0x86, 0xac,
	0xf0, 0x60, 0x6d, 0xa0, 0xcd, 0xd0, 0x14, 0xcd, 0x92, 0xfc, 0x6a, 0x77, 0x9c, 0x44, 0x2f, 0xc7,
	0xc9, 0xcf, 0x3c, 0x27, 0xbc, 0xf1, 0x56, 0x19, 0xf0, 0x9a, 0x57, 0xad, 0x5e, 0xc8, 0xaa, 0xb6,
	0x82, 0xbf, 0x03, 0x69, 0x61, 0xdc, 0x23, 0x5b, 0x5d, 0x17, 0x21, 0x82, 0xdc, 0xe0, 0xd8, 0x41,
	0x16, 0xff, 0x25, 0x28, 0x76, 0x40, 0x18, 0x4e, 0x4a, 0x03, 0xa2, 0xae, 0x84, 0x75, 0xd9, 0xbf,
	0x29, 0x9a, 0x9d, 0x5c, 0xa4, 0x2c, 0x9c, 0xc9, 0xf2, 0x4f, 0xbf, 0xf8, 0x1e, 0x99, 0x33, 0x9c,
	0x7c, 0xf9, 0x64, 0x8c, 0x07, 0xb7, 0xb0, 0x95, 0x69, 0x44, 0x12, 0x3c, 0xcc, 0x85, 0x6d, 0xaa,
	0x14, 0x91, 0xff, 0x78, 0x5c, 0xc8, 0x4d, 0x23, 0xca, 0x8d, 0x4c, 0xe3, 0x7c, 0xb9, 0xeb, 0x28,
	0xda, 0x77, 0x14, 0x1d, 0x3a, 0x8a, 0x5e, 0x3b, 0x8a, 0x9e, 0x7a, 0x1a, 0xed, 0x7b, 0x1a, 0x1d,
	0x7a, 0x1a, 0xdd, 0xcd, 0x7f, 0x05, 0x1c, 0x70, 0xca, 0x51, 0xf8, 0xe6, 0xe5, 0x5b, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x04, 0xad, 0x0b, 0xfc, 0x9e, 0x01, 0x00, 0x00,
}

func (m *Header) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Header) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Header) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Broadcast != 0 {
		i = encodeVarintMessage(dAtA, i, uint64(m.Broadcast))
		i--
		dAtA[i] = 0x18
	}
	if len(m.To) > 0 {
		i -= len(m.To)
		copy(dAtA[i:], m.To)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.To)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.From) > 0 {
		i -= len(m.From)
		copy(dAtA[i:], m.From)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.From)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintMessage(dAtA []byte, offset int, v uint64) int {
	offset -= sovMessage(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Header) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.From)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.To)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.Broadcast != 0 {
		n += 1 + sovMessage(uint64(m.Broadcast))
	}
	return n
}

func sovMessage(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMessage(x uint64) (n int) {
	return sovMessage(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Header) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Header: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Header: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field From", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.From = github_com_taurusgroup_cmp_ecdsa_pkg_party.ID(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field To", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.To = github_com_taurusgroup_cmp_ecdsa_pkg_party.ID(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Broadcast", wireType)
			}
			m.Broadcast = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Broadcast |= Broadcast(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipMessage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipMessage(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthMessage
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMessage
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMessage
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMessage        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMessage          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMessage = fmt.Errorf("proto: unexpected end of group")
)