// Code generated by protoc-gen-go.
// source: pb/dlog.proto
// DO NOT EDIT!

/*
Package pb is a generated protocol buffer package.

Version 1.0

It is generated from these files:
	pb/dlog.proto

It has these top-level messages:
	LogSet
	LogEntry
	L7GFrame
*/
package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type LogSet struct {
	StartTime int64       `protobuf:"varint,1,opt,name=startTime" json:"startTime,omitempty"`
	EndTime   int64       `protobuf:"varint,2,opt,name=endTime" json:"endTime,omitempty"`
	Logs      []*LogEntry `protobuf:"bytes,3,rep,name=logs" json:"logs,omitempty"`
}

func (m *LogSet) Reset()                    { *m = LogSet{} }
func (m *LogSet) String() string            { return proto.CompactTextString(m) }
func (*LogSet) ProtoMessage()               {}
func (*LogSet) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *LogSet) GetStartTime() int64 {
	if m != nil {
		return m.StartTime
	}
	return 0
}

func (m *LogSet) GetEndTime() int64 {
	if m != nil {
		return m.EndTime
	}
	return 0
}

func (m *LogSet) GetLogs() []*LogEntry {
	if m != nil {
		return m.Logs
	}
	return nil
}

type LogEntry struct {
	Time int64     `protobuf:"varint,1,opt,name=time" json:"time,omitempty"`
	L7G  *L7GFrame `protobuf:"bytes,2,opt,name=l7g" json:"l7g,omitempty"`
}

func (m *LogEntry) Reset()                    { *m = LogEntry{} }
func (m *LogEntry) String() string            { return proto.CompactTextString(m) }
func (*LogEntry) ProtoMessage()               {}
func (*LogEntry) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *LogEntry) GetTime() int64 {
	if m != nil {
		return m.Time
	}
	return 0
}

func (m *LogEntry) GetL7G() *L7GFrame {
	if m != nil {
		return m.L7G
	}
	return nil
}

type L7GFrame struct {
	Srcmac  string `protobuf:"bytes,1,opt,name=srcmac" json:"srcmac,omitempty"`
	Srcip   string `protobuf:"bytes,2,opt,name=srcip" json:"srcip,omitempty"`
	Popid   string `protobuf:"bytes,3,opt,name=popid" json:"popid,omitempty"`
	Poptime int64  `protobuf:"varint,4,opt,name=poptime" json:"poptime,omitempty"`
	Brtime  int64  `protobuf:"varint,5,opt,name=brtime" json:"brtime,omitempty"`
	Rssi    int32  `protobuf:"varint,6,opt,name=rssi" json:"rssi,omitempty"`
	Lqi     int32  `protobuf:"varint,7,opt,name=lqi" json:"lqi,omitempty"`
	Payload []byte `protobuf:"bytes,8,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (m *L7GFrame) Reset()                    { *m = L7GFrame{} }
func (m *L7GFrame) String() string            { return proto.CompactTextString(m) }
func (*L7GFrame) ProtoMessage()               {}
func (*L7GFrame) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *L7GFrame) GetSrcmac() string {
	if m != nil {
		return m.Srcmac
	}
	return ""
}

func (m *L7GFrame) GetSrcip() string {
	if m != nil {
		return m.Srcip
	}
	return ""
}

func (m *L7GFrame) GetPopid() string {
	if m != nil {
		return m.Popid
	}
	return ""
}

func (m *L7GFrame) GetPoptime() int64 {
	if m != nil {
		return m.Poptime
	}
	return 0
}

func (m *L7GFrame) GetBrtime() int64 {
	if m != nil {
		return m.Brtime
	}
	return 0
}

func (m *L7GFrame) GetRssi() int32 {
	if m != nil {
		return m.Rssi
	}
	return 0
}

func (m *L7GFrame) GetLqi() int32 {
	if m != nil {
		return m.Lqi
	}
	return 0
}

func (m *L7GFrame) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

func init() {
	proto.RegisterType((*LogSet)(nil), "pb.LogSet")
	proto.RegisterType((*LogEntry)(nil), "pb.LogEntry")
	proto.RegisterType((*L7GFrame)(nil), "pb.L7GFrame")
}

func init() { proto.RegisterFile("pb/dlog.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 259 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x44, 0x90, 0xc1, 0x6a, 0x84, 0x30,
	0x10, 0x86, 0x71, 0xa3, 0xae, 0x4e, 0xb7, 0x50, 0x86, 0x52, 0x72, 0x28, 0x45, 0x3c, 0x79, 0xb2,
	0xd0, 0x1e, 0xf6, 0xd6, 0x5b, 0xdb, 0xcb, 0x9e, 0xd2, 0xbe, 0x80, 0x51, 0x11, 0x21, 0x6e, 0xd2,
	0x24, 0x97, 0x7d, 0xbb, 0x3e, 0xda, 0x92, 0xd1, 0xb0, 0xb7, 0xf9, 0xfe, 0x1f, 0xbe, 0xcc, 0x04,
	0xee, 0x8d, 0x7c, 0x1d, 0x94, 0x9e, 0x5a, 0x63, 0xb5, 0xd7, 0xb8, 0x33, 0xb2, 0x96, 0x90, 0x9f,
	0xf4, 0xf4, 0x33, 0x7a, 0x7c, 0x86, 0xd2, 0xf9, 0xce, 0xfa, 0xdf, 0x79, 0x19, 0x79, 0x52, 0x25,
	0x0d, 0x13, 0xb7, 0x00, 0x39, 0xec, 0xc7, 0xf3, 0x40, 0xdd, 0x8e, 0xba, 0x88, 0x58, 0x41, 0xaa,
	0xf4, 0xe4, 0x38, 0xab, 0x58, 0x73, 0xf7, 0x76, 0x68, 0x8d, 0x6c, 0x4f, 0x7a, 0xfa, 0x3c, 0x7b,
	0x7b, 0x11, 0xd4, 0xd4, 0x1f, 0x50, 0xc4, 0x04, 0x11, 0x52, 0x7f, 0x7b, 0x80, 0x66, 0x7c, 0x01,
	0xa6, 0x8e, 0x13, 0x79, 0xa3, 0xe0, 0xf8, 0xfd, 0x65, 0xbb, 0x65, 0x14, 0xa1, 0xa8, 0xff, 0x13,
	0x28, 0x62, 0x82, 0x4f, 0x90, 0x3b, 0xdb, 0x2f, 0x5d, 0x4f, 0x8a, 0x52, 0x6c, 0x84, 0x8f, 0x90,
	0x39, 0xdb, 0xcf, 0x86, 0x34, 0xa5, 0x58, 0x21, 0xa4, 0x46, 0x9b, 0x79, 0xe0, 0x6c, 0x4d, 0x09,
	0xc2, 0x31, 0x46, 0x1b, 0xda, 0x23, 0x5d, 0x8f, 0xd9, 0x30, 0xd8, 0xa5, 0xa5, 0x22, 0xa3, 0x62,
	0xa3, 0xb0, 0xb6, 0x75, 0x6e, 0xe6, 0x79, 0x95, 0x34, 0x99, 0xa0, 0x19, 0x1f, 0x80, 0xa9, 0xbf,
	0x99, 0xef, 0x29, 0x0a, 0x23, 0x79, 0xbb, 0x8b, 0xd2, 0xdd, 0xc0, 0x8b, 0x2a, 0x69, 0x0e, 0x22,
	0xa2, 0xcc, 0xe9, 0xc7, 0xdf, 0xaf, 0x01, 0x00, 0x00, 0xff, 0xff, 0xa6, 0xb1, 0xa1, 0x9a, 0x82,
	0x01, 0x00, 0x00,
}