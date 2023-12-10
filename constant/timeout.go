package constant

import "time"

const (
	TCPKeepAliveInitial        = 10 * time.Minute
	TCPKeepAliveInterval       = 75 * time.Second
	TCPTimeout                 = 2 * time.Second
	ReadPayloadTimeout         = 300 * time.Millisecond
	DNSTimeout                 = 2 * time.Second
	QUICTimeout                = 30 * time.Second
	STUNTimeout                = 15 * time.Second
	UDPTimeout                 = 5 * time.Minute
	TCPIdleTimeout             = 10 * time.Minute
	DefaultURLTestInterval     = 3 * time.Minute
	DefaultURLTestIdleTimeout  = 30 * time.Minute
	DefaultStartTimeout        = 10 * time.Second
	DefaultStopTimeout         = 5 * time.Second
	DefaultStopFatalTimeout    = 10 * time.Second
	ClientIdleTimeout          = 3 * time.Minute
	StartTimeout               = 10 * time.Second
	StopTimeout                = 5 * time.Second
	FatalStopTimeout           = 10 * time.Second
	FakeIPMetadataSaveInterval = 10 * time.Second
)
