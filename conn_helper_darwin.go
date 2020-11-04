// +build darwin

package quic

import "syscall"

const (
	//nolint:stylecheck
	ip_recvtos   = 27
	msgTypeIPTOS = ip_recvtos
	// ReadBatch only returns a single packet on OSX, see https://godoc.org/golang.org/x/net/ipv4#PacketConn.ReadBatch.
	batchSize = 1
)

func setRECVTOS(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ip_recvtos, 1)
}
