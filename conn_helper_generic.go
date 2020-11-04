// +build !darwin,!windows

package quic

import "syscall"

const (
	msgTypeIPTOS = syscall.IP_TOS
	batchSize    = 10 // needs to smaller than MaxUint8 (otherwise the type of ecnConn.readPos has to be changed)
)

func setRECVTOS(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVTOS, 1)
}
