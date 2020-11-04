// +build !windows

package quic

import (
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ecnMask       uint8 = 0x3
	oobBufferSize       = 128
)

// Contrary to what the naming suggests, the ipv{4,6}.Message is not dependent on the IP version.
// They're both just aliases for x/net/internal/socket.Message.
// This means we can use this struct to read from a socket that receives both IPv4 and IPv6 messages.
var _ ipv4.Message = ipv6.Message{}

type ecnConn struct {
	net.PacketConn
	batchConn *ipv4.PacketConn

	readPos  uint8
	messages []ipv4.Message
	buffers  [batchSize]*packetBuffer
}

var _ connection = &ecnConn{}

func newConn(c ECNCapablePacketConn) (*ecnConn, error) {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6 connection.
	// Try enabling receiving of ECN for both IP versions.
	// We expect at least one of those syscalls to succeed.
	var errIPv4, errIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errIPv4 = setRECVTOS(fd)
	}); err != nil {
		return nil, err
	}
	if err := rawConn.Control(func(fd uintptr) {
		errIPv6 = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_RECVTCLASS, 1)
	}); err != nil {
		return nil, err
	}
	switch {
	case errIPv4 == nil && errIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4 and IPv6.")
	case errIPv4 == nil && errIPv6 != nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4.")
	case errIPv4 != nil && errIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv6.")
	case errIPv4 != nil && errIPv6 != nil:
		return nil, errors.New("activating ECN failed for both IPv4 and IPv6")
	}
	ecnConn := &ecnConn{
		PacketConn: c,
		batchConn:  ipv4.NewPacketConn(c),
		messages:   make([]ipv4.Message, batchSize),
		readPos:    batchSize,
	}
	for i := 0; i < batchSize; i++ {
		ecnConn.messages[i].OOB = make([]byte, oobBufferSize)
	}
	return ecnConn, nil
}

func (c *ecnConn) ReadPacket() (*receivedPacket, error) {
	if len(c.messages) == int(c.readPos) { // all messages read. Read the next batch of messages.
		c.messages = c.messages[:batchSize]
		// replace buffers data buffers up to the packet that has been consumed during the last ReadBatch call
		for i := uint8(0); i < c.readPos; i++ {
			buffer := getPacketBuffer()
			buffer.Data = buffer.Data[:protocol.MaxReceivePacketSize]
			c.buffers[i] = buffer
			c.messages[i].Buffers = [][]byte{c.buffers[i].Data}
		}
		c.readPos = 0

		n, err := c.batchConn.ReadBatch(c.messages, 0)
		if n == 0 || err != nil {
			return nil, err
		}
		c.messages = c.messages[:n]
	}

	msg := c.messages[c.readPos]
	ctrlMsgs, err := syscall.ParseSocketControlMessage(msg.OOB[:msg.NN])
	if err != nil {
		return nil, err
	}
	var ecn protocol.ECN
	for _, ctrlMsg := range ctrlMsgs {
		if ctrlMsg.Header.Level == syscall.IPPROTO_IP && ctrlMsg.Header.Type == msgTypeIPTOS {
			ecn = protocol.ECN(ctrlMsg.Data[0] & ecnMask)
			break
		}
		if ctrlMsg.Header.Level == syscall.IPPROTO_IPV6 && ctrlMsg.Header.Type == syscall.IPV6_TCLASS {
			ecn = protocol.ECN(ctrlMsg.Data[0] & ecnMask)
			break
		}
	}

	p := &receivedPacket{
		remoteAddr: msg.Addr,
		rcvTime:    time.Now(),
		data:       msg.Buffers[0][:msg.N],
		ecn:        ecn,
		buffer:     c.buffers[c.readPos],
	}
	c.readPos++
	return p, nil
}
