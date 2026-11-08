// Package link encrypts fixed-size cells between neighbouring nodes.
package link

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/noise"
	"github.com/jimichi-org/jimichi/wire"
)

var ErrUnconfirmed = errors.New("link: initiator transport key unconfirmed")

type Conn struct {
	raw          net.Conn
	send, recv   *noise.CipherState
	frame        int
	wmu          sync.Mutex
	writeTimeout time.Duration
	rmu          sync.Mutex
	buf          []byte
	stateMu      sync.Mutex
	terminal     error
	confirmed    bool
	cleanup      sync.Once
}

func handshakeInfo(p jcrypto.CryptoProvider) (jcrypto.HandshakeInfo, error) {
	if p == nil {
		return jcrypto.HandshakeInfo{}, ErrHandshake
	}
	info := p.HandshakeInfo()
	if !info.Valid() || info.KeySize != p.KeySize() {
		return jcrypto.HandshakeInfo{}, ErrHandshake
	}
	return info, nil
}

func InitiatorHandshakeSize(p jcrypto.CryptoProvider) (int, error) {
	_, err := handshakeInfo(p)
	return handshakeSize, err
}
func ResponderHandshakeSize(p jcrypto.CryptoProvider) (int, error) { return InitiatorHandshakeSize(p) }
func FrameSize(p jcrypto.CryptoProvider) (int, error) {
	info, err := handshakeInfo(p)
	if err != nil {
		return 0, err
	}
	return wire.CellSize + info.TagSize, nil
}

func (c *Conn) SetWriteTimeout(d time.Duration) {
	c.wmu.Lock()
	c.writeTimeout = d
	c.wmu.Unlock()
}
func (c *Conn) status() (error, bool) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.terminal, c.confirmed
}
func (c *Conn) fail(err error) error {
	c.stateMu.Lock()
	firstFailure := c.terminal == nil
	if firstFailure {
		c.terminal = err
	}
	first := c.terminal
	c.stateMu.Unlock()
	if firstFailure {
		_ = c.raw.Close()
	}
	return first
}
func (c *Conn) WriteCell(cell *wire.Cell) error {
	c.wmu.Lock()
	err := c.writeCell(cell)
	c.wmu.Unlock()
	if err != nil && !errors.Is(err, ErrUnconfirmed) {
		c.discard()
	}
	return err
}
func (c *Conn) writeCell(cell *wire.Cell) error {
	if err, confirmed := c.status(); err != nil {
		return err
	} else if !confirmed {
		return ErrUnconfirmed
	}
	frame, err := c.send.Encrypt(nil, cell[:])
	if err != nil {
		return c.fail(err)
	}
	if c.writeTimeout > 0 {
		if err := c.raw.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
			return c.fail(err)
		}
	}
	if err := writeFull(c.raw, frame); err != nil {
		return c.fail(err)
	}
	return nil
}

// authenticated padding confirms the initiator but never reaches a circuit
func (c *Conn) ReadCell(cell *wire.Cell) error {
	for {
		if err := c.readFrame(cell); err != nil {
			return err
		}
		if !cell.IsPadding() {
			return nil
		}
	}
}
func (c *Conn) readFrame(cell *wire.Cell) error {
	c.rmu.Lock()
	err := c.readFrameLocked(cell)
	c.rmu.Unlock()
	if err != nil {
		c.discard()
	}
	return err
}
func (c *Conn) readFrameLocked(cell *wire.Cell) error {
	if err, _ := c.status(); err != nil {
		return err
	}
	if _, err := io.ReadFull(c.raw, c.buf); err != nil {
		return c.fail(err)
	}
	plain, err := c.recv.Decrypt(nil, c.buf)
	if err != nil {
		return c.fail(fmt.Errorf("%w: %w", ErrFrame, err))
	}
	defer secmem.Zero(plain)
	if len(plain) != wire.CellSize {
		return c.fail(ErrFrame)
	}
	c.stateMu.Lock()
	c.confirmed = true
	c.stateMu.Unlock()
	copy(cell[:], plain)
	return nil
}
func (c *Conn) FrameSize() int { return c.frame }
func (c *Conn) Err() error     { err, _ := c.status(); return err }
func (c *Conn) Close() error {
	c.fail(net.ErrClosed)
	c.discard()
	return nil
}
func (c *Conn) discard() {
	c.cleanup.Do(func() {
		c.wmu.Lock()
		c.send.Destroy()
		c.wmu.Unlock()
		c.rmu.Lock()
		c.recv.Destroy()
		c.rmu.Unlock()
	})
}
