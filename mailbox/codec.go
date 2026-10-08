// Package mailbox is the store at the exit: queues of end-to-end records kept
// in RAM, filled by puts and emptied by fetches, one request and one reply of
// a constant size per data cell.
package mailbox

import (
	"encoding/binary"
	"errors"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

const (
	Version     = 0x01
	IDSize      = 16
	CapSize     = 16
	RecordSize  = 392
	RequestSize = 1 + 2 + CapSize + IDSize + RecordSize
	ReplySize   = 1 + 2 + 1 + RecordSize
)

const (
	StatusBad    byte = 0x80
	StatusRecord byte = 0x04
	PutMask      byte = 0x03
	PutNone      byte = 0x00
	PutStored    byte = 0x01
	PutFull      byte = 0x02
	PutRefused   byte = 0x03

	statusReserved byte = 0x78
)

var (
	ErrRequest = errors.New("mailbox: bad request")
	ErrReply   = errors.New("mailbox: bad reply")
	ErrCap     = errors.New("mailbox: bad fetch capability")
	ErrLimits  = errors.New("mailbox: bad limits")
)

// the first 16 bytes of the hash of the transcript of F: whoever holds F
// fetches from the queue, whoever holds the identifier puts into it
func QueueID(p jcrypto.CryptoProvider, fetchCap []byte) ([IDSize]byte, error) {
	var id [IDSize]byte
	if len(fetchCap) != CapSize {
		return id, ErrCap
	}
	ctx, err := jcrypto.NewContext(p, "mailbox/queue", fetchCap)
	if err != nil {
		return id, err
	}
	copy(id[:], ctx.Sum())
	return id, nil
}

// a zero Fetch asks for no fetch and a zero Put for no put
type Request struct {
	Tag    uint16
	Fetch  [CapSize]byte
	Put    [IDSize]byte
	Record [RecordSize]byte
}

func (r Request) Fetches() bool { return r.Fetch != [CapSize]byte{} }

func (r Request) Puts() bool { return r.Put != [IDSize]byte{} }

func ParseRequest(b []byte) (Request, error) {
	var r Request
	if len(b) != RequestSize || b[0] != Version {
		return r, ErrRequest
	}
	r.Tag = binary.BigEndian.Uint16(b[1:3])
	copy(r.Fetch[:], b[3:3+CapSize])
	copy(r.Put[:], b[3+CapSize:3+CapSize+IDSize])
	copy(r.Record[:], b[3+CapSize+IDSize:])
	return r, nil
}

func (r Request) Bytes() []byte {
	b := make([]byte, RequestSize)
	b[0] = Version
	binary.BigEndian.PutUint16(b[1:3], r.Tag)
	copy(b[3:], r.Fetch[:])
	copy(b[3+CapSize:], r.Put[:])
	copy(b[3+CapSize+IDSize:], r.Record[:])
	return b
}

type Reply struct {
	Tag    uint16
	Status byte
	Record [RecordSize]byte
}

func (r Reply) Bytes() []byte {
	b := make([]byte, ReplySize)
	b[0] = Version
	binary.BigEndian.PutUint16(b[1:3], r.Tag)
	b[3] = r.Status
	copy(b[4:], r.Record[:])
	return b
}

// the checks a reply passes on its own; Answers adds the ones that need the
// request it answers
func ParseReply(b []byte) (Reply, error) {
	var r Reply
	if len(b) != ReplySize || b[0] != Version {
		return r, ErrReply
	}
	r.Tag = binary.BigEndian.Uint16(b[1:3])
	r.Status = b[3]
	copy(r.Record[:], b[4:])
	switch {
	case r.Status&statusReserved != 0,
		r.Status&StatusBad != 0 && r.Status != StatusBad,
		r.Status&StatusRecord == 0 && r.Record != [RecordSize]byte{}:
		return Reply{}, ErrReply
	}
	return r, nil
}

// a client sends only well-formed requests bound to one queue each way, so
// for it a refusal of the whole request is as bad as a wrong tag
func (r Reply) Answers(req *Request) error {
	put := r.Status & PutMask
	switch {
	case r.Tag != req.Tag,
		r.Status&StatusBad != 0,
		req.Puts() != (put != PutNone),
		r.Status&StatusRecord != 0 && !req.Fetches():
		return ErrReply
	}
	return nil
}

func badReply(payload []byte) []byte {
	r := Reply{Status: StatusBad}
	if len(payload) >= 3 {
		r.Tag = binary.BigEndian.Uint16(payload[1:3])
	}
	return r.Bytes()
}
