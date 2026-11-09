package keymem

import "github.com/jimichi-org/jimichi/crypto/secmem"

type streamMatcher struct {
	pattern *secmem.Buffer
	prefix  [32]int
	length  int
	state   int
	count   uint64
}

func newStreamMatcher(pattern *secmem.Buffer) (streamMatcher, error) {
	if pattern == nil || pattern.Len() == 0 || pattern.Len() > 32 {
		return streamMatcher{}, errParseInvalid
	}
	m := streamMatcher{pattern: pattern, length: pattern.Len()}
	p := pattern.Bytes()
	for i, j := 1, 0; i < len(p); i++ {
		for j > 0 && p[i] != p[j] {
			j = m.prefix[j-1]
		}
		if p[i] == p[j] {
			j++
		}
		m.prefix[i] = j
	}
	return m, nil
}

func (m *streamMatcher) reset() {
	m.state = 0
}

func (m *streamMatcher) consume(data []byte, offset, wanted uint64) bool {
	p := m.pattern.Bytes()
	found := false
	for i, b := range data {
		for m.state > 0 && b != p[m.state] {
			m.state = m.prefix[m.state-1]
		}
		if b == p[m.state] {
			m.state++
		}
		if m.state == m.length {
			m.count++
			if offset+uint64(i)+1 >= uint64(m.length) && offset+uint64(i)+1-uint64(m.length) == wanted {
				found = true
			}
			m.state = m.prefix[m.state-1]
		}
	}
	return found
}
