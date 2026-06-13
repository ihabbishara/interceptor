package sensor

import "sort"

// Reassembler buffers RawEvent chunks per stream and reconstructs the
// ordered byte sequence for each. Chunks may arrive out of order or be
// delivered more than once; reassembly is by Seq and is idempotent.
type Reassembler struct {
	streams map[string]map[uint64][]byte // streamKey -> seq -> data
}

func NewReassembler() *Reassembler {
	return &Reassembler{streams: map[string]map[uint64][]byte{}}
}

// Add records one chunk. Duplicate (streamKey, seq) pairs are ignored.
func (r *Reassembler) Add(e RawEvent) {
	key := e.StreamKey()
	s, ok := r.streams[key]
	if !ok {
		s = map[uint64][]byte{}
		r.streams[key] = s
	}
	if _, dup := s[e.Seq]; dup {
		return
	}
	cp := make([]byte, len(e.Data))
	copy(cp, e.Data)
	s[e.Seq] = cp
}

// Bytes returns the ordered, concatenated payload for one stream.
func (r *Reassembler) Bytes(streamKey string) []byte {
	s := r.streams[streamKey]
	if len(s) == 0 {
		return nil
	}
	seqs := make([]uint64, 0, len(s))
	for seq := range s {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var out []byte
	for _, seq := range seqs {
		out = append(out, s[seq]...)
	}
	return out
}
