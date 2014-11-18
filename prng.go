package captcha
import "encoding/binary"
import "golang.org/x/crypto/salsa20/salsa"
import "sync/atomic"
import "sync"
import "crypto/rand"

type salsaPRNG struct {
	k       [32]byte
	counter uint64

	mutex    sync.Mutex
	buf      []byte
	buforig  []byte
}

func (p *salsaPRNG) Read(b []byte) (int, error) {
	var ctr [16]byte
	blocks := (uint64(len(b))+63)/64
	cv := atomic.AddUint64(&p.counter, blocks) - blocks
	binary.BigEndian.PutUint64(ctr[8:16], cv)
	salsa.XORKeyStream(b, b, &ctr, &p.k)
	return len(b), nil
}

func (p *salsaPRNG) SeedSystem() error {
	_, err := rand.Read(p.k[:])
	p.counter = 0
	return err
}

func (p *salsaPRNG) Int63() int64 {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if len(p.buf) < 8 {
		if p.buforig == nil {
			p.buforig = make([]byte, 64)
		}

		p.buf = p.buforig
		p.Read(p.buf)
	}

	v := binary.BigEndian.Uint64(p.buf[0:8])
	p.buf = p.buf[8:]
	return int64(v & 0x7FFFFFFFFFFFFFFF)
}

func (p *salsaPRNG) Seed(x int64) {
	panic("unimplemented")
}
