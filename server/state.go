package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

type Phone struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PublicKey string    `json:"publicKey"`
	Address   string    `json:"address"`
	CreatedAt time.Time `json:"createdAt"`
	Endpoint  string    `json:"endpoint,omitempty"`
}

type stateData struct {
	ServerKey  string  `json:"serverKey"`
	Phones     []Phone `json:"phones"`
	AdminHash  string  `json:"adminHash,omitempty"`
	SessionKey string  `json:"sessionKey"`
	LastAddr   string  `json:"lastAddr,omitempty"`
}

type Store struct {
	mu   sync.Mutex
	path string
	d    stateData
}

func openStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json")}
	b, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s.d); err != nil {
			return nil, fmt.Errorf("%s unreadable: %w", s.path, err)
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}

	changed := false
	if s.d.ServerKey == "" {
		priv, _, err := newKeyPair()
		if err != nil {
			return nil, err
		}
		s.d.ServerKey = priv
		changed = true
	}
	if k, err := base64.StdEncoding.DecodeString(s.d.SessionKey); err != nil || len(k) != 32 {
		s.d.SessionKey = randomB64(32)
		changed = true
	}
	if _, err := b64ToHex(s.d.ServerKey); err != nil {
		return nil, fmt.Errorf("%s: invalid Bridge key", s.path)
	}
	if changed {
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func (s *Store) ServerKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.ServerKey
}

func (s *Store) SessionKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := base64.StdEncoding.DecodeString(s.d.SessionKey)
	return b
}

func (s *Store) AdminHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.AdminHash
}

func (s *Store) SetAdminHash(h string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.AdminHash = h
	s.d.SessionKey = randomB64(32)
	return s.saveLocked()
}

func (s *Store) RevokeSessions() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.SessionKey = randomB64(32)
	return s.saveLocked()
}

func (s *Store) Phones() []Phone {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Phone(nil), s.d.Phones...)
}

func (s *Store) AddPhone(name, publicKey string, net netip.Prefix, endpoint string) (Phone, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	used := map[string]bool{}
	for _, p := range s.d.Phones {
		used[p.Address] = true
	}
	first := net.Addr().Next().Next()
	var pool []netip.Addr
	for a := first; net.Contains(a) && net.Contains(a.Next()); a = a.Next() {
		pool = append(pool, a)
	}
	start := 0
	if last, err := netip.ParseAddr(s.d.LastAddr); err == nil {
		for i, a := range pool {
			if a == last {
				start = i + 1
				break
			}
		}
	}
	var addr netip.Addr
	for i := range pool {
		a := pool[(start+i)%len(pool)]
		if !used[a.String()] {
			addr = a
			break
		}
	}
	if !addr.IsValid() {
		return Phone{}, errNoFreeAddress
	}
	p := Phone{
		ID:        randomID(),
		Name:      name,
		PublicKey: publicKey,
		Address:   addr.String(),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		Endpoint:  endpoint,
	}
	s.d.Phones = append(s.d.Phones, p)
	s.d.LastAddr = p.Address
	return p, s.saveLocked()
}

func (s *Store) ReplaceKey(id, publicKey, endpoint string) (Phone, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.d.Phones {
		if s.d.Phones[i].ID == id {
			s.d.Phones[i].PublicKey = publicKey
			s.d.Phones[i].Endpoint = endpoint
			return s.d.Phones[i], s.saveLocked()
		}
	}
	return Phone{}, errNotFound
}

func (s *Store) DeletePhone(id string) (Phone, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.d.Phones {
		if p.ID == id {
			s.d.Phones = append(s.d.Phones[:i], s.d.Phones[i+1:]...)
			return p, s.saveLocked()
		}
	}
	return Phone{}, errNotFound
}

var (
	errNotFound      = errors.New("not found")
	errNoFreeAddress = errors.New("no free address left for a new phone")
)

func newKeyPair() (priv, pub string, err error) {
	var k [32]byte
	if _, err = rand.Read(k[:]); err != nil {
		return
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p), nil
}

func publicKeyOf(priv string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(k) != 32 {
		return "", errors.New("invalid private key")
	}
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}

func randomB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func randomID() string {
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
