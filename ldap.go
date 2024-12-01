package restserver

import (
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/minio/sha256-simd"
)

type Ldap struct {
	// Addr is the LDAP server URL.
	// Passed to ldap.DialURL.
	//
	// The following schemas are supported: ldap://, ldaps://, ldapi://, and cldap://.
	Addr string

	// Uid is the LDAP attribute that maps to the username that users use to sign in.
	Uid string

	// Base where to search for users.
	Base string

	// Mutex for cache.
	mtx sync.Mutex
	// A cache for verified users to prevent repeatedly verifying the same auth credentials.
	cache map[string]cacheEntry
}

func NewLdap(addr, uid, base string) *Ldap {
	return &Ldap{
		Addr:  addr,
		Uid:   uid,
		Base:  base,
		mtx:   sync.Mutex{},
		cache: make(map[string]cacheEntry),
	}
}

func (l *Ldap) validateRemote(user, password string) (bool, error) {
	// Connect to LDAP server
	conn, err := ldap.DialURL(l.Addr)
	if err != nil {
		return false, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer func(conn *ldap.Conn) {
		_ = conn.Close()
	}(conn)

	// Search for user
	searchReq := ldap.NewSearchRequest(
		l.Base,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(%s=%s)", l.Uid, user),
		[]string{"dn"},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil {
		return false, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(sr.Entries) != 1 {
		return false, fmt.Errorf("expected exactly one LDAP entry for '%s', got %d", user, len(sr.Entries))
	}

	userDN := sr.Entries[0].DN

	// Bind to user
	err = conn.Bind(userDN, password)
	return err == nil, nil
}

func (l *Ldap) Validate(user, password string) (bool, error) {
	hash := sha256.New()
	// hash.Write can never fail
	_, _ = hash.Write([]byte(user))
	_, _ = hash.Write([]byte(":"))
	_, _ = hash.Write([]byte(password))

	l.mtx.Lock()
	entry, cacheExists := l.cache[user]
	l.mtx.Unlock()

	if cacheExists && subtle.ConstantTimeCompare(entry.verifier, hash.Sum(nil)) == 1 {
		l.mtx.Lock()
		// extend cache entry
		l.cache[user] = cacheEntry{
			verifier: entry.verifier,
			expiry:   time.Now().Add(PasswordCacheDuration),
		}
		l.mtx.Unlock()
		return true, nil
	}

	isValid, err := l.validateRemote(user, password)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}

	l.mtx.Lock()
	l.cache[user] = cacheEntry{
		verifier: hash.Sum(nil),
		expiry:   time.Now().Add(PasswordCacheDuration),
	}
	l.mtx.Unlock()

	return true, nil
}
