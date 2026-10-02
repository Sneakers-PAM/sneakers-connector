// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// fakeLDAP is an in-memory ldapClient: Bind succeeds unless bindErr is set,
// Search answers from entry (or fails with searchErr), and every write is
// recorded so a test can prove whether the target was changed.
type fakeLDAP struct {
	bindErr   error
	searchErr error
	entry     *ldap.Entry

	searches       []*ldap.SearchRequest
	modifies       []*ldap.ModifyRequest
	passwordModify int
}

func (f *fakeLDAP) Bind(string, string) error { return f.bindErr }
func (f *fakeLDAP) SetTimeout(time.Duration)  {}
func (f *fakeLDAP) Close() error              { return nil }

func (f *fakeLDAP) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.searches = append(f.searches, req)
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	if f.entry == nil {
		return &ldap.SearchResult{}, nil
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{f.entry}}, nil
}

func (f *fakeLDAP) Modify(req *ldap.ModifyRequest) error {
	f.modifies = append(f.modifies, req)
	return nil
}

func (f *fakeLDAP) PasswordModify(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	f.passwordModify++
	return &ldap.PasswordModifyResult{}, nil
}

func fakeAdapterFor(f *fakeLDAP) *ldapAdapter {
	return &ldapAdapter{dial: func(Conn) (ldapClient, error) { return f, nil }}
}

// Fake domain SIDs standing in for two separate domains.
const (
	domainA = "S-1-5-21-1111111111-2222222222-3333333333"
	domainB = "S-1-5-21-4000000004-500000005-600000006"
)

// sidBytes encodes a SID string in the binary objectSid form AD returns:
// revision, sub-authority count, 48-bit big-endian authority, then each
// sub-authority as a little-endian uint32.
func sidBytes(t *testing.T, sid string) string {
	t.Helper()
	parts := strings.Split(sid, "-")
	if len(parts) < 4 || parts[0] != "S" {
		t.Fatalf("bad test SID %q", sid)
	}
	rev, _ := strconv.Atoi(parts[1])
	auth, _ := strconv.ParseUint(parts[2], 10, 48)
	subs := parts[3:]
	b := make([]byte, 8+4*len(subs))
	b[0] = byte(rev)
	b[1] = byte(len(subs))
	for i := 0; i < 6; i++ {
		b[2+i] = byte(auth >> (8 * (5 - i)))
	}
	for i, s := range subs {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			t.Fatalf("bad test SID %q: %v", sid, err)
		}
		binary.LittleEndian.PutUint32(b[8+4*i:], uint32(v))
	}
	return string(b)
}

func adEntry(t *testing.T, sid string, adminCount ...string) *ldap.Entry {
	t.Helper()
	attrs := map[string][]string{"objectSid": {sidBytes(t, sid)}}
	if len(adminCount) > 0 {
		attrs["adminCount"] = adminCount
	}
	return ldap.NewEntry("CN=svc,CN=Users,DC=ad,DC=example,DC=org", attrs)
}

var adConn = Conn{Host: "dc1.ad.example.org", Port: 636, UseTLS: true, Domain: "ad.example.org"}

func rotateAgainst(f *fakeLDAP, c Conn, username string) (Result, string) {
	return fakeAdapterFor(f).Rotate(context.Background(), c, Cred{Username: username, Password: "old"}, "new")
}

func TestRotateADBuiltinAdministratorIsRefusedWithoutChange(t *testing.T) {
	for _, domain := range []string{domainA, domainB} {
		t.Run(domain, func(t *testing.T) {
			f := &fakeLDAP{entry: adEntry(t, domain+"-500")}

			result, detail := rotateAgainst(f, adConn, "renamed-admin")

			if result != Refused {
				t.Fatalf("Rotate result = %v, want %v", result, Refused)
			}
			if detail != BuiltinAdministratorReason {
				t.Fatalf("Rotate detail = %q, want %q", detail, BuiltinAdministratorReason)
			}
			if len(f.modifies) != 0 || f.passwordModify != 0 {
				t.Fatalf("the built-in Administrator was changed: %d modifies", len(f.modifies))
			}
		})
	}
}

func TestRotateADOtherAccountsUseSelfServiceChange(t *testing.T) {
	cases := map[string]func(t *testing.T) *ldap.Entry{
		"normal account":            func(t *testing.T) *ldap.Entry { return adEntry(t, domainA+"-1105") },
		"adminCount 1, not RID 500": func(t *testing.T) *ldap.Entry { return adEntry(t, domainB+"-1500", "1") },
		"adminCount 0":              func(t *testing.T) *ldap.Entry { return adEntry(t, domainA+"-2500", "0") },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			entry := mk(t)
			f := &fakeLDAP{entry: entry}

			result, detail := rotateAgainst(f, adConn, "svc")

			if result != Valid {
				t.Fatalf("Rotate = %v (%q), want %v", result, detail, Valid)
			}
			if len(f.modifies) != 1 || f.modifies[0].DN != entry.DN {
				t.Fatalf("want one self-service unicodePwd change against %s, got %+v", entry.DN, f.modifies)
			}
			if len(f.modifies[0].Changes) != 2 || f.modifies[0].Changes[0].Operation != ldap.DeleteAttribute {
				t.Fatalf("want the delete+add self-service form, got %+v", f.modifies[0].Changes)
			}
			if len(f.searches) != 1 || !hasAttr(f.searches[0], "objectSid") {
				t.Fatalf("the account lookup must read objectSid: %+v", f.searches)
			}
		})
	}
}

func TestRotateADDNUsernameReadsObjectSidOnTheEntry(t *testing.T) {
	const dn = "CN=Administrator,CN=Users,DC=ad,DC=example,DC=org"
	f := &fakeLDAP{entry: ldap.NewEntry(dn, map[string][]string{"objectSid": {sidBytes(t, domainA+"-500")}})}

	result, _ := rotateAgainst(f, Conn{Host: "dc1", Port: 636, UseTLS: true}, dn)

	if result != Refused {
		t.Fatalf("Rotate result = %v, want %v", result, Refused)
	}
	if len(f.searches) != 1 || f.searches[0].BaseDN != dn || f.searches[0].Scope != ldap.ScopeBaseObject {
		t.Fatalf("want one base-object read of %s, got %+v", dn, f.searches)
	}
	if len(f.modifies) != 0 {
		t.Fatal("the built-in Administrator was changed")
	}
}

func TestRotateADUnreadableObjectSidMakesNoChange(t *testing.T) {
	cases := map[string]*fakeLDAP{
		"lookup fails":      {searchErr: errors.New("connection reset")},
		"objectSid missing": {entry: ldap.NewEntry("CN=svc,DC=ad,DC=example,DC=org", map[string][]string{"adminCount": {"1"}})},
		"objectSid garbage": {entry: ldap.NewEntry("CN=svc,DC=ad,DC=example,DC=org", map[string][]string{"objectSid": {"\x01\x05"}})},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			result, _ := rotateAgainst(f, adConn, "svc")
			if result != Unreachable {
				t.Fatalf("Rotate result = %v, want %v", result, Unreachable)
			}
			if len(f.modifies) != 0 {
				t.Fatal("the password was changed without confirming the account is not the built-in Administrator")
			}
		})
	}
}

func TestValidateAccountReportsFlags(t *testing.T) {
	cases := []struct {
		name string
		f    func(t *testing.T) *fakeLDAP
		conn Conn
		want Result
		flag AccountFlags
	}{
		{"built-in Administrator", func(t *testing.T) *fakeLDAP { return &fakeLDAP{entry: adEntry(t, domainA+"-500", "1")} },
			adConn, Valid, AccountFlags{Known: true, BuiltinAdministrator: true, AdminCount: true}},
		{"adminCount 1 only", func(t *testing.T) *fakeLDAP { return &fakeLDAP{entry: adEntry(t, domainB+"-1105", "1")} },
			adConn, Valid, AccountFlags{Known: true, AdminCount: true}},
		{"normal account", func(t *testing.T) *fakeLDAP { return &fakeLDAP{entry: adEntry(t, domainB+"-1105")} },
			adConn, Valid, AccountFlags{Known: true}},
		{"lookup fails", func(*testing.T) *fakeLDAP { return &fakeLDAP{searchErr: errors.New("boom")} },
			adConn, Valid, AccountFlags{}},
		{"bind rejected", func(*testing.T) *fakeLDAP {
			return &fakeLDAP{bindErr: ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad"))}
		}, adConn, Invalid, AccountFlags{}},
		{"lldap target", func(t *testing.T) *fakeLDAP { return &fakeLDAP{entry: adEntry(t, domainA+"-500")} },
			Conn{Host: "lldap", Port: 3890, Domain: "dc=ad,dc=example,dc=org"}, Valid, AccountFlags{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.f(t)
			result, _, flags := fakeAdapterFor(f).ValidateAccount(context.Background(), tc.conn, Cred{Username: "svc", Password: "pw"})
			if result != tc.want || flags != tc.flag {
				t.Fatalf("ValidateAccount = (%v, %+v), want (%v, %+v)", result, flags, tc.want, tc.flag)
			}
			if len(f.modifies) != 0 || f.passwordModify != 0 {
				t.Fatal("a heartbeat must never change the account")
			}
		})
	}
}

func TestRIDOf(t *testing.T) {
	cases := []struct {
		sid  string
		want uint32
	}{
		{domainA + "-500", 500},
		{domainB + "-500", 500},
		{domainA + "-1105", 1105},
		{"S-1-5-32-544", 544},
	}
	for _, tc := range cases {
		got, err := ridOf([]byte(sidBytes(t, tc.sid)))
		if err != nil || got != tc.want {
			t.Fatalf("ridOf(%s) = (%d, %v), want %d", tc.sid, got, err, tc.want)
		}
	}
	for name, raw := range map[string][]byte{
		"empty":           nil,
		"header only":     {1, 1, 0, 0, 0, 0, 0, 5},
		"count too large": append([]byte{1, 4, 0, 0, 0, 0, 0, 5}, make([]byte, 12)...),
		"no subauthority": {1, 0, 0, 0, 0, 0, 0, 5},
		"bad revision":    append([]byte{2, 1, 0, 0, 0, 0, 0, 5}, 0xf4, 0x01, 0, 0),
	} {
		if _, err := ridOf(raw); err == nil {
			t.Fatalf("ridOf(%s) accepted a malformed SID", name)
		}
	}
}

func TestLDAPAdapterReportsAccountFlags(t *testing.T) {
	a, ok := Get("ldaps")
	if !ok {
		t.Fatal("ldaps adapter not registered")
	}
	if _, ok := a.(AccountValidator); !ok {
		t.Fatal("the LDAP adapter must report account flags on heartbeat")
	}
}

func hasAttr(req *ldap.SearchRequest, name string) bool {
	for _, a := range req.Attributes {
		if a == name {
			return true
		}
	}
	return false
}
