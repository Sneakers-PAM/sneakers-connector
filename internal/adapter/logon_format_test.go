// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"testing"
)

// The AD type's logon format picks the name the LDAP adapter binds as:
// NETBIOS\username or the UPN. Unset keeps today's choice.

func TestBindIdentifierFollowsTheLogonFormat(t *testing.T) {
	for name, tc := range map[string]struct {
		conn Conn
		want string
	}{
		"unset, AD domain":           {Conn{Domain: "ad.example.org"}, "svc@ad.example.org"},
		"unset, no domain":           {Conn{}, "svc"},
		"unset, lldap":               {Conn{Domain: "dc=example,dc=org"}, "uid=svc,ou=people,dc=example,dc=org"},
		"netbios":                    {Conn{Domain: "ad.example.org", Logon: LogonFormat{Format: LogonNetbios, Netbios: "EXAMPLE"}}, `EXAMPLE\svc`},
		"netbios without the domain": {Conn{Domain: "ad.example.org", Logon: LogonFormat{Format: LogonNetbios}}, "svc@ad.example.org"},
		"upn with a suffix":          {Conn{Domain: "ad.example.org", Logon: LogonFormat{Format: LogonUPN, UPNSuffix: "example.org"}}, "svc@example.org"},
		"upn without a suffix":       {Conn{Domain: "ad.example.org", Logon: LogonFormat{Format: LogonUPN, Netbios: "EXAMPLE"}}, "svc@ad.example.org"},
		"upn, suffix, no domain":     {Conn{Logon: LogonFormat{Format: LogonUPN, UPNSuffix: "example.org"}}, "svc@example.org"},
		"lldap ignores the format":   {Conn{Domain: "dc=example,dc=org", Logon: LogonFormat{Format: LogonNetbios, Netbios: "EXAMPLE"}}, "uid=svc,ou=people,dc=example,dc=org"},
		"unknown format":             {Conn{Domain: "ad.example.org", Logon: LogonFormat{Format: "other", Netbios: "EXAMPLE"}}, "svc@ad.example.org"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := bindIdentifier(tc.conn, "svc"); got != tc.want {
				t.Fatalf("bindIdentifier = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLDAPBindsAndRotatesWithTheLogonFormat(t *testing.T) {
	conn := Conn{Host: "dc01.example.org", Port: 636, UseTLS: true, Domain: "ad.example.org",
		Logon: LogonFormat{Format: LogonNetbios, Netbios: "EXAMPLE"}}
	cred := Cred{Username: "svc", Password: "Curr3nt!Pass"}

	f := &fakeLDAP{entry: adEntry(t, domainA+"-1105")}
	if res, detail := fakeAdapterFor(f).Validate(context.Background(), conn, cred); res != Valid {
		t.Fatalf("Validate = %v %q", res, detail)
	}
	if len(f.binds) != 1 || f.binds[0] != `EXAMPLE\svc` {
		t.Fatalf("heartbeat bound as %q, want EXAMPLE\\svc", f.binds)
	}
	if got := f.searches[0].Filter; got != "(sAMAccountName=svc)" {
		t.Fatalf("account lookup filter = %q, want the bare account name", got)
	}

	r := &fakeLDAP{entry: adEntry(t, domainA+"-1105")}
	if res, detail := fakeAdapterFor(r).Rotate(context.Background(), conn, cred, "N3w!Passw0rd-x"); res != Valid {
		t.Fatalf("Rotate = %v %q", res, detail)
	}
	if len(r.binds) == 0 || r.binds[0] != `EXAMPLE\svc` {
		t.Fatalf("rotation bound as %q, want EXAMPLE\\svc", r.binds)
	}
}
