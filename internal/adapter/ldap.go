// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// dialTimeout bounds how long the LDAP adapter waits for the TCP connect
// (and TLS handshake, when Conn.UseTLS is set) before treating the target
// as Unreachable.
const dialTimeout = 5 * time.Second

// ldapClient is the part of *ldap.Conn the adapter uses, so tests can drive
// the adapter against an in-memory directory.
type ldapClient interface {
	Bind(username, password string) error
	SetTimeout(timeout time.Duration)
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Modify(req *ldap.ModifyRequest) error
	PasswordModify(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
	Close() error
}

// ldapAdapter validates a credential by binding to an LDAP/LDAPS target as
// the account itself (no separate service account is used). It handles
// both AD-style LDAPS and lldap-style plain LDAP.
type ldapAdapter struct {
	dial func(c Conn) (ldapClient, error)
}

func init() {
	a := &ldapAdapter{dial: func(c Conn) (ldapClient, error) {
		conn, err := dialLDAP(c)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}}
	Register("ldap", a)
	Register("ldaps", a)
}

// Validate dials the target described by c and attempts to bind as cred.
//
// The bind identifier is best-effort, chosen from Conn.Domain (see
// bindIdentifier):
//   - empty Domain: bind with the raw username as-is (for targets that
//     accept a bare name, or when the caller already passes a full DN as
//     Username).
//   - Domain looks like a DN (contains "="), e.g. "dc=example,dc=org":
//     build an lldap-style DN "uid=<username>,ou=people,<domain>". lldap
//     requires a full bind DN over the LDAP protocol (a bare username or a
//     UPN both fail with "Naming Violation", verified against
//     lldap), and its default schema keeps accounts under
//     ou=people with a uid attribute.
//   - any other non-empty Domain, e.g. "corp.example.org": bind as the UPN
//     "username@domain", the form Active Directory expects.
//
// Outside the lldap case, the secret's AD logon format (Conn.Logon) comes
// first: NETBIOS binds as "NETBIOS\username", and UPN as
// "username@<UPN suffix>" (or "username@domain" without a suffix).
func (a *ldapAdapter) Validate(ctx context.Context, c Conn, cred Cred) (Result, string) {
	result, detail, _ := a.ValidateAccount(ctx, c, cred)
	return result, detail
}

// ValidateAccount is Validate that also reports AccountFlags. After a
// successful bind to an AD target it looks the account up exactly as Rotate
// does. A failed lookup leaves the heartbeat result alone and reports the
// flags as unknown.
func (a *ldapAdapter) ValidateAccount(ctx context.Context, c Conn, cred Cred) (Result, string, AccountFlags) {
	scheme := "ldap"
	if c.UseTLS {
		scheme = "ldaps"
	}
	conn, err := a.dial(c)
	if err != nil {
		return Unreachable, fmt.Sprintf("dial %s://%s:%d: %v", scheme, c.Host, c.Port, err), AccountFlags{}
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(dialTimeout)
	}
	conn.SetTimeout(time.Until(deadline))

	bindID := bindIdentifier(c, cred.Username)
	if err := conn.Bind(bindID, cred.Password); err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			return Invalid, "invalid credentials", AccountFlags{}
		}
		return Unreachable, fmt.Sprintf("bind %s: %v", bindID, err), AccountFlags{}
	}
	if strings.Contains(c.Domain, "=") {
		return Valid, "", AccountFlags{}
	}
	_, flags, err := resolveADAccount(conn, c, cred.Username)
	if err != nil {
		return Valid, "", AccountFlags{}
	}
	return Valid, "", flags
}

// bindIdentifier builds the identifier passed to Bind. See Validate's doc
// comment for the AD-vs-lldap rationale.
func bindIdentifier(c Conn, username string) string {
	switch {
	case strings.Contains(c.Domain, "="):
		return fmt.Sprintf("uid=%s,ou=people,%s", username, c.Domain)
	case c.Logon.Format == LogonNetbios && c.Logon.Netbios != "":
		return c.Logon.Netbios + `\` + username
	case c.Logon.Format == LogonUPN && c.Logon.UPNSuffix != "":
		return username + "@" + c.Logon.UPNSuffix
	case c.Domain == "":
		return username
	default:
		return fmt.Sprintf("%s@%s", username, c.Domain)
	}
}

// Rotate changes the account's own password on the target described by c,
// authenticating as the account with current (never newPassword: the
// account must prove it holds the CURRENT credential before it's allowed to
// set a new one). Domain selects the wire mechanism exactly as it selects
// the bind identifier in Validate/bindIdentifier:
//   - Domain contains "=" (lldap-style base DN): the RFC-3062 Password
//     Modify extended operation.
//   - anything else (AD, or no Domain at all): AD's self-service "Change
//     Password" form -- a single ModifyRequest that deletes the OLD
//     unicodePwd value and adds the NEW one, submitted in one round trip
//     over an encrypted connection. A bare Replace of unicodePwd is the
//     ADMINISTRATIVE reset form and requires the Reset-Password
//     control-access right, which this adapter (bound as the account
//     itself) does not have.
//
// Rotate never logs current.Password or newPassword.
func (a *ldapAdapter) Rotate(ctx context.Context, c Conn, current Cred, newPassword string) (Result, string) {
	conn, err := a.dial(c)
	if err != nil {
		return Unreachable, fmt.Sprintf("dial %s:%d: %v", c.Host, c.Port, err)
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(dialTimeout)
	}
	conn.SetTimeout(time.Until(deadline))

	bindID := bindIdentifier(c, current.Username)
	if err := conn.Bind(bindID, current.Password); err != nil {
		return classifyLDAPResultErr(err, fmt.Sprintf("bind %s", bindID))
	}

	if strings.Contains(c.Domain, "=") {
		return rotateLLDAP(conn, bindID, current.Password, newPassword)
	}
	return rotateAD(conn, c, current, newPassword)
}

// dialLDAP dials the target described by c, adding a TLS config (with the
// dev InsecureSkipVerify seam) when c.UseTLS is set. Both Validate and Rotate
// use it: a real AD/Samba LDAPS endpoint's certificate is usually self-signed
// in dev, so an LDAPS bind (heartbeat or post-rotation validate) needs the
// same seam the rotation change does.
func dialLDAP(c Conn) (*ldap.Conn, error) {
	scheme := "ldap"
	if c.UseTLS {
		scheme = "ldaps"
	}
	addr := fmt.Sprintf("%s://%s:%d", scheme, c.Host, c.Port)

	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout})}
	if c.UseTLS {
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: tlsInsecureSkipVerify()})) // #nosec G402 -- off unless CONNECTOR_TLS_INSECURE is set, see tlsInsecureSkipVerify
	}
	return ldap.DialURL(addr, opts...)
}

// tlsInsecureSkipVerify reports whether the LDAPS dial should skip server
// certificate verification. It defaults to false (SECURE: verify the
// server's certificate) -- this connection carries a new credential, so
// defaulting to skip-verify would be a MITM risk. It is opened only by
// explicitly setting CONNECTOR_TLS_INSECURE=true (or "1"), e.g. in a dev lab
// against a self-signed cert (a Samba AD DC) that has no trusted CA wired
// up.
func tlsInsecureSkipVerify() bool {
	v, ok := os.LookupEnv("CONNECTOR_TLS_INSECURE")
	if !ok {
		return false
	}
	return v == "true" || v == "1"
}

// classifyLDAPResultErr maps an LDAP error to a Result: an authoritative
// rejection (bad credentials, a constraint/policy violation such as
// password history or complexity, or a rights error confirming the server
// understood and refused the request) is Invalid; anything else (dial/
// timeout/protocol errors that don't confirm a rejection) is Unreachable.
func classifyLDAPResultErr(err error, context string) (Result, string) {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultInvalidCredentials:
			return Invalid, "invalid credentials"
		case ldap.LDAPResultConstraintViolation:
			return Invalid, fmt.Sprintf("constraint violation: %v", err)
		case ldap.LDAPResultInsufficientAccessRights:
			// Confirms the server understood the modify and refused it on
			// rights grounds -- e.g. the delete+add pair wasn't sent as a
			// single self-service change, or the account lacks even that.
			// Not Unreachable: the server answered authoritatively.
			return Invalid, fmt.Sprintf("insufficient access rights for self-service password change: %v", err)
		}
	}
	return Unreachable, fmt.Sprintf("%s: %v", context, err)
}

// rotateAD performs AD's self-service "Change Password" form: it resolves
// current.Username's DN and objectSid, refuses with Refused (no modify is
// sent) when the account is the domain's built-in Administrator, then submits a SINGLE ModifyRequest that deletes
// the OLD unicodePwd value (current.Password, encoded per encodeADPassword)
// and adds the NEW one (newPassword, likewise encoded), both in the same
// modify request. AD requires this exact delete-then-add pairing in one
// round trip for a self-service change made by the account itself over an
// encrypted (LDAPS) session; a bare Replace is the ADMINISTRATIVE reset
// form and requires the Reset-Password control-access right, which this
// adapter (bound as the account itself, not an admin) does not have.
//
// rotateAD never logs current.Password or newPassword.
func rotateAD(conn ldapClient, c Conn, current Cred, newPassword string) (Result, string) {
	dn, flags, err := resolveADAccount(conn, c, current.Username)
	if err != nil {
		return Unreachable, fmt.Sprintf("resolve DN for %s: %v", current.Username, err)
	}
	if flags.BuiltinAdministrator {
		return Refused, BuiltinAdministratorReason
	}

	mod := buildADChangePasswordModify(dn, current.Password, newPassword)
	if err := conn.Modify(mod); err != nil {
		return classifyLDAPResultErr(err, fmt.Sprintf("modify unicodePwd for %s", dn))
	}
	return Valid, ""
}

// buildADChangePasswordModify builds the single ModifyRequest AD's
// self-service "Change Password" form requires against dn: a Delete of the
// OLD unicodePwd value (oldPassword) followed by an Add of the NEW one
// (newPassword), both encoded per encodeADPassword. Split out from rotateAD
// as a pure function so the exact wire shape (both changes present, in
// order, correctly encoded) can be asserted without a live LDAP connection.
func buildADChangePasswordModify(dn, oldPassword, newPassword string) *ldap.ModifyRequest {
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Delete("unicodePwd", []string{encodeADPassword(oldPassword)})
	mod.Add("unicodePwd", []string{encodeADPassword(newPassword)})
	return mod
}

// rotateLLDAP performs lldap's self-service password change via the
// RFC-3062 Password Modify extended operation.
func rotateLLDAP(conn ldapClient, userIdentity, oldPassword, newPassword string) (Result, string) {
	req := ldap.NewPasswordModifyRequest(userIdentity, oldPassword, newPassword)
	if _, err := conn.PasswordModify(req); err != nil {
		return classifyLDAPResultErr(err, "password modify")
	}
	return Valid, ""
}

// resolveADAccount finds username's distinguishedName and AccountFlags by
// searching under the base DN derived from c.Domain (see adBaseDN). When
// c.Domain doesn't yield a usable search base (empty, or lldap-style), it
// falls back to the same identifier Bind used: callers in that shape are
// expected to pass a full DN (or an identifier the target accepts directly)
// as Username. A DN-shaped fallback is read directly; any other fallback
// can't be looked up, so its flags are unknown (and AD refuses a modify of
// a non-DN anyway).
//
// A found entry without a parseable objectSid is an error: rotation must
// not go ahead without knowing the account isn't the built-in Administrator.
func resolveADAccount(conn ldapClient, c Conn, username string) (string, AccountFlags, error) {
	var entry *ldap.Entry
	var err error
	if base := adBaseDN(c.Domain); base != "" {
		entry, err = searchOne(conn, base, ldap.ScopeWholeSubtree, fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(username)))
	} else {
		dn := bindIdentifier(c, username)
		if !strings.Contains(dn, "=") {
			return dn, AccountFlags{}, nil
		}
		entry, err = searchOne(conn, dn, ldap.ScopeBaseObject, "(objectClass=*)")
	}
	if err != nil {
		return "", AccountFlags{}, err
	}
	rid, err := ridOf(entry.GetRawAttributeValue("objectSid"))
	if err != nil {
		return "", AccountFlags{}, fmt.Errorf("objectSid of %s: %w", entry.DN, err)
	}
	return entry.DN, AccountFlags{
		Known:                true,
		BuiltinAdministrator: rid == builtinAdministratorRID,
		AdminCount:           entry.GetAttributeValue("adminCount") == "1",
	}, nil
}

// builtinAdministratorRID is the fixed relative ID of every domain's
// built-in Administrator. Matching on it, never the name, holds even when
// the account has been renamed.
const builtinAdministratorRID = 500

// searchOne reads objectSid and adminCount from the single entry the search
// must match.
func searchOne(conn ldapClient, base string, scope int, filter string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(
		base,
		scope, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"objectSid", "adminCount"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("expected exactly one entry for %s under %s, got %d", filter, base, len(res.Entries))
	}
	return res.Entries[0], nil
}

// ridOf returns the last sub-authority (the RID) of a binary SID: revision
// 1, a sub-authority count, a 6-byte authority, then that many
// little-endian uint32 sub-authorities.
func ridOf(sid []byte) (uint32, error) {
	if len(sid) < 8 {
		return 0, fmt.Errorf("SID is %d bytes, too short", len(sid))
	}
	if sid[0] != 1 {
		return 0, fmt.Errorf("SID revision %d, want 1", sid[0])
	}
	count := int(sid[1])
	if count == 0 || len(sid) != 8+4*count {
		return 0, fmt.Errorf("SID has %d sub-authorities in %d bytes", count, len(sid))
	}
	return binary.LittleEndian.Uint32(sid[len(sid)-4:]), nil
}

// adBaseDN converts a DNS-style domain (e.g. "example.org") into an LDAP
// search base ("dc=example,dc=org"). It returns "" for anything that
// isn't a DNS domain: empty, or lldap-style (already a DN, signalled by
// containing "=").
func adBaseDN(domain string) string {
	if domain == "" || strings.Contains(domain, "=") {
		return ""
	}
	parts := strings.Split(domain, ".")
	for i, p := range parts {
		parts[i] = "dc=" + p
	}
	return strings.Join(parts, ",")
}

// encodeADPassword encodes password the way Active Directory's unicodePwd
// attribute requires for a self-service Replace over LDAPS: the password
// wrapped in double quotes, encoded as UTF-16LE (no BOM, no trailing NUL).
// This is documented AD behavior, not a project convention -- changing it
// changes what byte string is sent on the wire to a real domain controller.
func encodeADPassword(password string) string {
	quoted := `"` + password + `"`
	units := utf16.Encode([]rune(quoted))
	buf := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[i*2:], u)
	}
	return string(buf)
}
