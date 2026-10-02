// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// defaultKerberosPort is the standard KDC port used when Conn.Port is unset.
const defaultKerberosPort = 88

// defaultKpasswdPort is the standard kpasswd port. Unlike the KDC port, this
// is not read from Conn: the kpasswd and KDC services are conventionally
// two independent listeners on the same host, and Conn has only one Port
// field (shared with Validate's KDC use), so Rotate always targets the
// well-known kpasswd port on c.Host.
const defaultKpasswdPort = 464

// kerberosAdapter validates a credential by performing a Kerberos AS-REQ
// (an unauthenticated TGT request) against the target's KDC: cl.Login()
// asks the KDC to issue a TGT for the account, exercising the account's
// password exactly as an interactive Kerberos logon would.
type kerberosAdapter struct{}

func init() {
	Register("kerberos", &kerberosAdapter{})
}

// Validate builds a minimal, single-KDC krb5 config from c (no krb5.conf
// file, no DNS SRV lookup: the KDC is always c.Host:c.Port) and attempts an
// AS-REQ for cred against it.
//
// gokrb5's client.Login has no context.Context parameter, so ctx is only
// checked up front for an early exit; it cannot cancel a Login already in
// flight. In practice this is an acceptable trade-off: gokrb5's own
// transport code applies short, hard-coded dial/read timeouts (a few
// seconds) when the KDC does not respond, which is what actually bounds the
// Unreachable case.
func (a *kerberosAdapter) Validate(ctx context.Context, c Conn, cred Cred) (Result, string) {
	if err := ctx.Err(); err != nil {
		return Unreachable, err.Error()
	}

	realm := kerberosRealm(c)
	if realm == "" {
		return Unreachable, "no realm or domain configured for kerberos target"
	}

	port := c.Port
	if port == 0 {
		port = defaultKerberosPort
	}
	kdc := fmt.Sprintf("%s:%d", c.Host, port)

	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.Realms = []config.Realm{
		{
			Realm: realm,
			KDC:   []string{kdc},
		},
	}

	cl := client.NewWithPassword(cred.Username, realm, cred.Password, cfg)
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		return classifyKrbErr(err)
	}
	return Valid, ""
}

// Rotate changes cred's own password via the kpasswd protocol (RFC 3244):
// an AS-REQ authenticated with current gets a ticket for the
// kadmin/changepw service, which is then used to send the new password to
// the kpasswd server. gokrb5's client.ChangePasswd implements the whole
// exchange; Rotate only has to authenticate the client with current and
// build a config that can find both the KDC (for the AS-REQ) and the
// kpasswd server.
//
// Like Validate, ctx is only checked up front: gokrb5 has no
// context.Context-aware transport, but its own dial/read timeouts bound
// the Unreachable case in practice.
func (a *kerberosAdapter) Rotate(ctx context.Context, c Conn, current Cred, newPassword string) (Result, string) {
	if err := ctx.Err(); err != nil {
		return Unreachable, err.Error()
	}

	realm := kerberosRealm(c)
	if realm == "" {
		return Unreachable, "no realm or domain configured for kerberos target"
	}

	kdcPort := c.Port
	if kdcPort == 0 {
		kdcPort = defaultKerberosPort
	}
	kdc := fmt.Sprintf("%s:%d", c.Host, kdcPort)
	kpasswd := fmt.Sprintf("%s:%d", c.Host, defaultKpasswdPort)

	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.Realms = []config.Realm{
		{
			Realm:         realm,
			KDC:           []string{kdc},
			KPasswdServer: []string{kpasswd},
		},
	}

	cl := client.NewWithPassword(current.Username, realm, current.Password, cfg)
	defer cl.Destroy()

	ok, err := cl.ChangePasswd(newPassword)
	if err != nil {
		return classifyKrbErr(err)
	}
	if !ok {
		return Unreachable, "kpasswd change was not acknowledged as successful"
	}
	return Valid, ""
}

// kerberosRealm picks the realm for the AS-REQ: Conn.Realm if set, falling
// back to Conn.Domain, both upper-cased (Kerberos realm names are
// conventionally upper-case, and AD/Samba KDCs expect it).
func kerberosRealm(c Conn) string {
	if c.Realm != "" {
		return strings.ToUpper(c.Realm)
	}
	return strings.ToUpper(c.Domain)
}

// credentialErrorText holds the exact substrings that errorcode.Lookup
// produces for the two KRB error codes that mean "the KDC understood the
// request and rejected the credential" (as opposed to a transport,
// configuration, or account-state problem): a wrong password
// (KDC_ERR_PREAUTH_FAILED) and an unknown account
// (KDC_ERR_C_PRINCIPAL_UNKNOWN). They are derived from errorcode.Lookup
// itself, rather than hard-coded, so classifyKrbErr's string-matching
// fallback (see below) stays byte-for-byte in sync with the text gokrb5
// actually embeds in its wrapped errors.
var credentialErrorText = []string{
	errorcode.Lookup(errorcode.KDC_ERR_PREAUTH_FAILED),
	errorcode.Lookup(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN),
}

// classifyKrbErr maps an error returned by (*client.Client).Login to a
// Result.
//
// gokrb5 represents the protocol-level error as messages.KRBError (carrying
// the numeric ErrorCode), but client.Login's AS-REQ path always wraps it in
// gokrb5's own krberror.Krberror before returning it -- and krberror.Krberror
// formats the cause into its Error() string rather than holding onto it (it
// has no Unwrap method), so errors.As cannot reach the original KRBError
// through a real Login() error.
//
// classifyKrbErr therefore tries errors.As first (it costs nothing, and
// covers any bare/wrapped-with-%w messages.KRBError a future gokrb5 version
// or another caller might hand us), then falls back to matching the KRB
// error code's description text, which errorcode.Lookup produces and which
// krberror.Krberror's formatting preserves verbatim inside the final error
// message. Any other error -- a different KDC error code, a dial/network
// failure, or a config problem -- is treated as Unreachable: the target
// could not be authoritatively confirmed to have rejected this specific
// credential.
func classifyKrbErr(err error) (Result, string) {
	detail := err.Error()

	var krbErr messages.KRBError
	if errors.As(err, &krbErr) {
		if isCredentialErrorCode(krbErr.ErrorCode) {
			return Invalid, detail
		}
		return Unreachable, detail
	}

	for _, text := range credentialErrorText {
		if strings.Contains(detail, text) {
			return Invalid, detail
		}
	}
	return Unreachable, detail
}

// isCredentialErrorCode reports whether code is one of the KRB error codes
// classifyKrbErr treats as Invalid (see its doc comment).
func isCredentialErrorCode(code int32) bool {
	return code == errorcode.KDC_ERR_PREAUTH_FAILED || code == errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN
}
