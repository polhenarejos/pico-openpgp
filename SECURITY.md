# Security Policy

## System and scope

This repository contains Pico OpenPGP firmware implementing OpenPGP and PIV
smart-card functionality over USB CCID. The security scope includes APDU
parsing and dispatch, PIN verification and retry state, lifecycle controls,
press-to-confirm behavior, private and secret-key storage, cryptographic
operations, certificates, secure messaging, and USB/CCID handling.

Issues in bundled SDK or third-party code are in scope when the integration
creates a product security impact. Otherwise, report them to the upstream
project as well.

## Threat model and security invariants

CCID hosts and APDU contents are untrusted. An attacker may also have physical
access to a device. Private keys, secret keys, PIN-derived protection, and
authorization state must not be exposed or bypassed through malformed APDUs,
unauthorized commands, lifecycle transitions, or reset paths.

APDU lengths and objects must be validated before use, PIN retry limits and
authorization checks must be enforced, and private-key operations must fail
closed. Sensitive key material must remain protected in storage and cleared
after use where the implementation promises this behavior.

## Reporting

Use a private GitHub security advisory for the
[pico-openpgp repository](https://github.com/polhenarejos/pico-openpgp/security/advisories/new)
when available. Otherwise contact the maintainers through the private channel
listed by the project. Include the affected version or commit, board and MCU,
APDU or transport context, attack prerequisites, impact, and a minimal
reproduction.

Do not include private keys, PINs, certificates containing sensitive data,
APDU captures with secrets, device images containing secrets, or credentials in
a report. Do not open a public issue for an unpatched vulnerability.

## Out of scope and limitations

Pure documentation issues, specification questions without a security impact,
and third-party vulnerabilities with no impact from this product's integration
are not security findings here. Hardware limitations described in the project
documentation are not by themselves vulnerabilities; report a bypass or an
impact that exceeds the documented limitation.

Only the latest release on the default branch is currently supported.
