# Security policy

credential-bridge handles git credentials, so security reports are very welcome.

## Supported versions

Only the latest release receives security fixes. While the project is in beta (0.x),
fixes go into a new 0.x release; there are no backports.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately instead:

1. Open
   [Report a vulnerability](https://github.com/XeS0r/ssh-credential-bridge/security/advisories/new)
   (repository tab "Security" → "Report a vulnerability").
2. Describe what is affected (daemon, helper, ctl, install scripts), how to reproduce
   it, and what an attacker could gain, for example which remote or local user could get
   which credentials.

Only the maintainer and you can see the report.

## What to expect

- A first response within **7 days**, on a best-effort basis (this is a one-person
  project).
- We agree on the fix and the timing together. The fix is developed privately and
  released, and then the advisory is published, with credit to you unless you prefer
  otherwise. A CVE can be requested through GitHub if appropriate.

## Scope

In scope is everything in this repository: the daemon and its policy, the helper on
remotes, `credential-bridge-ctl`, the install scripts and release packages.

Some limits are by design and documented in
[docs/architecture.md](docs/architecture.md#security-properties): while your ssh session
is open, someone with your account or root on a remote can use the forwarded socket
within that remote's policy, as with ssh agent forwarding. Reports that show a way
around a remote's policy, or a way for one remote to reach another remote's credentials,
are exactly what this policy is for.
