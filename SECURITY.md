# Security policy

credential-bridge sits between your ssh client and your ssh agents and hands out git
tokens and gpg operations, so security reports are very welcome.

## Supported versions

Only the latest release receives security fixes. While the project is in beta (0.x),
fixes go into a new 0.x release; there are no backports.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately instead:

1. Open
   [Report a vulnerability](https://github.com/XeS0r/ssh-credential-bridge/security/advisories/new)
   (repository tab "Security" → "Report a vulnerability").
2. Describe what is affected (daemon and its workers, `credential-bridge-remote`, ctl,
   install scripts), how to reproduce it, and what an attacker could gain, for example
   which server or local user could use which keys, tokens or gpg operations.

Only the maintainer and you can see the report.

## What to expect

- A first response within **7 days**, on a best-effort basis (this is a one-person
  project).
- We agree on the fix and the timing together. The fix is developed privately and
  released, and then the advisory is published, with credit to you unless you prefer
  otherwise. A CVE can be requested through GitHub if appropriate.

## Scope

In scope is everything in this repository: the daemon (agent proxy, server recognition,
policy, workers and their sandboxes), `credential-bridge-remote` on servers,
`credential-bridge-ctl`, the install scripts and release packages.

Especially welcome are reports that show a way for a server to:

- be treated as another configured server, or as your local machine;
- see or use keys, tokens or gpg operations its profile does not allow (for example a
  token for a repository outside its git rules), or use them from a hop when `hops`
  forbids it;
- change the agent's keys (write commands on `agent-forward.sock`);
- crash or exhaust the daemon, or escape a worker's sandbox, with crafted agent
  messages, session-binds, extension payloads or Assuan traffic.

Some limits are by design and documented in
[docs/architecture.md](docs/architecture.md#limitations): while your ssh session is
open, someone with your account or root on a server can use that session's agent socket
within the server's profile, as with plain ssh agent forwarding, and a malicious server
can hide further hops from the proxy. Problems in the upstream agents, vault tools and
`gh` themselves belong to those projects, but reports on how credential-bridge uses them
are in scope.
