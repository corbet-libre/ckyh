# cpky

**Passkey authentication factor for cvld.**

`cpky` will provide passkey registration and authentication for `cvld` (moved out of `cvld`), wrapping established WebAuthn libraries on the server plus the browser API. Hardware keys are a `cpky` policy, not a separate gate.

Status: name reserved, no implementation yet.

## Boundaries

What it does:

- Registers and verifies passkeys and hands `cvld` an opaque authentication result.

What it never does:

- A synced passkey alone never enrols a new device; device addition needs approval from an already active device (no recovery).
- No own WebAuthn cryptography.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).
