# certdrift

certdrift aims to be a Node.js library and command-line tool for inspecting, checking, and comparing X.509 certificates, producing structured output that programs can consume instead of parsing OpenSSL's human-oriented text.

**The package published on npm is a placeholder.** Version 0.0.1 exists only to reserve the name: it contains no working code and installs no command. The project is in early development and nothing is usable yet. Until the first stable release, the library API, the command-line interface, and the output format may change at any time without notice.

It requires Node.js 24 or later and has no runtime dependencies. To run the type checks and tests locally, use `npm run check`.

## Extracting a value

To extract a value, use `--query`. To make a decision, use the checking command. `--query` only reads: it never says whether a certificate is good.

<!-- PENDING: name `certdrift check` once that command exists -->

```sh
certdrift inspect --query 'certificates[0].notAfter' server.pem
```

A path is field names separated by dots and numeric indices in square brackets, and nothing else. Quote it, because a shell reads square brackets as a pattern. A string prints without quotes, and any other value as compact JSON.

The path is checked against the schema of the output before anything is read. A path the schema does not declare exits with code 2. A declared path with no value in this output, such as an index past the end of a list, exits with code 0, prints nothing and says why on standard error. A field the contract tolerates but the schema does not declare does not exist for `--query`.

## Inspecting a server

`--host` reads the certificates a server sends, not a file, and prints them the way it prints a file. It works with `--verbose`, `--json`, `--quiet`, `--query` and `--select`.

```sh
certdrift inspect --host api.example.com:443
certdrift inspect --host '[2001:db8::1]:443' --servername api.example.com
```

The host is a name or an address, with the port after a colon. The port is 443 unless given. An IPv6 address is written in brackets, and the argument is quoted because a shell reads brackets as a pattern. The host is always given with `--host`: a path is always a file, whatever it looks like, so `--host` takes no path and no `-`, and does not read standard input.

The certificates are exactly the ones the server sent, in the order it sent them. Nothing is added from the trust store of the machine, and nothing says whether that machine would trust them.

`--servername` sets the server name sent in the handshake, which decides the certificate a server picks. It is the host name unless given, and an IP address sends none unless it is given. `--timeout` sets the longest the whole attempt may take, as a positive whole number of milliseconds, 10000 unless given. Both need `--host`.

A host that cannot be reached, one that refuses the connection, one that does not speak TLS and one that does not answer in time each exit with code 3, and the message says which. A server that sends several certificates that could each be the one the connection is about exits with code 2 listing them, and `--select` chooses, as it does for a file.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `2` | Misuse, a `--query` path the schema does not declare, or a bundle whose certificate is ambiguous (the candidates are listed). |
| `3` | The file is missing or unreadable, the material is not a certificate, or the host cannot be reached, refuses the connection, does not speak TLS or does not answer in time. |
| `4` | The command crashed: an error it did not expect, which is a bug. The error is printed on standard error as it is, even with `--quiet`. |

<!-- PENDING: list exit code 1, "a check failed", in this table once the checking command exists. Nothing exits with 1 until then, so listing it would describe a code that is never given. -->

A fault that kills Node.js with a signal cannot be caught, and the shell then reports a code of its own, for example 134 or 139.

## Requirements and results

A check compares a certificate with what a person requires and says, for each requirement, what it found. Two documents carry that, both JSON, both with their own `contract` number and their own schema in `schema/`: the **policy** says what is required, and the **check result** says what was found. The package describes these documents, checks the shape of a policy and writes a check result; it does not evaluate a policy.

### The policy

A policy is a JSON object with `"contract": 1` and one optional entry per kind of rule. An entry says how severe a failure is, and takes a `value` where the rule has a parameter:

```json
{
  "contract": 1,
  "expiresWithin": { "value": "30d", "severity": "warn" },
  "expectEku": { "value": ["serverAuth"] },
  "expectSan": { "value": ["api.example.com", "192.0.2.10"] }
}
```

`severity` is `fail` unless the entry says `warn`. A rule with severity `warn` reports a failure as a warning and never makes a check fail. `schema/policy.schema.json` describes every entry, and `schema/examples/policy/` shows policies that validate.

| Entry | Parameter | Produces |
|---|---|---|
| `validityStarted` | none | `NOT_YET_VALID` |
| `validityNotEnded` | none | `EXPIRED` |
| `expiresWithin` | `"30d"` or `"72h"`: whole days or hours, with the unit | `EXPIRES_SOON` |
| `maxLifetimeUsed` | a number from 0 to 1 | `LIFETIME_USED_EXCEEDED` |
| `expectEku` | one or more usages | `EKU_MISSING` |
| `ekuAllows` | one or more usages | `EKU_NOT_PERMITTED` |
| `rejectEku` | one or more usages | `EKU_FORBIDDEN` |
| `expectSan` | one or more DNS names or IP addresses | `SAN_MISSING` |
| `expectFingerprint` | a SHA-256, 64 lowercase hexadecimal characters | `FINGERPRINT_MISMATCH` |
| `expectKind` | `"end-entity"` | `TARGET_NOT_END_ENTITY` |
| `matchesPrivateKey` | none | `KEY_MISMATCH`, `KEY_UNREADABLE` |

`validityStarted` and `validityNotEnded` are evaluated whether the policy lists them or not. They are in the policy so that their severity can be lowered. `matchesPrivateKey` shares one severity between its two codes. A usage is one of `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping` and `OCSPSigning`, or an OID as dotted text, which is the same usage as its name when it has one.

An `expectSan` item is an IP address exactly when it is one a certificate could list, and then it is compared in the canonical form the observation writes (IPv6 compressed, lower case). Anything else must be a DNS name, compared in lower case: labels of ASCII letters, digits, hyphens and underscores, optionally starting with a `*` label, whose last label is not a number. A name such as `1.2.3` or `010.0.0.1`, which a resolver reads as an address, is refused instead of being a name that could never be listed. A wildcard is compared as written: `*.example.com` is satisfied by a certificate that lists `*.example.com`, not by one that lists `a.example.com`.

A policy is a document people share and commit. It never carries a private key, a passphrase or anything read from them: the key is handed to the function that evaluates, and a property put in a policy anyway is tolerated like any property the contract does not know and is never repeated in a result. A rule of your own is code passed to the function that evaluates, not an entry of the policy, so a policy holds no function. A policy with no entry besides the two validity ones is valid, and evaluating it produces a `POLICY_EMPTY` warning, because a policy that checks nothing is a false "correct" under another name.

`policyProblems(policy)` checks the shape at run time, with code written in the package and no schema validator, and gives `[]` for a valid policy. Otherwise it lists each problem with a `path` (a JSON Pointer) and a `message`. A `contract` it does not know is a problem like any other: it is misuse of the policy, not a failed check. It also refuses what JSON cannot hold, under any key, the ones this version does not know included: a function put in a policy by mistake would otherwise be ignored without a word. A message never quotes a value of the policy, since a value in the wrong place may be a secret.

### The check result

`serializeCheckResult(result)` writes a check result as text, with the keys of the contract in a fixed order, the verdict first and the observation last, so the same result always gives the same bytes. `schema/check-result.schema.json` describes it, and `schema/examples/check-result/` shows results that validate.

| Field | What it holds |
|---|---|
| `contract` | `1`, the check result's own number |
| `now` | the instant the rules were evaluated against. It is the observation's `at` unless another instant was asked for, and `at` is never changed |
| `summary` | `status` (`fail` if any result failed, otherwise `warn` if any warned, otherwise `pass`) and the counts `pass`, `warn`, `fail` |
| `results` | one result per rule, in the order of the policy table above, then the rules of your own in the order given, then `POLICY_EMPTY` |
| `policy` | the policy that was applied: the entries this version knows, each with its `severity` written out, the two validity entries included |
| `observation` | the observation that was checked, as it is: `schema/observation.schema.json` describes it |

A result holds:

| Field | What it holds |
|---|---|
| `code` | a stable code for programs: capital letters, digits and underscores. Open: a rule of your own chooses its own |
| `status` | `pass`, `fail` or `warn`. Closed: a consumer that does not know a status cannot tell a pass from a failure, so a new one needs a new contract number |
| `rule` | `name` and the `value` it was given, as the policy wrote it. `null` only for `POLICY_EMPTY` |
| `message` | text for people, in English. Never parse it |
| `actual`, `expected` | what was found and what was required, where the rule compares something. Absent where there is nothing to show, and `null` is a value: `eku` is `null` when the extension is absent |

The code names the condition the result is about and the status says whether it holds, so a pass carries the code of the rule that passed. A rule that does not hold gives `fail`, or `warn` when its severity is `warn`. A result of a rule of your own has the same shape. Nothing in a result is a private key, a passphrase or anything read from them.

The time rules use the certificate's original `notBefore` and `notAfter` and `now`, never the rounded values in `derived`. `now` is the observation's `at` unless another instant is given. A validity period includes both its ends: an instant equal to `notAfter` or to `notBefore` is still valid. The package exports this rule as `outsideValidity(notBefore, notAfter, now)`, which gives `[]`, `["not yet valid"]`, `["expired"]` or both (a period that ends before it starts), from the observation's timestamps or `Date`s. `inspect`'s readable output uses it to end the target's `remaining` line with `(expired)` or `(not yet valid)`; the other certificates of the chain are never labelled.

### Reason codes

Codes are versioned with the contract: adding a code is additive, and changing what a code means requires a new contract number.

| Code | Entry | Passes when | Fails when | `actual` / `expected` |
|---|---|---|---|---|
| `EXPIRED` | `validityNotEnded` | `notAfter` is not before `now` | `notAfter` is before `now` | `notAfter` / `now` |
| `NOT_YET_VALID` | `validityStarted` | `notBefore` is not after `now` | `notBefore` is after `now` | `notBefore` / `now` |
| `EXPIRES_SOON` | `expiresWithin` | the seconds left until `notAfter` are not below the threshold | they are below it, which includes a certificate that has already ended | the seconds left, negative once ended / the threshold in seconds |
| `LIFETIME_USED_EXCEEDED` | `maxLifetimeUsed` | `now - notBefore` is not above the threshold times `notAfter - notBefore` | it is above | the fraction used, unrounded, `null` when `notAfter` is not after `notBefore` / the threshold |
| `EKU_MISSING` | `expectEku` | the target's `eku` is a list that includes every usage | `eku` is `null`, is `[]`, or lacks a usage | `eku` / the usages, by name where there is one |
| `EKU_NOT_PERMITTED` | `ekuAllows` | `eku` is `null`, or a list that includes every usage | `eku` is a list that lacks a usage, which includes `[]` | `eku` / the usages |
| `EKU_FORBIDDEN` | `rejectEku` | `eku` is `null`, `[]` or a list with none of the usages | `eku` lists any of them | `eku` / the usages |
| `SAN_MISSING` | `expectSan` | every name is listed: DNS names in `san.dns`, addresses in `san.ip` | any is not | `{ dns, ip }` the target lists / `{ dns, ip }` the names, as compared |
| `FINGERPRINT_MISMATCH` | `expectFingerprint` | the target's `sha256` is the expected one | it is not | the target's `sha256` / the expected one |
| `TARGET_NOT_END_ENTITY` | `expectKind` | the target's `kind` is `end-entity` | it is any other kind | `kind` / `end-entity` |
| `KEY_MISMATCH` | `matchesPrivateKey` | a private key was read and corresponds to the target's public key | a key was read and does not | the SPKI SHA-256 of the key's public key / the target's `spkiSha256` |
| `KEY_UNREADABLE` | `matchesPrivateKey` | never: a key that can be read gives `KEY_MISMATCH` | the key could not be read: its format, encrypted with no passphrase, or an algorithm that is not supported | none |
| `POLICY_EMPTY` | none | never | the policy has no entry besides the two validity ones and no rule of your own is given. Always `warn`, and `rule` is `null` | none |

`eku` is `null` when the extension is absent, which means Extended Key Usage does not restrict the purpose, not that the certificate is good for everything. That is why there are two rules about it: `expectEku` requires a usage to be listed, and `ekuAllows` only requires that the extension does not forbid it. An extension that is present and lists nothing (`[]`) permits nothing, so both fail on it, each with its own code, and `rejectEku` passes on it.

`kind` is the one the observation gives, which is the one Node.js reads. A CA that carries a known extension twice, or one that does not decode, reads as `end-entity`, so `TARGET_NOT_END_ENTITY` passes for it. The observation now carries a `KIND_UNRELIABLE` warning for that certificate.
<!-- `kind` keeps the value Node.js gives even where a warning says it cannot be trusted, so the limit above holds with or without that warning. -->
