# certdrift

certdrift aims to be a Node.js library and command-line tool for inspecting, checking, and comparing X.509 certificates, producing structured output that programs can consume instead of parsing OpenSSL's human-oriented text.

**The package published on npm is a placeholder.** Version 0.0.1 exists only to reserve the name: it contains no working code and installs no command. The project is in early development and nothing is usable yet. Until the first stable release, the library API, the command-line interface, and the output format may change at any time without notice.

It requires Node.js 24 or later and has no runtime dependencies. To run the type checks and tests locally, use `npm run check`.

## Extracting a value

To extract a value, use `--query`. To make a decision, use `certdrift check`. `--query` only reads: it never says whether a certificate is good.

```sh
certdrift inspect --query 'certificates[0].notAfter' server.pem
```

A path is field names separated by dots and numeric indices in square brackets, and nothing else. Quote it, because a shell reads square brackets as a pattern. A string prints without quotes, and any other value as compact JSON.

The path is checked against the schema of the output before anything is read. A path the schema does not declare exits with code 2. A declared path with no value in this output, such as an index past the end of a list, exits with code 0, prints nothing and says why on standard error. A field the contract tolerates but the schema does not declare does not exist for `--query`.

## Inspecting a server

`--host` reads the certificates a server sends, not a file, and prints them the way it prints a file (`certdrift check --host` checks them against requirements). It works with `--verbose`, `--json`, `--quiet`, `--query` and `--select`.

```sh
certdrift inspect --host api.example.com:443
certdrift inspect --host '[2001:db8::1]:443' --servername api.example.com
```

The host is a name or an address, with the port after a colon. The port is 443 unless given. An IPv6 address is written in brackets, and the argument is quoted because a shell reads brackets as a pattern. A URL is not accepted: a target that starts with a scheme and `://`, such as `https://example.com`, is exit 2, and the message says that the target is `host[:port]`. The host is always given with `--host`: a path is always a file, whatever it looks like, so `--host` takes no path and no `-`, and does not read standard input.

The certificates are exactly the ones the server sent, in the order it sent them. Nothing is added from the trust store of the machine, and nothing says whether that machine would trust them.

`--servername` sets the server name sent in the handshake, which decides the certificate a server picks. It is the host name unless given, and an IP address sends none unless it is given. `--timeout` sets the longest the whole attempt may take, as a positive whole number of milliseconds, 10000 unless given. Both need `--host`.

A host that cannot be reached, one that refuses the connection, one that does not speak TLS and one that does not answer in time each exit with code 3, and the message says which. A server that sends several certificates that could each be the one the connection is about exits with code 2 listing them, and `--select` chooses, as it does for a file.

## Checking a certificate

`certdrift check` decides. It reads a certificate the way `inspect` does (a file, or standard input when the path is `-`, PEM or DER, a bundle with `--select` when several certificates could be the one it is about), applies requirements and prints one result for each. It exits with 1 when a result fails, so a script can act on it. A requirement that does not hold is a failed result, never an error of the command.

```sh
certdrift check --expect-san api.example.com --expires-within 30d server.pem
```

```text
server.pem  checked at 2026-12-20T00:00:00Z
  OK    validityStarted   NOT_YET_VALID  the certificate is valid from 2026-10-14T17:37:52Z
  OK    validityNotEnded  EXPIRED        the certificate is valid until 2027-01-12T17:37:52Z
  FAIL  expiresWithin     EXPIRES_SOON   23 days are left, below 30d
  OK    expectSan         SAN_MISSING    the certificate lists every expected name

1 failed · exit 1
```

The first line names what was checked and the instant the rules were evaluated at. Each line has the status (`OK`, `WARN` or `FAIL`), the name of the rule, the reason code and a message, and the observation's own warnings, such as `KIND_UNRELIABLE` and `EKU_UNRELIABLE`, follow the results so that a rule that passes never hides what was said about the certificate it passed on. The last line says how many results failed and the exit code. Text that comes from a certificate or a file is escaped as `inspect` escapes it, and the output is coloured unless the `NO_COLOR` environment variable is set to a non-empty value. `--json` prints the check result of the section below, exactly as `serializeCheckResult` writes it, and nothing else on standard output. `--quiet` prints nothing and wins over `--json`.

### Requirements

Each option adds one rule to the policy that is applied. The validity of the certificate (`NOT_YET_VALID` and `EXPIRED`) is always checked.

| Option | Rule | Takes |
|---|---|---|
| `--expect-eku <name\|OID>` | `expectEku` | a usage; repeatable |
| `--eku-allows <name\|OID>` | `ekuAllows` | a usage; repeatable |
| `--reject-eku <name\|OID>` | `rejectEku` | a usage; repeatable |
| `--expect-san <name\|address>` | `expectSan` | a DNS name or an IP address; repeatable |
| `--expect-fingerprint <sha256>` | `expectFingerprint` | 64 hexadecimal characters, in either case, or pairs separated by colons as `openssl` prints them |
| `--expires-within <Nd\|Nh>` | `expiresWithin` | whole days or hours: `30d`, `72h` |
| `--lifetime-used <N%>` | `maxLifetimeUsed` | a percentage from 0% to 100%: `66%`, `66.3%` |

The command implements none of the rules: the options become a policy, `policyProblems` checks it and `evaluate` applies it, so what each rule decides is what the table of reason codes below says. `--lifetime-used 66.3%` is the threshold `0.663`, built from the digits of the text and not by dividing by a hundred, which in floating point gives a different number. A value that an option cannot take is exit 2, and the message names the option (and, for one that can be repeated, the value as it was typed), never a path inside a policy.

`--select <sha256>` works as in `inspect`. A flag that takes one value and is given twice is misuse. `--help` (or `-h`) prints the options of the command.

### Policy file and options

`--policy <file>` reads a policy, a JSON document with `"contract": 1`, from a file, or from standard input with `-`. A file that cannot be opened, or that is not JSON, is exit 3. A file whose shape `policyProblems` refuses, a `contract` the tool does not know included, is exit 2, with each problem and its path. A byte order mark at the start of the file is ignored.

The options add entries to the file. An option that gives an entry the file already has is exit 2 and says which, so that an option never changes a shared policy without anyone seeing it. `--warn-only <code>` is how a rule of the file, or of an option, is softened: it sets the severity of the entry that produces that reason code to `warn`, and a failure of that rule is then a `WARN` result that does not fail the check. The code must be that of a rule that is part of the run (the two validity rules always are). A code that does not exist, or whose rule is not checked, is exit 2: a mistyped code would otherwise leave failing a rule you believed softened.

```sh
certdrift check --policy policy.json --warn-only LIFETIME_USED_EXCEEDED server.pem
certdrift check --policy policy.json --expect-fingerprint 2D:71:16:42:B7:26:B0:44:01:62:7C:A9:FB:AC:32:F5:C8:53:0F:B1:90:3C:C4:DB:02:25:87:17:92:1A:48:81 server.pem
```

With no requirement option, no `--key`, no `--expect-fingerprint-of` and no `--policy` there is nothing to check, which is exit 2 (`nothing to check: give a requirement option, --key, --expect-fingerprint-of or --policy`); `--warn-only` and `--as-of` alone do not count. A policy that has only `contract` is something to check, and gives the `POLICY_EMPTY` warning. A policy that lists `matchesPrivateKey` needs `--key`: without one it is exit 2, and the message says that the policy asks for a private key.

A top-level entry of the file that this version does not know, such as `expectSAN` for `expectSan`, is exit 2: the message names it, with the other problems of the file and not instead of them, because a misspelled entry would otherwise check nothing in silence. The only top-level property that is not an entry and is accepted, besides `contract`, is `$schema`, which editors add to JSON files. Properties inside an entry that this version does not know are still tolerated, and `evaluate` and `policyProblems` still tolerate an unknown entry, so a program that passes its own policy keeps working.

An entry written twice in the file counts once, and the last one is the one that counts: `JSON.parse` keeps the last of two equal keys and does not say so, as in `{"expectEku": …, "expectEku": …}`. The command does not detect it.

### A private key

Before a renewed certificate goes live, the question is whether it and the private key in hand are a pair. `--key <file>` answers it: the file is read as a PEM private key, and the certificate is checked against it by the rule `matchesPrivateKey`, whose result is added to the others and to the verdict.

```sh
certdrift check --key server.key --expect-san api.example.com --expect-eku serverAuth --expires-within 30d server.pem
```

```text
server.pem  checked at 2026-10-20T00:00:00Z
  OK    validityStarted    NOT_YET_VALID  the certificate is valid from 2026-10-14T17:37:52Z
  OK    validityNotEnded   EXPIRED        the certificate is valid until 2027-01-12T17:37:52Z
  OK    expiresWithin      EXPIRES_SOON   84 days are left, not below 30d
  OK    expectEku          EKU_MISSING    the Extended Key Usage extension lists clientAuth, serverAuth, which includes serverAuth
  OK    expectSan          SAN_MISSING    the certificate lists every expected name
  OK    matchesPrivateKey  KEY_MISMATCH   the private key corresponds to the certificate's public key

0 failed · exit 0
```

With another key, the last result is `FAIL  matchesPrivateKey  KEY_MISMATCH` and the command exits with 1. The key is a requirement of its own, so `--key` alone is something to check and gives no `POLICY_EMPTY` warning. Its severity is `fail`, or the one a policy file gives `matchesPrivateKey` when it lists it, and `--warn-only KEY_MISMATCH` and `--warn-only KEY_UNREADABLE` soften it. A file that opens and does not hold a readable private key is not misuse and not a crash: it is the result `KEY_UNREADABLE`, a failed check with exit 1, and its message says why (the file holds a certificate, a public key or no private key, the key is encrypted and no passphrase was given, it could not be decrypted with the passphrase given, the file holds more than one private key, or its format or algorithm is not supported). A key file that cannot be opened is exit 3, as a certificate file is. `--key -` is misuse: a key is never read from standard input.

`--key-passphrase-env <VAR>` takes the passphrase of an encrypted key from the environment variable `VAR`, exactly as the variable holds it, with no trimming. **There is no option that takes the passphrase itself, on purpose:** a command line is shown to every user of the machine by the list of processes, and an environment is not. A variable that is not defined is exit 2, and so is `--key-passphrase-env` without `--key`. A variable that is defined and empty is an empty passphrase, which is not the same as no passphrase. A key that is not encrypted is read with any passphrase.

```sh
certdrift check --key encrypted.key --key-passphrase-env SERVER_KEY_PASSPHRASE server.pem
```

Set the variable without typing the passphrase in a command, for example with `read -rs SERVER_KEY_PASSPHRASE` followed by `export SERVER_KEY_PASSPHRASE`.

The key and the passphrase never appear on standard output, on standard error or in the JSON, whatever the way the check ends; the message of a failure names the key file's path and nothing of its content. The command only reads the file: the matching is the library's `matchesPrivateKey`, described below. `--key` and `--key-passphrase-env` given twice are misuse, as the other options that take one value are.

### A server

After a certificate is installed, what matters is what the server actually serves. `--host <host[:port]>` makes `check` read the certificates a server sends instead of a file, and apply the same requirements to them. It takes every option of `check` on a file, and `--servername` and `--timeout` as `inspect --host` does. The certificate the connection is about is chosen as `inspect --host` chooses it, and `--select` works as it does there.

```sh
certdrift check --host api.example.com:443 --expect-fingerprint-of fullchain.pem --expect-san api.example.com --expires-within 30d
```

`--expect-fingerprint-of <file>` requires the certificate the server serves to be the one in the file: the file is read as a certificate is, and the SHA-256 of its target is the fingerprint the rule `expectFingerprint` asks for. It fills the same rule as `--expect-fingerprint`, so the two together are exit 2, and so is one of them with a policy file that has the entry. A file that cannot be read, or that holds no certificate, is exit 3. A file with several certificates that could be the one it is about is exit 2 and lists them; `--select` chooses only in what the host sends, and does not choose in this file. Without `--host` it compares the certificate of one file with that of another.

The host is a name or an address, with the port after a colon, 443 unless given. An IPv6 address is written in brackets, and the argument quoted because a shell reads brackets as a pattern. The host is always given with `--host`, so `--host` takes no path and no `-`. The rules about `--host`, `--servername` and `--timeout` are those of `inspect --host`: a flag of the three given twice, `--servername` or `--timeout` without `--host`, and a `--timeout` that is not a positive whole number of milliseconds are exit 2 and are reported before the host is contacted. A host that cannot be reached, one that refuses the connection, one that does not speak TLS and one that does not answer in time each exit with code 3, with the message of `inspect --host`, the hint about `--servername` for an IP address included.

Every file an option names (`--policy`, `--key` and `--expect-fingerprint-of`) is read before the host is contacted. With `--host` nothing is read from standard input unless an option asks: `--policy -` or `--expect-fingerprint-of -` may, but not both, because standard input is read once.

The readable output, `--json`, `--quiet`, `--as-of` and the exit codes are those of a file. The first line names the host as `host:port`, and the `source` of the observation in `--json` is `{ "kind": "host", "ref": …, "servername": … }`.

### The instant

`--as-of <date>` evaluates the rules at another instant than now. It is `YYYY-MM-DD`, which is that day at 00:00:00 UTC, or a timestamp in the form the contract writes, with the `Z`. Anything else, a date that does not exist such as `2026-02-30`, and a year outside 0 to 9999 is exit 2. It never changes the observation's `at`, and the first line of the readable output says the instant used.

```sh
certdrift check --as-of 2026-03-01 --expect-eku serverAuth server.pem
```

### Reading from standard input

```sh
certdrift check --json --reject-eku codeSigning - < server.pem
```

`-` is the certificate, the policy with `--policy -`, or the certificate of `--expect-fingerprint-of -`, but only one of them: standard input is read once. With `--host` there is no certificate to read, so one of the other two may use it.

### Exit codes of `check`

`0` when no result fails (a warning does not), `1` when one does, `2` for misuse, an invalid policy or an ambiguous bundle, `3` when the certificate, the key file, the policy file or the file of `--expect-fingerprint-of` cannot be read, the material is not a certificate, or the host cannot be reached, refuses the connection, does not speak TLS or does not answer in time, and `4` when the command crashes. The table below has them all.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. For `certdrift check`, no result failed. |
| `1` | A check failed: `certdrift check` has a result that is `FAIL`, a key that is not the certificate's or cannot be read as a private key (`KEY_UNREADABLE`) included. `inspect` never gives it. |
| `2` | Misuse, a `--query` path the schema does not declare, a policy that is not valid (one that lists `matchesPrivateKey` with no `--key` included), or a bundle whose certificate is ambiguous (the candidates are listed, and so are those of the file of `--expect-fingerprint-of`). |
| `3` | The file is missing or unreadable (the policy file, the key file and the file of `--expect-fingerprint-of` of `check` too), the policy file is not JSON, the material is not a certificate, or the host cannot be reached, refuses the connection, does not speak TLS or does not answer in time. |
| `4` | The command crashed: an error it did not expect, which is a bug. The error is printed on standard error as it is, even with `--quiet`. |

A fault that kills Node.js with a signal cannot be caught, and the shell then reports a code of its own, for example 134 or 139.

## Requirements and results

A check compares a certificate with what a person requires and says, for each requirement, what it found. Two documents carry that, both JSON, both with their own `contract` number and their own schema in `schema/`: the **policy** says what is required, and the **check result** says what was found. The package describes these documents, checks the shape of a policy, evaluates a policy against an observation and writes the check result.

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

### Evaluating a policy

`evaluate(observation, policy, options)` applies a policy to an observation, as `inspect()` returns it, and gives the whole check result: `contract`, `now`, the `summary`, the `results`, the applied `policy` and the `observation`. The command and every program that wants a verdict share it, so none of them has to read the observation and apply the rules itself.

```js
import { evaluate, inspect, serializeCheckResult } from "certdrift";

const observation = inspect(pem);
const policy = { contract: 1, expiresWithin: { value: "30d" }, expectEku: { value: ["serverAuth"] } };
const result = evaluate(observation, policy, {
    rules: [
        function issuerAllowed(observation) {
            const issuer = observation.certificates[observation.target].issuer.cn;
            return { code: "ISSUER_NOT_ALLOWED", status: issuer === "Example Issuing CA 1" ? "pass" : "fail", message: `the issuer is ${issuer}`, actual: issuer };
        },
    ],
});
console.log(result.summary.status, serializeCheckResult(result));
```

Every rule is about the certificate the observation targets. The result has one entry per rule, in the order of the policy table above (the two validity rules always, the others when the policy lists them, and `matchesPrivateKey` also when `options.privateKey` is given), then the rules of your own in the order given, then `POLICY_EMPTY` if the policy lists nothing else and no rule of your own was given. `summary.status` is `fail` when any result is `fail`, otherwise `warn` when any is `warn`, otherwise `pass`.

`options.now` is a `Date` or a timestamp in the form the contract writes, and it defaults to the observation's `at`. The result records it cut to the whole second, and the observation's `at` is not changed. A `now` that is not an instant, or that falls outside the years 0 to 9999, which the result could not write, is a `TypeError`.

`options.rules` is a list of functions `(observation, now) => result`, where `now` is the timestamp text the result records. A result has a `code`, a `status` and a `message`, and may have `rule`, `actual` and `expected`, with the same meaning as in any other result: when `rule` is missing, `evaluate` writes `{ name }`. The name is the function's own, or `rule-<n>`, counting from 1 by position, for a function with none, as one written inline in the list has. A rule answers at once and gives JSON: its result is copied, and a `rule` with no `value` or an `actual` that is `undefined` is written as an absent property.

The code of a rule of your own is any code of capital letters, digits and underscores starting with a letter, including the codes of the library's rules: its `rule.name` says which rule produced a result, and the library may add codes in a later version. Only `POLICY_EMPTY`, which exists with `rule: null`, and `RULE_ERROR` are the library's alone. A rule that throws, that returns a promise or anything that is not a result, that returns one of those two codes, or that returns an `actual`, an `expected` or a `rule.value` that cannot be written as JSON (a function, a BigInt, `NaN`, a value that contains itself or is nested more than 100 levels) gets a `RULE_ERROR` result with status `fail` under its name, and the check goes on. Its message says which of these it was and never repeats the text of the error the rule threw.

`options.privateKey` is `{ material, passphrase }`, the private key a file holds, and asks for the rule `matchesPrivateKey` (see below): it is evaluated even when the policy does not list it, with severity `fail`, and the applied policy in the result shows the entry. When the policy lists it, the entry's severity is the one used. The key is read by that rule alone: it is not copied, a rule of your own is never given it, and neither it nor the passphrase is in the result.

`evaluate` never throws because a rule failed. It throws `PolicyError` when the policy is not valid, with the problems `policyProblems` lists in its `problems` property, and also when the policy lists `matchesPrivateKey` and no `options.privateKey` is given, because that rule needs a private key: that problem has the path `/matchesPrivateKey`. The message says how many problems there are and never quotes a value of the policy. A wrong call is a `TypeError`: an `observation` the rules cannot read, a `now` that is not an instant, `options.rules` that is not a list of functions, or an `options.privateKey` that is not an object with a `material` that is text or bytes and a `passphrase` that is text.

Nothing the caller passed is modified, and nothing in the result is shared with it. A rule of your own gets the observation frozen all the way down, so it cannot change what the next rule or the result sees. The same arguments always give the same result: `evaluate` does not read the clock. The messages of a result can hold text that comes from a certificate (a name in the SAN, a usage), and the library does not escape it: whoever prints it does.

`POLICY_ENTRIES` is the list of the names of the entries, frozen and in the order of the table above. `policyProblems` tolerates an entry it does not know, so a program that reads a policy from a person and wants to refuse a misspelled entry compares the names of the file with this list; `certdrift check --policy` does, and also accepts `contract` and `$schema`.

`entryOfCode(code)` gives the entry of the policy that produces a reason code, `"validityNotEnded"` for `EXPIRED`, and `null` for a code that has no entry: `POLICY_EMPTY`, `RULE_ERROR` and a code this version does not know. It answers for the library's codes. A rule of your own may give one of them too, so a program that has results from both looks at `rule.name` before asking for the entry.

### Matching a private key

`matchesPrivateKey(observation, privateKey, options)` says whether a private key is the key of the certificate an observation targets, which is what a person wants to know before installing a renewed certificate. It gives one result, for the rule `matchesPrivateKey`, in the shape of any result.

```js
import { inspect, matchesPrivateKey } from "certdrift";

const observation = inspect(certificatePem);
const result = matchesPrivateKey(observation, { material: keyPem, passphrase: "…" }, { severity: "fail" });
console.log(result.code, result.status, result.message);
```

`privateKey` is `{ material, passphrase }`. `material` is the text or the bytes of the key's file, and `passphrase` is optional text, for a key that is encrypted. An empty string is a passphrase. The library never reads a file: whoever calls it does. Only PEM is read, so a DER file or a PKCS#12 file is a key that could not be read. `options.severity` is `fail` unless it says `warn`, and any other value is a `TypeError`. `evaluate` takes the same object as `options.privateKey`. `certdrift check --key` reads the file, and the passphrase from an environment variable, and gives them to `evaluate` this way: see [A private key](#a-private-key).

The key matches when the SHA-256 of the public key derived from it, as SubjectPublicKeyInfo DER, is the target's `spkiSha256`. A key that was read gives `KEY_MISMATCH`: `pass` when it matches, and the status of the severity when it does not, with the SHA-256 of the key's public key as `actual` and the target's `spkiSha256` as `expected`, both public. A key that could not be read gives `KEY_UNREADABLE`, with the status of the severity and no `actual` or `expected`, and a message that says why. The message is fixed text for each reason, and it starts with `the private key could not be read: `:

| Reason | The message goes on |
|---|---|
| the file holds a certificate | `the file holds a certificate` |
| the file holds a public key | `the file holds a public key` |
| the file holds no private key | `the file holds no private key` |
| the key is encrypted and no passphrase was given | `it is encrypted and no passphrase was given` |
| the key is encrypted and was not decrypted | `it could not be decrypted with the passphrase given` |
| the file holds more than one private key | `the file holds more than one private key` |
| anything else: the format or the algorithm is not supported, or the key is damaged | `its format or algorithm is not supported, or the key is damaged` |

The reason is chosen from the PEM labels of the file, never from the error Node.js gives, because Node.js gives the same one for a certificate, a public key, an empty file and a truncated key, and the codes change between versions, and never from anything inside a block. When a file fits several reasons, the first that applies is the one:

1. A file with more than one private key block is `more than one`, even when the first is encrypted and cannot be read: Node.js uses the first key of a file and says nothing of the others. A private key block is a line `-----BEGIN <label>-----` whose label ends in `PRIVATE KEY` (`PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `DSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, and also `OPENSSH PRIVATE KEY`, which Node.js cannot read), so a key that Node.js skips next to one it reads is more than one, and a block cut short counts as one block. The line has to start a line, as Node.js requires, and ends with `\n`, optionally after white space.
2. With one private key block, a certificate or a public key or text before or after it is skipped, as Node.js skips it, so a file that holds a chain and its key is accepted. If the key cannot be read, the reason is `encrypted and no passphrase` when the block is encrypted (its label is `ENCRYPTED PRIVATE KEY`, or the first line after the BEGIN line is `Proc-Type: 4,ENCRYPTED`) and no passphrase was given; `could not be decrypted` when it is encrypted and one was given, whether it is wrong or the key is damaged, because the two cannot be told apart without the error code; and `anything else` otherwise.
3. With no private key block, `certificate` when a block's label ends in `CERTIFICATE` (`CERTIFICATE`, `X509 CERTIFICATE`, `TRUSTED CERTIFICATE`), then `public key` when it ends in `PUBLIC KEY` (`PUBLIC KEY`, `RSA PUBLIC KEY`), whatever their order. Otherwise `no private key`, unless the file is not text (it holds a control character other than tab and line ends, or bytes that are not UTF-8, as a DER or a PKCS#12 file does), which is `anything else`.

A key without encryption loads with any passphrase, wrong or empty, so a passphrase given for one is harmless. A `material` that is neither text nor bytes (a `Buffer` and a `Uint8Array` are bytes) and a `passphrase` that is not text are a `TypeError` that never quotes them, and so is an observation with no target that has a `spkiSha256`. No error of Node.js leaves the function.

The key and the passphrase are not in the result, in a message or in an error, whatever the call gives. They are read by `createPrivateKey` and nowhere else, and the key object lives until Node.js collects it. Decrypting is synchronous, and a key encrypted with costly parameters takes as long as they say.

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
| `LIFETIME_USED_EXCEEDED` | `maxLifetimeUsed` | `now - notBefore` is not above the threshold times `notAfter - notBefore` | it is above | the fraction used, unrounded and above 1 once the validity has ended, `0` before `notBefore` (the message says `0%`), `null` when `notAfter` is not after `notBefore` / the threshold |
| `EKU_MISSING` | `expectEku` | the target's `eku` is a list that includes every usage | `eku` is `null`, is `[]`, or lacks a usage, whether or not it includes `2.5.29.37.0` (anyExtendedKeyUsage) | `eku` / the usages, by name where there is one |
| `EKU_NOT_PERMITTED` | `ekuAllows` | `eku` is `null`, or a list that includes every usage or includes `2.5.29.37.0` (anyExtendedKeyUsage) | `eku` is a list that lacks a usage and does not include `2.5.29.37.0`, which includes `[]` | `eku` / the usages |
| `EKU_FORBIDDEN` | `rejectEku` | `eku` is `null`, `[]` or a list with none of the usages | `eku` lists any of them | `eku` / the usages |
| `SAN_MISSING` | `expectSan` | every name is listed: DNS names in `san.dns`, addresses in `san.ip` | any is not | `{ dns, ip }` the target lists / `{ dns, ip }` the names, as compared |
| `FINGERPRINT_MISMATCH` | `expectFingerprint` | the target's `sha256` is the expected one | it is not | the target's `sha256` / the expected one |
| `TARGET_NOT_END_ENTITY` | `expectKind` | the target's `kind` is `end-entity` | it is any other kind | `kind` / `end-entity` |
| `KEY_MISMATCH` | `matchesPrivateKey` | a private key was read and corresponds to the target's public key | a key was read and does not | the SPKI SHA-256 of the key's public key / the target's `spkiSha256` |
| `KEY_UNREADABLE` | `matchesPrivateKey` | never: a key that can be read gives `KEY_MISMATCH` | the key could not be read: the file holds a certificate, a public key, no private key or more than one, its format or algorithm is not supported or the key is damaged, it is encrypted and no passphrase was given, or the passphrase given does not decrypt it. The reasons are in "Matching a private key" | none |
| `POLICY_EMPTY` | none | never | the policy has no entry besides the two validity ones and no rule of your own is given. Always `warn`, and `rule` is `null` | none |
| `RULE_ERROR` | none | never | a rule of your own threw, returned a promise or something that is not a result, returned `POLICY_EMPTY` or `RULE_ERROR`, or returned an `actual`, an `expected` or a `rule.value` that JSON cannot hold. Always `fail`, and `rule` is `{ name }` with the name of the rule that failed | none |

`eku` is `null` when the extension is absent, which means Extended Key Usage does not restrict the purpose, not that the certificate is good for everything. That is why there are two rules about it: `expectEku` requires a usage to be listed, and `ekuAllows` only requires that the extension does not forbid it. An extension that is present and lists nothing (`[]`) permits nothing, so both fail on it, each with its own code, and `rejectEku` passes on it.

An extension that lists anyExtendedKeyUsage (the OID `2.5.29.37.0`, which `eku` shows as that text, since it is not one of the six names) forbids no usage, so `ekuAllows` passes for any usage, alone or next to others (RFC 5280, 4.2.1.12). `expectEku` asks for the usage to be listed, and anyExtendedKeyUsage lists none, so it still fails with `EKU_MISSING` unless the usage is listed too; its message says that the certificate lists anyExtendedKeyUsage. `rejectEku` does not change: it fails only for a usage that is listed, `2.5.29.37.0` included.

`eku` is also `null` when the extension is present and Node.js cannot read it, which happens when it appears more than once or its value does not decode. A certificate like that restricts its usages, but `ekuAllows` and `rejectEku` pass it and `expectEku` fails it, as they do for an absent extension. The observation carries an `EKU_UNRELIABLE` warning for that certificate, which `inspect` and `check` print with the others and `--json` carries: it says that `eku` cannot be trusted, and the message says whether the extension appears more than once or does not decode. `eku` keeps the value Node.js gives, and no verdict changes.

`kind` is the one the observation gives, which is the one Node.js reads. A CA that carries a known extension twice, or one that does not decode, reads as `end-entity`, so `TARGET_NOT_END_ENTITY` passes for it. The observation now carries a `KIND_UNRELIABLE` warning for that certificate.
<!-- `kind` keeps the value Node.js gives even where a warning says it cannot be trusted, so the limit above holds with or without that warning. -->

## What changed between two observations

A **delta** says what changed between two observations of a certificate. It is JSON with its own `contract` number (`1`), independent of the observation's, the policy's and the check result's. `schema/delta.schema.json` describes it, `schema/examples/delta/` shows deltas that validate, and `serializeDelta(delta)` writes one as text with the keys of the contract in a fixed order, so the same delta always gives the same bytes. The package defines this shape and writes it: it does not compare two observations yet, so a delta is something a program builds or reads.

A delta describes and does not judge. It has no class, no reason code and no status, and it never says whether a change matters: a program reads that from the `field`, the `direction` and the values of each change.

| Field | What it holds |
|---|---|
| `contract` | `1`, the delta's own number |
| `identical` | `true` exactly when the `sha256` of both targets is the same, which is when they are the same certificate. It says nothing about the chain: it can be `true` while `changes` is not empty |
| `before`, `after` | the `at` and the `source` of each observation, as they are in the observation |
| `changes` | what differs, in a fixed order |

### Before and after

The first observation given is `before` and the second is `after`, for the whole document. The two objects at the top level are the legend of the changes, and the `direction` of a change reads in the same sense: `removed` means the value was in `before` and is not in `after`. `before` and `after` say nothing about which observation is older: `before.at` can be later than `after.at`.

### Changes

A change is about one field and has a `direction`:

| Field | What it holds |
|---|---|
| `field` | a path in the target certificate, as the observation names it (`san.dns`, `eku`, `key.size`, `subject.dn`, `sha256`), or `chain`. Open: a program ignores a field it does not know |
| `direction` | `added`, `removed` or `changed`. Closed: a program that does not know a direction cannot tell which side holds the value |
| `before` | the value in `before`. Only for `removed` and `changed` |
| `after` | the value in `after`. Only for `added` and `changed` |

`null` is a value: `key.size` going from `null` to `2048` is `changed`, with both sides present. A field that is not a set and is not the chain is always `changed`, with the value of the observation on each side. The serial, the validity and the fingerprint are fields like any other: two different certificates always have them in `changes`, and nothing in the shape treats them apart.

A delta does not compare `derived`, which follows from the other fields, or `observation.at`, which says when an observation was made and nothing about the certificate. It does not compare `observation.source` either: that is the legend. `contract`, `format`, `target`, `index` and `issuedBy` are positions inside one observation's material and are not compared, and of the certificates other than the target only the `sha256` counts, as the chain.

```json
{
  "contract": 1,
  "identical": false,
  "before": { "at": "2026-09-15T14:02:11Z", "source": { "kind": "file", "ref": "deployed.pem" } },
  "after": { "at": "2026-09-15T14:05:40Z", "source": { "kind": "file", "ref": "renewed.pem" } },
  "changes": [
    { "field": "serial", "direction": "changed", "before": "5C1E8A3F0B7D4E92A6C8F1D2E3B4A590", "after": "2B7F90A1C4D3E6581A9B0C7D8E4F3A21" },
    { "field": "notBefore", "direction": "changed", "before": "2026-07-01T00:00:00Z", "after": "2026-09-15T00:00:00Z" },
    { "field": "notAfter", "direction": "changed", "before": "2026-09-29T00:00:00Z", "after": "2026-12-14T00:00:00Z" },
    { "field": "san.dns", "direction": "removed", "before": "old.example.com" },
    { "field": "san.dns", "direction": "added", "after": "new.example.com" },
    { "field": "sha256", "direction": "changed", "before": "0c9196e013f0d0d1273c1f31c6a7f37beb476b511207f0f15825b9f58ae611e6", "after": "4d7cfeff07ce8782c678b1ed99f3928969b56f2a4927570e3b078f4109fedc42" }
  ]
}
```

### Sets

A set is a list of the observation whose order means nothing: `san.dns`, `san.ip`, `san.email`, `san.uri` and `eku`. A change in a set names only the element that differs, as a string, and there is one change for each: a name that left and a name that arrived are two independent changes, `removed` and `added`, and the delta never merges them into a replacement. A SAN list is never `changed`.

Sets are compared as sets. An element is `added` or `removed` only when it is in the list of one side and not in the other's, and how many times a list repeats an element is not compared: a certificate that lists `a.example` twice and one that lists it once have no SAN change, because both list `a.example`.

`eku` is the one set that can be `null`. The extension absent (`null`) allows any purpose, and the extension present with no usages (`[]`) allows nothing, so a change between `null` and a list carries the whole value of each side, in one `changed` change, because a change that named only the elements that differ could not say `null`:

```json
[
  { "field": "eku", "direction": "changed", "before": ["serverAuth"], "after": null },
  { "field": "eku", "direction": "changed", "before": null, "after": [] },
  { "field": "eku", "direction": "changed", "before": [], "after": null },
  { "field": "eku", "direction": "removed", "before": "clientAuth" }
]
```

Read in order: a list to `null` (the extension was removed), `null` to `[]` (it now allows nothing), `[]` to `null` (it allows anything), and a usage that was dropped from a list that still has others. A list that loses all its usages is one `removed` for each of them and is never `null`. A change from one list to another list is never `changed`: it is the `added` and `removed` usages.

### The chain

The chain is the certificates of an observation other than its target, in the order of its `certificates`. A link is `{ "position", "sha256" }`: its `sha256` says which certificate it is, and its `position` is where it is among those certificates, counted from 0 in its own observation, so a link does not depend on where the target is in the material.

- A link whose `sha256` only `before` sends is `removed`, with its position in `before`. A link whose `sha256` only `after` sends is `added`, with its position in `after`.
- A link replaced by another at the same position is a `removed` and an `added` with the same `position`.
- The links that both sides send, in another relative order, are one `changed` change. `before` and `after` list their `sha256` in the order of each side, and only those: a link that was added or removed is in neither. A link that moves only because another was added or dropped before it is no change.

```json
[
  { "field": "chain", "direction": "removed", "before": { "position": 0, "sha256": "eae8efb355159e69315d5991dbbe5f266ce41dcea9be52c592ed74261fa1242a" } },
  { "field": "chain", "direction": "added", "after": { "position": 0, "sha256": "53bca08dd4a80434eceaccaaea5dd9af3d5d5da11b1fcf646d3cd7f8f774d7b3" } },
  { "field": "chain", "direction": "changed", "before": ["3d48201a582773a82a3d50c40f9ac75c25e8b43ce2b05f9fae455f2ad346725b", "f6b9f54ff067a6356c1c6f31186ec54deb798883fbbfa43df4409b855ab09be8"], "after": ["f6b9f54ff067a6356c1c6f31186ec54deb798883fbbfa43df4409b855ab09be8", "3d48201a582773a82a3d50c40f9ac75c25e8b43ce2b05f9fae455f2ad346725b"] }
]
```

The chain is about what the server or the file sent, not about the target, so `identical` can be `true` while it changes: the same target sent with its intermediate on one side and without it on the other is identical and still has a chain change.

### Order and bytes

`changes` has a fixed order, so that equal comparisons give equal bytes: the fields in the order the schema lists them in the description of `field` (`kind` first, `chain` last), `removed` before `added` before `changed` for one field, and the elements of a list in the order they have in it. `serializeDelta` keeps the order of `changes` and writes the keys of each object in the order of the examples; a key the contract does not name is kept after them, sorted. A side that is `undefined` is written as absent, as `JSON.stringify` writes any property, so `null` is the only way to write a side whose value is null.
