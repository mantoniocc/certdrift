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

`entryOfCode(code)` gives the entry of the policy that produces a reason code, `"validityNotEnded"` for `EXPIRED`, and `null` for a code that has no entry: `POLICY_EMPTY`, `RULE_ERROR` and a code this version does not know. It answers for the library's codes. A rule of your own may give one of them too, so a program that has results from both looks at `rule.name` before asking for the entry.

### Matching a private key

`matchesPrivateKey(observation, privateKey, options)` says whether a private key is the key of the certificate an observation targets, which is what a person wants to know before installing a renewed certificate. It gives one result, for the rule `matchesPrivateKey`, in the shape of any result.

```js
import { inspect, matchesPrivateKey } from "certdrift";

const observation = inspect(certificatePem);
const result = matchesPrivateKey(observation, { material: keyPem, passphrase: "…" }, { severity: "fail" });
console.log(result.code, result.status, result.message);
```

`privateKey` is `{ material, passphrase }`. `material` is the text or the bytes of the key's file, and `passphrase` is optional text, for a key that is encrypted. An empty string is a passphrase. The library never reads a file: whoever calls it does. Only PEM is read, so a DER file or a PKCS#12 file is a key that could not be read. `options.severity` is `fail` unless it says `warn`, and any other value is a `TypeError`. `evaluate` takes the same object as `options.privateKey`.

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
| `LIFETIME_USED_EXCEEDED` | `maxLifetimeUsed` | `now - notBefore` is not above the threshold times `notAfter - notBefore` | it is above | the fraction used, unrounded, `null` when `notAfter` is not after `notBefore` / the threshold |
| `EKU_MISSING` | `expectEku` | the target's `eku` is a list that includes every usage | `eku` is `null`, is `[]`, or lacks a usage | `eku` / the usages, by name where there is one |
| `EKU_NOT_PERMITTED` | `ekuAllows` | `eku` is `null`, or a list that includes every usage | `eku` is a list that lacks a usage, which includes `[]` | `eku` / the usages |
| `EKU_FORBIDDEN` | `rejectEku` | `eku` is `null`, `[]` or a list with none of the usages | `eku` lists any of them | `eku` / the usages |
| `SAN_MISSING` | `expectSan` | every name is listed: DNS names in `san.dns`, addresses in `san.ip` | any is not | `{ dns, ip }` the target lists / `{ dns, ip }` the names, as compared |
| `FINGERPRINT_MISMATCH` | `expectFingerprint` | the target's `sha256` is the expected one | it is not | the target's `sha256` / the expected one |
| `TARGET_NOT_END_ENTITY` | `expectKind` | the target's `kind` is `end-entity` | it is any other kind | `kind` / `end-entity` |
| `KEY_MISMATCH` | `matchesPrivateKey` | a private key was read and corresponds to the target's public key | a key was read and does not | the SPKI SHA-256 of the key's public key / the target's `spkiSha256` |
| `KEY_UNREADABLE` | `matchesPrivateKey` | never: a key that can be read gives `KEY_MISMATCH` | the key could not be read: the file holds a certificate, a public key or no private key or more than one, its format or algorithm is not supported, it is encrypted with no passphrase or the passphrase does not decrypt it. The reasons are in "Matching a private key" | none |
| `POLICY_EMPTY` | none | never | the policy has no entry besides the two validity ones and no rule of your own is given. Always `warn`, and `rule` is `null` | none |
| `RULE_ERROR` | none | never | a rule of your own threw, returned a promise or something that is not a result, returned `POLICY_EMPTY` or `RULE_ERROR`, or returned an `actual`, an `expected` or a `rule.value` that JSON cannot hold. Always `fail`, and `rule` is `{ name }` with the name of the rule that failed | none |

`eku` is `null` when the extension is absent, which means Extended Key Usage does not restrict the purpose, not that the certificate is good for everything. That is why there are two rules about it: `expectEku` requires a usage to be listed, and `ekuAllows` only requires that the extension does not forbid it. An extension that is present and lists nothing (`[]`) permits nothing, so both fail on it, each with its own code, and `rejectEku` passes on it.

`kind` is the one the observation gives, which is the one Node.js reads. A CA that carries a known extension twice, or one that does not decode, reads as `end-entity`, so `TARGET_NOT_END_ENTITY` passes for it. The observation now carries a `KIND_UNRELIABLE` warning for that certificate.
<!-- `kind` keeps the value Node.js gives even where a warning says it cannot be trusted, so the limit above holds with or without that warning. -->
