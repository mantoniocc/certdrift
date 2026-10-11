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
