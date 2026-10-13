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
