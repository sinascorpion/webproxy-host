# Notices

Webproxy Host is maintained by sinascorpion. The Go application, web interface,
and integration runner are MIT licensed; see LICENSE.

The application downloads and runs the unmodified official Telemt 3.5.14 Linux musl core,
verified against pinned SHA-256 checksums. It is a separate process under its own
license, preserved in LICENSE-TELEMT. Source and build instructions:
https://github.com/telemt/telemt/tree/3.5.14 . This is an independent application,
not an official or endorsed Telemt distribution.

The standalone verification tool tools/probe.py is GPL-3.0-or-later, copyright
2026 sinascorpion, from telegram-web-proxy. See LICENSE-GPL. Its optional
cryptography dependency is needed only for development/integration tests and
is not required by the hosting application.
