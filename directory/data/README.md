# Public-network bootstrap pins

`mainnet.json` contains the nine authority identities and all 200 fallback
relays from the official Tor Project Arti repository, retrieved over HTTPS on
2026-09-20. The fallback list was generated on 2026-06-25. These are bundled
public bootstrap contacts, never downloaded or replaced at runtime. Their role
is to obtain an authority-signed directory, not to select application paths.

Sources:

- https://gitlab.torproject.org/tpo/core/arti/-/raw/main/crates/tor-dircommon/src/authority.rs
- https://gitlab.torproject.org/tpo/core/arti/-/raw/main/crates/tor-dircommon/data/fallback_dirs.rs

SHA-256 of the retrieved source files:

- authority.rs: `a8f28ffa440739e7fffc49795013b559c78fcb253565c67a5b876b51b2064826`
- fallback_dirs.rs: `e749c1dbc13628a3541e5982d66f7ce70b213b60d4ebf69fcaf1b875a66e9069`

The Tor Project's MIT license notice is included in the repository LICENSE.
Do not learn authority trust anchors from downloaded directory documents or
reduce the configured quorum to the set of signers that happen to respond.
