# picomemo-tcl

A Tcl 9 extension that wraps [picomemo](https://github.com/mierenhoop/picomemo)
(OMEMO 0.3) one-to-one. This is the upstream source for the binding, in the
same role libdatachannel-tcl plays for rtc: it links statically into zippy's
kitsh and also works as a plain `package require omemo` extension under a
stock `tclsh9.0`.

## Build

```
git submodule update --init --recursive
make
```

The Makefile auto-detects a Tcl 9 install by scanning common
`tclConfig.sh` locations (`/usr/local/lib`, `/usr/lib`, `/usr/lib64`,
`/usr/lib/tcl9.0`, `/opt/homebrew/lib`); mbedcrypto comes from
`pkg-config --libs mbedcrypto` if available, else `-lmbedcrypto`.
Run `make config` to see what was picked.

Override knobs for non-standard trees (e.g. embedding hosts like zippy):

- `TCL_PREFIX=<dir>` - assumes `<dir>/include` and `<dir>/lib` hold the
  Tcl 9 headers and `libtclstub`.
- `TCLCONFIG=<path>` - point at a specific `tclConfig.sh`.
- `TCL_INCLUDE` / `TCL_STUB_LIB` - bypass detection entirely (raw `-I`
  and `-L -l` flags).
- `MBED_PREFIX=<dir>` - assumes `<dir>/include` and `<dir>/lib` for
  mbedcrypto, or set `MBED_INCLUDE` / `MBED_LIB` directly.

Outputs in the source dir:

- `libtcl9omemo<VER>.so`  - shared library, loadable from stock tclsh9.
- `libtcl9omemo<VER>.a`   - static archive, what zippy's kitsh links.
- `pkgIndex.tcl`          - for `package require omemo` in shared-load mode.

The shared library links against whatever `libmbedcrypto` `MBED_LIB`
resolves to (static archive or shared object, depending on what's in
the prefix); the `.a` we ship does not bake in mbedcrypto, so an
embedding host must supply it at the final link.

## API

All commands live in the `::omemo` namespace.

### Module-level

| Tcl                                          | Picomemo / behavior                                      |
| -------------------------------------------- | -------------------------------------------------------- |
| `omemo::version`                             | string `"0.3"` (protocol version, compile-time).         |
| `omemo::fingerprint <ik_bytes>`              | 32-byte IK -> 64 lowercase hex chars in 8 groups of 8.   |
| `omemo::set_storage -load <cmd> -store <cmd>`| registers Tcl callbacks for skipped-key storage.         |
| `omemo::encrypt_message <plaintext>`         | `omemoEncryptMessage`; returns `dict {ct bytes key 32-bytes iv 12-bytes}`. |
| `omemo::decrypt_message <key> <iv> <ct>`     | `omemoDecryptMessage`; returns plaintext bytes.          |

### Store (one per local account)

| Tcl                                          | Picomemo                                                |
| -------------------------------------------- | ------------------------------------------------------- |
| `omemo::store create <name> -device <uint32>`| alloc + tag with device id (required).                  |
| `<name> setup`                               | `omemoSetupStore`                                       |
| `<name> serialize`                           | `omemoSerializeStore`                                   |
| `<name> deserialize <blob>`                  | `omemoDeserializeStore`                                 |
| `<name> identity_pub`                        | `store->identity.pub` (32 bytes)                        |
| `<name> device_id`                           | the uint32 supplied at create time                      |
| `<name> bundle`                              | dict `{ik 32B  spk 32B  spk_id int  spks 64B  prekeys {{id <n> pk 32B} ...}}` |
| `<name> rotate_signed_prekey`                | `omemoRotateSignedPreKey`                               |
| `<name> refill_prekeys`                      | `omemoRefillPreKeys`                                    |
| `<name> mark_prekey_used <pk_id>`            | zeroes the matching `prekeys[i]` entry                  |
| `<name> destroy`                             | secure-wipe + free + delete command                     |

### Session (one per remote `(jid, device)`)

| Tcl                                                                                        | Picomemo                                                |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| `omemo::session create <name> -jid <bare> -device <uint32>`                                | alloc + tag with `(jid, device)` for callback context.  |
| `<name> initiate <store> -ik <32B> -spk <32B> -spks <64B> -pk <32B> -spk-id <int> -pk-id <int>` | `omemoInitiateSession` (raw 32-byte keys; the shim prepends the 0x05 OMEMO prefix internally). |
| `<name> serialize`                                                                         | `omemoSerializeSession`                                 |
| `<name> deserialize <blob>`                                                                | `omemoDeserializeSession`                               |
| `<name> encrypt_key <payload>`                                                             | `omemoEncryptKey`; returns `dict {p bytes isprekey 0|1}` |
| `<name> decrypt_key <store> <bytes> -prekey 0|1`                                           | `omemoDecryptKey`; returns the decrypted payload bytes  |
| `<name> heartbeat <store>`                                                                 | `omemoHeartbeat`; returns bytes or empty if no heartbeat needed |
| `<name> used_prekey_id`                                                                    | `session->usedpk_id`, or `{}` if zero                   |
| `<name> remote_identity`                                                                   | `session->remoteidentity` (32 bytes)                    |
| `<name> destroy`                                                                           | secure-wipe + free + delete command                     |

## Storage callbacks

`omemo::set_storage -load <cmd> -store <cmd>` registers two Tcl prefixes that
picomemo's skipped-key machinery calls.

`-load` is invoked as `$cmd <jid> <device> <dh> <nr>`:
- Return the stored 32-byte message key as bytes if found, **and delete the
  row in the same call**. picomemo does not issue a separate delete signal;
  the load callback owns delete-on-read.
- Return the empty value `{}` if no such key exists.
- Any Tcl `error` propagates out as `{OMEMO ESTORAGE}` through the originating
  `omemo::session` call.

`-store` is invoked as `$cmd <jid> <device> <dh> <nr> <mk> <n>`:
- `<mk>` is the 32-byte key to store.
- `<n>` is the total number of keys picomemo plans to ask you to skip in this
  batch. Callers can use this to enforce a `MAX_SKIPPED_KEYS` cap and `error`
  out if abusive. (Picomemo's reference passes the same number through.)
- The return value is ignored.
- Any Tcl `error` propagates out as `{OMEMO ESTORAGE}`.

There is one global `(load, store)` pair; the shim does NOT own a database
connection, links no libsqlite3, and has zero opinion about backing store.
`tests/test_helpers.tcl` shows a reference SQLite implementation.

Storage callbacks fire only from `omemo::session encrypt_key` /
`decrypt_key` / `heartbeat`. A call that triggers them before
`omemo::set_storage` was invoked surfaces as `{OMEMO ESTATE}`.

## Error codes

All errors throw with an `errorCode` list of the form `{OMEMO <TAG>}`. Tags:

| Tag         | Origin                                               |
| ----------- | ---------------------------------------------------- |
| `EPROTOBUF` | malformed protobuf in input                          |
| `ECRYPTO`   | crypto primitive failure                             |
| `ECORRUPT`  | data corruption detected                             |
| `EPARAM`    | invalid argument (wrong size, missing option, etc.)  |
| `ESTATE`    | function called in wrong order                       |
| `EKEYGONE`  | message key not available (load returned not-found)  |
| `ESTORE`    | store-level failure                                  |
| `EUSER`     | unmapped user-callback failure                       |
| `ESTORAGE`  | Tcl-level `-load` / `-store` callback threw         |

Use `try { ... } trap {OMEMO ESTORAGE} {msg opts} { ... }` to handle storage
errors structurally; the original `error` message from the callback is
preserved as the result.

## Fingerprint format

picomemo defines no fingerprint helper of its own. The format here is the
de-facto OMEMO 0.3 client display - the raw 32-byte identity key rendered as
64 lowercase hex chars in 8 space-separated groups of 8, the same way
Conversations, Dino, and Gajim show it:

```
deadbeef cafebabe 01234567 89abcdef 11111111 22222222 33333333 44444444
```

If you need a different format (SHA-256 of the serialized key, etc.), do the
hashing on the Tcl side.

## Pinned picomemo commit

```
7ac189ad2461d99b765abcc28e8439e81a047bc8
```

To bump, `cd picomemo && git fetch && git checkout <new-sha>` and commit the
submodule pointer.
