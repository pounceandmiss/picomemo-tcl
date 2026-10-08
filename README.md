# picomemo-tcl

Tcl 9 bindings for [picomemo](https://github.com/mierenhoop/picomemo) (OMEMO 0.3).
Builds as a loadable extension (`package require omemo`) and as a static
archive for embedding.

## Build

```
git submodule update --init --recursive
make
```

Needs Tcl 9 and mbedcrypto. `make config` shows what was detected. Overrides:

- `TCLCONFIG=<path>` or `TCL_PREFIX=<dir>`, or set `TCL_INCLUDE` / `TCL_STUB_LIB` directly
- `MBED_PREFIX=<dir>`, or set `MBED_INCLUDE` / `MBED_LIB` directly
- `OUTDIR=<dir>` for out-of-tree builds

Produces `libtcl9omemo<VER>.so`, `libtcl9omemo<VER>.a` and `pkgIndex.tcl`.
The `.a` does not include mbedcrypto; link it yourself.

## API

Everything is in `::omemo`. Byte arguments are Tcl byte arrays.

### Module

| Command                                   | Result                                     |
| ----------------------------------------- | ------------------------------------------ |
| `version`                                 | `"0.3"`                                    |
| `random <n>`                              | `n` random bytes (1..4096)                 |
| `fingerprint <ik>`                        | 32-byte key as 8 groups of 8 hex chars     |
| `set_storage -load <cmd> -store <cmd>`    | see below                                  |
| `encrypt_message <plaintext>`             | dict `{ct key iv}`                         |
| `decrypt_message <key> <iv> <ct>`         | plaintext                                  |
| `media_encrypt <plaintext>`               | AES-256-GCM (XEP-0454), dict `{ct key iv}` |
| `media_decrypt <key> <iv> <ct>`           | plaintext                                  |

### Store

`omemo::store create <name> -device <uint32>`, then:

| Subcommand                 |                                                        |
| -------------------------- | ------------------------------------------------------ |
| `setup`                    | generate identity and prekeys                          |
| `serialize`                | blob                                                   |
| `deserialize <blob>`       |                                                        |
| `identity_pub`             | 32 bytes                                               |
| `device_id`                |                                                        |
| `bundle`                   | dict `{ik spk spk_id spks prekeys {{id pk} ...}}`      |
| `rotate_signed_prekey`     |                                                        |
| `refill_prekeys`           |                                                        |
| `mark_prekey_used <id>`    |                                                        |
| `destroy`                  | wipe and free                                          |

Subcommands other than `setup`, `deserialize`, `device_id` and `destroy` return
`{OMEMO ESTATE}` until the store is set up.

### Session

`omemo::session create <name> -jid <bare> -device <uint32>`, then:

| Subcommand                                                                  |                                    |
| --------------------------------------------------------------------------- | ---------------------------------- |
| `initiate <store> -ik <32> -spk <32> -spks <64> -pk <32> -spk-id <n> -pk-id <n>` | keys without the 0x05 prefix  |
| `serialize` / `deserialize <blob>`                                          |                                    |
| `encrypt_key <payload>`                                                     | dict `{p isprekey}`                |
| `decrypt_key <store> <bytes> -prekey 0\|1`                                  | payload                            |
| `heartbeat <store>`                                                         | bytes, or empty if none needed     |
| `used_prekey_id`                                                            | id, or empty                       |
| `remote_identity`                                                           | 32 bytes                           |
| `destroy`                                                                   | wipe and free                      |

## Storage callbacks

Skipped message keys are stored through two callbacks set with
`omemo::set_storage`. They are per interpreter: each interp that loads the
package has its own pair. They must be set before any session call that might
need them, otherwise you get `{OMEMO ESTATE}`. Callbacks must not destroy or
re-enter the session/store being decrypted; doing so returns `{OMEMO ESTATE}`.

- `-load`: called as `cmd jid device dh nr`. Return the 32-byte key and delete
  it, or return `{}` if not found.
- `-store`: called as `cmd jid device dh nr mk n`. `n` is how many keys are
  being skipped in this batch, so you can refuse if it's too many. Return
  value is ignored.

An error in either callback comes out as `{OMEMO ESTORAGE}` with the original
message. `tests/test_helpers.tcl` has an SQLite example.

## Errors

Errors have `errorCode` `{OMEMO <tag>}`:

`EPROTOBUF`, `ECRYPTO`, `ECORRUPT`, `EPARAM`, `ESTATE`, `EKEYGONE`, `ESTORE`,
`EUSER`, `ESTORAGE`.

## picomemo version

Pinned at `7ac189ad2461d99b765abcc28e8439e81a047bc8` via the submodule.
