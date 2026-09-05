# PyBLØCK Watch

A watch-only Bitcoin wallet for Android that looks at **both sides of the BLAKE2b fork
at once**. You give it an extended *public* key; it shows what that key holds on the
BLAKE2b chain and on the classic SHA-256 chain, side by side.

Built for GrapheneOS: no Google Play Services, no push server, no analytics, no
account. Apache-2.0, reproducible, and every line of cryptography is in this repo.

---

## What it does

- **Watch-only, by construction.** There is no signing code anywhere in this app.
  It cannot spend, so an xpub is all it ever asks for and all it could ever leak.
- **Both chains, one key.** BLAKE2b and SHA-256 share a genesis block and Bitcoin's
  whole address scheme — the fork changed the proof-of-work, not key derivation — so
  the same xpub is meaningful on both, and the balances diverge at the fork.
- **xpub, ypub or zpub.** Legacy, wrapped SegWit and native SegWit, detected from the
  SLIP-132 version bytes and explained in the UI.
- **Your own node.** The BLAKE2b side can point at any Electrum server you run.
- **Balance-change notifications** without a push server: the phone asks the Electrum
  server itself, on a visible foreground service you opt into.
- **It explains itself.** The scan is narrated — derivation paths tick past, and the
  gap limit is drawn as a ring that fills and resets — so you can watch how a wallet
  actually finds your coins instead of staring at a spinner.

## Default servers

| Chain | Server | Software |
|---|---|---|
| BLAKE2b | `fulcrum.kilombino.com:17717` | Fulcrum 2.1.2 |
| SHA-256 | `nobip110fulcrum.kilombino.com:50002` | Frigate 1.5.2 |

Both are TLS with **self-signed certificates**, which is normal for Electrum servers
and means CA validation would be meaningless. Instead the app pins: it remembers the
SHA-256 fingerprint it saw first, and if the certificate ever changes it says so and
refuses to continue until you accept the new one deliberately.

The SHA-256 side is a lookup service — find your coins with an xpub — so it does not
offer a custom node. The BLAKE2b side does.

## Security posture

**This app holds no secrets.** That is the whole design, and several decisions follow
from it:

- No signing code, so an xpub cannot be turned into a spend.
- The xpub lives in ordinary app-private storage, not `EncryptedSharedPreferences`.
  Encrypting a non-secret would buy nothing but a dependency on
  `androidx.security:security-crypto`, which is both an alpha and deprecated.
  `allowBackup=false` keeps it off cloud backups; the app sandbox does the rest.
- An xpub **is** privacy-sensitive — it reveals every address you will ever use — and
  the app says so on the first screen.

## Cryptography

There is no crypto dependency in this project. No BouncyCastle, no bdk, no
secp256k1 JNI. All of it is Kotlin in `app/src/main/java/.../crypto/`:

| Piece | Why it is in-tree |
|---|---|
| `Secp256k1.kt` | Public-key arithmetic only (BIP-32 CKDpub). No private keys, no signing, no nonces — so the classic ECDSA footguns do not apply, and a bug produces a wrong address rather than a stolen key. |
| `Ripemd160.kt` | Android ships no RIPEMD-160, and HASH160 needs it. ~120 lines of fully specified, deterministic code with published vectors. |
| `Base58.kt`, `Bech32.kt` | Small, exactly specified encodings. |
| `Bip32.kt` | Public derivation only — there is deliberately no CKDpriv. |

Correctness is pinned by `app/src/test/.../CryptoTest.kt`: the RIPEMD-160
specification vectors, the published BIP-49 and BIP-84 account vectors, and an
Electrum scripthash confirmed against both live servers.

```
./gradlew :app:testDebugUnitTest
```

## Build

```
./gradlew :app:assembleRelease
```

See [PUBLISHING.md](PUBLISHING.md) to cut a signed release, and
[README-REPRODUCIBLE.md](README-REPRODUCIBLE.md) to rebuild the published APK and
check it byte-for-byte.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
