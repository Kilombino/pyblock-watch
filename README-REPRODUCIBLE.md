# Reproducible build — PyBLØCK Watch

Rebuild the published APK yourself and confirm it matches, byte for byte.

## 1. What is and is not compiled here

This project is **pure JVM/Kotlin + Android Gradle Plugin**. There is no Rust, no
NDK, no `Cargo.toml`, and no `.so` of ours anywhere.

That is the substantive difference from a typical Bitcoin wallet. Wallets usually
depend on prebuilt native libraries from Maven — `libbdkffi.so`, `libsecp256k1-jni.so`
— which are pinned by hash but **not rebuilt**, so the code that touches your keys
stays outside the reproducible surface. Here there is nothing to leave out: secp256k1
arithmetic, RIPEMD-160, Base58Check, Bech32 and BIP-32 derivation are all Kotlin in
`app/src/main/java/com/kilombino/pyblockwatch/crypto/`, compiled from this repo.

The only native code in the APK arrives transitively from Jetpack Compose:
`libandroidx.graphics.path.so`, about 10 KB per ABI, a path-parsing helper with no
cryptographic role. If you want a build with literally zero `.so`, drop Compose.

## 2. Toolchain pins

| Component | Version |
|---|---|
| JDK (build) | Temurin/OpenJDK **17.0.20+8** |
| Android Gradle Plugin | **8.7.3** |
| Gradle (wrapper) | **8.11.1** |
| Kotlin (android + compose) | **2.3.10** |
| compileSdk / targetSdk | **35** / **35** · build-tools **35.0.0** |
| Jetpack Compose | BOM **2024.12.01** |
| R8 / minify | **off** — no obfuscation variance |
| Packaged ABIs | all (no `abiFilters`; nothing native of ours to filter) |

## 3. Dependency pinning

`gradle/verification-metadata.xml` records the SHA-256 of **613 resolved artifacts**.
Gradle verifies every one on each build; a mismatch fails the build rather than
producing a quietly different APK. Inspect or regenerate with:

```
./gradlew --write-verification-metadata sha256 assembleRelease
```

## 4. Build

```
./gradlew clean assembleRelease
# → app/build/outputs/apk/release/app-release-unsigned.apk
```

A keystore is only needed to *sign*. The unsigned APK is what you compare.

## 5. Verified result

Version **0.1.0** (versionCode 1):

```
app-release-unsigned.apk
SHA-256  9c97676adc3625399c222e5958074a4303e12420e79fe01316ec5ff9b3a86b0f
```

Verified three ways, all producing that identical hash:

- two independent clean builds from two separate fresh clones;
- a clone sitting on a **different commit**;
- a **source tarball with no `.git` directory at all**.

That last case is the one that matters and the reason for the `vcsInfo` line in
`app/build.gradle.kts`. By default AGP writes `META-INF/version-control-info.textproto`
into the APK containing the current git commit SHA, which makes the output depend on
git state rather than on source. Anyone verifying from a tarball, a shallow clone or
an exported archive would then get a different hash and reasonably report "does not
reproduce" — for a wallet, a false alarm of that kind is expensive. With the stamp
disabled, the APK is a function of the source alone.

## 6. Comparing against a signed release

The signing block differs by signer by design, so compare the **unsigned** APK:

```
apksigcopier extract published.apk sig.zip
diffoscope your-unsigned.apk published-unsigned.apk
```

Or copy the published signature onto your own build and check the whole file:

```
apksigcopier copy published.apk your-unsigned.apk rebuilt.apk
cmp rebuilt.apk published.apk
```

Do **not** report "does not reproduce" because of the signature — only the signing
block should differ.

## 7. Signing

Releases are signed with APK Signature Scheme **v2 + v3**. v3 carries a rotation
lineage, so the key can be rotated later without users reinstalling and losing their
data. Verify with:

```
apksigner verify -v --print-certs the.apk
```
