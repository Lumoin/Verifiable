# HMAC + symmetric-key + cryptography-registry migration — implementation landed

This document is the post-landing handoff for the rev-2 HMAC MD. It catalogues what
is now in place, where each piece lives, how the wiring works, and what is still
open for downstream consumers (DPoP nonces, JWS HS-family, JWE composite AEAD,
COSE_Mac0/Mac, HKDF, TPM2_HMAC backend, etc.).

If you are continuing the original DPoP MD or starting any new HMAC-using or
hash-using consumer, you can take everything below as ground truth without reading
the MD that produced it — these facts replace the MD.

---

## 1. Summary of landed commits

Branch: `oauth-subsystem` (unpushed, 11 commits ahead of where it diverged from
`main`).

Newest commits relevant to this work:

```
c8aec01 TPM stack uniform async + registry-routed crypto                 ← Bucket C
66ace3b Data-integrity HMAC + SHA-256 sites routed through registry      ← Bucket D
f282218 SchnorrZkp + EcMath multi-segment migration                      ← Bucket B
0039efe Async-everywhere ComputeDigest + ReadOnlySequence HMAC + multi-segment paths   ← Foundation
4c88cfd Digest bypass migrations + TPM/SchnorrZkp inline retention comments
0ff5f3b ContentEncryptionKey composition refactor + AEAD widening
f853efa HMAC primitives + Microsoft backend + SymmetricKeyMemory
83710ac chore: refresh package versions and lockfiles
bcfe8c4 OAuth phase 6: DPoP (RFC 9449) primitives + client-side proof attachment
```

Test count: **2541 passing, 0 failing, 20 skipped** (the 20 are pre-existing
`Assert.Inconclusive` placeholders for unimplemented features like did:key
resolution and OpenID Federation).

---

## 2. The architectural shape now in place

All cryptographic primitives — digest, HMAC, signing, verification, nonce
generation, salt generation — go through `CryptographicKeyFactory`-registered
delegates dispatched via `CryptographicKeyEvents`. There are no exemptions.

Every primitive is **asynchronous**. The async surface is not a stylistic choice;
it is required for:

- Network-bound KMS / HSM backends (AWS KMS, Azure Key Vault, GCP KMS).
- TPM2_HMAC and TPM2_Hash via Linux `/dev/tpmrm0` with kernel-level async I/O
  (epoll/io_uring).
- The Linux TPM transport now genuinely awaits the kernel TPM round-trip.

Software backends (the in-tree Microsoft backend) return synchronously-completed
`ValueTask<T>`; the overhead is a struct return with state-machine elision.

The **input shape for digest and HMAC** is `ReadOnlySequence<byte>` — unifies
single-segment fast path (`input.IsSingleSegment` + `FirstSpan`) and multi-segment
streaming via `IncrementalHash.AppendData(segment.Span)` iteration. One-shot
callers wrap `ReadOnlyMemory<byte>` in `new ReadOnlySequence<byte>(memory)` via
convenience overloads at zero cost.

The **input shape for signing/verification** stays `ReadOnlyMemory<byte>` —
signatures are computed over one block, not over a stream.

The **algorithm family** (SHA-256/384/512/1) is carried in the `Tag` as a BCL
`HashAlgorithmName`, not as a `CryptoAlgorithm` enum value. Backends dispatch on
the `HashAlgorithmName` internally.

---

## 3. New types — full catalogue

All of these live in `src/Verifiable.Cryptography/` unless noted.

### 3.1 Key wrappers

| Type | File | Purpose |
|---|---|---|
| `SymmetricKeyMemory` | `SymmetricKeyMemory.cs` | Broad symmetric key wrapper, parallel to `PrivateKeyMemory`. Holds HMAC keys, persistent AEAD keys, KDF input keys, anything where the bytes are "key material with Tag". `Purpose` distinguishes uses. |
| `SymmetricKey` | `SymmetricKey.cs` | Bound-key wrapper parallel to `PrivateKey`. Holds `SymmetricKeyMemory` + bound `ComputeHmacDelegate` + bound `VerifyHmacDelegate`. Long-lived keys can be wrapped once and reused. |
| `ContentEncryptionKey` | `Aead/ContentEncryptionKey.cs` | Composition wrapper (does **not** inherit from `SymmetricKeyMemory`) with enforced single-use semantics. `UseKey()` atomically transfers the inner key; second call throws. Used for ephemeral CEKs derived per AEAD operation. See section 5.3 for the type-system rationale. |

### 3.2 Value wrappers (outputs)

| Type | File | Purpose |
|---|---|---|
| `HmacValue` | `HmacValue.cs` | Output of HMAC compute, parallel to `DigestValue`. Implements `IEquatable<HmacValue>` with byte-level comparison; `Length` property; OTel-tagged Dispose. |
| `DigestValue` | `DigestValue.cs` (pre-existing) | Output of digest compute. Now produced by the async `ComputeDigestDelegate`. `Length` property; `AsReadOnlySpan()` / `AsReadOnlyMemory()` on the `SensitiveMemory` base. |

### 3.3 Delegates

| Delegate | File | Signature |
|---|---|---|
| `ComputeDigestDelegate` | `EntropyDelegates.cs` | `ValueTask<(DigestValue, CryptoEvent?)> (ReadOnlySequence<byte> input, int outputByteLength, Tag tag, MemoryPool<byte> pool, FrozenDictionary<string, object>? context, CancellationToken)` |
| `ComputeHmacDelegate` | `HmacDelegates.cs` | `ValueTask<(HmacValue, CryptoEvent?)> (ReadOnlySequence<byte> message, ReadOnlyMemory<byte> keyBytes, int outputByteLength, Tag tag, MemoryPool<byte> pool, FrozenDictionary<string, object>? context, CancellationToken)` |
| `VerifyHmacDelegate` | `HmacDelegates.cs` | `ValueTask<(bool IsValid, CryptoEvent?)> (ReadOnlySequence<byte> message, ReadOnlyMemory<byte> keyBytes, ReadOnlyMemory<byte> expectedMac, Tag tag, MemoryPool<byte> pool, FrozenDictionary<string, object>? context, CancellationToken)` |
| `SigningDelegate` | (pre-existing) | Unchanged: `ReadOnlyMemory<byte>` input, async. |
| `VerificationDelegate` | (pre-existing) | Unchanged: `ReadOnlyMemory<byte>` input, async. |

### 3.4 Dispatchers (the public API)

In `CryptographicKeyEvents.cs`:

```csharp
ValueTask<DigestValue> ComputeDigestAsync(
    ReadOnlySequence<byte> input,
    int outputByteLength, Tag tag, MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    string? qualifier = null,
    CancellationToken cancellationToken = default);

ValueTask<DigestValue> ComputeDigestAsync(
    ReadOnlyMemory<byte> input,                            // convenience overload
    int outputByteLength, Tag tag, MemoryPool<byte> pool, ...);

DigestValue ComputeDigestSyncBridge(
    ReadOnlyMemory<byte> input,                            // sync-only callers
    int outputByteLength, Tag tag, MemoryPool<byte> pool, ...);

ValueTask<HmacValue> ComputeHmacAsync(
    ReadOnlySequence<byte> message, ReadOnlyMemory<byte> keyBytes,
    int outputByteLength, Tag tag, MemoryPool<byte> pool, ...);

ValueTask<HmacValue> ComputeHmacAsync(
    ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> keyBytes,
    int outputByteLength, Tag tag, MemoryPool<byte> pool, ...);  // convenience

ValueTask<bool> VerifyHmacAsync(
    ReadOnlySequence<byte> message, ReadOnlyMemory<byte> keyBytes,
    ReadOnlyMemory<byte> expectedMac,
    int outputByteLength, Tag tag, MemoryPool<byte> pool, ...);

ValueTask<bool> VerifyHmacAsync(
    ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> keyBytes,
    ReadOnlyMemory<byte> expectedMac,
    int outputByteLength, Tag tag, MemoryPool<byte> pool, ...); // convenience
```

`ComputeDigestSyncBridge` exists for callers that genuinely cannot propagate
async (pure-math primitives like `ConcatKdf`, `JwkThumbprintUtilities`, PKCE
generation). It asserts the underlying `ValueTask` is already completed; if a
hardware-async backend is registered, it throws rather than block. Default to
async; only use the sync bridge when async propagation would be punitive (e.g.
inside a sync mathematical pipeline).

### 3.5 Extension methods (consumer surface)

In `KeyExtensions.cs`:

```csharp
// On SymmetricKeyMemory:
ValueTask<HmacValue> ComputeHmacAsync(this SymmetricKeyMemory key,
    ReadOnlySequence<byte> message, int outputByteLength,
    ComputeHmacDelegate hmacDelegate, MemoryPool<byte> pool, ...);

ValueTask<HmacValue> ComputeHmacAsync(this SymmetricKeyMemory key,
    ReadOnlyMemory<byte> message, int outputByteLength,
    ComputeHmacDelegate hmacDelegate, MemoryPool<byte> pool, ...);

ValueTask<bool> VerifyHmacAsync(this SymmetricKeyMemory key,
    ReadOnlySequence<byte> message, HmacValue expectedMac,
    VerifyHmacDelegate verifyDelegate, MemoryPool<byte> pool, ...);

// ... and overloads accepting ReadOnlyMemory<byte> message and/or
// ReadOnlyMemory<byte> expectedMacBytes.
```

Use these when you hold the key as `SymmetricKeyMemory` and want the closure-free
`WithKeyBytesAsync` pattern; use `CryptographicKeyEvents.ComputeHmacAsync` when
you only have raw key bytes (`ReadOnlyMemory<byte>`).

### 3.6 Tag constants

In `CryptoTags.cs`:

```csharp
public static Tag Sha256Digest { get; }    // HashAlgorithmName.SHA256 + Purpose.Digest
public static Tag Sha384Digest { get; }
public static Tag Sha512Digest { get; }

public static Tag HmacSha256Key { get; }   // HashAlgorithmName.SHA256 + Purpose.Hmac
public static Tag HmacSha384Key { get; }
public static Tag HmacSha512Key { get; }
public static Tag HmacSha256Value { get; }
public static Tag HmacSha384Value { get; }
public static Tag HmacSha512Value { get; }
```

The HMAC `Key` vs `Value` distinction is type-system clarity at call sites; the
Tag bytes are equivalent.

**SHA-1 is intentionally absent from `CryptoTags`.** SHA-1 is supported by the
backends for TPM session protocol compatibility (TPM 2.0 spec allows SHA-1
session-key algorithms). Code that needs SHA-1 composes the Tag inline:

```csharp
Tag tag = new Tag(new Dictionary<Type, object>
{
    [typeof(HashAlgorithmName)] = HashAlgorithmName.SHA1,
    [typeof(Purpose)] = Purpose.Hmac,
    [typeof(EncodingScheme)] = EncodingScheme.Raw,
    [typeof(MaterialSemantics)] = MaterialSemantics.Direct
});
```

New protocol code (DPoP, JWS HS-family, JWE PBES2, COSE_Mac) should never need
SHA-1; use the `CryptoTags` constants.

### 3.7 Helper: `BufferSegment`

In `BufferSegment.cs`:

```csharp
public sealed class BufferSegment : ReadOnlySequenceSegment<byte>
{
    public BufferSegment(ReadOnlyMemory<byte> memory) { Memory = memory; }
    public BufferSegment Append(ReadOnlyMemory<byte> memory) { ... }
}
```

Standard pattern for building multi-segment `ReadOnlySequence<byte>`:

```csharp
BufferSegment first = new(segment0);
BufferSegment last = first.Append(segment1).Append(segment2);
ReadOnlySequence<byte> input = new(first, 0, last, last.Memory.Length);
```

Used by SchnorrZkp's challenge hash and TpmCommandExecutor's parameter hashing.
Any consumer that builds multi-segment input (RDF canonicalization, KERI event
log replay, large compound digests) follows the same pattern.

---

## 4. Backends

### 4.1 Microsoft backend

`src/Verifiable.Microsoft/MicrosoftHmacFunctions.cs` — implements both
`ComputeHmacDelegate` and `VerifyHmacDelegate`:

- Single-segment fast path: `HMACSHA256.HashData(key, message, destination)` and
  family.
- Multi-segment path: `IncrementalHash.CreateHMAC(algorithmName, key)` + iterate
  `AppendData(segment.Span)`.
- Supports SHA-1/256/384/512. CA5350 (weak crypto) suppressed with justification
  pointing to TPM session protocol compatibility.
- Verify uses `CryptographicOperations.FixedTimeEquals`.

`src/Verifiable.Microsoft/MicrosoftEntropyFunctions.cs` — `ComputeDigestAsync`
follows the same single-segment-fast-path / multi-segment-IncrementalHash pattern.
Supports SHA-1/256/384/512.

Both backends emit `CryptoEvent` (`HmacComputedEvent`, `HmacVerifiedEvent`,
`DigestComputedEvent`) and stamp the Tag via `CryptoProviderInstrumentation`.

### 4.2 BouncyCastle and NSec backends

**Not yet implemented for HMAC** — mechanical follow-up of ~50 lines each
(see section 8). The Microsoft backend is sufficient for everything in scope.

### 4.3 Registration

In application startup (or test setup):

```csharp
CryptographicKeyFactory.RegisterFunction(
    typeof(ComputeDigestDelegate),
    (ComputeDigestDelegate)MicrosoftEntropyFunctions.ComputeDigestAsync);

CryptographicKeyFactory.RegisterFunction(
    typeof(ComputeHmacDelegate),
    (ComputeHmacDelegate)MicrosoftHmacFunctions.ComputeHmacAsync);

CryptographicKeyFactory.RegisterFunction(
    typeof(VerifyHmacDelegate),
    (VerifyHmacDelegate)MicrosoftHmacFunctions.VerifyHmacAsync);
```

This is already done in `test/Verifiable.Tests/TestInfrastructure/TestSetup.cs`
under `InitializeEntropyFunctions` and `InitializeHmacFunctions`. Use that file
as the reference for production wiring.

---

## 5. Patterns and idioms

### 5.1 One-shot digest (DPoP `ath`, JWK thumbprint, PKCE, SD-JWT disclosures)

```csharp
using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
    inputBytes,                          // byte[] or ReadOnlyMemory<byte>
    outputByteLength: 32,
    tag: CryptoTags.Sha256Digest,
    pool: pool,
    cancellationToken: cancellationToken).ConfigureAwait(false);

string encoded = base64UrlEncoder(digest.AsReadOnlySpan());
```

Dispose discipline: `using DigestValue` returns the pooled buffer when the value
goes out of scope. Always `using` the result.

### 5.2 One-shot HMAC

```csharp
using HmacValue mac = await CryptographicKeyEvents.ComputeHmacAsync(
    message: messageBytes,               // ReadOnlyMemory<byte>
    keyBytes: hmacKey,                   // ReadOnlyMemory<byte>
    outputByteLength: 32,
    tag: CryptoTags.HmacSha256Value,
    pool: pool,
    cancellationToken: cancellationToken).ConfigureAwait(false);
```

For verify:

```csharp
bool valid = await CryptographicKeyEvents.VerifyHmacAsync(
    message: messageBytes,
    keyBytes: hmacKey,
    expectedMac: receivedMacBytes,
    outputByteLength: 32,                // size of receivedMacBytes
    tag: CryptoTags.HmacSha256Value,
    pool: pool,
    cancellationToken: cancellationToken).ConfigureAwait(false);
```

The verify uses `FixedTimeEquals` internally. Never compare HMAC values with
`SequenceEqual` or `==` at the consumer level.

### 5.3 Multi-segment hash (concatenate without pre-buffering)

```csharp
BufferSegment first = new(headerOwner.Memory[..headerLength]);
BufferSegment last = first;
foreach(var chunk in chunks)
{
    last = last.Append(chunk.Memory[..chunk.Length]);
}
ReadOnlySequence<byte> input = new(first, 0, last, last.Memory.Length);

using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
    input, outputByteLength: 32, tag: CryptoTags.Sha256Digest,
    pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);
```

The per-segment buffers (`headerOwner`, `chunks[i]`) must remain alive until the
`await` returns. Use `using` declarations or a `try/finally` block to dispose
them after the digest computation.

### 5.4 AEAD with ephemeral CEK

The CEK is single-use:

```csharp
using ContentEncryptionKey cek = await deriveCekDelegate(sharedSecret, ...);
using SymmetricKeyMemory key = cek.UseKey();
AeadEncryptResult result = await aeadEncryptDelegate(plaintext, key, aad, pool);
//A second cek.UseKey() throws InvalidOperationException.
```

Composition (not inheritance) was a deliberate choice: a `ContentEncryptionKey`
cannot be silently passed to a parameter typed `SymmetricKeyMemory`, so the
single-use signal cannot be lost via type slicing. See the `ContentEncryptionKey`
xmldoc for the full decision-matrix narrative including why this differs from
`Nonce.UseNonce()`'s observable-but-non-enforced semantics.

### 5.5 Persistent AEAD key (DPP carriers, eIDAS encryption key)

Use `SymmetricKeyMemory` directly with `Purpose.Encryption` — no `UseKey()`
single-use ceremony. The same key encrypts many payloads over its rotation
lifetime.

### 5.6 Sync-bridge for pure math

```csharp
using DigestValue digest = CryptographicKeyEvents.ComputeDigestSyncBridge(
    input,                               // ReadOnlyMemory<byte>
    outputByteLength: 32,
    tag: CryptoTags.Sha256Digest,
    pool: pool);
```

Asserts the underlying `ValueTask` is already completed (i.e. the registered
backend is software). Throws if a hardware-async backend is registered. Use only
inside genuinely-sync pipelines (`ConcatKdf.Derive`, `JwkThumbprintUtilities.
ComputeECThumbprint`, PKCE generation).

---

## 6. Migrations that landed (consumer-side reference)

If you are looking for "how did X get migrated" — this is the index.

### 6.1 One-shot digest migrations (Bucket A foundation, 0039efe)

| Site | File | Notes |
|---|---|---|
| DPoP `ath` claim | `src/Verifiable.OAuth/Dpop/DpopProofValidation.cs` `ComputeAthAsync` | Async, returns `string` |
| JWK thumbprint | `src/Verifiable.JCose/JwkThumbprintUtilities.cs` `ComputeSha256HashAsync` | Async helper |
| KB-JWT `sd_hash` | `src/Verifiable.OAuth/Oid4Vp/Wallet/KbJwtIssuance.cs` `ComputeSdHashAsync` | Async |
| SD-JWT disclosure hash | `src/Verifiable.Json/SdJwtPathExtraction.cs` `ComputeHashAsync` | Async, dispatches SHA-256/384/512 |
| ConcatKdf inner SHA-256 | `src/Verifiable.Cryptography/ConcatKdf.cs` | Uses `ComputeDigestSyncBridge` (sync math) |
| PKCE challenge | `src/Verifiable.OAuth/Pkce/Pkce.cs`, `PkceGeneration.cs` | Uses `ComputeDigestSyncBridge` |
| Auth-code endpoints | `src/Verifiable.OAuth/AuthCode/AuthCodeEndpoints.cs` `ComputeDigestBase64Url` | Uses sync bridge (API stability) |
| SD-JWT VP token | `src/Verifiable.OAuth/Oid4Vp/Server/SdJwtVpTokenVerification.cs` | Direct delegate-invoke site (async) |
| Data-integrity (presentation, credential) | `src/Verifiable.Core/Model/DataIntegrity/PresentationDataIntegrityExtensions.cs`, `CredentialDataIntegrityExtensions.cs` | Multiple sites, async |

### 6.2 Schnorr ZKP migration (Bucket B, f282218)

`src/Verifiable.Cryptography/Secdsa/SchnorrZkp.cs`:

- `Generate` / `Verify` → `GenerateAsync` / `VerifyAsync`, threading
  `MemoryPool<byte>` + `CancellationToken`.
- `ComputeChallengeHashAsync` builds multi-segment `ReadOnlySequence<byte>` via
  `BufferSegment` over pool-rented per-point encodings.
- `EcMath.EncodePointUncompressedInto(EcPoint, Span<byte>)` overload added to
  write directly into pool-rented buffers without allocation.

### 6.3 Data-integrity HMAC + SHA-256 (Bucket D, 66ace3b)

- `src/Verifiable.Core/Model/DataIntegrity/BlankNodeRelabeling.cs`:
  - Local sync `byte[]`-returning `HmacComputeDelegate` deleted.
  - Unused `BlankNodeRelabelDelegate` and `CreateRelabeler` factory deleted (dead code).
  - `RelabelNQuad` / `RelabelNQuadWithMap` / `RelabelNQuads` / `RelabelNQuadsWithMap`
    → async, accept `Verifiable.Cryptography.ComputeHmacDelegate` +
    `MemoryPool<byte>` + `CancellationToken`.

- `src/Verifiable.Core/Model/DataIntegrity/PreparedNQuadStatements.cs`:
  - `Prepare` → `PrepareAsync` with the new delegate shape.

- `src/Verifiable.Core/Model/DataIntegrity/CredentialEcdsaSd2023Extensions.cs`:
  - 5 HMAC sites resolve `ComputeHmacDelegate` once near the top of each method
    via a small `ResolveHmacDelegate()` helper.
  - 6 SHA-256 sites migrate to `await CryptographicKeyEvents.ComputeDigestAsync`
    with `CryptoTags.Sha256Digest`. Hashes flow as `using DigestValue` and copy
    out to `byte[]` only at the `BaseProofResult` / `HolderProofContext` wire-format
    boundary.

The W3C VC DI ECDSA test vectors (Examples 75 → 76, labels
`u4YIOZn1...`, `u3Lv2...`, `uVkUu...`) verify byte-equivalence.

### 6.4 TPM stack uniform async (Bucket C, c8aec01)

- `src/Verifiable.Tpm/TpmDevice.cs`:
  - `Submit` → `SubmitAsync(ReadOnlyMemory<byte>, MemoryPool<byte>, CancellationToken)`.
  - Linux `FileStream` opened with `isAsync: true` → genuine async I/O against
    `/dev/tpmrm0`.
  - Windows TBS `Tbsip_Submit_Command` wrapped in `ValueTask.FromResult`
    (platform-genuine sync; thread blocks on Windows only).
  - `TpmSubmitHandler` delegate updated to the new async shape.

- `src/Verifiable.Tpm/Infrastructure/TpmCommandExecutor.cs`:
  - `Execute<T>` → `ExecuteAsync<T>` with `CancellationToken`.
  - Parameter hashing (cpHash + rpHash) routes through
    `CryptographicKeyEvents.ComputeDigestAsync` over multi-segment
    `ReadOnlySequence<byte>` (command-code header || handles || parameters).
  - Tag composed inline with `HashAlgorithmName` because the TPM session
    algorithm is dynamic at runtime.
  - Buffers that need to survive across awaits flip from `stackalloc` to
    pool-rented `IMemoryOwner<byte>`. Writers stay sync inside scoped blocks
    (`TpmWriter` is a `ref struct`).

- `src/Verifiable.Tpm/Infrastructure/Sessions/TpmSessionBase.cs`:
  - Virtual API restructured to **precompute/write split** (because
    `WriteAuthCommand(ref TpmWriter, ...)` cannot cross await):
    - `PrepareAuthHmacAsync(ReadOnlyMemory<byte> cpHash, ...)` → `Tpm2bAuth?`
      (async; returns null for password sessions).
    - `WriteAuthCommand(ref TpmWriter writer, Tpm2bAuth? precomputedHmac)` (sync).
    - `VerifyAndUpdateAsync(TpmsAuthResponse, ReadOnlyMemory<byte> rpHash, ...)` → `bool` (async).

- `src/Verifiable.Tpm/Infrastructure/Sessions/TpmSession.cs`:
  - HMAC routed through `CryptographicKeyEvents.ComputeHmacAsync` with the Tag
    composed inline using `HashAlgorithmName`.
  - Empty HMAC key supported (unbound/unsalted sessions with no authValue) per
    RFC 2104.

- `src/Verifiable.Tpm/Infrastructure/Sessions/TpmPasswordSession.cs`:
  - `PrepareAuthHmacAsync` returns null (no HMAC computation).
  - `VerifyAndUpdateAsync` returns true (no response HMAC to verify).

- Production extension callers propagate async:
  - `TpmDeviceExtensions.ReadAllPcrsAsync` (was `ReadAllPcrs`).
  - `TpmDeviceExtensions.GetInfoAsync` (was `GetInfo`).
  - `TpmSecdsaExtensions.EcdhZGenAsync` (was `EcdhZGen`).
  - `VerifiableOperations.GetTpmInfoAsync` / `GetTpmInfoAsJsonAsync`; CLI
    (`Program.cs`) and MCP server (`VerifiableMcpServer.cs`) updated.

All TPM-interacting test methods (~41 total) migrated to `async Task` with
`TestContext.CancellationToken` threaded through every `ExecuteAsync` call.

---

## 7. Verification recipe

The MD's section 6.13 grep is the post-landing audit. Run from repo root:

```bash
grep -rn "SHA256\.HashData\|SHA256\.TryHashData\|SHA384\.HashData\|SHA512\.HashData\|SHA1\.HashData\|HMACSHA256\.HashData\|IncrementalHash\.CreateHash\|IncrementalHash\.CreateHMAC" src/ --include='*.cs'
```

Allowed (intentional) matches:

- `src/Verifiable.Microsoft/MicrosoftHmacFunctions.cs` — backend implementation
  (this IS the registered delegate).
- `src/Verifiable.Microsoft/MicrosoftEntropyFunctions.cs` — backend implementation.
- `src/Verifiable.BouncyCastle/BouncyCastleCryptographicFunctions.cs` lines
  ~904-906 — internal ECDSA hashing (not bypass at the library layer).
- `src/Verifiable.Cryptography/HashFunctionDelegate.cs`, `DigestValue.cs` — xmldoc
  references only.

Anything else is a bypass; treat as a bug.

---

## 8. What is still open (post-landing roadmap)

Each of these is its own work item; none are blockers for new consumers.

### 8.1 Backends to add

- **BouncyCastle HMAC backend** (`Verifiable.BouncyCastle.BouncyCastleHmacFunctions`) —
  ~50 lines implementing `ComputeHmacDelegate` and `VerifyHmacDelegate` using
  BouncyCastle's `Org.BouncyCastle.Crypto.Macs.HMac`. Useful for FIPS-mode
  environments. Mechanical follow-up.
- **NSec HMAC backend** — `NSec.Cryptography.MacAlgorithm.HmacSha256/384/512`.
  Mechanical follow-up.
- **TPM2_HMAC backend** — registers `Verifiable.Tpm.TpmHmacFunctions.ComputeHmacAsync`
  against the registry so HMAC keys can reside in the TPM. Requires designing
  `MaterialSemantics.TpmHandle` (key bytes are a TPM handle, not raw material),
  implementing `TPM2_LoadExternal` + `TPM2_HMAC` command pair, and shipping
  `Verifiable.Tpm` as a registered HMAC backend. This is the architectural
  payoff for the async-everywhere shape — the moment registry routing to
  TPM-resident keys becomes real. The Bucket C async migration explicitly
  unblocked this. Likely the first post-landing MD.
- **TPM2_Hash backend** — same shape, lower priority (software digest is rarely
  perf-critical).

### 8.2 Consumers to ship

All of these can be built **directly on top of what landed**. No further library
plumbing is required.

- **DPoP nonce (RFC 9449)** — server-held HMAC key, AS computes
  `HMAC(issuedAt || audience, key)`, client echoes, AS recomputes and verifies.
  Use `CryptographicKeyEvents.ComputeHmacAsync` with `CryptoTags.HmacSha256Value`.
  This is the natural next pass after the original DPoP MD.
- **OAuth state HMAC binding** — `StateMatchingMode.HmacBound` gains a consumer;
  recompute over state body, verify against embedded tag.
- **JWS HS256/HS384/HS512** — `SymmetricKey` consumer. `WellKnownJwaValues.Hs256`/
  `Hs384`/`Hs512` and `JwtIoTestData.HsTestData` exist as scaffolding.
- **JWE A128CBC-HS256 / A192CBC-HS384 / A256CBC-HS512** — composite AEAD using
  AES-CBC + HMAC. DIDComm v2 authcrypt content encryption needs this.
- **JWE PBES2-HS256+A128KW / PBES2-HS384+A192KW / PBES2-HS512+A256KW** — PBKDF2
  with HMAC as PRF, then AES-KW. Password-based key wrapping.
- **HKDF as PRF** — HMAC-based HKDF, complement to the existing Concat KDF.
- **COSE_Mac0 and COSE_Mac (RFC 9052)** — COSE MAC structures. Relevant to CWT,
  SD-CWT, and ISO mDoc / EUDI Wallet device authentication.
- **DPP / eIDAS persistent-AEAD carriers** — long-lived AEAD keys held by
  issuing authorities. `SymmetricKeyMemory` with `Purpose.Encryption` directly,
  no `ContentEncryptionKey` wrapping.

### 8.3 Streaming primitives (deferred)

When a fitting time-streaming consumer arrives (RDF parsing over large files,
KERI event log replay, large SD-CWT processing), add Pipelines-based variants:

```csharp
ValueTask<(DigestValue, CryptoEvent?)> ComputeDigestFromPipeAsync(
    PipeReader reader, Tag tag, MemoryPool<byte> pool, ...);

ValueTask<(HmacValue, CryptoEvent?)> ComputeHmacFromPipeAsync(
    PipeReader reader, ReadOnlyMemory<byte> keyBytes,
    int outputByteLength, Tag tag, MemoryPool<byte> pool, ...);
```

The `ReadOnlySequence<byte>` shape of the in-scope primitives composes cleanly
with `PipeReader.ReadAsync().Buffer`; the streaming primitive is a peer, not a
wrapper. Land when a consumer demands it; not before.

---

## 9. Known fragility addressed

`test/Verifiable.Tests/OAuth/Dpop/DpopProofValidationTests.cs`
`ValidateAsyncRejectsBadSignature` was flaky: it tampered the **last** character
of the base64url JWS signature, where only `{A, Q, g, w}` are valid trailing
characters for a 64-byte (P-256) signature. Random keys producing signatures
ending in `A` triggered `FormatException` instead of the expected
`SignatureFailed` result. The working-tree fix (uncommitted as of this writing)
tampers a middle character, which is always a valid base64url substitute.

---

## 10. How to take this forward

If you are continuing the original DPoP MD:

1. The original MD's "primitive missing" gap is closed. Everything DPoP needs
   (`ComputeHmacAsync`, `VerifyHmacAsync`, `SymmetricKeyMemory` for the
   server-held nonce key, `CryptoTags.HmacSha256Value`) is in place.
2. The original MD's reference to a sync HMAC helper or a local `HmacComputeDelegate`
   is obsolete. Resolve via `CryptographicKeyEvents.ComputeHmacAsync` directly,
   or accept a `ComputeHmacDelegate` parameter at the consumer's entry point.
3. The async surface propagates: any consumer signing or verifying DPoP nonces
   is `async ValueTask<...>` returning. Threading `MemoryPool<byte>` +
   `CancellationToken` through public APIs is the convention.
4. Test wiring is already done in `TestSetup.cs` — copying its
   `InitializeHmacFunctions` shape into your test fixture is the canonical
   pattern.

If you are starting a fresh consumer (HKDF, JWS HS, JWE composite AEAD, etc.):

1. Import `Verifiable.Cryptography` and pick the right tier:
   - Raw bytes in, raw bytes out → `CryptographicKeyEvents.ComputeHmacAsync` /
     `VerifyHmacAsync`.
   - Typed key in (`SymmetricKeyMemory`) → `KeyExtensions.ComputeHmacAsync` on
     the key.
   - Long-lived bound key → `SymmetricKey`.
2. Use `CryptoTags.HmacShaXXXValue` for the Tag unless your protocol demands
   SHA-1 (then compose inline).
3. Always `using` your `DigestValue` / `HmacValue` results.
4. Follow the dispose/scope discipline modelled in
   `CredentialEcdsaSd2023Extensions` and `DpopProofValidation` — pool-rented
   buffers wrapped in `using IMemoryOwner<byte>`, hash outputs in `using
   DigestValue`.

Open questions / non-trivial deviations from the rev-2 MD encountered during
implementation:

- The MD's TpmCommandExecutor section (~6.10.2) understated the
  `WriteAuthCommand(ref TpmWriter, ...)` constraint. The actual structural fix
  was a precompute/write split on `TpmSessionBase`. The split is documented in
  the type's xmldoc — preserve it when adding new session types.
- The MD's "no exemptions" stance led us to migrate both retention comments
  (`TpmCommandExecutor.CreateIncrementalHash` and `TpmSession.ComputeHmac`).
  Both retention comments had real engineering merit (sync span-write, software-only
  key, SHA-1 requirement); the migration succeeded by accepting the
  precompute/write structural cost. Anyone considering reverting either should
  read the type's xmldoc rationale first.
- `BlankNodeRelabelDelegate` and `CreateRelabeler` factory in the old
  `BlankNodeRelabeling.cs` were unused outside the file and deleted as part of
  Bucket D. If a downstream consumer turns out to depend on them, reintroduce
  them on the async shape.

---

*Document generated post-landing. Branch `oauth-subsystem` at commit `c8aec01`
(or later if the DPoP test fix has been committed).*
