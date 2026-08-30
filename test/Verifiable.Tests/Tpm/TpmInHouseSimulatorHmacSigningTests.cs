using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the HMAC row of Table 115 — <c>TPM2_Sign()</c>/<c>TPM2_VerifySignature()</c> over a digest and
/// <c>TPM2_SignSequenceStart()</c>/<c>TPM2_SignSequenceComplete()</c>/<c>TPM2_VerifySequenceStart()</c>/
/// <c>TPM2_VerifySequenceComplete()</c> over a message — against the in-house behavioural
/// <see cref="TpmSimulator"/> with loaded KEYEDHASH HMAC keys, entirely in-process
/// through the production command path (<see cref="TpmCommandExecutor"/>, the real command inputs, and the real
/// response codecs).
/// </summary>
/// <remarks>
/// <para>
/// The signing oracle is RFC 4231's published HMAC test vectors and the framework's own HMAC over the
/// caller-supplied key bytes, both independent of the simulator's HMAC seam; the digest-signing relation is
/// additionally proved against <c>TPM2_HMAC()</c> itself — clause 20.5 and clause 15.5 define the identical
/// <c>HMAC_h(bits, ·)</c> computation, so <c>TPM2_Sign(digest)</c> must equal <c>TPM2_HMAC(digest)</c> octet
/// for octet (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
/// Library Specification</see>, Part 3: Commands, clauses 20.1 (Table 115), 20.2, 20.3, 20.5, 20.6).
/// </para>
/// <para>
/// <c>TPM2_SignDigest()</c> and <c>TPM2_VerifyDigestSignature()</c> do not support HMAC keys at all — Table
/// 115's "Not supported" and clause 20.7.1's "a signing scheme that supports signing a digest (e.g.,
/// TPM_ALG_ECDSA, but not TPM_ALG_HMAC)" — and both refuse a loaded HMAC signing key with <c>TPM_RC_SCHEME</c>,
/// the same answer a sealed data object draws from them in their own test classes; the signing-key fixture is
/// what distinguishes the pin here.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorHmacSigningTests
{
    /// <summary>The RFC 4231 test case 3 key: twenty octets of <c>0xaa</c>.</summary>
    private static readonly byte[] Rfc4231Case3Key = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    /// <summary>The RFC 4231 test case 3 data: fifty octets of <c>0xdd</c>.</summary>
    private static readonly byte[] Rfc4231Case3Data = Convert.FromHexString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    /// <summary>The published RFC 4231 test case 3 HMAC-SHA-256 value.</summary>
    private static readonly byte[] Rfc4231Case3Sha256 = Convert.FromHexString("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /// <summary>A fixed 32-octet digest to sign — the SHA-256 width every SHA-256-scheme test needs; arbitrary octets, not tied to any vector.</summary>
    private static readonly byte[] Sha256WidthDigest = Convert.FromHexString("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f");

    /// <summary>A short secret sealed by the sealed-data fixtures, arbitrary and not tied to any published vector.</summary>
    private static readonly byte[] SealedSecretBytes = [1, 2, 3, 4];

    /// <summary>A fixed proof seed injected into the simulator so the minted verification tickets are reproducible off-TPM; arbitrary octets.</summary>
    private static readonly byte[] TicketSeed = Convert.FromHexString("c1a2b3d4e5f60718293a4b5c6d7e8f9001122334455667788990aabbccddeeff");

    /// <summary>A password that never matches any fixture's authValue.</summary>
    private static readonly byte[] WrongKeyPassword = "hmac-signing-wrong"u8.ToArray();

    /// <summary>The lowered <c>maxTries</c> the lockout cases use to reach Lockout mode quickly.</summary>
    private const uint LockoutTestMaxTries = 2;

    /// <summary>The attribute word every non-signing KEYEDHASH fixture here is built with: bound to this TPM and parent, password-authorizable, DA-exempt.</summary>
    private const TpmaObject BoundAttributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// <c>TPM2_Sign()</c> with a KEYEDHASH HMAC key signs the supplied digest: "This command causes the TPM to
    /// sign an externally provided hash with the specified symmetric or asymmetric signing key", and Table
    /// 115's HMAC row reads "Signs/verifies the digest". The signature is an HMAC of the digest under the
    /// key's own scheme hash, so it must equal both the framework's HMAC over the same key bytes and
    /// <c>TPM2_HMAC()</c> over the digest as its message — clauses 20.5 and 15.5 define the same computation
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 20.1, 20.5).
    /// </summary>
    [TestMethod]
    public async Task SignOverAnHmacKeyEqualsTheOneShotHmacOfTheDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignOverAnHmacKeyEqualsTheOneShotHmacOfTheDigest), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignResponse> signResult = await SignAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign() over an HMAC key must succeed: '{signResult.ResponseCode}'.");
        using SignResponse signature = signResult.Value;

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HMAC, signature.SignatureAlgorithm, "The framed TPMT_SIGNATURE must select the HMAC member.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm, "The TPMT_HA member must carry the key's scheme hash.");

        byte[] expected = HMACSHA256.HashData(Rfc4231Case3Key, Sha256WidthDigest);
        Assert.IsTrue(signature.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(expected), "The signature must be HMAC-SHA-256 of the digest under the key's bits.");

        TpmResult<HmacResponse> hmacResult = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(hmacResult.IsSuccess, $"TPM2_HMAC() over the same octets must succeed: '{hmacResult.ResponseCode}'.");
        using HmacResponse hmac = hmacResult.Value;

        Assert.IsTrue(
            signature.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(hmac.OutHmac.AsReadOnlySpan()),
            "TPM2_Sign(digest) and TPM2_HMAC(digest) are the same spec-defined HMAC_h(bits, ·) and must agree octet for octet.");
    }

    /// <summary>
    /// A NULL <c>inScheme</c> selects the key's own scheme: "If the scheme of keyHandle is TPM_ALG_NULL, the
    /// TPM will sign using inScheme; otherwise, it will sign using the scheme of keyHandle" — an HMAC key's
    /// scheme is never NULL, so the key's own <c>HMAC(SHA-256)</c> applies and the signature equals the
    /// explicit-scheme one (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 20.5.1).
    /// </summary>
    [TestMethod]
    public async Task SignWithANullSchemeSelectsTheKeysOwnHmacScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignWithANullSchemeSelectsTheKeysOwnHmacScheme), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignResponse> nullSchemeResult = await SignAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);
        Assert.IsTrue(nullSchemeResult.IsSuccess, $"TPM2_Sign() with a NULL inScheme over an HMAC key must succeed: '{nullSchemeResult.ResponseCode}'.");
        using SignResponse signature = nullSchemeResult.Value;

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HMAC, signature.SignatureAlgorithm, "A NULL inScheme must resolve to the key's own TPM_ALG_HMAC.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm, "A NULL inScheme must resolve to the key's own scheme hash.");

        byte[] expected = HMACSHA256.HashData(Rfc4231Case3Key, Sha256WidthDigest);
        Assert.IsTrue(signature.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(expected), "The NULL-scheme signature must equal the key's own HMAC of the digest.");
    }

    /// <summary>
    /// The scheme hash drives the digest width and the HMAC family: a SHA-384 HMAC key signs a 48-octet digest
    /// and the signature is HMAC-SHA-384 ("When the signing scheme uses a hash algorithm ... This is the same
    /// algorithm that is required to be used in producing digest",
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5.1).
    /// </summary>
    [TestMethod]
    public async Task SignOverASha384HmacKeyProducesTheSha384Hmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignOverASha384HmacKeyProducesTheSha384Hmac), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA384, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] digest = new byte[48];
        Sha256WidthDigest.CopyTo(digest, 0);

        TpmResult<SignResponse> signResult = await SignAsync(
            tpm, registry, pool, key.Handle, digest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign() over a SHA-384 HMAC key must succeed: '{signResult.ResponseCode}'.");
        using SignResponse signature = signResult.Value;

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA384, signature.HashAlgorithm, "The signature must carry the key's SHA-384 scheme hash.");
        byte[] expected = HMACSHA384.HashData(Rfc4231Case3Key, digest);
        Assert.IsTrue(signature.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(expected), "The signature must be HMAC-SHA-384 of the 48-octet digest.");
    }

    /// <summary>
    /// An <c>inScheme</c> that is neither the key's own scheme nor NULL is refused: "If the scheme of keyHandle
    /// is not TPM_ALG_NULL, then inScheme shall either be the same scheme as keyHandle or TPM_ALG_NULL" and
    /// "If inScheme is not a valid signing scheme for the type of keyHandle (or TPM_ALG_NULL), then the TPM
    /// shall return TPM_RC_SCHEME" — proved for a same-family hash mismatch (HMAC with SHA-512 against a
    /// SHA-256 key) and for a cross-family ECDSA scheme
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5.1).
    /// </summary>
    [TestMethod]
    public async Task SignWithAMismatchedOrForeignSchemeOnAnHmacKeyIsRefusedWithScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignWithAMismatchedOrForeignSchemeOnAnHmacKeyIsRefusedWithScheme), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignResponse> mismatchedHashResult = await SignAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA512).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, mismatchedHashResult.ResponseCode, "HMAC with a hash other than the key's own must be refused with TPM_RC_SCHEME.");

        TpmResult<SignResponse> ecdsaResult = await SignAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, ecdsaResult.ResponseCode, "An ECDSA inScheme against a KEYEDHASH key must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// "The size of digest must match that of the hash algorithm in the scheme" — a 31- and a 33-octet digest
    /// against a SHA-256-scheme HMAC key are each refused with <c>TPM_RC_SIZE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5.1).
    /// </summary>
    [TestMethod]
    public async Task SignWithAWrongWidthDigestOnAnHmacKeyIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignWithAWrongWidthDigestOnAnHmacKeyIsRefusedWithSize), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignResponse> shortResult = await SignAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest.AsSpan(0, 31).ToArray(), TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, shortResult.ResponseCode, "A 31-octet digest against a SHA-256 HMAC scheme must be refused with TPM_RC_SIZE.");

        byte[] wide = new byte[33];
        Sha256WidthDigest.CopyTo(wide, 0);
        TpmResult<SignResponse> wideResult = await SignAsync(
            tpm, registry, pool, key.Handle, wide, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, wideResult.ResponseCode, "A 33-octet digest against a SHA-256 HMAC scheme must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// "If the sign attribute is not SET in the key referenced by handle, then the TPM shall return TPM_RC_KEY"
    /// — a sealed data object (<c>sign</c> CLEAR) at <c>TPM2_Sign()</c> is refused with <c>TPM_RC_KEY</c>
    /// under a correct (empty) authorization, not with <c>TPM_RC_HANDLE</c>: a loaded KEYEDHASH object IS a
    /// loaded object (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 20.5.1).
    /// </summary>
    [TestMethod]
    public async Task SignOverASealedDataObjectIsRefusedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignOverASealedDataObjectIsRefusedWithKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint sealedHandle, _) = await PolicySweepHarness.SealAndLoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SealedSecretBytes, ReadOnlyMemory<byte>.Empty, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignResponse> result = await SignAsync(
            tpm, registry, pool, sealedHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "A sealed data object (sign CLEAR) at TPM2_Sign() must be refused with TPM_RC_KEY.");
    }

    /// <summary>
    /// A restricted HMAC key needs a validation ticket: "If keyHandle references a restricted signing key, then
    /// validation shall be provided" — this simulator models the NULL-ticket form of <c>TPM2_Sign()</c> only,
    /// which the reference refuses with <c>TPM_RC_TICKET</c> for a restricted key
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 20.5.1 and 20.5.2, Table 122).
    /// </summary>
    [TestMethod]
    public async Task SignOverARestrictedHmacKeyIsRefusedWithTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignOverARestrictedHmacKeyIsRefusedWithTicket), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint restrictedHandle = await CreateAndLoadRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        TpmResult<SignResponse> result = await SignAsync(
            tpm, registry, pool, restrictedHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_TICKET, result.ResponseCode, "A restricted HMAC key with the modelled NULL validation ticket must be refused with TPM_RC_TICKET.");
    }

    /// <summary>
    /// The key slot's USER-role authorization runs before any command rule, exactly as every other
    /// <c>@keyHandle</c> USER command: a wrong password against a DA-protected HMAC key answers
    /// session-index-encoded <c>TPM_RC_AUTH_FAIL</c> and charges <c>failedTries</c>, while a <c>noDA</c> key
    /// answers <c>TPM_RC_BAD_AUTH</c> uncharged (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 20.5.2, Table 122; Part 1: Architecture,
    /// clause 16.8.1).
    /// </summary>
    [TestMethod]
    public async Task SignWithAWrongPasswordChargesADaProtectedKeyAndLeavesANoDaKeyUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignWithAWrongPasswordChargesADaProtectedKeyAndLeavesANoDaKeyUncharged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] password = [0x70, 0x77];
        using HmacKeyHarness.LoadedHmacKey daKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: password, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignResponse> chargedResult = await SignAsync(
            tpm, registry, pool, daKey.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, keyPassword: new byte[] { 0x6e, 0x6f }).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), chargedResult.ResponseCode,
            "A wrong password against a DA-protected HMAC key must be refused with session-index-0-encoded TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(1u, await ReadLockoutCounterAsync(tpm, registry, pool).ConfigureAwait(false), "The DA-protected failure must charge failedTries once.");

        using HmacKeyHarness.LoadedHmacKey noDaKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: password, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignResponse> unchargedResult = await SignAsync(
            tpm, registry, pool, noDaKey.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, keyPassword: new byte[] { 0x6e, 0x6f }).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), unchargedResult.ResponseCode,
            "A wrong password against a noDA HMAC key must be refused with session-index-0-encoded TPM_RC_BAD_AUTH.");
        Assert.AreEqual(1u, await ReadLockoutCounterAsync(tpm, registry, pool).ConfigureAwait(false), "A noDA failure must not move failedTries.");
    }

    /// <summary>
    /// A key whose <c>userWithAuth</c> attribute is CLEAR may have its USER role satisfied only by a policy
    /// session, so a password authorization is refused with <c>TPM_RC_POLICY_FAIL</c> before the key's
    /// authValue is ever tested (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 5.6, check 7.1; Part 2: Structures, clause 8.3.3).
    /// </summary>
    [TestMethod]
    public async Task SignOverAUserWithAuthClearHmacKeyIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignOverAUserWithAuthClearHmacKeyIsRefusedWithPolicyFail), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, isUserWithAuth: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignResponse> result = await SignAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode, "A password against a userWithAuth-CLEAR HMAC key must be refused with TPM_RC_POLICY_FAIL.");
    }

    /// <summary>
    /// <c>TPM2_VerifySignature()</c> validates an HMAC signature by recomputing it — "If keyHandle references
    /// a symmetric key, both the public and private portions need to be loaded" — and a valid signature mints
    /// a <c>TPM_ST_VERIFIED</c> <c>TPMT_TK_VERIFIED</c> whose <c>hmac</c> is non-empty for a
    /// storage-hierarchy key, recomputable from the injected proof seed as
    /// <c>HMAC(H(seed ‖ hierarchy), TPM_ST_VERIFIED ‖ digest ‖ keyName)</c> — Equation (5)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 20.2.1 and 20.2.2, Table 117; Part 2: Structures, clause 10.6.5).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureOverAnHmacKeyRoundTripsAndMintsAVerifiedTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySignatureOverAnHmacKeyRoundTripsAndMintsAVerifiedTicket), pool, TestContext.CancellationToken, seed: TicketSeed).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] signature = HMACSHA256.HashData(Rfc4231Case3Key, Sha256WidthDigest);

        TpmResult<VerifySignatureResponse> result = await VerifySignatureAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, signature, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySignature() over a valid HMAC signature must succeed: '{result.ResponseCode}'.");
        using VerifySignatureResponse response = result.Value;

        Assert.AreEqual(TpmStConstants.TPM_ST_VERIFIED, response.Validation.Tag, "The minted ticket must be tagged TPM_ST_VERIFIED.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, response.Validation.Hierarchy, "The ticket hierarchy must be the verifying key's own hierarchy.");
        Assert.IsFalse(response.Validation.IsNull, "A successful verification under a real hierarchy must return a real ticket, not a NULL ticket.");
        Assert.IsFalse(response.Validation.Metadata.HasValue, "A TPM_ST_VERIFIED ticket carries no metadata.");

        byte[] expectedTicket = HMACSHA256.HashData(DeriveTicketProof((uint)TpmRh.TPM_RH_OWNER), BuildVerifiedTicketMessage(TpmStConstants.TPM_ST_VERIFIED, Sha256WidthDigest, key.Name.Span));
        Assert.IsTrue(expectedTicket.AsSpan().SequenceEqual(response.Validation.Hmac), "The verified ticket must be HMAC(H(seed ‖ hierarchy), TPM_ST_VERIFIED ‖ digest ‖ keyName), reproducible from the injected seed.");
    }

    /// <summary>
    /// "If the signature check succeeds, then the TPM will produce a TPMT_TK_VERIFIED. Otherwise, the TPM shall
    /// return TPM_RC_SIGNATURE" — proved for a tampered digest, for tampered signature octets, and for a
    /// signature whose hash disagrees with the key's own scheme hash (the reference validates scheme
    /// consistency inside <c>CryptHMACVerifySignature</c> and answers <c>TPM_RC_SIGNATURE</c>)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.2.1).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureOverATamperedOrMismatchedHmacSignatureIsRefusedWithSignature()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySignatureOverATamperedOrMismatchedHmacSignatureIsRefusedWithSignature), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] signature = HMACSHA256.HashData(Rfc4231Case3Key, Sha256WidthDigest);

        byte[] tamperedDigest = (byte[])Sha256WidthDigest.Clone();
        tamperedDigest[0] ^= 0x01;
        TpmResult<VerifySignatureResponse> tamperedDigestResult = await VerifySignatureAsync(
            tpm, registry, pool, key.Handle, tamperedDigest, signature, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, tamperedDigestResult.ResponseCode, "A signature over a different digest must be refused with TPM_RC_SIGNATURE.");

        byte[] tamperedSignature = (byte[])signature.Clone();
        tamperedSignature[^1] ^= 0x01;
        TpmResult<VerifySignatureResponse> tamperedSignatureResult = await VerifySignatureAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, tamperedSignature, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, tamperedSignatureResult.ResponseCode, "Tampered signature octets must be refused with TPM_RC_SIGNATURE.");

        byte[] sha384Signature = HMACSHA384.HashData(Rfc4231Case3Key, Sha256WidthDigest);
        TpmResult<VerifySignatureResponse> mismatchedHashResult = await VerifySignatureAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, sha384Signature, TpmAlgIdConstants.TPM_ALG_SHA384).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, mismatchedHashResult.ResponseCode, "A signature hash disagreeing with the key's scheme hash must be refused with TPM_RC_SIGNATURE.");
    }

    /// <summary>
    /// A signature algorithm incompatible with the key's type fails closed with <c>TPM_RC_SCHEME</c> in either
    /// direction: an HMAC signature against an ECC signing key, and an ECDSA signature against a KEYEDHASH key —
    /// mirroring the dispatch rule every attest command applies
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithASchemeForeignToTheKeysTypeIsRefusedWithScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySignatureWithASchemeForeignToTheKeysTypeIsRefusedWithScheme), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //An ECC SIGNING key, so the sign gate admits it and the scheme dispatch is what decides.
        using CreatePrimaryInput signerInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> signerResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, signerInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signerResult.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{signerResult.ResponseCode}'.");
        using CreatePrimaryResponse signer = signerResult.Value;

        byte[] hmacSignature = HMACSHA256.HashData(Rfc4231Case3Key, Sha256WidthDigest);

        TpmResult<VerifySignatureResponse> hmacAgainstEccResult = await VerifySignatureAsync(
            tpm, registry, pool, signer.ObjectHandle.Value, Sha256WidthDigest, hmacSignature, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, hmacAgainstEccResult.ResponseCode, "An HMAC signature against an ECC signing key must be refused with TPM_RC_SCHEME.");

        byte[] ecdsaShapedSignature = new byte[64];
        using VerifySignatureInput ecdsaInput = VerifySignatureInput.ForEcdsa(
            TpmiDhObject.FromValue(key.Handle), Sha256WidthDigest, ecdsaShapedSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySignatureResponse> ecdsaAgainstHmacResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, ecdsaInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, ecdsaAgainstHmacResult.ResponseCode, "An ECDSA signature against a KEYEDHASH key must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// Verification is not restricted-gated: clause 20.2 states no attribute rule, and the reference's
    /// <c>CryptHMACVerifySignature</c> checks scheme consistency only — so a restricted HMAC key at
    /// <c>TPM2_VerifySignature()</c> reaches the signature compare (a wrong signature answers
    /// <c>TPM_RC_SIGNATURE</c>, never an attribute refusal). A restricted key's bits are origin-generated and
    /// nothing may sign under them in this model, so the reachable compare is the provable half of the posture
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureOverARestrictedHmacKeyReachesTheSignatureCompare()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySignatureOverARestrictedHmacKeyReachesTheSignatureCompare), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint restrictedHandle = await CreateAndLoadRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        byte[] wrongSignature = new byte[32];
        TpmResult<VerifySignatureResponse> result = await VerifySignatureAsync(
            tpm, registry, pool, restrictedHandle, Sha256WidthDigest, wrongSignature, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIGNATURE, result.ResponseCode,
            "A restricted HMAC key must reach the compare and answer TPM_RC_SIGNATURE — verification is not restricted-gated.");
    }

    /// <summary>
    /// "The object to validate the signature must be a signing key" — the reference's first input validation
    /// refuses a <c>keyHandle</c> whose <c>sign</c> attribute is CLEAR with <c>TPM_RC_ATTRIBUTES</c> ahead of
    /// every other check. For a KEYEDHASH object the gate is load-bearing: <c>TPM2_VerifySignature()</c> needs
    /// no authorization and charges no <c>failedTries</c>, and the symmetric arm recomputes under the object's
    /// SENSITIVE bits, so a sealed data object or an XOR-scheme decryption key admitted here would be an
    /// unlimited guess-confirmation oracle for its own secret. Proved with the one signature that WOULD match
    /// the sealed bits — the refusal must land before the compare can ever confirm it
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.2 (Part 4 <c>VerifySignature.c</c>, Detailed Actions);
    /// Part 2: Structures, clause 8.3.3).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureOverANonSigningKeyedHashObjectIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySignatureOverANonSigningKeyedHashObjectIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint sealedHandle, _) = await PolicySweepHarness.SealAndLoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SealedSecretBytes, ReadOnlyMemory<byte>.Empty, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] matchingSignature = HMACSHA256.HashData(SealedSecretBytes, Sha256WidthDigest);
        TpmResult<VerifySignatureResponse> sealedResult = await VerifySignatureAsync(
            tpm, registry, pool, sealedHandle, Sha256WidthDigest, matchingSignature, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, sealedResult.ResponseCode,
            "A sealed data object (sign CLEAR) must be refused with TPM_RC_ATTRIBUTES even for the one signature its bits would confirm — its secret is never a verification key.");

        uint xorHandle = await CreateAndLoadXorDecryptObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
        TpmResult<VerifySignatureResponse> xorResult = await VerifySignatureAsync(
            tpm, registry, pool, xorHandle, Sha256WidthDigest, new byte[32], TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, xorResult.ResponseCode, "An XOR-scheme decryption key (sign CLEAR) must be refused with TPM_RC_ATTRIBUTES — its bits are keying material, not a verification key.");
    }

    /// <summary>
    /// The message form: <c>TPM2_SignSequenceStart()</c> admits an HMAC key ("The scheme of keyHandle can be
    /// any signing scheme, whether it signs a digest (e.g., TPM_ALG_ECDSA) or a message (e.g., TPM_ALG_HMAC)")
    /// and <c>TPM2_SignSequenceComplete()</c> signs the accumulated message — RFC 4231 case 3 split across two
    /// <c>TPM2_SequenceUpdate()</c> calls and the trailing <c>buffer</c> reproduces the published HMAC (the
    /// segments chain in order), and the sequence is flushed on success (<c>{F}</c>: a second Complete answers <c>TPM_RC_HANDLE</c>)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.5.1, 20.6.1; Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceOverAnHmacKeyReproducesRfc4231Case3AndFlushesTheSequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignSequenceOverAnHmacKeyReproducesRfc4231Case3AndFlushesTheSequence), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.Handle).ConfigureAwait(false);

        byte[] firstBlock = Rfc4231Case3Data.AsSpan(0, 20).ToArray();
        byte[] secondBlock = Rfc4231Case3Data.AsSpan(20, 20).ToArray();
        byte[] trailingBlock = Rfc4231Case3Data.AsSpan(40).ToArray();
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, firstBlock).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, secondBlock).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SignSequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, trailingBlock).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SignSequenceComplete() over an HMAC key must succeed: '{completeResult.ResponseCode}'.");
        using SignSequenceCompleteResponse completed = completeResult.Value;

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HMAC, completed.SignatureAlgorithm, "The framed TPMT_SIGNATURE must select the HMAC member.");
        Assert.IsTrue(completed.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(Rfc4231Case3Sha256), "The message HMAC must equal RFC 4231 case 3's published value.");

        TpmResult<SignSequenceCompleteResponse> replayResult = await SignSequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, trailingBlock).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, replayResult.ResponseCode, "A successful Complete flushes the sequence, so a second Complete must be refused with TPM_RC_HANDLE.");
    }

    /// <summary>
    /// "This means that a message that fits into a single TPM2B_MAX_BUFFER can be signed with
    /// TPM2_SignSequenceComplete() without calling TPM2_SequenceUpdate()" — the whole RFC 4231 case 3 data as
    /// the trailing <c>buffer</c> alone reproduces the published HMAC
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6.1).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteInASingleBufferReproducesTheRfcVector()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignSequenceCompleteInASingleBufferReproducesTheRfcVector), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.Handle).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> completeResult = await SignSequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, Rfc4231Case3Data).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"A single-buffer TPM2_SignSequenceComplete() must succeed: '{completeResult.ResponseCode}'.");
        using SignSequenceCompleteResponse completed = completeResult.Value;

        Assert.IsTrue(completed.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(Rfc4231Case3Sha256), "The single-buffer message HMAC must equal the published RFC 4231 case 3 value.");
    }

    /// <summary>
    /// "Because restricted HMAC keys sign digests, and TPM2_SignSequenceComplete() has no validation (i.e.,
    /// TPM_TK_HASHCHECK) parameter, it is not possible to support restricted HMAC keys with
    /// TPM2_SignSequenceComplete()" — the note names no response code, so the refusal is adjudicated at the
    /// earliest site, <c>TPM2_SignSequenceStart()</c>, with <c>TPM_RC_ATTRIBUTES</c> — the same
    /// "this key's attributes forbid this use" code the restricted rule answers at <c>TPM2_HMAC()</c> and
    /// <c>TPM2_HMAC_Start()</c> (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clauses 17.5.1, 20.6.1).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOverARestrictedHmacKeyIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignSequenceStartOverARestrictedHmacKeyIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint restrictedHandle = await CreateAndLoadRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        using SignSequenceStartInput input = SignSequenceStartInput.Create(TpmiDhObject.FromValue(restrictedHandle), [], pool);
        TpmResult<SignSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "A restricted HMAC key must be refused at TPM2_SignSequenceStart() with TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// "If keyHandle does not refer to a signing key, the TPM shall return TPM_RC_KEY" — a sealed data object
    /// (<c>sign</c> CLEAR) cannot open a signing sequence, and the identical sentence in clause 17.6 refuses
    /// it a verification sequence too (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clauses 17.5.1, 17.6.1).
    /// </summary>
    [TestMethod]
    public async Task SequenceStartsOverASealedDataObjectAreRefusedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SequenceStartsOverASealedDataObjectAreRefusedWithKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint sealedHandle, _) = await PolicySweepHarness.SealAndLoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SealedSecretBytes, ReadOnlyMemory<byte>.Empty, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using SignSequenceStartInput signStartInput = SignSequenceStartInput.Create(TpmiDhObject.FromValue(sealedHandle), [], pool);
        TpmResult<SignSequenceStartResponse> signStartResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, signStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, signStartResult.ResponseCode, "A sealed data object at TPM2_SignSequenceStart() must be refused with TPM_RC_KEY.");

        using VerifySequenceStartInput verifyStartInput = VerifySequenceStartInput.Create(TpmiDhObject.FromValue(sealedHandle), [], pool);
        TpmResult<VerifySequenceStartResponse> verifyStartResult = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, verifyStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, verifyStartResult.ResponseCode, "A sealed data object at TPM2_VerifySequenceStart() must be refused with TPM_RC_KEY.");
    }

    /// <summary>
    /// <c>TPM2_SignSequenceComplete()</c> completes only a Signing sequence: a sequence opened by
    /// <c>TPM2_HMAC_Start()</c> — even one bound to the very same key — answers <c>TPM_RC_MODE</c>, and the mode
    /// gate settles it ahead of the Name gate: an HMAC sequence binds no key (its starting Name is the Empty
    /// Buffer), so an arm ordered the other way would answer <c>TPM_RC_SIGN_CONTEXT_KEY</c> instead
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.8.1, 20.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteOnAnHmacStartSequenceIsRefusedWithMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignSequenceCompleteOnAnHmacStartSequenceIsRefusedWithMode), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> hmacStartResult = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_NULL, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(hmacStartResult.IsSuccess, $"TPM2_HMAC_Start() must succeed: '{hmacStartResult.ResponseCode}'.");
        HmacStartResponse hmacSequence = hmacStartResult.Value;

        TpmResult<SignSequenceCompleteResponse> result = await SignSequenceCompleteAsync(
            tpm, registry, pool, hmacSequence.SequenceHandle, key.Handle, Rfc4231Case3Data).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_MODE, result.ResponseCode, "TPM2_SignSequenceComplete() on an HMAC sequence must be refused with TPM_RC_MODE.");
    }

    /// <summary>
    /// "If keyHandle refers to a key that is not the same as the key that was used to start the signature
    /// context, the TPM shall return TPM_RC_SIGN_CONTEXT_KEY" — a second HMAC key presented at Complete
    /// against a sequence the first key opened. The identity test is the key's Name, and the second key is
    /// created from the SAME template: its <c>unique</c> digests its own key value and obfuscation value
    /// (Part 2: Structures, clause 12.2.3.1, equation (8)), so the Names differ by the sensitive areas alone — asserted before the refusal so the
    /// gate under test is the one deciding
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6.1; Part 2: Structures, clause 12.2.3.1; Part 1: Architecture, clause 13, Table 9 for the Name).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteWithASwappedHmacKeyIsRefusedWithSignContextKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignSequenceCompleteWithASwappedHmacKeyIsRefusedWithSignContextKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey startingKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey otherKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(startingKey.Name.Span.SequenceEqual(otherKey.Name.Span), "Same-template keys must differ in Name through their uniques, so the gate under test is the one deciding.");

        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, startingKey.Handle).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> result = await SignSequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, otherKey.Handle, Rfc4231Case3Data).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY, result.ResponseCode, "A key other than the sequence's starting key must be refused with TPM_RC_SIGN_CONTEXT_KEY.");
    }

    /// <summary>
    /// The two authorizations of <c>TPM2_SignSequenceComplete()</c> keep their arms distinct for a KEYEDHASH
    /// key exactly as for an asymmetric one: a wrong SEQUENCE password answers session-index-0-encoded
    /// <c>TPM_RC_BAD_AUTH</c> uncharged (a sequence object is DA-exempt), while a wrong KEY password against a
    /// DA-protected HMAC key answers session-index-1-encoded <c>TPM_RC_AUTH_FAIL</c> and charges <c>failedTries</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.6.2, Table 124; Part 1: Architecture, clauses 16.8.1, 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteDistinguishesTheSequenceAndKeyAuthorizationFailures()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignSequenceCompleteDistinguishesTheSequenceAndKeyAuthorizationFailures), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] keyPassword = [0x6b, 0x70];
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: keyPassword, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] sequenceAuth = [0x73, 0x71];
        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.Handle, sequenceAuth).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> wrongSequenceResult = await SignSequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, Rfc4231Case3Data, sequenceAuth: new byte[] { 0x00 }, keyAuth: keyPassword).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), wrongSequenceResult.ResponseCode,
            "A wrong sequence password must be refused with session-index-0-encoded TPM_RC_BAD_AUTH.");
        Assert.AreEqual(0u, await ReadLockoutCounterAsync(tpm, registry, pool).ConfigureAwait(false), "The sequence failure is DA-exempt and must not move failedTries.");

        TpmResult<SignSequenceCompleteResponse> wrongKeyResult = await SignSequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, Rfc4231Case3Data, sequenceAuth: sequenceAuth, keyAuth: new byte[] { 0x00 }).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), wrongKeyResult.ResponseCode,
            "A wrong key password against the DA-protected HMAC key must be refused with session-index-1-encoded TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(1u, await ReadLockoutCounterAsync(tpm, registry, pool).ConfigureAwait(false), "The DA-protected key failure must charge failedTries once.");

        TpmResult<SignSequenceCompleteResponse> correctResult = await SignSequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, Rfc4231Case3Data, sequenceAuth: sequenceAuth, keyAuth: keyPassword).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"The refused attempts must leave the sequence usable: '{correctResult.ResponseCode}'.");
        correctResult.Value.Dispose();
    }

    /// <summary>
    /// The verification-sequence form: <c>TPM2_VerifySequenceStart()</c> over the HMAC key, the RFC 4231 case 3
    /// data through <c>TPM2_SequenceUpdate()</c>, and <c>TPM2_VerifySequenceComplete()</c> with the published
    /// HMAC as the supplied signature — success mints a ticket whose tag is <c>TPM_ST_MESSAGE_VERIFIED</c>
    /// ("The ticket's tag is TPM_ST_MESSAGE_VERIFIED"), recomputable from the injected proof seed as
    /// <c>HMAC(H(seed ‖ hierarchy), TPM_ST_MESSAGE_VERIFIED ‖ message ‖ keyName)</c> over the RAW accumulated
    /// message, and the completed sequence is flushed (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clauses 17.6, 20.3.1; Part 2: Structures, clause 10.6.5).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceOverAnHmacKeyVerifiesTheRfcVectorAndMintsAMessageVerifiedTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySequenceOverAnHmacKeyVerifiesTheRfcVectorAndMintsAMessageVerifiedTicket), pool, TestContext.CancellationToken, seed: TicketSeed).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.Handle).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, Rfc4231Case3Data).ConfigureAwait(false);

        TpmResult<VerifySequenceCompleteResponse> result = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, Rfc4231Case3Sha256, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySequenceComplete() over the published RFC vector must succeed: '{result.ResponseCode}'.");
        using VerifySequenceCompleteResponse response = result.Value;

        Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, response.Validation.Tag, "The minted ticket must be tagged TPM_ST_MESSAGE_VERIFIED.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, response.Validation.Hierarchy, "The ticket hierarchy must be the verifying key's own hierarchy.");
        Assert.IsFalse(response.Validation.IsNull, "A successful verification under a real hierarchy must return a real ticket, not a NULL ticket.");
        Assert.IsFalse(response.Validation.Metadata.HasValue, "A TPM_ST_MESSAGE_VERIFIED ticket carries no metadata.");

        byte[] expectedTicket = HMACSHA256.HashData(DeriveTicketProof((uint)TpmRh.TPM_RH_OWNER), BuildVerifiedTicketMessage(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, Rfc4231Case3Data, key.Name.Span));
        Assert.IsTrue(expectedTicket.AsSpan().SequenceEqual(response.Validation.Hmac), "The ticket must be HMAC(H(seed ‖ hierarchy), TPM_ST_MESSAGE_VERIFIED ‖ message ‖ keyName) over the RAW message, reproducible from the injected seed.");

        TpmResult<VerifySequenceCompleteResponse> replayResult = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, Rfc4231Case3Sha256, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, replayResult.ResponseCode, "A successful Complete flushes the sequence, so a second Complete must be refused with TPM_RC_HANDLE.");
    }

    /// <summary>
    /// "If the signature check succeeds, then the TPM will produce a TPMT_TK_VERIFIED. Otherwise, the TPM shall
    /// return TPM_RC_SIGNATURE" — a signature over different octets is refused, no ticket is framed, and the
    /// sequence is NOT flushed: the same sequence then verifies the correct signature, proving the retry
    /// posture (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 3: Commands, clause 20.3.1).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverAWrongSignatureIsRefusedWithSignatureAndTheSequenceSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySequenceCompleteOverAWrongSignatureIsRefusedWithSignatureAndTheSequenceSurvives), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.Handle).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, Rfc4231Case3Data).ConfigureAwait(false);

        byte[] wrongSignature = (byte[])Rfc4231Case3Sha256.Clone();
        wrongSignature[0] ^= 0x01;
        TpmResult<VerifySequenceCompleteResponse> wrongResult = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, wrongSignature, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, wrongResult.ResponseCode, "A wrong HMAC signature must be refused with TPM_RC_SIGNATURE.");

        TpmResult<VerifySequenceCompleteResponse> retryResult = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, Rfc4231Case3Sha256, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.IsTrue(retryResult.IsSuccess, $"The refused verification must leave the sequence intact for a retry: '{retryResult.ResponseCode}'.");
        retryResult.Value.Dispose();
    }

    /// <summary>
    /// "The TPM will verify that the signing scheme (including the hash or XOF algorithm) in signature matches
    /// the signing scheme of keyHandle (TPM_RC_SCHEME)" — clause 20.4.1's rule, applied to its stated sibling
    /// <c>TPM2_VerifySequenceComplete()</c>: an HMAC signature carrying SHA-384 against a SHA-256-scheme
    /// sequence is refused with <c>TPM_RC_SCHEME</c> — unlike the one-shot <c>TPM2_VerifySignature()</c>,
    /// whose own mismatch channel is <c>TPM_RC_SIGNATURE</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 20.3, 20.4.1).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithAMismatchedSignatureHashIsRefusedWithScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySequenceCompleteWithAMismatchedSignatureHashIsRefusedWithScheme), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.Handle).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, Rfc4231Case3Data).ConfigureAwait(false);

        byte[] sha384Signature = HMACSHA384.HashData(Rfc4231Case3Key, Rfc4231Case3Data);
        TpmResult<VerifySequenceCompleteResponse> result = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, sha384Signature, TpmAlgIdConstants.TPM_ALG_SHA384).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode, "A signature hash disagreeing with the sequence's retained scheme must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// Table 115's "Not supported" row for the digest-signing pair: <c>TPM2_SignDigest()</c> requires "a
    /// signing scheme that supports signing a digest (e.g., TPM_ALG_ECDSA, but not TPM_ALG_HMAC)", so a real
    /// HMAC signing key — not merely a sealed object — answers <c>TPM_RC_SCHEME</c> there and at
    /// <c>TPM2_VerifyDigestSignature()</c> (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clauses 20.1, 20.4.1, 20.7.1).
    /// </summary>
    [TestMethod]
    public async Task SignDigestAndVerifyDigestSignatureOverAnHmacKeyAreRefusedWithScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignDigestAndVerifyDigestSignatureOverAnHmacKeyAreRefusedWithScheme), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using SignDigestInput signDigestInput = SignDigestInput.Create(TpmiDhObject.FromValue(key.Handle), Sha256WidthDigest, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignDigestResponse> signDigestResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signDigestInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, signDigestResult.ResponseCode, "TPM2_SignDigest() over an HMAC key must be refused with TPM_RC_SCHEME.");

        byte[] signature = HMACSHA256.HashData(Rfc4231Case3Key, Sha256WidthDigest);
        using VerifyDigestSignatureInput verifyDigestInput = VerifyDigestSignatureInput.Create(
            TpmiDhObject.FromValue(key.Handle), Sha256WidthDigest, signature, TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyDigestResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyDigestInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, verifyDigestResult.ResponseCode, "TPM2_VerifyDigestSignature() with an HMAC signature must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// The wire HMAC signature member is a <c>TPMT_HA</c> whose <c>hashAlg</c> both selects and sizes the
    /// digest; an unrecognized hashAlg cannot size it and is refused at the unmarshal with the bare
    /// <c>#TPM_RC_HASH</c> channel, before any pooled rental — proved by the metered pool's balance
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.2.2, Table 89; Part 3: Commands, clause 20.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithAGarbageSignatureHashOnTheWireIsRefusedWithHashBeforeAnyRental()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySignatureWithAGarbageSignatureHashOnTheWireIsRefusedWithHashBeforeAnyRental), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //keyHandle, digest (TPM2B), sigAlg = TPM_ALG_HMAC, then a hashAlg no TCG table defines.
        var body = new List<byte>();
        AppendUInt32(body, key.Handle);
        AppendUInt16(body, (ushort)Sha256WidthDigest.Length);
        body.AddRange(Sha256WidthDigest);
        AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_HMAC);
        AppendUInt16(body, 0x4242);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_VerifySignature, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, code, "An unrecognized TPMT_HA hashAlg must be refused with the bare TPM_RC_HASH unmarshal channel.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The refusal fires at the wire read, so a refused parse must rent nothing.");
    }

    /// <summary>
    /// The metered pool balances across the KEYEDHASH signing family — a <c>TPM2_Sign()</c> success, a
    /// <c>TPM_RC_SCHEME</c> refusal, and a <c>TPM2_VerifySignature()</c> round trip each release every
    /// parse-rented and effect-rented carrier once their responses are disposed — the ownership discipline
    /// every arm of the family documents (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clauses 20.2, 20.5).
    /// </summary>
    [TestMethod]
    public async Task HmacSigningCommandsBalanceTheMeteredPoolAcrossSuccessAndRefusal()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacSigningCommandsBalanceTheMeteredPoolAcrossSuccessAndRefusal), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<SignResponse> signResult = await SignAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign() must succeed: '{signResult.ResponseCode}'.");
        byte[] signature = signResult.Value.Signature.HmacSignature!.AsReadOnlyMemory().ToArray();
        signResult.Value.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A disposed TPM2_Sign() success must balance the pool.");

        TpmResult<SignResponse> refusedResult = await SignAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, refusedResult.ResponseCode, "The scheme refusal must hold under the metered pool.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused TPM2_Sign() must release every parse-rented carrier.");

        TpmResult<VerifySignatureResponse> verifyResult = await VerifySignatureAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, signature, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature() must succeed: '{verifyResult.ResponseCode}'.");
        verifyResult.Value.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A disposed TPM2_VerifySignature() success must balance the pool.");

        TpmResult<VerifySignatureResponse> refusedVerifyResult = await VerifySignatureAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, new byte[32], TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, refusedVerifyResult.ResponseCode, "The post-parse SIGNATURE refusal must hold under the metered pool.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A TPM2_VerifySignature() refused inside the effect must release the digest and signature carriers.");
    }

    /// <summary>
    /// "If the sign attribute is not SET in the key referenced by handle, then the TPM shall return TPM_RC_KEY"
    /// — an XOR-scheme decryption object (<c>decrypt</c> SET, <c>sign</c> CLEAR, a populated XOR scheme) at
    /// <c>TPM2_Sign()</c> is refused with <c>TPM_RC_KEY</c> under a correct (empty) authorization: its sensitive
    /// bits are keying material and must never serve as a signing oracle
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5.1).
    /// </summary>
    [TestMethod]
    public async Task SignOverAnXorSchemeDecryptObjectIsRefusedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignOverAnXorSchemeDecryptObjectIsRefusedWithKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint xorHandle = await CreateAndLoadXorDecryptObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        TpmResult<SignResponse> result = await SignAsync(
            tpm, registry, pool, xorHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "An XOR-scheme decryption object (sign CLEAR) at TPM2_Sign() must be refused with TPM_RC_KEY.");
    }

    /// <summary>
    /// The key slot's authorization is decided before any command rule: a WRONG password against a sealed data
    /// object answers the authorization failure (session-index-0-encoded <c>TPM_RC_BAD_AUTH</c> — the seal template
    /// is <c>noDA</c>), never the <c>TPM_RC_KEY</c> the sign gate would give, and a wrong password against a
    /// restricted HMAC key answers the same, never <c>TPM_RC_TICKET</c> — so a caller without the object's
    /// authValue learns nothing about what kind of object the handle names
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.6 (the mandatory check order), clause 20.5.2, Table 122).
    /// </summary>
    [TestMethod]
    public async Task SignWithAWrongPasswordIsRefusedBeforeAnyCommandRule()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignWithAWrongPasswordIsRefusedBeforeAnyCommandRule), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] sealedPassword = [0x70, 0x77];
        (uint sealedHandle, _) = await PolicySweepHarness.SealAndLoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SealedSecretBytes, ReadOnlyMemory<byte>.Empty, userAuth: sealedPassword, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<SignResponse> sealedResult = await SignAsync(
            tpm, registry, pool, sealedHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, keyPassword: WrongKeyPassword).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), sealedResult.ResponseCode,
            "A wrong password against a sealed data object must answer the authorization failure, not the sign gate's TPM_RC_KEY.");

        uint restrictedHandle = await CreateAndLoadRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
        TpmResult<SignResponse> restrictedResult = await SignAsync(
            tpm, registry, pool, restrictedHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, keyPassword: WrongKeyPassword).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), restrictedResult.ResponseCode,
            "A wrong password against a restricted HMAC key must answer the authorization failure, not the ticket rule's TPM_RC_TICKET.");
    }

    /// <summary>
    /// Once <c>failedTries</c> reaches <c>maxTries</c> the TPM is in Lockout mode, and <c>TPM2_Sign()</c> with
    /// the CORRECT password over a DA-protected HMAC key is refused with <c>TPM_RC_LOCKOUT</c> without moving
    /// the counter, while a <c>noDA</c> key keeps signing
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.6, check 3; Part 1: Architecture, clause 16.8).
    /// </summary>
    [TestMethod]
    public async Task SignInLockoutIsRefusedForADaProtectedHmacKeyAndAdmittedForANoDaKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignInLockoutIsRefusedForADaProtectedHmacKeyAndAdmittedForANoDaKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] password = [0x6b, 0x70];
        using HmacKeyHarness.LoadedHmacKey daKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: password, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey noDaKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: password, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await EnterLockoutAsync(tpm, registry, pool, daKey.Handle).ConfigureAwait(false);
        uint lockedOutCounter = await ReadLockoutCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<SignResponse> refused = await SignAsync(
            tpm, registry, pool, daKey.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, keyPassword: password).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, refused.ResponseCode, "In Lockout mode a DA-protected HMAC key must be refused with TPM_RC_LOCKOUT even under the correct password.");
        Assert.AreEqual(lockedOutCounter, await ReadLockoutCounterAsync(tpm, registry, pool).ConfigureAwait(false), "A Lockout-mode refusal must not move failedTries.");

        TpmResult<SignResponse> admitted = await SignAsync(
            tpm, registry, pool, noDaKey.Handle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, keyPassword: password).ConfigureAwait(false);
        Assert.IsTrue(admitted.IsSuccess, $"A noDA HMAC key must keep signing in Lockout mode: '{admitted.ResponseCode}'.");
        admitted.Value.Dispose();
    }

    /// <summary>
    /// The same Lockout-mode rule at <c>TPM2_SignSequenceComplete()</c>'s <c>@keyHandle</c>: a sequence opened
    /// before the lockout cannot be completed under a DA-protected HMAC key (<c>TPM_RC_LOCKOUT</c>, the counter
    /// untouched), while one bound to a <c>noDA</c> key completes
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.6, check 3, clause 20.6.2, Table 124; Part 1: Architecture, clause 16.8).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceCompleteInLockoutIsRefusedForADaProtectedHmacKeyAndAdmittedForANoDaKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignSequenceCompleteInLockoutIsRefusedForADaProtectedHmacKeyAndAdmittedForANoDaKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] password = [0x6b, 0x70];
        using HmacKeyHarness.LoadedHmacKey daKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: password, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey noDaKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: password, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject daSequence = await StartSignSequenceAsync(tpm, registry, pool, daKey.Handle).ConfigureAwait(false);
        TpmiDhObject noDaSequence = await StartSignSequenceAsync(tpm, registry, pool, noDaKey.Handle).ConfigureAwait(false);

        await EnterLockoutAsync(tpm, registry, pool, daKey.Handle).ConfigureAwait(false);
        uint lockedOutCounter = await ReadLockoutCounterAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<SignSequenceCompleteResponse> refused = await SignSequenceCompleteAsync(
            tpm, registry, pool, daSequence, daKey.Handle, Rfc4231Case3Data, keyAuth: password).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, refused.ResponseCode, "In Lockout mode a DA-protected HMAC key must be refused at Complete with TPM_RC_LOCKOUT even under the correct password.");
        Assert.AreEqual(lockedOutCounter, await ReadLockoutCounterAsync(tpm, registry, pool).ConfigureAwait(false), "A Lockout-mode refusal must not move failedTries.");

        TpmResult<SignSequenceCompleteResponse> admitted = await SignSequenceCompleteAsync(
            tpm, registry, pool, noDaSequence, noDaKey.Handle, Rfc4231Case3Data, keyAuth: password).ConfigureAwait(false);
        Assert.IsTrue(admitted.IsSuccess, $"A noDA HMAC key must complete its sequence in Lockout mode: '{admitted.ResponseCode}'.");
        admitted.Value.Dispose();
    }

    /// <summary>
    /// <c>hint</c> "must be zero-length" for every signature algorithm but EdDSA (Table 222) — a one-octet
    /// <c>hint</c> at <c>TPM2_VerifySequenceStart()</c> over an HMAC key is refused with <c>TPM_RC_SIZE</c> and
    /// every parse-rented carrier is released (the metered pool balances)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.6; Part 2: Structures, clause 11.3.9, Table 222).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOverAnHmacKeyWithANonEmptyHintIsRefusedWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySequenceStartOverAnHmacKeyWithANonEmptyHintIsRefusedWithSize), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_VerifySequenceStart,
            BuildVerifySequenceStartBody(key.Handle, hint: [0x01], context: [])).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A non-empty hint at TPM2_VerifySequenceStart() over an HMAC key must be refused with TPM_RC_SIZE.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The refused Start must release every parse-rented carrier.");
    }

    /// <summary>
    /// A non-empty <c>context</c> at <c>TPM2_VerifySequenceStart()</c> over an HMAC key is refused with
    /// <c>TPM_RC_SIZE</c> — the scheme consumes no context (Table 220's <c>empty[0]</c> arm) — and every
    /// parse-rented carrier is released (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 17.6; Part 2: Structures, clause 11.3.7, Table 220).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOverAnHmacKeyWithANonEmptyContextIsRefusedWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySequenceStartOverAnHmacKeyWithANonEmptyContextIsRefusedWithSize), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_VerifySequenceStart,
            BuildVerifySequenceStartBody(key.Handle, hint: [], context: [0x01])).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A non-empty context at TPM2_VerifySequenceStart() over an HMAC key must be refused with TPM_RC_SIZE.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The refused Start must release every parse-rented carrier.");
    }

    /// <summary>
    /// A non-empty <c>context</c> at <c>TPM2_SignSequenceStart()</c> over an HMAC key is refused with
    /// <c>TPM_RC_SIZE</c> — "depending on the scheme, context may be optional, i.e., zero-length", and the HMAC
    /// scheme consumes none (Table 220's <c>empty[0]</c> arm) — with every parse-rented carrier released
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5.2, Table 87; Part 2: Structures, clause 11.3.7, Table 220).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartOverAnHmacKeyWithANonEmptyContextIsRefusedWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SignSequenceStartOverAnHmacKeyWithANonEmptyContextIsRefusedWithSize), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //keyHandle, an empty auth (TPM2B), then a one-octet context (TPM2B) — Table 87's parameter order.
        var body = new List<byte>();
        AppendUInt32(body, key.Handle);
        AppendUInt16(body, 0);
        AppendUInt16(body, 1);
        body.Add(0x01);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_SignSequenceStart, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A non-empty context at TPM2_SignSequenceStart() over an HMAC key must be refused with TPM_RC_SIZE.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The refused Start must release every parse-rented carrier.");
    }

    /// <summary>
    /// "If keyHandle refers to a key that is not the same as the key that was used to start the signature
    /// context, the TPM shall return TPM_RC_SIGN_CONTEXT_KEY" — at <c>TPM2_VerifySequenceComplete()</c>, whose
    /// <c>keyHandle</c> carries no authorization, a SAME-template second HMAC key (its Name distinct through
    /// equation (8)'s <c>unique</c> over its own sensitive area) is refused and
    /// the sequence survives for the right key (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 20.3.1, Table 118; Part 1: Architecture, clause 13, Table 9 for the Name).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteWithASwappedHmacKeyIsRefusedWithSignContextKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySequenceCompleteWithASwappedHmacKeyIsRefusedWithSignContextKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey startingKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey otherKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(startingKey.Name.Span.SequenceEqual(otherKey.Name.Span), "Same-template keys must differ in Name through their uniques, so the gate under test is the one deciding.");

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, startingKey.Handle).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, Rfc4231Case3Data).ConfigureAwait(false);

        TpmResult<VerifySequenceCompleteResponse> swappedResult = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, otherKey.Handle, Rfc4231Case3Sha256, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY, swappedResult.ResponseCode, "A key other than the sequence's starting key must be refused with TPM_RC_SIGN_CONTEXT_KEY.");

        TpmResult<VerifySequenceCompleteResponse> retryResult = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, startingKey.Handle, Rfc4231Case3Sha256, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.IsTrue(retryResult.IsSuccess, $"The refused attempt must leave the sequence intact for the right key: '{retryResult.ResponseCode}'.");
        retryResult.Value.Dispose();
    }

    /// <summary>
    /// The signature's own hash is bounded to the hashes this simulator implements ahead of every other rule: a
    /// <c>TPMT_HA</c> member carrying <c>TPM_ALG_SHA1</c> parses (its width is known) but is refused with
    /// <c>TPM_RC_HASH</c> — not the <c>TPM_RC_SIGNATURE</c> a supported-but-mismatched hash draws — so the two
    /// channels stay distinguishable on the wire (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clause 20.2; Part 2: Structures, clause 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithASha1SignatureHashIsRefusedWithHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySignatureWithASha1SignatureHashIsRefusedWithHash), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<VerifySignatureResponse> result = await VerifySignatureAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, new byte[20], TpmAlgIdConstants.TPM_ALG_SHA1).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, result.ResponseCode, "A SHA-1 signature hash must be refused with TPM_RC_HASH ahead of the scheme and signature gates.");
    }

    /// <summary>
    /// "If the key is in the NULL hierarchy, then hmac in the ticket will be the Empty Buffer" — an HMAC key
    /// loaded under a NULL-hierarchy parent verifies, and the minted <c>TPM_ST_VERIFIED</c> ticket is the NULL
    /// ticket tuple (NULL hierarchy, empty <c>hmac</c>, no metadata)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.2.1; Part 2: Structures, clause 10.6.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureOverANullHierarchyHmacKeyMintsTheNullTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySignatureOverANullHierarchyHmacKeyMintsTheNullTicket), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken, hierarchy: TpmRh.TPM_RH_NULL).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] signature = HMACSHA256.HashData(Rfc4231Case3Key, Sha256WidthDigest);
        TpmResult<VerifySignatureResponse> result = await VerifySignatureAsync(
            tpm, registry, pool, key.Handle, Sha256WidthDigest, signature, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySignature() under a NULL-hierarchy HMAC key must succeed: '{result.ResponseCode}'.");
        using VerifySignatureResponse response = result.Value;

        Assert.AreEqual(TpmStConstants.TPM_ST_VERIFIED, response.Validation.Tag, "The ticket must be tagged TPM_ST_VERIFIED.");
        Assert.IsTrue(response.Validation.Hierarchy.IsNull, "The ticket hierarchy must be the NULL hierarchy.");
        Assert.IsTrue(response.Validation.Hmac.IsEmpty, "A NULL-hierarchy key's ticket hmac must be the Empty Buffer.");
        Assert.IsTrue(response.Validation.IsNull, "The whole ticket must be the NULL ticket tuple.");
        Assert.IsFalse(response.Validation.Metadata.HasValue, "A TPM_ST_VERIFIED ticket carries no metadata.");
    }

    /// <summary>
    /// The same NULL-hierarchy rule on the sequence form: "If the key is in the NULL hierarchy, then hmac in the
    /// ticket will be the Empty Buffer" — the <c>TPM_ST_MESSAGE_VERIFIED</c> ticket over a message verified
    /// under a NULL-hierarchy HMAC key is the NULL ticket tuple
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.3.1; Part 2: Structures, clause 10.6.2).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceCompleteOverANullHierarchyHmacKeyMintsTheNullTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySequenceCompleteOverANullHierarchyHmacKeyMintsTheNullTicket), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken, hierarchy: TpmRh.TPM_RH_NULL).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.Handle).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, Rfc4231Case3Data).ConfigureAwait(false);

        TpmResult<VerifySequenceCompleteResponse> result = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, Rfc4231Case3Sha256, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySequenceComplete() under a NULL-hierarchy HMAC key must succeed: '{result.ResponseCode}'.");
        using VerifySequenceCompleteResponse response = result.Value;

        Assert.AreEqual(TpmStConstants.TPM_ST_MESSAGE_VERIFIED, response.Validation.Tag, "The ticket must be tagged TPM_ST_MESSAGE_VERIFIED.");
        Assert.IsTrue(response.Validation.Hierarchy.IsNull, "The ticket hierarchy must be the NULL hierarchy.");
        Assert.IsTrue(response.Validation.Hmac.IsEmpty, "A NULL-hierarchy key's ticket hmac must be the Empty Buffer.");
        Assert.IsFalse(response.Validation.Metadata.HasValue, "A TPM_ST_MESSAGE_VERIFIED ticket carries no metadata.");
    }

    /// <summary>
    /// Verification is not restricted-gated on the sequence form either: clause 17.6 states only the
    /// signing-key and NULL-scheme refusals, so a restricted HMAC key opens a verification sequence (where
    /// <c>TPM2_SignSequenceStart()</c> refuses it), and the completing compare is reached — a wrong signature
    /// answers <c>TPM_RC_SIGNATURE</c>, never an attribute refusal
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 17.6.1, 20.3.1).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartOverARestrictedHmacKeyOpensASequenceThatReachesTheSignatureCompare()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySequenceStartOverARestrictedHmacKeyOpensASequenceThatReachesTheSignatureCompare), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint restrictedHandle = await CreateAndLoadRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, restrictedHandle).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, Rfc4231Case3Data).ConfigureAwait(false);

        TpmResult<VerifySequenceCompleteResponse> result = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, restrictedHandle, new byte[32], TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, result.ResponseCode, "A restricted HMAC key must reach the compare on the sequence form and answer TPM_RC_SIGNATURE — verification is not restricted-gated.");
    }

    /// <summary>
    /// A <c>TPMT_HA</c> member whose <c>hashAlg</c> sizes the digest wider than the octets that remain on the
    /// wire is refused at the unmarshal with <c>TPM_RC_INSUFFICIENT</c>, before any pooled rental — the parse
    /// never reads past the frame (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 2: Structures, clause 10.2.2, Table 89; Part 3: Commands, clause 5.8.2, Table 2).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithATruncatedHmacMemberOnTheWireIsRefusedWithInsufficientBeforeAnyRental()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySignatureWithATruncatedHmacMemberOnTheWireIsRefusedWithInsufficientBeforeAnyRental), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //keyHandle, digest (TPM2B), sigAlg = TPM_ALG_HMAC, hashAlg = SHA-512, then fewer octets than SHA-512 sizes.
        var body = new List<byte>();
        AppendUInt32(body, key.Handle);
        AppendUInt16(body, (ushort)Sha256WidthDigest.Length);
        body.AddRange(Sha256WidthDigest);
        AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_HMAC);
        AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_SHA512);
        body.AddRange(new byte[20]);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_VerifySignature, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INSUFFICIENT, code, "A TPMT_HA member shorter than its hashAlg sizes must be refused with TPM_RC_INSUFFICIENT.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The refusal fires at the wire read, so a refused parse must rent nothing.");
    }

    /// <summary>
    /// The metered pool balances across the sign-sequence family over an HMAC key: <c>TPM2_SignSequenceStart()</c>
    /// rents the sequence context, two <c>TPM2_SequenceUpdate()</c>s add segments, a refused
    /// <c>TPM2_SignSequenceComplete()</c> (a swapped key, <c>TPM_RC_SIGN_CONTEXT_KEY</c>) releases the buffer
    /// and passwords it parsed while the sequence stays, and the successful Complete — the effect owning the
    /// trailing buffer, the continuation flushing the segments — returns the count to the pre-Start baseline
    /// once its response is disposed (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clauses 17.5, 17.7, 20.6; Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task HmacSignSequenceCommandsBalanceTheMeteredPoolAcrossRefusalAndSuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacSignSequenceCommandsBalanceTheMeteredPoolAcrossRefusalAndSuccess), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey otherKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_SHA256, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmiDhObject sequenceHandle = await StartSignSequenceAsync(tpm, registry, pool, key.Handle).ConfigureAwait(false);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount, "An open sequence holds pooled context, so the later balance assertion is not vacuous.");

        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, Rfc4231Case3Data.AsSpan(0, 20).ToArray()).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, Rfc4231Case3Data.AsSpan(20, 20).ToArray()).ConfigureAwait(false);
        long afterUpdates = trackingPool.OutstandingCount;

        TpmResult<SignSequenceCompleteResponse> refused = await SignSequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, otherKey.Handle, Rfc4231Case3Data.AsSpan(40).ToArray()).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGN_CONTEXT_KEY, refused.ResponseCode, "The swapped-key refusal must hold under the metered pool.");
        Assert.AreEqual(afterUpdates, trackingPool.OutstandingCount, "A refused Complete must release its parsed buffer and passwords while the sequence keeps its segments.");

        TpmResult<SignSequenceCompleteResponse> completed = await SignSequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, Rfc4231Case3Data.AsSpan(40).ToArray()).ConfigureAwait(false);
        Assert.IsTrue(completed.IsSuccess, $"TPM2_SignSequenceComplete() must succeed: '{completed.ResponseCode}'.");
        Assert.IsTrue(completed.Value.Signature.HmacSignature!.AsReadOnlyMemory().Span.SequenceEqual(Rfc4231Case3Sha256), "The chained message must still reproduce the published HMAC.");
        completed.Value.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A disposed successful Complete — the sequence flushed — must return the pool to the pre-Start baseline.");
    }

    /// <summary>
    /// The metered pool balances across the verify-sequence family over an HMAC key: after
    /// <c>TPM2_VerifySequenceStart()</c> and a <c>TPM2_SequenceUpdate()</c>, a <c>TPM2_VerifySequenceComplete()</c>
    /// refused inside the effect (<c>TPM_RC_SIGNATURE</c>) releases the signature it parsed while the sequence
    /// stays retained, and the successful Complete returns the count to the pre-Start baseline once its
    /// response is disposed (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3: Commands, clauses 17.6, 17.7, 20.3; Part 1: Architecture, clause 29.4.6).
    /// </summary>
    [TestMethod]
    public async Task HmacVerifySequenceCommandsBalanceTheMeteredPoolAcrossRefusalAndSuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacVerifySequenceCommandsBalanceTheMeteredPoolAcrossRefusalAndSuccess), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmiDhObject sequenceHandle = await StartVerifySequenceAsync(tpm, registry, pool, key.Handle).ConfigureAwait(false);
        Assert.IsGreaterThan(baseline, trackingPool.OutstandingCount, "An open sequence holds pooled context, so the later balance assertion is not vacuous.");

        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, Rfc4231Case3Data).ConfigureAwait(false);
        long afterUpdate = trackingPool.OutstandingCount;

        TpmResult<VerifySequenceCompleteResponse> refused = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, new byte[32], TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, refused.ResponseCode, "The signature refusal must hold under the metered pool.");
        Assert.AreEqual(afterUpdate, trackingPool.OutstandingCount, "A Complete refused inside the effect must release the signature it parsed while the sequence keeps its segments.");

        TpmResult<VerifySequenceCompleteResponse> completed = await VerifySequenceCompleteAsync(
            tpm, registry, pool, sequenceHandle, key.Handle, Rfc4231Case3Sha256, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);
        Assert.IsTrue(completed.IsSuccess, $"TPM2_VerifySequenceComplete() must succeed: '{completed.ResponseCode}'.");
        completed.Value.Dispose();
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A disposed successful Complete — the sequence flushed — must return the pool to the pre-Start baseline.");
    }

    /// <summary>
    /// A well-formed <c>TPMT_HA</c> member followed by one octet the wire layout does not admit — <c>signature</c>
    /// is the final parameter, so nothing may follow it — is refused with <c>TPM_RC_SIZE</c>; the signature
    /// carrier the parse rented before the trailing-octet check is released, so the metered pool balances
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 5.2; Part 2: Structures, clause 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithAnOctetAfterTheHmacMemberOnTheWireIsRefusedWithSizeAndReleasesTheCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using var simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(VerifySignatureWithAnOctetAfterTheHmacMemberOnTheWireIsRefusedWithSizeAndReleasesTheCarrier), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //keyHandle, digest (TPM2B), sigAlg = TPM_ALG_HMAC, hashAlg = SHA-256, a full 32-octet digest, then one octet too many.
        var body = new List<byte>();
        AppendUInt32(body, key.Handle);
        AppendUInt16(body, (ushort)Sha256WidthDigest.Length);
        body.AddRange(Sha256WidthDigest);
        AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_HMAC);
        AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        body.AddRange(HMACSHA256.HashData(Rfc4231Case3Key, Sha256WidthDigest));
        body.Add(0xAA);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_VerifySignature, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An octet after the final parameter must be refused with TPM_RC_SIZE.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The trailing-octet refusal disposes the signature carrier the parse already rented.");
    }


    /// <summary>Builds the response codec registry covering every command these tests issue: the HMAC-key harness set plus the signing family.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceComplete, TpmResponseCodec.VerifySequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);
        _ = registry.Register(TpmCcConstants.TPM_CC_DictionaryAttackParameters, TpmResponseCodec.DictionaryAttackParameters);

        return registry;
    }

    /// <summary>
    /// Creates and loads an XOR-scheme decryption KEYEDHASH object (<c>decrypt</c> SET, <c>sign</c> CLEAR,
    /// <c>TPM_ALG_XOR</c> over SHA-256 with KDF1_SP800_108, TPM-generated bits) — the non-signing KEYEDHASH
    /// shape whose scheme field is populated.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <returns>The loaded object's transient handle.</returns>
    private async Task<uint> CreateAndLoadXorDecryptObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateKeyedHashObjectAsync(
            tpm, registry, pool, parentHandle, BoundAttributes | TpmaObject.DECRYPT | TpmaObject.SENSITIVE_DATA_ORIGIN,
            TpmsKeyedHashParms.Xor(TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108), ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (XOR decrypt object) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parentHandle, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (XOR decrypt object) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        return loaded.ObjectHandle.Value;
    }

    /// <summary>
    /// Drives the TPM into Lockout mode: lowers <c>maxTries</c> and fails the key's password that many times at
    /// <c>TPM2_Sign()</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="daKeyHandle">A loaded DA-protected HMAC key to fail against.</param>
    private async Task EnterLockoutAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint daKeyHandle)
    {
        TpmResult<DictionaryAttackParametersResponse> lowered = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LockoutTestMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowered.IsSuccess, $"Lowering maxTries failed: '{lowered.ResponseCode}'.");

        for(uint attempt = 1; attempt <= LockoutTestMaxTries; attempt++)
        {
            TpmResult<SignResponse> wrong = await SignAsync(
                tpm, registry, pool, daKeyHandle, Sha256WidthDigest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, keyPassword: WrongKeyPassword).ConfigureAwait(false);
            Assert.IsFalse(wrong.IsSuccess, $"Attempt {attempt} of {LockoutTestMaxTries} with a wrong password must fail.");
        }

        TpmResult<TpmDictionaryAttackParameters> state = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(state.IsSuccess, $"GetDictionaryAttackParameters failed: '{state.ResponseCode}'.");
        Assert.IsTrue(state.Value.IsLockedOut, "The TPM must be in Lockout mode before the locked-out cases run.");
    }

    /// <summary>Derives a hierarchy's ticket proof as the seeded simulator does: <c>H(seed ‖ hierarchy)</c>.</summary>
    /// <param name="hierarchy">The hierarchy handle.</param>
    /// <returns>The proof octets.</returns>
    private static byte[] DeriveTicketProof(uint hierarchy)
    {
        byte[] input = new byte[TicketSeed.Length + sizeof(uint)];
        var writer = new TpmWriter(input);
        writer.WriteBytes(TicketSeed);
        writer.WriteUInt32(hierarchy);

        return SHA256.HashData(input);
    }

    /// <summary>
    /// Builds a <c>TPMT_TK_VERIFIED</c> ticket HMAC message — Equation (5): the tag (UINT16), the signed digest
    /// or the RAW accumulated message, and the verifying key's Name, with no metadata
    /// (TPM 2.0 Library Part 2, clause 10.6.5).
    /// </summary>
    /// <param name="tag">The ticket tag (<c>TPM_ST_VERIFIED</c> or <c>TPM_ST_MESSAGE_VERIFIED</c>).</param>
    /// <param name="digestOrMessage">The digest, or the whole message for the sequence form.</param>
    /// <param name="keyName">The verifying key's Name.</param>
    /// <returns>The ticket message octets.</returns>
    private static byte[] BuildVerifiedTicketMessage(TpmStConstants tag, ReadOnlySpan<byte> digestOrMessage, ReadOnlySpan<byte> keyName)
    {
        byte[] result = new byte[sizeof(ushort) + digestOrMessage.Length + keyName.Length];
        var writer = new TpmWriter(result);
        writer.WriteUInt16((ushort)tag);
        writer.WriteBytes(digestOrMessage);
        writer.WriteBytes(keyName);

        return result;
    }

    /// <summary>Frames a <c>TPM2_VerifySequenceStart()</c> body — keyHandle, an empty <c>auth</c>, then <c>hint</c> and <c>context</c> as TPM2Bs (Part 3: Commands, clause 17.6.2, Table 89's parameter order).</summary>
    /// <param name="keyHandle">The key handle.</param>
    /// <param name="hint">The <c>hint</c> octets.</param>
    /// <param name="context">The <c>context</c> octets.</param>
    /// <returns>The command body after the header.</returns>
    private static byte[] BuildVerifySequenceStartBody(uint keyHandle, byte[] hint, byte[] context)
    {
        var body = new List<byte>();
        AppendUInt32(body, keyHandle);
        AppendUInt16(body, 0);
        AppendUInt16(body, (ushort)hint.Length);
        body.AddRange(hint);
        AppendUInt16(body, (ushort)context.Length);
        body.AddRange(context);

        return [.. body];
    }

    /// <summary>Submits <c>TPM2_Sign()</c> over one <c>TPM_RS_PW</c> session presenting <paramref name="keyPassword"/> and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The signing-key handle.</param>
    /// <param name="digest">The digest to sign.</param>
    /// <param name="scheme">The <c>inScheme</c> selector (may be <c>TPM_ALG_NULL</c>).</param>
    /// <param name="schemeHashAlg">The scheme hash (absent on the wire for a NULL scheme).</param>
    /// <param name="keyPassword">The password presented for the key slot; empty when omitted.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SignResponse>> SignAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle, byte[] digest,
        TpmAlgIdConstants scheme, TpmAlgIdConstants schemeHashAlg, ReadOnlyMemory<byte> keyPassword = default)
    {
        using SignInput input = SignInput.Create(TpmiDhObject.FromValue(keyHandle), digest, scheme, schemeHashAlg, pool);
        using TpmPasswordSession keyAuth = HmacKeyHarness.PasswordSession(keyPassword, pool);

        return await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Submits <c>TPM2_VerifySignature()</c> with an HMAC-member signature (no authorization — Table 116) and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The verifying-key handle.</param>
    /// <param name="digest">The digest the signature is claimed to be over.</param>
    /// <param name="signature">The claimed HMAC octets (the <c>TPMT_HA</c> member's unsized value).</param>
    /// <param name="schemeHashAlg">The hash carried inside the signature.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<VerifySignatureResponse>> VerifySignatureAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle, byte[] digest, byte[] signature, TpmAlgIdConstants schemeHashAlg)
    {
        using VerifySignatureInput input = VerifySignatureInput.Create(
            TpmiDhObject.FromValue(keyHandle), digest, signature, TpmAlgIdConstants.TPM_ALG_HMAC, schemeHashAlg, pool);

        return await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Starts a signing sequence over the HMAC key (no session — Part 3: Commands, clause 17.5.2, Table 87's keyHandle carries no <c>@</c>), asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The HMAC key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue; empty when omitted.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartSignSequenceAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle, byte[]? sequenceAuth = null)
    {
        using SignSequenceStartInput input = SignSequenceStartInput.Create(TpmiDhObject.FromValue(keyHandle), sequenceAuth ?? [], pool);
        TpmResult<SignSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceStart() over an HMAC key failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>Starts a verification sequence over the HMAC key (no session — Part 3: Commands, clause 17.6.2, Table 89's keyHandle carries no <c>@</c>), asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The HMAC key handle.</param>
    /// <returns>The started sequence's handle.</returns>
    private async Task<TpmiDhObject> StartVerifySequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle)
    {
        using VerifySequenceStartInput input = VerifySequenceStartInput.Create(TpmiDhObject.FromValue(keyHandle), [], pool);
        TpmResult<VerifySequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySequenceStart() over an HMAC key failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle;
    }

    /// <summary>Appends a buffer to an open sequence over the sequence's empty-auth <c>TPM_RS_PW</c> session, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="buffer">The update buffer.</param>
    private async Task UpdateSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, byte[] buffer)
    {
        using TpmPasswordSession sequenceSession = TpmPasswordSession.CreateEmpty(pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(sequenceHandle, buffer, pool);
        TpmResult<SequenceUpdateResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() failed: '{result.ResponseCode}'.");
    }

    /// <summary>Submits <c>TPM2_SignSequenceComplete()</c> over two <c>TPM_RS_PW</c> sessions (sequence then key) and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="keyHandle">The candidate signing-key handle.</param>
    /// <param name="buffer">The trailing Complete buffer.</param>
    /// <param name="sequenceAuth">The sequence password; empty when omitted.</param>
    /// <param name="keyAuth">The key password; empty when omitted.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SignSequenceCompleteResponse>> SignSequenceCompleteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, uint keyHandle, byte[] buffer,
        ReadOnlyMemory<byte> sequenceAuth = default, ReadOnlyMemory<byte> keyAuth = default)
    {
        using TpmPasswordSession sequenceSession = HmacKeyHarness.PasswordSession(sequenceAuth, pool);
        using TpmPasswordSession keySession = HmacKeyHarness.PasswordSession(keyAuth, pool);
        using SignSequenceCompleteInput input = SignSequenceCompleteInput.Create(sequenceHandle, TpmiDhObject.FromValue(keyHandle), buffer, pool);

        return await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, input, [sequenceSession, keySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Submits <c>TPM2_VerifySequenceComplete()</c> over the sequence's <c>TPM_RS_PW</c> session (keyHandle carries no <c>@</c> — Part 3: Commands, clause 20.3.2, Table 118) and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The sequence handle.</param>
    /// <param name="keyHandle">The verifying-key handle.</param>
    /// <param name="signature">The claimed HMAC octets (the <c>TPMT_HA</c> member's unsized value).</param>
    /// <param name="schemeHashAlg">The hash carried inside the signature.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<VerifySequenceCompleteResponse>> VerifySequenceCompleteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject sequenceHandle, uint keyHandle, byte[] signature, TpmAlgIdConstants schemeHashAlg)
    {
        using TpmPasswordSession sequenceSession = TpmPasswordSession.CreateEmpty(pool);
        using VerifySequenceCompleteInput input = VerifySequenceCompleteInput.Create(
            sequenceHandle, TpmiDhObject.FromValue(keyHandle), signature, TpmAlgIdConstants.TPM_ALG_HMAC, schemeHashAlg, pool);

        return await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(
            tpm, input, [sequenceSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates and loads a RESTRICTED HMAC signing key: the create gates require <c>sensitiveDataOrigin</c>
    /// SET for a restricted KEYEDHASH key, so its bits are TPM-generated and unknown to the caller.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <returns>The loaded restricted key's transient handle.</returns>
    private async Task<uint> CreateAndLoadRestrictedHmacKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
            tpm, registry, pool, parentHandle, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            isRestricted: true, isSensitiveDataOrigin: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (restricted HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parentHandle, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (restricted HMAC key) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        return loaded.ObjectHandle.Value;
    }

    /// <summary>Reads <c>TPM_PT_LOCKOUT_COUNTER</c>, the live <c>failedTries</c> value, back over <c>TPM2_GetCapability()</c>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The reported counter value.</returns>
    private async Task<uint> ReadLockoutCounterAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            tpm, GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, count: 1), [], null, pool, registry,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"GetCapability(TPM_PT_LOCKOUT_COUNTER) failed: '{result.ResponseCode}'.");

        using GetCapabilityResponse properties = result.Value;
        var reported = properties.CapabilityData.TpmProperties;
        Assert.IsNotNull(reported);
        Assert.IsNotEmpty(reported);
        Assert.AreEqual(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, reported[0].Property);

        return reported[0].Value;
    }

    /// <summary>Frames a raw command (header plus <paramref name="body"/>) and submits it, returning the response code alone.</summary>
    /// <param name="simulator">The simulator to submit to.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="commandCode">The command code.</param>
    /// <param name="body">The command body after the header.</param>
    /// <returns>The response header's code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmStConstants tag, TpmCcConstants commandCode, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)tag, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a malformed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Appends a big-endian <c>UINT32</c> to a command body under construction.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt32(List<byte> body, uint value)
    {
        Span<byte> octets = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(octets, value);
        body.AddRange(octets);
    }

    /// <summary>Appends a big-endian <c>UINT16</c> to a command body under construction.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt16(List<byte> body, ushort value)
    {
        Span<byte> octets = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(octets, value);
        body.AddRange(octets);
    }
}
