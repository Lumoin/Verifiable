using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_NV_Certify()</c> (NV Index content attestation) against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="NvCertifyInput"/> and response codecs): <c>TPM2_NV_DefineSpace()</c>/<c>TPM2_NV_Write()</c>
/// provision and populate an NV Index, <c>TPM2_CreatePrimary()</c> mints an attestation key (AK) under the
/// endorsement hierarchy, then the AK certifies the Index's contents over a caller nonce.
/// </summary>
/// <remarks>
/// <para>
/// The result is verified <b>off-TPM</b> from wire bytes only: the magic / type / nonce fields, that the
/// attested indexName equals the Index's Name recomputed independently from its public-area fields, that the
/// attested nvContents equals the octets this test itself wrote, and the ECDSA/RSA signature over the raw
/// attestation bytes against the AK's exported public key reconstructed from <c>outPublic</c> alone. Only the
/// TPMS_NV_CERTIFY_INFO attestation form is modelled (TPM 2.0 Library Part 3, clause 31.16); the zero-size/offset
/// TPMS_NV_DIGEST_CERTIFY_INFO form is fail-closed rejected.
/// </para>
/// <para>
/// Both <c>@signHandle</c> and <c>@authHandle</c> require authorization (Table 255), so the executor is given two
/// password sessions in handle order: the AK's empty-auth session first, the Index's real authValue session
/// second.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorNvCertifyTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA NV-certify tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>An ordinary NV Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint NvIndexHandle = 0x0100_0002;

    /// <summary>The Index handle of the SHA-384 nameAlg, non-empty-authPolicy Index the attested-Name test certifies.</summary>
    private const uint Sha384NvIndexHandle = 0x0100_0003;

    /// <summary>The Index handle of the rotation-capable Index the Name-stability test certifies before and after an authValue rotation.</summary>
    private const uint RotatableNvIndexHandle = 0x0100_0004;

    /// <summary>The default Name algorithm every other Index in this file is defined with.</summary>
    private const TpmAlgIdConstants DefaultNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-384 digest width, in octets — the Name digest width of <see cref="Sha384NvIndexHandle"/>.</summary>
    private const int Sha384DigestSize = 48;

    /// <summary>Index attributes that authorize read/write with the Index authValue and are dictionary-attack protected (no TPMA_NV_NO_DA).</summary>
    private const TpmaNv DaProtectedAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE;

    /// <summary>The Index authorization value used by these tests.</summary>
    private static byte[] IndexAuth { get; } = [0x0A, 0x0B, 0x0C, 0x0D];

    /// <summary>The replacement Index authorization value the Name-stability test rotates to.</summary>
    private static byte[] RotatedIndexAuth { get; } = [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F];

    /// <summary>
    /// A non-empty, correctly-sized (48-octet, matching <see cref="Sha384NvIndexHandle"/>'s SHA-384 nameAlg)
    /// access policy digest. It is never satisfied — the Index is authorized with its own authValue — it exists
    /// so the certified Index's public area differs from the default SHA-256/Empty-Policy shape in BOTH fields
    /// the Name is computed over.
    /// </summary>
    private static byte[] Sha384AuthPolicy { get; } =
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30
    ];

    /// <summary>A wrong Index authorization value, distinct from <see cref="IndexAuth"/>.</summary>
    private static byte[] WrongIndexAuth { get; } = [0x99, 0x99, 0x99, 0x99];

    /// <summary>The hash algorithm for every HMAC-arm session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The Index handle the mixed-session test certifies, disjoint from the earlier password-only fixtures.</summary>
    private const uint HmacArmNvIndexHandle = 0x0100_0005;

    /// <summary>The Index handle the HMAC-arm NO_DA contrast test certifies.</summary>
    private const uint NoDaHmacArmNvIndexHandle = 0x0100_0006;

    /// <summary>Index attributes for <see cref="NoDaHmacArmNvIndexHandle"/>: <see cref="DaProtectedAttributes"/> plus <c>TPMA_NV_NO_DA</c>.</summary>
    private const TpmaNv NoDaProtectedAttributes = DaProtectedAttributes | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The Index handle the both-slots-real HMAC session test certifies.</summary>
    private const uint TwoRealSessionsNvIndexHandle = 0x0100_0007;

    /// <summary>The Index handle the real-sign-slot response-verification test certifies.</summary>
    private const uint RealSignSlotNvIndexHandle = 0x0100_0008;

    /// <summary>
    /// The Index handle of an AUTHREAD-CLEAR, dictionary-attack-protected Index: writable by its own
    /// authValue but readable only by the owner hierarchy, used by the read-role availability-gate regressions.
    /// </summary>
    private const uint AuthReadClearNvIndexHandle = 0x0100_0009;

    /// <summary>
    /// Index attributes for <see cref="AuthReadClearNvIndexHandle"/>: <c>TPMA_NV_AUTHWRITE</c> (so this
    /// test's own <see cref="DefineAndWriteNvIndexAsync(TpmDevice, TpmResponseRegistry, BaseMemoryPool, uint, TpmAlgIdConstants, TpmaNv, ReadOnlyMemory{byte})"/>
    /// can provision it with the Index's own authValue) and <c>TPMA_NV_OWNERREAD</c>, deliberately WITHOUT
    /// <c>TPMA_NV_AUTHREAD</c> (TPM 2.0 Library Part 1, clause 34.2.5) and WITHOUT <c>TPMA_NV_NO_DA</c>, so
    /// the Index stays dictionary-attack protected.
    /// </summary>
    private const TpmaNv AuthReadClearAttributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERREAD;

    /// <summary>
    /// A second, ordinary dictionary-attack-protected Index used only to prove the shared <c>failedTries</c>
    /// counter was left untouched by an attempt against <see cref="AuthReadClearNvIndexHandle"/>.
    /// </summary>
    private const uint DaProbeNvIndexHandle = 0x0100_000A;

    /// <summary>The Index handle the duplicate-real-session-handle regression certifies.</summary>
    private const uint DuplicateSessionNvIndexHandle = 0x0100_000B;

    /// <summary>The Index handle of the <c>TPM_NT_PIN_PASS</c> Index the pinCount single-update regression certifies.</summary>
    private const uint PinPassNvIndexHandle = 0x0100_000C;

    /// <summary>
    /// The size in octets of <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> (pinCount + pinLimit) — TPM 2.0 Library
    /// Part 2, clause 13.3.
    /// </summary>
    private const ushort PinCounterParametersSize = 8;

    /// <summary>
    /// PIN Pass attributes for <see cref="PinPassNvIndexHandle"/>: readable by its own authValue (the PIN),
    /// writable only by the owner hierarchy — a PIN Index's own pinCount/pinLimit throttle is its localized
    /// defense, distinct from the TPM-wide dictionary-attack mechanism this opts out of (TPM 2.0 Library Part
    /// 1, clause 34.2.6.6).
    /// </summary>
    private const TpmaNv PinPassCertifyAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_PASS << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>
    /// The pinLimit the pinCount single-update regression defines its Index with, chosen greater than one so
    /// a single certify cannot coincidentally exhaust it.
    /// </summary>
    private const uint PinPassCertifyPinLimit = 3;

    /// <summary>The Index handle the session-arm userWithAuth-CLEAR signer tests certify.</summary>
    private const uint UserWithAuthClearSessionNvIndexHandle = 0x0100_000D;

    /// <summary>
    /// The Index handle the sign-slot Lockout-gate proofs certify: dictionary-attack exempt
    /// (<see cref="NoDaProtectedAttributes"/>), so with the TPM in Lockout mode the Index arm's own lockout
    /// gate stays silent and only the signing key's own gate (TPM 2.0 Library Part 3, clause 5.6, check 3)
    /// can be the one answering <c>TPM_RC_LOCKOUT</c>.
    /// </summary>
    private const uint SignerLockoutNvIndexHandle = 0x0100_000E;

    /// <summary>
    /// A non-empty term a caller might mistakenly fold into a real sign-slot session's authValue — distinct
    /// from every other fixture in this file so a test failure cannot be mistaken for the Index's own auth.
    /// </summary>
    private static byte[] NonEmptySignSlotAuthValue { get; } = [0x55, 0x66, 0x77, 0x88];

    /// <summary>The password a signing key with a non-empty authValue is created with (the sign-slot verification proofs).</summary>
    private const string SignerKeyPassword = "signer-key-auth";

    /// <summary>The signing key's authValue in wire form — the UTF-8 octets <see cref="SignerKeyPassword"/> derives (TPM 2.0 Library authValue-from-password is UTF-8, trailing zeros trimmed).</summary>
    private static byte[] SignerKeyAuth { get; } = System.Text.Encoding.UTF8.GetBytes(SignerKeyPassword);

    /// <summary>A wrong guess at the signing key's authValue, distinct from <see cref="SignerKeyAuth"/>.</summary>
    private static byte[] WrongSignerKeyAuth { get; } = [0xDE, 0xAD, 0xBE, 0xEF];

    /// <summary>The known octets written to the NV Index before certifying its contents.</summary>
    private static byte[] WrittenData { get; } = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

    /// <summary>The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.</summary>
    private static byte[] Nonce { get; } = "NvCertify nonce for the in-house TPM."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies a full ECDSA P-256 NV-certify round trip: the attested indexName matches the Index's
    /// independently recomputed Name, the attested nvContents equals the octets this test wrote, qualifiedSigner
    /// is the AK's real (non-collapsed) Qualified Name, and the signature verifies against the AK's exported
    /// public key (TPM 2.0 Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task EcdsaP256NvCertifyVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify failed: '{result.ResponseCode}'.");

        using NvCertifyResponse nvCertify = result.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, nvCertify.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, nvCertify.HashAlgorithm);

        await AssertNvCertifyAttestationAsync(nvCertify, WrittenData, offset: 0, ak, pool).ConfigureAwait(false);

        byte[] attestDigest = await ComputeSha256Async(nvCertify.CertifyInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmsEccPoint akPoint = ak.OutPublic.PublicArea.Unique.Ecc!;
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(akPoint.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(akPoint.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(nvCertify.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(nvCertify.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(
            ecdsa.VerifyHash(attestDigest, p1363Signature),
            "The NV-certify signature must verify over the raw attestation bytes against the AK's exported public key.");
    }

    /// <summary>
    /// Verifies NV-certify with an RSA AK under both RSASSA and RSAPSS, mirroring the ECDSA assertions (TPM 2.0
    /// Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task RsaNvCertifyVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        var rsaParameters = new RSAParameters
        {
            Modulus = ak.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        await NvCertifyAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, usePss: false).ConfigureAwait(false);
        await NvCertifyAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, usePss: true).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that certifying a partial window (a non-zero offset) attests exactly that window, independently
    /// cross-checked against the written bytes at that offset (TPM 2.0 Library Part 2, clause 10.11.8).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOfPartialWindowAttestsRequestedOffsetAndSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        const ushort PartialOffset = 2;
        const ushort PartialSize = 4;

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, PartialSize, PartialOffset, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify failed: '{result.ResponseCode}'.");

        using NvCertifyResponse nvCertify = result.Value;
        byte[] expectedWindow = WrittenData.AsSpan(PartialOffset, PartialSize).ToArray();
        await AssertNvCertifyAttestationAsync(nvCertify, expectedWindow, PartialOffset, ak, pool).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that certifying an unwritten Index (TPMA_NV_WRITTEN clear) is rejected: "If the NV Index has been
    /// defined but the TPMA_NV_WRITTEN attribute is CLEAR ... this command shall return TPM_RC_NV_UNINITIALIZED"
    /// (TPM 2.0 Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOfUnwrittenIndexReturnsNvUninitialized()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, result.ResponseCode);
    }

    /// <summary>
    /// Verifies that a wrong Index authorization value against a dictionary-attack-protected Index is an
    /// auth-failure, mirroring TPM2_NV_Read()'s equivalent negative (TPM 2.0 Library Part 1, clause 16.8.3).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithWrongIndexAuthReturnsAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession wrongIndexAuth = TpmPasswordSession.Create(WrongIndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, wrongIndexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 1), result.ResponseCode, "authHandle's own USER-role authorizing session, session 2 of Table 271, is refused with session-encoded TPM_RC_AUTH_FAIL on a wrong indexAuth.");
    }

    /// <summary>
    /// A real session at the SIGN slot BOUND to a dictionary-attack-protected entity, carrying the CORRECT bind
    /// authValue, now VERIFIES and attests — the sign slot's command HMAC is checked against the signing key's
    /// own (empty) authValue over the same session key both sides derived from the correct bind, so it matches
    /// and the command executes (TPM 2.0 Library Part 1, clause 16.6.5, equation 17): binding to a
    /// DA-protected entity is now admitted and evaluated, no longer refused up front, because a wrong
    /// bind guess now fails verification and is throttled (its companion test proves the charge). A correct
    /// guess never was an attack, so it attests and moves no counter.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverSignSlotBoundToDaProtectedEntityWithCorrectAuthAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<NvCertifyResponse> result = await CertifyOverSignSlotBoundToIndexAsync(
            tpm, registry, pool, ak, boundAuthValue: IndexAuth).ConfigureAwait(false);
        Assert.IsTrue(
            result.IsSuccess,
            $"A sign session bound to the DA-protected Index with the CORRECT authValue must verify and attest, but failed: '{result.ResponseCode}'.");
        using(NvCertifyResponse response = result.Value)
        {
            Assert.IsNotNull(response.CertifyInfo.AttestationData.Attested.Nv);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A correctly-authorized certify must move no counter.");
    }

    /// <summary>
    /// The DA-charge companion: a real session at the SIGN slot bound to a dictionary-attack-protected entity
    /// with a WRONG bind authValue derives a session key the TPM's own does not match, so the sign slot's
    /// command HMAC fails verification and is charged to <c>failedTries</c> — the throttle that closes the
    /// dictionary-attack oracle. The bound entity is DA-protected (clause 16.8.7's OR folds the bound entity's DA state into the
    /// sign-slot decision), so the refusal is the session-encoded <c>TPM_RC_AUTH_FAIL</c> at slot 0, and one
    /// wrong guess advances the lockout counter by exactly one. An unthrottled oracle would have moved nothing.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverSignSlotBoundToDaProtectedEntityWithWrongAuthChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<NvCertifyResponse> result = await CertifyOverSignSlotBoundToIndexAsync(
            tpm, registry, pool, ak, boundAuthValue: WrongIndexAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError,
            "A sign session bound to a DA-protected entity with a WRONG authValue must fail command-HMAC verification with TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
            "The mismatch names the sign slot (index 0), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter + 1, after.Value.LockoutCounter,
            "A wrong bind-entity guess on a verified sign slot must charge failedTries exactly once — the throttle that closes the dictionary-attack oracle.");
    }

    /// <summary>
    /// An UNBOUND sign session genuinely verifies the signing key's OWN authValue (TPM 2.0 Library Part 1,
    /// clause 16.6.5, equation 17): a key created with a non-empty authValue attests when the session folds the
    /// CORRECT value into its command HMAC, and is refused — session-encoded <c>TPM_RC_AUTH_FAIL</c> at slot 0,
    /// charging <c>failedTries</c> because the key is DA-protected (clause 16.8.1) — when the value is wrong.
    /// This proves the signing key's authValue is retained (<see cref="TransientKeyState.AuthValue"/>) and
    /// evaluated, not accepted unchecked, independent of any bind entity.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverUnboundSignSessionVerifiesTheSigningKeysOwnAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, RealSignSlotNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        byte[] indexName = await ComputeNvIndexNameAsync(
            RealSignSlotNvIndexHandle, DefaultNameAlg, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
            (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<NvCertifyResponse> correct = await CertifyOverRealSignSlotAsync(
            tpm, registry, pool, ak, RealSignSlotNvIndexHandle, indexName, signSlotAuthValue: SignerKeyAuth).ConfigureAwait(false);
        Assert.IsTrue(correct.IsSuccess, $"A sign session folding the signing key's CORRECT authValue must attest, but failed: '{correct.ResponseCode}'.");
        correct.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correct authorization must move no counter.");

        TpmResult<NvCertifyResponse> wrong = await CertifyOverRealSignSlotAsync(
            tpm, registry, pool, ak, RealSignSlotNvIndexHandle, indexName, signSlotAuthValue: WrongSignerKeyAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, wrong.BaseError,
            "A wrong signing-key authValue must fail the sign slot's command HMAC with TPM_RC_AUTH_FAIL (the key is DA-protected).");
        Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrong.ResponseCode, "signHandle's own USER-role authorizing session, session 1 of Table 271, is refused with session-encoded TPM_RC_AUTH_FAIL on a wrong signing-key authValue (the key is DA-protected).");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong signing-key authValue on a DA-protected key must charge failedTries exactly once.");
    }

    /// <summary>
    /// A sign session BOUND TO THE SIGNING KEY ITSELF attests with no authValue folded into its command HMAC:
    /// binding already incorporated the key's authValue into the session key (TPM 2.0 Library Part 1, clause
    /// 16.6.10, equation 20), so the command HMAC omits it (equations 21/22), exactly as the authorizing slot's
    /// self-bind does. Proves the sign-slot bind-omission path — the reason a session bound to the entity it
    /// authorizes needs no separate per-command authValue.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverSignSessionBoundToTheSigningKeyItselfAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, RealSignSlotNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        byte[] indexName = await ComputeNvIndexNameAsync(
            RealSignSlotNvIndexHandle, DefaultNameAlg, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
            (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);

        StartAuthSessionInput signStartInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(ak.ObjectHandle.Value, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> signStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, signStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signStartResult.IsSuccess, $"StartAuthSession (sign slot bound to the signing key) failed: '{signStartResult.ResponseCode}'.");

        StartAuthSessionResponse signStarted = signStartResult.Value;
        uint signSessionHandle = signStarted.SessionHandle.Value;

        try
        {
            using TpmSession signSession = await TpmSession.CreateBoundAsync(
                new TpmHandle(signSessionHandle), SignerKeyAuth, signStartInput.NonceCaller, signStarted.NonceTPM,
                HmacSessionAlg, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, RealSignSlotNvIndexHandle, RealSignSlotNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), indexName, indexName];

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signSession, indexAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                result.IsSuccess,
                $"A sign session bound to the signing key itself must attest with the authValue folded into the bind, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(signSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_CreatePrimary()</c> whose <c>inSensitive.userAuth</c> is wider than the digest of the object's
    /// nameAlg is refused with <c>TPM_RC_SIZE</c>: "the size of the authValue should not be larger than the
    /// digest size of the algorithm used to compute the Name of the object" (TPM 2.0 Library Part 1, clause
    /// 16.6.4.2). This keeps every RETAINED signing-key authValue inside the bound-entity fold's fixed width, so
    /// a session bound to the key can never overflow the <c>SessionBoundEntity</c> buffer — the same gate the NV
    /// and Create paths already apply.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryWithOverWideAuthValueReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        //A 33-octet authValue exceeds SHA-256's 32-octet digest (the template's nameAlg).
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT, password: new string('A', 33), TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, "An over-wide object authValue must be refused.");
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), result.ResponseCode, "Table 191: inSensitive is TPM2_CreatePrimary()'s first parameter (parameter 1); an over-wide object authValue is parameter-encoded TPM_RC_SIZE at index 0.");
    }

    /// <summary>
    /// Verifies that a storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) as the NV-certify's signHandle is
    /// rejected with <c>TPM_RC_KEY</c>: "If the sign attribute is not SET in the key referenced by signHandle then
    /// the TPM shall return TPM_RC_KEY" (TPM 2.0 Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithNonSigningKeyReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            parent.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), result.ResponseCode, "Table 271: signHandle is TPM2_NV_Certify()'s first handle (handle 1); a key without the sign attribute is handle-encoded TPM_RC_KEY at index 0.");
    }

    /// <summary>
    /// Verifies that requesting the unmodelled TPMS_NV_DIGEST_CERTIFY_INFO form (size and offset both zero) is
    /// rejected fail-closed rather than silently substituting the modelled TPMS_NV_CERTIFY_INFO form (TPM 2.0
    /// Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithDigestFormSelectedReturnsCommandCode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, size: 0, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_COMMAND_CODE, result.ResponseCode);
    }

    /// <summary>
    /// The attested <c>indexName</c> is the Index's REAL Name, computed over the Index's own <c>nameAlg</c> and
    /// its own <c>authPolicy</c> — not over a fixed algorithm and an Empty Policy. "It also includes the NV
    /// index Name" (TPM 2.0 Library Part 3, clause 31.16.1), and a Name is
    /// <c>nameAlg || H_nameAlg(handle || TPMS_NV_PUBLIC)</c> over the WHOLE marshaled public area, whose fields
    /// include both of them (Part 1, clause 13, Table 9; Part 2, clause 13.6, Table 251). The Index here is
    /// defined with a SHA-384 <c>nameAlg</c> and a non-empty access policy, so both fields differ from the
    /// defaults: the attested Name must equal this test's independent transcription and must NOT equal the one
    /// a fixed-SHA-256/Empty-Policy computation would produce.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyAttestsTheNameComputedOverTheIndexOwnNameAlgAndAuthPolicy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, Sha384NvIndexHandle, TpmAlgIdConstants.TPM_ALG_SHA384, DaProtectedAttributes, Sha384AuthPolicy).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, Sha384NvIndexHandle, Sha384NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify failed: '{result.ResponseCode}'.");

        using NvCertifyResponse nvCertify = result.Value;
        TpmsAttest attest = nvCertify.CertifyInfo.AttestationData;
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_NV, attest.Type);
        Assert.IsNotNull(attest.Attested.Nv);

        byte[] expectedIndexName = await ComputeNvIndexNameAsync(
            Sha384NvIndexHandle, TpmAlgIdConstants.TPM_ALG_SHA384, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, Sha384AuthPolicy,
            (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Nv!.IndexName.Span.SequenceEqual(expectedIndexName),
            "The attested indexName must equal the Name transcribed over the Index's OWN nameAlg and authPolicy.");

        byte[] fixedShapeName = await ComputeNvIndexNameAsync(
            Sha384NvIndexHandle, DefaultNameAlg, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
            (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(
            attest.Attested.Nv!.IndexName.Span.SequenceEqual(fixedShapeName),
            "A Name computed from a fixed SHA-256 nameAlg and an Empty Policy is a different Name, so attesting it would be attesting an Index that does not exist.");
    }

    /// <summary>
    /// An NV Index's Name does not move when its authorization value is rotated: <c>authValue</c> lives outside
    /// <c>TPMS_NV_PUBLIC</c>, which is the only thing the Name is computed over (TPM 2.0 Library Part 1, clause
    /// 13, Table 9; Part 2, clause 13.6, Table 251), and <c>TPM2_NV_ChangeAuth</c> changes nothing else (Part 3,
    /// clause 31.15.1). A verifier holding an attestation of the Index's identity therefore does not need a
    /// fresh one merely because the authorization value changed — this certifies the same Index before and
    /// after a real <c>TPM2_NV_ChangeAuth</c> under its own ADMIN-role policy and requires both attestations to
    /// carry the identical <c>indexName</c>, equal to the independent transcription.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyAttestsTheSameIndexNameBeforeAndAfterAnAuthValueRotation()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] rotationPolicy = await ComputeRotationAuthPolicyAsync(pool).ConfigureAwait(false);
        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, RotatableNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, rotationPolicy).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        byte[] expectedIndexName = await ComputeNvIndexNameAsync(
            RotatableNvIndexHandle, DefaultNameAlg, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, rotationPolicy,
            (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] nameBefore = await CertifyIndexNameAsync(tpm, registry, pool, ak, RotatableNvIndexHandle, IndexAuth).ConfigureAwait(false);
        Assert.IsTrue(
            nameBefore.AsSpan().SequenceEqual(expectedIndexName),
            "The pre-rotation attestation must carry the Name transcribed from the Index's public area.");

        await RotateIndexAuthValueAsync(tpm, pool, RotatableNvIndexHandle, expectedIndexName, IndexAuth, RotatedIndexAuth).ConfigureAwait(false);

        byte[] nameAfter = await CertifyIndexNameAsync(tpm, registry, pool, ak, RotatableNvIndexHandle, RotatedIndexAuth).ConfigureAwait(false);
        Assert.IsTrue(
            nameAfter.AsSpan().SequenceEqual(nameBefore),
            "The attested indexName must be byte-identical across a rotation: the authValue is not part of the public area the Name covers.");
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c> over MIXED sessions - a password session authorizing the
    /// signing key's slot, an HMAC session authorizing the Index's own slot - succeeds and attests the Index's
    /// REAL Name, exactly as the all-password composition does (TPM 2.0 Library Part 3, clause 31.16.2, Tables
    /// 271-272; Part 1, clause 13, Table 9's Name recipe). Both slots require authorization at USER role (Table 271),
    /// and neither slot's session shape constrains the other's.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverMixedPasswordAndHmacSessionsSucceedsAndAttestsTheRealName()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, HmacArmNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmSession indexAuth = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            indexAuth.SetAuthValue(IndexAuth, pool);

            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, HmacArmNvIndexHandle, HmacArmNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

            byte[] indexName = await ComputeNvIndexNameAsync(
                HmacArmNvIndexHandle, DefaultNameAlg, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
                (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);

            //cpHash covers every command handle regardless of which session authorizes which slot (Part 1,
            //clause 15.7, equation 15), so the signing key's own Name is supplied even though a PASSWORD
            //session authorizes that slot - only an all-password authorization area skips cpHash entirely.
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), indexName, indexName];

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signAuth, indexAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify (mixed sessions) failed: '{result.ResponseCode}'.");

            using NvCertifyResponse nvCertify = result.Value;
            TpmsAttest attest = nvCertify.CertifyInfo.AttestationData;
            Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_NV, attest.Type);
            Assert.IsNotNull(attest.Attested.Nv);
            Assert.IsTrue(
                attest.Attested.Nv!.IndexName.Span.SequenceEqual(indexName),
                "The attested indexName must equal the Index's Name even when its own authorization slot is proven over an HMAC session rather than a password.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The HMAC-arm companion (DA half) to <see cref="NvCertifyWithWrongIndexAuthReturnsAuthFail"/>.
    /// A wrong Index authorization value PROVEN OVER AN HMAC SESSION against a dictionary-attack-protected
    /// Index answers the identical <c>TPM_RC_AUTH_FAIL</c> - the read-role DA gate (TPM 2.0 Library Part 1,
    /// clause 34.2.5, p.237-238) binds the Index, not the mechanism the wrong value was presented with (clause
    /// 16.8.1/16.8.3). The mismatch is asserted against <c>BaseError</c> rather than the raw
    /// <c>ResponseCode</c>: a genuine command-HMAC mismatch names the offending session (the Index's own slot),
    /// so the wire code is the format-one session-encoded form - base error + <c>TPM_RC_S</c> + <c>0x100</c> for
    /// that slot (TPM 2.0 Library Part 2, clause 6.6.2) - never the bare constant.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverHmacWithWrongIndexAuthOnDaProtectedIndexReturnsAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, HmacArmNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<NvCertifyResponse> result = await CertifyOverHmacIndexSessionAsync(
            tpm, registry, pool, ak, HmacArmNvIndexHandle, DaProtectedAttributes, WrongIndexAuth).ConfigureAwait(false);

        //A genuine command-HMAC mismatch names the offending session (the Index's own slot, index 1), so the raw
        //wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2) - the base error is
        //what decodes to the bare constant, mirroring the NV_Increment HMAC arm's identical proof (case 1).
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError);
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode);
    }

    /// <summary>
    /// The NO_DA-half contrast to the test above (TPM 2.0 Library Part 2, Table 249, bit
    /// 25). A wrong Index authorization value proven over an HMAC session against a <c>TPMA_NV_NO_DA</c> Index
    /// answers a plain <c>TPM_RC_BAD_AUTH</c> rather than the DA-counted <c>TPM_RC_AUTH_FAIL</c>, mirroring the
    /// NV_Increment Index-arm's own NO_DA contrast test. The mismatch is asserted against
    /// <c>BaseError</c>: the wire code carries the format-one session-encoded modifier for the offending slot -
    /// base error + <c>TPM_RC_S</c> + <c>0x100</c> (TPM 2.0 Library Part 2, clause 6.6.2) - never the bare
    /// constant.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverHmacWithWrongIndexAuthOnNonDaIndexReturnsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, NoDaHmacArmNvIndexHandle, DefaultNameAlg, NoDaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<NvCertifyResponse> result = await CertifyOverHmacIndexSessionAsync(
            tpm, registry, pool, ak, NoDaHmacArmNvIndexHandle, NoDaProtectedAttributes, WrongIndexAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError);
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode,
            "A genuine command-HMAC mismatch names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");
    }

    /// <summary>
    /// Two REAL, unbound/unsalted HMAC sessions — one at NV_Certify's SIGN slot, one at its INDEX slot — both
    /// succeed and both adopt a genuinely rolled nonceTPM from their own response entry: a session's nonceTPM
    /// changes on every use, command and response alike (TPM 2.0 Library Part 1, clause 16.6.3.1), and the
    /// HMAC that authenticates a response entry (clause 16.6.5, equation 17) verifies — and only then lets the
    /// session adopt the new value — solely when that entry is genuine. The sign slot's own command HMAC is
    /// never verified server-side (the shipped Certify()/Quote()/GetTime() family posture), but its RESPONSE
    /// entry still owes this session a real, verifiable one; no test before this one puts a real session at
    /// that slot at all, so neither the slot-0-real framing nor this honesty was previously exercised.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverTwoRealHmacSessionsSucceedsAndBothSlotsAdoptARolledNonceTpm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, TwoRealSessionsNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        StartAuthSessionInput signStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> signStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, signStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signStartResult.IsSuccess, $"StartAuthSession (sign slot) failed: '{signStartResult.ResponseCode}'.");
        StartAuthSessionResponse signStarted = signStartResult.Value;
        uint signSessionHandle = signStarted.SessionHandle.Value;

        StartAuthSessionInput indexStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> indexStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, indexStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(indexStartResult.IsSuccess, $"StartAuthSession (Index slot) failed: '{indexStartResult.ResponseCode}'.");
        StartAuthSessionResponse indexStarted = indexStartResult.Value;
        uint indexSessionHandle = indexStarted.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(signSessionHandle), signStarted.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            using TpmSession indexSession = new(new TpmHandle(indexSessionHandle), indexStarted.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            indexSession.SetAuthValue(IndexAuth, pool);

            byte[] nonceTpmBeforeSign = signSession.NonceTpm.ToArray();
            byte[] nonceTpmBeforeIndex = indexSession.NonceTpm.ToArray();

            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, TwoRealSessionsNvIndexHandle, TwoRealSessionsNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

            byte[] indexName = await ComputeNvIndexNameAsync(
                TwoRealSessionsNvIndexHandle, DefaultNameAlg, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
                (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), indexName, indexName];

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signSession, indexSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify (two real sessions) failed: '{result.ResponseCode}'.");

            using NvCertifyResponse nvCertify = result.Value;
            TpmsAttest attest = nvCertify.CertifyInfo.AttestationData;
            Assert.IsNotNull(attest.Attested.Nv);
            Assert.IsTrue(
                attest.Attested.Nv!.IndexName.Span.SequenceEqual(indexName),
                "The attested indexName must equal the Index's real Name even when both authorization slots are real HMAC sessions.");

            Assert.IsFalse(
                signSession.NonceTpm.Span.SequenceEqual(nonceTpmBeforeSign),
                "The sign slot must adopt a genuinely rolled nonceTPM from its own response entry - it only does so once that entry's own response HMAC has verified.");
            Assert.IsFalse(
                indexSession.NonceTpm.Span.SequenceEqual(nonceTpmBeforeIndex),
                "The Index slot must likewise adopt a genuinely rolled nonceTPM from its own response entry.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(signSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(indexSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A real, unbound/unsalted HMAC session at NV_Certify's SIGN slot, paired with a password-authorized
    /// Index slot, succeeds and attests the Index's real Name when the sign session's own authValue MATCHES the
    /// signing key's — here both empty, so its command HMAC verifies against the key's retained (empty)
    /// authValue and its response entry is keyed on the same term (TPM 2.0 Library Part 1, clause 16.6.5,
    /// equation 17). The SAME composition with a NON-EMPTY authValue folded into that session
    /// (<see cref="TpmSession.SetAuthValue"/>) now makes the client's COMMAND HMAC key disagree with the key's
    /// real authValue, so the sign slot's command HMAC fails verification SERVER-SIDE, before any signing, and
    /// the command is rejected at the wire with a session-encoded <c>TPM_RC_BAD_AUTH</c> at slot 0 (the signing
    /// key is <c>noDA</c>, so the mismatch is a plain bad authorization, not a DA-counted one). This is the
    /// the sign slot's USER-role authorization is now genuinely evaluated, not accepted unchecked.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverRealSignSessionWithNonEmptyAuthValueIsRejectedWhileEmptyAuthSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, RealSignSlotNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        byte[] indexName = await ComputeNvIndexNameAsync(
            RealSignSlotNvIndexHandle, DefaultNameAlg, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
            (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //MATCHING: the sign session's authValue is left empty, matching the signing key's own retained
        //authValue, so its command HMAC verifies and it attests the Index's real Name - the "real-sign +
        //password-Index" slot-0-real framing.
        TpmResult<NvCertifyResponse> matchingResult = await CertifyOverRealSignSlotAsync(
            tpm, registry, pool, ak, RealSignSlotNvIndexHandle, indexName, signSlotAuthValue: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(matchingResult.IsSuccess, $"TPM2_NV_Certify (real sign slot, matching empty auth) failed: '{matchingResult.ResponseCode}'.");
        using(NvCertifyResponse matchingResponse = matchingResult.Value)
        {
            TpmsAttest attest = matchingResponse.CertifyInfo.AttestationData;
            Assert.IsNotNull(attest.Attested.Nv);
            Assert.IsTrue(
                attest.Attested.Nv!.IndexName.Span.SequenceEqual(indexName),
                "The attested indexName must equal the Index's real Name when the real session sits at the sign slot instead of the Index slot.");
        }

        //MISMATCHING: the same composition, but the sign session folds a NON-EMPTY authValue - the command HMAC
        //no longer matches the signing key's real (empty) authValue, so the sign slot is refused at the wire
        //before signing, session-encoded at slot 0 (the key is noDA, so a plain bad authorization).
        TpmResult<NvCertifyResponse> mismatchingResult = await CertifyOverRealSignSlotAsync(
            tpm, registry, pool, ak, RealSignSlotNvIndexHandle, indexName, signSlotAuthValue: NonEmptySignSlotAuthValue).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, mismatchingResult.BaseError,
            "A non-empty sign-slot authValue no longer matches the signing key's real authValue, so the sign slot's command HMAC is rejected server-side before signing.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), mismatchingResult.ResponseCode,
            "The mismatch names the sign slot (index 0), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");
    }

    /// <summary>
    /// The all-password arm's read-role availability gate for an AUTHREAD-CLEAR Index now runs BEFORE any
    /// credential is compared, mirroring the mixed-session arm's own early gate (arm parity):
    /// access control precedes authorization (TPM 2.0 Library Part 1, clause 13), and
    /// clause 34.2.5's TPMA_NV_AUTHREAD requirement is checked by Part 3, clause 5.6's check 7.2.2, which is
    /// ordered ahead of its checks 9/10 (the HMAC/password credential compare) and governs the password and
    /// HMAC mechanisms identically. So a CORRECT Index authValue answers <c>TPM_RC_AUTH_UNAVAILABLE</c> exactly
    /// like a WRONG one: comparing the credential first would either sign an attestation over contents the
    /// Index's own authValue has no read authorization for at all (a correct value) or charge the shared
    /// dictionary-attack counter for an access control failure it should never reach (a wrong value); both are
    /// closed by ordering access control ahead of the credential compare. The WRONG-value half also proves the
    /// dictionary-attack <c>failedTries</c> counter is left untouched, the same indirect probe
    /// <see cref="NvCertifyOverHmacWithWrongAuthOnAuthReadClearIndexHitsEarlyAvailabilityGateWithoutChargingFailedTries"/>
    /// uses: with <c>maxTries</c> lowered to one, a SEPARATE, genuinely-AUTHREAD Index still answers a plain
    /// auth-failure rather than <c>TPM_RC_LOCKOUT</c> to a wrong password right afterward.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyAllPasswordWithAuthReadClearIndexHitsEarlyAvailabilityGateRegardlessOfAuthValue()
    {
        const uint SingleAttemptMaxTries = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, AuthReadClearNvIndexHandle, DefaultNameAlg, AuthReadClearAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using(TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool))
        using(TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool))
        using(NvCertifyInput correctAuthInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, AuthReadClearNvIndexHandle, AuthReadClearNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool))
        {
            TpmResult<NvCertifyResponse> correctAuthResult = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, correctAuthInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, correctAuthResult.ResponseCode,
                "The availability gate must answer before the credential compare, so a CORRECT authValue never buys a signed attestation of a read-forbidden Index.");
        }

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, SingleAttemptMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        using(TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool))
        using(TpmPasswordSession wrongIndexAuth = TpmPasswordSession.Create(WrongIndexAuth, pool))
        using(NvCertifyInput wrongAuthInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, AuthReadClearNvIndexHandle, AuthReadClearNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool))
        {
            TpmResult<NvCertifyResponse> wrongAuthResult = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, wrongAuthInput, [signAuth, wrongIndexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, wrongAuthResult.ResponseCode,
                "The availability gate must answer before the credential compare, so a WRONG authValue never even reaches an auth-failure answer.");
        }

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, DaProbeNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        using(TpmPasswordSession probeSignAuth = TpmPasswordSession.CreateEmpty(pool))
        using(TpmPasswordSession probeWrongIndexAuth = TpmPasswordSession.Create(WrongIndexAuth, pool))
        using(NvCertifyInput probeInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, DaProbeNvIndexHandle, DaProbeNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool))
        {
            TpmResult<NvCertifyResponse> probeResult = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, probeInput, [probeSignAuth, probeWrongIndexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 1), probeResult.ResponseCode,
                "If the AUTHREAD-clear attempts above had charged the shared failedTries counter, this single wrong-password attempt against a DIFFERENT DA-protected Index (maxTries lowered to one) would already read TPM_RC_LOCKOUT instead of a plain auth-failure.");
        }
    }

    /// <summary>
    /// The session arm's read-role availability gate for an AUTHREAD-CLEAR Index runs BEFORE any credential is
    /// compared: a WRONG Index authValue proven over an HMAC session answers the availability
    /// code <c>TPM_RC_AUTH_UNAVAILABLE</c> (TPM 2.0 Library Part 3, clause 5.6, check 7.2.2) rather than an
    /// auth-failure, and — because access control precedes authorization (Part 1, clause 13) — the shared
    /// dictionary-attack <c>failedTries</c> counter is never charged for it: with <c>maxTries</c> lowered to
    /// one, a SEPARATE, genuinely-AUTHREAD Index answers a plain auth-failure rather than
    /// <c>TPM_RC_LOCKOUT</c> to a wrong password right afterward, proving the AUTHREAD-clear attempt above
    /// left the shared counter at zero.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverHmacWithWrongAuthOnAuthReadClearIndexHitsEarlyAvailabilityGateWithoutChargingFailedTries()
    {
        const uint SingleAttemptMaxTries = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, SingleAttemptMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, AuthReadClearNvIndexHandle, DefaultNameAlg, AuthReadClearAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<NvCertifyResponse> earlyGateResult = await CertifyOverHmacIndexSessionAsync(
            tpm, registry, pool, ak, AuthReadClearNvIndexHandle, AuthReadClearAttributes, WrongIndexAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, earlyGateResult.ResponseCode,
            "The availability gate must answer before any credential is compared, so a WRONG authValue never even reaches an auth-failure answer.");

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, DaProbeNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        using TpmPasswordSession probeSignAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession probeWrongIndexAuth = TpmPasswordSession.Create(WrongIndexAuth, pool);
        using NvCertifyInput probeInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, DaProbeNvIndexHandle, DaProbeNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> probeResult = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, probeInput, [probeSignAuth, probeWrongIndexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 1), probeResult.ResponseCode,
            "If the AUTHREAD-clear attempt above had charged the shared failedTries counter, this single wrong-password attempt against a DIFFERENT DA-protected Index (maxTries lowered to one) would already read TPM_RC_LOCKOUT instead of a plain auth-failure.");
    }

    /// <summary>
    /// A single successful <c>TPM2_NV_Certify()</c> over the mixed real-sign-session + password-Index area
    /// advances a <c>TPM_NT_PIN_PASS</c> Index's pinCount by exactly ONE, not two: the pinCount
    /// update (TPM 2.0 Library Part 1, clause 34.2.6.6) happens before the attested window is sliced, so the
    /// attestation's own <c>nvContents</c> IS the read of the post-update value — no separate read is needed.
    /// Run to pinLimit to prove the allowance is the FULL spec'd count: a double-update defect would exhaust a
    /// pinLimit-3 Index in two certifies, not three.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverMixedRealSignAndPasswordIndexAdvancesPinPassCountByExactlyOnePerUse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineNvIndexAsync(
            tpm, registry, pool, PinPassNvIndexHandle, DefaultNameAlg, PinPassCertifyAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        await WritePinCounterParametersAsync(tpm, registry, pool, PinPassNvIndexHandle, pinCount: 0, PinPassCertifyPinLimit).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        for(uint expectedPinCount = 1; expectedPinCount <= PinPassCertifyPinLimit; expectedPinCount++)
        {
            TpmResult<NvCertifyResponse> result = await CertifyPinPassCounterAsync(tpm, registry, pool, ak, PinPassNvIndexHandle).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Use {expectedPinCount} of {PinPassCertifyPinLimit} must still succeed: '{result.ResponseCode}'.");

            using NvCertifyResponse response = result.Value;
            TpmsAttest attest = response.CertifyInfo.AttestationData;
            Assert.IsNotNull(attest.Attested.Nv);
            uint attestedPinCount = BinaryPrimitives.ReadUInt32BigEndian(attest.Attested.Nv!.NvContents[..sizeof(uint)]);
            Assert.AreEqual(
                expectedPinCount, attestedPinCount,
                $"pinCount must be {expectedPinCount} after {expectedPinCount} successful mixed-session certifies - a double update would already read {expectedPinCount * 2}.");
        }

        TpmResult<NvCertifyResponse> atLimitResult = await CertifyPinPassCounterAsync(tpm, registry, pool, ak, PinPassNvIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, atLimitResult.ResponseCode,
            "Once pinCount reaches pinLimit, even the correct PIN must be rejected - proving the loop above genuinely reached the limit rather than having exhausted it early via a double update.");
    }

    /// <summary>
    /// A single real HMAC session named in BOTH authorization slots is refused: "a specific HMAC or policy
    /// session handle can occur only once in the Authorization Area; TPM_RS_PW may repeat" (TPM 2.0 Library
    /// Part 1, clause 15.6.3). <c>TPM2_NV_Certify()</c> is the first two-real-session command this simulator
    /// models (Table 271), so this is the first case in which the rule has anything to compare — composing
    /// the SAME live <see cref="TpmSession"/> into both slots through the production
    /// <see cref="TpmCommandExecutor"/> already produces the identical wire scenario the rule forbids (two
    /// <c>TPMS_AUTH_COMMAND</c> entries naming the same real sessionHandle), through the same request-framing
    /// code path every other test in this file uses. Part 1 names no response code for the violation; the
    /// reference does, its <c>RetrieveSessionData</c> comparing each unmarshaled slot against every earlier one
    /// and answering <c>TPM_RCS_HANDLE + errorIndex</c>, so the refusal is a handle error.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithTheSameRealSessionHandleInBothSlotsIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineNvIndexAsync(
            tpm, registry, pool, DuplicateSessionNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            session.SetAuthValue(IndexAuth, pool);

            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, DuplicateSessionNvIndexHandle, DuplicateSessionNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

            byte[] indexName = await ComputeNvIndexNameAsync(
                DuplicateSessionNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty,
                (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), indexName, indexName];

            //The SAME session names both the sign slot and the Index slot, so the wire's two
            //TPMS_AUTH_COMMAND entries carry the identical real sessionHandle - the exact composition clause
            //16.6.3 forbids.
            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [session, session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            //The refusal names the SECOND occurrence (TPM 2.0 Library Part 2, clause 6.6.2), the offending
            //re-claim, not the first (legitimate) use of the handle.
            Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.BaseError);
            Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1), result.ResponseCode, "The second authorization slot, session 2 of Table 271 (authHandle's own), reused across both slots is session-encoded TPM_RC_HANDLE, per the session area's own duplicate-handle check (TPM 2.0 Library Part 3, clause 5.5).");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The all-password arm's sign-slot compare (TPM 2.0 Library Part 3, clause 5.6, checks 9/10) accepts a
    /// genuine non-empty credential: a userWithAuth-SET signer created with a non-empty password attests when
    /// the CORRECT sign password is supplied alongside the correct Index authorization value, once the signer's
    /// DA/Lockout gate (check 3) and userWithAuth gate (check 7.1) have both already passed.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyAllPasswordWithSignersNonEmptyPasswordAndCorrectIndexAuthAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, RealSignSlotNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.Create(SignerKeyAuth, pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, RealSignSlotNvIndexHandle, RealSignSlotNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A CORRECT non-empty sign password must attest, but failed: '{result.ResponseCode}'.");

        using NvCertifyResponse nvCertify = result.Value;
        Assert.IsNotNull(nvCertify.CertifyInfo.AttestationData.Attested.Nv, "A successful certify must carry the NV attestation form.");
    }

    /// <summary>
    /// The all-password arm's DA-charge companion to
    /// <see cref="NvCertifyAllPasswordWithSignersNonEmptyPasswordAndCorrectIndexAuthAttests"/>: a WRONG sign
    /// password against the same DA-protected, userWithAuth-SET signer fails the sign-slot compare (TPM 2.0
    /// Library Part 3, clause 5.6, checks 9/10) after its DA/Lockout gate (check 3) and userWithAuth gate (check
    /// 7.1) have both already passed — a session-encoded <c>TPM_RC_AUTH_FAIL</c> naming the sign slot (session
    /// index 0, Part 2, clause 6.6.2), and the dictionary-attack counter is charged exactly once (Part 1, clause
    /// 16.8.7).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyAllPasswordWithWrongSignerPasswordChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, RealSignSlotNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.Create(WrongSignerKeyAuth, pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, RealSignSlotNvIndexHandle, RealSignSlotNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError,
            "A wrong sign password against a DA-protected signer must fail the sign slot's compare with TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
            "The mismatch names the sign slot (index 0), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter + 1, after.Value.LockoutCounter,
            "A wrong sign password on a DA-protected signer must charge failedTries exactly once.");
    }

    /// <summary>
    /// The all-password arm's USER-role gate (TPM 2.0 Library Part 3, clause 5.6, check 7.1; clause 5.6 line
    /// 1407): a signer whose <c>TPMA_OBJECT.userWithAuth</c> is CLEAR may have its USER role authorized only by
    /// a policy session, so it is refused with <c>TPM_RC_POLICY_FAIL</c>, session-encoded (Table 15's session
    /// designation) at the sign slot, session 1 of Table 271, even when the supplied sign password is the
    /// signer's own genuinely correct (empty) authValue — the gate runs before checks 9/10's credential compare,
    /// so a genuinely correct credential is never examined, and the refusal is uncharged: <c>TPM_RC_POLICY_FAIL</c>
    /// is not <c>TPM_RC_AUTH_FAIL</c>, and clause 5.6's closing rule states that a non-AUTH_FAIL error "shall not
    /// alter any TPM state".
    /// </summary>
    [TestMethod]
    public async Task NvCertifyAllPasswordWithUserWithAuthClearSignerIsRefusedWithoutComparingThePassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse clearSigner = await CreateUserWithAuthClearSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            clearSigner.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.BaseError,
            "A userWithAuth-CLEAR signer must be refused with TPM_RC_POLICY_FAIL (Part 3, clause 5.6 line 1407), even though the supplied sign password was the signer's own correct (empty) authValue.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, sessionIndex: 0), result.ResponseCode,
            "signHandle's own USER-role authorizing session, session 1 of Table 271, carries the session-encoded refusal.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "TPM_RC_POLICY_FAIL is not TPM_RC_AUTH_FAIL, so the userWithAuth gate must move no counter.");
    }

    /// <summary>
    /// The PIN-Index pinCount half of
    /// <see cref="NvCertifyAllPasswordWithUserWithAuthClearSignerIsRefusedWithoutComparingThePassword"/>: the
    /// userWithAuth gate (TPM 2.0 Library Part 3, clause 5.6, check 7.1) for a <c>TPM_NT_PIN_PASS</c> Index's
    /// signer runs before the Index's own authValue is ever compared, so the Index's once-per-authorization
    /// pinCount update (Part 1, clause 34.2.6.6) never runs for the refused attempt. A single SUBSEQUENT
    /// successful certify by a userWithAuth-SET signer then reads pinCount back as exactly ONE, not two - a
    /// double count would prove the refused attempt had already moved it.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyAllPasswordWithUserWithAuthClearSignerAgainstPinPassIndexLeavesPinCountUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(
            tpm, registry, pool, PinPassNvIndexHandle, DefaultNameAlg, PinPassCertifyAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        await WritePinCounterParametersAsync(tpm, registry, pool, PinPassNvIndexHandle, pinCount: 0, PinPassCertifyPinLimit).ConfigureAwait(false);
        using CreatePrimaryResponse clearSigner = await CreateUserWithAuthClearSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using(TpmPasswordSession refusedSignAuth = TpmPasswordSession.CreateEmpty(pool))
        using(TpmPasswordSession refusedIndexAuth = TpmPasswordSession.Create(IndexAuth, pool))
        using(NvCertifyInput refusedInput = NvCertifyInput.ForEcdsa(
            clearSigner.ObjectHandle, PinPassNvIndexHandle, PinPassNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, PinCounterParametersSize, offset: 0, pool))
        {
            TpmResult<NvCertifyResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, refusedInput, [refusedSignAuth, refusedIndexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, sessionIndex: 0), refused.ResponseCode,
                "A userWithAuth-CLEAR signer over a PIN Index must be refused with the sign slot's session-encoded TPM_RC_POLICY_FAIL (session 1 of Table 271) before the Index's own pinCount-gated compare runs.");
        }

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession okSignAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession okIndexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput okInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, PinPassNvIndexHandle, PinPassNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, PinCounterParametersSize, offset: 0, pool);

        TpmResult<NvCertifyResponse> okResult = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, okInput, [okSignAuth, okIndexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(okResult.IsSuccess, $"The follow-up certify by a userWithAuth-SET signer must succeed: '{okResult.ResponseCode}'.");

        using NvCertifyResponse okResponse = okResult.Value;
        TpmsAttest attest = okResponse.CertifyInfo.AttestationData;
        Assert.IsNotNull(attest.Attested.Nv);
        uint attestedPinCount = BinaryPrimitives.ReadUInt32BigEndian(attest.Attested.Nv!.NvContents[..sizeof(uint)]);
        Assert.AreEqual(
            1u, attestedPinCount,
            "pinCount must be exactly ONE after exactly one successful authorization - a double count would prove the refused userWithAuth-CLEAR attempt had already moved it.");
    }

    /// <summary>
    /// The session arm's USER-role gate (TPM 2.0 Library Part 3, clause 5.6, check 7.1; clause 5.6 line 1407)
    /// for a userWithAuth-CLEAR signer answers the session-encoded <c>TPM_RC_POLICY_FAIL</c> (sign slot, session
    /// 0 of Table 271) on the PASSWORD sub-path too: a <c>TPM_RS_PW</c> sign slot is refused before its inline
    /// password compare, exactly as the all-password arm refuses it, so both arms answer a
    /// userWithAuth-CLEAR signer identically regardless of which sub-path the sign slot takes. Uncharged,
    /// because <c>TPM_RC_POLICY_FAIL</c> is not <c>TPM_RC_AUTH_FAIL</c>.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverSessionWithUserWithAuthClearSignerAndPasswordSignSlotReturnsPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, UserWithAuthClearSessionNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse clearSigner = await CreateUserWithAuthClearSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        //A password sign slot (TPM_RS_PW) paired with a REAL session at the Index slot - the composition puts
        //this request on the mixed-session arm, whose userWithAuth gate governs the password sub-path
        //identically to the all-password arm.
        TpmResult<NvCertifyResponse> result = await CertifyOverHmacIndexSessionAsync(
            tpm, registry, pool, clearSigner, UserWithAuthClearSessionNvIndexHandle, DaProtectedAttributes, IndexAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, sessionIndex: 0), result.ResponseCode,
            "A userWithAuth-CLEAR signer's TPM_RS_PW sign slot must be refused with the session-encoded TPM_RC_POLICY_FAIL (session 1 of Table 271) before its inline password compare.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "TPM_RC_POLICY_FAIL is not TPM_RC_AUTH_FAIL, so the userWithAuth gate must move no counter.");
    }

    /// <summary>
    /// The session arm's USER-role gate (TPM 2.0 Library Part 3, clause 5.6, check 7.1; clause 5.6 line 1407)
    /// for a userWithAuth-CLEAR signer runs before any sign-slot command HMAC is queued for verification: a
    /// REAL, unbound/unsalted HMAC sign session carrying a WRONG guess at the signer's authValue still answers
    /// the sign slot's session-encoded <c>TPM_RC_POLICY_FAIL</c> (session 1 of Table 271), never a
    /// session-encoded <c>TPM_RC_AUTH_FAIL</c> - proving the gate precedes the Name hop and the queued
    /// command-HMAC verification that would otherwise fail and charge the dictionary-attack counter for a wrong
    /// guess against a DA-protected signer. Uncharged.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverSessionWithUserWithAuthClearSignerAndWrongHmacSignSlotGuessReturnsPolicyFailNotAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, UserWithAuthClearSessionNvIndexHandle, DefaultNameAlg, DaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse clearSigner = await CreateUserWithAuthClearSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        byte[] indexName = await ComputeNvIndexNameAsync(
            UserWithAuthClearSessionNvIndexHandle, DefaultNameAlg, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
            (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<NvCertifyResponse> result = await CertifyOverRealSignSlotAsync(
            tpm, registry, pool, clearSigner, UserWithAuthClearSessionNvIndexHandle, indexName, signSlotAuthValue: WrongSignerKeyAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.BaseError,
            "A wrong guess folded into a real sign session against a userWithAuth-CLEAR signer must still answer TPM_RC_POLICY_FAIL, never an auth failure.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, sessionIndex: 0), result.ResponseCode,
            "The refusal is session-encoded at the sign slot, session 1 of Table 271, not the session-encoded TPM_RC_AUTH_FAIL a genuine command-HMAC mismatch would carry - the gate runs before that verification is ever queued.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "TPM_RC_POLICY_FAIL is not TPM_RC_AUTH_FAIL, so the userWithAuth gate must move no counter, even though the guess was wrong.");
    }

    /// <summary>
    /// The all-password arm's sign slot carries the signing key's own DA/Lockout gate (TPM 2.0 Library Part 3,
    /// clause 5.6, check 3): with the TPM in Lockout mode, a DA-protected signing key answers the bare
    /// <c>TPM_RC_LOCKOUT</c> even though BOTH supplied credentials are correct — check 3 precedes check 7.1 and
    /// the checks 9/10 compares in clause 5.6's mandatory order, so no credential is ever evaluated. The Index
    /// is dictionary-attack exempt (<see cref="NoDaProtectedAttributes"/>), so the Index arm's own lockout gate
    /// cannot be the one answering: the refusal is attributable to the sign slot's gate alone.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyAllPasswordWithDaProtectedSignerUnderLockoutReturnsLockout()
    {
        const uint SingleAttemptMaxTries = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, SignerLockoutNvIndexHandle, DefaultNameAlg, NoDaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse signer = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, SingleAttemptMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        //A single wrong sign password charges the DA-protected signer (clause 5.6, check 10) and, with maxTries
        //at one, enters Lockout mode as a side effect.
        using(TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongSignerKeyAuth, pool))
        using(TpmPasswordSession seedingIndexAuth = TpmPasswordSession.Create(IndexAuth, pool))
        using(NvCertifyInput seedingInput = NvCertifyInput.ForEcdsa(
            signer.ObjectHandle, SignerLockoutNvIndexHandle, SignerLockoutNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool))
        {
            TpmResult<NvCertifyResponse> seedingResult = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, seedingInput, [wrongSignAuth, seedingIndexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), seedingResult.ResponseCode,
                "The seeding mismatch must be a charged sign-slot auth failure at session index 0.");
        }

        using TpmPasswordSession signAuth = TpmPasswordSession.Create(SignerKeyAuth, pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput provingInput = NvCertifyInput.ForEcdsa(
            signer.ObjectHandle, SignerLockoutNvIndexHandle, SignerLockoutNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, provingInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
            "A DA-protected signing key in Lockout mode must be refused before any credential is evaluated, correct or not (clause 5.6's check 3 precedes checks 7.1 and 9/10).");
    }

    /// <summary>
    /// The session arm's sign slot carries the identical DA/Lockout gate (TPM 2.0 Library Part 3, clause 5.6,
    /// check 3), answering before EITHER sign-slot credential shape is evaluated: with the TPM in Lockout mode,
    /// a DA-protected signing key answers the bare <c>TPM_RC_LOCKOUT</c> even though the sign password is
    /// correct and the Index slot is proven over a real HMAC session carrying the correct authValue. The Index
    /// is dictionary-attack exempt (<see cref="NoDaProtectedAttributes"/>) and the Index session is unbound, so
    /// neither the Index arm's lockout gate nor the bind-side session gates can be the ones answering.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverSessionWithDaProtectedSignerUnderLockoutReturnsLockout()
    {
        const uint SingleAttemptMaxTries = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(
            tpm, registry, pool, SignerLockoutNvIndexHandle, DefaultNameAlg, NoDaProtectedAttributes, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        using CreatePrimaryResponse signer = await CreateDaProtectedSigningPrimaryWithAuthAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, SingleAttemptMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        //A single wrong sign password over the all-password arm charges the DA-protected signer and, with
        //maxTries at one, enters Lockout mode as a side effect.
        using(TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongSignerKeyAuth, pool))
        using(TpmPasswordSession seedingIndexAuth = TpmPasswordSession.Create(IndexAuth, pool))
        using(NvCertifyInput seedingInput = NvCertifyInput.ForEcdsa(
            signer.ObjectHandle, SignerLockoutNvIndexHandle, SignerLockoutNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool))
        {
            TpmResult<NvCertifyResponse> seedingResult = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, seedingInput, [wrongSignAuth, seedingIndexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), seedingResult.ResponseCode,
                "The seeding mismatch must be a charged sign-slot auth failure at session index 0.");
        }

        //An unbound, unsalted HMAC session needs no authorization to start, so Lockout mode admits it
        //(Part 3, clause 11.1.1); the lockout answer must come from the sign slot's own gate instead.
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmPasswordSession signAuth = TpmPasswordSession.Create(SignerKeyAuth, pool);
            using TpmSession indexSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            indexSession.SetAuthValue(IndexAuth, pool);

            using NvCertifyInput provingInput = NvCertifyInput.ForEcdsa(
                signer.ObjectHandle, SignerLockoutNvIndexHandle, SignerLockoutNvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

            byte[] indexName = await ComputeNvIndexNameAsync(
                SignerLockoutNvIndexHandle, DefaultNameAlg, NoDaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
                (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [signer.Name.Span.ToArray(), indexName, indexName];

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, provingInput, [signAuth, indexSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
                "A DA-protected signing key in Lockout mode must be refused before either sign-slot credential shape is evaluated (clause 5.6's check 3 precedes checks 7.1 and 9/10).");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Certifies <paramref name="nvIndex"/> with <paramref name="ak"/>, authorizing the sign slot with an empty
    /// password session and the Index's own slot with an UNBOUND, unsalted HMAC session whose authValue is
    /// <paramref name="suppliedIndexAuth"/> (TPM 2.0 Library Part 1, clause 16.6.9, equation 19) - the read-role
    /// HMAC-arm composition the DA/NO_DA contrast tests above drive.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="nvIndex">The Index to certify.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes it was defined with.</param>
    /// <param name="suppliedIndexAuth">The candidate authorization value proven by the HMAC session.</param>
    /// <returns>The NV-certify result.</returns>
    private async Task<TpmResult<NvCertifyResponse>> CertifyOverHmacIndexSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, uint nvIndex, TpmaNv attributes, ReadOnlyMemory<byte> suppliedIndexAuth)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmSession indexAuth = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            indexAuth.SetAuthValue(suppliedIndexAuth.Span, pool);

            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, nvIndex, nvIndex, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

            byte[] indexName = await ComputeNvIndexNameAsync(
                nvIndex, DefaultNameAlg, attributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
                (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), indexName, indexName];

            return await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signAuth, indexAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>Extends <see cref="CreateRegistry"/> with the StartAuthSession/FlushContext codecs the HMAC-arm tests need.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateHmacArmRegistry()
    {
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Certifies <paramref name="nvIndex"/> with <paramref name="ak"/>, authorizing the SIGN slot with a
    /// fresh, real, unbound/unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9, equation 19)
    /// carrying <paramref name="signSlotAuthValue"/>, and the Index's own slot with a password session
    /// carrying <see cref="IndexAuth"/> — the mirror composition to
    /// <see cref="CertifyOverHmacIndexSessionAsync"/>, which puts the real session at the Index slot instead.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="nvIndex">The Index to certify.</param>
    /// <param name="indexName">The Index's independently transcribed Name, for cpHash.</param>
    /// <param name="signSlotAuthValue">The authValue term folded into the sign session; empty for the honest shape.</param>
    /// <returns>The NV-certify result.</returns>
    private async Task<TpmResult<NvCertifyResponse>> CertifyOverRealSignSlotAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, uint nvIndex, byte[] indexName, ReadOnlyMemory<byte> signSlotAuthValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (sign slot) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            if(!signSlotAuthValue.IsEmpty)
            {
                signSession.SetAuthValue(signSlotAuthValue.Span, pool);
            }

            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, nvIndex, nvIndex, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), indexName, indexName];

            return await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signSession, indexAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Certifies <see cref="NvIndexHandle"/> with <paramref name="ak"/> over a SIGN-slot HMAC session BOUND to
    /// that Index (carrying <paramref name="boundAuthValue"/> as its believed bind authValue), paired with a
    /// correct-authValue password session at the Index slot — the composition the sign-slot verification
    /// pair drives. A correct bind authValue makes the sign slot verify and attest; a wrong one fails its
    /// command HMAC and, because the bound entity is DA-protected, charges the counter.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="boundAuthValue">The authValue the client folds into the bound session key — correct or deliberately wrong.</param>
    /// <returns>The NV-certify result.</returns>
    private async Task<TpmResult<NvCertifyResponse>> CertifyOverSignSlotBoundToIndexAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, ReadOnlyMemory<byte> boundAuthValue)
    {
        StartAuthSessionInput signStartInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(NvIndexHandle, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> signStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, signStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signStartResult.IsSuccess, $"StartAuthSession (sign slot bound to the Index) failed: '{signStartResult.ResponseCode}'.");

        StartAuthSessionResponse signStarted = signStartResult.Value;
        uint signSessionHandle = signStarted.SessionHandle.Value;

        try
        {
            using TpmSession signSession = await TpmSession.CreateBoundAsync(
                new TpmHandle(signSessionHandle), boundAuthValue, signStartInput.NonceCaller, signStarted.NonceTPM,
                HmacSessionAlg, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            byte[] indexName = await ComputeNvIndexNameAsync(
                NvIndexHandle, DefaultNameAlg, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
                (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), indexName, indexName];

            return await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signSession, indexAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(signSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Certifies <paramref name="nvIndex"/>'s <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> window (the whole 8-octet
    /// data area) with <paramref name="ak"/>, authorizing the sign slot with a fresh real HMAC session (empty
    /// authValue) and the Index's own slot with a password session carrying <see cref="IndexAuth"/> — the
    /// mixed composition the pinCount single-update regression drives.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="nvIndex">The PIN Pass Index to certify.</param>
    /// <returns>The NV-certify result.</returns>
    private async Task<TpmResult<NvCertifyResponse>> CertifyPinPassCounterAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, uint nvIndex)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (sign slot) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, nvIndex, nvIndex, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, PinCounterParametersSize, offset: 0, pool);

            byte[] indexName = await ComputeNvIndexNameAsync(
                nvIndex, DefaultNameAlg, PinPassCertifyAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
                PinCounterParametersSize, pool, TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), indexName, indexName];

            return await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signSession, indexAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Issues an OWNER-authorized <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/>, storing
    /// <paramref name="pinCount"/> and <paramref name="pinLimit"/> as the 8-octet
    /// <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> blob (TPM 2.0 Library Part 2, clause 13.3). A PIN Index forbids
    /// <c>TPMA_NV_AUTHWRITE</c> (TPM 2.0 Library Part 1, clause 34.2.6.6), so the owner-authorized arm is the
    /// sole provisioning path — the (empty) owner authValue authorizes it, never the PIN.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="pinCount">The pinCount value to store.</param>
    /// <param name="pinLimit">The pinLimit value to store.</param>
    private async Task WritePinCounterParametersAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, uint pinCount, uint pinLimit)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using IMemoryOwner<byte> owner = pool.Rent(PinCounterParametersSize);
        Memory<byte> blob = owner.Memory[..PinCounterParametersSize];
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span, pinCount);
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(blob.Span, pool);
        var writeInput = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, nvIndex, writeInputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"Writing PIN counter parameters failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// Certifies an NV Index's contents with <paramref name="ak"/> and returns the attested <c>indexName</c>,
    /// authorizing the Index with <paramref name="indexAuthValue"/> — the read the caller needs when what it is
    /// asserting about is the attested Name rather than the signature (TPM 2.0 Library Part 3, clause 31.16).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="nvIndex">The Index to certify.</param>
    /// <param name="indexAuthValue">The Index's current authorization value.</param>
    /// <returns>The attested Name.</returns>
    private async Task<byte[]> CertifyIndexNameAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, uint nvIndex, ReadOnlyMemory<byte> indexAuthValue)
    {
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(indexAuthValue.Span, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, nvIndex, nvIndex, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify failed: '{result.ResponseCode}'.");

        using NvCertifyResponse nvCertify = result.Value;
        TpmsAttest attest = nvCertify.CertifyInfo.AttestationData;
        Assert.IsNotNull(attest.Attested.Nv);

        return attest.Attested.Nv!.IndexName.Span.ToArray();
    }

    /// <summary>
    /// Rotates an NV Index's authorization value with <c>TPM2_NV_ChangeAuth</c> under the Index's own ADMIN-role
    /// policy: a policy session asserting <c>TPM2_PolicyAuthValue</c> then
    /// <c>TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c>, which is the only authorization shape the command
    /// accepts (TPM 2.0 Library Part 3, clause 31.15.1). The Index Name feeding cpHash is the caller's own
    /// independent transcription rather than a value read back from the TPM, so a mistranscribed Name shows up
    /// as an authorization failure here instead of silently agreeing with the implementation under test.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index to rotate.</param>
    /// <param name="indexName">The Index's Name, independently transcribed.</param>
    /// <param name="currentAuthValue">The Index's current authorization value.</param>
    /// <param name="newAuthValue">The replacement authorization value.</param>
    private async Task RotateIndexAuthValueAsync(
        TpmDevice tpm, BaseMemoryPool pool, uint nvIndex, ReadOnlyMemory<byte> indexName, ReadOnlyMemory<byte> currentAuthValue, ReadOnlyMemory<byte> newAuthValue)
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmResponseCodec.NvChangeAuth);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySessionAsync failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool);

            TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValueAsync failed: '{authValueResult.ResponseCode}'.");

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_NV_ChangeAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCodeAsync failed: '{commandCodeResult.ResponseCode}'.");

            session.SetAuthValue(currentAuthValue.Span, pool);

            using Tpm2bAuth newAuth = Tpm2bAuth.Create(newAuthValue.Span, pool);
            using NvChangeAuthInput input = new(nvIndex, newAuth);

            //The response HMAC is keyed on the value the rotation installs, because the TPM commits the change
            //before it frames the response (Part 3, clause 31.15.1), so the session moves onto the new value
            //between submission and verification.
            async ValueTask<TpmResult<TpmResponse>> SubmitThenAdoptNewAuthAsync(
                ReadOnlyMemory<byte> command, BaseMemoryPool submitPool, CancellationToken submitCancellationToken)
            {
                TpmResult<TpmResponse> submitted = await tpm.SubmitAsync(command, submitPool, submitCancellationToken).ConfigureAwait(false);
                session.SetAuthValue(newAuthValue.Span, pool);

                return submitted;
            }

            using TpmDevice rotationDevice = TpmDevice.Create(SubmitThenAdoptNewAuthAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

            TpmResult<NvChangeAuthResponse> rotationResult = await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
                rotationDevice, input, [session], [indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(rotationResult.IsSuccess, $"TPM2_NV_ChangeAuth failed: '{rotationResult.ResponseCode}'.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Transcribes the ADMIN-role rotation policy digest independently from the two extend formulas the
    /// specification states: <c>policyDigest = H(zeroes || TPM_CC_PolicyAuthValue)</c> (TPM 2.0 Library Part 3,
    /// clause 23.17), then
    /// <c>policyDigest = H(policyDigest || TPM_CC_PolicyCommandCode || TPM_CC_NV_ChangeAuth)</c> (clause 23.11).
    /// An Index defined with this digest is one whose <c>authPolicy</c> a live session asserting the same two
    /// predicates in the same order can satisfy, which is what makes it rotation-capable at all (Part 1, clause
    /// 11.2: an Empty Policy satisfies nothing).
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The transcribed policy digest.</returns>
    private async Task<byte[]> ComputeRotationAuthPolicyAsync(BaseMemoryPool pool)
    {
        byte[] authValueInput = new byte[P256ComponentSize + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authValueInput.AsSpan(P256ComponentSize), (uint)TpmCcConstants.TPM_CC_PolicyAuthValue);
        byte[] afterAuthValue = await ComputeSha256Async(authValueInput, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] commandCodeInput = new byte[P256ComponentSize + sizeof(uint) + sizeof(uint)];
        afterAuthValue.CopyTo(commandCodeInput.AsSpan());
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(P256ComponentSize), (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(P256ComponentSize + sizeof(uint)), (uint)TpmCcConstants.TPM_CC_NV_ChangeAuth);

        return await ComputeSha256Async(commandCodeInput, pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Certifies the Index's contents with the RSA AK under the given scheme through the production command
    /// path, verifies the attestation off-TPM, and verifies the signature against the AK's exported modulus with
    /// an independent RSA verifier.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The RSA attestation key's CreatePrimary response.</param>
    /// <param name="rsaParameters">The public key reconstructed from the AK's exported modulus.</param>
    /// <param name="usePss">When <see langword="true"/>, certifies and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task NvCertifyAndVerifyRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, RSAParameters rsaParameters, bool usePss)
    {
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = usePss
            ? NvCertifyInput.ForRsaPss(ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool)
            : NvCertifyInput.ForRsaSsa(ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        string schemeName = usePss ? "RSAPSS" : "RSASSA";
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify ({schemeName}) failed: '{result.ResponseCode}'.");

        using NvCertifyResponse nvCertify = result.Value;
        Assert.AreEqual(usePss ? TpmAlgIdConstants.TPM_ALG_RSAPSS : TpmAlgIdConstants.TPM_ALG_RSASSA, nvCertify.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, nvCertify.HashAlgorithm);

        await AssertNvCertifyAttestationAsync(nvCertify, WrittenData, offset: 0, ak, pool).ConfigureAwait(false);

        byte[] attestDigest = await ComputeSha256Async(nvCertify.CertifyInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(attestDigest, nvCertify.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, padding),
            $"The {schemeName} NV-certify signature must verify against the RSA AK's exported modulus.");
    }

    /// <summary>
    /// Asserts the envelope (magic/type/nonce), the attested indexName against an independent Name recomputation,
    /// the attested offset and nvContents against the expected written window, and qualifiedSigner against an
    /// independent (non-collapsed) Qualified Name recomputation.
    /// </summary>
    /// <param name="nvCertify">The parsed NV-certify response.</param>
    /// <param name="expectedWindow">The expected attested NV contents (the octets this test wrote at <paramref name="offset"/>).</param>
    /// <param name="offset">The expected attested offset.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task AssertNvCertifyAttestationAsync(NvCertifyResponse nvCertify, byte[] expectedWindow, ushort offset, CreatePrimaryResponse ak, BaseMemoryPool pool)
    {
        TpmsAttest attest = nvCertify.CertifyInfo.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_NV, attest.Type);
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
        Assert.IsNotNull(attest.Attested.Nv);

        //The Index's Name is computed over its CURRENT attributes (TPM 2.0 Library Part 1, clause 13, Table 9): by the
        //time NV_Certify() runs the Index has been written, so TPMA_NV_WRITTEN is folded in exactly as
        //TPM2_NV_Write() set it, distinct from the attributes this test originally defined the Index with.
        byte[] expectedIndexName = await ComputeNvIndexNameAsync(
            NvIndexHandle, DefaultNameAlg, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty,
            (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Nv!.IndexName.Span.SequenceEqual(expectedIndexName),
            "The attested indexName must equal the Index's Name recomputed from its public-area fields.");

        Assert.AreEqual(offset, attest.Attested.Nv!.Offset, "The attested offset must equal the requested offset.");
        Assert.IsTrue(
            attest.Attested.Nv!.NvContents.SequenceEqual(expectedWindow),
            "The attested nvContents must equal the octets this test wrote at the requested offset/size.");

        byte[] expectedSignerQn = await ComputeQualifiedNameAsync(
            (uint)TpmRh.TPM_RH_ENDORSEMENT, ak.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.QualifiedSigner.Span.SequenceEqual(expectedSignerQn),
            "qualifiedSigner must equal the AK's independently recomputed Qualified Name.");
        Assert.IsFalse(
            attest.QualifiedSigner.Span.SequenceEqual(ak.Name.Span),
            "qualifiedSigner must not collapse to the AK's plain Name.");
    }

    /// <summary>
    /// Defines <see cref="NvIndexHandle"/> under the owner hierarchy (empty owner authorization, matching the
    /// simulator's default) with the given attributes and <see cref="IndexAuth"/>, sized for
    /// <see cref="WrittenData"/>, without writing it.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="attributes">The Index attributes.</param>
    private Task DefineNvIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmaNv attributes) =>
        DefineNvIndexAsync(tpm, registry, pool, NvIndexHandle, DefaultNameAlg, attributes, ReadOnlyMemory<byte>.Empty);

    /// <summary>
    /// Defines an NV Index under the owner hierarchy (empty owner authorization, matching the simulator's
    /// default) with a caller-chosen handle, Name algorithm, attributes, and access policy, carrying
    /// <see cref="IndexAuth"/> as its own authorization value and sized for <see cref="WrittenData"/>, without
    /// writing it.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="nameAlg">The Index's Name algorithm.</param>
    /// <param name="attributes">The Index attributes.</param>
    /// <param name="authPolicy">The access policy digest; empty for an Index with no policy.</param>
    private async Task DefineNvIndexAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ReadOnlyMemory<byte> authPolicy)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(IndexAuth, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, nameAlg, attributes, policyDigest, dataSize: (ushort)WrittenData.Length);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
    }

    /// <summary>
    /// Defines <see cref="NvIndexHandle"/> (via <see cref="DefineNvIndexAsync"/>) and then writes
    /// <see cref="WrittenData"/> to it in full, setting <c>TPMA_NV_WRITTEN</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="attributes">The Index attributes.</param>
    private Task DefineAndWriteNvIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmaNv attributes) =>
        DefineAndWriteNvIndexAsync(tpm, registry, pool, NvIndexHandle, DefaultNameAlg, attributes, ReadOnlyMemory<byte>.Empty);

    /// <summary>
    /// Defines an NV Index with a caller-chosen handle, Name algorithm, attributes, and access policy (via
    /// <see cref="DefineNvIndexAsync(TpmDevice, TpmResponseRegistry, BaseMemoryPool, uint, TpmAlgIdConstants, TpmaNv, ReadOnlyMemory{byte})"/>)
    /// and then writes <see cref="WrittenData"/> to it in full, setting <c>TPMA_NV_WRITTEN</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="nameAlg">The Index's Name algorithm.</param>
    /// <param name="attributes">The Index attributes.</param>
    /// <param name="authPolicy">The access policy digest; empty for an Index with no policy.</param>
    private async Task DefineAndWriteNvIndexAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ReadOnlyMemory<byte> authPolicy)
    {
        await DefineNvIndexAsync(tpm, registry, pool, nvIndex, nameAlg, attributes, authPolicy).ConfigureAwait(false);

        using TpmPasswordSession writeAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(WrittenData, pool);
        var writeInput = new NvWriteInput(nvIndex, nvIndex, writeInputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy and returns the response (the caller
    /// owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a DA-protected ECC P-256 signing key under the endorsement hierarchy with a NON-EMPTY authValue
    /// (<see cref="SignerKeyPassword"/>) — the fixture the sign-slot verification proofs need to exercise a
    /// signing key's own retained authValue rather than the empty one every other AK fixture carries.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateDaProtectedSigningPrimaryWithAuthAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT,
            password: SignerKeyPassword,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: false);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (DA-protected ECC signer with authValue) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy with an EMPTY authValue and
    /// <c>TPMA_OBJECT.userWithAuth</c> CLEAR — composed directly (there is no factory) rather than through
    /// <see cref="CreatePrimaryInput.ForEccSigningKey"/>, which always sets that attribute. A hierarchy "operates
    /// as if userWithAuth is SET" (TPM 2.0 Library Part 3, clause 5.6), so creation itself succeeds even though
    /// the created key's own USER role can then be authorized only by a policy session — never a password or an
    /// HMAC session, bound or not (check 7.1).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the CreatePrimaryInput, whose Dispose releases them.")]
    private async Task<CreatePrimaryResponse> CreateUserWithAuthClearSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        var attributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN | TpmaObject.SIGN_ENCRYPT;
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));
        using CreatePrimaryInput input = new(hierarchy, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (userWithAuth-CLEAR ECC signer, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary RSA-2048 signing key under the given hierarchy and returns the response (the caller owns
    /// it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            hierarchy, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates an ECC storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) under the given hierarchy and returns
    /// the response (the caller owns it) — a key that cannot sign, for the negative sign-attribute test.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the parent.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, authPassword: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC storage parent, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Recomputes an NV Index's Name independently: <c>nameAlg || H_nameAlg(nvIndex || nameAlg || attributes ||
    /// authPolicy || dataSize)</c> — the whole marshaled TPMS_NV_PUBLIC this test itself defined the Index with
    /// (TPM 2.0 Library Part 2, clause 13.6) hashed per Part 1, clause 13, Table 9 — through the registered
    /// digest seam. Every field the recipe reads is a parameter here, so an Index defined with a non-default
    /// Name algorithm or a non-empty access policy is transcribed as faithfully as the default shape. This test
    /// never calls the production <c>TpmsNvPublic</c>/<c>TpmObjectName</c> types, matching the firewalled,
    /// off-TPM oracle style the Certify test file uses.
    /// </summary>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="nameAlg">The Index's Name algorithm, which both prefixes the Name and selects the hash.</param>
    /// <param name="attributes">The Index attributes this test defined the Index with.</param>
    /// <param name="authPolicy">The Index's access policy digest; empty for an Index defined with no policy.</param>
    /// <param name="dataSize">The Index's declared data size.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Name (2-byte nameAlg prefix + digest).</returns>
    private static async Task<byte[]> ComputeNvIndexNameAsync(
        uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ReadOnlyMemory<byte> authPolicy, ushort dataSize, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] marshaled = new byte[sizeof(uint) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + authPolicy.Length + sizeof(ushort)];
        int offset = 0;
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset), nvIndex);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), (ushort)nameAlg);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset), (uint)attributes);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), (ushort)authPolicy.Length);
        offset += sizeof(ushort);
        authPolicy.Span.CopyTo(marshaled.AsSpan(offset));
        offset += authPolicy.Length;
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), dataSize);

        byte[] digest = await ComputeNameDigestAsync(nameAlg, marshaled, pool, cancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Computes a digest under an Index's own Name algorithm through the registered digest seam (not a direct
    /// framework hash) — the <c>H_nameAlg</c> of the Name recipe, which is the Index's <c>nameAlg</c> rather
    /// than any fixed algorithm (TPM 2.0 Library Part 1, clause 13, Table 9).
    /// </summary>
    /// <param name="nameAlg">The Name algorithm selecting the hash and its output width.</param>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The digest, at the Name algorithm's own width.</returns>
    private static async Task<byte[]> ComputeNameDigestAsync(
        TpmAlgIdConstants nameAlg, ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        (HashAlgorithmName algorithm, int digestSize) = nameAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA256 => (HashAlgorithmName.SHA256, P256ComponentSize),
            TpmAlgIdConstants.TPM_ALG_SHA384 => (HashAlgorithmName.SHA384, Sha384DigestSize),
            _ => throw new NotSupportedException($"No Name-algorithm oracle is transcribed for '{nameAlg}'.")
        };

        Tag tag = Tag.Create(algorithm)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: digestSize,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Recomputes an object's Qualified Name independently: <c>nameAlg || H(hierarchyHandle || Name)</c> (TPM 2.0
    /// Library Part 1, clause 13, Table 9), through the registered digest seam. Every object this simulator certifies is a
    /// primary created directly under a permanent hierarchy, so the hierarchy's own Qualified Name is its 4-octet
    /// big-endian handle value — this test never calls the production <c>TpmObjectName</c> helper, matching the
    /// firewalled, off-TPM oracle style the Certify test file uses.
    /// </summary>
    /// <param name="hierarchy">The permanent hierarchy handle the object was created under.</param>
    /// <param name="name">The object's own Name.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Qualified Name.</returns>
    private static async Task<byte[]> ComputeQualifiedNameAsync(uint hierarchy, ReadOnlyMemory<byte> name, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ushort nameAlg = BinaryPrimitives.ReadUInt16BigEndian(name.Span[..sizeof(ushort)]);
        Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_SHA256, nameAlg, "This test assumes a SHA-256 nameAlg.");

        byte[] message = new byte[sizeof(uint) + name.Length];
        BinaryPrimitives.WriteUInt32BigEndian(message, hierarchy);
        name.Span.CopyTo(message.AsSpan(sizeof(uint)));

        byte[] digest = await ComputeSha256Async(message, pool, cancellationToken).ConfigureAwait(false);

        byte[] qualifiedName = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(qualifiedName, nameAlg);
        digest.CopyTo(qualifiedName.AsSpan(sizeof(ushort)));

        return qualifiedName;
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-nv-certify",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);

        return registry;
    }

    /// <summary>
    /// Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: P256ComponentSize,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 / ECPoint encodings require. The
    /// simulator returns TPM2B integers that may omit leading zero bytes.
    /// </summary>
    /// <param name="value">The big-endian value.</param>
    /// <param name="length">The fixed width to pad to.</param>
    /// <returns>A new array of exactly <paramref name="length"/> bytes.</returns>
    private static byte[] ToFixed(ReadOnlySpan<byte> value, int length)
    {
        byte[] result = new byte[length];
        if(value.Length <= length)
        {
            value.CopyTo(result.AsSpan(length - value.Length));
        }
        else
        {
            //Defensive: drop any leading zero padding the simulator may have included.
            value[^length..].CopyTo(result);
        }

        return result;
    }
}
