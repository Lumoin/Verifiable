using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_GetTime()</c> (time attestation) against the in-house behavioural <see cref="TpmSimulator"/> —
/// entirely in-process, with no external assets — through the same production command path the production code
/// uses (<see cref="TpmCommandExecutor"/> with the real <see cref="GetTimeInput"/> and response codecs):
/// <c>TPM2_CreatePrimary()</c> mints an attestation key (AK) under the endorsement hierarchy, then the AK attests
/// the TPM's real time image over a caller nonce.
/// </summary>
/// <remarks>
/// <para>
/// The result is verified <b>off-TPM</b> from wire bytes only: the magic / type / nonce fields, that the attested
/// time image carries the real Clock/Time/resetCount/restartCount/Safe/firmwareVersion snapshot the transition
/// folded from state after the per-command advance (TPM 2.0 Library Part 1, clause 36; Part 3, clause 18.7), and
/// the ECDSA/RSA signature over the raw attestation bytes against the AK's exported public key reconstructed
/// from <c>outPublic</c> alone.
/// </para>
/// <para>
/// Both handles require authorization (TPM 2.0 Library Part 3, clause 18.7, Table 99), so the executor is given
/// two empty-auth password sessions in handle order: <c>@privacyAdminHandle</c> first, <c>@signHandle</c> second.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorGetTimeTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA get-time tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.</summary>
    private static IMemoryOwner<byte> Nonce { get; } = RentLiteral("GetTime nonce for the in-house TPM."u8);

    /// <summary>
    /// The simulator's synthetic firmware version this test expects: a UINT32 major half of 1 and a minor
    /// half of 184, mirroring <c>TpmSimulator</c>'s own <c>SimulatedFirmwareVersion</c> constant (TPM 2.0
    /// Library Part 2, clause 10.12.12).
    /// </summary>
    private const ulong ExpectedFirmwareVersion = (1UL << 32) | 184UL;

    /// <summary>The real password installed on the endorsement hierarchy for the hierarchy authValue proof.</summary>
    private const string EndorsementHierarchyPassword = "get-time-endorsement-auth-proof";

    /// <summary>
    /// The endorsement hierarchy's installed password in wire form — the UTF-8 octets of
    /// <see cref="EndorsementHierarchyPassword"/>, matching the password-to-authValue convention
    /// <see cref="Tpm2bAuth.CreateFromPassword"/> applies on the installation side (the password carries no
    /// trailing zeros, so no trimming is in play).
    /// </summary>
    private static byte[] EndorsementHierarchyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(EndorsementHierarchyPassword);

    /// <summary>A wrong guess at the endorsement hierarchy's password, distinct from <see cref="EndorsementHierarchyPasswordBytes"/>.</summary>
    private static byte[] WrongEndorsementHierarchyPasswordBytes { get; } = [0xC1, 0xC2, 0xC3, 0xC4];

    /// <summary>The real password the signing-key authValue proof creates its AK with.</summary>
    private const string SigningKeyPassword = "get-time-signing-key-auth-proof";

    /// <summary>A wrong guess at the signing key's password, distinct from <see cref="SigningKeyPassword"/>.</summary>
    private static byte[] WrongSigningKeyPasswordBytes { get; } = [0xD1, 0xD2, 0xD3, 0xD4];

    /// <summary>
    /// The real password installed on the <c>TPMA_OBJECT.userWithAuth</c>-CLEAR signing key the check-7.1 proof
    /// creates its AK with. USER-role authorization by authValue (password or HMAC session) is never available
    /// against this key regardless of whether this exact value is supplied (TPM 2.0 Library Part 3, clause 5.6,
    /// check 7.1).
    /// </summary>
    private const string UserWithAuthClearSignerPassword = "get-time-clear-signer-proof";

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Releases the pooled <see cref="Nonce"/> buffer shared across every test in this class.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Nonce.Dispose();
    }

    /// <summary>
    /// Verifies a full ECDSA P-256 get-time round trip: the real time image is attested, the nonce is echoed,
    /// qualifiedSigner is the AK's real (non-collapsed) Qualified Name, and the signature verifies against the
    /// AK's exported public key (TPM 2.0 Library Part 3, clause 18.7).
    /// </summary>
    [TestMethod]
    public async Task EcdsaP256GetTimeVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, getTimeInput, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetTime failed: '{result.ResponseCode}'.");

        using GetTimeResponse getTime = result.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, getTime.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, getTime.HashAlgorithm);

        await AssertTimeAttestationAsync(getTime, ak, pool).ConfigureAwait(false);

        byte[] attestDigest = await ComputeSha256Async(getTime.TimeInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

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
        ToFixed(getTime.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(getTime.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(
            ecdsa.VerifyHash(attestDigest, p1363Signature),
            "The get-time signature must verify over the raw attestation bytes against the AK's exported public key.");
    }

    /// <summary>
    /// Verifies get-time with an RSA AK under both RSASSA and RSAPSS, mirroring the ECDSA assertions (TPM 2.0
    /// Library Part 3, clause 18.7).
    /// </summary>
    [TestMethod]
    public async Task RsaGetTimeVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        var rsaParameters = new RSAParameters
        {
            Modulus = ak.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        await GetTimeAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, usePss: false).ConfigureAwait(false);
        await GetTimeAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, usePss: true).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that <c>Clock</c> and <c>Time</c> strictly increase across two sequential
    /// <c>TPM2_GetTime()</c> calls within one power cycle, while <c>resetCount</c>/<c>restartCount</c> stay
    /// stable (TPM 2.0 Library Part 1, clause 36.1: each dispatched command advances the free-running
    /// counters by one fixed quantum).
    /// </summary>
    [TestMethod]
    public async Task GetTimeAdvancesMonotonicallyAcrossCalls()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using GetTimeResponse first = await IssueGetTimeAsync(tpm, registry, pool, ak).ConfigureAwait(false);
        using GetTimeResponse second = await IssueGetTimeAsync(tpm, registry, pool, ak).ConfigureAwait(false);

        TpmsTimeAttestInfo firstTimeInfo = first.TimeInfo.AttestationData.Attested.Time!.Value;
        TpmsTimeAttestInfo secondTimeInfo = second.TimeInfo.AttestationData.Attested.Time!.Value;

        Assert.IsGreaterThan(firstTimeInfo.Time.ClockInfo.Clock, secondTimeInfo.Time.ClockInfo.Clock, "Clock must strictly increase across two sequential commands.");
        Assert.IsGreaterThan(firstTimeInfo.Time.Time, secondTimeInfo.Time.Time, "Time must strictly increase across two sequential commands within one power cycle.");
        Assert.AreEqual(firstTimeInfo.Time.ClockInfo.ResetCount, secondTimeInfo.Time.ClockInfo.ResetCount, "resetCount must stay stable within one power cycle.");
        Assert.AreEqual(firstTimeInfo.Time.ClockInfo.RestartCount, secondTimeInfo.Time.ClockInfo.RestartCount, "restartCount must stay stable within one power cycle.");
    }

    /// <summary>
    /// Issues one <c>TPM2_GetTime()</c> against the AK and returns the parsed response (the caller owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <returns>The parsed get-time response.</returns>
    private async Task<GetTimeResponse> IssueGetTimeAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak)
    {
        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, getTimeInput, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetTime failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Verifies that a privacyAdminHandle other than <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> is rejected: this
    /// simulator mirrors the <c>TPM2_NV_DefineSpace()</c> fixed-handle precedent (a wrong provisioning handle is
    /// <c>TPM_RC_HANDLE</c>) since TPMI_RH_ENDORSEMENT has exactly one legal value (TPM 2.0 Library Part 3,
    /// clause 18.7).
    /// </summary>
    [TestMethod]
    public async Task GetTimeWithWrongPrivacyAdminHandleReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput getTimeInput = GetTimeInput.Create(
            TpmRh.TPM_RH_OWNER, ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, getTimeInput, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode);
    }

    /// <summary>
    /// Verifies that an RSA scheme against an ECC signing key is a genuine scheme/key-type mismatch, distinct
    /// from an unresolved handle (TPM 2.0 Library Part 3, clause 18.7, mirroring TPM2_Certify()'s equivalent
    /// check).
    /// </summary>
    [TestMethod]
    public async Task GetTimeWithSchemeMismatchedToSignerKeyTypeReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput getTimeInput = GetTimeInput.ForRsaSsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, getTimeInput, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode);
    }

    /// <summary>
    /// TPM2_GetTime()'s privacyAdminHandle slot (Auth Index 1, Auth Role USER, fixed to
    /// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/>; TPM 2.0 Library Part 3, clause 18.7, Table 99) is verified
    /// against the endorsement hierarchy's own retained authorization value, installed by
    /// <c>TPM2_HierarchyChangeAuth</c> (Part 3, clause 24.8.1): permanent hierarchies are dictionary-attack
    /// exempt (Part 1, clause 17.8.1), so a WRONG password is refused with the plain, never
    /// session-index-encoded, <c>TPM_RC_BAD_AUTH</c> (clause 17.8.7's downgrade) and moves no dictionary-attack
    /// counter, while the CORRECT password authorizes the command and the attestation carries the real time
    /// image.
    /// </summary>
    [TestMethod]
    public async Task GetTimeVerifiesTheEndorsementHierarchysAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The AK is created before the rotation, while the endorsement hierarchy still carries its
        //factory-empty authorization value, so TPM2_CreatePrimary()'s own hierarchy slot authorizes.
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<HierarchyChangeAuthResponse> rotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, EndorsementHierarchyPasswordBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotation.IsSuccess, $"Installing the endorsement hierarchy's authorization value failed: '{rotation.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession correctPrivacyAdminAuth = TpmPasswordSession.Create(EndorsementHierarchyPassword, pool);
        using TpmPasswordSession correctSignAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput correctGetTimeInput = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, correctGetTimeInput, [correctPrivacyAdminAuth, correctSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"GetTime with the endorsement hierarchy's correct authorization value must succeed, but failed: '{correctResult.ResponseCode}'.");

        using(GetTimeResponse correctGetTime = correctResult.Value)
        {
            await AssertTimeAttestationAsync(correctGetTime, ak, pool).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized GetTime must move no dictionary-attack counter.");

        using TpmPasswordSession wrongPrivacyAdminAuth = TpmPasswordSession.Create(WrongEndorsementHierarchyPasswordBytes, pool);
        using TpmPasswordSession wrongSignAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput wrongGetTimeInput = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, wrongGetTimeInput, [wrongPrivacyAdminAuth, wrongSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(wrongResult.IsTpmError, "A wrong endorsement hierarchy password must be refused.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.ResponseCode,
            "Owner, endorsement and platform authorization values are dictionary-attack exempt permanent-entity values (TPM 2.0 Library Part 1, clause 17.8.1), so a mismatch is the plain, never session-index-encoded, TPM_RC_BAD_AUTH.");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter, afterWrong.Value.LockoutCounter,
            "A wrong hierarchy authorization value must never move the dictionary-attack counter: permanent entities are dictionary-attack exempt (TPM 2.0 Library Part 1, clause 17.8.1).");
    }

    /// <summary>
    /// TPM2_GetTime()'s signHandle slot (Auth Index 2, Auth Role USER; TPM 2.0 Library Part 3, clause 18.7,
    /// Table 99) is verified against the signing key's own retained authorization value: a dictionary-attack
    /// protected AK created with a real password is refused with the session-index-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> at slot 1 (Part 2, clause 6.6.2) and charges <c>failedTries</c> exactly once
    /// (Part 1, clause 17.8.7) when the wrong password is supplied — while the endorsement hierarchy's own
    /// privacyAdminHandle slot (slot 0) still authorizes with its factory-empty value — and the CORRECT
    /// signing-key password authorizes the command and the attestation carries the real time image.
    /// </summary>
    [TestMethod]
    public async Task GetTimeVerifiesTheSigningKeysAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession correctPrivacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession correctSignAuth = TpmPasswordSession.Create(SigningKeyPassword, pool);
        using GetTimeInput correctGetTimeInput = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, correctGetTimeInput, [correctPrivacyAdminAuth, correctSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"GetTime with the signing key's correct authorization value must succeed, but failed: '{correctResult.ResponseCode}'.");

        using(GetTimeResponse correctGetTime = correctResult.Value)
        {
            await AssertTimeAttestationAsync(correctGetTime, ak, pool).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized GetTime must move no dictionary-attack counter.");

        using TpmPasswordSession wrongPrivacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongSigningKeyPasswordBytes, pool);
        using GetTimeInput wrongGetTimeInput = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, wrongGetTimeInput, [wrongPrivacyAdminAuth, wrongSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(wrongResult.IsTpmError, "A wrong signing-key password must be refused.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), wrongResult.ResponseCode,
            "A wrong signing-key password over a plain TPM_RS_PW session names the sign slot (index 1), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong signing-key password against a dictionary-attack-protected signing key must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 17.8.7).");
    }

    /// <summary>
    /// TPM2_GetTime()'s signHandle slot (Auth Index 2, Auth Role USER; TPM 2.0 Library Part 3, clause 18.7,
    /// Table 99) refuses authValue-based authorization outright when the signing key's
    /// <c>TPMA_OBJECT.userWithAuth</c> is CLEAR, even given the key's own correct password: check 7.1 in Part 3,
    /// clause 5.6's mandatory order runs before checks 9/10 (the credential comparison and any command-HMAC
    /// queuing), so the command is refused with the bare <c>TPM_RC_POLICY_FAIL</c> — never the session-index-
    /// encoded form checks 9/10 would produce — without charging <c>failedTries</c> (clause 5.6's closing rule:
    /// a non-AUTH_FAIL error "shall not alter any TPM state"). Meanwhile the privacyAdminHandle slot (Auth Index
    /// 1) authorizes TPM_RH_ENDORSEMENT, a hierarchy, which "operates as if userWithAuth is SET" (clause 5.6)
    /// and is exempt from check 7.1: supplying its own correct, freshly rotated password proves that slot passed
    /// and the refusal originates at the object slot alone, not from an unauthorized hierarchy.
    /// </summary>
    [TestMethod]
    public async Task GetTimeWithUserWithAuthClearSignerIsRefusedWithoutComparingThePassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The AK is created before the hierarchy rotation, while the endorsement hierarchy still carries its
        //factory-empty authorization value, so TPM2_CreatePrimary()'s own hierarchy slot authorizes: creation
        //itself is authorized by the hierarchy, which is exempt from check 7.1.
        using CreatePrimaryResponse ak = await CreateUserWithAuthClearSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, UserWithAuthClearSignerPassword).ConfigureAwait(false);

        TpmResult<HierarchyChangeAuthResponse> rotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, EndorsementHierarchyPasswordBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotation.IsSuccess, $"Installing the endorsement hierarchy's authorization value failed: '{rotation.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        //The correct endorsement hierarchy password (privacyAdminHandle, exempt) AND the signing key's own
        //correct password (signHandle, userWithAuth CLEAR) — the object slot must still refuse, proving the
        //gate never reaches the credential comparison at all.
        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.Create(EndorsementHierarchyPassword, pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.Create(UserWithAuthClearSignerPassword, pool);
        using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, getTimeInput, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode,
            $"A userWithAuth-CLEAR signing key must refuse password authorization on the signHandle slot with the bare " +
            $"TPM_RC_POLICY_FAIL (TPM 2.0 Library Part 3, clause 5.6, check 7.1), even given its own correct password and " +
            $"a correctly authorized hierarchy slot (got '{result.ResponseCode}').");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "Check 7.1's refusal is TPM_RC_POLICY_FAIL, not TPM_RC_AUTH_FAIL, so failedTries must stay untouched " +
            "(TPM 2.0 Library Part 3, clause 5.6's closing rule: a non-AUTH_FAIL error shall not alter any TPM state).");
    }

    /// <summary>
    /// Attests time with the RSA AK under the given scheme through the production command path, verifies the
    /// attestation off-TPM, and verifies the signature against the AK's exported modulus with an independent RSA
    /// verifier.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The RSA attestation key's CreatePrimary response.</param>
    /// <param name="rsaParameters">The public key reconstructed from the AK's exported modulus.</param>
    /// <param name="usePss">When <see langword="true"/>, attests and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task GetTimeAndVerifyRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse ak, RSAParameters rsaParameters, bool usePss)
    {
        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput getTimeInput = usePss
            ? GetTimeInput.ForRsaPss(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool)
            : GetTimeInput.ForRsaSsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, getTimeInput, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        string schemeName = usePss ? "RSAPSS" : "RSASSA";
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetTime ({schemeName}) failed: '{result.ResponseCode}'.");

        using GetTimeResponse getTime = result.Value;
        Assert.AreEqual(usePss ? TpmAlgIdConstants.TPM_ALG_RSAPSS : TpmAlgIdConstants.TPM_ALG_RSASSA, getTime.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, getTime.HashAlgorithm);

        await AssertTimeAttestationAsync(getTime, ak, pool).ConfigureAwait(false);

        byte[] attestDigest = await ComputeSha256Async(getTime.TimeInfo.GetRawMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(attestDigest, getTime.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, padding),
            $"The {schemeName} get-time signature must verify against the RSA AK's exported modulus.");
    }

    /// <summary>
    /// Asserts the envelope (magic/type/nonce), that the attested time image carries the real
    /// Clock/Time/resetCount/restartCount/Safe/firmwareVersion snapshot — both the envelope-level
    /// <c>TPMS_ATTEST.clockInfo</c> and the nested <c>TPMS_TIME_ATTEST_INFO</c> copy agree (TPM 2.0 Library
    /// Part 1, clause 36.7) — and qualifiedSigner against an independent (non-collapsed) Qualified Name
    /// recomputation.
    /// </summary>
    /// <param name="getTime">The parsed get-time response.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task AssertTimeAttestationAsync(GetTimeResponse getTime, CreatePrimaryResponse ak, BaseMemoryPool pool)
    {
        TpmsAttest attest = getTime.TimeInfo.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_TIME, attest.Type);
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce.Memory.Span), "extraData must echo the caller's qualifyingData nonce.");
        Assert.IsNotNull(attest.Attested.Time);

        TpmsTimeAttestInfo timeInfo = attest.Attested.Time!.Value;
        Assert.IsGreaterThan(0ul, timeInfo.Time.Time, "Time must be real: > 0 after at least CreatePrimary and GetTime have each advanced it by one quantum.");
        Assert.IsGreaterThan(0ul, timeInfo.Time.ClockInfo.Clock, "Clock must be real: > 0 after Startup, CreatePrimary, and GetTime have each advanced it by one quantum.");
        Assert.AreEqual(1u, timeInfo.Time.ClockInfo.ResetCount, "A fresh simulator's single Startup(CLEAR) is exactly one TPM Reset (Part 1, clause 36.4).");
        Assert.AreEqual(0u, timeInfo.Time.ClockInfo.RestartCount, "No Restart or Resume has occurred in this fresh simulator's single power cycle.");
        Assert.IsTrue(timeInfo.Time.ClockInfo.Safe.IsYes, "A fresh simulator's very first Reset is Safe: no prior Clock value could ever have been reported (Part 1, clause 36.3).");
        Assert.AreEqual(ExpectedFirmwareVersion, timeInfo.FirmwareVersion, "The simulator reports its fixed synthetic firmware version.");

        Assert.AreEqual(attest.ClockInfo.Clock, timeInfo.Time.ClockInfo.Clock, "The envelope-level clockInfo and the nested TPMS_TIME_ATTEST_INFO copy must agree (Part 1, clause 36.7).");
        Assert.AreEqual(attest.ClockInfo.ResetCount, timeInfo.Time.ClockInfo.ResetCount, "The envelope-level clockInfo and the nested copy must agree on resetCount.");
        Assert.AreEqual(attest.ClockInfo.RestartCount, timeInfo.Time.ClockInfo.RestartCount, "The envelope-level clockInfo and the nested copy must agree on restartCount.");
        Assert.AreEqual(attest.ClockInfo.Safe.IsYes, timeInfo.Time.ClockInfo.Safe.IsYes, "The envelope-level clockInfo and the nested copy must agree on Safe.");
        Assert.AreEqual(ExpectedFirmwareVersion, attest.FirmwareVersion, "The envelope-level firmwareVersion must equal the nested copy's.");

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
    /// Creates a primary ECC P-256 signing key under the given hierarchy with a real, non-empty password and
    /// dictionary-attack protection left engaged (<c>TPMA_OBJECT.NO_DA</c> clear) — the fixture the signing
    /// key's own authValue verification proof needs to exercise TPM2_GetTime()'s signHandle slot (TPM 2.0
    /// Library Part 3, clause 18.7, Table 99) against a genuine retained authorization value.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The signing key's password.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreatePasswordProtectedSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: false);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, password-protected, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy whose <c>TPMA_OBJECT.userWithAuth</c>
    /// attribute is CLEAR — composed directly rather than through
    /// <see cref="CreatePrimaryInput.ForEccSigningKey"/>, which always sets
    /// <see cref="TpmaObject.USER_WITH_AUTH"/> — and dictionary-attack protection left engaged
    /// (<c>TPMA_OBJECT.NO_DA</c> clear), so a password-authorization attempt against it is a genuine check-7.1
    /// proof rather than a vacuously uncharged one. Creation itself is authorized by the hierarchy, which is
    /// exempt from check 7.1 (TPM 2.0 Library Part 3, clause 5.6).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The key's retained authValue, in password form.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateUserWithAuthClearSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string password)
    {
        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.SIGN_ENCRYPT;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.WithPassword(password, pool);
        using Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));
        using CreatePrimaryInput input = new(hierarchy, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, userWithAuth CLEAR, {hierarchy}) failed: '{result.ResponseCode}'.");

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
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-get-time",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
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

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetTime, TpmResponseCodec.GetTime);

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
    /// Recomputes an object's Qualified Name independently: <c>nameAlg || H(hierarchyHandle || Name)</c> (TPM 2.0
    /// Library Part 1, clause 14, Table 6), through the registered digest seam. Every object this simulator certifies is a
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

    /// <summary>
    /// Rents a buffer from <see cref="BaseMemoryPool.Shared"/> sized to <paramref name="literal"/> and copies the
    /// literal's bytes into it, so a fixed test constant is pool-backed rather than a naked array.
    /// </summary>
    /// <param name="literal">The compile-time literal bytes to copy into pooled memory.</param>
    /// <returns>A pooled owner holding exactly <paramref name="literal"/>'s bytes.</returns>
    private static IMemoryOwner<byte> RentLiteral(ReadOnlySpan<byte> literal)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(literal.Length);
        literal.CopyTo(owner.Memory.Span);

        return owner;
    }

    /// <summary>The hash algorithm every HMAC or policy session these over-session tests compose uses.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The signing key's authValue in wire form — the UTF-8 octets <see cref="SigningKeyPassword"/> derives.</summary>
    private static byte[] SigningKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SigningKeyPassword);

    /// <summary>tpmKey's own Name algorithm for the salted-session tests, sizing the drawn salt and driving OAEP (TPM 2.0 Library Part 1, Annex B.10.3/B.10.4).</summary>
    private const TpmAlgIdConstants TpmKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA public exponent the framework RSA key generator uses (the wire template's own "0" encodes this default, TPM 2.0 Library Part 2, Table 215).</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>
    /// Verifies a REAL, unbound/unsalted HMAC session at TPM2_GetTime()'s sign slot: a CORRECT authValue folded
    /// into the command HMAC attests, and a SECOND command over the SAME session also attests, adopting a
    /// genuinely rolled nonceTPM from its own response entry — a session's nonceTPM changes on every use, and
    /// the response HMAC that authenticates the entry (TPM 2.0 Library Part 1, clause 17.6.5, equation 17)
    /// verifies, and only then lets the session adopt the new value, solely when that entry is genuine (Part 3,
    /// clause 18.7).
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverUnboundHmacSignSessionWithCorrectAuthAttestsAndRollsNonceOnASecondCommand()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            signSession.SetAuthValue(SigningKeyPasswordBytes, pool);

            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

            using(TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool))
            using(GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
            {
                TpmResult<GetTimeResponse> firstResult = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                    tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(firstResult.IsSuccess, $"The first GetTime over a correctly-authorized HMAC sign session must succeed, but failed: '{firstResult.ResponseCode}'.");
                firstResult.Value.Dispose();
            }

            byte[] nonceTpmBeforeSecond = signSession.NonceTpm.ToArray();

            using(TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool))
            using(GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
            {
                TpmResult<GetTimeResponse> secondResult = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                    tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(secondResult.IsSuccess, $"A second command over the same session must still succeed, but failed: '{secondResult.ResponseCode}'.");
                secondResult.Value.Dispose();
            }

            Assert.IsFalse(
                signSession.NonceTpm.Span.SequenceEqual(nonceTpmBeforeSecond),
                "The session must adopt a genuinely rolled nonceTPM from its own response entry after the second command - proof the response HMAC was actually verified, not merely accepted.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The DA-charge half: a REAL HMAC sign session carrying a WRONG guess against a dictionary-attack-protected
    /// signing key fails the sign slot's command HMAC and charges <c>failedTries</c> exactly once — a
    /// session-encoded <c>TPM_RC_AUTH_FAIL</c> naming the sign slot (index 1, TPM 2.0 Library Part 2, clause
    /// 6.6.2), per Part 1, clause 17.8.7's OR: the entity being authorized is itself dictionary-attack protected.
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverHmacSignSessionWithWrongAuthOnDaProtectedSignerChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            signSession.SetAuthValue(WrongSigningKeyPasswordBytes, pool);

            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError,
                "A wrong guess against a dictionary-attack-protected signing key's real authValue must fail the sign slot's command HMAC with TPM_RC_AUTH_FAIL.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), result.ResponseCode,
                "The mismatch names the sign slot (index 1), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter + 1, after.Value.LockoutCounter,
            "A wrong sign-slot HMAC guess against a dictionary-attack-protected signing key must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 17.8.7).");
    }

    /// <summary>
    /// The NO_DA contrast: a REAL HMAC sign session carrying a WRONG guess against a <c>noDA</c> signing key
    /// answers a plain <c>TPM_RC_BAD_AUTH</c>, never the dictionary-attack-counted <c>TPM_RC_AUTH_FAIL</c> (TPM
    /// 2.0 Library Part 2, Table 233, bit 25), and the shared <c>failedTries</c> counter stays untouched. Still
    /// session-index-encoded to the sign slot (index 1, Part 2, clause 6.6.2).
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverHmacSignSessionWithWrongAuthOnNoDaSignerReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            signSession.SetAuthValue(WrongSigningKeyPasswordBytes, pool);

            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError, "A wrong guess against a noDA signing key must be a plain TPM_RC_BAD_AUTH, never the dictionary-attack-counted form.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), result.ResponseCode,
                "The mismatch still names the sign slot (index 1), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A noDA signing key's wrong guess must never move the dictionary-attack counter.");
    }

    /// <summary>
    /// A sign session BOUND TO THE SIGNING KEY ITSELF attests with no per-command authValue supplied: binding
    /// already incorporated the key's authValue into the session key (TPM 2.0 Library Part 1, clause 17.6.10,
    /// equation 20), so the command HMAC omits it (equations 21/22) — the bind-omission path.
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverSignSessionBoundToTheSigningKeyItselfAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        StartAuthSessionInput signStartInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(signer.ObjectHandle.Value, HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> signStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, signStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signStartResult.IsSuccess, $"StartAuthSession (bound to the signer) failed: '{signStartResult.ResponseCode}'.");

        StartAuthSessionResponse signStarted = signStartResult.Value;
        uint sessionHandle = signStarted.SessionHandle.Value;

        try
        {
            using TpmSession signSession = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), SigningKeyPasswordBytes, signStartInput.NonceCaller, signStarted.NonceTPM,
                HmacSessionAlg, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                result.IsSuccess,
                $"A sign session bound to the signing key itself must attest with the authValue folded into the bind, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A salted-and-bound session (RSA tpmKey) authorizing the privacy-administrator slot, bound DIRECTLY to
    /// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/>, attests: salting (TPM 2.0 Library Part 1, clause 17.6.12) and
    /// binding a HIERARCHY entity (clause 17.6.10) compose exactly as binding an object does — <c>@signHandle</c>
    /// stays a plain password (Part 3, clause 18.7, Table 99).
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverSaltedAndBoundEndorsementSessionAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;
        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        try
        {
            ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
            TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

            (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateBoundAndSaltedHmacSession(
                tpmKeyHandle, (uint)TpmRh.TPM_RH_ENDORSEMENT, modulus, DefaultRsaExponent, TpmKeyNameAlg, HmacSessionAlg,
                rsaBackend.EncryptOaep, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using(salt)
            {
                TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                    tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted-and-bound to the endorsement hierarchy) failed: '{startResult.ResponseCode}'.");
                StartAuthSessionResponse started = startResult.Value;
                uint sessionHandle = started.SessionHandle.Value;

                try
                {
                    using TpmSession privacyAdminSession = await TpmSession.CreateBoundAsync(
                        new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller, started.NonceTPM,
                        HmacSessionAlg, pool, symmetric: TpmtSymDef.Null, salt: salt.Memory[..saltLength], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                    privacyAdminSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

                    using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                    using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                    ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

                    TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                        tpm, getTimeInput, [privacyAdminSession, signAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"A salted-and-bound session authorizing the endorsement hierarchy must attest, but failed: '{result.ResponseCode}'.");
                    result.Value.Dispose();
                }
                finally
                {
                    await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_GetTime()</c> over MIXED sessions — a REAL HMAC session authorizing the privacy-administrator
    /// slot, a plain password authorizing the sign slot — succeeds: both slots require USER-role authorization
    /// (TPM 2.0 Library Part 3, clause 18.7, Table 99), and neither slot's session shape constrains the other's.
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverHmacPrivacyAdminAndPasswordSignSlotAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmSession privacyAdminSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);

            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminSession, signAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"GetTime (HMAC privacy-admin slot, password sign slot) failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The mirror composition to <see cref="GetTimeOverHmacPrivacyAdminAndPasswordSignSlotAttests"/>: a plain
    /// password authorizes the privacy-administrator slot, a REAL HMAC session authorizes the sign slot. Succeeds
    /// for the identical reason (TPM 2.0 Library Part 3, clause 18.7, Table 99).
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverPasswordPrivacyAdminAndHmacSignSlotAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);

            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"GetTime (password privacy-admin slot, HMAC sign slot) failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A single real HMAC session named in BOTH GetTime authorization slots is refused: "a specific HMAC or
    /// policy session handle can occur only once in the Authorization Area; TPM_RS_PW may repeat" (TPM 2.0
    /// Library Part 1, clause 16.6.3). Part 1 names no response code for the violation; the reference does, its
    /// <c>RetrieveSessionData</c> comparing each unmarshaled slot against every earlier one and answering
    /// <c>TPM_RCS_HANDLE + errorIndex</c>, so the refusal is a handle error naming the SECOND occurrence (index
    /// 1, TPM 2.0 Library Part 2, clause 6.6.2), the offending re-claim.
    /// </summary>
    [TestMethod]
    public async Task GetTimeWithTheSameRealSessionHandleInBothSlotsIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);

            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

            //The SAME session names both slots, so the wire's two TPMS_AUTH_COMMAND entries carry the identical
            //real sessionHandle - the exact composition clause 16.6.3 forbids.
            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [session, session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.BaseError, "A duplicated real session handle must be refused with TPM_RC_HANDLE.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1), result.ResponseCode,
                "The refusal names the SECOND occurrence (session index 1), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A real HMAC session claiming the AUDIT session attribute at GetTime's sign slot is refused with the
    /// session-encoded <c>TPM_RC_ATTRIBUTES</c>: this arm models no command audit
    /// (<c>ValidateSessionArea(auditIsSupported: false)</c>), so a session claiming audit is refused rather than
    /// accepted and echoed back auditing nothing (TPM 2.0 Library Part 3, clause 5.5; Part 2, clause 8.4, Table
    /// 40), encoded to the offending slot's index (clause 6.6.2). Audit is the attribute this gate refuses
    /// categorically, which is what makes it the one this test pins: the decrypt and encrypt attributes name the
    /// command's parameter-encryption gates and are admitted on their own terms.
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverSignSessionWithAuditAttributeReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            signSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError, "An audit-claiming session against a command this arm does not audit must be refused with TPM_RC_ATTRIBUTES.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), result.ResponseCode,
                "The refusal names the claiming session (sign slot, index 1), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The session arm's USER-role gate (TPM 2.0 Library Part 3, clause 5.6, check 7.1) for a userWithAuth-CLEAR
    /// signer runs before any sign-slot command HMAC is queued: a REAL, unbound/unsalted HMAC sign session
    /// carrying a WRONG guess still answers the BARE <c>TPM_RC_POLICY_FAIL</c>, never a session-encoded
    /// <c>TPM_RC_AUTH_FAIL</c>, and moves no dictionary-attack counter.
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverSessionWithUserWithAuthClearSignerAndWrongHmacSignSlotGuessReturnsPolicyFailNotAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse clearSigner = await CreateUserWithAuthClearSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, UserWithAuthClearSignerPassword).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            signSession.SetAuthValue(WrongSigningKeyPasswordBytes, pool);

            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(clearSigner.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), clearSigner.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_POLICY_FAIL, result.BaseError,
                "A wrong guess folded into a real sign session against a userWithAuth-CLEAR signer must still answer TPM_RC_POLICY_FAIL, never an auth failure.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode,
                "The refusal is the BARE constant, not the session-encoded form a genuine command-HMAC mismatch would carry - the gate runs before that verification is ever queued.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "TPM_RC_POLICY_FAIL is not TPM_RC_AUTH_FAIL, so the userWithAuth gate must move no counter, even though the guess was wrong.");
    }

    /// <summary>
    /// The session arm's sign slot carries the signing key's own DA/Lockout gate (TPM 2.0 Library Part 3, clause
    /// 5.6, check 3), answering before either sign-slot credential shape is evaluated: with the TPM in Lockout
    /// mode, a dictionary-attack-protected signing key answers the bare <c>TPM_RC_LOCKOUT</c> even though the
    /// sign slot's HMAC is genuinely correct and the privacy-administrator slot's password is correct too.
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverSessionWithDaProtectedSignerUnderLockoutReturnsLockout()
    {
        const uint SingleAttemptMaxTries = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, SingleAttemptMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        //A single wrong sign password over the all-password arm charges the DA-protected signer and, with
        //maxTries at one, enters Lockout mode as a side effect.
        using(TpmPasswordSession seedingPrivacyAdminAuth = TpmPasswordSession.CreateEmpty(pool))
        using(TpmPasswordSession seedingWrongSignAuth = TpmPasswordSession.Create(WrongSigningKeyPasswordBytes, pool))
        using(GetTimeInput seedingInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool))
        {
            TpmResult<GetTimeResponse> seedingResult = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, seedingInput, [seedingPrivacyAdminAuth, seedingWrongSignAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), seedingResult.ResponseCode,
                "The seeding mismatch must be a charged sign-slot auth failure at session index 1.");
        }

        //An unbound, unsalted HMAC session needs no authorization to start, so Lockout mode admits it (Part 3,
        //clause 11.1.1); the lockout answer must come from the sign slot's own gate instead.
        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            signSession.SetAuthValue(SigningKeyPasswordBytes, pool);

            using GetTimeInput provingInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, provingInput, [privacyAdminAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
                "A DA-protected signing key in Lockout mode must be refused before either sign-slot credential shape is evaluated, even with a correct HMAC (clause 5.6's check 3 precedes checks 7.1 and 9/10).");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A policy-session handle at GetTime's sign slot is a kind of authorization the session arm does not model
    /// yet, and is refused with the bare <c>TPM_RC_AUTH_TYPE</c>, never session-encoded (TPM 2.0 Library Part 3,
    /// clause 5.6, step 2 of the entry ladder).
    /// </summary>
    [TestMethod]
    public async Task GetTimeWithPolicySessionOnSignSlotReturnsAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPolicySession signSession = TpmPolicySession.ForSession(sessionHandle, HmacSessionAlg, pool);

            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                "A policy-session handle at a GetTime slot must be refused bare, never session-encoded - the session arm does not model this authorization kind.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A sign-slot session handle the simulator no longer has loaded is refused with the format-zero
    /// "session not loaded" warning for slot index 1, <c>TPM_RC_REFERENCE_S1</c> (TPM 2.0 Library Part 2, clause
    /// 6.6.2): the session is started, then flushed, then its (now stale) handle is offered at the sign slot.
    /// </summary>
    [TestMethod]
    public async Task GetTimeWithUnloadedSignSessionHandleReturnsReferenceS1()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using TpmSession staleSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);

        //Flushing removes the handle from the simulator's loaded-session table, but the client-side TpmSession
        //still carries its cached key material and can still frame a wire request naming that handle - the
        //composition an "unloaded session" negative exercises.
        await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);

        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

        TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
            tpm, getTimeInput, [privacyAdminAuth, staleSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S1, result.ResponseCode,
            "A sign-slot session handle the simulator no longer has loaded must be refused with the session-not-loaded warning for slot index 1.");
    }

    /// <summary>
    /// Pool-balance regression over the over-session composition: a REFUSED GetTime (wrong sign-slot HMAC guess)
    /// and a SUCCESSFUL GetTime (correct sign-slot HMAC guess) each return every pooled carrier they rented — the
    /// supplied non-empty authValue carriers included — proving neither the refusing arm nor the completing arm
    /// orphans a rental (TPM 2.0 Library Part 3, clause 18.7).
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverSessionPoolBalanceReturnsEveryRentedCarrierInRefusedAndSuccessfulAreas()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse signer = await CreatePasswordProtectedSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, SigningKeyPassword).ConfigureAwait(false);

        long refusedBaseline = trackingPool.OutstandingCount;
        {
            (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

            try
            {
                using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
                using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, trackingPool.Pool);
                signSession.SetAuthValue(WrongSigningKeyPasswordBytes, trackingPool.Pool);

                Assert.IsGreaterThan(
                    refusedBaseline, trackingPool.OutstandingCount,
                    "The wrong non-empty authValue carrier must be a live rental, or the balance check below is vacuous.");

                using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
                ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

                TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                    tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsTpmError, "A wrong sign-slot HMAC guess must be refused.");
                Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), result.ResponseCode);
            }
            finally
            {
                await FlushHandleAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            }
        }

        Assert.AreEqual(
            refusedBaseline, trackingPool.OutstandingCount,
            "The refused area must return every rented carrier, the supplied wrong authValue included.");

        long successBaseline = trackingPool.OutstandingCount;
        {
            (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

            try
            {
                using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
                using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, trackingPool.Pool);
                signSession.SetAuthValue(SigningKeyPasswordBytes, trackingPool.Pool);

                Assert.IsGreaterThan(
                    successBaseline, trackingPool.OutstandingCount,
                    "The correct non-empty authValue carrier must be a live rental, or the balance check below is vacuous.");

                using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(signer.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
                ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), signer.Name.Span.ToArray()];

                TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                    tpm, getTimeInput, [privacyAdminAuth, signSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"GetTime with the correct sign-slot HMAC guess must succeed, but failed: '{result.ResponseCode}'.");
                result.Value.Dispose();
            }
            finally
            {
                await FlushHandleAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            }
        }

        Assert.AreEqual(
            successBaseline, trackingPool.OutstandingCount,
            "The completed attestation must return every rented carrier, the supplied correct authValue included.");
    }

    /// <summary>
    /// The privacy-administrator slot over a session BOUND DIRECTLY to <see cref="TpmRh.TPM_RH_ENDORSEMENT"/>
    /// carrying its CORRECT, rotated authValue attests via bind-omission (TPM 2.0 Library Part 1, clause
    /// 17.6.10, equation 20): the endorsement hierarchy's authValue is folded into the session key at bind time,
    /// so the per-command HMAC omits it.
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverEndorsementBoundHmacSessionWithCorrectAuthAttests()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        //The AK is created before the rotation, while the endorsement hierarchy still carries its factory-empty
        //authorization value, so TPM2_CreatePrimary()'s own hierarchy slot authorizes.
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<HierarchyChangeAuthResponse> rotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, EndorsementHierarchyPasswordBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotation.IsSuccess, $"Installing the endorsement hierarchy's authorization value failed: '{rotation.ResponseCode}'.");

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession((uint)TpmRh.TPM_RH_ENDORSEMENT, HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to the endorsement hierarchy) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession privacyAdminSession = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), EndorsementHierarchyPasswordBytes, startInput.NonceCaller, started.NonceTPM,
                HmacSessionAlg, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            privacyAdminSession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), ak.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminSession, signAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A session bound to the endorsement hierarchy with its correct authValue must attest, but failed: '{result.ResponseCode}'.");

            using GetTimeResponse getTime = result.Value;
            await AssertTimeAttestationAsync(getTime, ak, pool).ConfigureAwait(false);
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A WRONG endorsement hierarchy authValue proven over an UNBOUND HMAC session at the privacy-administrator
    /// slot answers a session-encoded <c>TPM_RC_BAD_AUTH</c>, UNCHARGED: permanent hierarchies other than
    /// <c>lockoutAuth</c> are dictionary-attack exempt (TPM 2.0 Library Part 1, clause 17.8.1), so the mismatch
    /// never reaches <c>failedTries</c>, unlike the sign slot's own DA-protected key.
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverHmacPrivacyAdminSessionWithWrongEndorsementAuthReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        TpmResult<HierarchyChangeAuthResponse> rotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, EndorsementHierarchyPasswordBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotation.IsSuccess, $"Installing the endorsement hierarchy's authorization value failed: '{rotation.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmSession privacyAdminSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            privacyAdminSession.SetAuthValue(WrongEndorsementHierarchyPasswordBytes, pool);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), ak.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminSession, signAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
                "A wrong endorsement hierarchy authValue proven over an HMAC session must fail the privacy-admin slot's command HMAC with TPM_RC_BAD_AUTH: permanent hierarchies other than lockoutAuth are dictionary-attack exempt (TPM 2.0 Library Part 1, clause 17.8.1).");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                "The mismatch names the privacy-admin slot (index 0), so the wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A wrong endorsement hierarchy authValue must never move the dictionary-attack counter: permanent entities other than lockoutAuth are dictionary-attack exempt.");
    }

    /// <summary>
    /// A DISABLED endorsement hierarchy is refused with <c>TPM_RC_HIERARCHY</c> before any credential is
    /// compared: "no authorization method... will be permitted" while a hierarchy's enable is CLEAR (TPM 2.0
    /// Library Part 1, clause 11.2, Table 5), so the enable gate precedes the authValue availability gate and
    /// the compare/HMAC-queue steps entirely.
    /// </summary>
    [TestMethod]
    public async Task GetTimeOverSessionWithEndorsementHierarchyDisabledReturnsHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        //The signing key is created under the OWNER hierarchy, not endorsement: disabling a hierarchy flushes the
        //transient objects created under it, so an endorsement-hierarchy AK would be evicted by the disable below
        //and the command would fail its signer-presence check (TPM_RC_HANDLE) before ever reaching the
        //privacy-administrator slot's enable gate. An owner key survives, so the endorsement enable gate on the
        //fixed privacyAdminHandle slot is what answers — which is exactly the gate under test.
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<HierarchyControlResponse> disable = await tpm.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_ENDORSEMENT, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disable.IsSuccess, $"Disabling the endorsement hierarchy failed: '{disable.ResponseCode}'.");

        (uint sessionHandle, StartAuthSessionResponse started) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        try
        {
            using TpmSession privacyAdminSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);

            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(ak.ObjectHandle, Nonce.Memory.Span, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [EndorsementHandleBytes(), ak.Name.Span.ToArray()];

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [privacyAdminSession, signAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HIERARCHY, result.ResponseCode,
                "A disabled endorsement hierarchy must be refused before any credential is compared - the enable gate precedes the authValue availability and compare gates.");
        }
        finally
        {
            await FlushHandleAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>The 4-octet big-endian wire form of <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> — the privacy-administrator slot's cpHash handle-Name term (TPM 2.0 Library Part 1, clause 16.7, equation 15).</summary>
    private static byte[] EndorsementHandleBytes()
    {
        byte[] bytes = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)TpmRh.TPM_RH_ENDORSEMENT);

        return bytes;
    }

    /// <summary>Extends <see cref="CreateRegistry"/> with the StartAuthSession/FlushContext/HierarchyControl codecs the over-session tests need.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateHmacArmRegistry()
    {
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl);

        return registry;
    }

    /// <summary>Flushes a session or object handle, ignoring the result — the standard cleanup for a real HMAC/policy session or a salting key this file starts.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private static async Task FlushHandleAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>Starts a fresh, unbound, unsalted HMAC session; the caller composes the <see cref="TpmSession"/> from the result and owns its cleanup.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the StartAuthSession response (ownership of its NonceTPM transfers into whichever <see cref="TpmSession"/> the caller constructs from it).</returns>
    private async Task<(uint SessionHandle, StartAuthSessionResponse Started)> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;

        return (started.SessionHandle.Value, started);
    }

    /// <summary>Creates the standard RSA endorsement-key-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) used as a salted session's RSA tpmKey.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }
}
