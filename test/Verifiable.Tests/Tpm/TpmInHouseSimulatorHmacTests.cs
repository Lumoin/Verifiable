using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for the one-shot <c>TPM2_HMAC()</c> command against a loaded KEYEDHASH HMAC key (TPM 2.0
/// Library Part 3, clause 15.5, Tables 71 and 72). The positive cases key the simulator's HMAC seam with the
/// published RFC 4231 test-vector keys and assert the returned <c>outHMAC</c> equals the published value, so the
/// oracle is the specification's own vector, independent of the implementation under test. The refusal cases
/// cover the key-shape ladder, the USER-role authorization ladder with its dictionary-attack accounting, and the
/// single-password-session wire form.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorHmacTests
{
    /// <summary>The MSTest-provided per-test context, its cancellation token observed across every exchange.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The lowered <c>maxTries</c> the lockout cases use to reach Lockout mode quickly.</summary>
    private const uint LockoutTestMaxTries = 2;

    /// <summary>RFC 4231 test case 1 key: 20 octets of 0x0b.</summary>
    private static readonly byte[] Rfc4231Case1Key = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    /// <summary>RFC 4231 test case 1 data: "Hi There".</summary>
    private static readonly byte[] Rfc4231Case1Data = Convert.FromHexString("4869205468657265");

    /// <summary>RFC 4231 test case 1 published HMAC-SHA-256.</summary>
    private static readonly byte[] Rfc4231Case1Sha256 = Convert.FromHexString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /// <summary>RFC 4231 test case 2 key: "Jefe".</summary>
    private static readonly byte[] Rfc4231Case2Key = Convert.FromHexString("4a656665");

    /// <summary>RFC 4231 test case 2 data: "what do ya want for nothing?".</summary>
    private static readonly byte[] Rfc4231Case2Data = Convert.FromHexString("7768617420646f2079612077616e7420666f72206e6f7468696e673f");

    /// <summary>RFC 4231 test case 3 key: 20 octets of 0xaa.</summary>
    private static readonly byte[] Rfc4231Case3Key = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    /// <summary>RFC 4231 test case 3 data: 50 octets of 0xdd.</summary>
    private static readonly byte[] Rfc4231Case3Data = Convert.FromHexString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    /// <summary>A key authorization value the authorization-ladder cases install.</summary>
    private static readonly byte[] KeyPassword = "hmac-key-auth"u8.ToArray();

    /// <summary>A value that is not the key's authorization value.</summary>
    private static readonly byte[] WrongKeyPassword = "hmac-key-wrong"u8.ToArray();

    /// <summary>A short secret sealed by the sealed-data fixture in <see cref="HmacOverASealedDataObjectIsRefusedWithKey"/>, arbitrary and not tied to any published vector.</summary>
    private static readonly byte[] SealedSecretBytes = [1, 2, 3, 4];

    /// <summary>
    /// <c>TPM2_HMAC()</c> over an HMAC key holding RFC 4231 test case 1's key, with the hash algorithm named
    /// explicitly, returns the published HMAC-SHA-256 value
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.2">RFC 4231, section 4.2</see>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverRfc4231Case1WithSha256ReturnsThePublishedValue()
    {
        await AssertHmacAsync(Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, Rfc4231Case1Sha256).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> with <c>hashAlg = TPM_ALG_NULL</c> selects the key's own scheme hash (Table 79's
    /// "hashAlg TPM_ALG_NULL" row) and returns the same published HMAC-SHA-256 value as the explicit form.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.5, Table 79</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacOverRfc4231Case1WithNullHashSelectsTheKeyDefault()
    {
        await AssertHmacAsync(Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_NULL, Rfc4231Case1Sha256).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> over RFC 4231 test case 2 (a key shorter than the digest) returns the published
    /// HMAC-SHA-256 value (<see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.3">RFC 4231, section 4.3</see>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverRfc4231Case2WithSha256ReturnsThePublishedValue()
    {
        byte[] expected = Convert.FromHexString("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        await AssertHmacAsync(Rfc4231Case2Key, TpmAlgIdConstants.TPM_ALG_SHA256, Rfc4231Case2Data, TpmAlgIdConstants.TPM_ALG_SHA256, expected).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> over RFC 4231 test case 3 (50 octets of data) returns the published HMAC-SHA-256 value
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.4">RFC 4231, section 4.4</see>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverRfc4231Case3WithSha256ReturnsThePublishedValue()
    {
        byte[] expected = Convert.FromHexString("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        await AssertHmacAsync(Rfc4231Case3Key, TpmAlgIdConstants.TPM_ALG_SHA256, Rfc4231Case3Data, TpmAlgIdConstants.TPM_ALG_SHA256, expected).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> over an SHA-384 HMAC key returns the published HMAC-SHA-384 value for RFC 4231 test case
    /// 1 (<see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.2">RFC 4231, section 4.2</see>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverRfc4231Case1WithSha384ReturnsThePublishedValue()
    {
        byte[] expected = Convert.FromHexString("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
        await AssertHmacAsync(Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA384, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA384, expected).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> over an SHA-512 HMAC key returns the published HMAC-SHA-512 value for RFC 4231 test case
    /// 1 (<see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.2">RFC 4231, section 4.2</see>).
    /// </summary>
    [TestMethod]
    public async Task HmacOverRfc4231Case1WithSha512ReturnsThePublishedValue()
    {
        byte[] expected = Convert.FromHexString("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
        await AssertHmacAsync(Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA512, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA512, expected).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> with a <c>hashAlg</c> that is neither <c>TPM_ALG_NULL</c> nor the key's own scheme hash
    /// is refused with <c>TPM_RC_VALUE</c> (Table 79's error row: "error (TPM_RC_VALUE) if hashAlg != handle
    /// scheme").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.5, Table 79</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacWithAMismatchedHashAlgIsRefusedWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacWithAMismatchedHashAlgIsRefusedWithValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA384, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode, "TPM2_HMAC() with a hashAlg other than the key's scheme hash must be refused with TPM_RC_VALUE.");
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> over a handle that names an asymmetric key rather than a KEYEDHASH object is refused
    /// with <c>TPM_RC_TYPE</c> ("If the key type is not TPM_ALG_KEYEDHASH then the TPM shall return
    /// TPM_RC_TYPE").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacOverAnAsymmetricKeyHandleIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAnAsymmetricKeyHandleIsRefusedWithType), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_TYPE, result.ResponseCode, "TPM2_HMAC() over an asymmetric key handle must be refused with TPM_RC_TYPE.");
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> over an open sequence handle is refused with <c>TPM_RC_TYPE</c>: a sequence object is
    /// not a KEYEDHASH key ("If the key type is not TPM_ALG_KEYEDHASH then the TPM shall return TPM_RC_TYPE").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacOverASequenceHandleIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverASequenceHandleIsRefusedWithType), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        TpmResult<HmacStartResponse> started = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(started.IsSuccess, $"TPM2_HMAC_Start() failed: '{started.ResponseCode}'.");

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, started.Value.SequenceHandle.Value, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_TYPE, result.ResponseCode, "TPM2_HMAC() over a sequence handle must be refused with TPM_RC_TYPE.");
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> over a sealed data object (a KEYEDHASH object whose sign attribute is CLEAR) is refused
    /// with <c>TPM_RC_KEY</c> ("If the sign attribute is not SET in the key referenced by handle, then the TPM
    /// shall return TPM_RC_KEY").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacOverASealedDataObjectIsRefusedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverASealedDataObjectIsRefusedWithKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint sealedHandle, _) = await PolicySweepHarness.SealAndLoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SealedSecretBytes, ReadOnlyMemory<byte>.Empty, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, sealedHandle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "TPM2_HMAC() over a sealed data object must be refused with TPM_RC_KEY.");
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> over a restricted KEYEDHASH key is refused with <c>TPM_RC_ATTRIBUTES</c> ("If the key
    /// referenced by handle has the restricted attribute SET, the TPM shall return TPM_RC_ATTRIBUTES").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacOverARestrictedKeyIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverARestrictedKeyIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint restrictedHandle = await LoadGeneratedRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value, isNoDa: true, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, restrictedHandle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "TPM2_HMAC() over a restricted KEYEDHASH key must be refused with TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// <c>TPM2_HMAC()</c> over a handle that names no loaded object is refused with <c>TPM_RC_HANDLE</c> — the
    /// handle-area validation every command runs before its parameters are read (Part 3, clause 5.4; Part 2,
    /// Table 18: "the handle is not correct for the use").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4; Part 2, clause 6.6.3, Table 18</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacOverAnUnloadedHandleIsRefusedWithHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAnUnloadedHandleIsRefusedWithHandle), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, 0x80FFFFFFu, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode, "TPM2_HMAC() over an unloaded handle must be refused with TPM_RC_HANDLE.");
    }

    /// <summary>
    /// "The caller shall provide proper authorization for use of handle": <c>TPM2_HMAC()</c> over a key created
    /// with a non-empty authorization value succeeds when that value is presented in the password session, and
    /// returns the published RFC 4231 test case 1 value, so the authorization gate admits exactly the installed
    /// password.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.5.1; Part 1, clause 16.6.4</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacWithTheCorrectPasswordSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacWithTheCorrectPasswordSucceeds), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, KeyPassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() with the key's password failed: '{result.ResponseCode}'.");
        using HmacResponse response = result.Value;

        Assert.IsTrue(response.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The password-authorized HMAC must equal the published RFC 4231 value.");
    }

    /// <summary>
    /// A wrong password against a DA-protected HMAC key (<c>noDA</c> CLEAR) is refused with the
    /// session-index-encoded <c>TPM_RC_AUTH_FAIL</c> and charges <c>failedTries</c> exactly once (Part 3, clause
    /// 5.6, check 10; Part 1, clause 16.8.2), and the key is not used.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6; Part 1, clause 16.8.2; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacWithAWrongPasswordOnADaProtectedKeyIsAuthFailAndCharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacWithAWrongPasswordOnADaProtectedKeyIsAuthFailAndCharged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, WrongKeyPassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode, "A wrong password on a DA-protected key must be refused with the session-encoded TPM_RC_AUTH_FAIL.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "A wrong password against a DA-protected key must charge failedTries exactly once.");
    }

    /// <summary>
    /// A wrong password against a <c>noDA</c> HMAC key is refused with the session-index-encoded
    /// <c>TPM_RC_BAD_AUTH</c> and moves no dictionary-attack counter — only a DA-protected authValue's failure is
    /// ever charged (Part 1, clause 16.8.3).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.3; Part 3, clause 5.6, check 10</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacWithAWrongPasswordOnANoDaKeyIsBadAuthAndUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacWithAWrongPasswordOnANoDaKeyIsBadAuthAndUncharged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, WrongKeyPassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode, "A wrong password on a noDA key must be refused with the session-encoded TPM_RC_BAD_AUTH.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A wrong password against a noDA key must not move failedTries.");
    }

    /// <summary>
    /// A key whose <c>userWithAuth</c> attribute is CLEAR may have its USER role authorized only by a policy
    /// session, so a password session at <c>TPM2_HMAC()</c> is refused with <c>TPM_RC_POLICY_FAIL</c> before any
    /// password is compared (Part 3, clause 5.6, check 7.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6, check 7.1; Part 2, clause 8.3.3.6</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacOverAUserWithAuthClearKeyIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAUserWithAuthClearKeyIsRefusedWithPolicyFail), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, isUserWithAuth: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode, "A password session against a userWithAuth-CLEAR key must be refused with TPM_RC_POLICY_FAIL.");
    }

    /// <summary>
    /// The <c>userWithAuth</c> check precedes the command's own key-shape checks (Part 3, clause 5.6, check 7.1,
    /// runs before the detailed actions of clause 15.5): a password session over a RESTRICTED key whose
    /// <c>userWithAuth</c> is CLEAR answers <c>TPM_RC_POLICY_FAIL</c>, not the <c>TPM_RC_ATTRIBUTES</c> the key's
    /// shape would otherwise earn.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.6 (check 7.1) and 15.5.1; Part 2, clause 8.3.3.6</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacOverAUserWithAuthClearRestrictedKeyAnswersPolicyFailBeforeAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacOverAUserWithAuthClearRestrictedKeyAnswersPolicyFailBeforeAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint restrictedHandle = await LoadGeneratedRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value, isNoDa: true, ReadOnlyMemory<byte>.Empty, isUserWithAuth: false).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, restrictedHandle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, result.ResponseCode, "The userWithAuth gate must answer before the restricted-key gate.");
    }

    /// <summary>
    /// "While in Lockout mode, any use of a DA-protected authValue will return TPM_RC_LOCKOUT": once
    /// <c>failedTries</c> reaches <c>maxTries</c>, <c>TPM2_HMAC()</c> with the CORRECT password over a
    /// DA-protected key is refused with the bare <c>TPM_RC_LOCKOUT</c> and moves the counter no further, while a
    /// <c>noDA</c> key still produces the published value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.3; Part 3, clause 5.6, check 3</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacInLockoutIsRefusedForADaProtectedKeyAndAdmittedForANoDaKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacInLockoutIsRefusedForADaProtectedKeyAndAdmittedForANoDaKey), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey daKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey noDaKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await EnterLockoutAsync(tpm, registry, pool, daKey.Handle).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> lockedOut = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> refused = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, daKey.Handle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, KeyPassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, refused.ResponseCode, "A locked-out TPM must refuse even a correct-password TPM2_HMAC() over a DA-protected key with the bare TPM_RC_LOCKOUT.");

        TpmResult<TpmDictionaryAttackParameters> afterRefusal = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(lockedOut.Value.LockoutCounter, afterRefusal.Value.LockoutCounter, "A LOCKOUT refusal must never move failedTries further.");

        TpmResult<HmacResponse> admitted = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, noDaKey.Handle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, KeyPassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(admitted.IsSuccess, $"A noDA key must stay usable in Lockout mode, but TPM2_HMAC() failed: '{admitted.ResponseCode}'.");
        using HmacResponse response = admitted.Value;
        Assert.IsTrue(response.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The noDA key's HMAC must equal the published RFC 4231 value.");
    }

    /// <summary>
    /// The authorization checks precede the command's own key-shape checks (Part 3, clause 5.6 runs before the
    /// detailed actions of clause 15.5): in Lockout mode, <c>TPM2_HMAC()</c> over a RESTRICTED DA-protected key
    /// answers <c>TPM_RC_LOCKOUT</c>, not the <c>TPM_RC_ATTRIBUTES</c> the key's shape would otherwise earn.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.6 and 15.5.1; Part 1, clause 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacInLockoutOverARestrictedDaProtectedKeyAnswersLockoutBeforeAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacInLockoutOverARestrictedDaProtectedKeyAnswersLockoutBeforeAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey daKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        uint restrictedHandle = await LoadGeneratedRestrictedHmacKeyAsync(tpm, registry, pool, parent.ObjectHandle.Value, isNoDa: false, KeyPassword).ConfigureAwait(false);

        await EnterLockoutAsync(tpm, registry, pool, daKey.Handle).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, restrictedHandle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, KeyPassword, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode, "In Lockout mode the DA gate must answer before the restricted-key gate.");
    }

    /// <summary>
    /// The authorization checks precede the command's own parameter checks: a wrong password over a DA-protected
    /// key is refused with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> and charged even when the request's
    /// <c>hashAlg</c> does not match the key — the mismatch's <c>TPM_RC_VALUE</c> (Table 79) is never reached.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.6 and 15.5, Table 79; Part 1, clause 16.8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacWithAWrongPasswordAndAMismatchedHashAlgIsAuthFailAndCharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacWithAWrongPasswordAndAMismatchedHashAlgIsAuthFailAndCharged), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, userAuth: KeyPassword, isNoDa: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, key.Handle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA384, WrongKeyPassword, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode, "The password compare must answer before the hashAlg selection.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "The failed compare must charge failedTries even though the parameters were also wrong.");
    }

    /// <summary>
    /// Table 71's <c>@handle</c> requires an authorization session: a <c>TPM_ST_NO_SESSIONS</c> frame is refused
    /// with <c>TPM_RC_AUTH_MISSING</c> (Part 3, clause 5.5: "An authorization session is present for each of the
    /// handles with the '@' decoration").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, Table 71</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacFramedWithoutSessionsIsRefusedWithAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacFramedWithoutSessionsIsRefusedWithAuthMissing), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants code = await SubmitHmacFramedAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, key.Handle, [], Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, code, "A TPM2_HMAC() frame without an authorization area must be refused with TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// A session-shaped handle at the key's slot that names no loaded session is refused with
    /// <c>TPM_RC_REFERENCE_S0</c> ("the handle in the indicated position refers to an entity that is not
    /// present", Part 2, Table 18): the slot is resolved as any session would be (Part 3, clause 5.5, step 4),
    /// so a well-typed-but-absent handle is a missing reference, not a type error. A real HMAC or policy session
    /// authorizes <c>TPM2_HMAC()</c> through the session forms.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.3, Table 18; Part 3, clause 5.5, step 4</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacFramedWithASessionHandleNamingNoLoadedSessionIsRefusedWithReferenceS0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacFramedWithASessionHandleNamingNoLoadedSessionIsRefusedWithReferenceS0), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        const uint HmacSessionShapedHandle = 0x02000000u;
        TpmRcConstants code = await SubmitHmacFramedAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, key.Handle, [HmacSessionShapedHandle], Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_S0, code, "A session-shaped handle naming no loaded session must be refused with TPM_RC_REFERENCE_S0.");
    }

    /// <summary>
    /// Table 71 carries exactly one <c>@</c> handle, so an authorization area holding a second session is a
    /// structure of the wrong size: refused with <c>TPM_RC_AUTHSIZE</c> ("authorizationSize is out of range or
    /// greater than required", Part 2, Table 18).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.3, Table 18; Part 3, clause 5.5, Table 71</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacFramedWithTwoSessionsIsRefusedWithAuthSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(HmacFramedWithTwoSessionsIsRefusedWithAuthSize), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants code = await SubmitHmacFramedAsync(
            simulator, pool, (ushort)TpmStConstants.TPM_ST_SESSIONS, key.Handle, [(uint)TpmRh.TPM_RH_PW, (uint)TpmRh.TPM_RH_PW], Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTHSIZE, code, "Two sessions for a single @ handle must be refused with TPM_RC_AUTHSIZE.");
    }

    /// <summary>
    /// Creates a loadable HMAC key from <paramref name="key"/>, computes <c>TPM2_HMAC()</c> over
    /// <paramref name="data"/> with <paramref name="requestHashAlg"/>, and asserts the returned <c>outHMAC</c>
    /// equals <paramref name="expected"/>.
    /// </summary>
    /// <param name="key">The HMAC key value.</param>
    /// <param name="keyHashAlg">The key's scheme hash algorithm.</param>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="requestHashAlg">The requested hash algorithm on the command (may be <c>TPM_ALG_NULL</c>).</param>
    /// <param name="expected">The published HMAC value.</param>
    /// <returns>A task that completes once the assertion has run.</returns>
    private async Task AssertHmacAsync(byte[] key, TpmAlgIdConstants keyHashAlg, byte[] data, TpmAlgIdConstants requestHashAlg, byte[] expected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync("hmac-kat", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey loadedKey = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, key, keyHashAlg, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, loadedKey.Handle, data, requestHashAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() failed: '{result.ResponseCode}'.");
        using HmacResponse response = result.Value;

        bool matches = response.OutHmac.AsReadOnlySpan().SequenceEqual(expected);
        Assert.IsTrue(matches, "The returned outHMAC must equal the published RFC 4231 test vector.");
    }

    /// <summary>
    /// Creates and loads a restricted HMAC key whose sensitive value the TPM generates (sensitiveDataOrigin SET),
    /// the shape that is creatable but unusable by <c>TPM2_HMAC()</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="isNoDa">Whether the key is exempt from dictionary-attack protection.</param>
    /// <param name="userAuth">The key's authorization value.</param>
    /// <param name="isUserWithAuth">Whether the template sets <c>userWithAuth</c>, admitting a password session for the USER role.</param>
    /// <returns>The loaded restricted HMAC key handle.</returns>
    private async Task<uint> LoadGeneratedRestrictedHmacKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, bool isNoDa, ReadOnlyMemory<byte> userAuth, bool isUserWithAuth = true)
    {
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
            tpm, registry, pool, parentHandle, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
            isRestricted: true, isSensitiveDataOrigin: true, userAuth: userAuth, isNoDa: isNoDa, isUserWithAuth: isUserWithAuth, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (restricted HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parentHandle, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (restricted HMAC key) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        return loaded.ObjectHandle.Value;
    }

    /// <summary>
    /// Drives the TPM into Lockout mode: lowers <c>maxTries</c> and fails the key's password that many times.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="daKeyHandle">A loaded DA-protected HMAC key to fail against.</param>
    /// <returns>A task that completes once Lockout mode has been asserted.</returns>
    private async Task EnterLockoutAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint daKeyHandle)
    {
        TpmResult<DictionaryAttackParametersResponse> lowered = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LockoutTestMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowered.IsSuccess, $"Lowering maxTries failed: '{lowered.ResponseCode}'.");

        for(uint attempt = 1; attempt <= LockoutTestMaxTries; attempt++)
        {
            TpmResult<HmacResponse> wrong = await HmacKeyHarness.HmacAsync(
                tpm, registry, pool, daKeyHandle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, WrongKeyPassword, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(wrong.IsSuccess, $"Attempt {attempt} of {LockoutTestMaxTries} with a wrong password must fail.");
        }

        TpmResult<TpmDictionaryAttackParameters> state = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(state.IsSuccess, $"GetDictionaryAttackParameters failed: '{state.ResponseCode}'.");
        Assert.IsTrue(state.Value.IsLockedOut, "The TPM must be in Lockout mode before the locked-out cases run.");
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_HMAC()</c> whose authorization area the typed input cannot express — the header,
    /// the key handle, one session block per entry of <paramref name="sessionHandles"/> (each with an empty nonce,
    /// <c>continueSession</c>, and an empty hmac), then the parameters (<c>buffer</c> as a <c>TPM2B_MAX_BUFFER</c>
    /// then <c>hashAlg</c>) — submits it, and returns the response code.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="keyHandle">The <c>@handle</c> value.</param>
    /// <param name="sessionHandles">The session handles to frame; empty for no authorization area.</param>
    /// <param name="buffer">The data to authenticate.</param>
    /// <param name="hashAlg">The requested hash algorithm.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitHmacFramedAsync(
        TpmSimulator simulator, BaseMemoryPool pool, ushort tag, uint keyHandle, uint[] sessionHandles, ReadOnlyMemory<byte> buffer, TpmAlgIdConstants hashAlg)
    {
        const int SessionBlockSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        int authorizationSize = sessionHandles.Length * SessionBlockSize;
        int parametersSize = sizeof(ushort) + buffer.Length + sizeof(ushort);
        int length = TpmHeader.HeaderSize + sizeof(uint) + (sessionHandles.Length > 0 ? sizeof(uint) + authorizationSize : 0) + parametersSize;
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader(tag, (uint)length, (uint)TpmCcConstants.TPM_CC_HMAC);
        header.WriteTo(ref writer);
        writer.WriteUInt32(keyHandle);
        if(sessionHandles.Length > 0)
        {
            writer.WriteUInt32((uint)authorizationSize);
            foreach(uint sessionHandle in sessionHandles)
            {
                writer.WriteUInt32(sessionHandle);
                writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
                writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            }
        }

        writer.WriteTpm2b(buffer.Span);
        writer.WriteUInt16((ushort)hashAlg);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed TPM2_HMAC() must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }
}
