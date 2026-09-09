using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
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
/// Drives <c>TPM2_ObjectChangeAuth()</c> against the in-house behavioural <see cref="TpmSimulator"/> over the
/// production command path (<see cref="TpmCommandExecutor"/> with <see cref="ObjectChangeAuthInput"/> and the
/// real codecs): a sealed data object or an HMAC key created under an elliptic-curve storage parent and loaded
/// is given a new authorization value, the returned private area is reloaded under the same parent and used with
/// the new value, and every refusal row of the ADMIN-role ladder, the parent judgment and the wire shape is
/// pinned (TPM 2.0 Library Part 3, clause 12.8; Part 3, clause 5.6; Part 1, clause 16.2).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorObjectChangeAuthTests
{
    /// <summary>The Name and session hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width of <see cref="SessionAlg"/>.</summary>
    private const int DigestSize = 32;

    /// <summary>The secret the sealed data objects carry.</summary>
    private static byte[] SecretBytes { get; } = "Rewrap this secret under a new authorization value."u8.ToArray();

    /// <summary>The authorization value the objects are created with.</summary>
    private static byte[] OriginalAuth { get; } = "original-object-auth"u8.ToArray();

    /// <summary>The replacement authorization value the command installs.</summary>
    private static byte[] NewAuth { get; } = "replacement-object-auth"u8.ToArray();

    /// <summary>A value distinct from both <see cref="OriginalAuth"/> and <see cref="NewAuth"/>.</summary>
    private static byte[] WrongAuth { get; } = [0x9A, 0x9B, 0x9C, 0x9D];

    /// <summary>RFC 4231 test case 1's 20-octet key, the value an HMAC key under test carries.</summary>
    private static byte[] Rfc4231Case1Key { get; } = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    /// <summary>RFC 4231 test case 1's data, "Hi There".</summary>
    private static byte[] Rfc4231Case1Data { get; } = Convert.FromHexString("4869205468657265");

    /// <summary>RFC 4231 test case 1's published HMAC-SHA-256 tag.</summary>
    private static byte[] Rfc4231Case1Sha256 { get; } = Convert.FromHexString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /// <summary>The attribute word of an ordinary bound sealed object exempt from dictionary-attack protection.</summary>
    private const TpmaObject NoDaSealedAttributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA;

    /// <summary>The attribute word of an ordinary bound sealed object under dictionary-attack protection.</summary>
    private const TpmaObject DaProtectedSealedAttributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.USER_WITH_AUTH;

    /// <summary>A transient handle value naming no loaded object in a freshly operational simulator.</summary>
    private const uint UnloadedTransientHandle = 0x8000_00FD;

    /// <summary>A second transient handle value naming no loaded object.</summary>
    private const uint UnloadedParentHandle = 0x8000_00FE;

    /// <summary>The <c>TPMS_AUTH_COMMAND</c> block of an empty <c>TPM_RS_PW</c> session: handle, empty nonce, attributes, empty hmac.</summary>
    private const int PasswordSessionBlockSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "If successful, a new private area for the TPM-resident object associated with objectHandle is returned,
    /// which includes the new authorization value" and "The returned outPrivate will need to be loaded before the
    /// new authorization will apply": the returned area loads under the same parent with the unchanged public
    /// area to the same Name, and the reloaded object unseals with the new value and refuses the old one. The
    /// private area keeps the creation wrap's width — the authorization value padded to its maximum size (TPM 2.0
    /// Library Part 2, clause 12.3.7), so the blob's length leaks nothing about the value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthReturnsAPrivateAreaThatReloadsWithTheNewAuthorizationValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthReturnsAPrivateAreaThatReloadsWithTheNewAuthorizationValue), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, DaProtectedSealedAttributes).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ObjectChangeAuth() with the object's password must succeed (Part 3, clause 12.8), but failed: '{result.ResponseCode}'.");

        using ObjectChangeAuthResponse response = result.Value;
        Assert.IsFalse(response.OutPrivate.IsEmpty, "The response must carry a new private area (Part 3, clause 12.8, Table 33).");
        Assert.AreEqual(
            sealedObject.CreatedPrivateLength, response.OutPrivate.Length,
            "The new private area keeps the creation wrap's width: a 32-octet integrity digest, a 16-octet IV, and a sensitive area whose authValue is padded to its 64-octet maximum (Part 1, Clause 19; Part 2, clause 12.3.7).");
        Assert.AreEqual(
            ExpectedPrivateAreaLength(SecretBytes.Length), response.OutPrivate.Length,
            "TPM2B_DIGEST(32) ‖ TPM2B_IV(16) ‖ TPM2B_SENSITIVE(type ‖ TPM2B_AUTH(64) ‖ TPM2B_DIGEST(32) ‖ TPM2B_SENSITIVE_DATA) is the private area's layout (Part 1, Clause 19; Part 2, clause 12.3, Table 240).");

        TpmResult<LoadResponse> reloadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, response.OutPrivate, sealedObject.PublicArea, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(reloadResult.IsSuccess, $"The returned private area must load under the same parent with the unchanged public area (Part 3, clause 12.8.1), but failed: '{reloadResult.ResponseCode}'.");
        using LoadResponse reloaded = reloadResult.Value;
        Assert.IsTrue(
            reloaded.Name.Span.SequenceEqual(sealedObject.Name.Span),
            "The public area is unchanged, so the reloaded object's Name equals the original's (Part 1, clause 13, Table 9).");

        TpmResult<UnsealResponse> newAuthUnseal = await UnsealAsync(tpm, registry, pool, reloaded.ObjectHandle.Value, NewAuth).ConfigureAwait(false);
        Assert.IsTrue(newAuthUnseal.IsSuccess, $"The reloaded object must unseal with the new authorization value (Part 3, clause 12.8.1), but failed: '{newAuthUnseal.ResponseCode}'.");
        using UnsealResponse unsealed = newAuthUnseal.Value;
        Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes), "The rewrapped sensitive data is the original secret, byte for byte.");

        TpmResult<UnsealResponse> oldAuthUnseal = await UnsealAsync(tpm, registry, pool, reloaded.ObjectHandle.Value, OriginalAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), oldAuthUnseal.ResponseCode,
            "The reloaded object no longer authorizes with the old value (Part 3, clause 12.8.1).");
    }

    /// <summary>
    /// The private area's layout apart from its total width: "The combination of the HMAC and the encrypted
    /// sensitive area is a key's private area" (TPM 2.0 Library Part 1, clause 23.4) — the outer TPM2B_DIGEST
    /// integrity HMAC comes first, then "the TPM2B_IV containing the random symIv is placed in front of the
    /// encrypted data" (Part 1, clause 19.4) and "the integrity value is placed before the symmetric IV" (Part 1,
    /// clause 19.5) — so a SHA-256 digest precedes a 16-octet IV, which precedes the size-prefixed TPMT_SENSITIVE
    /// interior whose authValue the TPM pads to its maximum size (Part 2, clause 12.3.7), with nothing after it.
    /// This is a layout oracle only: it neither decrypts the sensitive area nor verifies the integrity HMAC.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthReturnsAPrivateAreaInTheProtectedStorageLayout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthReturnsAPrivateAreaInTheProtectedStorageLayout), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, DaProtectedSealedAttributes).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ObjectChangeAuth() with the object's password must succeed (Part 3, clause 12.8), but failed: '{result.ResponseCode}'.");
        using ObjectChangeAuthResponse response = result.Value;

        var reader = new TpmReader(response.OutPrivate.Span);
        ReadOnlySpan<byte> integrityDigest = reader.ReadTpm2b();
        Assert.HasCount(DigestSize, integrityDigest, "The outer integrity value is a SHA-256 TPM2B_DIGEST (TPM 2.0 Library Part 1, clause 19.5).");

        ReadOnlySpan<byte> iv = reader.ReadTpm2b();
        Assert.HasCount(16, iv, "The TPM2B_IV follows the integrity value and is one AES-128-CFB block wide (TPM 2.0 Library Part 1, clause 19.4).");

        int expectedSensitiveAreaWidth = ExpectedPrivateAreaLength(SecretBytes.Length) - reader.Consumed;
        Assert.AreEqual(
            expectedSensitiveAreaWidth, reader.Remaining,
            "The octets after the digest and IV are exactly the size-prefixed TPMT_SENSITIVE interior with authValue padded to Tpm2bAuth.MaxSize, and nothing follows it (TPM 2.0 Library Part 2, clause 12.3.7).");
    }

    /// <summary>
    /// "This command does not change the authorization of the TPM-resident object on which it operates": after a
    /// successful rewrap the ORIGINAL loaded object still unseals with its old authorization value and refuses the
    /// new one.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthLeavesTheResidentObjectsAuthorizationUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthLeavesTheResidentObjectsAuthorizationUnchanged), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ObjectChangeAuth() must succeed, but failed: '{result.ResponseCode}'.");
        result.Value.Dispose();

        TpmResult<UnsealResponse> oldAuthUnseal = await UnsealAsync(tpm, registry, pool, sealedObject.Handle, OriginalAuth).ConfigureAwait(false);
        Assert.IsTrue(oldAuthUnseal.IsSuccess, $"The TPM-resident object keeps its old authorization value (Part 3, clause 12.8.1), but the old value was refused: '{oldAuthUnseal.ResponseCode}'.");
        oldAuthUnseal.Value.Dispose();

        TpmResult<UnsealResponse> newAuthUnseal = await UnsealAsync(tpm, registry, pool, sealedObject.Handle, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), newAuthUnseal.ResponseCode,
            "The TPM-resident object does not authorize with the new value (Part 3, clause 12.8.1); a noDA object's mismatch is TPM_RC_BAD_AUTH.");
    }

    /// <summary>
    /// The rewrap of an HMAC key: the returned private area reloads under the same parent, the reloaded key
    /// authorizes <c>TPM2_HMAC()</c> with the new value and reproduces RFC 4231 test case 1's tag — the key value
    /// survived the rewrap unchanged — while the old value is refused on the reloaded key.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOnAnHmacKeyReloadsToAKeyAuthorizedByTheNewValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOnAnHmacKeyReloadsToAKeyAuthorizedByTheNewValue), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyWithPublicAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, SessionAlg, userAuth: OriginalAuth, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, key.Handle, parent.ObjectHandle.Value, keyAuth, null, NewAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ObjectChangeAuth() on an HMAC key must succeed (Part 3, clause 12.8), but failed: '{result.ResponseCode}'.");
        using ObjectChangeAuthResponse response = result.Value;

        TpmResult<LoadResponse> reloadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, response.OutPrivate, key.PublicArea!, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(reloadResult.IsSuccess, $"The rewrapped HMAC key must load under the same parent, but failed: '{reloadResult.ResponseCode}'.");
        using LoadResponse reloaded = reloadResult.Value;

        TpmResult<HmacResponse> hmacResult = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, reloaded.ObjectHandle.Value, Rfc4231Case1Data, SessionAlg, NewAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(hmacResult.IsSuccess, $"The reloaded HMAC key must authorize with the new value, but failed: '{hmacResult.ResponseCode}'.");
        using HmacResponse hmac = hmacResult.Value;
        Assert.IsTrue(
            hmac.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256),
            "The reloaded key reproduces RFC 4231 test case 1's HMAC-SHA-256 tag: the key value survived the rewrap unchanged.");

        TpmResult<HmacResponse> oldAuthResult = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, reloaded.ObjectHandle.Value, Rfc4231Case1Data, SessionAlg, OriginalAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), oldAuthResult.ResponseCode,
            "The reloaded key refuses the old authorization value (Part 3, clause 12.8.1).");
    }

    /// <summary>
    /// An empty <c>newAuth</c> is a legitimate new authorization value: the rewrap succeeds and the reloaded
    /// object authorizes with the empty password (TPM 2.0 Library Part 1, clause 16.6.4.3: an empty authValue
    /// authorizes with an empty password).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthWithAnEmptyNewAuthReloadsToAnObjectAuthorizedByTheEmptyPassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthWithAnEmptyNewAuthReloadsToAnObjectAuthorizedByTheEmptyPassword), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, objectAuth, null, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ObjectChangeAuth() with an empty newAuth must succeed, but failed: '{result.ResponseCode}'.");
        using ObjectChangeAuthResponse response = result.Value;

        TpmResult<LoadResponse> reloadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, response.OutPrivate, sealedObject.PublicArea, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(reloadResult.IsSuccess, $"The rewrapped object must load, but failed: '{reloadResult.ResponseCode}'.");
        using LoadResponse reloaded = reloadResult.Value;

        TpmResult<UnsealResponse> unsealResult = await UnsealAsync(tpm, registry, pool, reloaded.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(unsealResult.IsSuccess, $"The reloaded object must authorize with the empty password (Part 1, clause 16.6.4.3), but failed: '{unsealResult.ResponseCode}'.");
        unsealResult.Value.Dispose();
    }

    /// <summary>
    /// The <c>newAuth</c> width rule after authorization: trailing zeros are removed (TPM 2.0 Library Part 1,
    /// clause 16.6.4.3) and the remainder may be no wider than the digest of the object's Name algorithm — 33
    /// octets under SHA-256 is <c>TPM_RC_SIZE</c>, 32 succeeds, and 33 whose last octet is zero strips to 32 and
    /// succeeds (Part 4 <c>AdjustAuthSize</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    /// <param name="width">The <c>newAuth</c> width in octets.</param>
    /// <param name="endsWithZero">Whether the last octet is zero, so the strip shortens the value by one.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(DigestSize + 1, false, TpmRcConstants.TPM_RC_SIZE)]
    [DataRow(DigestSize, false, TpmRcConstants.TPM_RC_SUCCESS)]
    [DataRow(DigestSize + 1, true, TpmRcConstants.TPM_RC_SUCCESS)]
    public async Task ObjectChangeAuthJudgesTheNewAuthWidthAgainstTheNameAlgDigestAfterStrippingTrailingZeros(int width, bool endsWithZero, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants, so the over-width row carries the format-zero code and
        //this computes the expected value designated to newAuth, parameter 1 of Table 32.
        if(expected == TpmRcConstants.TPM_RC_SIZE)
        {
            expected = HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ObjectChangeAuthJudgesTheNewAuthWidthAgainstTheNameAlgDigestAfterStrippingTrailingZeros)}-{width}-{endsWithZero}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes).ConfigureAwait(false);

        byte[] newAuth = new byte[width];
        for(int index = 0; index < width; index++)
        {
            newAuth[index] = (byte)(0x41 + index);
        }

        if(endsWithZero)
        {
            newAuth[width - 1] = 0;
        }

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, objectAuth, null, newAuth).ConfigureAwait(false);
        TpmRcConstants observed = result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;
        Assert.AreEqual(
            expected, observed,
            $"A {width}-octet newAuth{(endsWithZero ? " ending in a zero octet" : string.Empty)} under a SHA-256 Name algorithm must answer {expected} (Part 3, clause 12.8; Part 1, clause 16.6.4.3).");

        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }
    }

    /// <summary>
    /// "This command may not be used to change the authorization value for an NV Index or a Primary Object": a
    /// Primary Object at <c>objectHandle</c> has no parent whose Qualified Name chains to its own — its ancestor
    /// is a Primary Seed — so the parent judgment refuses it with <c>TPM_RC_TYPE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOnAPrimaryObjectIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOnAPrimaryObjectIsRefusedWithType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse other = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, primary.ObjectHandle.Value, other.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 1), result.ResponseCode,
            "A Primary Object's ancestor is a Primary Seed, never a loaded parent, so the Qualified Name judgment refuses it with TPM_RC_TYPE at parentHandle, handle 2 of Table 32 (Part 3, clause 12.8.1).");
    }

    /// <summary>
    /// An object <c>TPM2_LoadExternal()</c> loaded with its sensitive area (a Temporary Object under
    /// <c>TPM_RH_NULL</c>, TPM 2.0 Library Part 3, clause 12.3) has no Storage Parent whose Qualified Name chains
    /// to its own, so the parent judgment refuses it with <c>TPM_RC_TYPE</c> once its (empty) authorization has
    /// been proved.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOnAnExternalObjectIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOnAnExternalObjectIsRefusedWithType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint externalHandle = await LoadExternalHmacKeyAsync(tpm, registry, pool, includeSensitive: true).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, externalHandle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 1), result.ResponseCode,
            "A Temporary Object loaded from outside has no parent whose Qualified Name chains to its own, so the judgment refuses it with TPM_RC_TYPE at parentHandle, handle 2 of Table 32 (Part 3, clause 12.8.1).");
    }

    /// <summary>
    /// A sequence object at <c>objectHandle</c> has no authorization value a private area could carry (Part 4
    /// <c>TPM2_ObjectChangeAuth</c>: "Can not change authorization on sequence object"), so it is refused with
    /// <c>TPM_RC_TYPE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOnASequenceObjectIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOnASequenceObjectIsRefusedWithType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, Rfc4231Case1Key, SessionAlg, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacStartResponse> startResult = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, key.Handle, SessionAlg, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_HMAC_Start() must open a sequence, but failed: '{startResult.ResponseCode}'.");
        uint sequenceHandle = startResult.Value.SequenceHandle.Value;

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sequenceHandle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 0), result.ResponseCode,
            "A sequence object has no authorization value a private area could carry, so it is refused with TPM_RC_TYPE (Part 4 TPM2_ObjectChangeAuth).");
    }

    /// <summary>
    /// A <c>parentHandle</c> that is a Storage Parent but not the object's own: the object's Qualified Name
    /// recomputed from that parent's does not reproduce the retained one, so the command refuses it with
    /// <c>TPM_RC_TYPE</c> — "parentHandle: handle of the parent" is judged, never trusted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 32</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthUnderAnotherStorageParentIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthUnderAnotherStorageParentIsRefusedWithType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse otherParent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, otherParent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 1), result.ResponseCode,
            "The object's Qualified Name chained from another parent's does not reproduce the retained one, so the parent is refused with TPM_RC_TYPE at parentHandle, handle 2 of Table 32 (Part 3, clause 12.8.1).");
    }

    /// <summary>
    /// A <c>parentHandle</c> naming a signing key — no Storage Parent at all — cannot be the object's parent, so
    /// the parent judgment refuses it with <c>TPM_RC_TYPE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthUnderASigningKeyParentIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthUnderASigningKeyParentIsRefusedWithType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes).ConfigureAwait(false);

        using CreatePrimaryInput signerInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> signerResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, signerInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signerResult.IsSuccess, $"CreatePrimary (signing key) failed: '{signerResult.ResponseCode}'.");
        using CreatePrimaryResponse signer = signerResult.Value;

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, signer.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 1), result.ResponseCode,
            "A signing key is no Storage Parent and chains no child's Qualified Name, so it is refused with TPM_RC_TYPE at parentHandle, handle 2 of Table 32 (Part 3, clause 12.8.1).");
    }

    /// <summary>
    /// <c>parentHandle</c> is <c>TPM2_ObjectChangeAuth()</c>'s 2nd handle (index 1, TPM 2.0 Library Part 3, Table
    /// 32); a TRANSIENT-range value naming no loaded object is <c>TPM_RC_REFERENCE_H1</c> (clause 5.4, step 2.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 32</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthWithAnUnloadedParentHandleAnswersReferenceH1()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthWithAnUnloadedParentHandleAnswersReferenceH1), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, UnloadedParentHandle, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_H1, result.ResponseCode,
            "parentHandle is TPM2_ObjectChangeAuth()'s 2nd handle (index 1); a TRANSIENT-range value naming no loaded object is TPM_RC_REFERENCE_H1 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
    }

    /// <summary>
    /// <c>objectHandle</c> is <c>TPM2_ObjectChangeAuth()</c>'s 1st handle (index 0, TPM 2.0 Library Part 3, Table
    /// 32); a TRANSIENT-range value naming no loaded object is <c>TPM_RC_REFERENCE_H0</c> (clause 5.4, step 2.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 32</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOnAnUnloadedObjectHandleAnswersReferenceH0()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOnAnUnloadedObjectHandleAnswersReferenceH0), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, UnloadedTransientHandle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_H0, result.ResponseCode,
            "objectHandle is TPM2_ObjectChangeAuth()'s 1st handle (index 0); a TRANSIENT-range value naming no loaded object is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");
    }

    /// <summary>
    /// Both handles are <c>TPMI_DH_OBJECT</c> without the <c>+</c> that would admit <c>TPM_RH_NULL</c> (TPM 2.0
    /// Library Part 2, clause 9.3, Table 49), so <c>TPM_RH_NULL</c> at either position is <c>TPM_RC_VALUE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 32</see>.
    /// </summary>
    /// <param name="isObjectHandleNull">Whether <c>TPM_RH_NULL</c> rides <c>objectHandle</c> (else <c>parentHandle</c>).</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task ObjectChangeAuthWithNullAtEitherHandleIsRefusedWithValue(bool isObjectHandleNull)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ObjectChangeAuthWithNullAtEitherHandleIsRefusedWithValue)}-{isObjectHandleNull}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes).ConfigureAwait(false);

        uint objectHandle = isObjectHandleNull ? (uint)TpmRh.TPM_RH_NULL : sealedObject.Handle;
        uint parentHandle = isObjectHandleNull ? parent.ObjectHandle.Value : (uint)TpmRh.TPM_RH_NULL;

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, objectHandle, parentHandle, objectAuth, null, NewAuth).ConfigureAwait(false);
        //The reference validates each TPMI_DH_OBJECT handle separately at unmarshal: objectHandle is H1,
        //parentHandle is H2 (Table 32's own handle-area order).
        Assert.AreEqual(
            isObjectHandleNull ? HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0) : HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 1),
            result.ResponseCode,
            $"TPM_RH_NULL at {(isObjectHandleNull ? "objectHandle" : "parentHandle")} is outside TPMI_DH_OBJECT's admitted ranges, so it is TPM_RC_VALUE (Part 2, clause 9.3, Table 49).");
    }

    /// <summary>
    /// Check 1 of the authorization ladder — "The public and sensitive portions of the object shall be present
    /// on the TPM" — refuses a public-only object with <c>TPM_RC_AUTH_UNAVAILABLE</c> before any credential is
    /// read, so the dictionary-attack counter does not move.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOnAPublicOnlyObjectIsRefusedWithAuthUnavailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOnAPublicOnlyObjectIsRefusedWithAuthUnavailable), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint publicOnlyHandle = await LoadExternalHmacKeyAsync(tpm, registry, pool, includeSensitive: false).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, publicOnlyHandle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode,
            "A public-only object has no sensitive portion present, so its ADMIN-role authorization is unavailable (Part 3, clause 5.6, check 1).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "Check 1 reads no credential, so it moves no dictionary-attack counter.");
    }

    /// <summary>
    /// A wrong password on a dictionary-attack-protected object is the session-index-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> at index 0 (TPM 2.0 Library Part 2, clause 6.6.2) and charges <c>failedTries</c>
    /// once (Part 1, clause 16.8.7); on a <c>noDA</c> object the same mismatch is <c>TPM_RC_BAD_AUTH</c> and
    /// charges nothing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    /// <param name="isDaProtected">Whether the object is dictionary-attack protected (<c>noDA</c> CLEAR).</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task ObjectChangeAuthWithAWrongPasswordChargesOnlyADaProtectedObject(bool isDaProtected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ObjectChangeAuthWithAWrongPasswordChargesOnlyADaProtectedObject)}-{isDaProtected}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, isDaProtected ? DaProtectedSealedAttributes : NoDaSealedAttributes).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession wrongAuth = TpmPasswordSession.Create(WrongAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, wrongAuth, null, NewAuth).ConfigureAwait(false);
        TpmRcConstants expected = isDaProtected ? TpmRcConstants.TPM_RC_AUTH_FAIL : TpmRcConstants.TPM_RC_BAD_AUTH;
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(expected, sessionIndex: 0), result.ResponseCode,
            $"A wrong password at the ADMIN slot is the session-index-encoded {expected} (Part 2, clause 6.6.2; Part 1, clause 16.8.1).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter + (isDaProtected ? 1u : 0u), after.Value.LockoutCounter,
            isDaProtected ? "A DA-protected object's mismatch charges failedTries once (Part 1, clause 16.8.7)." : "A noDA object's mismatch charges nothing (Part 1, clause 16.8.1).");
    }

    /// <summary>
    /// Check 3 of the authorization ladder: with the TPM in Lockout mode, a dictionary-attack-protected object's
    /// ADMIN-role authorization is refused with the bare <c>TPM_RC_LOCKOUT</c> even when the password is
    /// correct, and the refusal moves <c>failedTries</c> no further.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthInLockoutIsRefusedWithLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthInLockoutIsRefusedWithLockout), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, DaProtectedSealedAttributes).ConfigureAwait(false);

        await DriveIntoLockoutAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
        TpmResult<TpmDictionaryAttackParameters> lockedOut = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
            "In Lockout mode a DA-protected object's authorization is refused with the bare TPM_RC_LOCKOUT ahead of the compare (Part 3, clause 5.6, check 3; Part 1, clause 16.8.3).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(lockedOut.Value.LockoutCounter, after.Value.LockoutCounter, "A LOCKOUT refusal moves failedTries no further.");
    }

    /// <summary>
    /// Check 5.1 of the authorization ladder: with <c>adminWithPolicy</c> SET, "ADMIN role actions may only be
    /// approved with a policy session" (TPM 2.0 Library Part 2, clause 8.3.3), so a password at the ADMIN slot is
    /// refused with the bare <c>TPM_RC_AUTH_TYPE</c> before any compare and charges nothing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthWithAPasswordOnAnAdminWithPolicyObjectIsRefusedWithAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthWithAPasswordOnAnAdminWithPolicyObjectIsRefusedWithAuthType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, DaProtectedSealedAttributes | TpmaObject.ADMIN_WITH_POLICY).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
            "adminWithPolicy SET admits only a policy session at the ADMIN slot, so a password is TPM_RC_AUTH_TYPE (Part 3, clause 5.6, check 5.1; Part 2, clause 8.3.3).");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "Check 5.1 reads no credential, so it moves no dictionary-attack counter.");
    }

    /// <summary>
    /// Check 3 precedes check 5.1 in the authorization ladder: an <c>adminWithPolicy</c>-SET, dictionary-attack-
    /// protected object with the TPM in Lockout mode answers <c>TPM_RC_LOCKOUT</c> to a password, not
    /// <c>TPM_RC_AUTH_TYPE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthInLockoutOnAnAdminWithPolicyObjectIsRefusedWithLockoutBeforeAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthInLockoutOnAnAdminWithPolicyObjectIsRefusedWithLockoutBeforeAuthType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, DaProtectedSealedAttributes | TpmaObject.ADMIN_WITH_POLICY).ConfigureAwait(false);

        await DriveIntoLockoutAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
        TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
            "Check 3 (Lockout) is judged before check 5.1 (the session kind), so the answer is TPM_RC_LOCKOUT rather than TPM_RC_AUTH_TYPE (Part 3, clause 5.6).");
    }

    /// <summary>
    /// The ADMIN role over a policy session (TPM 2.0 Library Part 1, clause 16.2): an object whose authPolicy is
    /// the <c>TPM2_PolicyCommandCode(TPM_CC_ObjectChangeAuth)</c> digest is rewrapped by a satisfied session that
    /// latched that command, whether <c>adminWithPolicy</c> is SET or CLEAR; the returned area reloads and
    /// authorizes with the new value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    /// <param name="isAdminWithPolicy">Whether the object's <c>adminWithPolicy</c> attribute is SET.</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task ObjectChangeAuthOverAPolicySessionLatchedToTheCommandSucceeds(bool isAdminWithPolicy)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ObjectChangeAuthOverAPolicySessionLatchedToTheCommandSucceeds)}-{isAdminWithPolicy}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        TpmaObject attributes = isAdminWithPolicy ? NoDaSealedAttributes | TpmaObject.ADMIN_WITH_POLICY : NoDaSealedAttributes;
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, attributes, PolicyCommandCodeDigest(TpmCcConstants.TPM_CC_ObjectChangeAuth)).ConfigureAwait(false);

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, pool, isTrial: false).ConfigureAwait(false);
        try
        {
            await LatchCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_ObjectChangeAuth).ConfigureAwait(false);

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);
            TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(
                tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, policySession, [sealedObject.Name.AsReadOnlyMemory(), parent.Name.AsReadOnlyMemory()], NewAuth).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A policy session latched to TPM_CC_ObjectChangeAuth must authorize the ADMIN role (Part 1, clause 16.2), but failed: '{result.ResponseCode}'.");
            using ObjectChangeAuthResponse response = result.Value;

            TpmResult<LoadResponse> reloadResult = await HmacKeyHarness.LoadAsync(
                tpm, registry, pool, parent.ObjectHandle.Value, response.OutPrivate, sealedObject.PublicArea, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(reloadResult.IsSuccess, $"The rewrapped object must load, but failed: '{reloadResult.ResponseCode}'.");
            using LoadResponse reloaded = reloadResult.Value;

            TpmResult<UnsealResponse> unsealResult = await UnsealAsync(tpm, registry, pool, reloaded.ObjectHandle.Value, NewAuth).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"The reloaded object must authorize with the new value, but failed: '{unsealResult.ResponseCode}'.");
            unsealResult.Value.Dispose();
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A policy session whose digest reproduces the object's authPolicy but whose latched command code is
    /// ANOTHER command's is refused with <c>TPM_RC_POLICY_CC</c> (Part 4 <c>CheckPolicyAuthSession</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.11</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOverAPolicySessionLatchedToAnotherCommandIsRefusedWithPolicyCc()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOverAPolicySessionLatchedToAnotherCommandIsRefusedWithPolicyCc), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes, PolicyCommandCodeDigest(TpmCcConstants.TPM_CC_Certify)).ConfigureAwait(false);

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, pool, isTrial: false).ConfigureAwait(false);
        try
        {
            await LatchCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_Certify).ConfigureAwait(false);

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);
            TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(
                tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, policySession, [sealedObject.Name.AsReadOnlyMemory(), parent.Name.AsReadOnlyMemory()], NewAuth).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_CC, 0), result.ResponseCode,
                "A policy latched to TPM_CC_Certify authorizes that command alone, so TPM2_ObjectChangeAuth() is TPM_RC_POLICY_CC (Part 3, clause 23.11).");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A trial session (<c>TPM_SE_TRIAL</c>) accumulates a policyDigest for prediction but authorizes nothing, so
    /// it is refused with <c>TPM_RC_POLICY_FAIL</c> even when latched to the command.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOverATrialSessionIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOverATrialSessionIsRefusedWithPolicyFail), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes, PolicyCommandCodeDigest(TpmCcConstants.TPM_CC_ObjectChangeAuth)).ConfigureAwait(false);

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, pool, isTrial: true).ConfigureAwait(false);
        try
        {
            await LatchCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_ObjectChangeAuth).ConfigureAwait(false);

            using TpmPolicySession trialSession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);
            TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(
                tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, trialSession, [sealedObject.Name.AsReadOnlyMemory(), parent.Name.AsReadOnlyMemory()], NewAuth).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), result.ResponseCode,
                "A trial session authorizes nothing, so it is TPM_RC_POLICY_FAIL (Part 3, clause 11.1).");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An object with an EMPTY authPolicy has no policy any session can reproduce, so a policy session at its
    /// ADMIN slot — even one latched to the command — is refused with <c>TPM_RC_POLICY_FAIL</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOverAPolicySessionOnAnObjectWithAnEmptyAuthPolicyIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOverAPolicySessionOnAnObjectWithAnEmptyAuthPolicyIsRefusedWithPolicyFail), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes).ConfigureAwait(false);

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, pool, isTrial: false).ConfigureAwait(false);
        try
        {
            await LatchCommandCodeAsync(tpm, registry, pool, sessionHandle, TpmCcConstants.TPM_CC_ObjectChangeAuth).ConfigureAwait(false);

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);
            TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(
                tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, policySession, [sealedObject.Name.AsReadOnlyMemory(), parent.Name.AsReadOnlyMemory()], NewAuth).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), result.ResponseCode,
                "An empty authPolicy has no policy any session can reproduce, so the policy path is TPM_RC_POLICY_FAIL (Part 3, clause 5.6).");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The ADMIN role requires the policy to select the command (TPM 2.0 Library Part 1, clause 16.2; Part 4
    /// <c>CheckPolicyAuthSession</c>): a fresh policy session reproduces an all-zero authPolicy but latched no
    /// command code, so it is refused with <c>TPM_RC_POLICY_FAIL</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.11</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthOverAPolicySessionWithNoLatchedCommandCodeIsRefusedWithPolicyFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthOverAPolicySessionWithNoLatchedCommandCodeIsRefusedWithPolicyFail), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes, new byte[DigestSize]).ConfigureAwait(false);

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, pool, isTrial: false).ConfigureAwait(false);
        try
        {
            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);
            TpmResult<ObjectChangeAuthResponse> result = await ChangeAuthAsync(
                tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, policySession, [sealedObject.Name.AsReadOnlyMemory(), parent.Name.AsReadOnlyMemory()], NewAuth).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), result.ResponseCode,
                "The ADMIN role's policy must select the command; a session that latched no command code is TPM_RC_POLICY_FAIL (Part 1, clause 16.2).");
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The command's tag is <c>TPM_ST_SESSIONS</c> (Table 32): a <c>TPM_ST_NO_SESSIONS</c> frame carries no
    /// authorization for the ADMIN slot and is refused with <c>TPM_RC_AUTH_MISSING</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 32</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthWithoutASessionAreaIsRefusedWithAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthWithoutASessionAreaIsRefusedWithAuthMissing), pool).ConfigureAwait(false);

        var body = new List<byte>();
        AppendUInt32(body, UnloadedTransientHandle);
        AppendUInt32(body, UnloadedParentHandle);
        AppendTpm2b(body, NewAuth);

        TpmRcConstants responseCode = await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, [.. body]).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, responseCode, "TPM2_ObjectChangeAuth() requires TPM_ST_SESSIONS (Part 3, clause 12.8, Table 32).");
    }

    /// <summary>
    /// The parameter area's wire shape: a <c>newAuth</c> declaring more octets than a <c>TPM2B_AUTH</c> may carry
    /// (TPM 2.0 Library Part 2, clause 10.3.5, Table 93) is <c>TPM_RC_SIZE</c>; one declaring more octets than the
    /// frame holds is <c>TPM_RC_INSUFFICIENT</c>; octets after the last parameter are <c>TPM_RC_SIZE</c> (Part 3,
    /// clause 5.2).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8, Table 32</see>.
    /// </summary>
    /// <param name="declaredSize">The <c>newAuth</c> size field.</param>
    /// <param name="presentOctets">How many <c>newAuth</c> octets follow the size field.</param>
    /// <param name="trailingOctets">How many octets follow <c>newAuth</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(65, 65, 0, TpmRcConstants.TPM_RC_SIZE)]
    [DataRow(4, 2, 0, TpmRcConstants.TPM_RC_INSUFFICIENT)]
    [DataRow(4, 4, 1, TpmRcConstants.TPM_RC_SIZE)]
    public async Task ObjectChangeAuthRefusesAMalformedParameterArea(int declaredSize, int presentOctets, int trailingOctets, TpmRcConstants expected)
    {
        //DataRow arguments must be compile-time constants. newAuth is TPM2_ObjectChangeAuth()'s sole parameter
        //(Table 32, index 0): a declared size the frame cannot supply (the TPM2B read's own INSUFFICIENT) and
        //a declared size over Tpm2bAuth.MaxSize (the command's own bound check) are both
        //parameter-encoded; the trailing-octet row stays bare — the reference's own generic "nothing more was
        //declared" check, not attributable to newAuth specifically (Table 15's own N=0 case).
        if((declaredSize == 4 && presentOctets == 2 && trailingOctets == 0) || (declaredSize == 65 && presentOctets == 65 && trailingOctets == 0))
        {
            expected = HmacKeyHarness.ParameterEncodedRc(expected, 0);
        }

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ObjectChangeAuthRefusesAMalformedParameterArea)}-{declaredSize}-{presentOctets}-{trailingOctets}", pool).ConfigureAwait(false);

        var body = new List<byte>();
        AppendUInt32(body, UnloadedTransientHandle);
        AppendUInt32(body, UnloadedParentHandle);
        AppendEmptyPasswordSession(body);
        AppendUInt16(body, (ushort)declaredSize);
        for(int index = 0; index < presentOctets; index++)
        {
            body.Add(0x5A);
        }

        for(int index = 0; index < trailingOctets; index++)
        {
            body.Add(0xA5);
        }

        TpmRcConstants responseCode = await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, [.. body]).ConfigureAwait(false);
        Assert.AreEqual(expected, responseCode, $"A newAuth declaring {declaredSize} octets with {presentOctets} present and {trailingOctets} trailing must answer {expected}.");
    }

    /// <summary>
    /// Pool hygiene: a refused command (a wrong parent) and a successful one whose response is released leave the
    /// pool with exactly the carriers outstanding before them — every carrier the parse, the transitions and the
    /// effect rent is returned.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ObjectChangeAuthLeavesThePoolBalancedAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ObjectChangeAuthLeavesThePoolBalancedAcrossARefusalAndASuccess), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse otherParent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        using SealedObject sealedObject = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle.Value, OriginalAuth, NoDaSealedAttributes).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        {
            using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
            TpmResult<ObjectChangeAuthResponse> refused = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, otherParent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 1), refused.ResponseCode, "The wrong parent is refused with TPM_RC_TYPE at parentHandle, handle 2 of Table 32 (Part 3, clause 12.8.1).");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused TPM2_ObjectChangeAuth() returns every carrier it rented.");

        {
            using TpmPasswordSession objectAuth = TpmPasswordSession.Create(OriginalAuth, pool);
            TpmResult<ObjectChangeAuthResponse> accepted = await ChangeAuthAsync(tpm, registry, pool, sealedObject.Handle, parent.ObjectHandle.Value, objectAuth, null, NewAuth).ConfigureAwait(false);
            Assert.IsTrue(accepted.IsSuccess, $"TPM2_ObjectChangeAuth() must succeed, but failed: '{accepted.ResponseCode}'.");
            accepted.Value.Dispose();
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A successful TPM2_ObjectChangeAuth() returns every carrier once its response is released.");
    }

    /// <summary>
    /// A loaded sealed object under test: its transient handle, an owned clone of its Name, an owned clone of its
    /// public area (the unchanged area a rewrapped private area reloads with), and the width of the private area
    /// its creation returned.
    /// </summary>
    private sealed class SealedObject: IDisposable
    {
        /// <summary>Whether the owned clones have been released.</summary>
        private bool isDisposed;

        /// <summary>Gets the loaded transient handle.</summary>
        public uint Handle { get; }

        /// <summary>Gets an owned clone of the loaded object's Name.</summary>
        public Tpm2bName Name { get; }

        /// <summary>Gets an owned clone of the object's public area.</summary>
        public Tpm2bPublic PublicArea { get; }

        /// <summary>Gets the width of the private area <c>TPM2_Create()</c> returned for the object.</summary>
        public int CreatedPrivateLength { get; }

        /// <summary>Initializes the record, adopting <paramref name="name"/> and <paramref name="publicArea"/>.</summary>
        /// <param name="handle">The loaded transient handle.</param>
        /// <param name="name">An owned clone of the Name.</param>
        /// <param name="publicArea">An owned clone of the public area.</param>
        /// <param name="createdPrivateLength">The created private area's width.</param>
        public SealedObject(uint handle, Tpm2bName name, Tpm2bPublic publicArea, int createdPrivateLength)
        {
            Handle = handle;
            Name = name;
            PublicArea = publicArea;
            CreatedPrivateLength = createdPrivateLength;
        }

        /// <summary>Releases the Name and public-area clones.</summary>
        public void Dispose()
        {
            if(!isDisposed)
            {
                Name.Dispose();
                PublicArea.Dispose();
                isDisposed = true;
            }
        }
    }

    /// <summary>
    /// Creates a simulator with the elliptic-curve backend, powers it on and brings it operational through
    /// <c>TPM2_Startup(CLEAR)</c>.
    /// </summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool) =>
        HmacKeyHarness.CreateOperationalAsync($"tpm-in-house-object-change-auth-{name}", pool, TestContext.CancellationToken);

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_ObjectChangeAuth, TpmResponseCodec.ObjectChangeAuth)
            .Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal);

    /// <summary>
    /// Seals <see cref="SecretBytes"/> into a KEYEDHASH object with the given authorization value, attribute word
    /// and authorization policy under <paramref name="parentHandle"/>, loads it, and returns the loaded object.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <param name="userAuth">The object's authorization value.</param>
    /// <param name="attributes">The object's <c>TPMA_OBJECT</c> word.</param>
    /// <param name="authPolicy">The object's authorization policy digest, or empty for none.</param>
    /// <returns>The loaded object; the caller disposes it.</returns>
    private async Task<SealedObject> CreateAndLoadSealedObjectAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> userAuth, TpmaObject attributes, ReadOnlyMemory<byte> authPolicy = default)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, userAuth.Span, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateKeyedHashTemplate(SessionAlg, attributes, TpmsKeyedHashParms.SealedData, authPolicy.Span, pool);

        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateAsync(tpm, registry, pool, parentHandle, inSensitive, template, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (sealed object) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        Tpm2bPublic publicArea = HmacKeyHarness.ClonePublic(created.OutPublic, pool);
        try
        {
            TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
                tpm, registry, pool, parentHandle, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");
            using LoadResponse loaded = loadResult.Value;

            return new SealedObject(loaded.ObjectHandle.Value, Tpm2bName.Create(loaded.Name.Span, pool), publicArea, created.OutPrivate.Length);
        }
        catch
        {
            publicArea.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Loads an HMAC key from outside the TPM through <c>TPM2_LoadExternal()</c> (TPM 2.0 Library Part 3, clause
    /// 12.3): with its sensitive area under <c>TPM_RH_NULL</c>, or public-only under the owner hierarchy. The
    /// public area's <c>unique</c> is <c>H_nameAlg(seedValue ‖ key)</c> computed off-TPM (Part 2, clause 12.2.3.1,
    /// equation (8)), so the sensitive form binds.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="includeSensitive">Whether the sensitive area is supplied.</param>
    /// <returns>The loaded transient handle.</returns>
    private async Task<uint> LoadExternalHmacKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, bool includeSensitive)
    {
        byte[] seedValue = new byte[DigestSize];
        for(int index = 0; index < seedValue.Length; index++)
        {
            seedValue[index] = (byte)(0xC0 + index);
        }

        byte[] seedAndKey = new byte[seedValue.Length + Rfc4231Case1Key.Length];
        seedValue.CopyTo(seedAndKey, 0);
        Rfc4231Case1Key.CopyTo(seedAndKey, seedValue.Length);
        byte[] unique = SHA256.HashData(seedAndKey);

        using LoadExternalInput input = CreateExternalHmacKeyInput(seedValue, unique, includeSensitive, pool);

        TpmResult<LoadExternalResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"LoadExternal ({(includeSensitive ? "sensitive" : "public-only")} HMAC key) failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        return loaded.ObjectHandle.Value;
    }

    /// <summary>
    /// Builds the <c>TPM2_LoadExternal()</c> input for an HMAC key whose <c>unique</c> is <paramref name="unique"/>:
    /// the public area alone under the owner hierarchy, or the public area with a sensitive area carrying an
    /// empty authorization value, <paramref name="seedValue"/> and RFC 4231 test case 1's key under
    /// <c>TPM_RH_NULL</c>.
    /// </summary>
    /// <param name="seedValue">The sensitive area's <c>seedValue</c>, the object's Name-algorithm digest wide.</param>
    /// <param name="unique">The public area's <c>unique</c>, <c>H_nameAlg(seedValue ‖ key)</c>.</param>
    /// <param name="includeSensitive">Whether the sensitive area is supplied.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The input; the caller disposes it, releasing the public and sensitive areas it owns.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area and of the sensitive area's three carriers transfers to the returned LoadExternalInput, which disposes them; the public area is released here if the sensitive area's construction faults.")]
    private static LoadExternalInput CreateExternalHmacKeyInput(ReadOnlySpan<byte> seedValue, ReadOnlySpan<byte> unique, bool includeSensitive, BaseMemoryPool pool)
    {
        const TpmaObject ExternalAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;
        Tpm2bPublic inPublic = Tpm2bPublic.CreateKeyedHashTemplate(SessionAlg, ExternalAttributes, TpmsKeyedHashParms.Hmac(SessionAlg), default, pool, unique);
        try
        {
            TpmtSensitive? inPrivate = includeSensitive
                ? TpmtSensitive.ForKeyedHash(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Create(seedValue, pool), Tpm2bSensitiveData.Create(Rfc4231Case1Key, pool))
                : null;

            return new LoadExternalInput(inPrivate, inPublic, includeSensitive ? TpmiRhHierarchy.Null : TpmiRhHierarchy.Owner);
        }
        catch
        {
            inPublic.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Issues <c>TPM2_ObjectChangeAuth()</c> through the production executor and returns the raw result for the
    /// caller to assert.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The object whose authorization value is replaced.</param>
    /// <param name="parentHandle">The parent handle.</param>
    /// <param name="session">The ADMIN slot's session; the caller owns and disposes it.</param>
    /// <param name="handleNames">The two handle Names a real session's cpHash folds, or <see langword="null"/> for a password session.</param>
    /// <param name="newAuth">The replacement authorization value.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<ObjectChangeAuthResponse>> ChangeAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle, uint parentHandle, TpmSessionBase session, ReadOnlyMemory<byte>[]? handleNames, ReadOnlyMemory<byte> newAuth)
    {
        using Tpm2bAuth newAuthCarrier = newAuth.IsEmpty ? Tpm2bAuth.CreateEmpty(pool) : Tpm2bAuth.Create(newAuth.Span, pool);
        var input = new ObjectChangeAuthInput(TpmiDhObject.FromValue(objectHandle), TpmiDhObject.FromValue(parentHandle), newAuthCarrier);

        return await TpmCommandExecutor.ExecuteAsync<ObjectChangeAuthResponse>(
            tpm, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_Unseal()</c> over a password session and returns the raw result.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="itemHandle">The sealed object.</param>
    /// <param name="password">The password to present.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<UnsealResponse>> UnsealAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint itemHandle, ReadOnlyMemory<byte> password)
    {
        using TpmPasswordSession itemAuth = HmacKeyHarness.PasswordSession(password, pool);
        UnsealInput input = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));

        return await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, input, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Lowers <c>maxTries</c> to one and drives the TPM into Lockout mode with a single wrong-password
    /// <c>TPM2_Unseal()</c> against a throwaway dictionary-attack-protected sealed object under
    /// <paramref name="parentHandle"/> (TPM 2.0 Library Part 1, clause 16.8).
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent the throwaway object is sealed under.</param>
    private async Task DriveIntoLockoutAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        const uint LoweredMaxTries = 1;
        TpmResult<DictionaryAttackParametersResponse> lowerResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds, TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        using SealedObject throwaway = await CreateAndLoadSealedObjectAsync(tpm, registry, pool, parentHandle, OriginalAuth, DaProtectedSealedAttributes).ConfigureAwait(false);
        TpmResult<UnsealResponse> wrongResult = await UnsealAsync(tpm, registry, pool, throwaway.Handle, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
            "The priming unseal must fail and count, taking the TPM into Lockout mode.");

        TpmResult<TpmDictionaryAttackParameters> state = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(state.Value.IsLockedOut, "The TPM must be in Lockout mode before the case under proof runs.");
    }

    /// <summary>
    /// Computes the <c>TPM2_PolicyCommandCode(commandCode)</c> policy digest over a fresh session (TPM 2.0
    /// Library Part 3, clause 23.11), the minimal ADMIN-role policy an object binds to.
    /// </summary>
    /// <param name="commandCode">The command the policy selects.</param>
    /// <returns>The SHA-256 policy digest.</returns>
    private static byte[] PolicyCommandCodeDigest(TpmCcConstants commandCode)
    {
        byte[] digest = new byte[DigestSize];
        _ = TpmPolicyDigest.ExtendForCommandCode(new byte[DigestSize], commandCode, SessionAlg, digest, BaseMemoryPool.Shared);

        return digest;
    }

    /// <summary>Starts an unbound, unsalted policy session — real or trial — and returns its handle.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="isTrial">Whether to start a <c>TPM_SE_TRIAL</c> session.</param>
    /// <returns>The session handle.</returns>
    private async Task<uint> StartPolicySessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, bool isTrial)
    {
        StartAuthSessionInput input = isTrial
            ? StartAuthSessionInput.CreateTrialPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool)
            : StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession ({(isTrial ? "trial" : "policy")}) failed: '{result.ResponseCode}'.");
        using StartAuthSessionResponse response = result.Value;

        return response.SessionHandle.Value;
    }

    /// <summary>Issues <c>TPM2_PolicyCommandCode()</c> over the session and asserts it succeeded.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The policy session.</param>
    /// <param name="commandCode">The command to latch.</param>
    private async Task LatchCommandCodeAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint sessionHandle, TpmCcConstants commandCode)
    {
        PolicyCommandCodeInput input = PolicyCommandCodeInput.Create(sessionHandle, commandCode);
        TpmResult<PolicyCommandCodeResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyCommandCodeResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PolicyCommandCode failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// The width of a <c>TPM2B_PRIVATE</c>'s buffer for a sealed object under a SHA-256 parent: the integrity
    /// <c>TPM2B_DIGEST</c>, the <c>TPM2B_IV</c> of one AES block, and the size-prefixed <c>TPMT_SENSITIVE</c> whose
    /// <c>authValue</c> is padded to its 64-octet maximum (TPM 2.0 Library Part 1, Clause 19; Part 2, clause 12.3,
    /// Table 240, and clause 12.3.7).
    /// </summary>
    /// <param name="sensitiveDataLength">The sealed data's width.</param>
    /// <returns>The buffer width.</returns>
    private static int ExpectedPrivateAreaLength(int sensitiveDataLength)
    {
        const int IntegrityLength = sizeof(ushort) + DigestSize;
        const int IvLength = sizeof(ushort) + 16;
        int sensitiveInterior = sizeof(ushort) + (sizeof(ushort) + Tpm2bAuth.MaxSize) + (sizeof(ushort) + DigestSize) + (sizeof(ushort) + sensitiveDataLength);

        return IntegrityLength + IvLength + sizeof(ushort) + sensitiveInterior;
    }

    /// <summary>Appends a big-endian <c>UINT32</c>.</summary>
    /// <param name="body">The frame under construction.</param>
    /// <param name="value">The value.</param>
    private static void AppendUInt32(List<byte> body, uint value)
    {
        Span<byte> scratch = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(scratch, value);
        body.AddRange(scratch);
    }

    /// <summary>Appends a big-endian <c>UINT16</c>.</summary>
    /// <param name="body">The frame under construction.</param>
    /// <param name="value">The value.</param>
    private static void AppendUInt16(List<byte> body, ushort value)
    {
        Span<byte> scratch = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(scratch, value);
        body.AddRange(scratch);
    }

    /// <summary>Appends a size-prefixed <c>TPM2B</c>.</summary>
    /// <param name="body">The frame under construction.</param>
    /// <param name="octets">The buffer contents.</param>
    private static void AppendTpm2b(List<byte> body, ReadOnlySpan<byte> octets)
    {
        AppendUInt16(body, (ushort)octets.Length);
        body.AddRange(octets);
    }

    /// <summary>
    /// Appends an authorization area holding one empty <c>TPM_RS_PW</c> block — the size prefix, then the
    /// handle, an empty nonce, <c>continueSession</c>, and an empty hmac (TPM 2.0 Library Part 1, clause 15.6.4).
    /// </summary>
    /// <param name="body">The frame under construction.</param>
    private static void AppendEmptyPasswordSession(List<byte> body)
    {
        AppendUInt32(body, PasswordSessionBlockSize);
        AppendUInt32(body, (uint)TpmRh.TPM_RH_PW);
        AppendUInt16(body, 0);
        body.Add((byte)TpmaSession.CONTINUE_SESSION);
        AppendUInt16(body, 0);
    }

    /// <summary>Frames a <c>TPM2_ObjectChangeAuth()</c> header around <paramref name="body"/>, submits it straight to the simulator, and returns the response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="body">The handle area, authorization area and parameter area, already laid out.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmStConstants tag, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)tag, (uint)length, (uint)TpmCcConstants.TPM_CC_ObjectChangeAuth);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a malformed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }
}
