using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for creating, loading, importing, and reading a KEYEDHASH HMAC signing key, and for the
/// creation, load, import, and unseal rules that distinguish an HMAC key from a sealed data object and from an
/// XOR decryption key (TPM 2.0 Library Part 3, clauses 12.1, 12.2, 12.4, 12.7, 13.3; Part 2, clauses 8.3.3,
/// 11.1.19–11.1.23, 12.2.3.3; Part 1, clause 24.7.5.1; Part 4 <c>CreateChecks</c>/<c>PublicAttributesValidation</c>/
/// <c>SchemeChecks</c>/<c>CryptValidateKeys</c>).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorHmacKeyTests
{
    /// <summary>The MSTest-provided per-test context, its cancellation token observed across every exchange.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A 20-octet HMAC key value used where a valid caller-provided key is required (RFC 4231 test case 1's key).</summary>
    private static readonly byte[] SampleKey = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    /// <summary>RFC 4231 test case 1 data: "Hi There".</summary>
    private static readonly byte[] Rfc4231Case1Data = Convert.FromHexString("4869205468657265");

    /// <summary>RFC 4231 test case 1 published HMAC-SHA-256.</summary>
    private static readonly byte[] Rfc4231Case1Sha256 = Convert.FromHexString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /// <summary>A short secret sealed by <see cref="CreateSealedDataAsync"/>, arbitrary and not tied to any published vector.</summary>
    private static readonly byte[] SealedSecretBytes = [1, 2, 3, 4];

    /// <summary>The attribute word of an ordinary bound key: <c>fixedTPM</c>, <c>fixedParent</c>, <c>userWithAuth</c>, <c>noDA</c>.</summary>
    private const TpmaObject BoundAttributes = TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA;

    /// <summary>
    /// <c>TPM2_ReadPublic()</c> on a loaded HMAC key returns a public area whose type is <c>TPM_ALG_KEYEDHASH</c>,
    /// whose <c>sign</c> attribute is SET, and whose scheme is <c>TPM_ALG_HMAC</c> with the requested hash —
    /// the template <c>TPM2_Create()</c> echoed as <c>outPublic</c> (Part 3, clause 12.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 12.1 and 12.4; Part 2, clause 8.3.3.14, Table 227</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOnAnHmacKeyEchoesTheHmacSchemeTemplate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ReadPublicOnAnHmacKeyEchoesTheHmacSchemeTemplate), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ReadPublicInput input = ReadPublicInput.ForHandle(TpmiDhObject.FromValue(key.Handle));
        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadPublic() (HMAC key) failed: '{result.ResponseCode}'.");
        using ReadPublicResponse response = result.Value;

        TpmtPublic publicArea = response.PublicArea.PublicArea;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_KEYEDHASH, publicArea.Type, "An HMAC key's public type must be TPM_ALG_KEYEDHASH.");
        Assert.AreNotEqual(default, publicArea.ObjectAttributes & TpmaObject.SIGN_ENCRYPT, "An HMAC key must have the sign attribute SET.");

        TpmsKeyedHashParms scheme = publicArea.Parameters.KeyedHashDetail!.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HMAC, scheme.Scheme, "An HMAC key's scheme must be TPM_ALG_HMAC.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, scheme.HashAlg, "The HMAC scheme hash must be the one requested at creation.");
    }

    /// <summary>
    /// <c>TPM2_Unseal()</c> on an HMAC key (a KEYEDHASH object with <c>sign</c> SET) is refused with
    /// <c>TPM_RC_ATTRIBUTES</c> ("If either restricted, decrypt, or sign is SET in the attributes of itemHandle,
    /// then the TPM shall return TPM_RC_ATTRIBUTES").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task UnsealOnAnHmacKeyIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(UnsealOnAnHmacKeyIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        UnsealInput input = UnsealInput.ForItem(TpmiDhObject.FromValue(key.Handle));
        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, input, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "TPM2_Unseal() on an HMAC key must be refused with TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// <c>TPM2_Unseal()</c> over a bound HMAC session on an HMAC key is refused with <c>TPM_RC_ATTRIBUTES</c>
    /// exactly as the password form is — the attribute rule does not depend on the authorization channel.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task UnsealOverAnHmacSessionOnAnHmacKeyIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(UnsealOverAnHmacSessionOnAnHmacKeyIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                UnsealInput input = UnsealInput.ForItem(TpmiDhObject.FromValue(key.Handle));
                TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, input, [session], [key.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "TPM2_Unseal() over an HMAC session on an HMAC key must be refused with TPM_RC_ATTRIBUTES.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_Create()</c> of an HMAC key whose template sets <c>sensitiveDataOrigin</c> yet supplies a key value
    /// is refused with <c>TPM_RC_ATTRIBUTES</c> ("sensitiveDataOrigin shall be SET if inSensitive.data is an
    /// Empty Buffer and CLEAR if inSensitive.data is not an Empty Buffer").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.1.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateHmacKeyWithSensitiveDataOriginAndSuppliedDataIsRefusedWithAttributes()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateHmacKeyWithSensitiveDataOriginAndSuppliedDataIsRefusedWithAttributes)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateHmacKeyAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256,
                isRestricted: false, isSensitiveDataOrigin: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "A sensitiveDataOrigin-SET template that supplies data must be refused with TPM_RC_ATTRIBUTES.");
        }
    }

    /// <summary>
    /// <c>TPM2_Create()</c> of an HMAC key whose template clears <c>sensitiveDataOrigin</c> yet supplies no key
    /// value is refused with <c>TPM_RC_ATTRIBUTES</c> (CLEAR requires a non-empty inSensitive.data).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.1.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateHmacKeyWithoutSensitiveDataOriginAndNoDataIsRefusedWithAttributes()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateHmacKeyWithoutSensitiveDataOriginAndNoDataIsRefusedWithAttributes)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateHmacKeyAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256,
                isRestricted: false, isSensitiveDataOrigin: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "A sensitiveDataOrigin-CLEAR template with no data must be refused with TPM_RC_ATTRIBUTES.");
        }
    }

    /// <summary>
    /// A restricted KEYEDHASH key must have <c>sensitiveDataOrigin</c> SET unless it is duplicable (Part 4
    /// <c>CreateChecks</c>: "A restricted key symmetric key ... must have sensitiveDataOrigin SET unless it has
    /// fixedParent and fixedTPM CLEAR"): a bound restricted HMAC key created from a caller-supplied value is
    /// refused with <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.3.3.5; Part 3, clause 12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateRestrictedHmacKeyWithACallerSuppliedKeyIsRefusedWithAttributes()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateRestrictedHmacKeyWithACallerSuppliedKeyIsRefusedWithAttributes)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateHmacKeyAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256,
                isRestricted: true, isSensitiveDataOrigin: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "A bound restricted HMAC key from a caller-supplied value must be refused with TPM_RC_ATTRIBUTES.");
        }
    }

    /// <summary>
    /// <c>TPM2_Create()</c> of an HMAC key whose supplied key value exceeds the scheme hash's block size is refused
    /// with <c>TPM_RC_SIZE</c> (Part 4 <c>CryptGenerateKeyedHash</c>). A 65-octet key exceeds SHA-256's 64-octet
    /// block size.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 24.7.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateHmacKeyWithAnOversizedKeyIsRefusedWithSize()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateHmacKeyWithAnOversizedKeyIsRefusedWithSize)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            using IMemoryOwner<byte> oversizedKeyOwner = pool.Rent(65);
            Span<byte> oversizedKey = oversizedKeyOwner.Memory.Span[..65];
            oversizedKey.Fill(0xaa);

            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateHmacKeyAsync(
                tpm, registry, pool, parentHandle, oversizedKeyOwner.Memory[..65], TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode, "An HMAC key value larger than the scheme hash block size must be refused with TPM_RC_SIZE.");
        }
    }

    /// <summary>
    /// The key-value bound follows the scheme hash's own block size, not a flat 64 octets: a 100-octet key under
    /// an SHA-512 scheme (block size 128) creates, loads, and produces a self-consistent HMAC through the
    /// one-shot and the sequence forms.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 24.7.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateHmacKeyOf100OctetsUnderSha512Succeeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(CreateHmacKeyOf100OctetsUnderSha512Succeeds), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> wideKeyOwner = pool.Rent(100);
        Span<byte> wideKey = wideKeyOwner.Memory.Span[..100];
        wideKey.Fill(0x5c);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, wideKeyOwner.Memory[..100], TpmAlgIdConstants.TPM_ALG_SHA512, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<HmacResponse> oneShot = await HmacKeyHarness.HmacAsync(tpm, registry, pool, key.Handle, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA512, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(oneShot.IsSuccess, $"TPM2_HMAC() over the 100-octet SHA-512 key failed: '{oneShot.ResponseCode}'.");
        using HmacResponse oneShotResponse = oneShot.Value;
        Assert.AreEqual(64, oneShotResponse.OutHmac.Size, "An HMAC-SHA-512 is 64 octets wide.");

        using SequenceCompleteResponse sequenceCompleted = await HmacViaSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA512, Rfc4231Case1Data).ConfigureAwait(false);
        Assert.IsTrue(oneShotResponse.OutHmac.AsReadOnlySpan().SequenceEqual(sequenceCompleted.Result.AsReadOnlySpan()), "Both forms must agree over the 100-octet key.");
    }

    /// <summary>
    /// A 129-octet key value is one octet past <c>MAX_SYM_DATA</c>, the <c>TPM2B_SENSITIVE_DATA</c> bound, and is
    /// refused at unmarshal with <c>TPM_RC_SIZE</c> under every scheme hash. That bound coincides with SHA-512's
    /// 128-octet block size, so the widest sensitive value <c>TPM2_Create()</c> can carry is also the widest
    /// HMAC-SHA-512 key; the per-hash block-size arm itself is proven at 65 octets under SHA-256 by
    /// <see cref="CreateHmacKeyWithAnOversizedKeyIsRefusedWithSize"/>. The typed sensitive carrier refuses the
    /// width host-side, so the frame is hand-marshaled.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.14, Table 170; Part 1, clause 24.7.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateHmacKeyOf129OctetsUnderSha512IsRefusedWithSize()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateHmacKeyOf129OctetsUnderSha512IsRefusedWithSize)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            const int OversizedLength = Tpm2bSensitiveData.MaxSize + 1;
            using IMemoryOwner<byte> oversizedKey = pool.Rent(OversizedLength);
            oversizedKey.Memory.Span[..OversizedLength].Fill(0xaa);

            using Tpm2bPublic template = Tpm2bPublic.CreateHmacKeyTemplate(HmacKeyHarness.NameAlg, TpmAlgIdConstants.TPM_ALG_SHA512, pool, noDa: true, isSensitiveDataOrigin: false);
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateWithRawSensitiveAsync(
                tpm, registry, pool, parentHandle, ReadOnlyMemory<byte>.Empty, oversizedKey.Memory[..OversizedLength], template, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode, "A 129-octet key value is not a TPM2B_SENSITIVE_DATA and must be refused with TPM_RC_SIZE under every scheme hash.");
        }
    }

    /// <summary>
    /// <c>TPM2_Create()</c> of an HMAC key whose scheme hash is SHA-1 is refused with <c>TPM_RC_HASH</c>. This
    /// pins the simulator's own posture: an HMAC signing scheme hash is restricted to the signing family's set
    /// (SHA-256/384/512), the same set the asymmetric signing schemes admit, although SHA-1 is an implemented
    /// hash here — a TPM implementing SHA-1 may accept it (Part 2, Table 176's <c>TPMI_ALG_HASH</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.20, Table 176; Part 0, clause 3.1.1.2</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateHmacKeyWithASha1SchemeIsRefusedWithHash()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateHmacKeyWithASha1SchemeIsRefusedWithHash)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateHmacKeyAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA1, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, result.ResponseCode, "An HMAC key with a SHA-1 scheme must be refused with TPM_RC_HASH.");
        }
    }

    /// <summary>
    /// A sign-only KEYEDHASH template with scheme <c>TPM_ALG_NULL</c> is refused with <c>TPM_RC_SCHEME</c>:
    /// "Support for TPM_ALG_NULL for HMAC keys with the sign attribute was deprecated in version 185" (Part 2,
    /// Table 227; Part 0, clause 3.1.4.2), and Part 4 <c>SchemeChecks</c> requires <c>TPM_ALG_HMAC</c> for a
    /// signing key.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.3, Table 227; Part 0, clause 3.1.4.2; Part 3, clause 12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateSignOnlyKeyedHashWithANullSchemeIsRefusedWithScheme()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateSignOnlyKeyedHashWithANullSchemeIsRefusedWithScheme)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateKeyedHashObjectAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, BoundAttributes | TpmaObject.SIGN_ENCRYPT, TpmsKeyedHashParms.SealedData, SampleKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode, "A sign-only KEYEDHASH template with a NULL scheme must be refused with TPM_RC_SCHEME.");
        }
    }

    /// <summary>
    /// A KEYEDHASH template with <c>sign</c> and <c>decrypt</c> both SET and the <c>TPM_ALG_NULL</c> scheme Part 3,
    /// clause 12.1's rule 2 pairs with it — the one both-SET shape that rule leaves unrefused — is refused with
    /// <c>TPM_RC_ATTRIBUTES</c>: "having both objectAttributes.sign SET and objectAttributes.decrypt SET was
    /// deprecated in TPM 2.0 version 185 unless type is TPM_ALG_SYMCIPHER" (Part 0, clause 3.1.4.1). This pins the
    /// simulator's own posture — the 1.83 reference admits the shape — under which Table 79's "handle scheme
    /// TPM_ALG_NULL" rows are unreachable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 0, clause 3.1.4.1; Part 3, clause 12.1.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateKeyedHashWithSignAndDecryptBothSetAndANullSchemeIsRefusedWithAttributes()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateKeyedHashWithSignAndDecryptBothSetAndANullSchemeIsRefusedWithAttributes)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateKeyedHashObjectAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, BoundAttributes | TpmaObject.SIGN_ENCRYPT | TpmaObject.DECRYPT, TpmsKeyedHashParms.SealedData, SampleKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "A KEYEDHASH template with sign and decrypt both SET must be refused with TPM_RC_ATTRIBUTES.");
        }
    }

    /// <summary>
    /// "If sign and decrypt are both CLEAR or both SET and the scheme in the public area of the template is not
    /// TPM_ALG_NULL, the TPM shall return TPM_RC_SCHEME" (keyedHash rule 2): a both-SET template with an HMAC
    /// scheme is <c>TPM_RC_SCHEME</c> — the rule's own code, which the deprecated-shape posture of
    /// <see cref="CreateKeyedHashWithSignAndDecryptBothSetAndANullSchemeIsRefusedWithAttributes"/> does not
    /// override.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.1.1; Part 4 <c>SchemeChecks</c></see>.
    /// </summary>
    [TestMethod]
    public async Task CreateKeyedHashWithSignAndDecryptBothSetAndAnHmacSchemeIsRefusedWithScheme()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateKeyedHashWithSignAndDecryptBothSetAndAnHmacSchemeIsRefusedWithScheme)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateKeyedHashObjectAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, BoundAttributes | TpmaObject.SIGN_ENCRYPT | TpmaObject.DECRYPT, TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA256), SampleKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode, "A both-SET template with a non-NULL scheme must be refused with rule 2's TPM_RC_SCHEME.");
        }
    }

    /// <summary>
    /// "If sign and decrypt are both CLEAR ... and the scheme in the public area of the template is not
    /// TPM_ALG_NULL, the TPM shall return TPM_RC_SCHEME": a data object template carrying an HMAC scheme is
    /// refused.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.1.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateDataObjectWithAnHmacSchemeIsRefusedWithScheme()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateDataObjectWithAnHmacSchemeIsRefusedWithScheme)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateKeyedHashObjectAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, BoundAttributes, TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA256), SampleKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode, "A data object template with an HMAC scheme must be refused with TPM_RC_SCHEME.");
        }
    }

    /// <summary>
    /// A decrypt-only KEYEDHASH key must carry the <c>TPM_ALG_XOR</c> scheme (Part 4 <c>SchemeChecks</c>: "if
    /// decrypt ... scheme != TPM_ALG_XOR ... TPM_RCS_SCHEME"): an HMAC scheme on a decryption key is refused with
    /// <c>TPM_RC_SCHEME</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.3.3.13; Part 3, clause 12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateDecryptOnlyKeyedHashWithAnHmacSchemeIsRefusedWithScheme()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateDecryptOnlyKeyedHashWithAnHmacSchemeIsRefusedWithScheme)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateKeyedHashObjectAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, BoundAttributes | TpmaObject.DECRYPT, TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA256), SampleKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode, "A decrypt-only KEYEDHASH template with an HMAC scheme must be refused with TPM_RC_SCHEME.");
        }
    }

    /// <summary>
    /// A restricted KEYEDHASH object must have exactly one of <c>sign</c> and <c>decrypt</c> SET (Part 4
    /// <c>PublicAttributesValidation</c>: "a restricted key cannot have both SET or both CLEAR"): a restricted
    /// data object is refused with <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.3.3.12; Part 3, clause 12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateRestrictedDataObjectIsRefusedWithAttributes()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateRestrictedDataObjectIsRefusedWithAttributes)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateKeyedHashObjectAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, BoundAttributes | TpmaObject.RESTRICTED, TpmsKeyedHashParms.SealedData, SampleKey, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "A restricted data object must be refused with TPM_RC_ATTRIBUTES.");
        }
    }

    /// <summary>
    /// "The TPM_ALG_NULL hashAlg now returns TPM_RC_HASH" (Part 2, Table 177): a decrypt-only XOR key whose
    /// scheme hash is <c>TPM_ALG_NULL</c> is refused with <c>TPM_RC_HASH</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.21, Table 177</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateXorKeyWithANullHashIsRefusedWithHash()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateXorKeyWithANullHashIsRefusedWithHash)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateKeyedHashObjectAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, BoundAttributes | TpmaObject.DECRYPT | TpmaObject.SENSITIVE_DATA_ORIGIN,
                TpmsKeyedHashParms.Xor(TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108), ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, result.ResponseCode, "An XOR key with a NULL scheme hash must be refused with TPM_RC_HASH.");
        }
    }

    /// <summary>
    /// A restricted XOR key is a derivation parent and its kdf must be <c>TPM_ALG_KDF1_SP800_108</c> (Part 4
    /// <c>SchemeChecks</c>: "If this is a derivation parent, then the KDF needs to be SP800-108 ...
    /// TPM_RCS_SCHEME"): any other kdf is refused with <c>TPM_RC_SCHEME</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.21, Table 177; Part 1, clause 24.7.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateRestrictedXorKeyWithoutKdf1IsRefusedWithScheme()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(CreateRestrictedXorKeyWithoutKdf1IsRefusedWithScheme)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            TpmResult<CreateResponse> result = await HmacKeyHarness.CreateKeyedHashObjectAsync(
                tpm, registry, BaseMemoryPool.Shared, parentHandle, BoundAttributes | TpmaObject.DECRYPT | TpmaObject.RESTRICTED | TpmaObject.SENSITIVE_DATA_ORIGIN,
                TpmsKeyedHashParms.Xor(TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_NULL), ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode, "A restricted XOR key whose kdf is not KDF1_SP800_108 must be refused with TPM_RC_SCHEME.");
        }
    }

    /// <summary>
    /// A decrypt-only XOR key with an implemented scheme hash and <c>TPM_ALG_KDF1_SP800_108</c> creates and loads,
    /// its <c>outPublic</c> echoing the XOR scheme — the well-formed member of Table 177.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.21, Table 177; Part 3, clauses 12.1 and 12.2</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateXorKeyWithKdf1CreatesAndLoads()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(CreateXorKeyWithKdf1CreatesAndLoads), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateKeyedHashObjectAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, BoundAttributes | TpmaObject.DECRYPT | TpmaObject.SENSITIVE_DATA_ORIGIN,
            TpmsKeyedHashParms.Xor(TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108), ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (XOR key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmsKeyedHashParms echoed = created.OutPublic.PublicArea.Parameters.KeyedHashDetail!.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_XOR, echoed.Scheme, "outPublic must echo the XOR scheme.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108, echoed.Kdf, "outPublic must echo the kdf.");

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (XOR key) failed: '{loadResult.ResponseCode}'.");
        loadResult.Value.Dispose();
    }

    /// <summary>
    /// A TPM-generated HMAC key (<c>sensitiveDataOrigin</c> SET, empty data) creates, loads, and produces the same
    /// HMAC through the one-shot <c>TPM2_HMAC()</c> and through <c>TPM2_HMAC_Start()</c> plus
    /// <c>TPM2_SequenceComplete()</c> over the same message — the two forms key the same generated value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 15.5, 17.2 and 17.8</see>.
    /// </summary>
    [TestMethod]
    public async Task GeneratedHmacKeyProducesAConsistentHmac()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(GeneratedHmacKeyProducesAConsistentHmac), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] message = Convert.FromHexString("48656c6c6f2c20484d414321");

        TpmResult<HmacResponse> oneShot = await HmacKeyHarness.HmacAsync(tpm, registry, pool, key.Handle, message, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(oneShot.IsSuccess, $"One-shot TPM2_HMAC() failed: '{oneShot.ResponseCode}'.");
        using HmacResponse oneShotResponse = oneShot.Value;

        using SequenceCompleteResponse sequenceCompleted = await HmacViaSequenceAsync(tpm, registry, pool, key.Handle, TpmAlgIdConstants.TPM_ALG_SHA256, message).ConfigureAwait(false);

        bool matches = oneShotResponse.OutHmac.AsReadOnlySpan().SequenceEqual(sequenceCompleted.Result.AsReadOnlySpan());
        Assert.IsTrue(matches, "The one-shot HMAC must equal the value produced by an HMAC sequence over the same key and message.");
    }

    /// <summary>
    /// "If inSensitive.sensitive.data is an Empty Buffer, a TPM-generated key value that is the size of the
    /// digest produced by the nameAlg in inPublic is placed in TPMT_SENSITIVE.sensitive.bits" (keyedHash rule
    /// 4): a generated key whose nameAlg is SHA-256 and whose scheme hash is SHA-384 carries a 32-octet key
    /// value, not a 48-octet one, and a 32-octet <c>seedValue</c> — observed through the bare
    /// <c>TPM2B_SENSITIVE</c> a <c>TPM_RH_NULL</c> duplication hands out, octet for octet.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.1.1; Part 1, clause 24.7.5.1; Part 2, clause 12.3.2, Table 240</see>.
    /// </summary>
    [TestMethod]
    public async Task GeneratedHmacKeyValueIsTheNameAlgDigestSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(GeneratedHmacKeyValueIsTheNameAlgDigestSize), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using Tpm2bDigest duplicationPolicy = HmacKeyHarness.DuplicationPolicyDigest(pool);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA384,
            isDuplicable: true, authPolicy: duplicationPolicy.AsReadOnlyMemory(), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using IMemoryOwner<byte> nullParentNameOwner = pool.Rent(sizeof(uint));
        Span<byte> nullParentName = nullParentNameOwner.Memory.Span[..sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(nullParentName, (uint)TpmRh.TPM_RH_NULL);
        using DuplicateResponse duplicated = await HmacKeyHarness.DuplicateAsync(
            tpm, registry, pool, key.Handle, key.Name.AsReadOnlyMemory(), (uint)TpmRh.TPM_RH_NULL, nullParentNameOwner.Memory[..sizeof(uint)], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(duplicated.OutSymSeed.IsEmpty, "No seed is transported when there is no new parent.");

        //The spec-derived bare shape: [UINT16 interior size][UINT16 TPM_ALG_KEYEDHASH][TPM2B authValue, padded
        //to 64][TPM2B seedValue][TPM2B sensitive.bits] (Part 2, Table 240; Part 1, clause 24.7.3).
        ReadOnlySpan<byte> bare = duplicated.Duplicate.Span;
        int offset = sizeof(ushort);
        Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_KEYEDHASH, BinaryPrimitives.ReadUInt16BigEndian(bare[offset..]), "sensitiveType is TPM_ALG_KEYEDHASH.");
        offset += sizeof(ushort);
        ushort authSize = BinaryPrimitives.ReadUInt16BigEndian(bare[offset..]);
        offset += sizeof(ushort) + authSize;
        ushort seedSize = BinaryPrimitives.ReadUInt16BigEndian(bare[offset..]);
        offset += sizeof(ushort) + seedSize;
        ushort bitsSize = BinaryPrimitives.ReadUInt16BigEndian(bare[offset..]);

        Assert.AreEqual(32, seedSize, "seedValue is one nameAlg (SHA-256) digest wide.");
        Assert.AreEqual(32, bitsSize, "The generated key value is the nameAlg (SHA-256) digest size, not the SHA-384 scheme hash's 48 octets.");
    }

    /// <summary>
    /// An HMAC key survives migration: a duplicable key holding RFC 4231 test case 1's value, duplicated under a
    /// second storage parent through the DUP-role policy, imported and loaded there, still returns the
    /// published HMAC-SHA-256 — the sensitive layout <c>TPMT_SENSITIVE(KEYEDHASH ‖ authValue ‖ seedValue ‖
    /// bits)</c> travels intact.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 13.1 and 13.3; Part 1, Clause 20</see>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.2">RFC 4231, section 4.2</see>.
    /// </summary>
    [TestMethod]
    public async Task DuplicatedAndImportedHmacKeyStillReturnsThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(DuplicatedAndImportedHmacKeyStillReturnsThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using Tpm2bDigest duplicationPolicy = HmacKeyHarness.DuplicationPolicyDigest(pool);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyWithPublicAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256,
            isDuplicable: true, authPolicy: duplicationPolicy.AsReadOnlyMemory(), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse newParent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using DuplicateResponse duplicated = await HmacKeyHarness.DuplicateAsync(
            tpm, registry, pool, key.Handle, key.Name.AsReadOnlyMemory(), newParent.ObjectHandle.Value, newParent.Name.AsReadOnlyMemory(), TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<ImportResponse> importResult = await HmacKeyHarness.ImportAsync(
            tpm, registry, pool, newParent.ObjectHandle.Value, key.PublicArea!, duplicated.Duplicate, duplicated.OutSymSeed, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(importResult.IsSuccess, $"Import (HMAC key) failed: '{importResult.ResponseCode}'.");
        using ImportResponse imported = importResult.Value;

        using Tpm2bPublic inPublic = HmacKeyHarness.ClonePublic(key.PublicArea!, pool);
        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, newParent.ObjectHandle.Value, imported.OutPrivate, inPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (imported HMAC key) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, loaded.ObjectHandle.Value, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() over the imported key failed: '{result.ResponseCode}'.");
        using HmacResponse response = result.Value;

        Assert.IsTrue(response.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The migrated key must still return the published RFC 4231 value.");
    }

    /// <summary>
    /// The load-time scheme check (Part 3, clause 12.2 attribute validation; Part 4 <c>ObjectLoad</c> →
    /// <c>SchemeChecks</c>): a sealed data object's blob presented with a public area whose <c>sign</c> bit has
    /// been added — a signing key with a NULL scheme — is refused with <c>TPM_RC_SCHEME</c> on <c>inPublic</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.2.1; Part 2, clause 8.3.3.14</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadWithASignAttributeAddedToASealedDataPublicIsRefusedWithScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(LoadWithASignAttributeAddedToASealedDataPublicIsRefusedWithScheme), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (Tpm2bPrivate outPrivate, TpmaObject sealedAttributes) = await CreateSealedDataAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
        using(outPrivate)
        {
            using Tpm2bPublic doctored = Tpm2bPublic.CreateKeyedHashTemplate(HmacKeyHarness.NameAlg, sealedAttributes | TpmaObject.SIGN_ENCRYPT, TpmsKeyedHashParms.SealedData, authPolicy: default, pool);
            TpmResult<LoadResponse> result = await HmacKeyHarness.LoadAsync(
                tpm, registry, pool, parent.ObjectHandle.Value, outPrivate, doctored, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode, "A sign-SET public area with a NULL scheme must be refused at Load with TPM_RC_SCHEME.");
        }
    }

    /// <summary>
    /// The load-time attribute check (Part 4 <c>ObjectLoad</c> → <c>PublicAttributesValidation</c>): a sealed
    /// data object's blob presented with a public area whose <c>restricted</c> bit has been added — a restricted
    /// object with <c>sign</c> and <c>decrypt</c> both CLEAR — is refused with <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.2.1; Part 2, clause 8.3.3.12</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadWithRestrictedAddedToASealedDataPublicIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(LoadWithRestrictedAddedToASealedDataPublicIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (Tpm2bPrivate outPrivate, TpmaObject sealedAttributes) = await CreateSealedDataAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
        using(outPrivate)
        {
            using Tpm2bPublic doctored = Tpm2bPublic.CreateKeyedHashTemplate(HmacKeyHarness.NameAlg, sealedAttributes | TpmaObject.RESTRICTED, TpmsKeyedHashParms.SealedData, authPolicy: default, pool);
            TpmResult<LoadResponse> result = await HmacKeyHarness.LoadAsync(
                tpm, registry, pool, parent.ObjectHandle.Value, outPrivate, doctored, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "A restricted data-object public area must be refused at Load with TPM_RC_ATTRIBUTES.");
        }
    }

    /// <summary>
    /// The load-time scheme-hash check: a public area declaring a signing key with an HMAC-SHA-1 scheme is
    /// refused with <c>TPM_RC_HASH</c> — the simulator judges the public area's scheme before unwrapping the blob,
    /// an ordering Part 3, clause 12.2 permits but does not require — the same signing-family posture the
    /// creation gate applies.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.2.1; Part 2, clause 11.1.20, Table 176</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadWithASha1HmacSchemePublicIsRefusedWithHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(LoadWithASha1HmacSchemePublicIsRefusedWithHash), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (Tpm2bPrivate outPrivate, TpmaObject sealedAttributes) = await CreateSealedDataAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
        using(outPrivate)
        {
            using Tpm2bPublic doctored = Tpm2bPublic.CreateKeyedHashTemplate(HmacKeyHarness.NameAlg, sealedAttributes | TpmaObject.SIGN_ENCRYPT, TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA1), authPolicy: default, pool);
            TpmResult<LoadResponse> result = await HmacKeyHarness.LoadAsync(
                tpm, registry, pool, parent.ObjectHandle.Value, outPrivate, doctored, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, result.ResponseCode, "An HMAC-SHA-1 public area must be refused at Load with TPM_RC_HASH.");
        }
    }

    /// <summary>
    /// "For all objects, the size of the key in the sensitive area shall be consistent with the key size
    /// indicated in the public area or the TPM shall return TPM_RC_KEY_SIZE": a bare duplicate whose key value
    /// is 65 octets under an HMAC-SHA-256 public area (block size 64) is refused at <c>TPM2_Import()</c> with
    /// <c>TPM_RC_KEY_SIZE</c> — the reference runs <c>CryptValidateKeys</c> at Import under a fixedTPM parent.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 12.2.1 and 13.3.1; Part 1, clause 24.7.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ImportOfABareDuplicateWithAnOversizedKeyValueIsRefusedWithKeySize()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(ImportOfABareDuplicateWithAnOversizedKeyValueIsRefusedWithKeySize)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            using IMemoryOwner<byte> bitsOwner = pool.Rent(65);
            Span<byte> bits = bitsOwner.Memory.Span[..65];
            bits.Fill(0xaa);

            using Tpm2bPublic publicArea = DuplicableHmacKeyPublic(pool);
            using Tpm2bPrivate duplicate = BareSensitive(pool, seedSize: 32, bits);
            TpmResult<ImportResponse> result = await HmacKeyHarness.ImportAsync(
                tpm, registry, pool, parentHandle, publicArea, duplicate, Tpm2bEncryptedSecret.Empty, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_KEY_SIZE, result.ResponseCode, "A 65-octet key value under an HMAC-SHA-256 public area must be refused at Import with TPM_RC_KEY_SIZE.");
        }
    }

    /// <summary>
    /// The recovered <c>seedValue</c> must be one nameAlg digest wide (Part 4 <c>ObjectLoad</c>: a seedValue
    /// wider than the nameAlg's digest is <c>TPM_RC_KEY_SIZE</c>): a bare duplicate carrying a 33-octet seed
    /// under a SHA-256 nameAlg is refused at <c>TPM2_Import()</c> with <c>TPM_RC_KEY_SIZE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 12.2.1 and 13.3.1; Part 2, clause 12.3.2, Table 240</see>.
    /// </summary>
    [TestMethod]
    public async Task ImportOfABareDuplicateWithAWrongSizedSeedIsRefusedWithKeySize()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(ImportOfABareDuplicateWithAWrongSizedSeedIsRefusedWithKeySize)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            BaseMemoryPool pool = BaseMemoryPool.Shared;

            using Tpm2bPublic publicArea = DuplicableHmacKeyPublic(pool);
            using Tpm2bPrivate duplicate = BareSensitive(pool, seedSize: 33, SampleKey);
            TpmResult<ImportResponse> result = await HmacKeyHarness.ImportAsync(
                tpm, registry, pool, parentHandle, publicArea, duplicate, Tpm2bEncryptedSecret.Empty, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_KEY_SIZE, result.ResponseCode, "A 33-octet seedValue under a SHA-256 nameAlg must be refused at Import with TPM_RC_KEY_SIZE.");
        }
    }

    /// <summary>
    /// <c>TPM2B_SENSITIVE_DATA</c> is bounded by <c>MAX_SYM_DATA</c> (128 octets, Part 2, Tables 169 and 170):
    /// a bare duplicate whose key value declares 129 octets cannot be unmarshaled and <c>TPM2_Import()</c>
    /// answers <c>TPM_RC_SENSITIVE</c> ("the sensitive area could not be unmarshaled").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.14, Table 170; Part 3, clause 13.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ImportOfABareDuplicateWithASensitiveValueOver128OctetsIsRefusedWithSensitive()
    {
        (TpmResponseRegistry registry, TpmDevice tpm, TpmSimulator simulator, uint parentHandle) = await SetUpAsync(nameof(ImportOfABareDuplicateWithASensitiveValueOver128OctetsIsRefusedWithSensitive)).ConfigureAwait(false);
        using(simulator)
        using(tpm)
        {
            BaseMemoryPool pool = BaseMemoryPool.Shared;
            using IMemoryOwner<byte> bitsOwner = pool.Rent(129);
            Span<byte> bits = bitsOwner.Memory.Span[..129];
            bits.Fill(0xaa);

            using Tpm2bPublic publicArea = DuplicableHmacKeyPublic(pool);
            using Tpm2bPrivate duplicate = BareSensitive(pool, seedSize: 32, bits);
            TpmResult<ImportResponse> result = await HmacKeyHarness.ImportAsync(
                tpm, registry, pool, parentHandle, publicArea, duplicate, Tpm2bEncryptedSecret.Empty, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_SENSITIVE, result.ResponseCode, "A 129-octet sensitive value is not a TPM2B_SENSITIVE_DATA and must be refused at Import with TPM_RC_SENSITIVE.");
        }
    }

    /// <summary>
    /// <c>TPM2_Create()</c> of an HMAC key whose parent is authorized by a bound HMAC session — the
    /// session-authorized form — creates the key, which then loads under a password and returns the published
    /// RFC 4231 test case 1 value, so the session form applies the same KEYEDHASH creation rules and key handling.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.1; Part 1, clause 16.6</see>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.2">RFC 4231, section 4.2</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateHmacKeyOverAnHmacSessionThenHmacReturnsThePublishedValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(CreateHmacKeyOverAnHmacSessionThenHmacReturnsThePublishedValue), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForHmacKey(SampleKey, ReadOnlySpan<byte>.Empty, pool);
                using Tpm2bPublic template = Tpm2bPublic.CreateHmacKeyTemplate(HmacKeyHarness.NameAlg, TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true, isSensitiveDataOrigin: false);
                using CreateInput createInput = new(parent.ObjectHandle.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                    tpm, createInput, [session], [parent.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(createResult.IsSuccess, $"Create (HMAC key) over an HMAC session failed: '{createResult.ResponseCode}'.");
                using CreateResponse created = createResult.Value;

                TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
                    tpm, registry, pool, parent.ObjectHandle.Value, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(loadResult.IsSuccess, $"Load (HMAC key) failed: '{loadResult.ResponseCode}'.");
                using LoadResponse loaded = loadResult.Value;

                TpmResult<HmacResponse> result = await HmacKeyHarness.HmacAsync(
                    tpm, registry, pool, loaded.ObjectHandle.Value, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_HMAC() failed: '{result.ResponseCode}'.");
                using HmacResponse response = result.Value;

                Assert.IsTrue(response.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The session-created key must return the published RFC 4231 value.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The session-authorized <c>TPM2_Create()</c> applies the same origin rule as the password form: a template
    /// that sets <c>sensitiveDataOrigin</c> yet supplies a key value is refused with <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.1.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateHmacKeyOverAnHmacSessionWithSensitiveDataOriginAndSuppliedDataIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(CreateHmacKeyOverAnHmacSessionWithSensitiveDataOriginAndSuppliedDataIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForHmacKey(SampleKey, ReadOnlySpan<byte>.Empty, pool);
                using Tpm2bPublic template = Tpm2bPublic.CreateHmacKeyTemplate(HmacKeyHarness.NameAlg, TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true, isSensitiveDataOrigin: true);
                using CreateInput createInput = new(parent.ObjectHandle.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                    tpm, createInput, [session], [parent.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "The session form must refuse a sensitiveDataOrigin-SET template that supplies data with TPM_RC_ATTRIBUTES.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Computes an HMAC over one message through <c>TPM2_HMAC_Start()</c> plus <c>TPM2_SequenceComplete()</c>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The loaded HMAC key handle.</param>
    /// <param name="hashAlg">The hash algorithm to request.</param>
    /// <param name="message">The message to authenticate.</param>
    /// <returns>The completed sequence response; the caller disposes it.</returns>
    private async Task<SequenceCompleteResponse> HmacViaSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle, TpmAlgIdConstants hashAlg, ReadOnlyMemory<byte> message)
    {
        TpmResult<HmacStartResponse> startResult = await HmacKeyHarness.HmacStartAsync(
            tpm, registry, pool, keyHandle, hashAlg, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_HMAC_Start() failed: '{startResult.ResponseCode}'.");

        TpmResult<SequenceCompleteResponse> completeResult = await HmacKeyHarness.SequenceCompleteAsync(
            tpm, registry, pool, startResult.Value.SequenceHandle, message, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_SequenceComplete() (HMAC) failed: '{completeResult.ResponseCode}'.");

        return completeResult.Value;
    }

    /// <summary>Seals a short secret through the password form and returns the private blob with the attribute word <c>outPublic</c> echoed.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <returns>The wrapped private blob, an independent pooled clone the caller disposes, and the sealed object's attribute word.</returns>
    private async Task<(Tpm2bPrivate OutPrivate, TpmaObject Attributes)> CreateSealedDataAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecretBytes, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(HmacKeyHarness.NameAlg, pool, noDa: true);
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateAsync(tpm, registry, pool, parentHandle, inSensitive, template, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (sealed data) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        return (Tpm2bPrivate.Create(created.OutPrivate.Span, pool), created.OutPublic.PublicArea.ObjectAttributes);
    }

    /// <summary>
    /// "The computation for unique for a KeyedHash object is: unique = H_nameAlg(obfuscate ‖ key)" — a created
    /// KEYEDHASH object's public area carries a <c>unique</c> of the nameAlg's digest width, and the returned
    /// Name equals <c>nameAlg ‖ H_nameAlg(marshaled TPMT_PUBLIC)</c> recomputed off-TPM over the returned
    /// public area, so the Name provably covers the filled <c>unique</c> and therefore depends on the sensitive
    /// value (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 24.5.3.2, equation (48) for the quoted computation; Part 2:
    /// Structures, clause 12.2.3.1, equation (8); Part 1: Architecture, clause 13, Table 9 for the Name).
    /// </summary>
    [TestMethod]
    public async Task CreateFillsTheKeyedHashUniqueAndTheNameCoversIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(CreateFillsTheKeyedHashUniqueAndTheNameCoversIt), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyWithPublicAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ReadOnlySpan<byte> unique = key.PublicArea!.PublicArea.Unique.GetKeyedHashUnique();
        Assert.HasCount(32, unique.ToArray(), "The unique must be one SHA-256 nameAlg digest wide.");

        int publicSize = key.PublicArea!.GetSerializedSize();
        using IMemoryOwner<byte> marshaled = pool.Rent(publicSize);
        Span<byte> publicOctets = marshaled.Memory.Span[..publicSize];
        var writer = new TpmWriter(publicOctets);
        key.PublicArea!.WriteTo(ref writer);

        byte[] expectedName = new byte[sizeof(ushort) + 32];
        var nameWriter = new TpmWriter(expectedName);
        nameWriter.WriteUInt16((ushort)HmacKeyHarness.NameAlg);
        nameWriter.WriteBytes(SHA256.HashData(publicOctets[sizeof(ushort)..]));

        Assert.IsTrue(expectedName.AsSpan().SequenceEqual(key.Name.Span), "The Name must be nameAlg ‖ H_nameAlg(TPMT_PUBLIC) over the returned public area, unique included.");
    }

    /// <summary>
    /// The obfuscation property: including the seedValue in the <c>unique</c> computation "obfuscates unique so
    /// that the sensitive value cannot be determined", and "at least one of the sensitive area values will be
    /// provided by the TPM to ensure that unique is, in fact, unique" — two keys created from the SAME template
    /// with the SAME key value still differ in <c>unique</c> and in Name, because each object draws a fresh
    /// obfuscation value (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 1: Architecture, clause 23.3, Table 35 (the <c>seedValue</c> row)
    /// and clause 24.5.3.1; Part 2: Structures, clause 12.2.3.1, equation (8)).
    /// </summary>
    [TestMethod]
    public async Task SameTemplateSameKeyCreatesDifferInUniqueAndName()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SameTemplateSameKeyCreatesDifferInUniqueAndName), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacKeyHarness.LoadedHmacKey first = await HmacKeyHarness.CreateAndLoadHmacKeyWithPublicAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey second = await HmacKeyHarness.CreateAndLoadHmacKeyWithPublicAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(
            first.PublicArea!.PublicArea.Unique.GetKeyedHashUnique().SequenceEqual(second.PublicArea!.PublicArea.Unique.GetKeyedHashUnique()),
            "Two objects with identical templates and key values must differ in unique — each draws a fresh obfuscation value.");
        Assert.IsFalse(first.Name.Span.SequenceEqual(second.Name.Span), "Their Names must differ with their uniques.");
    }

    /// <summary>
    /// The fidelity consequence of equation (8): two sealed data objects created from the SAME template but
    /// with DIFFERENT data differ in Name — a sealed object's Name depends on what it seals
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.1, equation (8); Part 1: Architecture, clause 13).
    /// </summary>
    [TestMethod]
    public async Task SameTemplateDifferentDataSealedObjectsDifferInName()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SameTemplateDifferentDataSealedObjectsDifferInName), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        (_, byte[] firstName) = await PolicySweepHarness.SealAndLoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, new byte[] { 1, 2, 3, 4 }, ReadOnlyMemory<byte>.Empty, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        (_, byte[] secondName) = await PolicySweepHarness.SealAndLoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, new byte[] { 5, 6, 7, 8 }, ReadOnlyMemory<byte>.Empty, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(firstName.AsSpan().SequenceEqual(secondName), "Sealed objects with different data must differ in Name.");
    }

    /// <summary>
    /// The binding at <c>TPM2_Load()</c> sits behind the wrap's integrity check: a public area whose
    /// <c>unique</c> has been tampered with names a DIFFERENT object, so the private blob's outer HMAC — which
    /// binds the Name, and the Name covers the unique — answers <c>TPM_RC_INTEGRITY</c> before the
    /// <c>TPM_RC_BINDING</c> recomputation could run
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, Clause 19, equation 36; Part 3: Commands, clause 12.2).
    /// </summary>
    [TestMethod]
    public async Task LoadWithATamperedUniqueIsRefusedWithIntegrity()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(LoadWithATamperedUniqueIsRefusedWithIntegrity), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (HMAC key) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        //The unique's octets are the tail of the marshaled TPMT_PUBLIC (type ‖ nameAlg ‖ attributes ‖
        //authPolicy ‖ parameters ‖ unique); flipping the last octet tampers the unique alone.
        int publicSize = created.OutPublic.GetSerializedSize();
        using IMemoryOwner<byte> mutated = pool.Rent(publicSize);
        Span<byte> octets = mutated.Memory.Span[..publicSize];
        var writer = new TpmWriter(octets);
        created.OutPublic.WriteTo(ref writer);
        octets[^1] ^= 0x01;

        var reader = new TpmReader(octets);
        using Tpm2bPublic tampered = Tpm2bPublic.Parse(ref reader, pool);
        TpmResult<LoadResponse> result = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, created.OutPrivate, tampered, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INTEGRITY, result.ResponseCode, "A tampered unique changes the Name, so the outer HMAC must refuse the blob with TPM_RC_INTEGRITY before any binding recomputation.");
    }

    /// <summary>
    /// The binding's reachable site: a bare duplicate carries no integrity wrap, so <c>TPM2_Import()</c>
    /// recomputes the <c>unique</c> over the presented sensitive area and refuses a public area whose
    /// <c>unique</c> does not re-derive with <c>TPM_RC_BINDING</c> — proved both ways with the exact off-TPM
    /// value: the bare fixture's seedValue is all zeros, so <c>unique = SHA-256(0³² ‖ bits)</c> is computable;
    /// the empty-unique public area is refused with the metered pool balanced across the refusal, and the
    /// matching one imports, loads, and — the accepted binding being over the RIGHT bits rather than a vacuous
    /// compare — returns RFC 4231 case 1's published HMAC
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.1, equation (8); Part 3: Commands, clause 13.3.1;
    /// <see href="https://www.rfc-editor.org/rfc/rfc4231#section-4.2">RFC 4231, section 4.2</see>).
    /// </summary>
    [TestMethod]
    public async Task ImportOfABareDuplicateChecksTheUniqueBinding()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ImportOfABareDuplicateChecksTheUniqueBinding), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        byte[] seedThenBits = new byte[32 + SampleKey.Length];
        SampleKey.CopyTo(seedThenBits, 32);
        byte[] expectedUnique = SHA256.HashData(seedThenBits);

        long baseline = trackingPool.OutstandingCount;

        using(Tpm2bPublic unboundPublic = DuplicableHmacKeyPublic(pool))
        using(Tpm2bPrivate duplicate = BareSensitive(pool, seedSize: 32, SampleKey))
        {
            TpmResult<ImportResponse> refused = await HmacKeyHarness.ImportAsync(
                tpm, registry, pool, parentHandle, unboundPublic, duplicate, Tpm2bEncryptedSecret.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_BINDING, refused.ResponseCode, "A public area whose unique does not re-derive from the presented sensitive area must be refused with TPM_RC_BINDING.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The BINDING refusal must release every carrier the import rented.");

        using Tpm2bPublic boundPublic = DuplicableHmacKeyPublic(pool, expectedUnique);
        using Tpm2bPrivate boundDuplicate = BareSensitive(pool, seedSize: 32, SampleKey);
        TpmResult<ImportResponse> imported = await HmacKeyHarness.ImportAsync(
            tpm, registry, pool, parentHandle, boundPublic, boundDuplicate, Tpm2bEncryptedSecret.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(imported.IsSuccess, $"A public area carrying SHA-256(0³² ‖ bits) must import: '{imported.ResponseCode}'.");
        using ImportResponse importedValue = imported.Value;

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parentHandle, importedValue.OutPrivate, boundPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (imported bare key) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        TpmResult<HmacResponse> hmacResult = await HmacKeyHarness.HmacAsync(
            tpm, registry, pool, loaded.ObjectHandle.Value, Rfc4231Case1Data, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(hmacResult.IsSuccess, $"TPM2_HMAC() over the imported key failed: '{hmacResult.ResponseCode}'.");
        using HmacResponse hmacValue = hmacResult.Value;

        Assert.IsTrue(hmacValue.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The imported bits are RFC 4231 case 1's key, so the HMAC must be the published value.");
    }

    /// <summary>
    /// "unique := H_nameAlg(seedValue ‖ sensitive)" holds for a sealed data object (scheme <c>TPM_ALG_NULL</c>)
    /// as for a key: its <c>outPublic</c> carries a <c>unique</c> one nameAlg digest wide
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.1, equation (8)).
    /// </summary>
    [TestMethod]
    public async Task SealedObjectUniqueIsTheNameAlgDigestWidth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SealedObjectUniqueIsTheNameAlgDigestWidth), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecretBytes, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(HmacKeyHarness.NameAlg, pool, noDa: true);
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateAsync(tpm, registry, pool, parent.ObjectHandle.Value, inSensitive, template, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (sealed data) failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        Assert.HasCount(32, created.OutPublic.PublicArea.Unique.GetKeyedHashUnique().ToArray(), "A sealed data object's unique must be one SHA-256 nameAlg digest wide.");
    }

    /// <summary>
    /// The TPM-generated arm of the sensitive value — <c>sensitiveDataOrigin</c> SET with an empty
    /// <c>inSensitive.data</c>, "a TPM-generated key value that is the size of the digest produced by the
    /// nameAlg" — feeds the same <c>unique</c> computation: the public area carries a digest-width
    /// <c>unique</c> and the returned Name recomputes off-TPM over the returned public area
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 12.1 (keyedHash rule 4); Part 2: Structures, clause
    /// 12.2.3.1, equation (8); Part 1: Architecture, clause 13, Table 9 for the Name).
    /// </summary>
    [TestMethod]
    public async Task CreateWithGeneratedBitsFillsTheKeyedHashUniqueAndTheNameCoversIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(CreateWithGeneratedBitsFillsTheKeyedHashUniqueAndTheNameCoversIt), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyWithPublicAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(32, key.PublicArea!.PublicArea.Unique.GetKeyedHashUnique().ToArray(), "A generated-bits HMAC key's unique must be one SHA-256 nameAlg digest wide.");

        int publicSize = key.PublicArea!.GetSerializedSize();
        using IMemoryOwner<byte> marshaled = pool.Rent(publicSize);
        Span<byte> publicOctets = marshaled.Memory.Span[..publicSize];
        var writer = new TpmWriter(publicOctets);
        key.PublicArea!.WriteTo(ref writer);

        byte[] expectedName = new byte[sizeof(ushort) + 32];
        var nameWriter = new TpmWriter(expectedName);
        nameWriter.WriteUInt16((ushort)HmacKeyHarness.NameAlg);
        nameWriter.WriteBytes(SHA256.HashData(publicOctets[sizeof(ushort)..]));

        Assert.IsTrue(expectedName.AsSpan().SequenceEqual(key.Name.Span), "The Name must be nameAlg ‖ H_nameAlg(TPMT_PUBLIC) over the returned public area, unique included.");
    }

    /// <summary>
    /// A creation template's <c>unique</c> is whatever the caller sends and is OVERWRITTEN by the computed
    /// value, never refused: <c>outPublic</c> "is the input template with its unique filled in", the reference
    /// copying the template whole and then filling the field
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 12.1; Part 2: Structures, clause 12.2.3.1, equation (8)).
    /// </summary>
    [TestMethod]
    public async Task CreateOverwritesACallerSuppliedTemplateUniqueRatherThanRefusingIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(CreateOverwritesACallerSuppliedTemplateUniqueRatherThanRefusingIt), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] callerUnique = new byte[32];
        callerUnique.AsSpan().Fill(0xAA);
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForHmacKey(SampleKey, ReadOnlySpan<byte>.Empty, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateKeyedHashTemplate(
            HmacKeyHarness.NameAlg, BoundAttributes | TpmaObject.SIGN_ENCRYPT, TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA256), authPolicy: default, pool, callerUnique);
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateAsync(tpm, registry, pool, parent.ObjectHandle.Value, inSensitive, template, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"A template carrying a caller-supplied unique must not be refused: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        ReadOnlySpan<byte> unique = created.OutPublic.PublicArea.Unique.GetKeyedHashUnique();
        Assert.HasCount(32, unique.ToArray(), "The returned unique must be one nameAlg digest wide.");
        Assert.IsFalse(unique.SequenceEqual(callerUnique), "The returned unique must be the computed value, not the caller's octets.");
    }

    /// <summary>
    /// <c>TPM2_ReadPublic()</c> "allows access to the public area of a loaded object" — the area it answers with
    /// carries the same filled <c>unique</c> the creation returned
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 12.4.1; Part 2: Structures, clause 12.2.3.1, equation (8)).
    /// </summary>
    [TestMethod]
    public async Task ReadPublicEchoesTheFilledKeyedHashUnique()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ReadPublicEchoesTheFilledKeyedHashUnique), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using HmacKeyHarness.LoadedHmacKey key = await HmacKeyHarness.CreateAndLoadHmacKeyWithPublicAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, SampleKey, TpmAlgIdConstants.TPM_ALG_SHA256, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ReadPublicInput input = ReadPublicInput.ForHandle(TpmiDhObject.FromValue(key.Handle));
        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadPublic() (HMAC key) failed: '{result.ResponseCode}'.");
        using ReadPublicResponse response = result.Value;

        ReadOnlySpan<byte> echoed = response.PublicArea.PublicArea.Unique.GetKeyedHashUnique();
        Assert.IsFalse(echoed.IsEmpty, "The echoed public area must carry the filled unique.");
        Assert.IsTrue(echoed.SequenceEqual(key.PublicArea!.PublicArea.Unique.GetKeyedHashUnique()), "TPM2_ReadPublic() must echo the unique the creation returned.");
    }

    /// <summary>
    /// A restricted decryption KEYEDHASH object — a derivation parent, <c>restricted</c> and <c>decrypt</c> both
    /// SET over an XOR scheme — takes the other arm of the reference's <c>unique</c> computation: an HMAC keyed by
    /// the obfuscation value over the sensitive value, not the plain hash of their concatenation. Proved at the
    /// binding's reachable site with the exact off-TPM values (the bare fixture's seedValue is all zeros): a
    /// public area carrying <c>HMAC-SHA-256(key = 0³², bits)</c> imports, while one carrying the plain
    /// <c>SHA-256(0³² ‖ bits)</c> is refused with <c>TPM_RC_BINDING</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.1 (Part 4 <c>CryptComputeSymmetricUnique</c>'s
    /// parent arm, Detailed Actions); Part 3: Commands, clause 13.3.1).
    /// </summary>
    [TestMethod]
    public async Task ImportOfABareRestrictedXorObjectBindsThroughTheHmacUnique()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ImportOfABareRestrictedXorObjectBindsThroughTheHmacUnique), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        byte[] seedThenBits = new byte[32 + SampleKey.Length];
        SampleKey.CopyTo(seedThenBits, 32);
        byte[] hashUnique = SHA256.HashData(seedThenBits);
        byte[] hmacUnique = HMACSHA256.HashData(new byte[32], SampleKey);

        using(Tpm2bPublic hashPublic = RestrictedXorObjectPublic(pool, hashUnique))
        using(Tpm2bPrivate duplicate = BareSensitive(pool, seedSize: 32, SampleKey))
        {
            TpmResult<ImportResponse> refused = await HmacKeyHarness.ImportAsync(
                tpm, registry, pool, parentHandle, hashPublic, duplicate, Tpm2bEncryptedSecret.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_BINDING, refused.ResponseCode, "A derivation parent's public area carrying the plain-hash unique must be refused with TPM_RC_BINDING — its arm is the HMAC.");
        }

        using Tpm2bPublic hmacPublic = RestrictedXorObjectPublic(pool, hmacUnique);
        using Tpm2bPrivate boundDuplicate = BareSensitive(pool, seedSize: 32, SampleKey);
        TpmResult<ImportResponse> imported = await HmacKeyHarness.ImportAsync(
            tpm, registry, pool, parentHandle, hmacPublic, boundDuplicate, Tpm2bEncryptedSecret.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(imported.IsSuccess, $"A derivation parent's public area carrying HMAC(seedValue, bits) must import: '{imported.ResponseCode}'.");
        using ImportResponse importedValue = imported.Value;

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parentHandle, importedValue.OutPrivate, hmacPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (imported derivation parent) failed: '{loadResult.ResponseCode}'.");
        loadResult.Value.Dispose();
    }

    /// <summary>The marshaled public area of a duplicable, caller-keyed HMAC-SHA-256 key — the <c>objectPublic</c> a bare import presents.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="unique">The <c>unique</c> value the public area carries — <c>H_nameAlg(seedValue ‖ bits)</c>, TPM 2.0 Library Part 2, clause 12.2.3.1, equation (8) — or empty for a public area that binds to no sensitive area.</param>
    /// <returns>The public area; the caller disposes it.</returns>
    private static Tpm2bPublic DuplicableHmacKeyPublic(BaseMemoryPool pool, ReadOnlySpan<byte> unique = default) =>
        Tpm2bPublic.CreateKeyedHashTemplate(
            HmacKeyHarness.NameAlg,
            TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA | TpmaObject.SIGN_ENCRYPT,
            TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA256), authPolicy: default, pool, unique);

    /// <summary>The marshaled public area of a duplicable restricted XOR-scheme decryption object — a derivation parent over SHA-256 with KDF1_SP800_108 — the <c>objectPublic</c> a bare import presents.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="unique">The <c>unique</c> value the public area carries — the parent arm's <c>HMAC_nameAlg(seedValue, bits)</c> (Part 4 <c>CryptComputeSymmetricUnique</c>) when it is to bind.</param>
    /// <returns>The public area; the caller disposes it.</returns>
    private static Tpm2bPublic RestrictedXorObjectPublic(BaseMemoryPool pool, ReadOnlySpan<byte> unique) =>
        Tpm2bPublic.CreateKeyedHashTemplate(
            HmacKeyHarness.NameAlg,
            TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA | TpmaObject.DECRYPT | TpmaObject.RESTRICTED | TpmaObject.SENSITIVE_DATA_ORIGIN,
            TpmsKeyedHashParms.Xor(TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108), authPolicy: default, pool, unique);

    /// <summary>
    /// Marshals a bare <c>TPM2B_SENSITIVE</c> for a KEYEDHASH object (Part 2, Table 240): an empty authValue
    /// padded to 64 octets, a <paramref name="seedSize"/>-octet seedValue, and <paramref name="bits"/>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="seedSize">The seedValue width to declare.</param>
    /// <param name="bits">The key value.</param>
    /// <returns>The marshaled bare sensitive area, wrapped as the opaque blob a bare duplicate's content is; the caller disposes it.</returns>
    private static Tpm2bPrivate BareSensitive(BaseMemoryPool pool, int seedSize, ReadOnlySpan<byte> bits)
    {
        const int PaddedAuthSize = 64;
        int interior = sizeof(ushort) + (sizeof(ushort) + PaddedAuthSize) + (sizeof(ushort) + seedSize) + (sizeof(ushort) + bits.Length);
        int length = sizeof(ushort) + interior;

        using IMemoryOwner<byte> zerosOwner = pool.Rent(PaddedAuthSize);
        Span<byte> zeros = zerosOwner.Memory.Span[..PaddedAuthSize];
        zeros.Clear();

        using IMemoryOwner<byte> owner = pool.Rent(length);
        Span<byte> marshaled = owner.Memory.Span[..length];
        var writer = new TpmWriter(marshaled);
        writer.WriteUInt16((ushort)interior);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_KEYEDHASH);
        writer.WriteTpm2b(zeros);
        writer.WriteTpm2b(zeros[..seedSize]);
        writer.WriteTpm2b(bits);

        return Tpm2bPrivate.Create(marshaled, pool);
    }

    /// <summary>Creates an operational simulator, device, registry, and storage parent, returning the handle.</summary>
    /// <param name="name">A per-test simulator identifier.</param>
    /// <returns>The registry, device, simulator, and storage parent handle.</returns>
    private async Task<(TpmResponseRegistry Registry, TpmDevice Tpm, TpmSimulator Simulator, uint ParentHandle)> SetUpAsync(string name)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(name, pool, TestContext.CancellationToken).ConfigureAwait(false);
        TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        parent.Dispose();

        return (registry, tpm, simulator, parentHandle);
    }
}
