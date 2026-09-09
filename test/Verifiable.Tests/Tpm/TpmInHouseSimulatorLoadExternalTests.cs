using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
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
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the plain (<c>TPM_ST_NO_SESSIONS</c>) form of <c>TPM2_LoadExternal()</c> against the in-house
/// behavioural <see cref="TpmSimulator"/> through the production command path (<see cref="TpmCommandExecutor"/>
/// with <see cref="LoadExternalInput"/> and the real codecs): keys minted OFF the TPM with the framework's own
/// ECDSA and RSA are loaded public-only under a hierarchy or with their sensitive area under <c>TPM_RH_NULL</c>,
/// the returned Name is checked against an independent transcription, the loaded objects verify and sign against
/// off-TPM oracles, and every attribute, hierarchy, consistency and wire-shape refusal is pinned (TPM 2.0 Library
/// Part 3, clause 12.3; Part 2, clause 8.3; Part 4 <c>CryptValidateKeys</c>).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorLoadExternalTests
{
    /// <summary>The Name algorithm used throughout unless a case names another.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width of <see cref="NameAlg"/>.</summary>
    private const int DigestSize = 32;

    /// <summary>The width of a P-256 coordinate or scalar.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus width in bits.</summary>
    private const ushort RsaKeyBits = 2048;

    /// <summary>The <c>TPM_ALG_SYMCIPHER</c> selector (TPM 2.0 Library Part 2, clause 6.3, Table 8), which the sensitive-area union refuses.</summary>
    private const ushort SymCipherSelector = 0x0025;

    /// <summary>A <c>TPMI_ALG_PUBLIC</c> selector this simulator's implemented profile does not recognize at all (TPM 2.0 Library Part 2, clause 6.3, Table 8).</summary>
    private const ushort UnknownPublicTypeSelector = 0x7FFF;

    /// <summary>The attribute word of an external RSA storage-shaped restricted decryption key.</summary>
    private const TpmaObject RestrictedDecryptAttributes = TpmaObject.RESTRICTED | TpmaObject.DECRYPT | TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA;

    /// <summary>The order of the P-256 group, the first scalar outside the private-key range.</summary>
    private static byte[] P256Order { get; } = Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

    /// <summary>The message the signatures are over.</summary>
    private static byte[] MessageBytes { get; } = "Load me from outside the TPM."u8.ToArray();

    /// <summary>The secret a sealed data object carries.</summary>
    private static byte[] SealedSecret { get; } = "external sealed secret"u8.ToArray();

    /// <summary>RFC 4231 test case 1's 20-octet key.</summary>
    private static byte[] Rfc4231Case1Key { get; } = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    /// <summary>RFC 4231 test case 1's data, "Hi There".</summary>
    private static byte[] Rfc4231Case1Data { get; } = Convert.FromHexString("4869205468657265");

    /// <summary>RFC 4231 test case 1's published HMAC-SHA-256 tag.</summary>
    private static byte[] Rfc4231Case1Sha256 { get; } = Convert.FromHexString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /// <summary>The attribute word of an external signing key: unbound, caller-supplied, USER-role by password, dictionary-attack exempt.</summary>
    private const TpmaObject ExternalSigningAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;

    /// <summary>The attribute word of an external sealed data object.</summary>
    private const TpmaObject ExternalSealedAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "This command is used to load an object that is not a Protected Object into the TPM. The command allows
    /// loading of a public area or both a public and sensitive area": a public-only ECC signing key under the
    /// owner hierarchy loads to a transient handle, "The command returns a handle for the loaded object and the
    /// Name that the TPM computed for inPublic.public" — <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c> transcribed
    /// independently — <c>TPM2_ReadPublic()</c> echoes it with "The Qualified Name for the object will be the
    /// same as its Name", an off-TPM ECDSA signature verifies with a REAL ticket, and the key cannot sign
    /// (<c>TPM_RC_AUTH_UNAVAILABLE</c>, Part 3, clause 5.6, check 1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalPublicOnlyEccKeyUnderOwnerLoadsNamesAndVerifiesButCannotSign()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalPublicOnlyEccKeyUnderOwnerLoadsNamesAndVerifiesButCannotSign), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] expectedName = TranscribeEccName(pool, NameAlg, ExternalSigningAttributes, key);
        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A public-only ECC key must load under the owner hierarchy (Part 3, clause 12.3.1), but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        Assert.IsTrue(loaded.ObjectHandle.IsTransient, "The loaded object is addressed by a transient handle (Part 2, clause 7.2).");
        Assert.IsTrue(loaded.Name.Span.SequenceEqual(expectedName), "The returned Name is nameAlg ‖ H_nameAlg(TPMT_PUBLIC), transcribed independently (Part 3, clause 12.3.1).");

        using ReadPublicResponse readPublic = await ReadPublicAsync(tpm, registry, pool, loaded.ObjectHandle).ConfigureAwait(false);
        Assert.IsTrue(readPublic.Name.Span.SequenceEqual(expectedName), "TPM2_ReadPublic() echoes the same Name.");
        Assert.IsTrue(readPublic.QualifiedName.Span.SequenceEqual(expectedName), "The Qualified Name for the object will be the same as its Name (Part 3, clause 12.3.1).");

        byte[] digest = SHA256.HashData(MessageBytes);
        byte[] signature = key.Key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        using VerifySignatureResponse verified = await VerifyEcdsaAsync(tpm, registry, pool, loaded.ObjectHandle, digest, signature).ConfigureAwait(false);
        Assert.AreEqual(TpmStConstants.TPM_ST_VERIFIED, verified.Validation.Tag, "The ticket tag is TPM_ST_VERIFIED.");
        Assert.AreEqual(TpmiRhHierarchy.Owner, verified.Validation.Hierarchy, "The ticket carries the object's hierarchy.");
        Assert.IsFalse(verified.Validation.IsNull, "A public key under a real hierarchy with a real Name algorithm earns a REAL ticket (Part 3, clause 12.3.1).");
        Assert.HasCount(DigestSize, verified.Validation.Hmac, "The ticket's HMAC is one SHA-256 digest wide.");

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(loaded.ObjectHandle, digest, NameAlg, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, signResult.ResponseCode, "A public-only object has no sensitive portion to authorize a signature with (Part 3, clause 5.6, check 1).");
    }

    /// <summary>
    /// "The hierarchy parameter provides this association": a public-only key loads under the endorsement and
    /// platform hierarchies alike, and the ticket a verification mints carries that hierarchy.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    /// <param name="isEndorsement">Whether the key is associated with the endorsement hierarchy (else the platform hierarchy).</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task LoadExternalPublicOnlyEccKeyAssociatesWithTheNamedHierarchy(bool isEndorsement)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalPublicOnlyEccKeyAssociatesWithTheNamedHierarchy)}-{isEndorsement}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();
        TpmiRhHierarchy hierarchy = isEndorsement ? TpmiRhHierarchy.Endorsement : TpmiRhHierarchy.Platform;

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, hierarchy, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A public-only key must load under {hierarchy.Value:X8} (Part 3, clause 12.3.1), but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        byte[] digest = SHA256.HashData(MessageBytes);
        using VerifySignatureResponse verified = await VerifyEcdsaAsync(tpm, registry, pool, loaded.ObjectHandle, digest, key.Key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)).ConfigureAwait(false);
        Assert.AreEqual(hierarchy, verified.Validation.Hierarchy, "The ticket carries the hierarchy the load named.");
        Assert.IsFalse(verified.Validation.IsNull, "A real hierarchy earns a real ticket.");
    }

    /// <summary>
    /// "If hierarchy is TPM_RH_NULL or nameAlg is TPM_ALG_NULL, a ticket produced using the object shall be a NULL
    /// Ticket": a public-only key under <c>TPM_RH_NULL</c> verifies, and the ticket is the NULL tuple — the
    /// NULL hierarchy with an empty hmac.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalPublicOnlyEccKeyUnderNullVerifiesWithANullTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalPublicOnlyEccKeyUnderNullVerifiesWithANullTicket), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A public-only key must load under TPM_RH_NULL, but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        byte[] digest = SHA256.HashData(MessageBytes);
        using VerifySignatureResponse verified = await VerifyEcdsaAsync(tpm, registry, pool, loaded.ObjectHandle, digest, key.Key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)).ConfigureAwait(false);
        Assert.AreEqual(TpmStConstants.TPM_ST_VERIFIED, verified.Validation.Tag, "The ticket tag is still TPM_ST_VERIFIED.");
        Assert.IsTrue(verified.Validation.IsNull, "A TPM_RH_NULL object's ticket is the NULL tuple (Part 3, clause 12.3.1).");
        Assert.IsTrue(verified.Validation.Hierarchy.IsNull, "The NULL ticket names TPM_RH_NULL.");
        Assert.IsTrue(verified.Validation.Hmac.IsEmpty, "The NULL ticket's hmac is the Empty Buffer.");
    }

    /// <summary>
    /// A hierarchy disabled through <c>TPM2_HierarchyControl()</c> admits no object: a public-only load under
    /// the disabled owner hierarchy is refused with <c>TPM_RC_HIERARCHY</c>, the disabled hierarchy's standing
    /// answer (TPM 2.0 Library Part 3, clause 24.2.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalUnderADisabledHierarchyIsRefusedWithHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalUnderADisabledHierarchyIsRefusedWithHierarchy), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        await DisableOwnerHierarchyAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 2), result.ResponseCode, "A disabled hierarchy admits no external object (Part 3, clause 24.2.1).");
    }

    /// <summary>
    /// "If nameAlg is TPM_ALG_NULL, then the Name is the Empty Buffer": a public-only key with the NULL Name
    /// algorithm loads, the returned <c>name</c> is <c>00 00</c>, <c>TPM2_ReadPublic()</c> answers an empty Name
    /// and Qualified Name, and "a ticket produced using the object shall be a NULL Ticket".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalWithANullNameAlgLoadsANamelessObjectWhoseTicketsAreNull()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalWithANullNameAlgLoadsANamelessObjectWhoseTicketsAreNull), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, TpmAlgIdConstants.TPM_ALG_NULL, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A public-only key with nameAlg TPM_ALG_NULL must load (Part 3, clause 12.3.1), but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;
        Assert.IsTrue(loaded.Name.IsEmpty, "If nameAlg is TPM_ALG_NULL, then the Name is the Empty Buffer (Part 3, clause 12.3.1).");

        using ReadPublicResponse readPublic = await ReadPublicAsync(tpm, registry, pool, loaded.ObjectHandle).ConfigureAwait(false);
        Assert.IsTrue(readPublic.Name.IsEmpty, "TPM2_ReadPublic() answers the Empty Buffer as the Name.");
        Assert.IsTrue(readPublic.QualifiedName.IsEmpty, "The Qualified Name of a nameless object is the Empty Buffer too.");

        byte[] digest = SHA256.HashData(MessageBytes);
        using VerifySignatureResponse verified = await VerifyEcdsaAsync(tpm, registry, pool, loaded.ObjectHandle, digest, key.Key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)).ConfigureAwait(false);
        Assert.IsTrue(verified.Validation.IsNull, "nameAlg TPM_ALG_NULL makes every ticket the NULL Ticket (Part 3, clause 12.3.1).");
    }

    /// <summary>
    /// "If a key is loaded with hierarchy set to TPM_RH_NULL, then TPM2_VerifySignature(),
    /// TPM2_VerifySequenceComplete() or TPM2_VerifyDigestSignature() will produce a NULL Ticket of the required
    /// type" — the same NULL-ticket rule a NULL <c>nameAlg</c> triggers independently of hierarchy: a public-only
    /// key under the OWNER hierarchy with <c>nameAlg TPM_ALG_NULL</c> mints a NULL ticket from every one of the
    /// three named commands, <c>TPM2_VerifySequenceStart()</c>/<c>TPM2_SequenceUpdate()</c> included on the path
    /// to <c>TPM2_VerifySequenceComplete()</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    /// <param name="isRsa">Whether the loaded key is RSA (else ECC).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task LoadExternalWithANullNameAlgMintsNullTicketsOnEveryVerifyCommand(bool isRsa)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalWithANullNameAlgMintsNullTicketsOnEveryVerifyCommand)}-{isRsa}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        byte[] digest = SHA256.HashData(MessageBytes);

        if(isRsa)
        {
            using RsaKeyMaterial key = RsaKeyMaterial.Generate();
            TpmResult<LoadExternalResponse> result = await LoadRsaAsync(
                tpm, registry, pool, TpmiRhHierarchy.Owner, ExternalSigningAttributes, TpmtRsaScheme.Rsassa(NameAlg), key.Modulus, nameAlg: TpmAlgIdConstants.TPM_ALG_NULL).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A public-only RSA key with nameAlg TPM_ALG_NULL must load, but failed: '{result.ResponseCode}'.");
            using LoadExternalResponse loaded = result.Value;
            byte[] signature = key.Key.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            await AssertNullTicketsAcrossVerifyCommandsAsync(tpm, registry, pool, loaded.ObjectHandle, digest, signature, isRsa: true).ConfigureAwait(false);
        }
        else
        {
            using EccKeyMaterial key = EccKeyMaterial.Generate();
            TpmResult<LoadExternalResponse> result = await LoadEccAsync(
                tpm, registry, pool, TpmiRhHierarchy.Owner, TpmAlgIdConstants.TPM_ALG_NULL, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A public-only ECC key with nameAlg TPM_ALG_NULL must load, but failed: '{result.ResponseCode}'.");
            using LoadExternalResponse loaded = result.Value;
            byte[] signature = key.Key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

            await AssertNullTicketsAcrossVerifyCommandsAsync(tpm, registry, pool, loaded.ObjectHandle, digest, signature, isRsa: false).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A Name algorithm outside the implemented profile is refused with <c>TPM_RC_HASH</c> (TPM 2.0 Library Part 2,
    /// clause 12.2.4, Table 235: <c>nameAlg</c> is <c>TPMI_ALG_HASH</c>, whose unimplemented values answer
    /// <c>TPM_RC_HASH</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalWithANameAlgOutsideTheProfileIsRefusedWithHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalWithANameAlgOutsideTheProfileIsRefusedWithHash), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, TpmAlgIdConstants.TPM_ALG_SHA3_256, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, parameterIndex: 1), result.ResponseCode,
            "Table 22: inPublic is TPM2_LoadExternal()'s second parameter (index 1); a nameAlg this TPM does not implement is TPM_RC_HASH there (Part 2, clause 12.2.4, Table 235).");
    }

    /// <summary>
    /// "Typical use for loading both a public and sensitive area is to allow the TPM to be used as a crypto
    /// accelerator": an ECC key loaded with its scalar under <c>TPM_RH_NULL</c> signs with its (empty) password,
    /// the framework's own ECDSA accepts the signature against the same public point, and the Name recomputes
    /// from the public area.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalFullEccKeyUnderNullSignsForTheFrameworkToVerify()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalFullEccKeyUnderNullSignsForTheFrameworkToVerify), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] expectedName = TranscribeEccName(pool, NameAlg, ExternalSigningAttributes, key);
        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, ExternalSigningAttributes, key.X, key.Y, scalar: key.D).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"An ECC key with its sensitive area must load under TPM_RH_NULL (Part 3, clause 12.3.1), but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;
        Assert.IsTrue(loaded.Name.Span.SequenceEqual(expectedName), "The Name recomputes from the public area (Part 3, clause 12.3.1).");

        byte[] digest = SHA256.HashData(MessageBytes);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(loaded.ObjectHandle, digest, NameAlg, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"The loaded key must sign with its empty password, but failed: '{signResult.ResponseCode}'.");
        using SignResponse signed = signResult.Value;

        byte[] p1363 = ConcatenateP1363(signed.Signature.SignatureR!.AsReadOnlySpan(), signed.Signature.SignatureS!.AsReadOnlySpan());
        Assert.IsTrue(key.Key.VerifyHash(digest, p1363, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "The framework's ECDSA accepts the TPM's signature against the imported key's public point.");
    }

    /// <summary>
    /// "If the public and sensitive portions of the object are loaded, hierarchy is required to be TPM_RH_NULL":
    /// a full ECC load under the owner hierarchy is refused with <c>TPM_RC_HIERARCHY</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalFullKeyUnderARealHierarchyIsRefusedWithHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalFullKeyUnderARealHierarchyIsRefusedWithHierarchy), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes, key.X, key.Y, scalar: key.D).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 2), result.ResponseCode, "A sensitive-bearing external object may only be loaded under TPM_RH_NULL (Part 3, clause 12.3.1).");
    }

    /// <summary>
    /// "In particular, fixedTPM, fixedParent, and restricted shall be CLEAR if inPrivate is not the Empty
    /// Buffer": a full load whose public area sets any of the three is refused with <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    /// <param name="boundAttribute">The attribute the case sets.</param>
    [TestMethod]
    [DataRow(TpmaObject.FIXED_TPM)]
    [DataRow(TpmaObject.FIXED_PARENT)]
    [DataRow(TpmaObject.RESTRICTED)]
    public async Task LoadExternalFullKeyWithABoundOrRestrictedAttributeIsRefusedWithAttributes(TpmaObject boundAttribute)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalFullKeyWithABoundOrRestrictedAttributeIsRefusedWithAttributes)}-{boundAttribute}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, ExternalSigningAttributes | boundAttribute, key.X, key.Y, scalar: key.D).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode, $"{boundAttribute} shall be CLEAR if inPrivate is not the Empty Buffer (Part 3, clause 12.3.1).");
    }

    /// <summary>
    /// The three-CLEAR rule binds a sensitive-bearing load only: a public-only load may carry <c>restricted</c>
    /// SET, since "The duplication status of a public key needs to be able to be the same as the full key which
    /// may be resident on a different TPM".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalPublicOnlyKeyWithRestrictedSetLoads()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalPublicOnlyKeyWithRestrictedSetLoads), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(
            tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes | TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.RESTRICTED, key.X, key.Y).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A public-only load carries whatever attributes the full key has (Part 3, clause 12.3.1), but failed: '{result.ResponseCode}'.");
        result.Value.Dispose();
    }

    /// <summary>
    /// Table 37's Reserved bits — bit 0, bit 3, bits 15:12, and bits 31:20 — "shall be zero" (TPM 2.0 Library
    /// Part 2, clause 8.3.2): the host-side <see cref="Tpm2bPublic.Parse"/> does not judge attributes, so an
    /// otherwise well-formed ECC public area carrying one SET reaches the simulator, which refuses it with
    /// <c>TPM_RC_RESERVED_BITS</c> (Part 4 <c>TPMA_OBJECT_Unmarshal</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    /// <param name="bit">The Reserved bit under test.</param>
    [TestMethod]
    [DataRow(0x0000_0001u)]
    [DataRow(0x0000_0008u)]
    [DataRow(0x0000_1000u)]
    [DataRow(0x0010_0000u)]
    public async Task LoadExternalPublicAreaWithAReservedAttributeBitIsRefusedWithReservedBits(uint bit)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalPublicAreaWithAReservedAttributeBitIsRefusedWithReservedBits)}-{bit:X8}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] marshaled;
        using(Tpm2bPublic template = BuildEccPublic(pool, NameAlg, ExternalSigningAttributes, key.X, key.Y))
        {
            marshaled = MarshalPublic(template);
        }

        //TPM2B_PUBLIC: size(2) ‖ type(2) ‖ nameAlg(2), then the 4-octet objectAttributes this case ORs the bit into.
        const int AttributesOffset = sizeof(ushort) + sizeof(ushort) + sizeof(ushort);
        uint attributes = BinaryPrimitives.ReadUInt32BigEndian(marshaled.AsSpan(AttributesOffset, sizeof(uint)));
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(AttributesOffset, sizeof(uint)), attributes | bit);

        TpmResult<LoadExternalResponse> result = await LoadMarshaledPublicAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, marshaled).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_RESERVED_BITS, parameterIndex: 1), result.ResponseCode,
            $"Table 22: inPublic is TPM2_LoadExternal()'s second parameter (index 1); a Reserved bit 0x{bit:X8} SET is TPM_RC_RESERVED_BITS there (Part 2, clause 8.3.2, Table 37).");
    }

    /// <summary>
    /// "For an ECC object, the TPM will verify that the public key is on the curve of the key before the public
    /// area is used": a point off P-256 is refused with <c>TPM_RC_ECC_POINT</c> for a public-only load, under a
    /// real Name algorithm and under <c>TPM_ALG_NULL</c> alike — "The TPM will still perform cryptographic
    /// validity checks (e.g., the ECC public point is on the curve)".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    /// <param name="isNullNameAlg">Whether the public area's Name algorithm is <c>TPM_ALG_NULL</c>.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task LoadExternalOffCurvePointIsRefusedWithEccPoint(bool isNullNameAlg)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalOffCurvePointIsRefusedWithEccPoint)}-{isNullNameAlg}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] offCurveY = (byte[])key.Y.Clone();
        offCurveY[^1] ^= 0x01;
        TpmAlgIdConstants nameAlg = isNullNameAlg ? TpmAlgIdConstants.TPM_ALG_NULL : NameAlg;

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, nameAlg, ExternalSigningAttributes, key.X, offCurveY).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_ECC_POINT, result.ResponseCode, "A public point off the curve is TPM_RC_ECC_POINT (Part 3, clause 12.3.1; Part 4 CryptValidateKeys).");
    }

    /// <summary>
    /// A coordinate narrower than the curve's field width is <c>TPM_RC_KEY</c> (Part 4 <c>CryptValidateKeys</c>:
    /// an ECC public point whose coordinate size does not match the curve).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalCoordinateOfTheWrongWidthIsRefusedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalCoordinateOfTheWrongWidthIsRefusedWithKey), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes, key.X.AsMemory(1), key.Y).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "A coordinate of the wrong width for the curve is TPM_RC_KEY (Part 4 CryptValidateKeys).");
    }

    /// <summary>
    /// "The TPM will validate that the size of the key in the sensitive area is consistent with the size indicated
    /// in the public area. If it is not, the TPM shall return TPM_RC_KEY_SIZE": a scalar of zero or of the group
    /// order is outside the private-key range and refused with <c>TPM_RC_KEY_SIZE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    /// <param name="isOrder">Whether the scalar is the group order (else zero).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task LoadExternalScalarOutsideThePrivateKeyRangeIsRefusedWithKeySize(bool isOrder)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalScalarOutsideThePrivateKeyRangeIsRefusedWithKeySize)}-{isOrder}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] scalar = isOrder ? P256Order : new byte[P256ComponentSize];
        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, ExternalSigningAttributes, key.X, key.Y, scalar: scalar).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY_SIZE, result.ResponseCode, "A scalar outside [1, n-1] is TPM_RC_KEY_SIZE (Part 3, clause 12.3.1; Part 4 CryptValidateKeys).");
    }

    /// <summary>
    /// "If nameAlg is not TPM_ALG_NULL, then the same consistency checks between inPublic and inPrivate are made
    /// as for TPM2_Load()": a scalar that does not produce the public point is <c>TPM_RC_BINDING</c> under a real
    /// Name algorithm, while under <c>TPM_ALG_NULL</c> the pair loads — "the TPM cannot, and thus shall not verify
    /// the integrity HMAC" and the binding check falls with it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    /// <param name="isNullNameAlg">Whether the public area's Name algorithm is <c>TPM_ALG_NULL</c>.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(false, TpmRcConstants.TPM_RC_BINDING)]
    [DataRow(true, TpmRcConstants.TPM_RC_SUCCESS)]
    public async Task LoadExternalScalarNotMatchingThePointIsBindingOnlyUnderARealNameAlg(bool isNullNameAlg, TpmRcConstants expected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalScalarNotMatchingThePointIsBindingOnlyUnderARealNameAlg)}-{isNullNameAlg}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();
        using EccKeyMaterial otherKey = EccKeyMaterial.Generate();
        TpmAlgIdConstants nameAlg = isNullNameAlg ? TpmAlgIdConstants.TPM_ALG_NULL : NameAlg;

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, nameAlg, ExternalSigningAttributes, key.X, key.Y, scalar: otherKey.D).ConfigureAwait(false);
        TpmRcConstants observed = result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;
        Assert.AreEqual(expected, observed, $"A scalar not matching the point is {expected} under {nameAlg} (Part 3, clause 12.3.1).");

        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }
    }

    /// <summary>
    /// "The TPM will validate that the authPolicy is either the size of the digest produced by nameAlg or the
    /// Empty Buffer": a 20-octet authPolicy under SHA-256 is refused with <c>TPM_RC_SIZE</c>, and — "The digest
    /// size for TPM_ALG_NULL is zero" — a 32-octet authPolicy under the NULL Name algorithm is refused with
    /// <c>TPM_RC_SIZE</c> too, since only the Empty Buffer is admitted under it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    /// <param name="nameAlg">The public area's Name algorithm.</param>
    /// <param name="policyWidth">The authPolicy width supplied.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA256, 20)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL, 32)]
    public async Task LoadExternalAuthPolicyOfTheWrongWidthIsRefusedWithSize(TpmAlgIdConstants nameAlg, int policyWidth)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalAuthPolicyOfTheWrongWidthIsRefusedWithSize)}-{nameAlg}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] policy = new byte[policyWidth];
        policy.AsSpan().Fill(0x11);
        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, nameAlg, ExternalSigningAttributes, key.X, key.Y, authPolicy: policy).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), result.ResponseCode, $"A {policyWidth}-octet authPolicy under {nameAlg} is neither empty nor one digest wide: TPM_RC_SIZE (Part 3, clause 12.3.1).");
    }

    /// <summary>
    /// The sensitive area's authValue may be no wider than the Name algorithm's digest (TPM 2.0 Library Part 1,
    /// clause 16.6.4.2): 33 octets under SHA-256 is <c>TPM_RC_SIZE</c>, 32 loads and the value then authorizes
    /// <c>TPM2_Sign()</c> as the object's password.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    /// <param name="width">The authValue width.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(DigestSize + 1, TpmRcConstants.TPM_RC_SIZE)]
    [DataRow(DigestSize, TpmRcConstants.TPM_RC_SUCCESS)]
    public async Task LoadExternalAuthValueWidthIsJudgedAgainstTheNameAlgDigest(int width, TpmRcConstants expected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalAuthValueWidthIsJudgedAgainstTheNameAlgDigest)}-{width}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] authValue = new byte[width];
        for(int index = 0; index < width; index++)
        {
            authValue[index] = (byte)(0x61 + index);
        }

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, ExternalSigningAttributes, key.X, key.Y, scalar: key.D, authValue: authValue).ConfigureAwait(false);
        TpmRcConstants observed = result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;
        Assert.AreEqual(expected, observed, $"A {width}-octet authValue under SHA-256 is {expected} (Part 1, clause 16.6.4.2).");

        if(result.IsSuccess)
        {
            using LoadExternalResponse loaded = result.Value;
            byte[] digest = SHA256.HashData(MessageBytes);
            using TpmPasswordSession keyAuth = TpmPasswordSession.Create(authValue, pool);
            using SignInput signInput = SignInput.ForEcdsa(loaded.ObjectHandle, digest, NameAlg, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"The loaded authValue authorizes the key as its password, but signing failed: '{signResult.ResponseCode}'.");
            signResult.Value.Dispose();
        }
    }

    /// <summary>
    /// A <c>seedValue</c> wider than the Name algorithm's digest is inconsistent with the public area's size
    /// indications and refused with <c>TPM_RC_KEY_SIZE</c> (Part 4 <c>CryptValidateKeys</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalSeedValueOfTheWrongWidthIsRefusedWithKeySize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalSeedValueOfTheWrongWidthIsRefusedWithKeySize), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] seed = new byte[DigestSize + 1];
        seed.AsSpan().Fill(0x22);
        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, ExternalSigningAttributes, key.X, key.Y, scalar: key.D, seed: seed).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_KEY_SIZE, 0), result.ResponseCode, "A seedValue wider than the nameAlg digest is TPM_RC_KEY_SIZE (Part 4 CryptValidateKeys).");
    }

    /// <summary>
    /// An asymmetric key with neither <c>sign</c> nor <c>decrypt</c> SET has no use the attribute rules admit and
    /// is refused with <c>TPM_RC_ATTRIBUTES</c> (TPM 2.0 Library Part 2, clause 8.3.3; Part 4
    /// <c>PublicAttributesValidation</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalEccKeyWithNeitherSignNorDecryptIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalEccKeyWithNeitherSignNorDecryptIsRefusedWithAttributes), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA, key.X, key.Y, scalar: key.D).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode, "An asymmetric key with sign and decrypt both CLEAR is TPM_RC_ATTRIBUTES (Part 2, clause 8.3.3).");
    }

    /// <summary>
    /// "If the Object is not a keyedHash object, and the sign and encrypt attributes are CLEAR, the TPM shall
    /// return TPM_RC_ATTRIBUTES" refuses only the both-CLEAR pairing — both SET is admitted provided the scheme
    /// answers for it: "if the key is both sign and decrypt, then the scheme must be TPM_ALG_NULL" (Part 4
    /// <c>SchemeChecks</c>). An ECC key with <c>sign</c> and <c>decrypt</c> both SET and the NULL scheme loads
    /// under <c>TPM_RH_NULL</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalEccKeyWithBothSignAndDecryptSetLoadsUnderANullScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalEccKeyWithBothSignAndDecryptSetLoadsUnderANullScheme), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmaObject attributes = TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA | TpmaObject.SIGN_ENCRYPT | TpmaObject.DECRYPT;
        TpmResult<LoadExternalResponse> result = await LoadEccAsync(
            tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, attributes, key.X, key.Y, scalar: key.D, scheme: TpmtEccScheme.Null).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"An ECC key with sign and decrypt both SET loads under the NULL scheme (Part 4 SchemeChecks), but failed: '{result.ResponseCode}'.");
        result.Value.Dispose();
    }

    /// <summary>
    /// A restricted signing key must name its scheme (TPM 2.0 Library Part 2, clause 12.2.3.5, Table 229: "If the
    /// sign attribute of the key is SET, then this shall be a valid signing scheme" with the NULL scheme admitted
    /// only on an unrestricted key), so a restricted RSA key with <c>TPM_ALG_NULL</c> is <c>TPM_RC_SCHEME</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRestrictedRsaKeyWithANullSchemeIsRefusedWithScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRestrictedRsaKeyWithANullSchemeIsRefusedWithScheme), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadRsaAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, ExternalSigningAttributes | TpmaObject.RESTRICTED, TpmtRsaScheme.Null, key.Modulus).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 1), result.ResponseCode, "A restricted signing key with a NULL scheme is TPM_RC_SCHEME (Part 2, clause 12.2.3.5, Table 229).");
    }

    /// <summary>
    /// "If this is a restricted decryption key with symmetric algorithms, then it is an ordinary parent (not a
    /// derivation parent). It needs to specific symmetric algorithms other than TPM_ALG_NULL" (Part 4
    /// <c>SchemeChecks</c>): an RSA storage-shaped public area (RESTRICTED and DECRYPT SET) whose
    /// <c>TPMS_RSA_PARMS.symmetric</c> is patched from AES-128-CFB to <c>TPM_ALG_NULL</c> is refused with
    /// <c>TPM_RC_SYMMETRIC</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRestrictedDecryptKeyWithANullSymmetricIsRefusedWithSymmetric()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRestrictedDecryptKeyWithANullSymmetricIsRefusedWithSymmetric), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        byte[] marshaled;
        using(Tpm2bPublic template = Tpm2bPublic.CreateRsaStorageParent(NameAlg, RestrictedDecryptAttributes, RsaKeyBits, key.Modulus, pool))
        {
            marshaled = MarshalPublic(template);
        }

        byte[] patched = PatchRsaSymmetricToNull(marshaled);
        TpmResult<LoadExternalResponse> result = await LoadMarshaledPublicAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, patched).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, 1), result.ResponseCode, "A restricted decryption key needs a real symmetric algorithm (Part 4 SchemeChecks).");
    }

    /// <summary>
    /// The unpatched control for <see cref="LoadExternalRestrictedDecryptKeyWithANullSymmetricIsRefusedWithSymmetric"/>:
    /// the same RSA storage-shaped public area, its real AES-128-CFB <c>symmetric</c> algorithm intact, loads.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRestrictedDecryptKeyWithARealSymmetricLoads()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRestrictedDecryptKeyWithARealSymmetricLoads), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        byte[] marshaled;
        using(Tpm2bPublic template = Tpm2bPublic.CreateRsaStorageParent(NameAlg, RestrictedDecryptAttributes, RsaKeyBits, key.Modulus, pool))
        {
            marshaled = MarshalPublic(template);
        }

        TpmResult<LoadExternalResponse> result = await LoadMarshaledPublicAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, marshaled).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A restricted decryption key with a real symmetric algorithm must load, but failed: '{result.ResponseCode}'.");
        result.Value.Dispose();
    }

    /// <summary>
    /// A public-only RSA-2048 key loads and verifies the framework's own RSASSA (PKCS#1 v1.5) and RSAPSS
    /// signatures over a digest, each minting a real ticket under the owner hierarchy.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    /// <param name="isPss">Whether the signature is RSAPSS (else RSASSA).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task LoadExternalPublicOnlyRsaKeyVerifiesTheFrameworksSignature(bool isPss)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalPublicOnlyRsaKeyVerifiesTheFrameworksSignature)}-{isPss}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadRsaAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, ExternalSigningAttributes, TpmtRsaScheme.Null, key.Modulus).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A public-only RSA key must load (Part 3, clause 12.3.1), but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        byte[] digest = SHA256.HashData(MessageBytes);
        byte[] signature = key.Key.SignHash(digest, HashAlgorithmName.SHA256, isPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
        using VerifySignatureInput verifyInput = isPss
            ? VerifySignatureInput.ForRsaPss(loaded.ObjectHandle, digest, signature, NameAlg, pool)
            : VerifySignatureInput.ForRsaSsa(loaded.ObjectHandle, digest, signature, NameAlg, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"The framework's {(isPss ? "RSAPSS" : "RSASSA")} signature must verify against the imported modulus, but failed: '{verifyResult.ResponseCode}'.");
        using VerifySignatureResponse verified = verifyResult.Value;
        Assert.IsFalse(verified.Validation.IsNull, "A real hierarchy earns a real ticket.");
    }

    /// <summary>
    /// "For an RSA key, the private exponent is computed using the two prime factors of the public modulus. One
    /// of the primes is P, and the second prime (Q) is found by dividing the public modulus by P": an RSA key
    /// loaded from its modulus and one prime under <c>TPM_RH_NULL</c> signs, and the framework's own RSA verifies
    /// the signature against the same modulus.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalFullRsaKeyFromItsPrimeSignsForTheFrameworkToVerify()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalFullRsaKeyFromItsPrimeSignsForTheFrameworkToVerify), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadRsaAsync(tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSigningAttributes, TpmtRsaScheme.Null, key.Modulus, prime: key.P).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"An RSA key with its prime must load under TPM_RH_NULL (Part 3, clause 12.3.1), but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        byte[] digest = SHA256.HashData(MessageBytes);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForRsaSsa(loaded.ObjectHandle, digest, NameAlg, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"The imported RSA key must sign, but failed: '{signResult.ResponseCode}'.");
        using SignResponse signed = signResult.Value;

        Assert.IsTrue(
            key.Key.VerifyHash(digest, signed.Signature.RsaSignature.Buffer, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "The framework's RSA accepts the TPM's RSASSA signature against the imported modulus.");
    }

    /// <summary>
    /// A modulus narrower than the declared <c>keyBits</c>, or one whose top bit is clear, is inconsistent with
    /// the public area and refused with <c>TPM_RC_KEY</c> (Part 4 <c>CryptValidateKeys</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    /// <param name="isTopBitClear">Whether the case clears the modulus's top bit (else drops its first octet).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task LoadExternalRsaModulusInconsistentWithKeyBitsIsRefusedWithKey(bool isTopBitClear)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalRsaModulusInconsistentWithKeyBitsIsRefusedWithKey)}-{isTopBitClear}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        byte[] modulus = isTopBitClear ? (byte[])key.Modulus.Clone() : key.Modulus[1..];
        if(isTopBitClear)
        {
            modulus[0] &= 0x7F;
        }

        TpmResult<LoadExternalResponse> result = await LoadRsaAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, ExternalSigningAttributes, TpmtRsaScheme.Null, modulus).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "A modulus inconsistent with keyBits is TPM_RC_KEY (Part 4 CryptValidateKeys).");
    }

    /// <summary>
    /// The public exponent rule (TPM 2.0 Library Part 2, clause 12.2.3.4, Table 228: "the value of the exponent
    /// ... shall be an odd number that is greater than or equal to 2^16 + 1", zero standing for the default):
    /// an explicit exponent of 3 is <c>TPM_RC_VALUE</c>, an explicit 65537 loads.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    /// <param name="exponent">The explicit exponent written into the public area.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(3u, TpmRcConstants.TPM_RC_VALUE)]
    [DataRow(65537u, TpmRcConstants.TPM_RC_SUCCESS)]
    public async Task LoadExternalRsaExponentIsJudged(uint exponent, TpmRcConstants expected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalRsaExponentIsJudged)}-{exponent}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        byte[] marshaled;
        using(Tpm2bPublic template = BuildRsaPublic(pool, NameAlg, ExternalSigningAttributes, TpmtRsaScheme.Null, key.Modulus))
        {
            marshaled = MarshalPublic(template);
        }

        //TPM2B_PUBLIC: size(2) ‖ type(2) ‖ nameAlg(2) ‖ objectAttributes(4) ‖ authPolicy(2, empty) ‖
        //TPMS_RSA_PARMS: symmetric TPM_ALG_NULL(2) ‖ scheme TPM_ALG_NULL(2) ‖ keyBits(2) ‖ exponent(4) ‖ unique.
        const int ExponentOffset = 2 + 2 + 2 + 4 + 2 + 2 + 2 + 2;
        Assert.AreEqual(0u, BinaryPrimitives.ReadUInt32BigEndian(marshaled.AsSpan(ExponentOffset, sizeof(uint))), "The template carries the zero (default) exponent before the patch.");
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(ExponentOffset, sizeof(uint)), exponent);

        TpmResult<LoadExternalResponse> result = await LoadMarshaledPublicAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, marshaled).ConfigureAwait(false);
        TpmRcConstants observed = result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;
        Assert.AreEqual(expected, observed, $"An explicit exponent of {exponent} is {expected} (Part 2, clause 12.2.3.4, Table 228).");

        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }
    }

    /// <summary>
    /// "The TPM will validate that the size of the key in the sensitive area is consistent with the size indicated
    /// in the public area. If it is not, the TPM shall return TPM_RC_KEY_SIZE": a prime narrower than half the
    /// modulus is refused with <c>TPM_RC_KEY_SIZE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRsaPrimeOfTheWrongWidthIsRefusedWithKeySize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRsaPrimeOfTheWrongWidthIsRefusedWithKeySize), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadRsaAsync(tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSigningAttributes, TpmtRsaScheme.Null, key.Modulus, prime: key.P.AsMemory(1)).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY_SIZE, result.ResponseCode, "A prime of the wrong width for the modulus is TPM_RC_KEY_SIZE (Part 3, clause 12.3.1).");
    }

    /// <summary>
    /// "If the parts of the object are not properly linked, the TPM shall return TPM_RC_BINDING": a prime that
    /// does not divide the modulus — another key's — links to nothing and is refused with <c>TPM_RC_BINDING</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRsaPrimeThatDoesNotDivideTheModulusIsRefusedWithBinding()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRsaPrimeThatDoesNotDivideTheModulusIsRefusedWithBinding), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();
        using RsaKeyMaterial otherKey = RsaKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadRsaAsync(tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSigningAttributes, TpmtRsaScheme.Null, key.Modulus, prime: otherKey.P).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BINDING, result.ResponseCode, "A prime that does not divide the modulus binds no key pair: TPM_RC_BINDING (Part 3, clause 12.3.1).");
    }

    /// <summary>
    /// "A TPM may return an error (TPM_RC_BINDING) if the bit size of P and Q are not the same": a modulus formed
    /// as <c>P · (2^1024 + 1)</c> pairs a 1024-bit prime with a 1025-bit cofactor — P divides the modulus exactly,
    /// yet the bit-size mismatch is refused with <c>TPM_RC_BINDING</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRsaPrimeWhoseCofactorHasAnotherBitLengthIsRefusedWithBinding()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRsaPrimeWhoseCofactorHasAnotherBitLengthIsRefusedWithBinding), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        var p = new BigInteger(key.P, isUnsigned: true, isBigEndian: true);
        BigInteger cofactor = BigInteger.Pow(2, 1024) + BigInteger.One;
        BigInteger n = p * cofactor;
        byte[] modulus = PadLeft(n.ToByteArray(isUnsigned: true, isBigEndian: true), RsaKeyBits / 8);

        TpmResult<LoadExternalResponse> result = await LoadRsaAsync(tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSigningAttributes, TpmtRsaScheme.Null, modulus, prime: key.P).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BINDING, result.ResponseCode, "A prime paired with a cofactor of a different bit size is TPM_RC_BINDING (Part 3, clause 12.3.1).");
    }

    /// <summary>
    /// A prime pair whose Euler totient <c>(P-1)(Q-1)</c> is divisible by the public exponent has no modular
    /// inverse for the private exponent — a genuine RSA key pair cannot exist — and the TPM answers the binding
    /// failure rather than faulting: <c>TPM_RC_BINDING</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRsaPairWhoseExponentIsNotInvertibleIsRefusedWithBinding()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRsaPairWhoseExponentIsNotInvertibleIsRefusedWithBinding), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using RsaKeyMaterial key = RsaKeyMaterial.Generate();

        var exponent = new BigInteger(TpmsRsaParms.DefaultExponent);
        BigInteger twoPow1024 = BigInteger.Pow(2, 1024);
        BigInteger r = BigInteger.Remainder(twoPow1024 - 2, exponent);
        BigInteger q = twoPow1024 - BigInteger.One - r;
        if(q.IsEven)
        {
            r += exponent;
            q = twoPow1024 - BigInteger.One - r;
        }

        var p = new BigInteger(key.P, isUnsigned: true, isBigEndian: true);
        BigInteger n = p * q;
        Assert.AreEqual(2048L, n.GetBitLength(), "The fabricated modulus must be exactly 2048 bits wide before it is framed.");
        Assert.AreEqual(1024L, q.GetBitLength(), "The fabricated cofactor must be exactly 1024 bits wide before it is framed.");
        byte[] modulus = PadLeft(n.ToByteArray(isUnsigned: true, isBigEndian: true), RsaKeyBits / 8);

        TpmResult<LoadExternalResponse> result = await LoadRsaAsync(tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSigningAttributes, TpmtRsaScheme.Null, modulus, prime: key.P).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BINDING, result.ResponseCode, "An exponent with no inverse modulo φ(N) admits no private key: TPM_RC_BINDING (Part 3, clause 12.3.1).");
    }

    /// <summary>
    /// An HMAC key loaded with its sensitive area under <c>TPM_RH_NULL</c> — <c>unique = H_nameAlg(seedValue ‖
    /// key)</c> computed off-TPM (TPM 2.0 Library Part 2, clause 12.2.3.1, equation (8)) — reproduces RFC 4231
    /// test case 1's HMAC-SHA-256 tag through <c>TPM2_HMAC()</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalHmacKeyReproducesRfc4231Case1()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalHmacKeyReproducesRfc4231Case1), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        byte[] seed = KeyedHashSeed();

        TpmResult<LoadExternalResponse> result = await LoadKeyedHashAsync(
            tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSigningAttributes, TpmsKeyedHashParms.Hmac(NameAlg), KeyedHashUnique(seed, Rfc4231Case1Key), seed, Rfc4231Case1Key).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"An HMAC key with its sensitive area must load under TPM_RH_NULL (Part 3, clause 12.3.1), but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        TpmResult<HmacResponse> hmacResult = await HmacKeyHarness.HmacAsync(tpm, registry, pool, loaded.ObjectHandle.Value, Rfc4231Case1Data, NameAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(hmacResult.IsSuccess, $"TPM2_HMAC() over the imported key must succeed, but failed: '{hmacResult.ResponseCode}'.");
        using HmacResponse hmac = hmacResult.Value;
        Assert.IsTrue(hmac.OutHmac.AsReadOnlySpan().SequenceEqual(Rfc4231Case1Sha256), "The imported key reproduces RFC 4231 test case 1's tag.");
    }

    /// <summary>
    /// A KEYEDHASH <c>unique</c> that is not <c>H_nameAlg(seedValue ‖ key)</c> binds no sensitive area and is
    /// refused with <c>TPM_RC_BINDING</c> — "the same consistency checks between inPublic and inPrivate are made
    /// as for TPM2_Load()".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalKeyedHashWithAMismatchedUniqueIsRefusedWithBinding()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalKeyedHashWithAMismatchedUniqueIsRefusedWithBinding), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        byte[] seed = KeyedHashSeed();

        TpmResult<LoadExternalResponse> result = await LoadKeyedHashAsync(
            tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSigningAttributes, TpmsKeyedHashParms.Hmac(NameAlg), SHA256.HashData(MessageBytes), seed, Rfc4231Case1Key).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BINDING, result.ResponseCode, "A unique that is not H(seedValue ‖ key) is TPM_RC_BINDING (Part 3, clause 12.3.1; Part 2, clause 12.2.3.1).");
    }

    /// <summary>
    /// An HMAC key value wider than its scheme hash's block size is refused with <c>TPM_RC_KEY_SIZE</c> (TPM 2.0
    /// Library Part 1, clause 24.7.5.1; Part 4 <c>CryptValidateKeys</c>: 65 octets under SHA-256's 64-octet block).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalHmacKeyWiderThanTheBlockSizeIsRefusedWithKeySize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalHmacKeyWiderThanTheBlockSizeIsRefusedWithKeySize), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        byte[] seed = KeyedHashSeed();
        byte[] wideKey = new byte[65];
        wideKey.AsSpan().Fill(0x0B);

        TpmResult<LoadExternalResponse> result = await LoadKeyedHashAsync(
            tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSigningAttributes, TpmsKeyedHashParms.Hmac(NameAlg), KeyedHashUnique(seed, wideKey), seed, wideKey).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY_SIZE, result.ResponseCode, "An HMAC key wider than the hash block is TPM_RC_KEY_SIZE (Part 1, clause 24.7.5.1).");
    }

    /// <summary>
    /// A sealed data object loaded from outside under <c>TPM_RH_NULL</c> unseals to the octets its sensitive
    /// area carried.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalSealedDataObjectUnseals()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalSealedDataObjectUnseals), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        byte[] seed = KeyedHashSeed();

        TpmResult<LoadExternalResponse> result = await LoadKeyedHashAsync(
            tpm, registry, pool, TpmiRhHierarchy.Null, ExternalSealedAttributes, TpmsKeyedHashParms.SealedData, KeyedHashUnique(seed, SealedSecret), seed, SealedSecret).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A sealed data object must load from outside under TPM_RH_NULL, but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, UnsealInput.ForItem(loaded.ObjectHandle), [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unsealResult.IsSuccess, $"TPM2_Unseal() over the imported object must succeed, but failed: '{unsealResult.ResponseCode}'.");
        using UnsealResponse unsealed = unsealResult.Value;
        Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SealedSecret), "The unsealed data is the imported sensitive area, byte for byte.");
    }

    /// <summary>
    /// A public-only KEYEDHASH object loads but has no key to use: <c>TPM2_HMAC()</c> is
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> (Part 3, clause 5.6, check 1), <c>TPM2_VerifySignature()</c> with an HMAC
    /// signature — which needs the key value — is <c>TPM_RC_HANDLE</c> (Part 3, clause 20.2.1), and
    /// <c>TPM2_VerifySequenceStart()</c> is refused for the same reason: "If keyHandle references a symmetric
    /// key, both the public and private portions need to be loaded" (Part 3, clause 20.3.1) — this TPM refuses
    /// at the START a sequence, where Part 4's reference implementation opens it and refuses only at
    /// <c>TPM2_VerifySequenceComplete()</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalPublicOnlyKeyedHashLoadsButCannotAuthorizeOrVerify()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalPublicOnlyKeyedHashLoadsButCannotAuthorizeOrVerify), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        byte[] seed = KeyedHashSeed();

        TpmResult<LoadExternalResponse> result = await LoadKeyedHashAsync(
            tpm, registry, pool, TpmiRhHierarchy.Owner, ExternalSigningAttributes, TpmsKeyedHashParms.Hmac(NameAlg), KeyedHashUnique(seed, Rfc4231Case1Key)).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A public-only KEYEDHASH object must load, but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        TpmResult<HmacResponse> hmacResult = await HmacKeyHarness.HmacAsync(tpm, registry, pool, loaded.ObjectHandle.Value, Rfc4231Case1Data, NameAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, hmacResult.ResponseCode, "A public-only KEYEDHASH object cannot be authorized (Part 3, clause 5.6, check 1).");

        using VerifySignatureInput verifyInput = VerifySignatureInput.Create(loaded.ObjectHandle, SHA256.HashData(MessageBytes), Rfc4231Case1Sha256, TpmAlgIdConstants.TPM_ALG_HMAC, NameAlg, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        //TPM2_VerifySignature attributes every failure of the signature validation itself to the signature
        //parameter (parameter 2 of its command table), whatever the base code's name suggests — the same
        //designation its asymmetric-arm public-only check carries.
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), verifyResult.ResponseCode, "An HMAC verification needs the key value a public-only object lacks: TPM_RC_HANDLE (Part 3, clause 20.2.1).");

        using VerifySequenceStartInput startInput = VerifySequenceStartInput.Create(loaded.ObjectHandle, [], pool);
        TpmResult<VerifySequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        //VerifySequenceStart's KEYEDHASH arm answers this unwrapped, unlike VerifySignature: keyHandle is
        //VerifySequenceStart's sole handle (Table 89, H1).
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), startResult.ResponseCode, "A public-only KEYEDHASH object has no bits to verify a sequence over: TPM_RC_HANDLE (Part 3, clause 20.3.1).");
    }

    /// <summary>
    /// A sensitive area whose type differs from the public area's is refused with <c>TPM_RC_TYPE</c> (Part 4
    /// <c>CryptValidateKeys</c>: "sensitiveType shall match publicArea->type").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalWithMismatchedPublicAndSensitiveTypesIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalWithMismatchedPublicAndSensitiveTypesIsRefusedWithType), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccPublicWithKeyedHashSensitiveAsync(tpm, registry, pool, key, KeyedHashSeed(), Rfc4231Case1Key).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_TYPE, result.ResponseCode, "A KEYEDHASH sensitive area under an ECC public area is TPM_RC_TYPE (Part 4 CryptValidateKeys).");
    }

    /// <summary>
    /// A <c>TPM_ALG_SYMCIPHER</c> sensitive area is a type this TPM does not implement for an external object and
    /// is refused with parameter-encoded <c>TPM_RC_TYPE</c> at the sensitive-area union (TPM 2.0 Library Part 2,
    /// clause 12.3.2, Table 239) — <c>inPrivate</c>, <c>TPM2_LoadExternal()</c>'s first parameter (Table 22,
    /// index 0).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalWithASymCipherSensitiveIsRefusedWithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalWithASymCipherSensitiveIsRefusedWithType), pool).ConfigureAwait(false);
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        var sensitive = new List<byte>();
        AppendUInt16(sensitive, SymCipherSelector);
        AppendUInt16(sensitive, 0);
        AppendUInt16(sensitive, 0);
        AppendTpm2b(sensitive, new byte[16]);

        byte[] marshaledPublic;
        using(Tpm2bPublic inPublic = BuildEccPublic(pool, NameAlg, ExternalSigningAttributes, key.X, key.Y))
        {
            marshaledPublic = MarshalPublic(inPublic);
        }

        var body = new List<byte>();
        AppendTpm2b(body, [.. sensitive]);
        body.AddRange(marshaledPublic);
        AppendUInt32(body, (uint)TpmRh.TPM_RH_NULL);

        TpmRcConstants responseCode = await SubmitFramedAsync(simulator, pool, [.. body]).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TYPE, 0), responseCode,
            "TPM2_LoadExternal()'s inPrivate parameter parse designates a SYMCIPHER sensitive area's TPM_RC_TYPE to inPrivate itself (Table 22, index 0); the decrypt continuation's already-designated guard keeps that same answer from ever picking up a second, session designation (Part 2, clause 12.3.2, Table 239).");
    }

    /// <summary>
    /// The parameter area's wire shape (TPM 2.0 Library Part 3, clause 12.3, Table 22; clause 5.2): an
    /// <c>inPublic</c> of size zero is parameter-encoded <c>TPM_RC_SIZE</c>; an <c>inPrivate</c> declaring one
    /// octet more than its <c>TPMT_SENSITIVE</c> consumes is parameter-encoded <c>TPM_RC_SIZE</c>; one declaring
    /// more than the frame holds is parameter-encoded <c>TPM_RC_INSUFFICIENT</c>; a <c>hierarchy</c> outside
    /// <c>TPMI_RH_HIERARCHY</c> is parameter-encoded <c>TPM_RC_VALUE</c>; an octet after the last parameter is
    /// bare <c>TPM_RC_SIZE</c> (the reference's own generic trailing-octets rule, not a property of one field);
    /// a <c>TPM2B_PUBLIC</c> declaring one octet more than its <c>TPMT_PUBLIC</c> consumes is parameter-encoded
    /// <c>TPM_RC_SIZE</c> (Part 4 <c>TPM2B_PUBLIC_Unmarshal</c>); an <c>inPublic</c> of type
    /// <c>TPM_ALG_SYMCIPHER</c> or an unassigned selector is parameter-encoded <c>TPM_RC_TYPE</c>; an
    /// <c>inPrivate</c> whose <c>seedValue</c> size exceeds <see cref="Tpm2bDigest.MaxSize"/> is
    /// parameter-encoded <c>TPM_RC_SIZE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 22; Part 2, clause 6.6.2, Table 15</see>.
    /// </summary>
    /// <param name="shape">The malformation applied.</param>
    /// <param name="expected">The expected response code.</param>
    [TestMethod]
    [DataRow(MalformedShape.EmptyPublic, TpmRcConstants.TPM_RC_SIZE)]
    [DataRow(MalformedShape.SensitiveOverDeclared, TpmRcConstants.TPM_RC_SIZE)]
    [DataRow(MalformedShape.SensitivePastTheFrame, TpmRcConstants.TPM_RC_INSUFFICIENT)]
    [DataRow(MalformedShape.HierarchyOutOfRange, TpmRcConstants.TPM_RC_VALUE)]
    [DataRow(MalformedShape.TrailingOctet, TpmRcConstants.TPM_RC_SIZE)]
    [DataRow(MalformedShape.PublicOverDeclared, TpmRcConstants.TPM_RC_SIZE)]
    [DataRow(MalformedShape.SymCipherPublic, TpmRcConstants.TPM_RC_TYPE)]
    [DataRow(MalformedShape.UnknownTypePublic, TpmRcConstants.TPM_RC_TYPE)]
    [DataRow(MalformedShape.SeedValueOverBound, TpmRcConstants.TPM_RC_SIZE)]
    public async Task LoadExternalRefusesAMalformedParameterArea(MalformedShape shape, TpmRcConstants expected)
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(LoadExternalRefusesAMalformedParameterArea)}-{shape}", pool).ConfigureAwait(false);
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        byte[] marshaledPublic;
        using(Tpm2bPublic inPublic = BuildEccPublic(pool, NameAlg, ExternalSigningAttributes, key.X, key.Y))
        {
            marshaledPublic = MarshalPublic(inPublic);
        }

        byte[] marshaledSensitive;
        using(TpmtSensitive inPrivate = BuildEccSensitive(pool, key.D))
        {
            marshaledSensitive = MarshalSensitive(inPrivate);
        }

        long baseline = trackingPool.OutstandingCount;

        var body = new List<byte>();
        uint hierarchy = (uint)TpmRh.TPM_RH_NULL;
        switch(shape)
        {
            case MalformedShape.EmptyPublic:
            {
                AppendUInt16(body, 0);
                AppendUInt16(body, 0);
                break;
            }
            case MalformedShape.SensitiveOverDeclared:
            {
                AppendUInt16(body, (ushort)(marshaledSensitive.Length + 1));
                body.AddRange(marshaledSensitive);
                body.Add(0x00);
                body.AddRange(marshaledPublic);
                break;
            }
            case MalformedShape.SensitivePastTheFrame:
            {
                AppendUInt16(body, (ushort)(marshaledSensitive.Length + marshaledPublic.Length + 64));
                body.AddRange(marshaledSensitive);
                body.AddRange(marshaledPublic);
                break;
            }
            case MalformedShape.HierarchyOutOfRange:
            {
                AppendUInt16(body, 0);
                body.AddRange(marshaledPublic);
                hierarchy = 0x4000_0010;
                break;
            }
            case MalformedShape.TrailingOctet:
            {
                AppendUInt16(body, 0);
                body.AddRange(marshaledPublic);
                break;
            }
            case MalformedShape.PublicOverDeclared:
            {
                ushort originalSize = BinaryPrimitives.ReadUInt16BigEndian(marshaledPublic);
                byte[] overDeclared = new byte[marshaledPublic.Length + 1];
                marshaledPublic.CopyTo(overDeclared, 0);
                BinaryPrimitives.WriteUInt16BigEndian(overDeclared.AsSpan(0, sizeof(ushort)), (ushort)(originalSize + 1));
                overDeclared[^1] = 0x00;

                AppendUInt16(body, 0);
                body.AddRange(overDeclared);
                break;
            }
            case MalformedShape.SymCipherPublic:
            {
                AppendTpm2b(body, BuildWellFormedKeyedHashSensitiveBytes());
                AppendTpm2b(body, BuildSymCipherShapedPublicBytes(SymCipherSelector));
                break;
            }
            case MalformedShape.UnknownTypePublic:
            {
                AppendTpm2b(body, BuildWellFormedKeyedHashSensitiveBytes());
                AppendTpm2b(body, BuildSymCipherShapedPublicBytes(UnknownPublicTypeSelector));
                break;
            }
            case MalformedShape.SeedValueOverBound:
            {
                AppendTpm2b(body, BuildOverBoundSeedSensitiveBytes());
                body.AddRange(marshaledPublic);
                break;
            }
            default:
            {
                throw new ArgumentOutOfRangeException(nameof(shape));
            }
        }

        AppendUInt32(body, hierarchy);
        if(shape == MalformedShape.TrailingOctet)
        {
            body.Add(0xA5);
        }

        TpmRcConstants responseCode = await SubmitFramedAsync(simulator, pool, [.. body]).ConfigureAwait(false);

        //DataRow attributes must be compile-time constants, so every row carries the bare code; each shape is
        //re-encoded here to the field its own malformation lands on, per Table 22 (inPrivate = 0, inPublic = 1,
        //hierarchy = 2). EmptyPublic/PublicOverDeclared/SymCipherPublic/UnknownTypePublic fail decoding
        //inPublic itself (P1); HierarchyOutOfRange fails the command body's own hierarchy judgment (P2);
        //SensitiveOverDeclared/SensitivePastTheFrame/SeedValueOverBound fail inside inPrivate's own parameter
        //parse, designated to inPrivate itself (P0) — the decrypt continuation's already-designated guard
        //keeps that same answer from ever picking up a second, session designation when reached over
        //already-decrypted plaintext; TrailingOctet is the reference's own generic trailing-octets check,
        //which stays bare regardless of field.
        TpmRcConstants expectedEncoded = shape switch
        {
            MalformedShape.EmptyPublic or MalformedShape.PublicOverDeclared
                or MalformedShape.SymCipherPublic or MalformedShape.UnknownTypePublic => HmacKeyHarness.ParameterEncodedRc(expected, 1),
            MalformedShape.HierarchyOutOfRange => HmacKeyHarness.ParameterEncodedRc(expected, 2),
            MalformedShape.SensitiveOverDeclared or MalformedShape.SensitivePastTheFrame or MalformedShape.SeedValueOverBound => HmacKeyHarness.ParameterEncodedRc(expected, 0),
            _ => expected
        };
        Assert.AreEqual(expectedEncoded, responseCode, $"A frame with {shape} must answer {expectedEncoded} (Part 3, clause 12.3, Table 22; clause 5.2).");

        if(shape is MalformedShape.SymCipherPublic or MalformedShape.UnknownTypePublic)
        {
            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused load releases every carrier it rented, the well-formed inPrivate rental included.");
        }
    }

    /// <summary>
    /// Marshals a well-formed KEYEDHASH <c>TPMT_SENSITIVE</c> (RFC 4231 test case 1's key, no <c>seedValue</c>)
    /// for pairing with a public area whose own shape is under test — proving that a rented, well-formed
    /// <c>inPrivate</c> is released when <c>inPublic</c> subsequently refuses.
    /// </summary>
    /// <returns>The marshaled <c>TPMT_SENSITIVE</c> octets, no size prefix.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the auth and data carriers transfers to the local sensitive area, disposed by the using declaration once it is marshaled.")]
    private static byte[] BuildWellFormedKeyedHashSensitiveBytes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmtSensitive inPrivate = TpmtSensitive.ForKeyedHash(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, Tpm2bSensitiveData.Create(Rfc4231Case1Key, pool));

        return MarshalSensitive(inPrivate);
    }

    /// <summary>
    /// Hand-frames a bare (no outer <c>TPM2B_PUBLIC</c> size prefix) <c>TPMT_PUBLIC</c> whose <c>type</c> is
    /// <paramref name="typeSelector"/> — <c>TPM_ALG_SYMCIPHER</c> or an unassigned selector — around a SHA-256
    /// <c>nameAlg</c>, an unbound-signing attribute word, an empty <c>authPolicy</c>, a
    /// <c>TPMS_SYMCIPHER_PARMS</c> (AES-128-CFB), and an empty <c>unique</c> digest (TPM 2.0 Library Part 2,
    /// clause 12.2.4, Table 235; clause 11.1.9, Table 165).
    /// </summary>
    /// <param name="typeSelector">The <c>TPMI_ALG_PUBLIC</c> selector under test.</param>
    /// <returns>The bare <c>TPMT_PUBLIC</c> octets, no size prefix.</returns>
    private static byte[] BuildSymCipherShapedPublicBytes(ushort typeSelector)
    {
        var bytes = new List<byte>();
        AppendUInt16(bytes, typeSelector);
        AppendUInt16(bytes, (ushort)NameAlg);
        AppendUInt32(bytes, (uint)(TpmaObject.SIGN_ENCRYPT | TpmaObject.USER_WITH_AUTH));
        AppendUInt16(bytes, 0);
        AppendUInt16(bytes, (ushort)TpmAlgIdConstants.TPM_ALG_AES);
        AppendUInt16(bytes, 128);
        AppendUInt16(bytes, (ushort)TpmAlgIdConstants.TPM_ALG_CFB);
        AppendUInt16(bytes, 0);

        return [.. bytes];
    }

    /// <summary>
    /// Hand-frames a bare (no outer <c>TPM2B_SENSITIVE</c> size prefix) KEYEDHASH <c>TPMT_SENSITIVE</c> whose
    /// <c>seedValue</c> size field declares one octet more than <see cref="Tpm2bDigest.MaxSize"/>, followed by
    /// that many filler octets and an empty <c>bits</c> field (TPM 2.0 Library Part 2, clause 10.3.2, Table 90).
    /// </summary>
    /// <returns>The bare <c>TPMT_SENSITIVE</c> octets, no size prefix.</returns>
    private static byte[] BuildOverBoundSeedSensitiveBytes()
    {
        const ushort OverBoundSeedSize = Tpm2bDigest.MaxSize + 1;

        var bytes = new List<byte>();
        AppendUInt16(bytes, (ushort)TpmAlgIdConstants.TPM_ALG_KEYEDHASH);
        AppendUInt16(bytes, 0);
        AppendUInt16(bytes, OverBoundSeedSize);
        bytes.AddRange(new byte[OverBoundSeedSize]);
        AppendUInt16(bytes, 0);

        return [.. bytes];
    }

    /// <summary>
    /// The object-slot bound is judged LAST: with every slot taken by public-only loads the next load is
    /// <c>TPM_RC_OBJECT_MEMORY</c> ("When the TPM is out of object slots, it returns TPM_RC_OBJECT_MEMORY", TPM 2.0
    /// Library Part 1, clause 36.3.2), while a load the attribute rules refuse still answers
    /// <c>TPM_RC_ATTRIBUTES</c> with no slot free.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRefusesWithObjectMemoryOnlyAfterTheAttributeRules()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRefusesWithObjectMemoryOnlyAfterTheAttributeRules), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        for(int slot = 0; slot < TpmSimulatorState.MaxLoadedObjects; slot++)
        {
            TpmResult<LoadExternalResponse> filler = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
            Assert.IsTrue(filler.IsSuccess, $"Load {slot + 1} of {TpmSimulatorState.MaxLoadedObjects} must take a slot, but failed: '{filler.ResponseCode}'.");
            filler.Value.Dispose();
        }

        TpmResult<LoadExternalResponse> overflow = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "With every slot taken the next load is TPM_RC_OBJECT_MEMORY (Part 1, clause 36.3.2).");

        TpmResult<LoadExternalResponse> refused = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, ExternalSigningAttributes | TpmaObject.FIXED_TPM, key.X, key.Y, scalar: key.D).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), refused.ResponseCode, "The attribute rules are judged before the slot bound (Part 3, clause 12.3.1).");
    }

    /// <summary>
    /// "External objects are flushed when their associated hierarchy is disabled. If hierarchy is TPM_RH_NULL,
    /// the object is part of no hierarchy, and there is no implicit flush": disabling the owner hierarchy flushes
    /// the owner-associated external object and leaves the <c>TPM_RH_NULL</c> one loaded.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task HierarchyControlFlushesTheOwnerExternalObjectAndLeavesTheNullOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(HierarchyControlFlushesTheOwnerExternalObjectAndLeavesTheNullOne), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        (TpmiDhObject ownerHandle, TpmiDhObject nullHandle) = await LoadUnderOwnerAndNullAsync(tpm, registry, pool, key).ConfigureAwait(false);
        await DisableOwnerHierarchyAsync(tpm, registry, pool).ConfigureAwait(false);

        await AssertReadPublicAnswersAsync(tpm, registry, pool, ownerHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, "The owner-associated external object is flushed with its hierarchy (Part 3, clause 12.3.1), so its transient handle references nothing loaded (clause 5.4, step 2.1).").ConfigureAwait(false);
        await AssertReadPublicAnswersAsync(tpm, registry, pool, nullHandle, TpmRcConstants.TPM_RC_SUCCESS, "The TPM_RH_NULL object is part of no hierarchy and is not flushed (Part 3, clause 12.3.1).").ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Clear()</c> flushes "resident objects (persistent and volatile) in the Storage and Endorsement
    /// hierarchies" (TPM 2.0 Library Part 3, clause 24.6.1): the owner-associated external object is flushed, the
    /// <c>TPM_RH_NULL</c> one stays loaded.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ClearFlushesTheOwnerExternalObjectAndLeavesTheNullOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ClearFlushesTheOwnerExternalObjectAndLeavesTheNullOne), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        (TpmiDhObject ownerHandle, TpmiDhObject nullHandle) = await LoadUnderOwnerAndNullAsync(tpm, registry, pool, key).ConfigureAwait(false);

        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ClearResponse> clearResult = await TpmCommandExecutor.ExecuteAsync<ClearResponse>(
            tpm, new ClearInput(TpmRh.TPM_RH_PLATFORM), [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearResult.IsSuccess, $"TPM2_Clear() under platform authorization failed: '{clearResult.ResponseCode}'.");

        await AssertReadPublicAnswersAsync(tpm, registry, pool, ownerHandle, TpmRcConstants.TPM_RC_REFERENCE_H0, "TPM2_Clear() flushes the owner-associated external object (Part 3, clause 24.6.1), so its transient handle references nothing loaded (clause 5.4, step 2.1).").ConfigureAwait(false);
        await AssertReadPublicAnswersAsync(tpm, registry, pool, nullHandle, TpmRcConstants.TPM_RC_SUCCESS, "TPM2_Clear() leaves the TPM_RH_NULL object loaded (Part 3, clause 24.6.1).").ConfigureAwait(false);
    }

    /// <summary>
    /// A session may not be bound to a public-only object: its bind arm needs the entity's authValue, which a
    /// public-only object has no sensitive area to carry, so <c>TPM2_StartAuthSession()</c> answers
    /// <c>TPM_RC_HANDLE</c> for <c>bind</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task StartAuthSessionBoundToAPublicOnlyObjectIsRefusedWithHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(StartAuthSessionBoundToAPublicOnlyObjectIsRefusedWithHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A public-only key must load, but failed: '{result.ResponseCode}'.");
        using LoadExternalResponse loaded = result.Value;

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(loaded.ObjectHandle.Value, NameAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), startResult.ResponseCode, "A public-only object carries no authValue a session could bind to: TPM_RC_HANDLE (Part 3, clause 11.1).");
    }

    /// <summary>
    /// A command sent before <c>TPM2_Startup()</c> is answered with <c>TPM_RC_INITIALIZE</c>; the load's own rules
    /// are never reached.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.2; Part 3, clause 9.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalBeforeStartupReturnsInitialize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator($"tpm-in-house-load-external-{nameof(LoadExternalBeforeStartupReturnsInitialize)}", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, result.ResponseCode, "Before TPM2_Startup() the TPM answers TPM_RC_INITIALIZE (Part 3, clause 9.3).");
        Assert.AreEqual(TpmLifecyclePhase.Initializing, simulator.CurrentPhase, "The TPM stays in its initializing phase.");
    }

    /// <summary>
    /// In Failure Mode the TPM answers <c>TPM_RC_FAILURE</c> to every command but the few the mode admits, so a
    /// load is refused before any rule of its own runs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.3; Part 3, clause 9.4</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalInFailureModeReturnsFailure()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator($"tpm-in-house-load-external-{nameof(LoadExternalInFailureModeReturnsFailure)}",selfTest: TpmSelfTestBehavior.Fails, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmRcConstants selfTestCode = await SubmitSelfTestAsync(simulator, pool).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, selfTestCode, "A failing self-test enters Failure Mode.");
        Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase, "The TPM is in Failure Mode.");

        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();
        TpmResult<LoadExternalResponse> result = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, result.ResponseCode, "In Failure Mode TPM2_LoadExternal() is TPM_RC_FAILURE (Part 3, clause 9.4).");
    }

    /// <summary>
    /// Pool hygiene: a refused load (an off-curve point) and a successful one whose object is then flushed and
    /// whose response is released leave the pool with exactly the carriers outstanding before them.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalLeavesThePoolBalancedAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalLeavesThePoolBalancedAcrossARefusalAndASuccess), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();
        using EccKeyMaterial key = EccKeyMaterial.Generate();

        long baseline = trackingPool.OutstandingCount;

        byte[] offCurveY = (byte[])key.Y.Clone();
        offCurveY[^1] ^= 0x01;
        TpmResult<LoadExternalResponse> refused = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, ExternalSigningAttributes, key.X, offCurveY, scalar: key.D).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_ECC_POINT, refused.ResponseCode, "The off-curve load is refused with TPM_RC_ECC_POINT.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused load returns every carrier it rented, the sensitive area's included.");

        TpmResult<LoadExternalResponse> accepted = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, ExternalSigningAttributes, key.X, key.Y, scalar: key.D).ConfigureAwait(false);
        Assert.IsTrue(accepted.IsSuccess, $"The load must succeed, but failed: '{accepted.ResponseCode}'.");
        uint handle;
        using(LoadExternalResponse loaded = accepted.Value)
        {
            handle = loaded.ObjectHandle.Value;
        }

        TpmResult<FlushContextResponse> flushed = await HmacKeyHarness.FlushAsync(tpm, registry, pool, handle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushed.IsSuccess, $"Flushing the loaded object failed: '{flushed.ResponseCode}'.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A successful load returns every carrier once the object is flushed and the response released.");
    }

    /// <summary>The malformations <see cref="LoadExternalRefusesAMalformedParameterArea"/> applies to the parameter area.</summary>
    internal enum MalformedShape
    {
        /// <summary>An <c>inPublic</c> of size zero.</summary>
        EmptyPublic,

        /// <summary>An <c>inPrivate</c> declaring one octet more than its <c>TPMT_SENSITIVE</c> consumes.</summary>
        SensitiveOverDeclared,

        /// <summary>An <c>inPrivate</c> declaring more octets than the frame holds.</summary>
        SensitivePastTheFrame,

        /// <summary>A <c>hierarchy</c> value outside <c>TPMI_RH_HIERARCHY</c>.</summary>
        HierarchyOutOfRange,

        /// <summary>An octet after <c>hierarchy</c>.</summary>
        TrailingOctet,

        /// <summary>A <c>TPM2B_PUBLIC</c> declaring one octet more than its <c>TPMT_PUBLIC</c> consumes.</summary>
        PublicOverDeclared,

        /// <summary>An <c>inPublic</c> of type <c>TPM_ALG_SYMCIPHER</c>, paired with a well-formed KEYEDHASH <c>inPrivate</c>.</summary>
        SymCipherPublic,

        /// <summary>An <c>inPublic</c> whose type is a selector this simulator's implemented profile does not recognize at all, paired with a well-formed KEYEDHASH <c>inPrivate</c>.</summary>
        UnknownTypePublic,

        /// <summary>An <c>inPrivate</c> whose <c>seedValue</c> size field exceeds <see cref="Tpm2bDigest.MaxSize"/>.</summary>
        SeedValueOverBound,
    }

    /// <summary>A P-256 key pair minted by the framework, its coordinates and scalar padded to the field width.</summary>
    private sealed class EccKeyMaterial: IDisposable
    {
        /// <summary>Gets the framework key, the off-TPM signing and verifying oracle.</summary>
        public ECDsa Key { get; }

        /// <summary>Gets the public point's X coordinate, 32 octets.</summary>
        public byte[] X { get; }

        /// <summary>Gets the public point's Y coordinate, 32 octets.</summary>
        public byte[] Y { get; }

        /// <summary>Gets the private scalar, 32 octets.</summary>
        public byte[] D { get; }

        /// <summary>Initializes the material from the framework key.</summary>
        /// <param name="key">The framework key; owned.</param>
        private EccKeyMaterial(ECDsa key)
        {
            Key = key;
            ECParameters parameters = key.ExportParameters(includePrivateParameters: true);
            X = PadLeft(parameters.Q.X!, P256ComponentSize);
            Y = PadLeft(parameters.Q.Y!, P256ComponentSize);
            D = PadLeft(parameters.D!, P256ComponentSize);
        }

        /// <summary>Mints a fresh P-256 key pair.</summary>
        /// <returns>The material; the caller disposes it.</returns>
        public static EccKeyMaterial Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

        /// <summary>Releases the framework key and clears the scalar.</summary>
        public void Dispose()
        {
            Array.Clear(D);
            Key.Dispose();
        }
    }

    /// <summary>An RSA-2048 key pair minted by the framework, its modulus and first prime exported.</summary>
    private sealed class RsaKeyMaterial: IDisposable
    {
        /// <summary>Gets the framework key, the off-TPM signing and verifying oracle.</summary>
        public RSA Key { get; }

        /// <summary>Gets the public modulus, 256 octets.</summary>
        public byte[] Modulus { get; }

        /// <summary>Gets the first prime factor, 128 octets.</summary>
        public byte[] P { get; }

        /// <summary>Initializes the material from the framework key.</summary>
        /// <param name="key">The framework key; owned.</param>
        private RsaKeyMaterial(RSA key)
        {
            Key = key;
            RSAParameters parameters = key.ExportParameters(includePrivateParameters: true);
            Modulus = PadLeft(parameters.Modulus!, RsaKeyBits / 8);
            P = PadLeft(parameters.P!, RsaKeyBits / 16);
        }

        /// <summary>Mints a fresh RSA-2048 key pair.</summary>
        /// <returns>The material; the caller disposes it.</returns>
        public static RsaKeyMaterial Generate() => new(RSA.Create(RsaKeyBits));

        /// <summary>Releases the framework key and clears the prime.</summary>
        public void Dispose()
        {
            Array.Clear(P);
            Key.Dispose();
        }
    }

    /// <summary>Left-pads an unsigned big-endian integer to a fixed width.</summary>
    /// <param name="value">The integer's octets.</param>
    /// <param name="width">The target width.</param>
    /// <returns>The padded octets.</returns>
    private static byte[] PadLeft(byte[] value, int width)
    {
        byte[] padded = new byte[width];
        value.CopyTo(padded, width - value.Length);

        return padded;
    }

    /// <summary>Lays an ECDSA signature's two components out as IEEE P1363 <c>r ‖ s</c> at the curve's field width.</summary>
    /// <param name="r">The r component.</param>
    /// <param name="s">The s component.</param>
    /// <returns>The concatenated signature.</returns>
    private static byte[] ConcatenateP1363(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
    {
        byte[] p1363 = new byte[2 * P256ComponentSize];
        r.CopyTo(p1363.AsSpan(P256ComponentSize - r.Length));
        s.CopyTo(p1363.AsSpan((2 * P256ComponentSize) - s.Length));

        return p1363;
    }

    /// <summary>Creates an operational simulator with both asymmetric backends wired.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            $"tpm-in-house-load-external-{name}", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var startup = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startup.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startup.CommandCode);
        header.WriteTo(ref writer);
        startup.WriteHandles(ref writer);
        startup.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)TpmHeader.Parse(ref reader).Code, "TPM2_Startup(CLEAR) must succeed.");
    }

    /// <summary>Issues <c>TPM2_SelfTest(NO)</c> directly against the simulator and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSelfTestAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new SelfTestInput(IsFullTest: false);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer TPM2_SelfTest() rather than fault.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        HmacKeyHarness.CreateRegistry()
            .Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal)
            .Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature)
            .Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign)
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl)
            .Register(TpmCcConstants.TPM_CC_Clear, TpmResponseCodec.Clear)
            .Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature)
            .Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart)
            .Register(TpmCcConstants.TPM_CC_VerifySequenceComplete, TpmResponseCodec.VerifySequenceComplete);

    /// <summary>
    /// Builds an ECC P-256 ECDSA-SHA-256 signing public area carrying the given point (TPM 2.0 Library Part 2,
    /// clause 12.2.4, Table 235).
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nameAlg">The Name algorithm.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <param name="x">The point's X coordinate.</param>
    /// <param name="y">The point's Y coordinate.</param>
    /// <param name="authPolicy">The authorization policy digest, or empty.</param>
    /// <param name="scheme">The ECC scheme, or <see langword="null"/> for the default ECDSA-SHA-256 scheme.</param>
    /// <returns>The public area; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the point transfers to the returned public area, which its owner disposes.")]
    private static Tpm2bPublic BuildEccPublic(
        BaseMemoryPool pool, TpmAlgIdConstants nameAlg, TpmaObject attributes, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, ReadOnlySpan<byte> authPolicy = default, TpmtEccScheme? scheme = null) =>
        Tpm2bPublic.CreateEccSigningKey(nameAlg, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, scheme ?? TpmtEccScheme.Ecdsa(NameAlg), TpmsEccPoint.Create(x, y, pool), pool, authPolicy);

    /// <summary>Builds an RSA-2048 signing public area carrying the given modulus (TPM 2.0 Library Part 2, clause 12.2.4, Table 235).</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nameAlg">The Name algorithm.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <param name="scheme">The signing scheme.</param>
    /// <param name="modulus">The public modulus.</param>
    /// <returns>The public area; the caller owns it.</returns>
    private static Tpm2bPublic BuildRsaPublic(BaseMemoryPool pool, TpmAlgIdConstants nameAlg, TpmaObject attributes, TpmtRsaScheme scheme, ReadOnlySpan<byte> modulus) =>
        Tpm2bPublic.CreateRsaSigningKey(nameAlg, attributes, RsaKeyBits, scheme, modulus, pool);

    /// <summary>Builds an ECC sensitive area (TPM 2.0 Library Part 2, clause 12.3.2, Table 240) around a scalar.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="scalar">The private scalar.</param>
    /// <param name="authValue">The authorization value, or empty.</param>
    /// <param name="seed">The <c>seedValue</c>, or empty.</param>
    /// <returns>The sensitive area; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the three carriers transfers to the returned sensitive area, which its owner disposes.")]
    private static TpmtSensitive BuildEccSensitive(BaseMemoryPool pool, ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> authValue = default, ReadOnlySpan<byte> seed = default) =>
        new(
            authValue.IsEmpty ? Tpm2bAuth.CreateEmpty(pool) : Tpm2bAuth.Create(authValue, pool),
            seed.IsEmpty ? Tpm2bDigest.Empty : Tpm2bDigest.Create(seed, pool),
            TpmuSensitiveComposite.FromEcc(Tpm2bEccParameter.Create(scalar, pool)));

    /// <summary>Transcribes the Name the TPM must compute for an ECC public area built from <paramref name="key"/>: <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c> (TPM 2.0 Library Part 1, clause 13, Table 9).</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nameAlg">The Name algorithm.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <param name="key">The key material.</param>
    /// <returns>The Name octets.</returns>
    private static byte[] TranscribeEccName(BaseMemoryPool pool, TpmAlgIdConstants nameAlg, TpmaObject attributes, EccKeyMaterial key)
    {
        using Tpm2bPublic publicArea = BuildEccPublic(pool, nameAlg, attributes, key.X, key.Y);
        byte[] marshaled = MarshalPublic(publicArea);
        byte[] digest = SHA256.HashData(marshaled.AsSpan(sizeof(ushort)));
        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.CopyTo(name, sizeof(ushort));

        return name;
    }

    /// <summary>Marshals a <c>TPM2B_PUBLIC</c>, size prefix included.</summary>
    /// <param name="publicArea">The public area.</param>
    /// <returns>The octets.</returns>
    private static byte[] MarshalPublic(Tpm2bPublic publicArea)
    {
        byte[] octets = new byte[publicArea.GetSerializedSize()];
        var writer = new TpmWriter(octets);
        publicArea.WriteTo(ref writer);

        return octets;
    }

    /// <summary>Marshals a <c>TPMT_SENSITIVE</c>, no size prefix.</summary>
    /// <param name="sensitive">The sensitive area.</param>
    /// <returns>The octets.</returns>
    private static byte[] MarshalSensitive(TpmtSensitive sensitive)
    {
        byte[] octets = new byte[sensitive.SerializedSize];
        var writer = new TpmWriter(octets);
        sensitive.WriteTo(ref writer);

        return octets;
    }

    /// <summary>
    /// Patches a marshaled RSA storage-shaped <c>TPM2B_PUBLIC</c>'s <c>TPMS_RSA_PARMS.symmetric</c> field from a
    /// real <c>TPMT_SYM_DEF_OBJECT</c> (algorithm ‖ keyBits ‖ mode, six octets) down to the bare
    /// <c>TPM_ALG_NULL</c> selector (two octets), shrinking the buffer and the outer <c>TPM2B_PUBLIC</c> size
    /// prefix by the four octets the bare selector's absent <c>keyBits</c>/<c>mode</c> fields free up.
    /// </summary>
    /// <param name="marshaled">The marshaled <c>TPM2B_PUBLIC</c>: an RSA storage-shaped public area with an empty <c>authPolicy</c>.</param>
    /// <returns>The patched octets.</returns>
    private static byte[] PatchRsaSymmetricToNull(byte[] marshaled)
    {
        //TPM2B_PUBLIC: size(2) ‖ type(2) ‖ nameAlg(2) ‖ objectAttributes(4) ‖ authPolicy(2, empty) ‖
        //TPMS_RSA_PARMS.symmetric: algorithm(2) ‖ keyBits(2) ‖ mode(2).
        const int SymmetricOffset = 2 + 2 + 2 + 4 + 2;
        const int RealSymmetricSize = 6;
        const int NullSymmetricSize = 2;

        byte[] patched = new byte[marshaled.Length - (RealSymmetricSize - NullSymmetricSize)];
        marshaled.AsSpan(0, SymmetricOffset).CopyTo(patched);
        BinaryPrimitives.WriteUInt16BigEndian(patched.AsSpan(SymmetricOffset, sizeof(ushort)), (ushort)TpmAlgIdConstants.TPM_ALG_NULL);
        marshaled.AsSpan(SymmetricOffset + RealSymmetricSize).CopyTo(patched.AsSpan(SymmetricOffset + NullSymmetricSize));

        ushort originalOuterSize = BinaryPrimitives.ReadUInt16BigEndian(marshaled);
        BinaryPrimitives.WriteUInt16BigEndian(patched.AsSpan(0, sizeof(ushort)), (ushort)(originalOuterSize - (RealSymmetricSize - NullSymmetricSize)));

        return patched;
    }

    /// <summary>A fixed 32-octet <c>seedValue</c> for the KEYEDHASH objects.</summary>
    /// <returns>The seed.</returns>
    private static byte[] KeyedHashSeed()
    {
        byte[] seed = new byte[DigestSize];
        for(int index = 0; index < seed.Length; index++)
        {
            seed[index] = (byte)(0xC0 + index);
        }

        return seed;
    }

    /// <summary><c>unique = H_nameAlg(seedValue ‖ sensitive)</c> for a KEYEDHASH object (TPM 2.0 Library Part 2, clause 12.2.3.1, equation (8)), computed off-TPM.</summary>
    /// <param name="seed">The <c>seedValue</c>.</param>
    /// <param name="bits">The key value or sealed data.</param>
    /// <returns>The digest.</returns>
    private static byte[] KeyedHashUnique(byte[] seed, byte[] bits)
    {
        byte[] message = new byte[seed.Length + bits.Length];
        seed.CopyTo(message, 0);
        bits.CopyTo(message, seed.Length);

        return SHA256.HashData(message);
    }

    /// <summary>
    /// Issues <c>TPM2_LoadExternal()</c> for an ECC P-256 ECDSA key built from the given coordinates — public-only
    /// when <paramref name="scalar"/> is empty, with a sensitive area around it otherwise — and returns the raw
    /// result.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy the object joins.</param>
    /// <param name="nameAlg">The Name algorithm.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <param name="x">The point's X coordinate.</param>
    /// <param name="y">The point's Y coordinate.</param>
    /// <param name="scalar">The private scalar, or empty for a public-only load.</param>
    /// <param name="authValue">The sensitive area's authorization value, or empty.</param>
    /// <param name="seed">The sensitive area's <c>seedValue</c>, or empty.</param>
    /// <param name="authPolicy">The public area's authorization policy digest, or empty.</param>
    /// <param name="scheme">The ECC scheme, or <see langword="null"/> for the default ECDSA-SHA-256 scheme.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once the command has been issued.")]
    private async Task<TpmResult<LoadExternalResponse>> LoadEccAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiRhHierarchy hierarchy, TpmAlgIdConstants nameAlg, TpmaObject attributes,
        ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y, ReadOnlyMemory<byte> scalar = default, ReadOnlyMemory<byte> authValue = default, ReadOnlyMemory<byte> seed = default,
        ReadOnlyMemory<byte> authPolicy = default, TpmtEccScheme? scheme = null)
    {
        Tpm2bPublic inPublic = BuildEccPublic(pool, nameAlg, attributes, x.Span, y.Span, authPolicy.Span, scheme);
        TpmtSensitive? inPrivate = scalar.IsEmpty ? null : BuildEccSensitive(pool, scalar.Span, authValue.Span, seed.Span);
        using var input = new LoadExternalInput(inPrivate, inPublic, hierarchy);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_LoadExternal()</c> for an RSA-2048 key built from the given modulus — public-only when
    /// <paramref name="prime"/> is empty, with a sensitive area around the prime otherwise — and returns the raw
    /// result.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy the object joins.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <param name="scheme">The signing scheme.</param>
    /// <param name="modulus">The public modulus.</param>
    /// <param name="prime">One prime factor, or empty for a public-only load.</param>
    /// <param name="nameAlg">The Name algorithm.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once the command has been issued.")]
    private async Task<TpmResult<LoadExternalResponse>> LoadRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiRhHierarchy hierarchy, TpmaObject attributes, TpmtRsaScheme scheme,
        ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> prime = default, TpmAlgIdConstants nameAlg = NameAlg)
    {
        Tpm2bPublic inPublic = BuildRsaPublic(pool, nameAlg, attributes, scheme, modulus.Span);
        TpmtSensitive? inPrivate = prime.IsEmpty
            ? null
            : new TpmtSensitive(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, TpmuSensitiveComposite.FromRsa(Tpm2bPrivateKeyRsa.Create(prime.Span, pool)));
        using var input = new LoadExternalInput(inPrivate, inPublic, hierarchy);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_LoadExternal()</c> for a KEYEDHASH object whose public area carries the given <c>unique</c>
    /// — public-only when <paramref name="seed"/> is empty, with a sensitive area around the seed and the key or
    /// secret otherwise — and returns the raw result.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy the object joins.</param>
    /// <param name="attributes">The attribute word.</param>
    /// <param name="scheme">The keyed-hash scheme.</param>
    /// <param name="unique">The public area's <c>unique</c> digest.</param>
    /// <param name="seed">The sensitive area's <c>seedValue</c>, or empty for a public-only load.</param>
    /// <param name="bits">The key value or sealed data.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once the command has been issued.")]
    private async Task<TpmResult<LoadExternalResponse>> LoadKeyedHashAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiRhHierarchy hierarchy, TpmaObject attributes, TpmsKeyedHashParms scheme,
        ReadOnlyMemory<byte> unique, ReadOnlyMemory<byte> seed = default, ReadOnlyMemory<byte> bits = default)
    {
        Tpm2bPublic inPublic = Tpm2bPublic.CreateKeyedHashTemplate(NameAlg, attributes, scheme, default, pool, unique.Span);
        TpmtSensitive? inPrivate = seed.IsEmpty
            ? null
            : TpmtSensitive.ForKeyedHash(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Create(seed.Span, pool), Tpm2bSensitiveData.Create(bits.Span, pool));
        using var input = new LoadExternalInput(inPrivate, inPublic, hierarchy);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_LoadExternal()</c> under <c>TPM_RH_NULL</c> with an ECC public area and a KEYEDHASH sensitive area, the type mismatch under test, and returns the raw result.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The ECC key material for the public area.</param>
    /// <param name="seed">The sensitive area's <c>seedValue</c>.</param>
    /// <param name="bits">The sensitive area's key value.</param>
    /// <returns>The raw result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public and sensitive areas transfers to the load input, disposed here once the command has been issued.")]
    private async Task<TpmResult<LoadExternalResponse>> LoadEccPublicWithKeyedHashSensitiveAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, EccKeyMaterial key, ReadOnlyMemory<byte> seed, ReadOnlyMemory<byte> bits)
    {
        Tpm2bPublic inPublic = BuildEccPublic(pool, NameAlg, ExternalSigningAttributes, key.X, key.Y);
        TpmtSensitive inPrivate = TpmtSensitive.ForKeyedHash(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Create(seed.Span, pool), Tpm2bSensitiveData.Create(bits.Span, pool));
        using var input = new LoadExternalInput(inPrivate, inPublic, TpmiRhHierarchy.Null);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a public-only <c>TPM2_LoadExternal()</c> whose public area is parsed from already-marshaled octets, and returns the raw result.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy the object joins.</param>
    /// <param name="marshaledPublic">The <c>TPM2B_PUBLIC</c> octets, size prefix included.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parsed public area transfers to the load input, disposed here once the command has been issued.")]
    private async Task<TpmResult<LoadExternalResponse>> LoadMarshaledPublicAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiRhHierarchy hierarchy, byte[] marshaledPublic)
    {
        var reader = new TpmReader(marshaledPublic);
        using LoadExternalInput input = LoadExternalInput.PublicOnly(Tpm2bPublic.Parse(ref reader, pool), hierarchy);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Loads the same public-only key under the owner hierarchy and under <c>TPM_RH_NULL</c>.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="key">The key material.</param>
    /// <returns>The two loaded handles.</returns>
    private async Task<(TpmiDhObject OwnerHandle, TpmiDhObject NullHandle)> LoadUnderOwnerAndNullAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, EccKeyMaterial key)
    {
        TpmResult<LoadExternalResponse> ownerResult = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Owner, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.IsTrue(ownerResult.IsSuccess, $"The owner-associated load failed: '{ownerResult.ResponseCode}'.");
        using LoadExternalResponse ownerLoaded = ownerResult.Value;

        TpmResult<LoadExternalResponse> nullResult = await LoadEccAsync(tpm, registry, pool, TpmiRhHierarchy.Null, NameAlg, ExternalSigningAttributes, key.X, key.Y).ConfigureAwait(false);
        Assert.IsTrue(nullResult.IsSuccess, $"The TPM_RH_NULL load failed: '{nullResult.ResponseCode}'.");
        using LoadExternalResponse nullLoaded = nullResult.Value;

        return (ownerLoaded.ObjectHandle, nullLoaded.ObjectHandle);
    }

    /// <summary>Disables the owner hierarchy through <c>TPM2_HierarchyControl(shEnable, NO)</c> under platform authorization.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DisableOwnerHierarchyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            tpm, new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, TpmRh.TPM_RH_OWNER, TpmiYesNo.No), [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl(OWNER, NO) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues <c>TPM2_ReadPublic()</c> and asserts it succeeded.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The object.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<ReadPublicResponse> ReadPublicAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject handle)
    {
        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, ReadPublicInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadPublic() failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Issues <c>TPM2_ReadPublic()</c> and asserts its response code.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The object.</param>
    /// <param name="expected">The expected response code.</param>
    /// <param name="because">The assertion message.</param>
    private async Task AssertReadPublicAnswersAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject handle, TpmRcConstants expected, string because)
    {
        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, ReadPublicInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        TpmRcConstants observed = result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;
        Assert.AreEqual(expected, observed, because);

        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }
    }

    /// <summary>Verifies an ECDSA signature through <c>TPM2_VerifySignature()</c> and asserts it succeeded.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The verifying key.</param>
    /// <param name="digest">The digest.</param>
    /// <param name="signature">The IEEE P1363 signature.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<VerifySignatureResponse> VerifyEcdsaAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject handle, byte[] digest, byte[] signature)
    {
        using VerifySignatureInput input = VerifySignatureInput.ForEcdsa(handle, digest, signature, NameAlg, pool);
        TpmResult<VerifySignatureResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySignature() over the framework's ECDSA signature must succeed, but failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Drives <c>TPM2_VerifySignature()</c>, <c>TPM2_VerifyDigestSignature()</c>, and
    /// <c>TPM2_VerifySequenceStart()</c>/<c>TPM2_SequenceUpdate()</c>/<c>TPM2_VerifySequenceComplete()</c>
    /// against <paramref name="handle"/> with an off-TPM <paramref name="signature"/> over
    /// <paramref name="digest"/>/<see cref="MessageBytes"/>, asserting every response's ticket is the NULL
    /// Ticket.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The loaded key.</param>
    /// <param name="digest">The digest the signature is claimed to be over.</param>
    /// <param name="signature">The off-TPM signature: IEEE P1363 for ECDSA, raw PKCS#1 v1.5 for RSASSA.</param>
    /// <param name="isRsa">Whether <paramref name="signature"/> is RSASSA (else ECDSA).</param>
    private async Task AssertNullTicketsAcrossVerifyCommandsAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject handle, byte[] digest, byte[] signature, bool isRsa)
    {
        using VerifySignatureInput signatureInput = isRsa
            ? VerifySignatureInput.ForRsaSsa(handle, digest, signature, NameAlg, pool)
            : VerifySignatureInput.ForEcdsa(handle, digest, signature, NameAlg, pool);
        TpmResult<VerifySignatureResponse> signatureResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, signatureInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signatureResult.IsSuccess, $"TPM2_VerifySignature() must succeed, but failed: '{signatureResult.ResponseCode}'.");
        using(VerifySignatureResponse signatureVerified = signatureResult.Value)
        {
            Assert.IsTrue(signatureVerified.Validation.IsNull, "nameAlg TPM_ALG_NULL mints a NULL ticket from TPM2_VerifySignature() (Part 3, clause 12.3.1).");
        }

        using VerifyDigestSignatureInput digestInput = isRsa
            ? VerifyDigestSignatureInput.ForRsaSsa(handle, digest, signature, NameAlg, pool)
            : VerifyDigestSignatureInput.ForEcdsa(handle, digest, signature, NameAlg, pool);
        TpmResult<VerifyDigestSignatureResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, digestInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(digestResult.IsSuccess, $"TPM2_VerifyDigestSignature() must succeed, but failed: '{digestResult.ResponseCode}'.");
        using(VerifyDigestSignatureResponse digestVerified = digestResult.Value)
        {
            Assert.IsTrue(digestVerified.Validation.IsNull, "nameAlg TPM_ALG_NULL mints a NULL ticket from TPM2_VerifyDigestSignature() (Part 3, clause 12.3.1).");
        }

        using VerifySequenceStartInput startInput = VerifySequenceStartInput.Create(handle, [], pool);
        TpmResult<VerifySequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_VerifySequenceStart() must succeed, but failed: '{startResult.ResponseCode}'.");
        TpmiDhObject sequence = startResult.Value.SequenceHandle;

        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using SequenceUpdateInput updateInput = SequenceUpdateInput.Create(sequence, MessageBytes, pool);
        TpmResult<SequenceUpdateResponse> updateResult = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, updateInput, [sequenceAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(updateResult.IsSuccess, $"TPM2_SequenceUpdate() must succeed, but failed: '{updateResult.ResponseCode}'.");

        using TpmPasswordSession completeAuth = TpmPasswordSession.CreateEmpty(pool);
        using VerifySequenceCompleteInput completeInput = isRsa
            ? VerifySequenceCompleteInput.ForRsaSsa(sequence, handle, signature, NameAlg, pool)
            : VerifySequenceCompleteInput.ForEcdsa(sequence, handle, signature, NameAlg, pool);
        TpmResult<VerifySequenceCompleteResponse> completeResult = await TpmCommandExecutor.ExecuteAsync<VerifySequenceCompleteResponse>(
            tpm, completeInput, [completeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(completeResult.IsSuccess, $"TPM2_VerifySequenceComplete() must succeed, but failed: '{completeResult.ResponseCode}'.");
        using(VerifySequenceCompleteResponse sequenceVerified = completeResult.Value)
        {
            Assert.IsTrue(sequenceVerified.Validation.IsNull, "nameAlg TPM_ALG_NULL mints a NULL ticket from TPM2_VerifySequenceComplete() (Part 3, clause 12.3.1).");
        }
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

    /// <summary>Frames a <c>TPM_ST_NO_SESSIONS</c> <c>TPM2_LoadExternal()</c> header around <paramref name="body"/>, submits it straight to the simulator, and returns the response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="body">The parameter area, already laid out.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_LoadExternal);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a malformed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }
}
