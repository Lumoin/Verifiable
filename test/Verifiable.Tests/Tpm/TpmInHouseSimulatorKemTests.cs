using System;
using System.Buffers;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Verifiable.Cryptography;
using Verifiable.Foundation.Automata;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_CreatePrimary()</c> (the ECC KEM template), <c>TPM2_Encapsulate()</c>, and
/// <c>TPM2_Decapsulate()</c> against the in-house behavioural <see cref="TpmSimulator"/> — entirely
/// in-process, with no external assets — through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> with the real <see cref="CreatePrimaryInput"/>,
/// <see cref="EncapsulateInput"/>, <see cref="DecapsulateInput"/>, and response codecs). Covers KEM-key
/// creation admission and its <c>TPM_RC_KDF</c>/<c>TPM_RC_SYMMETRIC</c>/<c>TPM_RC_SCHEME</c> refusals, the
/// Encapsulate/Decapsulate round trip and its freshness/determinism security-hardening properties, an
/// independent host-side check on the simulator's own <c>kem_context</c> assembly, the <c>TPM_RC_KEY</c>
/// key-shape gate, the clause 14.11.1 anti-oracle <c>TPM_RC_ATTRIBUTES</c> gate, malformed-ciphertext
/// <c>TPM_RC_ECC_POINT</c> refusals, and the auth/session gates on <c>TPM2_Decapsulate()</c>.
/// </summary>
/// <remarks>
/// <b>RFC 9180 vector-exactness is not reachable through this simulator.</b> <c>TPM2_CreatePrimary()</c>
/// always generates its own recipient key pair (DHKEM's <c>skR</c>/<c>pkR</c>); there is no shipped surface
/// to inject RFC 9180 Appendix A.3.1's fixed recipient key material into a KEM key created this way, and this
/// simulator's <c>TPM2_Create()</c>/<c>TPM2_Import()</c> paths admit only <c>TPM_ALG_KEYEDHASH</c> objects (so
/// importing a vector-exact ECC key under a storage parent is not a route either — independently confirmed by
/// reading <c>TryParseCreate</c>'s and <c>OnImport</c>'s own type gates). Reaching vector-exact decapsulation
/// would need a test-only seam in production code, which the house rules forbid. The vector-level proof —
/// both the encapsulation math and a full round trip against the SAME vector — lives in
/// <see cref="Verifiable.Tests.Cryptography.DhkemTests"/> instead, over the shared DHKEM core this
/// simulator's own Encapsulate/Decapsulate effects call
/// (<see cref="Dhkem.ExtractAndExpandAsync"/>), and the host-side encapsulation core's own reproduction of
/// the same vector's <c>enc</c> lives in <see cref="DhkemEncapsulationTests"/>. What THIS file proves
/// instead is that the simulator's command-level plumbing (parsing, gating, framing) is correct, and —
/// independently of any vector — that the simulator's own <c>kem_context</c> assembly matches an ephemeral
/// this file generates and derives against entirely outside the simulator
/// (<see cref="DecapsulateAgainstAnIndependentlyGeneratedCiphertextMatchesAHostSideDerivation"/>,
/// <see cref="HostSideEncapsulationDecapsulatedBySimulatorYieldsTheSameSharedSecret"/>).
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorKemTests
{
    /// <summary>The RSA modulus size in bits used by the RSA-key gate test.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The real password a DA-protected KEM key's own-authValue verification proof creates the key with.</summary>
    private const string KemKeyPassword = "kem-key-auth-proof";

    /// <summary>
    /// <see cref="KemKeyPassword"/>'s UTF-8 octets, matching the password-to-authValue convention
    /// <see cref="Tpm2bAuth.CreateFromPassword"/> applies on the creation side.
    /// </summary>
    private static byte[] KemKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(KemKeyPassword);

    /// <summary>A wrong guess at the KEM key's password, distinct from <see cref="KemKeyPasswordBytes"/>'s UTF-8 octets.</summary>
    private static byte[] WrongKemKeyPasswordBytes { get; } = [0x5D, 0x5E, 0x5F, 0x60];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A KEM key template — an unrestricted decryption <c>TPM_ALG_ECDH</c> key with a non-NULL
    /// <c>TPM_ALG_HKDF</c> kdf — is admitted by <c>TPM2_CreatePrimary()</c>, and the created object's exported
    /// public area retains the KEM shape: <c>ECDH</c> scheme, <c>HKDF</c> kdf under the requested hash, and a
    /// real P-256 public point (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 2: Structures, clause 12.2.3.6, Table 229).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryForEccKemKeyIsAdmitted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmsEccParms eccParms = primary.OutPublic.PublicArea.Parameters.EccDetail!.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDH, eccParms.Scheme.Scheme, "A KEM key's scheme is TPM_ALG_ECDH.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_HKDF, eccParms.Kdf.Scheme, "Currently, TPM_ALG_HKDF is the only supported KDF for DHKEM.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, eccParms.Kdf.HashAlg);
        Assert.AreEqual(32, primary.OutPublic.PublicArea.Unique.Ecc!.X.Length, "P-256's coordinate width.");
        Assert.AreEqual(32, primary.OutPublic.PublicArea.Unique.Ecc!.Y.Length, "P-256's coordinate width.");
    }

    /// <summary>
    /// Table 229's <c>kdf</c> field is admitted "if the key is an unrestricted decryption TPM_ALG_ECDH
    /// key... Shall be NULL in all other cases (TPM_RC_KDF)": a template that is otherwise a well-formed
    /// DHKEM(P-256, HKDF-SHA256) KEM key but additionally carries <c>TPMA_OBJECT.restricted</c> is refused
    /// <c>TPM_RC_KDF</c> at creation — the admission gate is checked against the attribute shape, not
    /// merely against scheme/kdf identity
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.6, Table 229).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryEccKemKeyWithRestrictedAttributeReturnsKdf()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var restrictedKemAttributes =
            TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH | TpmaObject.DECRYPT | TpmaObject.RESTRICTED | TpmaObject.NO_DA;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = Tpm2bPublic.CreateEccKemKeyTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256, restrictedKemAttributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256);
        using var primaryInput = new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KDF, result.ResponseCode, "A KEM kdf on a RESTRICTED decrypt template must be refused with TPM_RC_KDF.");
    }

    /// <summary>
    /// "Currently, TPM_ALG_HKDF is the only supported KDF for DHKEM" (Table 229): an otherwise well-formed
    /// unrestricted-decrypt <c>ECDH</c> template whose <c>kdf.scheme</c> is <c>TPM_ALG_MGF1</c> instead of
    /// <c>TPM_ALG_HKDF</c> is refused <c>TPM_RC_KDF</c> at creation
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.6, Table 229). No shipped factory can express
    /// this shape — <see cref="TpmsEccParms.ForKeyEncapsulation"/> always selects <c>TPM_ALG_HKDF</c> — so the
    /// template is hand-built via <see cref="BuildEccKemTemplateWithCustomKdfScheme"/>.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryEccKemKeyWithMgf1KdfSchemeReturnsKdf()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildEccKemTemplateWithCustomKdfScheme(TpmAlgIdConstants.TPM_ALG_MGF1, pool);
        using var primaryInput = new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KDF, result.ResponseCode, "A non-HKDF kdf.scheme on an otherwise-KEM-shaped template must be refused with TPM_RC_KDF.");
    }

    /// <summary>
    /// This simulator's one wired DHKEM suite is DHKEM(P-256, HKDF-SHA256): a template requesting
    /// HKDF-SHA384 on P-256 names no suite this simulator can service and is refused <c>TPM_RC_KDF</c> at
    /// creation rather than minting a key it could never correctly encapsulate/decapsulate for
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.6, Table 229).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryEccKemKeyWithHkdfSha384OnP256ReturnsKdf()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var attributes =
            TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH | TpmaObject.DECRYPT | TpmaObject.NO_DA;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = Tpm2bPublic.CreateEccKemKeyTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256, attributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA384);
        using var primaryInput = new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KDF, result.ResponseCode, "HKDF-SHA384 on P-256 names no DHKEM suite this simulator wires; it must be refused with TPM_RC_KDF rather than minted.");
    }

    /// <summary>
    /// Table 229's <c>symmetric</c> row: "if the key is not a restricted decryption key, this field shall be
    /// set to TPM_ALG_NULL." On an unrestricted KEM template a non-NULL <c>symmetric</c> — here AES-128-CFB —
    /// is therefore refused <c>TPM_RC_SYMMETRIC</c> (a restricted template carrying a kdf answers for the kdf
    /// first, <c>TPM_RC_KDF</c>)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.6, Table 229).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryEccKemKeyWithNonNullSymmetricReturnsSymmetric()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildEccKemTemplateWithSymmetric(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), pool);
        using var primaryInput = new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SYMMETRIC, result.ResponseCode, "A KEM template's non-NULL symmetric must be refused with TPM_RC_SYMMETRIC.");
    }

    /// <summary>
    /// Table 229's <c>scheme</c> row: "If the sign attribute of the key is SET, then this shall be a valid
    /// signing scheme." <c>TPM_ALG_ECDH</c> is not a signing scheme, so a KEM template additionally carrying
    /// <c>SIGN_ENCRYPT</c> is refused <c>TPM_RC_SCHEME</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.6, Table 229).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryEccKemKeyWithSignEncryptSetReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildEccKemTemplateWithSignEncryptSet(pool);
        using var primaryInput = new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, result.ResponseCode, "A KEM template carrying SIGN_ENCRYPT must be refused with TPM_RC_SCHEME — TPM_ALG_ECDH is not a signing scheme.");
    }

    /// <summary>
    /// An ECC template whose scheme is <c>TPM_ALG_NULL</c> (not <c>TPM_ALG_ECDH</c>) on an unrestricted-decrypt
    /// key, but which still carries a non-NULL HKDF <c>kdf</c>, matches neither the ECDSA branch, the KEM
    /// branch, nor the RESTRICTED+DECRYPT storage branch this simulator models: it falls through to the
    /// ECC-wide "any other case" gate and is refused <c>TPM_RC_KDF</c> rather than the generic
    /// <c>TPM_RC_SCHEME</c> catch-all
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.6, Table 229).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryEccTemplateWithNullSchemeAndHkdfKdfFallsThroughToKdf()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildEccNullSchemeTemplateWithKdf(pool);
        using var primaryInput = new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KDF, result.ResponseCode, "A NULL-scheme ECC template carrying a non-NULL kdf must fall through to TPM_RC_KDF, not the generic TPM_RC_SCHEME catch-all.");
    }

    /// <summary>
    /// Part 3, clause 24.1.1: "All of the bits of the template are used in the creation of the Primary Key" —
    /// a KEM template's own <c>scheme.details.ecdh.hashAlg</c> is creation-time template data and must be
    /// echoed into the exported public area UNCHANGED, independently of <c>kdf.hashAlg</c>, even though Table
    /// 229 states the field is ignored once the key is actually used with <c>TPM2_Encapsulate()</c>/
    /// <c>TPM2_Decapsulate()</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 12.2.3.6, Table 229; Part 3: Commands, clause 24.1.1).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryForEccKemKeyEchoesTheTemplatesOwnSchemeHashIndependentlyOfTheKdfHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using Tpm2bPublic inPublic = BuildEccKemTemplateWithDistinctSchemeHash(TpmAlgIdConstants.TPM_ALG_SHA384, pool);
        using var primaryInput = new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC KEM key, distinct scheme/kdf hash) failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse primary = result.Value;
        TpmsEccParms eccParms = primary.OutPublic.PublicArea.Parameters.EccDetail!.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA384, eccParms.Scheme.HashAlg, "The template's own scheme.details.ecdh.hashAlg must echo unchanged, never substituted with the KDF hash.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, eccParms.Kdf.HashAlg, "kdf.hashAlg parameterizes DHKEM and stays independent of scheme.details.ecdh.hashAlg.");
    }

    /// <summary>
    /// <c>TPM2_Encapsulate()</c> followed by <c>TPM2_Decapsulate()</c> over the resulting ciphertext
    /// reproduces the identical 32-octet DHKEM(P-256, HKDF-SHA256) shared secret on both sides, and the
    /// ciphertext is a 65-octet SEC 1 uncompressed point (<c>0x04 || X || Y</c>) — clause 44.4.2 step 3's
    /// ciphertext = <c>pkE_serialized</c> (Part 1, clause 44.4.2)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clauses 14.10/14.11).
    /// </summary>
    [TestMethod]
    public async Task EncapsulateThenDecapsulateProducesTheSameSharedSecret()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using EncapsulateResponse encapsulated = await EncapsulateAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        Assert.AreEqual(Dhkem.P256HkdfSha256.NSecret, encapsulated.SharedSecret.Size, "DHKEM(P-256, HKDF-SHA256)'s Nsecret is 32.");
        Assert.AreEqual(1 + 2 * 32, encapsulated.Ciphertext.Size, "A SEC 1 uncompressed P-256 point is 65 octets: 0x04 plus two 32-octet coordinates.");
        Assert.AreEqual(0x04, encapsulated.Ciphertext.Ciphertext[0]);

        byte[] ciphertextBytes = encapsulated.Ciphertext.Ciphertext.ToArray();
        using DecapsulateResponse decapsulated = await DecapsulateAsync(tpm, registry, pool, primary.ObjectHandle, ciphertextBytes, password: null).ConfigureAwait(false);

        Assert.AreEqual(Dhkem.P256HkdfSha256.NSecret, decapsulated.SharedSecret.Size);
        Assert.AreSequenceEqual(encapsulated.SharedSecret.AsReadOnlySpan().ToArray(), decapsulated.SharedSecret.AsReadOnlySpan().ToArray(), "Both sides of a genuine DHKEM exchange must recover the identical shared secret.");
    }

    /// <summary>
    /// THE INDEPENDENT <c>kem_context</c> ORACLE. Both <c>TPM2_Encapsulate()</c> and <c>TPM2_Decapsulate()</c>
    /// route through the SAME simulator helper to assemble <c>kem_context = pkE_serialized ||
    /// pkR_serialized</c> (Part 1, clause 44.4.3 step 3), so an Encapsulate/Decapsulate round trip through the
    /// simulator alone cannot catch a wrong concatenation order or a swapped operand — both arms would still
    /// agree with each other. This test supplies its OWN ephemeral key pair (<c>skT</c>, <c>pkT</c>) via
    /// BouncyCastle, submits <c>pkT</c> as a real <c>TPM2_Decapsulate()</c> ciphertext against a genuine
    /// simulator KEM key, and compares the returned shared secret against a derivation computed entirely
    /// OUTSIDE the simulator: <c>dh = skT · pkR</c> via BouncyCastle, <c>kem_context = pkT || pkR</c>
    /// assembled independently in this test, and <see cref="Dhkem.ExtractAndExpandAsync"/> called directly —
    /// never through the simulator's own <c>kem_context</c>-assembly helper — a peer-side reproduction of
    /// clause 44.4.3's Decap steps
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 44.4.3).
    /// </summary>
    [TestMethod]
    public async Task DecapsulateAgainstAnIndependentlyGeneratedCiphertextMatchesAHostSideDerivation()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] pkR = ExtractEccPoint(primary).ToArray();

        (byte[] skT, byte[] pkT) = GenerateP256KeyPair();

        using DecapsulateResponse decapsulated = await DecapsulateAsync(tpm, registry, pool, primary.ObjectHandle, pkT, password: null).ConfigureAwait(false);

        byte[] dh = ComputeP256DiffieHellman(skT, pkR);
        byte[] kemContext = Concat(pkT, pkR);
        using IMemoryOwner<byte> expected = await Dhkem.ExtractAndExpandAsync(
            Dhkem.P256HkdfSha256.HashAlgorithm, dh, kemContext, Dhkem.P256HkdfSha256.KemId, Dhkem.P256HkdfSha256.NSecret, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreSequenceEqual(
            expected.Memory.Span[..Dhkem.P256HkdfSha256.NSecret].ToArray(), decapsulated.SharedSecret.AsReadOnlySpan().ToArray(),
            "The simulator's Decapsulate() must recover the identical shared secret an independent host-side DHKEM derivation computes from the same skT·pkR and pkT || pkR — pinning kem_context's concatenation order against a same-helper tautology.");
    }

    /// <summary>
    /// HOST-ENCAP → SIM-DECAP END TO END. <see cref="DhkemEncapsulation.EncapsulateAsync"/> — the host-side
    /// core, run entirely outside the simulator — encapsulates against a simulator KEM key's own public
    /// point; decapsulating the resulting ciphertext through a real <c>TPM2_Decapsulate()</c> against that
    /// same key recovers the identical shared secret. Because the host core and the simulator's own
    /// Encapsulate effect never share a code path (only the underlying <see cref="Dhkem"/> KDF composition
    /// itself is shared), this pins the simulator's <c>kem_context</c> assembly against an
    /// independently-driven encapsulation, closing the other half of the same-helper tautology
    /// <see cref="DecapsulateAgainstAnIndependentlyGeneratedCiphertextMatchesAHostSideDerivation"/> closes for
    /// Decapsulate
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 44.4.2/44.4.3).
    /// </summary>
    [TestMethod]
    public async Task HostSideEncapsulationDecapsulatedBySimulatorYieldsTheSameSharedSecret()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        ReadOnlyMemory<byte> pkR = ExtractEccPoint(primary);

        TpmEccSigningBackend backend = BouncyCastleTpmEccSigningBackend.Create();
        (Tpm2bSharedSecret hostSecret, Tpm2bKemCiphertext hostCiphertext) = await DhkemEncapsulation.EncapsulateAsync(
            pkR, backend.GenerateKey, backend.ComputeSharedSecret, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] ciphertextBytes;
        using(hostCiphertext)
        {
            ciphertextBytes = hostCiphertext.Ciphertext.ToArray();
        }

        using(hostSecret)
        {
            using DecapsulateResponse decapsulated = await DecapsulateAsync(tpm, registry, pool, primary.ObjectHandle, ciphertextBytes, password: null).ConfigureAwait(false);

            Assert.AreSequenceEqual(
                hostSecret.AsReadOnlySpan().ToArray(), decapsulated.SharedSecret.AsReadOnlySpan().ToArray(),
                "A ciphertext the host-side DHKEM core produced independently of the simulator must decapsulate, through a real TPM2_Decapsulate(), to the identical shared secret.");
        }
    }

    /// <summary>
    /// Every <c>TPM2_Encapsulate()</c> call generates a fresh ephemeral key pair (clause 44.4.2 step 1): two
    /// calls against the same KEM key produce different shared secrets and different ciphertexts — the
    /// "Encapsulate never returns the same secret twice" security-hardening property
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.10).
    /// </summary>
    [TestMethod]
    public async Task EncapsulateProducesFreshSecretsAndCiphertextsAcrossCalls()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        using EncapsulateResponse first = await EncapsulateAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);
        using EncapsulateResponse second = await EncapsulateAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        Assert.IsFalse(first.SharedSecret.AsReadOnlySpan().SequenceEqual(second.SharedSecret.AsReadOnlySpan()), "Two Encapsulate() calls must never return the same shared secret.");
        Assert.IsFalse(first.Ciphertext.Ciphertext.SequenceEqual(second.Ciphertext.Ciphertext), "Two Encapsulate() calls must generate distinct ephemeral ciphertexts.");
    }

    /// <summary>
    /// <c>TPM2_Decapsulate()</c> is a pure function of the key's private point and the supplied ciphertext:
    /// decapsulating the same ciphertext twice recovers byte-identical shared secrets — the "Decapsulate is
    /// deterministic (same ciphertext → same secret, no state mutation)" security-hardening property
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.11).
    /// </summary>
    [TestMethod]
    public async Task DecapsulateIsDeterministicForTheSameCiphertext()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using EncapsulateResponse encapsulated = await EncapsulateAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);
        byte[] ciphertextBytes = encapsulated.Ciphertext.Ciphertext.ToArray();

        using DecapsulateResponse first = await DecapsulateAsync(tpm, registry, pool, primary.ObjectHandle, ciphertextBytes, password: null).ConfigureAwait(false);
        using DecapsulateResponse second = await DecapsulateAsync(tpm, registry, pool, primary.ObjectHandle, ciphertextBytes, password: null).ConfigureAwait(false);

        Assert.AreSequenceEqual(first.SharedSecret.AsReadOnlySpan().ToArray(), second.SharedSecret.AsReadOnlySpan().ToArray(), "Decapsulating the identical ciphertext twice must recover byte-identical shared secrets.");
    }

    /// <summary>
    /// <c>TPM2_Encapsulate()</c>'s <c>keyHandle</c> carries Auth Index None — "The TPM does not verify the
    /// objectAttributes of the key" — so the command executes successfully with an EMPTY session list
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.10, Table 60).
    /// </summary>
    [TestMethod]
    public async Task EncapsulateExecutesWithNoAuthorizationSessions()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        EncapsulateInput input = EncapsulateInput.ForHandle(primary.ObjectHandle);
        TpmResult<EncapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_Encapsulate must succeed with no sessions at all: '{result.ResponseCode}'.");
        result.Value.Dispose();
    }

    /// <summary>
    /// "The key referenced by keyHandle shall be a KEM key (TPM_RC_KEY)" (clause 14.10.1): an ordinary ECDSA
    /// signing key — ECC, but <c>kdf</c> NULL — is not a KEM key and is refused <c>TPM_RC_KEY</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.10).
    /// </summary>
    [TestMethod]
    public async Task EncapsulateAgainstAKdfNullEccSigningKeyReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        EncapsulateInput encapsulateInput = EncapsulateInput.ForHandle(primary.ObjectHandle);
        TpmResult<EncapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
            tpm, encapsulateInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "A kdf-NULL ECC signing key is not a KEM key and must be refused with TPM_RC_KEY.");
    }

    /// <summary>
    /// The v185 command KEM has no RSA arm at all (Table 101 has only <c>ecdh</c>/<c>mlkem</c> selectors): an
    /// RSA key of any kind is refused <c>TPM_RC_KEY</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.10).
    /// </summary>
    [TestMethod]
    public async Task EncapsulateAgainstAnRsaKeyReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        EncapsulateInput encapsulateInput = EncapsulateInput.ForHandle(primary.ObjectHandle);
        TpmResult<EncapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
            tpm, encapsulateInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "An RSA key is never a KEM key (Table 101 has no RSA arm) and must be refused with TPM_RC_KEY.");
    }

    /// <summary>
    /// A loaded KEYEDHASH sealed-data object lives in the simulator's sealed-object table, not among its
    /// signing/KEM keys, so <c>OnEncapsulate</c> refuses it through its dedicated sealed-object arm — never
    /// through the KEM-key gate a real transient object resolves through — and answers <c>TPM_RC_KEY</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.10.1).
    /// </summary>
    [TestMethod]
    public async Task EncapsulateAgainstASealedKeyedhashObjectReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = parentResult.Value;
        uint parentHandle = parent.ObjectHandle.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData("not a KEM key"u8.ToArray(), pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal) failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

        using LoadResponse loaded = loadResult.Value;
        EncapsulateInput encapsulateInput = EncapsulateInput.ForHandle(loaded.ObjectHandle);
        TpmResult<EncapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
            tpm, encapsulateInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode, "A sealed KEYEDHASH object is not a KEM key and must be refused with TPM_RC_KEY.");
    }

    /// <summary>
    /// "The key referenced by keyHandle shall be a KEM key (TPM_RC_KEY)" (clause 14.11.1): an ordinary ECDSA
    /// signing key — ECC, but <c>kdf</c> NULL — is not a KEM key and is refused <c>TPM_RC_KEY</c> on
    /// <c>TPM2_Decapsulate()</c> exactly as on Encapsulate. The KEY gate is checked before the ciphertext is
    /// ever validated (Part 1, clause 44.5.1 runs only inside the effect this transition's success declares),
    /// so an arbitrary stand-in ciphertext suffices
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.11).
    /// </summary>
    [TestMethod]
    public async Task DecapsulateAgainstAKdfNullEccSigningKeyReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] standInCiphertext = [0x04, 0xAA, 0xBB, 0xCC, 0xDD];
        TpmRcConstants code = await SubmitDecapsulateAndGetResponseCodeAsync(tpm, registry, pool, primary.ObjectHandle, standInCiphertext, password: null).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, code, "A kdf-NULL ECC signing key is not a KEM key and must be refused with TPM_RC_KEY on Decapsulate.");
    }

    /// <summary>
    /// A real storage parent — RESTRICTED and DECRYPT SET, but never a KEM key (<c>kdf</c> NULL) — hits
    /// clause 14.11.1's KEY gate before its ATTRIBUTES gate: the clause's own sentence order names the
    /// KEM-key rule first ("shall be a KEM key (TPM_RC_KEY) with restricted CLEAR and decrypt SET
    /// (TPM_RC_ATTRIBUTES)"), and no storage parent this simulator creates ever carries a non-NULL kdf, so
    /// Decapsulate against one answers <c>TPM_RC_KEY</c>, never <c>TPM_RC_ATTRIBUTES</c> — the anti-oracle
    /// ATTRIBUTES gate (<see cref="DecapsulateAgainstAKemKeyForcedRestrictedReturnsAttributes"/>) stands as
    /// defense in depth for a shape no real key of this simulator's own minting ever reaches
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.11.1).
    /// </summary>
    [TestMethod]
    public async Task DecapsulateAgainstARealStorageParentReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary storage parent failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = primaryResult.Value;
        byte[] standInCiphertext = [0x04, 0xAA, 0xBB, 0xCC, 0xDD];
        TpmRcConstants code = await SubmitDecapsulateAndGetResponseCodeAsync(tpm, registry, pool, parent.ObjectHandle, standInCiphertext, password: null).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, code, "A real storage parent has no kdf and must be refused with TPM_RC_KEY before the ATTRIBUTES gate is ever reached.");
    }

    /// <summary>
    /// THE ANTI-ORACLE TEST. Clause 14.11.1: <c>TPM2_Decapsulate()</c>'s key "shall be a KEM key (TPM_RC_KEY)
    /// with restricted CLEAR and decrypt SET (TPM_RC_ATTRIBUTES)". This gate is what keeps the new,
    /// general-purpose, UNLABELED KEM primitive (Part 1, clause 8.4.5.1) from becoming a decryption oracle
    /// against a key protecting the OLDER, architecturally disjoint Labeled KEM traffic of clause 8.4.5.2
    /// (salting, credential protection, duplication) — a storage parent chief among them, since every storage
    /// parent this simulator creates is RESTRICTED+DECRYPT by construction
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.11.1).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The creation-time admission gate (<c>TryBuildCreatePrimaryRequest</c>) refuses a non-NULL <c>kdf</c>
    /// on anything but an UNRESTRICTED decryption key with <c>TPM_RC_KDF</c> (see
    /// <see cref="CreatePrimaryEccKemKeyWithRestrictedAttributeReturnsKdf"/>), so no key this simulator can
    /// create through <c>TPM2_CreatePrimary()</c> is EVER both a KEM key
    /// (<see cref="TransientKeyState.KemKdfScheme"/> non-null) and RESTRICTED at the same time — the exact
    /// shape clause 14.11.1's attribute gate exists to refuse. <c>TPM2_Create()</c>/<c>TPM2_Import()</c>
    /// additionally admit only <c>TPM_ALG_KEYEDHASH</c> objects in this simulator, closing that route too
    /// (independently confirmed by reading <c>TryParseCreate</c>'s and <c>OnImport</c>'s own type gates). The
    /// attribute gate is therefore genuine defense-in-depth against a shape the creation-time gate already
    /// forecloses, and the only way to prove it fires — rather than merely trusting that the two gates agree
    /// — is to construct the forbidden shape directly and drive it through the ACTUAL, shipped transition
    /// function.
    /// </para>
    /// <para>
    /// This test does exactly that, entirely over PUBLIC, already-shipped surface — never a test-only seam in
    /// production code: it drives a KEM key through a real <c>TPM2_CreatePrimary()</c>, captures the
    /// resulting <see cref="TpmSimulatorState"/> via <see cref="TpmSimulator"/>'s own
    /// <see cref="IObservable{T}"/> trace subscription (the exact same channel a replay journal or metrics
    /// subscriber would use), takes the installed <see cref="TransientKeyState"/> for that key UNCHANGED
    /// except for one bit — <see cref="TpmaObject.RESTRICTED"/> forced SET via a record <c>with</c>
    /// expression, leaving the real generated private key, public point, and KEM kdf fields exactly as the
    /// simulator produced them — and calls <see cref="TpmLifecycleTransitions.Create"/>'s returned transition
    /// delegate directly with a hand-built <see cref="TpmDecapsulateRequested"/>, exactly the input
    /// <c>TryParseDecapsulate</c> would have produced from a real wire frame. No private member, reflection,
    /// or production-code test seam is touched.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task DecapsulateAgainstAKemKeyForcedRestrictedReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var capture = new LastStateObserver();
        using IDisposable subscription = simulator.Subscribe(capture);

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmSimulatorState? maybeCapturedState = capture.LastState;
        Assert.IsNotNull(maybeCapturedState, "The simulator's own trace subscription must have observed at least one step by the time CreatePrimary returns.");
        TpmSimulatorState capturedState = maybeCapturedState!;

        Assert.IsTrue(capturedState.TransientObjects.TryGetValue(primary.ObjectHandle, out TransientKeyState? maybeKemKey), "The newly created KEM key must be present in the captured post-CreatePrimary state.");
        TransientKeyState kemKey = maybeKemKey!;
        Assert.IsNotNull(kemKey.KemKdfScheme, "Sanity: the captured key really is a KEM key before it is forced restricted.");

        TransientKeyState forcedRestrictedKey = kemKey with { Attributes = kemKey.Attributes | TpmaObject.RESTRICTED };
        TpmSimulatorState mutatedState = capturedState with
        {
            TransientObjects = capturedState.TransientObjects.SetItem(primary.ObjectHandle, forcedRestrictedKey)
        };

        //Both carriers are the shared, dispose-immune Empty sentinels: the rejecting transition disposes
        //`request` itself (TpmDecapsulateRequested's own documented contract), and this using's own Dispose
        //on scope exit is therefore a harmless second call, kept here only to satisfy this method's own
        //local disposal obligation for the IDisposable it constructs.
        using var request = new TpmDecapsulateRequested(primary.ObjectHandle, Tpm2bAuth.Empty, Tpm2bKemCiphertext.Empty);
        TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> transition = TpmLifecycleTransitions.Create();
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = await transition(
            mutatedState, request, TpmSimulatorStackSymbol.Lifecycle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "OnDecapsulate always yields a transition — either a rejection or a declared action — never a halt.");
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> nonNullResult = result!;
        Assert.IsInstanceOfType<TpmHeaderOnlyResponse>(nonNullResult.NextState.ResponseIntent, "A rejection frames a header-only response.");
        var rejection = (TpmHeaderOnlyResponse)nonNullResult.NextState.ResponseIntent!;
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, rejection.ResponseCode,
            "A KEM key additionally carrying RESTRICTED must be refused with TPM_RC_ATTRIBUTES — the clause 14.11.1 anti-oracle gate that keeps the general-purpose KEM from decapsulating Labeled-KEM (e.g. storage-parent) traffic.");
    }

    /// <summary>
    /// The other half of clause 14.11.1's attribute gate: a KEM key with <c>decrypt</c> forced CLEAR
    /// (<c>restricted</c> left CLEAR, exactly as a real KEM key's own creation gate leaves it) is refused
    /// <c>TPM_RC_ATTRIBUTES</c> just as forcing RESTRICTED SET is
    /// (<see cref="DecapsulateAgainstAKemKeyForcedRestrictedReturnsAttributes"/>) — the gate's "restricted
    /// CLEAR AND decrypt SET" conjunction fails on EITHER half independently, not merely on the RESTRICTED
    /// bit, mirroring that test's own trace-captured, forced-<c>with</c> technique over the same real
    /// <c>TPM2_CreatePrimary()</c>-minted key and the same shipped
    /// <see cref="TpmLifecycleTransitions.Create"/> delegate
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.11.1).
    /// </summary>
    [TestMethod]
    public async Task DecapsulateAgainstAKemKeyForcedDecryptClearReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var capture = new LastStateObserver();
        using IDisposable subscription = simulator.Subscribe(capture);

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmSimulatorState? maybeCapturedState = capture.LastState;
        Assert.IsNotNull(maybeCapturedState, "The simulator's own trace subscription must have observed at least one step by the time CreatePrimary returns.");
        TpmSimulatorState capturedState = maybeCapturedState!;

        Assert.IsTrue(capturedState.TransientObjects.TryGetValue(primary.ObjectHandle, out TransientKeyState? maybeKemKey), "The newly created KEM key must be present in the captured post-CreatePrimary state.");
        TransientKeyState kemKey = maybeKemKey!;
        Assert.IsNotNull(kemKey.KemKdfScheme, "Sanity: the captured key really is a KEM key before its decrypt attribute is forced clear.");

        TransientKeyState forcedDecryptClearKey = kemKey with { Attributes = kemKey.Attributes & ~TpmaObject.DECRYPT };
        TpmSimulatorState mutatedState = capturedState with
        {
            TransientObjects = capturedState.TransientObjects.SetItem(primary.ObjectHandle, forcedDecryptClearKey)
        };

        //Both carriers are the shared, dispose-immune Empty sentinels: the rejecting transition disposes
        //`request` itself, and this using's own Dispose on scope exit is therefore a harmless second call,
        //kept here only to satisfy this method's own local disposal obligation for the IDisposable it
        //constructs.
        using var request = new TpmDecapsulateRequested(primary.ObjectHandle, Tpm2bAuth.Empty, Tpm2bKemCiphertext.Empty);
        TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> transition = TpmLifecycleTransitions.Create();
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = await transition(
            mutatedState, request, TpmSimulatorStackSymbol.Lifecycle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "OnDecapsulate always yields a transition — either a rejection or a declared action — never a halt.");
        TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> nonNullResult = result!;
        Assert.IsInstanceOfType<TpmHeaderOnlyResponse>(nonNullResult.NextState.ResponseIntent, "A rejection frames a header-only response.");
        var rejection = (TpmHeaderOnlyResponse)nonNullResult.NextState.ResponseIntent!;
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, rejection.ResponseCode,
            "A KEM key with decrypt forced CLEAR must be refused with TPM_RC_ATTRIBUTES independently of the RESTRICTED bit.");
    }

    /// <summary>
    /// Clause 44.5.1's general ECC point rule: a ciphertext whose first octet is not <c>0x04</c> is not a
    /// conformant SEC 1 uncompressed point and is refused <c>TPM_RC_ECC_POINT</c> before any curve check runs
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 1: Architecture, clause 44.5.1).
    /// </summary>
    [TestMethod]
    public async Task DecapsulateWithWrongFirstOctetReturnsEccPoint()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using EncapsulateResponse encapsulated = await EncapsulateAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        byte[] malformed = encapsulated.Ciphertext.Ciphertext.ToArray();
        malformed[0] = 0x03;

        TpmRcConstants code = await SubmitDecapsulateAndGetResponseCodeAsync(tpm, registry, pool, primary.ObjectHandle, malformed, password: null).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ECC_POINT, code, "A ciphertext not prefixed 0x04 is not a conformant SEC 1 point and must be refused with TPM_RC_ECC_POINT.");
    }

    /// <summary>
    /// The same clause 44.5.1 rule applied to length: a ciphertext shorter than the 65-octet uncompressed
    /// point width (here, <c>0x04</c> plus a bare 32-octet X with no Y at all) is refused
    /// <c>TPM_RC_ECC_POINT</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 44.5.1).
    /// </summary>
    [TestMethod]
    public async Task DecapsulateWithATruncatedPointReturnsEccPoint()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using EncapsulateResponse encapsulated = await EncapsulateAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        byte[] truncated = encapsulated.Ciphertext.Ciphertext[..33].ToArray();

        TpmRcConstants code = await SubmitDecapsulateAndGetResponseCodeAsync(tpm, registry, pool, primary.ObjectHandle, truncated, password: null).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ECC_POINT, code, "A ciphertext shorter than the 65-octet uncompressed point width must be refused with TPM_RC_ECC_POINT.");
    }

    /// <summary>
    /// Clause 44.5.1's on-curve check: a well-formed-length, correctly-prefixed point whose coordinates do
    /// not satisfy the P-256 curve equation is refused <c>TPM_RC_ECC_POINT</c> — distinct from the
    /// prefix/length checks
    /// <see cref="DecapsulateWithWrongFirstOctetReturnsEccPoint"/>/<see cref="DecapsulateWithATruncatedPointReturnsEccPoint"/>
    /// exercise
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 44.5.1).
    /// </summary>
    [TestMethod]
    public async Task DecapsulateWithAnOffCurvePointReturnsEccPoint()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using EncapsulateResponse encapsulated = await EncapsulateAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        //A genuine point with one bit of Y flipped: astronomically unlikely to still satisfy the P-256 curve
        //equation, so length and prefix stay conformant and only the on-curve check can account for the refusal.
        byte[] offCurve = encapsulated.Ciphertext.Ciphertext.ToArray();
        offCurve[^1] ^= 0x01;

        TpmRcConstants code = await SubmitDecapsulateAndGetResponseCodeAsync(tpm, registry, pool, primary.ObjectHandle, offCurve, password: null).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ECC_POINT, code, "A well-formed-length point whose coordinates do not satisfy the P-256 curve equation must be refused with TPM_RC_ECC_POINT.");
    }

    /// <summary>
    /// Table 62's <c>TPM2B_KEM_CIPHERTEXT</c> parameter is bound-checked before any rental (Table 102's
    /// <c>sizeof(TPMU_KEM_CIPHERTEXT)</c> = 1568): a hand-framed <c>TPM2_Decapsulate()</c> command declaring a
    /// ciphertext size of 1569 — one octet past the bound — is refused <c>TPM_RC_SIZE</c> at the command
    /// level, proving <c>TryParseDecapsulate</c>'s own exception-to-RC mapping
    /// (<c>InvalidOperationException</c> → <c>TPM_RC_SIZE</c>) rather than only the type's own
    /// <see cref="Tpm2bKemCiphertext.Parse"/>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.14, Table 102).
    /// </summary>
    [TestMethod]
    public async Task HandFramedDecapsulateWithOverMaxCiphertextSizeReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmRcConstants code = await SubmitHandFramedDecapsulateAsync(
            simulator, pool, primary.ObjectHandle.Value, declaredCiphertextSize: (ushort)(Tpm2bKemCiphertext.MaxSize + 1), actualCiphertextPayload: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "A declared ciphertext size past MaxSize must be refused with TPM_RC_SIZE, checked before any rental.");
    }

    /// <summary>
    /// The same Table 62 parameter's remaining-octets check is its own, distinct failure from the size-bound
    /// one: a hand-framed command declaring a within-bound ciphertext size but supplying fewer octets than
    /// declared is refused <c>TPM_RC_INSUFFICIENT</c> at the command level, proving
    /// <c>TryParseDecapsulate</c>'s <c>ArgumentOutOfRangeException</c> → <c>TPM_RC_INSUFFICIENT</c> mapping
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.3.14, Table 102).
    /// </summary>
    [TestMethod]
    public async Task HandFramedDecapsulateWithTruncatedCiphertextReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmRcConstants code = await SubmitHandFramedDecapsulateAsync(
            simulator, pool, primary.ObjectHandle.Value, declaredCiphertextSize: 10, actualCiphertextPayload: new byte[] { 0x01, 0x02 }).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INSUFFICIENT, code, "A declared ciphertext size exceeding the octets actually supplied must be refused with TPM_RC_INSUFFICIENT.");
    }

    /// <summary>
    /// <c>TPM2_Decapsulate()</c>'s key slot (Auth Index 1, Auth Role USER) is verified against the KEM key's
    /// own retained authValue over a plain <c>TPM_RS_PW</c> session, mirroring
    /// <c>TpmInHouseSimulatorSignDigestTests.SignDigestVerifiesTheSigningKeysOwnAuthValue</c>: a DA-protected
    /// KEM key decapsulates when the CORRECT password authorizes it and moves no dictionary-attack counter,
    /// while a WRONG password is refused with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> (Part 2,
    /// clause 6.6.2) and charges <c>failedTries</c> exactly once (Part 1, clause 16.8.7)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.11, Table 62).
    /// </summary>
    [TestMethod]
    public async Task DecapsulateVerifiesTheKemKeysOwnAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool, password: KemKeyPassword, noDa: false).ConfigureAwait(false);
        using EncapsulateResponse encapsulated = await EncapsulateAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);
        byte[] ciphertextBytes = encapsulated.Ciphertext.Ciphertext.ToArray();

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using DecapsulateInput correctInput = DecapsulateInput.Create(primary.ObjectHandle, ciphertextBytes, pool);
        using TpmPasswordSession correctKeyAuth = TpmPasswordSession.Create(KemKeyPasswordBytes, pool);
        TpmResult<DecapsulateResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(
            tpm, correctInput, [correctKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"TPM2_Decapsulate with the key's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");
        correctResult.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized Decapsulate must move no dictionary-attack counter.");

        using DecapsulateInput wrongInput = DecapsulateInput.Create(primary.ObjectHandle, ciphertextBytes, pool);
        using TpmPasswordSession wrongKeyAuth = TpmPasswordSession.Create(WrongKemKeyPasswordBytes, pool);
        TpmResult<DecapsulateResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(
            tpm, wrongInput, [wrongKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(wrongResult.IsTpmError, "A wrong key password must be refused.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
            "A wrong key password over a plain TPM_RS_PW session names the key slot (index 0), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong key password against a DA-protected KEM key must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 16.8.7).");
    }

    /// <summary>
    /// Table 62 pins <c>TPM2_Decapsulate()</c>'s tag to <c>TPM_ST_SESSIONS</c>; this simulator refuses the
    /// <c>TPM_ST_NO_SESSIONS</c> form at the parse with <c>TPM_RC_AUTH_MISSING</c> — the refusal
    /// <c>TryParseDecapsulate</c> implements for a tag mismatch (a command with no authorization area at
    /// all, exactly what supplying an empty session list to the executor frames)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.11, Table 62).
    /// </summary>
    [TestMethod]
    public async Task DecapsulateWithoutSessionsReturnsTheParseRefusal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateKemPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using EncapsulateResponse encapsulated = await EncapsulateAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);
        byte[] ciphertextBytes = encapsulated.Ciphertext.Ciphertext.ToArray();

        using DecapsulateInput input = DecapsulateInput.Create(primary.ObjectHandle, ciphertextBytes, pool);
        TpmResult<DecapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, result.ResponseCode, "TPM2_Decapsulate() with no sessions at all frames TPM_ST_NO_SESSIONS, which this simulator refuses with TPM_RC_AUTH_MISSING.");
    }

    /// <summary>The unrestricted-decrypt object attributes an ECC KEM template carries: no RESTRICTED, no SIGN_ENCRYPT.</summary>
    private static TpmaObject UnrestrictedDecryptAttributes =>
        TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN |
        TpmaObject.USER_WITH_AUTH | TpmaObject.DECRYPT | TpmaObject.NO_DA;

    /// <summary>
    /// Hand-builds a TPM2B_PUBLIC ECC KEM template carrying an arbitrary <c>TPMT_KDF_SCHEME.scheme</c> — a
    /// shape none of the shipped factories can express, since <see cref="TpmsEccParms.ForKeyEncapsulation"/>
    /// always selects <c>TPM_ALG_HKDF</c> — via <see cref="BuildEccPublicTemplate"/>.
    /// </summary>
    /// <param name="kdfScheme">The (possibly non-HKDF) kdf scheme to carry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The composed public template; the caller owns and disposes it.</returns>
    private static Tpm2bPublic BuildEccKemTemplateWithCustomKdfScheme(TpmAlgIdConstants kdfScheme, BaseMemoryPool pool)
    {
        TpmsEccParms eccParms = TpmsEccParms.ForKeyEncapsulation(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_SHA256) with
        {
            Kdf = new TpmtKdfScheme { Scheme = kdfScheme, HashAlg = TpmAlgIdConstants.TPM_ALG_SHA256 }
        };

        return BuildEccPublicTemplate(UnrestrictedDecryptAttributes, eccParms, pool);
    }

    /// <summary>
    /// Hand-builds a TPM2B_PUBLIC ECC KEM template carrying an arbitrary <c>TPMS_ECC_PARMS.symmetric</c> — a
    /// shape none of the shipped factories can express, since <see cref="TpmsEccParms.ForKeyEncapsulation"/>
    /// always sets <c>symmetric</c> to <c>TPM_ALG_NULL</c> — via <see cref="BuildEccPublicTemplate"/>.
    /// </summary>
    /// <param name="symmetric">The (possibly non-NULL) symmetric algorithm to carry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The composed public template; the caller owns and disposes it.</returns>
    private static Tpm2bPublic BuildEccKemTemplateWithSymmetric(TpmtSymDefObject symmetric, BaseMemoryPool pool)
    {
        TpmsEccParms eccParms = TpmsEccParms.ForKeyEncapsulation(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_SHA256) with
        {
            Symmetric = symmetric
        };

        return BuildEccPublicTemplate(UnrestrictedDecryptAttributes, eccParms, pool);
    }

    /// <summary>
    /// Hand-builds an otherwise well-formed TPM2B_PUBLIC ECC KEM template additionally carrying
    /// <see cref="TpmaObject.SIGN_ENCRYPT"/> — a shape <see cref="Tpm2bPublic.CreateEccKemKeyTemplate"/>
    /// cannot express, since it always builds the fixed unrestricted-decrypt attribute shape — via
    /// <see cref="BuildEccPublicTemplate"/>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The composed public template; the caller owns and disposes it.</returns>
    private static Tpm2bPublic BuildEccKemTemplateWithSignEncryptSet(BaseMemoryPool pool)
    {
        TpmsEccParms eccParms = TpmsEccParms.ForKeyEncapsulation(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_SHA256);

        return BuildEccPublicTemplate(UnrestrictedDecryptAttributes | TpmaObject.SIGN_ENCRYPT, eccParms, pool);
    }

    /// <summary>
    /// Hand-builds a TPM2B_PUBLIC ECC KEM template whose <c>scheme.details.ecdh.hashAlg</c> differs from its
    /// <c>kdf.hashAlg</c> — a shape <see cref="Tpm2bPublic.CreateEccKemKeyTemplate"/> cannot express, since its
    /// single hash parameter feeds both fields — via <see cref="BuildEccPublicTemplate"/>.
    /// </summary>
    /// <param name="schemeHashAlg">The <c>scheme.details.ecdh.hashAlg</c> to carry — inert on the KEM path, but live template data at creation.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The composed public template; the caller owns and disposes it.</returns>
    private static Tpm2bPublic BuildEccKemTemplateWithDistinctSchemeHash(TpmAlgIdConstants schemeHashAlg, BaseMemoryPool pool)
    {
        TpmsEccParms eccParms = TpmsEccParms.ForKeyEncapsulation(TpmEccCurveConstants.TPM_ECC_NIST_P256, schemeHashAlg, TpmAlgIdConstants.TPM_ALG_SHA256);

        return BuildEccPublicTemplate(UnrestrictedDecryptAttributes, eccParms, pool);
    }

    /// <summary>
    /// Hand-builds a TPM2B_PUBLIC ECC template whose scheme is <c>TPM_ALG_NULL</c> (not <c>TPM_ALG_ECDH</c>)
    /// on an unrestricted-decrypt key, but which still carries a non-NULL HKDF <c>kdf</c> — a shape matching
    /// neither the ECDSA branch, the KEM branch, nor the RESTRICTED+DECRYPT storage branch this simulator
    /// models — via <see cref="BuildEccPublicTemplate"/>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The composed public template; the caller owns and disposes it.</returns>
    private static Tpm2bPublic BuildEccNullSchemeTemplateWithKdf(BaseMemoryPool pool)
    {
        TpmsEccParms eccParms = TpmsEccParms.ForStorage(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtSymDefObject.Null) with
        {
            Kdf = new TpmtKdfScheme { Scheme = TpmAlgIdConstants.TPM_ALG_HKDF, HashAlg = TpmAlgIdConstants.TPM_ALG_SHA256 }
        };

        return BuildEccPublicTemplate(UnrestrictedDecryptAttributes, eccParms, pool);
    }

    /// <summary>
    /// Hand-builds a TPM2B_PUBLIC ECC template from caller-supplied attributes and ECC parameters — a shape
    /// none of the shipped factories can express on their own — by composing the wire bytes directly
    /// (type/nameAlg/attributes/authPolicy, then the ECC parameters' own <see cref="TpmsEccParms.WriteTo"/>,
    /// then an empty unique point) and re-parsing them, mirroring how
    /// <c>TpmInHouseSimulatorSignDigestTests.CreateRestrictedEccSigningKeyInput</c> hand-builds a shape no
    /// factory expresses.
    /// </summary>
    /// <param name="attributes">The object attributes to carry.</param>
    /// <param name="eccParms">The ECC parameters (symmetric/scheme/curve/kdf) to carry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The composed public template; the caller owns and disposes it.</returns>
    private static Tpm2bPublic BuildEccPublicTemplate(TpmaObject attributes, TpmsEccParms eccParms, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> scratch = pool.Rent(256);
        var writer = new TpmWriter(scratch.Memory.Span);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_ECC);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        writer.WriteUInt32((uint)attributes);
        Tpm2bDigest.Empty.WriteTo(ref writer);
        eccParms.WriteTo(ref writer);
        using(TpmuPublicId emptyUnique = TpmuPublicId.EmptyEcc())
        {
            emptyUnique.WriteTo(ref writer);
        }

        var reader = new TpmReader(scratch.Memory.Span[..writer.Written]);
        TpmtPublic publicArea = TpmtPublic.Parse(ref reader, pool);

        return Tpm2bPublic.FromTemplate(publicArea);
    }

    /// <summary>Creates an unrestricted, ECC KEM primary under the owner hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">Optional password for the key, or <see langword="null"/> for no password.</param>
    /// <param name="noDa">When <see langword="true"/> (the default), the key is exempt from dictionary-attack lockout.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateKemPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string? password = null, bool noDa = true)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccKemKey(
            TpmRh.TPM_RH_OWNER, password, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: noDa);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC KEM key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Issues <c>TPM2_Encapsulate()</c> against <paramref name="keyHandle"/> with no sessions and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The KEM key's handle.</param>
    /// <returns>The Encapsulate response.</returns>
    private async Task<EncapsulateResponse> EncapsulateAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle)
    {
        EncapsulateInput input = EncapsulateInput.ForHandle(keyHandle);
        TpmResult<EncapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Encapsulate failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Issues <c>TPM2_Decapsulate()</c> against <paramref name="keyHandle"/> and returns the response (the caller owns it), asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The KEM key's handle.</param>
    /// <param name="ciphertext">The ciphertext to decapsulate.</param>
    /// <param name="password">The key's password, or <see langword="null"/> for an empty authorization value.</param>
    /// <returns>The Decapsulate response.</returns>
    private async Task<DecapsulateResponse> DecapsulateAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, ReadOnlyMemory<byte> ciphertext, byte[]? password)
    {
        using DecapsulateInput input = DecapsulateInput.Create(keyHandle, ciphertext.Span, pool);
        using TpmPasswordSession keyAuth = password is null ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(password, pool);
        TpmResult<DecapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Decapsulate failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Issues <c>TPM2_Decapsulate()</c> and returns its response code without asserting success — for the malformed-ciphertext refusal tests.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The KEM key's handle.</param>
    /// <param name="ciphertext">The (possibly malformed) ciphertext to decapsulate.</param>
    /// <param name="password">The key's password, or <see langword="null"/> for an empty authorization value.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitDecapsulateAndGetResponseCodeAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, ReadOnlyMemory<byte> ciphertext, byte[]? password)
    {
        using DecapsulateInput input = DecapsulateInput.Create(keyHandle, ciphertext.Span, pool);
        using TpmPasswordSession keyAuth = password is null ? TpmPasswordSession.CreateEmpty(pool) : TpmPasswordSession.Create(password, pool);
        TpmResult<DecapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        return result.ResponseCode;
    }

    /// <summary>
    /// Hand-frames a complete <c>TPM2_Decapsulate()</c> command — header, <c>@keyHandle</c>, a plain
    /// <c>TPM_RS_PW</c> auth area with an empty password, and a ciphertext TPM2B whose declared size and
    /// actual payload length are supplied independently — and submits it directly to the simulator,
    /// bypassing <see cref="DecapsulateInput.Create"/>'s own bound check so a malformed ciphertext TPM2B
    /// reaches <c>TryParseDecapsulate</c>'s own parse-level RC mapping. Any well-formed auth area suffices
    /// here regardless of the key's real password, since a malformed ciphertext is refused by the parser
    /// before the key-slot password compare ever runs.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The KEM key's handle.</param>
    /// <param name="declaredCiphertextSize">The <c>TPM2B_KEM_CIPHERTEXT</c> size field to declare.</param>
    /// <param name="actualCiphertextPayload">The octets actually following the size field — independent of <paramref name="declaredCiphertextSize"/>.</param>
    /// <returns>The response code the simulator's header carries.</returns>
    private async Task<TpmRcConstants> SubmitHandFramedDecapsulateAsync(TpmSimulator simulator, BaseMemoryPool pool, uint keyHandle, ushort declaredCiphertextSize, ReadOnlyMemory<byte> actualCiphertextPayload)
    {
        const int AuthAreaSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort); //sessionHandle + nonceSize(0) + attributes + hmacSize(0).
        int length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + AuthAreaSize + sizeof(ushort) + actualCiphertextPayload.Length;

        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span);

        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_Decapsulate);
        header.WriteTo(ref writer);
        writer.WriteUInt32(keyHandle);

        writer.WriteUInt32((uint)AuthAreaSize);
        writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
        writer.WriteUInt16(0); //nonceCaller: empty.
        writer.WriteByte(0); //sessionAttributes: none set.
        writer.WriteUInt16(0); //hmac (the plaintext password for a TPM_RS_PW slot): empty.

        writer.WriteUInt16(declaredCiphertextSize);
        writer.WriteBytes(actualCiphertextPayload.Span);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..writer.Written], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must always answer with a well-formed response frame.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>Extracts a primary ECC key's exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</summary>
    /// <param name="primary">The primary's CreatePrimary response.</param>
    /// <returns>The uncompressed public point.</returns>
    private static ReadOnlyMemory<byte> ExtractEccPoint(CreatePrimaryResponse primary)
    {
        TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;

        return EllipticCurveUtilities.CombineToUncompressedPoint(point.X.AsReadOnlySpan(), point.Y.AsReadOnlySpan());
    }

    /// <summary>
    /// Generates a fresh NIST P-256 key pair with BouncyCastle, independently of any project ECC backend —
    /// the test-side ephemeral the independent <c>kem_context</c> oracle submits as a ciphertext.
    /// </summary>
    /// <returns>The private scalar (32 octets, unsigned big-endian) and the SEC 1 uncompressed public point (65 octets).</returns>
    private static (byte[] PrivateScalar, byte[] PublicPoint) GenerateP256KeyPair()
    {
        X9ECParameters parameters = SecNamedCurves.GetByName("secp256r1");
        var domain = new ECDomainParameters(parameters.Curve, parameters.G, parameters.N, parameters.H, parameters.GetSeed());

        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

        byte[] publicPoint = ((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded(compressed: false);
        byte[] privateScalar = LeftPad(((ECPrivateKeyParameters)keyPair.Private).D.ToByteArrayUnsigned(), 32);

        return (privateScalar, publicPoint);
    }

    /// <summary>
    /// Computes the raw NIST P-256 Diffie-Hellman value <c>dh</c> RFC 9180 Section 4.1's <c>DH(skX, pkY)</c>
    /// names, on BouncyCastle — independently of the project's own ECC backend and of the simulator's
    /// internal <c>kem_context</c>-assembly helper, mirroring
    /// <c>Verifiable.Tests.Cryptography.DhkemTests.ComputeP256DiffieHellman</c>.
    /// </summary>
    /// <param name="privateScalar">The local party's private scalar, unsigned big-endian (32 octets).</param>
    /// <param name="peerPublicPoint">The peer's public point, SEC 1 uncompressed (<c>0x04 || X || Y</c>, 65 octets).</param>
    /// <returns>The 32-octet shared value <c>dh</c>.</returns>
    private static byte[] ComputeP256DiffieHellman(byte[] privateScalar, byte[] peerPublicPoint)
    {
        X9ECParameters parameters = SecNamedCurves.GetByName("secp256r1");
        var domain = new ECDomainParameters(parameters.Curve, parameters.G, parameters.N, parameters.H, parameters.GetSeed());

        var scalar = new BigInteger(1, privateScalar);
        Org.BouncyCastle.Math.EC.ECPoint peer = domain.Curve.DecodePoint(peerPublicPoint);
        Org.BouncyCastle.Math.EC.ECPoint product = peer.Multiply(scalar).Normalize();

        return LeftPad(product.AffineXCoord.ToBigInteger().ToByteArrayUnsigned(), 32);
    }

    /// <summary>Left-pads a big-endian value to a fixed width, as SEC 1 coordinate encoding requires.</summary>
    /// <param name="value">The big-endian value. BouncyCastle's unsigned encoding may omit leading zero bytes.</param>
    /// <param name="length">The fixed width to produce.</param>
    /// <returns>A new array of exactly <paramref name="length"/> bytes.</returns>
    private static byte[] LeftPad(byte[] value, int length)
    {
        if(value.Length == length)
        {
            return value;
        }

        byte[] result = new byte[length];
        value.CopyTo(result, length - value.Length);

        return result;
    }

    /// <summary>Concatenates two byte sequences, as RFC 9180's <c>concat(...)</c> notation does when building <c>kem_context</c>.</summary>
    /// <param name="first">The leading sequence.</param>
    /// <param name="second">The trailing sequence.</param>
    /// <returns>A new array holding <paramref name="first"/> followed by <paramref name="second"/>.</returns>
    private static byte[] Concat(byte[] first, byte[] second)
    {
        byte[] result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);

        return result;
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)).
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
        _ = registry.Register(TpmCcConstants.TPM_CC_Encapsulate, TpmResponseCodec.Encapsulate);
        _ = registry.Register(TpmCcConstants.TPM_CC_Decapsulate, TpmResponseCodec.Decapsulate);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers
    /// it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-kem",
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
    /// Persist-then-reload a public area through wire bytes only — the disk round-trip a real deployment
    /// performs — yielding an independently-owned copy rather than aliasing <paramref name="source"/>'s own
    /// storage, mirroring <c>TpmInHouseSimulatorSealTests.ClonePublic</c>.
    /// </summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cloned public area; the caller owns and disposes it.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>
    /// Captures the most recent post-transition <see cref="TpmSimulatorState"/> the simulator's own
    /// <see cref="IObservable{T}"/> trace emits — the exact same public channel a replay journal or metrics
    /// subscriber would use, not a test-only hook into production code.
    /// </summary>
    private sealed class LastStateObserver: IObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>
    {
        /// <summary>Gets the state after the most recently observed step, or <see langword="null"/> before the first one.</summary>
        public TpmSimulatorState? LastState { get; private set; }

        /// <inheritdoc/>
        public void OnNext(TraceEntry<TpmSimulatorState, TpmSimulatorInput> value) => LastState = value.StateAfter;

        /// <inheritdoc/>
        public void OnError(Exception error)
        {
        }

        /// <inheritdoc/>
        public void OnCompleted()
        {
        }
    }
}
