using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_CreatePrimary()</c> then <c>TPM2_SignDigest()</c> against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="CreatePrimaryInput"/>, <see cref="SignDigestInput"/>, and response codecs).
/// </summary>
/// <remarks>
/// <para>
/// <c>TPM2_SignDigest()</c> (TPM 2.0 Library Part 3, clause 20.7, Tables 126/127) carries no <c>inScheme</c>: the
/// key's own scheme always applies. Signing with a restricted key additionally requires a valid
/// <c>TPMT_TK_HASHCHECK</c> <c>validation</c> ticket proving the digest is known by the TPM to be the hash of some
/// message; an unrestricted key accepts a NULL ticket, but a caller-supplied non-NULL one is still HMAC-checked.
/// The ticket tests here mirror <c>TpmInHouseSimulatorSignTests.CreationTicketIsAVerifiableHmacOfTheInjectedSeed</c>'s
/// technique: inject a fixed proof seed, then independently reproduce the ticket HMAC (Equation (7), TPM 2.0
/// Library Part 2, clause 10.6.7) from it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSignDigestTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA signing tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The fixed message whose SHA-256 digest is signed.</summary>
    private static byte[] MessageBytes { get; } = "Verifiable in-house TPM SignDigest acceptance test."u8.ToArray();

    /// <summary>A digest-shaped buffer of the wrong length for a SHA-256 scheme (16, not 32, octets).</summary>
    private static byte[] WrongSizedDigestBytes { get; } = new byte[16];

    /// <summary>The real password the signing key's own-authValue verification proof creates the key with.</summary>
    private const string SigningKeyPassword = "sign-digest-key-auth-proof";

    /// <summary>
    /// <see cref="SigningKeyPassword"/>'s UTF-8 octets, matching the password-to-authValue convention
    /// <see cref="Tpm2bAuth.CreateFromPassword"/> applies on the creation side.
    /// </summary>
    private static byte[] SigningKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SigningKeyPassword);

    /// <summary>A wrong guess at the signing key's password, distinct from <see cref="SigningKeyPasswordBytes"/>.</summary>
    private static byte[] WrongSigningKeyPasswordBytes { get; } = [0x5D, 0x5E, 0x5F, 0x60];

    /// <summary>A fixed seed standing in for the hierarchy's persistent random proof secret, injected to make a validation ticket reproducible.</summary>
    private static byte[] TicketSeed { get; } = Convert.FromHexString("102030405060708090A0B0C0D0E0F00102030405060708090A0B0C0D0E0F00");

    /// <summary>A forged hash-check ticket digest, unrelated to any real hierarchy proof.</summary>
    private static byte[] ForgedTicketDigestBytes { get; } = new byte[P256ComponentSize];

    /// <summary>
    /// A transient handle value naming no loaded object in a freshly-brought-operational simulator — stands in
    /// for <c>@keyHandle</c> in a test whose refusal fires at the parse, ahead of any handle resolution.
    /// </summary>
    private const uint ArbitraryKeyHandle = 0x8000_0001;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The ECDSA happy path: an unrestricted P-256 signing key, given the NULL validation ticket
    /// <see cref="SignDigestInput.Create"/> frames, signs a caller-supplied digest whose size matches the key's
    /// SHA-256 scheme (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 3: Commands, clause 20.7, Tables 126/127).
    /// </summary>
    [TestMethod]
    public async Task EcdsaSignDigestVerifiesAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(primary.ObjectHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest (ECDSA) failed: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, signature.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);

        //Independent-oracle carve-out: framework ECDsa verifies against wire-exported simulator output, sharing
        //no code path with the signer, so a divergence in either implementation fails here.
        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(primary.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
            "An ECDSA signature produced by TPM2_SignDigest() must verify against the simulator's exported public key.");
    }

    /// <summary>
    /// The RSASSA happy path: an RSA signing key created with an EXPLICIT RSASSA/SHA-256 TEMPLATE scheme signs a
    /// caller-supplied digest under that RETAINED scheme. <c>TPM2_SignDigest()</c> carries no <c>inScheme</c> —
    /// unlike <c>TPM2_Sign()</c>'s, which lets a caller select the scheme per call — so "the key's own scheme
    /// always applies" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 3: Commands, clause 20.7.1); a key created with a NULL template scheme
    /// retains none and is refused <c>TPM_RC_SCHEME</c> instead (<see cref="SignDigestAgainstANullSchemeRsaKeyReturnsScheme"/>).
    /// </summary>
    [TestMethod]
    public async Task RsaSignDigestVerifiesRsaSsaSignatureAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048, RSASSA) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(primary.ObjectHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest (RSASSA) failed: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, signature.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);

        var rsaParameters = new RSAParameters
        {
            Modulus = primary.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        //Independent-oracle carve-out: framework RSA verifies against wire-exported simulator output, sharing no
        //code path with the signer, so a divergence in either implementation fails here.
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(digest, signature.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "An RSASSA signature produced by TPM2_SignDigest() must verify against the simulator's exported modulus.");
    }

    /// <summary>
    /// The RSAPSS counterpart of <see cref="RsaSignDigestVerifiesRsaSsaSignatureAgainstInHouseSimulator"/>: an RSA
    /// signing key created with an EXPLICIT RSAPSS/SHA-256 template scheme signs a caller-supplied digest under
    /// that retained scheme, and the signature independently verifies out-of-band as PSS — proving the RETAINED
    /// scheme, not a fixed model default, drove the signing primitive
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7.1).
    /// </summary>
    [TestMethod]
    public async Task RsaSignDigestVerifiesRsaPssSignatureAgainstInHouseSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.RsaPss(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048, RSAPSS) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(primary.ObjectHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest (RSAPSS) failed: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSAPSS, signature.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);

        var rsaParameters = new RSAParameters
        {
            Modulus = primary.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        //Independent-oracle carve-out: framework RSA verifies against wire-exported simulator output, sharing no
        //code path with the signer, so a divergence in either implementation fails here.
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(digest, signature.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            "An RSAPSS signature produced by TPM2_SignDigest() must verify against the simulator's exported modulus as PSS.");
    }

    /// <summary>
    /// "The scheme of keyHandle must be a signing scheme that supports signing a digest": an RSA key created
    /// with a NULL template scheme retains none, and
    /// <c>TPM2_SignDigest()</c> carries no <c>inScheme</c> to substitute one — unlike <c>TPM2_Sign()</c>, which
    /// resolves a NULL request to the key's model default — so the command is refused <c>TPM_RC_SCHEME</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7.1).
    /// </summary>
    [TestMethod]
    public async Task SignDigestAgainstANullSchemeRsaKeyReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048, NULL scheme) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(primary.ObjectHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 0), signResult.ResponseCode,
            "An RSA key created with a NULL template scheme retains none, and TPM2_SignDigest() has no inScheme to substitute one.");
    }

    /// <summary>
    /// A storage parent's <c>sign</c> (SIGN_ENCRYPT) attribute is
    /// CLEAR, so <c>TPM2_SignDigest()</c> must refuse it before it can ever reach the ticket or scheme gates —
    /// otherwise a caller with USER auth on the parent and a freely-constructible hashcheck ticket (the shape
    /// <see cref="SignDigestOverARestrictedKeyWithASeedReproducedTicketSucceeds"/> demonstrates building) could
    /// turn a custody-root storage key into a signing oracle
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5.1, carried to 20.7 via the "is like
    /// TPM2_SignSequenceComplete()" relation: "If the sign attribute is not SET in the key referenced by handle,
    /// then the TPM shall return TPM_RC_KEY").
    /// </summary>
    [TestMethod]
    public async Task SignDigestAgainstAnEccStorageParentHandleReturnsKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = parentResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //A NULL ticket is enough to prove the point: the sign-attribute gate runs BEFORE the ticket-null check,
        //so the storage parent never even reaches it.
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(parent.ObjectHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), signResult.ResponseCode,
            "A storage parent's sign attribute is CLEAR; TPM2_SignDigest() must refuse it with TPM_RC_KEY, not sign with it.");
    }

    /// <summary>
    /// "The size of digest must match the size of the hash algorithm of the signing scheme"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7): a digest shorter than SHA-256's 32 octets is refused
    /// with <c>TPM_RC_SIZE</c> against an ECC key [owner-flaggable basis: no RC named in clause 20.7 itself; Part
    /// 2 clause 4.15 / Part 3 clause 5.8's general size-parameter fallback].
    /// </summary>
    [TestMethod]
    public async Task SignDigestWithMismatchedDigestSizeAgainstAnEccKeyReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(primary.ObjectHandle, WrongSizedDigestBytes, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), signResult.ResponseCode, "A digest whose size mismatches the ECC key's SHA-256 scheme must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// The RSA counterpart of <see cref="SignDigestWithMismatchedDigestSizeAgainstAnEccKeyReturnsSize"/>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7) — the key carries an EXPLICIT RSASSA/SHA-256 template
    /// scheme (a NULL-scheme template would instead be refused <c>TPM_RC_SCHEME</c> ahead of the size check; see
    /// <see cref="SignDigestAgainstANullSchemeRsaKeyReturnsScheme"/>).
    /// </summary>
    [TestMethod]
    public async Task SignDigestWithMismatchedDigestSizeAgainstAnRsaKeyReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048, RSASSA) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(primary.ObjectHandle, WrongSizedDigestBytes, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), signResult.ResponseCode, "A digest whose size mismatches the RSA key's SHA-256 scheme must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// A non-empty <c>context</c> is refused with <c>TPM_RC_SIZE</c> under ECDSA: Table 220's <c>empty[0]</c> arm
    /// is the only conformant value for every scheme this simulator resolves
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.3.7/11.3.8, Tables 220/221).
    /// <see cref="SignDigestInput"/> always frames an empty context, so this hand-frames the command to express
    /// the violation.
    /// </summary>
    [TestMethod]
    public async Task SignDigestWithNonEmptyContextReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] nonEmptyContext = [0x01, 0x02, 0x03, 0x04];
        TpmRcConstants code = await SubmitSignDigestCommandAsync(
            simulator, pool, primary.ObjectHandle.Value, nonEmptyContext, digest).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code, "A non-empty context under ECDSA must be refused with TPM_RC_SIZE (Table 220's empty[0] arm).");
    }

    /// <summary>
    /// "Signing using a restricted key is permitted, but it requires a valid TPMT_TK_HASHCHECK"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7, Table 126's note): a restricted signing key given the
    /// NULL ticket <see cref="SignDigestInput.Create"/> frames is refused with <c>TPM_RC_TICKET</c>, the same
    /// code TPM2_Sign's analogous rule (clause 20.5) names.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverARestrictedKeyWithANullTicketReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(primary.ObjectHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), signResult.ResponseCode, "A restricted key given a NULL validation ticket must be refused with TPM_RC_TICKET.");
    }

    /// <summary>
    /// A restricted key given a genuine <c>TPMT_TK_HASHCHECK</c> — Equation (7),
    /// <c>HMAC_contextAlg(proof, TPM_ST_HASHCHECK ‖ digest)</c>, reproduced here from the injected proof seed
    /// exactly as the command's own ticket-recomputation check does — signs successfully
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7; Part 2: Structures, clause 10.6.7). The
    /// independently-recomputed ticket accepting proves it is a genuine, verifiable HMAC bound to the injected
    /// seed, not an opaque value.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverARestrictedKeyWithASeedReproducedTicketSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateSeededOperationalAsync(TicketSeed, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] ticketDigest = await ComputeHashcheckTicketDigestAsync(
            TicketSeed, (uint)TpmRh.TPM_RH_OWNER, digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmtTkHashcheck validation = TpmtTkHashcheck.Create(TpmiRhHierarchy.Owner, ticketDigest, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.CreateForRestrictedKey(primary.ObjectHandle, digest, validation, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest over a restricted key with a valid ticket must succeed: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;
        Assert.IsTrue(
            VerifyEcdsaSignatureOffTpm(primary.OutPublic.PublicArea.Unique.Ecc!, digest, signature.Signature),
            "The signature produced under a validated ticket must still verify against the exported public key.");
    }

    /// <summary>
    /// The single-bit-tampered counterpart of <see cref="SignDigestOverARestrictedKeyWithASeedReproducedTicketSucceeds"/>:
    /// flipping one bit of an otherwise-genuine ticket HMAC is refused with <c>TPM_RC_TICKET</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7), proving the comparison is a real byte-exact HMAC
    /// check and not merely a shape or presence check.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverARestrictedKeyWithATamperedTicketReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateSeededOperationalAsync(TicketSeed, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRestrictedEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] ticketDigest = await ComputeHashcheckTicketDigestAsync(
            TicketSeed, (uint)TpmRh.TPM_RH_OWNER, digest, pool, TestContext.CancellationToken).ConfigureAwait(false);
        ticketDigest[^1] ^= 0x01;

        using TpmtTkHashcheck tamperedValidation = TpmtTkHashcheck.Create(TpmiRhHierarchy.Owner, ticketDigest, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.CreateForRestrictedKey(primary.ObjectHandle, digest, tamperedValidation, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), signResult.ResponseCode, "validation is TPM2_SignDigest()'s third parameter (Table 126, index 2); a single-bit-tampered ticket must be refused with parameter-encoded TPM_RC_TICKET.");
    }

    /// <summary>
    /// "Unrestricted key: NULL ticket accepted... a supplied non-NULL ticket is still HMAC-checked (a forged
    /// ticket is refused rather than ignored)" [owner-flaggable — the spec is silent on this case; refusing forged
    /// input is the secure default]
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7, Table 126's note). An unrestricted key given a ticket
    /// that is not a genuine HMAC over its own hierarchy's proof is refused with <c>TPM_RC_TICKET</c> exactly as
    /// a restricted key's would be.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverAnUnrestrictedKeyWithAForgedTicketReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmtTkHashcheck forgedValidation = TpmtTkHashcheck.Create(TpmiRhHierarchy.Owner, ForgedTicketDigestBytes, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.CreateForRestrictedKey(primary.ObjectHandle, digest, forgedValidation, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 2), signResult.ResponseCode, "validation is TPM2_SignDigest()'s third parameter (Table 126, index 2); an unrestricted key given a forged non-NULL ticket must still be refused with parameter-encoded TPM_RC_TICKET.");
    }

    /// <summary>
    /// The RSA counterpart of <see cref="SignDigestOverARestrictedKeyWithASeedReproducedTicketSucceeds"/>,
    /// exercising <c>SignRsaDigestWithTicketAsync</c> (the restricted-RSA ticket-validating effect no other test
    /// in this file reaches): a restricted RSA signing key given a genuine, seed-reproduced
    /// <c>TPMT_TK_HASHCHECK</c> — Equation (7),
    /// <c>HMAC_contextAlg(proof, TPM_ST_HASHCHECK ‖ digest)</c> — signs successfully
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7; Part 2: Structures, clause 10.6.7), and the resulting
    /// RSASSA signature independently verifies against the exported modulus.
    /// </summary>
    [TestMethod]
    public async Task SignDigestOverARestrictedRsaKeyWithASeedReproducedTicketSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateSeededOperationalAsync(TicketSeed, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateRestrictedRsaSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] ticketDigest = await ComputeHashcheckTicketDigestAsync(
            TicketSeed, (uint)TpmRh.TPM_RH_OWNER, digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmtTkHashcheck validation = TpmtTkHashcheck.Create(TpmiRhHierarchy.Owner, ticketDigest, pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.CreateForRestrictedKey(primary.ObjectHandle, digest, validation, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(signResult.IsSuccess, $"TPM2_SignDigest over a restricted RSA key with a valid ticket must succeed: '{signResult.ResponseCode}'.");

        using SignDigestResponse signature = signResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSASSA, signature.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);

        var rsaParameters = new RSAParameters
        {
            Modulus = primary.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        //Independent-oracle carve-out: framework RSA verifies against wire-exported simulator output, sharing no
        //code path with the signer, so a divergence in either implementation fails here.
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(digest, signature.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "The signature produced under a validated ticket must still verify against the exported modulus.");
    }

    /// <summary>
    /// <c>TPMT_TK_HASHCHECK.tag</c> admits only <c>TPM_ST_HASHCHECK</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 10.6.7, Table 115: "#TPM_RC_TAG — error returned when tag
    /// is not TPM_ST_HASHCHECK"): a <c>validation</c> ticket hand-framed with <c>TPM_ST_CREATION</c> instead is
    /// refused with <c>TPM_RC_TAG</c> at the wire read, before any handle even resolves — proving the tag gate
    /// runs independently of the ticket's hierarchy or digest, which this frame leaves otherwise well-formed.
    /// </summary>
    [TestMethod]
    public async Task SignDigestWithAHashcheckTicketTaggedCreationReturnsTag()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants code = await SubmitSignDigestCommandWithTicketTagAsync(
            simulator, pool, ArbitraryKeyHandle, (ushort)TpmStConstants.TPM_ST_CREATION, (uint)TpmRh.TPM_RH_OWNER, ForgedTicketDigestBytes, digest).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TAG, 2), code,
            "Table 126: validation is TPM2_SignDigest()'s third parameter (index 2); a ticket tagged TPM_ST_CREATION instead of TPM_ST_HASHCHECK must be refused with TPM_RC_TAG there.");
    }

    /// <summary>
    /// <c>TPM2_SignDigest()</c>'s key slot (Auth Index 1, Auth Role USER;
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7) is verified against the signing key's own retained
    /// authValue over a plain <c>TPM_RS_PW</c> session, mirroring
    /// <c>TpmInHouseSimulatorSignTests.SignVerifiesTheSigningKeysOwnAuthValue</c>: a DA-protected ECC signing key
    /// signs when the CORRECT password authorizes it and moves no dictionary-attack counter, while a WRONG
    /// password is refused with the session-index-encoded <c>TPM_RC_AUTH_FAIL</c> (Part 2, clause 6.6.2) and
    /// charges <c>failedTries</c> exactly once (Part 1, clause 16.8.7).
    /// </summary>
    [TestMethod]
    public async Task SignDigestVerifiesTheSigningKeysOwnAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            SigningKeyPassword,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: false);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (password-protected ECC signing key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession correctKeyAuth = TpmPasswordSession.Create(SigningKeyPasswordBytes, pool);
        using SignDigestInput correctSignInput = SignDigestInput.Create(primary.ObjectHandle, digest, pool);
        TpmResult<SignDigestResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, correctSignInput, [correctKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctResult.IsSuccess, $"TPM2_SignDigest with the key's correct password must succeed, but failed: '{correctResult.ResponseCode}'.");
        correctResult.Value.Dispose();

        TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized SignDigest must move no dictionary-attack counter.");

        using TpmPasswordSession wrongKeyAuth = TpmPasswordSession.Create(WrongSigningKeyPasswordBytes, pool);
        using SignDigestInput wrongSignInput = SignDigestInput.Create(primary.ObjectHandle, digest, pool);
        TpmResult<SignDigestResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, wrongSignInput, [wrongKeyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(wrongResult.IsTpmError, "A wrong key password must be refused.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), wrongResult.ResponseCode,
            "A wrong key password over a plain TPM_RS_PW session names the key slot (index 0), session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
            "A wrong key password against a DA-protected signing key must charge failedTries exactly once (TPM 2.0 Library Part 1, clause 16.8.7).");
    }

    /// <summary>
    /// "The scheme of keyHandle must be a signing scheme that supports signing a digest"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7.1): a KEYEDHASH object (a sealed data item, loaded here
    /// through the shipped Create/Load custody path — the same shape <c>TpmInHouseSimulatorSealTests</c> builds)
    /// lives in the simulator's sealed-object table rather than among its signing keys, so <c>TPM2_SignDigest()</c>
    /// refuses it via its dedicated sealed-object arm — never through the retained-scheme gate a real signing
    /// key resolves through — and answers <c>TPM_RC_SCHEME</c> (family precedent, clauses 20.2/20.5).
    /// </summary>
    [TestMethod]
    public async Task SignDigestAgainstAKeyedhashKeyReturnsScheme()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = parentResult.Value;
        uint parentHandle = parent.ObjectHandle.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData("not a signing key"u8.ToArray(), pool);
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
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignDigestInput signInput = SignDigestInput.Create(loaded.ObjectHandle, digest, pool);
        TpmResult<SignDigestResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_SCHEME, 0), signResult.ResponseCode, "A KEYEDHASH object has no digest-signing default scheme and must be refused with TPM_RC_SCHEME.");
    }

    /// <summary>
    /// Composes a restricted ECC signing key template — <c>TPMA_OBJECT.restricted</c> SET alongside <c>sign</c>,
    /// with no password (empty authValue) — mirroring
    /// <c>TpmInHouseSimulatorSignTests.CreateUserWithAuthClearEccSigningKeyInput</c>'s direct-template style, since
    /// no production factory builds a restricted signing key.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateRestrictedEccSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);

        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT |
            TpmaObject.RESTRICTED |
            TpmaObject.NO_DA;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>Creates a restricted ECC signing primary under the owner hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRestrictedEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateRestrictedEccSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (restricted ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Composes a restricted RSA signing key template — <c>TPMA_OBJECT.restricted</c> SET alongside <c>sign</c>,
    /// an EXPLICIT RSASSA/SHA-256 template scheme, and no password (empty authValue) — the RSA counterpart of
    /// <see cref="CreateRestrictedEccSigningKeyInput"/>, since no production factory builds a restricted signing
    /// key.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the composed sensitive area and public template transfers to the returned CreatePrimaryInput, whose Dispose releases them.")]
    private static CreatePrimaryInput CreateRestrictedRsaSigningKeyInput(BaseMemoryPool pool)
    {
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);

        var attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT |
            TpmaObject.RESTRICTED |
            TpmaObject.NO_DA;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateRsaSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            Rsa2048KeyBits,
            TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256));

        return new CreatePrimaryInput(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>Creates a restricted RSA signing primary under the owner hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRestrictedRsaSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreateRestrictedRsaSigningKeyInput(pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (restricted RSA signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an unrestricted, empty-password ECC P-256 signing primary under the owner hierarchy and returns the response (the caller owns it).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Verifies a P-256 ECDSA signature off-TPM against a public key reconstructed solely from the simulator's
    /// exported public point — sharing no code path with the signer.
    /// </summary>
    /// <param name="point">The exported public point.</param>
    /// <param name="digest">The digest that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <returns><see langword="true"/> when the signature verifies.</returns>
    private static bool VerifyEcdsaSignatureOffTpm(TpmsEccPoint point, byte[] digest, TpmuSignature signature)
    {
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);

        return ecdsa.VerifyHash(digest, p1363Signature);
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
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);

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

    /// <summary>Computes an HMAC-SHA256 through the registered HMAC seam.</summary>
    /// <param name="message">The message to authenticate.</param>
    /// <param name="key">The HMAC key.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte HMAC.</returns>
    private static async Task<byte[]> ComputeHmacSha256Async(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> key, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            message, key, P256ComponentSize, CryptoTags.HmacSha256Value, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return hmac.AsReadOnlySpan().ToArray();
    }

    /// <summary>Builds the hierarchy proof-derivation input: the seed followed by the hierarchy handle.</summary>
    /// <param name="seed">The TPM seed.</param>
    /// <param name="hierarchy">The hierarchy handle.</param>
    /// <returns>The proof-derivation input bytes.</returns>
    private static byte[] BuildProofInput(byte[] seed, uint hierarchy)
    {
        byte[] input = new byte[seed.Length + sizeof(uint)];
        var writer = new TpmWriter(input);
        writer.WriteBytes(seed);
        writer.WriteUInt32(hierarchy);

        return input;
    }

    /// <summary>Builds the hash-check ticket HMAC message: TPM_ST_HASHCHECK (UINT16) followed by the digest — Equation (7).</summary>
    /// <param name="digest">The digest the ticket asserts was produced by the TPM.</param>
    /// <returns>The message bytes.</returns>
    private static byte[] BuildHashcheckTicketMessage(ReadOnlySpan<byte> digest)
    {
        byte[] message = new byte[sizeof(ushort) + digest.Length];
        var writer = new TpmWriter(message);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_HASHCHECK);
        writer.WriteBytes(digest);

        return message;
    }

    /// <summary>
    /// Reproduces a hash-check ticket digest from an injected proof seed exactly as
    /// <c>TpmSimulator.ComputeHashcheckTicketDigestAsync</c> computes it: proof = H(seed ‖ hierarchy), digest =
    /// HMAC(proof, TPM_ST_HASHCHECK ‖ digest) — Equation (7), TPM 2.0 Library Part 2, clause 10.6.7.
    /// </summary>
    /// <param name="seed">The injected hierarchy proof seed.</param>
    /// <param name="hierarchy">The hierarchy the ticket is claimed under.</param>
    /// <param name="digest">The digest the ticket asserts was produced by the TPM.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte ticket digest.</returns>
    private static async Task<byte[]> ComputeHashcheckTicketDigestAsync(
        byte[] seed, uint hierarchy, byte[] digest, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] proof = await ComputeSha256Async(BuildProofInput(seed, hierarchy), pool, cancellationToken).ConfigureAwait(false);
        byte[] message = BuildHashcheckTicketMessage(digest);

        return await ComputeHmacSha256Async(message, proof, pool, cancellationToken).ConfigureAwait(false);
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
            "tpm-in-house-sign-digest",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Creates a simulator wired with a caller-injected hierarchy proof seed (making its tickets independently
    /// reproducible) and BOTH signing backends, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c>
    /// into the operational phase.
    /// </summary>
    /// <param name="seed">The proof seed to inject.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateSeededOperationalAsync(byte[] seed, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-sign-digest-seed",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(),
            seed: seed, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
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
    /// Hand-frames a <c>TPM2_SignDigest()</c> command whose <c>context</c> body is supplied verbatim, bypassing
    /// <see cref="SignDigestInput"/> (which always frames an empty context) — letting a caller submit a non-empty
    /// context directly against the simulator. A single empty <c>TPM_RS_PW</c> password slot authorizes
    /// <c>@keyHandle</c>; a NULL <c>validation</c> ticket follows the digest, mirroring
    /// <see cref="SignDigestInput.WriteParameters"/>'s own NULL-ticket convention for an unrestricted key.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="context">The <c>context</c> parameter's octets, written verbatim as a TPM2B.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameSignDigestCommand(
        BaseMemoryPool pool, uint keyHandle, ReadOnlySpan<byte> context, ReadOnlySpan<byte> digest, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        const int NullValidationTicketSize = sizeof(ushort) + sizeof(uint) + sizeof(ushort);

        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                              //Handle area: @keyHandle.
            + sizeof(uint) + PasswordSlotSize            //authorizationSize + one TPM_RS_PW slot.
            + sizeof(ushort) + context.Length            //TPM2B_SIGNATURE_CTX.
            + sizeof(ushort) + digest.Length             //TPM2B_DIGEST.
            + NullValidationTicketSize;

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_SignDigest);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteUInt32((uint)PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteTpm2b(context);
            writer.WriteTpm2b(digest);

            //NULL ticket: tag = TPM_ST_HASHCHECK, hierarchy = TPM_RH_NULL, digest size = 0.
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_HASHCHECK);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_NULL);
            writer.WriteUInt16(0);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_SignDigest()</c> built by <see cref="FrameSignDigestCommand"/> straight to
    /// the simulator (bypassing <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="context">The <c>context</c> parameter's octets.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSignDigestCommandAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint keyHandle, byte[] context, byte[] digest)
    {
        using IMemoryOwner<byte> commandOwner = FrameSignDigestCommand(pool, keyHandle, context, digest, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_SignDigest()</c> command whose <c>validation</c> ticket tag is supplied verbatim,
    /// bypassing <see cref="TpmtTkHashcheck"/> (which always frames <c>TPM_ST_HASHCHECK</c>) — letting a caller
    /// submit an inadmissible ticket tag directly against the simulator. An empty context and a well-formed
    /// digest keep every OTHER gate satisfied, so only the ticket tag can account for the refusal.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="ticketTag">The <c>validation.tag</c> octets to frame verbatim.</param>
    /// <param name="ticketHierarchy">The <c>validation.hierarchy</c> value.</param>
    /// <param name="ticketDigest">The <c>validation.digest</c> octets.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <param name="length">The framed command's total length.</param>
    /// <returns>The rented, framed command buffer.</returns>
    private static IMemoryOwner<byte> FrameSignDigestCommandWithTicketTag(
        BaseMemoryPool pool, uint keyHandle, ushort ticketTag, uint ticketHierarchy, ReadOnlySpan<byte> ticketDigest, ReadOnlySpan<byte> digest, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);

        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                                        //Handle area: @keyHandle.
            + sizeof(uint) + PasswordSlotSize                     //authorizationSize + one TPM_RS_PW slot.
            + sizeof(ushort)                                      //Empty TPM2B_SIGNATURE_CTX.
            + sizeof(ushort) + digest.Length                      //TPM2B_DIGEST.
            + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + ticketDigest.Length; //TPMT_TK_HASHCHECK.

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_SignDigest);
            header.WriteTo(ref writer);
            writer.WriteUInt32(keyHandle);
            writer.WriteUInt32((uint)PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty); //Empty context.
            writer.WriteTpm2b(digest);

            writer.WriteUInt16(ticketTag);
            writer.WriteUInt32(ticketHierarchy);
            writer.WriteTpm2b(ticketDigest);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_SignDigest()</c> built by <see cref="FrameSignDigestCommandWithTicketTag"/>
    /// straight to the simulator (bypassing <see cref="TpmCommandExecutor"/>) and yields the response code.
    /// </summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The <c>@keyHandle</c> handle value.</param>
    /// <param name="ticketTag">The <c>validation.tag</c> octets to frame verbatim.</param>
    /// <param name="ticketHierarchy">The <c>validation.hierarchy</c> value.</param>
    /// <param name="ticketDigest">The <c>validation.digest</c> octets.</param>
    /// <param name="digest">The <c>digest</c> parameter's octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSignDigestCommandWithTicketTagAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint keyHandle, ushort ticketTag, uint ticketHierarchy, byte[] ticketDigest, byte[] digest)
    {
        using IMemoryOwner<byte> commandOwner = FrameSignDigestCommandWithTicketTag(pool, keyHandle, ticketTag, ticketHierarchy, ticketDigest, digest, out int length);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed command must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
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
            value[^length..].CopyTo(result);
        }

        return result;
    }
}
