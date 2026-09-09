using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
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
/// Vector-exact DHKEM(P-256, HKDF-SHA256) through the in-house behavioural <see cref="TpmSimulator"/>: RFC 9180
/// Appendix A.3.1's recipient key pair is loaded from outside through <c>TPM2_LoadExternal()</c> and
/// <c>TPM2_Decapsulate()</c> over the vector's <c>enc</c> reproduces its <c>shared_secret</c> byte for byte; the
/// recipient's public point alone is loaded and <c>TPM2_Encapsulate()</c> with the vector's ephemeral injected
/// through the backend seam reproduces <c>enc</c> and <c>shared_secret</c>; and a scalar that is not the
/// recipient's is refused at the load (TPM 2.0 Library Part 3, clauses 12.3, 14.10 and 14.11; Part 1, clause 44.4;
/// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see>, Appendix A.3.1).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorLoadExternalKemVectorTests
{
    /// <summary>The Name algorithm and the DHKEM's KDF hash.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The width of a P-256 coordinate or scalar.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>RFC 9180, Appendix A.3.1: the recipient's SEC 1 uncompressed public key <c>pkRm</c> (the text's lines 2909-2910).</summary>
    private const string PkRm = "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0";

    /// <summary>RFC 9180, Appendix A.3.1: the recipient's private scalar <c>skRm</c> (the text's line 2912).</summary>
    private const string SkRm = "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2";

    /// <summary>RFC 9180, Appendix A.3.1: the ephemeral sender's private scalar <c>skEm</c> (the text's line 2906).</summary>
    private const string SkEm = "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb";

    /// <summary>RFC 9180, Appendix A.3.1: the ephemeral sender's public key <c>pkEm</c> (the text's lines 2903-2904), byte-identical to <c>enc</c> (lines 2913-2914).</summary>
    private const string PkEm = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4";

    /// <summary>RFC 9180, Appendix A.3.1: the 32-octet DHKEM <c>shared_secret</c> (the text's line 2916).</summary>
    private const string SharedSecret = "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8";

    /// <summary>The attribute word of an external unrestricted decryption (KEM) key: caller-supplied, USER-role by password, dictionary-attack exempt.</summary>
    private const TpmaObject ExternalKemAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.DECRYPT | TpmaObject.NO_DA;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The recipient side, vector-exact: <c>skRm</c> and <c>pkRm</c> loaded under <c>TPM_RH_NULL</c> as an
    /// unrestricted ECDH decryption key with an HKDF-SHA256 <c>kdf</c> — the DHKEM(P-256, HKDF-SHA256) suite —
    /// and <c>TPM2_Decapsulate()</c> over the vector's <c>enc</c> answers the vector's <c>shared_secret</c> byte
    /// for byte ("Decapsulate ... shall be a NULL Ticket" does not apply: the KEM answers a secret, not a ticket).
    /// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see>, Appendix A.3.1;
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.11; Part 1, clause 44.4.3</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRecipientKeyDecapsulatesTheRfc9180Vector()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRecipientKeyDecapsulatesTheRfc9180Vector), BouncyCastleTpmEccSigningBackend.Create(), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<LoadExternalResponse> loadResult = await LoadKemKeyAsync(tpm, registry, pool, Convert.FromHexString(SkRm)).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"The vector's recipient key must load under TPM_RH_NULL (Part 3, clause 12.3.1), but failed: '{loadResult.ResponseCode}'.");
        using LoadExternalResponse loaded = loadResult.Value;

        using DecapsulateInput input = DecapsulateInput.Create(loaded.ObjectHandle, Convert.FromHexString(PkEm), pool);
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<DecapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<DecapsulateResponse>(
            tpm, input, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Decapsulate() over the vector's enc must succeed, but failed: '{result.ResponseCode}'.");
        using DecapsulateResponse decapsulated = result.Value;

        Assert.AreEqual(SharedSecret, Convert.ToHexStringLower(decapsulated.SharedSecret.AsReadOnlySpan()), "TPM2_Decapsulate() reproduces RFC 9180 Appendix A.3.1's shared_secret from the vector's own recipient key and enc.");
    }

    /// <summary>
    /// The sender side, vector-exact: <c>pkRm</c> alone is loaded public-only under the owner hierarchy, and
    /// <c>TPM2_Encapsulate()</c> — its ephemeral draw replaced through the backend's own key-generation seam by
    /// the vector's (<c>skEm</c>, <c>pkEm</c>) — answers <c>enc = pkEm</c> and the vector's <c>shared_secret</c>
    /// byte for byte, a public-key operation the public-only object performs without authorization.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see>, Appendix A.3.1;
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.10; Part 1, clause 44.4.2</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalPublicOnlyRecipientKeyEncapsulatesTheRfc9180Vector()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmEccSigningBackend backend = BouncyCastleTpmEccSigningBackend.Create() with { GenerateKey = FixedEphemeralKeyAsync };
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalPublicOnlyRecipientKeyEncapsulatesTheRfc9180Vector), backend, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<LoadExternalResponse> loadResult = await LoadKemKeyAsync(tpm, registry, pool, scalar: null).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"The vector's recipient public key must load public-only (Part 3, clause 12.3.1), but failed: '{loadResult.ResponseCode}'.");
        using LoadExternalResponse loaded = loadResult.Value;

        TpmResult<EncapsulateResponse> result = await TpmCommandExecutor.ExecuteAsync<EncapsulateResponse>(
            tpm, EncapsulateInput.ForHandle(loaded.ObjectHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Encapsulate() over the public-only recipient key must succeed, but failed: '{result.ResponseCode}'.");
        using EncapsulateResponse encapsulated = result.Value;

        Assert.AreEqual(PkEm, Convert.ToHexStringLower(encapsulated.Ciphertext.Ciphertext), "enc is the vector's own serialized ephemeral public key (Part 1, clause 44.4.2, step 3).");
        Assert.AreEqual(SharedSecret, Convert.ToHexStringLower(encapsulated.SharedSecret.AsReadOnlySpan()), "TPM2_Encapsulate() reproduces RFC 9180 Appendix A.3.1's shared_secret from the vector ephemeral alone.");
    }

    /// <summary>
    /// "If nameAlg is not TPM_ALG_NULL, then the same consistency checks between inPublic and inPrivate are made
    /// as for TPM2_Load()": a valid scalar that is not the recipient's — the vector's <c>skEm</c> — under
    /// <c>pkRm</c> is refused with <c>TPM_RC_BINDING</c>, so no key pair the vector did not bind can ever
    /// decapsulate.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalRecipientPublicKeyWithAnotherScalarIsRefusedWithBinding()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(LoadExternalRecipientPublicKeyWithAnotherScalarIsRefusedWithBinding), BouncyCastleTpmEccSigningBackend.Create(), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<LoadExternalResponse> result = await LoadKemKeyAsync(tpm, registry, pool, Convert.FromHexString(SkEm)).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BINDING, result.ResponseCode, "A scalar that does not produce pkRm binds no key pair: TPM_RC_BINDING (Part 3, clause 12.3.1).");
    }

    /// <summary>Creates a simulator over <paramref name="backend"/>, powers it on and brings it operational through <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="name">The per-test simulator identifier.</param>
    /// <param name="backend">The elliptic-curve backend to wire.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, TpmEccSigningBackend backend, BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator($"tpm-in-house-load-external-kem-{name}", signingBackend: backend, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

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

        return simulator;
    }

    /// <summary>Builds the codec registry covering every command these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal)
            .Register(TpmCcConstants.TPM_CC_Encapsulate, TpmResponseCodec.Encapsulate)
            .Register(TpmCcConstants.TPM_CC_Decapsulate, TpmResponseCodec.Decapsulate)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Issues <c>TPM2_LoadExternal()</c> for the vector's recipient public key as a DHKEM(P-256, HKDF-SHA256) key
    /// — an unrestricted ECDH decryption key with an HKDF-SHA256 <c>kdf</c> (TPM 2.0 Library Part 2, clause
    /// 12.2.3.5, Table 229) — public-only under the owner hierarchy when <paramref name="scalar"/> is
    /// <see langword="null"/>, or with the scalar as its sensitive area under <c>TPM_RH_NULL</c>.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="scalar">The private scalar, or <see langword="null"/> for a public-only load.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the point, the public area and the sensitive area's carriers transfers to the load input, disposed here once the command has been issued.")]
    private async Task<TpmResult<LoadExternalResponse>> LoadKemKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, byte[]? scalar)
    {
        byte[] point = Convert.FromHexString(PkRm);
        TpmsEccPoint unique = TpmsEccPoint.Create(point.AsSpan(1, P256ComponentSize), point.AsSpan(1 + P256ComponentSize, P256ComponentSize), pool);
        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccKemKey(NameAlg, ExternalKemAttributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, NameAlg, NameAlg, unique, pool);
        TpmtSensitive? inPrivate = scalar is null
            ? null
            : new TpmtSensitive(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, TpmuSensitiveComposite.FromEcc(Tpm2bEccParameter.Create(scalar, pool)));
        using var input = new LoadExternalInput(inPrivate, inPublic, scalar is null ? TpmiRhHierarchy.Owner : TpmiRhHierarchy.Null);

        return await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>The fixed key-generation delegate standing in for the encapsulation's ephemeral draw: RFC 9180 Appendix A.3.1's own (<c>skEm</c>, <c>pkEm</c>) instead of a fresh pair.</summary>
    /// <param name="curve">The requested curve, P-256 for this delegate's one caller.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token, unused — the fixed key needs no asynchronous work.</param>
    /// <returns>The vector's ephemeral key pair, in pool-owned carriers the caller disposes.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the scalar and point carriers transfers to the returned TpmGeneratedEccKey, which the encapsulation effect disposes after the ephemeral has been used.")]
    private static ValueTask<TpmGeneratedEccKey> FixedEphemeralKeyAsync(TpmEccCurveConstants curve, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] scalar = Convert.FromHexString(SkEm);
        IMemoryOwner<byte> scalarOwner = pool.Rent(scalar.Length);
        scalar.AsSpan().CopyTo(scalarOwner.Memory.Span);
        Array.Clear(scalar);

        var privateScalar = new PrivateKeyMemory(scalarOwner, CryptoTags.P256PrivateKey);
        EncodedEcPoint publicPoint = EncodedEcPoint.FromBytes(Convert.FromHexString(PkEm), CryptoTags.P256ExchangePublicKey, pool);

        return ValueTask.FromResult(new TpmGeneratedEccKey(privateScalar, publicPoint));
    }
}
