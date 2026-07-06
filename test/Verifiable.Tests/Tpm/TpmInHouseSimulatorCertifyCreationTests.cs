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
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_CertifyCreation()</c> (creation attestation) against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="CertifyCreationInput"/> and response codecs): <c>TPM2_CreatePrimary()</c> mints a subject signing
/// key under the owner hierarchy and a separate attestation key (AK) under the endorsement hierarchy, then the AK
/// certifies that the subject was created by the TPM, re-verifying the creation ticket <c>TPM2_CreatePrimary()</c>
/// returned.
/// </summary>
/// <remarks>
/// <para>
/// The result is verified <b>off-TPM</b> from wire bytes only: the magic / type / nonce fields, that the attested
/// objectName equals the subject's Name recomputed independently from its exported public area, that the attested
/// creationHash equals the creation hash <c>TPM2_CreatePrimary()</c> reported, and the ECDSA/RSA signature over the
/// raw attestation bytes against the AK's exported public key reconstructed from <c>outPublic</c> alone.
/// </para>
/// <para>
/// Only the signing key (<c>@signHandle</c>) requires authorization (TPM 2.0 Library Part 3, clause 18.3, Table
/// 88); the certified object (<c>objectHandle</c>) carries no authorization at all, so the executor is given a
/// single empty-auth password session.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCertifyCreationTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA certify-creation tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.</summary>
    private static byte[] Nonce { get; } = "CertifyCreation nonce for the in-house TPM."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies a full ECDSA P-256 certify-creation round trip: the attested objectName matches the subject's
    /// independently recomputed Name, the attested creationHash matches CreatePrimary's own reported creation
    /// hash, qualifiedSigner is the AK's real (non-collapsed) Qualified Name, and the signature verifies against
    /// the AK's exported public key (TPM 2.0 Library Part 3, clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task EcdsaP256CertifyCreationVerifiesAgainstInHouseSimulator()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_CertifyCreation failed: '{result.ResponseCode}'.");

        using CertifyCreationResponse certifyCreation = result.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, certifyCreation.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, certifyCreation.HashAlgorithm);

        await AssertCreationAttestationAsync(certifyCreation, subject, ak, pool).ConfigureAwait(false);

        byte[] attestDigest = await ComputeSha256Async(certifyCreation.CertifyInfo.GetRawBytes().ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);

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
        ToFixed(certifyCreation.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(certifyCreation.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(
            ecdsa.VerifyHash(attestDigest, p1363Signature),
            "The certify-creation signature must verify over the raw attestation bytes against the AK's exported public key.");
    }

    /// <summary>
    /// Verifies certify-creation with an RSA AK under both RSASSA and RSAPSS, mirroring the ECDSA assertions
    /// (TPM 2.0 Library Part 3, clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task RsaCertifyCreationVerifiesAgainstInHouseSimulator()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        var rsaParameters = new RSAParameters
        {
            Modulus = ak.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        await CertifyCreationAndVerifyRsaAsync(tpm, registry, pool, subject, ak, rsaParameters, usePss: false).ConfigureAwait(false);
        await CertifyCreationAndVerifyRsaAsync(tpm, registry, pool, subject, ak, rsaParameters, usePss: true).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that a creation ticket with one flipped octet fails the stateless re-verification: "This ticket
    /// is then compared to creationTicket. If the tickets are not the same, the TPM shall return TPM_RC_TICKET"
    /// (TPM 2.0 Library Part 3, clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithTamperedTicketReturnsTicket()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmtTkCreation tamperedTicket = FlipTicketOctet(subject.CreationTicket, pool);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), tamperedTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_TICKET, result.ResponseCode);
    }

    /// <summary>
    /// Verifies that a storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) as the certify-creation's signHandle
    /// is rejected with <c>TPM_RC_KEY</c>: "If the sign attribute is not SET in the key referenced by signHandle
    /// then the TPM shall return TPM_RC_KEY" (TPM 2.0 Library Part 3, clause 18.1, shared by clause 18.3).
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithNonSigningKeyReturnsKey()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
            parent.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode);
    }

    /// <summary>
    /// Certifies the subject's creation with the RSA AK under the given scheme through the production command
    /// path, verifies the attestation off-TPM, and verifies the signature against the AK's exported modulus with
    /// an independent RSA verifier.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="subject">The certified object's CreatePrimary response.</param>
    /// <param name="ak">The RSA attestation key's CreatePrimary response.</param>
    /// <param name="rsaParameters">The public key reconstructed from the AK's exported modulus.</param>
    /// <param name="usePss">When <see langword="true"/>, certifies and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task CertifyCreationAndVerifyRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, CreatePrimaryResponse subject, CreatePrimaryResponse ak, RSAParameters rsaParameters, bool usePss)
    {
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyCreationInput certifyCreationInput = usePss
            ? CertifyCreationInput.ForRsaPss(ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool)
            : CertifyCreationInput.ForRsaSsa(ak.ObjectHandle, subject.ObjectHandle, Nonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
            tpm, certifyCreationInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        string schemeName = usePss ? "RSAPSS" : "RSASSA";
        Assert.IsTrue(result.IsSuccess, $"TPM2_CertifyCreation ({schemeName}) failed: '{result.ResponseCode}'.");

        using CertifyCreationResponse certifyCreation = result.Value;
        Assert.AreEqual(usePss ? TpmAlgIdConstants.TPM_ALG_RSAPSS : TpmAlgIdConstants.TPM_ALG_RSASSA, certifyCreation.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, certifyCreation.HashAlgorithm);

        await AssertCreationAttestationAsync(certifyCreation, subject, ak, pool).ConfigureAwait(false);

        byte[] attestDigest = await ComputeSha256Async(certifyCreation.CertifyInfo.GetRawBytes().ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(attestDigest, certifyCreation.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, padding),
            $"The {schemeName} certify-creation signature must verify against the RSA AK's exported modulus.");
    }

    /// <summary>
    /// Asserts the envelope (magic/type/nonce), the attested objectName against an independent Name
    /// recomputation, the attested creationHash against CreatePrimary's own reported creation hash, and
    /// qualifiedSigner against an independent (non-collapsed) Qualified Name recomputation.
    /// </summary>
    /// <param name="certifyCreation">The parsed certify-creation response.</param>
    /// <param name="subject">The certified object's CreatePrimary response.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task AssertCreationAttestationAsync(CertifyCreationResponse certifyCreation, CreatePrimaryResponse subject, CreatePrimaryResponse ak, MemoryPool<byte> pool)
    {
        TpmsAttest attest = certifyCreation.CertifyInfo.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_CREATION, attest.Type);
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
        Assert.IsNotNull(attest.Attested.Creation);

        byte[] expectedName = await ComputeObjectNameAsync(subject.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Creation!.ObjectName.Span.SequenceEqual(expectedName),
            "The attested objectName must equal the subject's Name recomputed from its exported public area.");

        Assert.IsTrue(
            attest.Attested.Creation!.CreationHash.AsReadOnlySpan().SequenceEqual(subject.CreationHash.AsReadOnlySpan()),
            "The attested creationHash must equal the creation hash TPM2_CreatePrimary() reported for the subject.");

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
    /// Round-trips a creation ticket through the wire form with the last octet (part of the HMAC digest) flipped,
    /// producing a ticket that fails the stateless re-verification without depending on any non-public
    /// construction API.
    /// </summary>
    /// <param name="ticket">The genuine creation ticket to tamper with.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>A tampered creation ticket the caller owns and must dispose.</returns>
    private static TpmtTkCreation FlipTicketOctet(TpmtTkCreation ticket, MemoryPool<byte> pool)
    {
        int size = ticket.SerializedSize;
        byte[] wireBytes = new byte[size];
        var writer = new TpmWriter(wireBytes);
        ticket.WriteTo(ref writer);

        wireBytes[^1] ^= 0xFF;

        var reader = new TpmReader(wireBytes);
        return TpmtTkCreation.Parse(ref reader, pool);
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
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
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
    /// Creates a primary RSA-2048 signing key under the given hierarchy and returns the response (the caller owns
    /// it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
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
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
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
    /// Recomputes a loaded object's Name from its exported public area: <c>nameAlg || H_nameAlg(TPMT_PUBLIC)</c>
    /// (TPM 2.0 Library Part 1, clause 16), through the registered digest seam. The test keys use a SHA-256 nameAlg.
    /// </summary>
    /// <param name="outPublic">The object's exported public area.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Name (2-byte nameAlg prefix + digest).</returns>
    private static async Task<byte[]> ComputeObjectNameAsync(Tpm2bPublic outPublic, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        TpmAlgIdConstants nameAlg = outPublic.PublicArea.NameAlg;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, nameAlg, "This test assumes a SHA-256 nameAlg.");

        byte[] marshaledPublic = MarshalPublicArea(outPublic, pool);
        byte[] digest = await ComputeSha256Async(marshaledPublic, pool, cancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Recomputes an object's Qualified Name independently: <c>nameAlg || H(hierarchyHandle || Name)</c> (TPM 2.0
    /// Library Part 1, clause 16), through the registered digest seam. Every object this simulator certifies is a
    /// primary created directly under a permanent hierarchy, so the hierarchy's own Qualified Name is its 4-octet
    /// big-endian handle value — this test never calls the production <c>TpmObjectName</c> helper, matching the
    /// file's firewalled, off-TPM oracle style.
    /// </summary>
    /// <param name="hierarchy">The permanent hierarchy handle the object was created under.</param>
    /// <param name="name">The object's own Name.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Qualified Name.</returns>
    private static async Task<byte[]> ComputeQualifiedNameAsync(uint hierarchy, ReadOnlyMemory<byte> name, MemoryPool<byte> pool, CancellationToken cancellationToken)
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
    /// Marshals the exported public area into its canonical TPMT_PUBLIC wire form (no TPM2B size prefix) — the
    /// hash input the object Name is computed over.
    /// </summary>
    /// <param name="outPublic">The exported public area.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The marshaled TPMT_PUBLIC bytes.</returns>
    private static byte[] MarshalPublicArea(Tpm2bPublic outPublic, MemoryPool<byte> pool)
    {
        int size = outPublic.PublicArea.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        outPublic.PublicArea.WriteTo(ref writer);

        return owner.Memory.Span[..size].ToArray();
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-certify-creation",
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
    private async Task BringOperationalAsync(TpmSimulator simulator, MemoryPool<byte> pool)
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
        _ = registry.Register(TpmCcConstants.TPM_CC_CertifyCreation, TpmResponseCodec.CertifyCreation);

        return registry;
    }

    /// <summary>
    /// Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, MemoryPool<byte> pool, CancellationToken cancellationToken)
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
