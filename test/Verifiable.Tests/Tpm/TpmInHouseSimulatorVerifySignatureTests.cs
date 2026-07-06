using System;
using System.Buffers;
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
/// Drives <c>TPM2_CreatePrimary()</c>, <c>TPM2_Sign()</c>, then <c>TPM2_VerifySignature()</c> against the
/// in-house behavioural <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the
/// same production command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="CreatePrimaryInput"/>, <see cref="SignInput"/>, <see cref="VerifySignatureInput"/>, and response
/// codecs).
/// </summary>
/// <remarks>
/// <para>
/// <c>TPM2_VerifySignature()</c> is a public-key operation (TPM 2.0 Library Part 3, clause 20.1): unlike every
/// other command this simulator signs with, the key referenced by <c>keyHandle</c> needs no authorization and
/// the effect never consults its <c>sign</c> attribute. A successful verification returns a
/// <c>TPMT_TK_VERIFIED</c> whose HMAC folds <c>TPM_ST_VERIFIED || digest || keyName</c> under the verifying key's
/// hierarchy proof — the field-order mirror of the creation ticket's <c>name || creationHash</c>.
/// </para>
/// <para>
/// The ECC positive test injects a fixed proof seed and independently reproduces the ticket HMAC from it, proving
/// the ticket is a genuine, verifiable HMAC bound to the injected seed rather than an opaque or stubbed value —
/// the same technique <c>TpmInHouseSimulatorSignTests.CreationTicketIsAVerifiableHmacOfTheInjectedSeed</c> uses
/// for the creation ticket.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorVerifySignatureTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate, an ECDSA r/s component, or a SHA-256 digest.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA verify-signature tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>The fixed message whose SHA-256 digest is signed and then verified.</summary>
    private static byte[] MessageBytes { get; } = "Verifiable in-house TPM VerifySignature acceptance test."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies a full ECDSA P-256 round trip through <c>TPM2_Sign()</c> then <c>TPM2_VerifySignature()</c>, and
    /// independently reproduces the returned <c>TPMT_TK_VERIFIED</c> HMAC from the injected proof seed — proving
    /// it is a real HMAC over <c>TPM_ST_VERIFIED || digest || keyName</c> bound to that seed (TPM 2.0 Library
    /// Part 3, clause 20.1; Part 2, clause 10.7.4), not a placeholder.
    /// </summary>
    [TestMethod]
    public async Task EcdsaVerifySignatureProducesAVerifiableTicket()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //A fixed seed stands in for the hierarchy's persistent random proof secret; injecting it makes the
        //verified ticket reproducible and lets this test recompute it.
        byte[] seed = Convert.FromHexString("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");

        var simulator = new TpmSimulator("tpm-in-house-verify-signature-seed", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), seed: seed);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (ECDSA) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        byte[] p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan());

        //VerifySignature carries no authorization at all: keyHandle needs none (a public-key operation), so the
        //executor is given no sessions and frames TPM_ST_NO_SESSIONS.
        using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(primary.ObjectHandle, digest, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature (ECDSA) failed: '{verifyResult.ResponseCode}'.");

        using VerifySignatureResponse verified = verifyResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_VERIFIED, verified.Validation.Tag, "The ticket tag must be TPM_ST_VERIFIED.");
        Assert.AreEqual(TpmRh.TPM_RH_OWNER, verified.Validation.Hierarchy, "The ticket hierarchy must be the signing key's own hierarchy.");
        Assert.IsFalse(verified.Validation.IsNull, "A successful verification must return a real ticket, not a NULL ticket.");
        Assert.AreEqual(P256ComponentSize, verified.Validation.Digest.Length, "The verified ticket digest is a SHA-256 HMAC.");

        //Recompute the ticket exactly as TPM2_VerifySignature would: the proof is H(seed || hierarchy), and the
        //ticket digest is HMAC(proof, TPM_ST_VERIFIED || digest || keyName) — the mirror image of the creation
        //ticket's TPM_ST_CREATION || name || creationHash order. A match proves the ticket is a real, verifiable
        //HMAC bound to the injected seed, not an opaque or stubbed value.
        byte[] proof = await ComputeSha256Async(BuildProofInput(seed, (uint)TpmRh.TPM_RH_OWNER), pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] ticketMessage = BuildVerifiedTicketMessage(digest, primary.Name.Span);
        byte[] expectedTicket = await ComputeHmacSha256Async(ticketMessage, proof, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            expectedTicket.AsSpan().SequenceEqual(verified.Validation.Digest),
            "The verified ticket must be HMAC(H(seed || hierarchy), TPM_ST_VERIFIED || digest || keyName), verifiable against the injected seed.");
    }

    /// <summary>
    /// Verifies RSA signatures under both RSASSA and RSAPSS through <c>TPM2_Sign()</c> then
    /// <c>TPM2_VerifySignature()</c>, asserting the returned ticket is structurally sound (TPM 2.0 Library Part 3,
    /// clause 20.1).
    /// </summary>
    [TestMethod]
    public async Task RsaVerifySignatureAcceptsRsaSsaAndRsaPssSignatures()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A NULL scheme makes this an unrestricted signing key, so the scheme (RSASSA or RSAPSS) is chosen per
        //TPM2_Sign() / TPM2_VerifySignature() — both are exercised against one (expensive) RSA key generation.
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        await SignAndVerifyRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, usePss: false).ConfigureAwait(false);
        await SignAndVerifyRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, usePss: true).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that a signature with one flipped octet fails verification: "Otherwise, the TPM shall return
    /// TPM_RC_SIGNATURE" (TPM 2.0 Library Part 3, clause 20.1).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithCorruptedSignatureReturnsSignature()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (ECDSA) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        byte[] p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan());

        //Flip one octet of the signature (part of the s component) so it no longer verifies against the digest.
        p1363Signature[^1] ^= 0xFF;

        using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(primary.ObjectHandle, digest, p1363Signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIGNATURE, verifyResult.ResponseCode);
    }

    /// <summary>
    /// Verifies that an RSA-shaped signature against an ECC key is rejected: the signature algorithm must be
    /// compatible with the resolved key's type (TPM_RC_SCHEME on mismatch, mirroring TPM2_Certify()'s dispatch).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithSchemeIncompatibleWithKeyTypeReturnsScheme()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //An RSASSA-shaped signature against an ECC key: rejected before the verify delegate is ever consulted, so
        //the placeholder signature bytes need not be genuine.
        byte[] placeholderSignature = new byte[Rsa2048KeyBits / 8];
        using VerifySignatureInput verifyInput = VerifySignatureInput.ForRsaSsa(primary.ObjectHandle, digest, placeholderSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SCHEME, verifyResult.ResponseCode);
    }

    /// <summary>
    /// Verifies that an unknown <c>keyHandle</c> is rejected: no transient object resolves to it (TPM 2.0 Library
    /// Part 3, clause 20.1).
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureWithUnknownKeyHandleReturnsHandle()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //No key was created, so the transient handle does not resolve.
        byte[] digest = await ComputeSha256Async(MessageBytes, pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] placeholderSignature = new byte[2 * P256ComponentSize];
        using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase), digest, placeholderSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, verifyResult.ResponseCode);
    }

    /// <summary>
    /// Signs the digest with the given RSA scheme through <c>TPM2_Sign()</c>, then verifies it through
    /// <c>TPM2_VerifySignature()</c>, asserting success and a structurally sound returned ticket.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The handle of the loaded RSA signing key.</param>
    /// <param name="digest">The pre-computed SHA-256 digest to sign and verify.</param>
    /// <param name="usePss">When <see langword="true"/>, signs and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task SignAndVerifyRsaAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmiDhObject keyHandle, byte[] digest, bool usePss)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = usePss
            ? SignInput.ForRsaPss(keyHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool)
            : SignInput.ForRsaSsa(keyHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        string schemeName = usePss ? "RSAPSS" : "RSASSA";
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign ({schemeName}) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        byte[] rsaSignature = signature.Signature.RsaSignature.Buffer.ToArray();

        using VerifySignatureInput verifyInput = usePss
            ? VerifySignatureInput.ForRsaPss(keyHandle, digest, rsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool)
            : VerifySignatureInput.ForRsaSsa(keyHandle, digest, rsaSignature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature ({schemeName}) failed: '{verifyResult.ResponseCode}'.");

        using VerifySignatureResponse verified = verifyResult.Value;
        Assert.AreEqual(TpmStConstants.TPM_ST_VERIFIED, verified.Validation.Tag, "The ticket tag must be TPM_ST_VERIFIED.");
        Assert.AreEqual(TpmRh.TPM_RH_OWNER, verified.Validation.Hierarchy, "The ticket hierarchy must be the signing key's own hierarchy.");
        Assert.IsFalse(verified.Validation.IsNull, "A successful verification must return a real ticket, not a NULL ticket.");
        Assert.AreEqual(P256ComponentSize, verified.Validation.Digest.Length, "The verified ticket digest is a SHA-256 HMAC.");
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
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Concatenates the ECDSA r and s components into the IEEE P1363 <c>r ‖ s</c> form the verify delegate and
    /// <see cref="VerifySignatureInput.ForEcdsa"/> take, left-padding each to the P-256 field width.
    /// </summary>
    /// <param name="r">The signature's r component.</param>
    /// <param name="s">The signature's s component.</param>
    /// <returns>The concatenated, fixed-width P1363 signature.</returns>
    private static byte[] ConcatenateP1363(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s)
    {
        byte[] result = new byte[2 * P256ComponentSize];
        ToFixed(r, P256ComponentSize).CopyTo(result.AsSpan(0));
        ToFixed(s, P256ComponentSize).CopyTo(result.AsSpan(P256ComponentSize));

        return result;
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
            "tpm-in-house-verify-signature",
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
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature);

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

    /// <summary>Computes an HMAC-SHA256 through the registered HMAC seam.</summary>
    /// <param name="message">The message to authenticate.</param>
    /// <param name="key">The HMAC key.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte HMAC.</returns>
    private static async Task<byte[]> ComputeHmacSha256Async(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> key, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            message, key, P256ComponentSize, CryptoTags.HmacSha256Value, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return hmac.AsReadOnlySpan().ToArray();
    }

    /// <summary>Builds the ticket proof-derivation input: the seed followed by the hierarchy handle.</summary>
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

    /// <summary>
    /// Builds the verified-ticket HMAC message: TPM_ST_VERIFIED (UINT16) followed by the digest and the
    /// verifying key's Name — the mirror image of the creation ticket's TPM_ST_CREATION || name || creationHash
    /// order.
    /// </summary>
    /// <param name="digest">The digest the signature was claimed to be over.</param>
    /// <param name="keyName">The verifying key's Name.</param>
    /// <returns>The ticket message bytes.</returns>
    private static byte[] BuildVerifiedTicketMessage(ReadOnlySpan<byte> digest, ReadOnlySpan<byte> keyName)
    {
        byte[] message = new byte[sizeof(ushort) + digest.Length + keyName.Length];
        var writer = new TpmWriter(message);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_VERIFIED);
        writer.WriteBytes(digest);
        writer.WriteBytes(keyName);

        return message;
    }

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 encoding requires. The simulator
    /// returns TPM2B integers that may omit leading zero bytes.
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
