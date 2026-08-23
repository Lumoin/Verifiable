using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Foundation.Automata;
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

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The response-side structure proofs for the in-house <see cref="TpmSimulator"/>: every response parameter the
/// specification names a structure for is carried as that structure rather than as a buffer plus a length, and the
/// structure is the intent's owned carrier — so a completed command must RETURN every one of those rentals to the
/// pool once the response is framed and the caller has released it. Proven with real pool telemetry
/// (<see cref="MeteredHousePool"/>) over the real wire, never with internal hooks, and always over a genuinely
/// non-empty value, since an empty one rides a dispose-immune shared sentinel that rents nothing and would make the
/// balance vacuous.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorResponseStructureSlotTests
{
    /// <summary>The session hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The NV Index handle the NV proofs define.</summary>
    private const uint NvIndexHandle = 0x0100_0031;

    /// <summary>The declared data area size of the Index the NV proofs define; <see cref="NvWriteData"/> fills it exactly.</summary>
    private const ushort NvDataSize = 8;

    /// <summary>The attribute set the NV proofs define their Index with: caller-authorized both ways, dictionary-attack exempt.</summary>
    private const TpmaNv IndexAttributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The number of random octets the <c>TPM2_GetRandom()</c> proof asks for — non-zero, so a real rental is under proof.</summary>
    private const ushort RequestedRandomBytes = 32;

    /// <summary>The octets the NV proofs write, sized to fill the declared data area.</summary>
    private static byte[] NvWriteData { get; } = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];

    /// <summary>The secret the credential proofs wrap and recover.</summary>
    private static byte[] CredentialSecret { get; } = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];

    /// <summary>The octets the seal proofs seal, so the wrapped private blob is genuinely non-empty.</summary>
    private static byte[] SealedSecret { get; } = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];

    /// <summary>The digest the signature proofs sign and then have the TPM verify.</summary>
    private static byte[] SignedDigest { get; } =
    [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60
    ];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A completed <c>TPM2_GetRandom()</c> returns its <c>randomBytes</c> carrier to the pool: Table 72 types
    /// that response parameter <c>TPM2B_DIGEST</c> (TPM 2.0 Library Part 3, clause 16.1), so the RNG effect rents
    /// exactly the requested octets into that carrier and the serializer is its terminal owner. The request is
    /// deliberately for a non-zero width: a zero-length request frames the dispose-immune shared empty digest,
    /// which rents nothing and would make this balance vacuous.
    /// </summary>
    [TestMethod]
    public async Task CompletedGetRandomReturnsTheRandomBytesCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-slots-getrandom").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;
        {
            var input = new GetRandomInput(RequestedRandomBytes);
            TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_GetRandom failed: '{result.ResponseCode}'.");

            using GetRandomResponse random = result.Value;
            Assert.AreEqual(RequestedRandomBytes, random.RandomBytes.Size, "The TPM must return exactly the octets asked for.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Framing the response must return the randomBytes carrier the RNG effect rented.");
    }

    /// <summary>
    /// A completed <c>TPM2_Create()</c> returns its <c>outPrivate</c> carrier to the pool: Table 19 types that
    /// response parameter <c>TPM2B_PRIVATE</c> (TPM 2.0 Library Part 3, clause 12.1) — a blob whose content is by
    /// definition the TPM's own opaque encoding — so the seal effect packs it straight into that carrier and the
    /// serializer is its terminal owner.
    /// </summary>
    [TestMethod]
    public async Task CompletedCreateReturnsThePrivateBlobCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-slots-create").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle;
        using(CreatePrimaryResponse parent = await CreateStoragePrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            parentHandle = parent.ObjectHandle.Value;
        }

        long baseline = trackingPool.OutstandingCount;
        {
            using CreateResponse sealedObject = await SealAsync(tpm, registry, trackingPool.Pool, parentHandle).ConfigureAwait(false);
            Assert.IsFalse(sealedObject.OutPrivate.IsEmpty, "The wrapped private blob must be non-empty for this balance to prove anything.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Framing the response must return the outPrivate carrier the seal effect packed.");
    }

    /// <summary>
    /// A completed <c>TPM2_Load()</c> returns the loaded object's <c>name</c> carrier to the pool: Table 21 types
    /// that response parameter <c>TPM2B_NAME</c> (TPM 2.0 Library Part 3, clause 12.2), so the load effect adopts
    /// the Name octets it computed into that carrier and the serializer is its terminal owner. The loaded object's
    /// own retained Name is a separate copy, so flushing the object afterwards proves no double release.
    /// </summary>
    [TestMethod]
    public async Task CompletedLoadReturnsTheObjectNameCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-slots-load").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle;
        using(CreatePrimaryResponse parent = await CreateStoragePrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            parentHandle = parent.ObjectHandle.Value;
        }

        using CreateResponse sealedObject = await SealAsync(tpm, registry, trackingPool.Pool, parentHandle).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        uint loadedHandle;
        {
            using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, trackingPool.Pool);
            using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, trackingPool.Pool);
            using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
            using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

            TpmResult<LoadResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, loadInput, [parentAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_Load failed: '{result.ResponseCode}'.");

            using LoadResponse loaded = result.Value;
            loadedHandle = loaded.ObjectHandle.Value;
            Assert.IsFalse(loaded.Name.IsEmpty, "A loaded object's Name must be non-empty for this balance to prove anything.");
        }

        await FlushAsync(tpm, registry, trackingPool.Pool, loadedHandle).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Framing the response must return the Name carrier the load effect adopted, and the flushed object must release only its own retained copy.");
    }

    /// <summary>
    /// A completed <c>TPM2_NV_ReadPublic()</c> returns the Index's <c>nvName</c> carrier to the pool: Table 235
    /// types that response parameter <c>TPM2B_NAME</c> (TPM 2.0 Library Part 3, clause 31.6), so the Name effect
    /// adopts the octets it computed into that carrier and the serializer is its terminal owner alongside the
    /// built public area.
    /// </summary>
    [TestMethod]
    public async Task CompletedNvReadPublicReturnsTheIndexNameCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-slots-nvreadpublic").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            var input = new NvReadPublicInput(NvIndexHandle);
            TpmResult<NvReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
                tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_NV_ReadPublic failed: '{result.ResponseCode}'.");

            using NvReadPublicResponse readPublic = result.Value;
            Assert.IsFalse(readPublic.NvName.IsEmpty, "An Index's computed Name must be non-empty for this balance to prove anything.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Framing the response must return the nvName carrier the Name effect adopted.");
    }

    /// <summary>
    /// A completed <c>TPM2_NV_Read()</c> authorized over an HMAC session returns the response session's own
    /// <c>hmac</c> carrier to the pool: <c>TPMS_AUTH_RESPONSE.hmac</c> is a <c>TPM2B_AUTH</c> (TPM 2.0 Library
    /// Part 2, clause 10.13.3, Table 154), so the framing effect rents exactly the session digest into that
    /// carrier and the serializer is its terminal owner. The client session is built OUTSIDE the measured window
    /// because it adopts the response's nonceTPM carrier, which would otherwise blur the one balance under proof.
    /// </summary>
    [TestMethod]
    public async Task CompletedNvReadOverSessionReturnsTheResponseHmacCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-slots-nvread-session").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        await WriteIndexAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        //An NV Index authorized over an HMAC session contributes its Name to cpHash, so the caller reads it
        //first (TPM 2.0 Library Part 1, clause 16.7, equation 15).
        ReadOnlyMemory<byte>[] handleNames;
        {
            var readPublicInput = new NvReadPublicInput(NvIndexHandle);
            TpmResult<NvReadPublicResponse> readPublicResult = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
                tpm, readPublicInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(readPublicResult.IsSuccess, $"TPM2_NV_ReadPublic failed: '{readPublicResult.ResponseCode}'.");

            using NvReadPublicResponse readPublic = readPublicResult.Value;
            //Both of TPM2_NV_Read()'s handles address the same Index here (it authorizes itself), so the same
            //Name stands in both cpHash slots.
            byte[] indexName = readPublic.NvName.Span.ToArray();
            handleNames = [indexName, indexName];
        }

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, trackingPool.Pool);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        long baseline = trackingPool.OutstandingCount;
        {
            var readInput = new NvReadInput(AuthHandle: NvIndexHandle, NvIndex: NvIndexHandle, Size: NvDataSize, Offset: 0);
            TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                tpm, readInput, [session], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Read over an HMAC session failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Framing the session-tagged response must return the response HMAC carrier the framing effect rented.");

        await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// A completed <c>TPM2_MakeCredential()</c> returns both of its response carriers to the pool: Table 29 types
    /// <c>credentialBlob</c> a <c>TPM2B_ID_OBJECT</c> and <c>secret</c> a <c>TPM2B_ENCRYPTED_SECRET</c> (TPM 2.0
    /// Library Part 3, clause 12.6), so the credential effect adopts the octets it built into those two carriers
    /// and the serializer is the terminal owner of both.
    /// </summary>
    [TestMethod]
    public async Task CompletedMakeCredentialReturnsBothResponseCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-slots-makecredential").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse credentialKey = await CreateStoragePrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        using CreatePrimaryResponse activateObject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        byte[] activateName = activateObject.Name.Span.ToArray();

        long baseline = trackingPool.OutstandingCount;
        {
            using MakeCredentialResponse made = await MakeCredentialAsync(
                tpm, registry, trackingPool.Pool, credentialKey.ObjectHandle, activateName, CredentialSecret).ConfigureAwait(false);
            Assert.IsFalse(made.CredentialBlob.IsEmpty, "The credential blob must be non-empty for this balance to prove anything.");
            Assert.IsFalse(made.Secret.IsEmpty, "The encrypted secret must be non-empty for this balance to prove anything.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Framing the response must return both the credentialBlob and the secret carriers the credential effect adopted.");

        await FlushAsync(tpm, registry, trackingPool.Pool, activateObject.ObjectHandle.Value).ConfigureAwait(false);
        await FlushAsync(tpm, registry, trackingPool.Pool, credentialKey.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// A completed <c>TPM2_ActivateCredential()</c> returns its <c>certInfo</c> carrier to the pool: Table 27
    /// types that response parameter <c>TPM2B_DIGEST</c> (TPM 2.0 Library Part 3, clause 12.5), so the recovered
    /// secret rides that carrier from the activation effect to the serializer, which is its terminal owner and
    /// releases its pinned segment to the pool that zeroes every segment it takes back.
    /// </summary>
    [TestMethod]
    public async Task CompletedActivateCredentialReturnsTheCertInfoCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-slots-activatecredential").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse credentialKey = await CreateStoragePrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        using CreatePrimaryResponse activateObject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        byte[] activateName = activateObject.Name.Span.ToArray();

        using MakeCredentialResponse made = await MakeCredentialAsync(
            tpm, registry, trackingPool.Pool, credentialKey.ObjectHandle, activateName, CredentialSecret).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using ActivateCredentialInput input = ActivateCredentialInput.Create(
                activateObject.ObjectHandle, credentialKey.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, trackingPool.Pool);
            using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

            TpmResult<ActivateCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                tpm, input, [activateAuth, keyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_ActivateCredential failed: '{result.ResponseCode}'.");

            using ActivateCredentialResponse activated = result.Value;
            Assert.IsTrue(
                activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret),
                "The recovered credential must equal the wrapped secret, so the balance is taken over a real, non-empty carrier.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Framing the response must return the certInfo carrier the activation effect rented.");

        await FlushAsync(tpm, registry, trackingPool.Pool, activateObject.ObjectHandle.Value).ConfigureAwait(false);
        await FlushAsync(tpm, registry, trackingPool.Pool, credentialKey.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// A completed <c>TPM2_VerifySignature()</c> returns its <c>validation</c> ticket to the pool: Table 108 gives
    /// the response exactly one parameter, a <c>TPMT_TK_VERIFIED</c> (TPM 2.0 Library Part 3, clause 20.1; Part 2,
    /// clause 10.7.4, Table 110), so the tag, hierarchy, and ticket HMAC travel as one owned structure that the
    /// serializer is the terminal owner of.
    /// </summary>
    [TestMethod]
    public async Task CompletedVerifySignatureReturnsTheValidationTicketToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-slots-verifysignature").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signingKey = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
        using SignInput signInput = SignInput.ForEcdsa(signingKey.ObjectHandle, SignedDigest, SessionAlg, trackingPool.Pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [signAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        using Signature p1363Signature = ConcatenateP1363(
            signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), trackingPool.Pool);

        long baseline = trackingPool.OutstandingCount;
        {
            using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(
                signingKey.ObjectHandle, SignedDigest, p1363Signature.AsReadOnlySpan(), SessionAlg, trackingPool.Pool);

            TpmResult<VerifySignatureResponse> result = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
                tpm, verifyInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_VerifySignature failed: '{result.ResponseCode}'.");

            using VerifySignatureResponse verified = result.Value;
            Assert.IsFalse(verified.Validation.IsNull, "A real-hierarchy key must produce a non-NULL ticket, so the balance is taken over a real rental.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Framing the response must return the validation ticket's digest storage the verify effect adopted.");

        await FlushAsync(tpm, registry, trackingPool.Pool, signingKey.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// Adopting a <c>TPM2B_NAME</c> whose declared size overruns the buffer it is handed releases that buffer
    /// before the refusal leaves: an adopter takes ownership or releases it, never both and never neither, so a
    /// rejected adoption cannot orphan the producer's rental (TPM 2.0 Library Part 2, clause 10.5.3, Table 104).
    /// </summary>
    [TestMethod]
    public void NameAdoptionOfAnOverrunningSizeReleasesTheStorage()
    {
        using var trackingPool = new MeteredHousePool();

        long baseline = trackingPool.OutstandingCount;
        IMemoryOwner<byte> storage = trackingPool.Pool.Rent(8);

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Tpm2bName.FromMarshaled(storage, 9));

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A refused adoption must return the buffer it was handed rather than orphan the rental.");
    }

    /// <summary>
    /// Adopting a <c>TPM2B_ENCRYPTED_SECRET</c> with a negative declared length releases the buffer before the
    /// refusal leaves — the same release-on-failure contract every adopter carries (TPM 2.0 Library Part 2,
    /// clause 11.4.3, Table 210).
    /// </summary>
    [TestMethod]
    public void EncryptedSecretAdoptionOfANegativeLengthReleasesTheStorage()
    {
        using var trackingPool = new MeteredHousePool();

        long baseline = trackingPool.OutstandingCount;
        IMemoryOwner<byte> storage = trackingPool.Pool.Rent(8);

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Tpm2bEncryptedSecret.FromMarshaled(storage, -1));

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A refused adoption must return the buffer it was handed rather than orphan the rental.");
    }

    /// <summary>
    /// Adopting a zero-length <c>TPM2B_PRIVATE</c> yields the shared empty singleton and releases the buffer it
    /// was handed: the singleton owns no storage, so keeping the rental alive behind it would leak a segment no
    /// disposal ever reaches (TPM 2.0 Library Part 2, clause 12.3.7, Table 227).
    /// </summary>
    [TestMethod]
    public void PrivateAdoptionOfAZeroLengthValueYieldsTheEmptySingletonAndReleasesTheStorage()
    {
        using var trackingPool = new MeteredHousePool();

        long baseline = trackingPool.OutstandingCount;
        IMemoryOwner<byte> storage = trackingPool.Pool.Rent(8);
        Tpm2bPrivate adopted = Tpm2bPrivate.FromMarshaled(storage, 0);

        Assert.AreSame(Tpm2bPrivate.Empty, adopted, "A zero-length adoption must yield the shared empty singleton.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The singleton owns no storage, so the adopted buffer must be returned rather than held behind it.");

        adopted.Dispose();

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the shared empty singleton must stay a no-op.");
    }

    /// <summary>
    /// Adopting a <c>TPM2B_ID_OBJECT</c> carries exactly the declared prefix of a longer buffer: the producer
    /// rents whatever width its own layout needs and declares how much of it is the value, and the carrier frames
    /// that prefix and nothing else (TPM 2.0 Library Part 2, clause 12.4.3, Table 229).
    /// </summary>
    [TestMethod]
    public void IdObjectAdoptionCarriesOnlyTheDeclaredPrefixOfALongerBuffer()
    {
        using var trackingPool = new MeteredHousePool();
        ReadOnlySpan<byte> value = [0x71, 0x72, 0x73, 0x74];

        long baseline = trackingPool.OutstandingCount;
        {
            IMemoryOwner<byte> storage = trackingPool.Pool.Rent(16);
            value.CopyTo(storage.Memory.Span);

            using Tpm2bIdObject adopted = Tpm2bIdObject.FromMarshaled(storage, value.Length);
            Assert.AreEqual(value.Length, adopted.Length, "The carrier's length must be the declared prefix, not the buffer's width.");
            Assert.AreEqual(sizeof(ushort) + value.Length, adopted.SerializedSize, "The framed size must count the declared prefix only.");
            Assert.AreSequenceEqual(value.ToArray(), adopted.Span.ToArray(), "The carrier must expose exactly the declared prefix.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the carrier must return the adopted buffer.");
    }

    /// <summary>
    /// Adopting a <c>TPMT_TK_VERIFIED</c> whose declared digest length overruns the buffer releases that buffer
    /// before the refusal leaves, and a zero-length one yields the shared NULL ticket and releases it too — the
    /// ticket owns storage only when it genuinely carries a digest (TPM 2.0 Library Part 2, clause 10.7.4,
    /// Table 110).
    /// </summary>
    [TestMethod]
    public void VerifiedTicketAdoptionReleasesTheDigestOnRefusalAndOnTheNullForm()
    {
        using var trackingPool = new MeteredHousePool();

        long baseline = trackingPool.OutstandingCount;
        IMemoryOwner<byte> overrunning = trackingPool.Pool.Rent(32);

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => TpmtTkVerified.FromMarshaled(TpmiRhHierarchy.Owner, overrunning, 33));

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refused adoption must return the buffer it was handed.");

        IMemoryOwner<byte> emptyDigest = trackingPool.Pool.Rent(32);
        TpmtTkVerified nullTicket = TpmtTkVerified.FromMarshaled(TpmiRhHierarchy.Null, emptyDigest, 0);

        Assert.IsTrue(nullTicket.IsNull, "A zero-length digest under TPM_RH_NULL is the NULL Verified Ticket.");
        Assert.AreSame(TpmtTkVerified.Null, nullTicket, "A zero-length adoption under TPM_RH_NULL must yield the shared sentinel.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The NULL ticket owns no storage, so the adopted buffer must be returned.");

        nullTicket.Dispose();

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the shared NULL ticket must stay a no-op.");
        Assert.IsTrue(TpmtTkVerified.Null.Digest.IsEmpty, "The disposed-through sentinel must still read as an empty digest.");
        Assert.IsTrue(TpmtTkVerified.Null.IsNull, "The disposed-through sentinel must still be the NULL Verified Ticket.");
    }

    /// <summary>
    /// The shared NULL Verified Ticket survives disposal from every direction: the instance a zero-length
    /// adoption hands back IS that sentinel, and neither disposing it through that reference nor disposing
    /// <see cref="TpmtTkVerified.Null"/> directly may retire it, because every consumer of a NULL ticket holds
    /// the same instance and a caller that releases a returned ticket without inspecting it would otherwise
    /// break every later one. After both disposals the sentinel still reads an empty digest and still frames
    /// the NULL tuple <c>(TPM_ST_VERIFIED, TPM_RH_NULL, empty)</c> of TPM 2.0 Library Part 2, clause 10.7.2
    /// (clause 10.7.4, Table 110).
    /// </summary>
    [TestMethod]
    public void VerifiedTicketNullSentinelStaysUsableAfterEveryDisposal()
    {
        using var trackingPool = new MeteredHousePool();
        byte[] expected = [0x80, 0x22, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00];

        long baseline = trackingPool.OutstandingCount;
        IMemoryOwner<byte> adopted = trackingPool.Pool.Rent(32);
        TpmtTkVerified fromAdoption = TpmtTkVerified.FromMarshaled(TpmiRhHierarchy.Null, adopted, 0);

        Assert.AreSame(TpmtTkVerified.Null, fromAdoption, "The zero-length NULL form must be the shared sentinel, not a fresh instance.");

        fromAdoption.Dispose();
        TpmtTkVerified.Null.Dispose();

        Assert.IsTrue(TpmtTkVerified.Null.Digest.IsEmpty, "The sentinel carries no digest and must stay readable after disposal.");
        Assert.AreEqual(sizeof(ushort) + sizeof(uint) + sizeof(ushort), TpmtTkVerified.Null.SerializedSize, "The NULL tuple frames as tag, hierarchy, and an empty TPM2B_DIGEST.");

        {
            using IMemoryOwner<byte> framing = trackingPool.Pool.Rent(TpmtTkVerified.Null.SerializedSize);
            var writer = new TpmWriter(framing.Memory.Span);
            TpmtTkVerified.Null.WriteTo(ref writer);

            Assert.AreSequenceEqual(
                expected, framing.Memory.Span[..TpmtTkVerified.Null.SerializedSize].ToArray(),
                "The disposed-through sentinel must still frame TPM_ST_VERIFIED, TPM_RH_NULL, and a zero-length digest.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Neither the adoption nor the framing may leave a rental outstanding.");
    }

    /// <summary>
    /// A zero-length digest adopted under a hierarchy other than <c>TPM_RH_NULL</c> is NOT the NULL Verified
    /// Ticket: clause 10.7.2 defines that sentinel as the whole tuple <c>(TPM_ST_VERIFIED, TPM_RH_NULL, empty
    /// digest)</c>, so the hierarchy is part of the value. The adoption keeps the hierarchy it was handed in a
    /// storage-less ticket that frames those exact octets back — the same instance
    /// <see cref="TpmtTkVerified.Parse"/> reconstructs when it reads them off the wire — and the buffer it was
    /// handed is released either way, since a digest-less ticket owns nothing (TPM 2.0 Library Part 2, clause
    /// 10.7.4, Table 110).
    /// </summary>
    [TestMethod]
    public void VerifiedTicketAdoptionOfAZeroLengthDigestUnderANonNullHierarchyKeepsThatHierarchy()
    {
        using var trackingPool = new MeteredHousePool();
        byte[] expected = [0x80, 0x22, 0x40, 0x00, 0x00, 0x01, 0x00, 0x00];

        long baseline = trackingPool.OutstandingCount;
        {
            IMemoryOwner<byte> storage = trackingPool.Pool.Rent(32);
            using TpmtTkVerified adopted = TpmtTkVerified.FromMarshaled(TpmiRhHierarchy.Owner, storage, 0);

            Assert.AreNotSame(TpmtTkVerified.Null, adopted, "Only TPM_RH_NULL yields the shared NULL sentinel.");
            Assert.IsFalse(adopted.IsNull, "A ticket under the owner hierarchy is not the NULL Verified Ticket.");
            Assert.AreEqual(TpmiRhHierarchy.Owner, adopted.Hierarchy, "The adopter must keep the hierarchy it was handed.");
            Assert.IsTrue(adopted.Digest.IsEmpty, "A zero-length adoption carries no digest octets.");
            Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A digest-less ticket owns no storage, so the adopted buffer must be returned.");

            using IMemoryOwner<byte> framing = trackingPool.Pool.Rent(adopted.SerializedSize);
            var writer = new TpmWriter(framing.Memory.Span);
            adopted.WriteTo(ref writer);

            Assert.AreSequenceEqual(
                expected, framing.Memory.Span[..adopted.SerializedSize].ToArray(),
                "The storage-less non-NULL form frames TPM_ST_VERIFIED, the given hierarchy, and a zero-length digest.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the storage-less ticket must leave nothing outstanding.");
    }

    /// <summary>
    /// Every adopter refuses a <see langword="null"/> buffer with <see cref="ArgumentNullException"/>: adoption
    /// is a transfer of ownership, so with nothing handed over there is nothing to take and nothing to release,
    /// and the refusal precedes every length check (TPM 2.0 Library Part 2, clause 10.5.3, Table 104; clause
    /// 11.4.3, Table 210; clause 12.3.7, Table 227; clause 12.4.3, Table 229; clause 10.7.4, Table 110).
    /// </summary>
    [TestMethod]
    public void AdoptionOfANullStorageIsRefusedByEveryAdopter()
    {
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => Tpm2bName.FromMarshaled(null!, 0), "TPM2B_NAME must refuse a null buffer.");
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => Tpm2bEncryptedSecret.FromMarshaled(null!, 0), "TPM2B_ENCRYPTED_SECRET must refuse a null buffer.");
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => Tpm2bIdObject.FromMarshaled(null!, 0), "TPM2B_ID_OBJECT must refuse a null buffer.");
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => Tpm2bPrivate.FromMarshaled(null!, 0), "TPM2B_PRIVATE must refuse a null buffer.");
        _ = Assert.ThrowsExactly<ArgumentNullException>(
            () => TpmtTkVerified.FromMarshaled(TpmiRhHierarchy.Owner, null!, 0), "TPMT_TK_VERIFIED must refuse a null digest buffer.");
    }

    /// <summary>
    /// Every adopter refuses a declared length wider than the <c>UINT16</c> size field a <c>TPM2B</c> frames it
    /// through, and releases the buffer it was handed before the refusal leaves. The buffer is deliberately rented
    /// wide enough for the length, so the overrun check passes and the size-field bound is the one under proof
    /// (TPM 2.0 Library Part 2, clause 10.5.3, Table 104; clause 11.4.3, Table 210; clause 12.3.7, Table 227;
    /// clause 12.4.3, Table 229; clause 10.7.4, Table 110).
    /// </summary>
    [TestMethod]
    public void AdoptionOfALengthBeyondTheTpm2bSizeFieldIsRefusedAndReleasesTheStorage()
    {
        using var trackingPool = new MeteredHousePool();
        const int OverWideLength = ushort.MaxValue + 1;

        long baseline = trackingPool.OutstandingCount;

        IMemoryOwner<byte> nameStorage = trackingPool.Pool.Rent(OverWideLength);
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Tpm2bName.FromMarshaled(nameStorage, OverWideLength));

        IMemoryOwner<byte> secretStorage = trackingPool.Pool.Rent(OverWideLength);
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Tpm2bEncryptedSecret.FromMarshaled(secretStorage, OverWideLength));

        IMemoryOwner<byte> idObjectStorage = trackingPool.Pool.Rent(OverWideLength);
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Tpm2bIdObject.FromMarshaled(idObjectStorage, OverWideLength));

        IMemoryOwner<byte> privateStorage = trackingPool.Pool.Rent(OverWideLength);
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Tpm2bPrivate.FromMarshaled(privateStorage, OverWideLength));

        IMemoryOwner<byte> ticketStorage = trackingPool.Pool.Rent(OverWideLength);
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => TpmtTkVerified.FromMarshaled(TpmiRhHierarchy.Owner, ticketStorage, OverWideLength));

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Every refused adoption must return the buffer it was handed rather than orphan the rental.");
    }

    /// <summary>
    /// Adopting a <c>TPM2B_PRIVATE</c> whose declared length overruns the buffer it is handed releases that
    /// buffer before the refusal leaves — the same release-on-failure contract every adopter carries, taken here
    /// over the blob the TPM's own opaque encoding rides in (TPM 2.0 Library Part 2, clause 12.3.7, Table 227).
    /// </summary>
    [TestMethod]
    public void PrivateAdoptionOfAnOverrunningLengthReleasesTheStorage()
    {
        using var trackingPool = new MeteredHousePool();

        long baseline = trackingPool.OutstandingCount;
        IMemoryOwner<byte> storage = trackingPool.Pool.Rent(8);

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Tpm2bPrivate.FromMarshaled(storage, 9));

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A refused adoption must return the buffer it was handed rather than orphan the rental.");
    }

    /// <summary>
    /// Adopting a zero-length <c>TPM2B_ID_OBJECT</c> yields the shared empty singleton, releases the buffer it
    /// was handed, and frames the bare <c>0x0000</c> size field: the singleton owns no storage, so holding the
    /// rental behind it would leak a segment no disposal ever reaches (TPM 2.0 Library Part 2, clause 12.4.3,
    /// Table 229).
    /// </summary>
    [TestMethod]
    public void IdObjectAdoptionOfAZeroLengthValueYieldsTheEmptySingletonAndReleasesTheStorage()
    {
        using var trackingPool = new MeteredHousePool();
        byte[] expected = [0x00, 0x00];

        long baseline = trackingPool.OutstandingCount;
        IMemoryOwner<byte> storage = trackingPool.Pool.Rent(8);
        Tpm2bIdObject adopted = Tpm2bIdObject.FromMarshaled(storage, 0);

        Assert.AreSame(Tpm2bIdObject.Empty, adopted, "A zero-length adoption must yield the shared empty singleton.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The singleton owns no storage, so the adopted buffer must be returned rather than held behind it.");

        adopted.Dispose();

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the shared empty singleton must stay a no-op.");

        {
            using IMemoryOwner<byte> framing = trackingPool.Pool.Rent(Tpm2bIdObject.Empty.SerializedSize);
            var writer = new TpmWriter(framing.Memory.Span);
            Tpm2bIdObject.Empty.WriteTo(ref writer);

            Assert.AreSequenceEqual(
                expected, framing.Memory.Span[..Tpm2bIdObject.Empty.SerializedSize].ToArray(),
                "The disposed-through singleton must still frame an empty TPM2B_ID_OBJECT.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The framing rental must come back too.");
    }

    /// <summary>
    /// Adopting a zero-length <c>TPM2B_ENCRYPTED_SECRET</c> yields the shared empty singleton, releases the
    /// buffer it was handed, and frames the bare <c>0x0000</c> size field — the same dispose-immune sentinel
    /// contract the other sized carriers hold (TPM 2.0 Library Part 2, clause 11.4.3, Table 210).
    /// </summary>
    [TestMethod]
    public void EncryptedSecretAdoptionOfAZeroLengthValueYieldsTheEmptySingletonAndReleasesTheStorage()
    {
        using var trackingPool = new MeteredHousePool();
        byte[] expected = [0x00, 0x00];

        long baseline = trackingPool.OutstandingCount;
        IMemoryOwner<byte> storage = trackingPool.Pool.Rent(8);
        Tpm2bEncryptedSecret adopted = Tpm2bEncryptedSecret.FromMarshaled(storage, 0);

        Assert.AreSame(Tpm2bEncryptedSecret.Empty, adopted, "A zero-length adoption must yield the shared empty singleton.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The singleton owns no storage, so the adopted buffer must be returned rather than held behind it.");

        adopted.Dispose();

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the shared empty singleton must stay a no-op.");

        {
            using IMemoryOwner<byte> framing = trackingPool.Pool.Rent(Tpm2bEncryptedSecret.Empty.SerializedSize);
            var writer = new TpmWriter(framing.Memory.Span);
            Tpm2bEncryptedSecret.Empty.WriteTo(ref writer);

            Assert.AreSequenceEqual(
                expected, framing.Memory.Span[..Tpm2bEncryptedSecret.Empty.SerializedSize].ToArray(),
                "The disposed-through singleton must still frame an empty TPM2B_ENCRYPTED_SECRET.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The framing rental must come back too.");
    }

    /// <summary>
    /// Adopting a <c>TPM2B_NAME</c> carries exactly the declared prefix of a longer buffer and frames that
    /// prefix alone: the producer rents whatever width its own layout needs and declares how much of it is the
    /// Name, so the size field and the framed octets follow the declaration, not the rental (TPM 2.0 Library
    /// Part 2, clause 10.5.3, Table 104).
    /// </summary>
    [TestMethod]
    public void NameAdoptionCarriesOnlyTheDeclaredPrefixOfALongerBuffer()
    {
        using var trackingPool = new MeteredHousePool();
        byte[] value = [0x00, 0x0B, 0x81, 0x82];
        byte[] expected = [0x00, 0x04, 0x00, 0x0B, 0x81, 0x82];

        long baseline = trackingPool.OutstandingCount;
        {
            IMemoryOwner<byte> storage = trackingPool.Pool.Rent(32);
            value.CopyTo(storage.Memory.Span);

            using Tpm2bName adopted = Tpm2bName.FromMarshaled(storage, value.Length);
            Assert.AreEqual(value.Length, adopted.Size, "The carrier's size must be the declared prefix, not the buffer's width.");
            Assert.AreEqual(sizeof(ushort) + value.Length, adopted.SerializedSize, "The framed size must count the declared prefix only.");
            Assert.AreSequenceEqual(value, adopted.Span.ToArray(), "The carrier must expose exactly the declared prefix.");

            using IMemoryOwner<byte> framing = trackingPool.Pool.Rent(adopted.SerializedSize);
            var writer = new TpmWriter(framing.Memory.Span);
            adopted.WriteTo(ref writer);

            Assert.AreSequenceEqual(
                expected, framing.Memory.Span[..adopted.SerializedSize].ToArray(),
                "The framed Name must be the declared size followed by exactly those octets.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the carrier must return the adopted buffer.");
    }

    /// <summary>
    /// Adopting a <c>TPM2B_ENCRYPTED_SECRET</c> carries exactly the declared prefix of a longer buffer and frames
    /// that prefix alone — the seed transport's own width is whatever the credential key's algorithm produced,
    /// never the rental the producer happened to take (TPM 2.0 Library Part 2, clause 11.4.3, Table 210).
    /// </summary>
    [TestMethod]
    public void EncryptedSecretAdoptionCarriesOnlyTheDeclaredPrefixOfALongerBuffer()
    {
        using var trackingPool = new MeteredHousePool();
        byte[] value = [0x91, 0x92, 0x93, 0x94, 0x95];
        byte[] expected = [0x00, 0x05, 0x91, 0x92, 0x93, 0x94, 0x95];

        long baseline = trackingPool.OutstandingCount;
        {
            IMemoryOwner<byte> storage = trackingPool.Pool.Rent(64);
            value.CopyTo(storage.Memory.Span);

            using Tpm2bEncryptedSecret adopted = Tpm2bEncryptedSecret.FromMarshaled(storage, value.Length);
            Assert.AreEqual(value.Length, adopted.Length, "The carrier's length must be the declared prefix, not the buffer's width.");
            Assert.AreEqual(sizeof(ushort) + value.Length, adopted.SerializedSize, "The framed size must count the declared prefix only.");
            Assert.AreSequenceEqual(value, adopted.Span.ToArray(), "The carrier must expose exactly the declared prefix.");

            using IMemoryOwner<byte> framing = trackingPool.Pool.Rent(adopted.SerializedSize);
            var writer = new TpmWriter(framing.Memory.Span);
            adopted.WriteTo(ref writer);

            Assert.AreSequenceEqual(
                expected, framing.Memory.Span[..adopted.SerializedSize].ToArray(),
                "The framed secret must be the declared size followed by exactly those octets.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the carrier must return the adopted buffer.");
    }

    /// <summary>
    /// A completed <c>TPM2_GetRandom()</c> asking for zero octets frames the empty <c>TPM2B_DIGEST</c> — a bare
    /// <c>0x0000</c> size field with no buffer behind it (Table 72 types <c>randomBytes</c>, TPM 2.0 Library
    /// Part 3, clause 16.1) — and rents nothing at all: the RNG effect hands back the dispose-immune shared
    /// empty digest, whose release at the serializer is a no-op, so the sentinel stays framable afterwards. This
    /// is the sentinel counterpart of
    /// <see cref="CompletedGetRandomReturnsTheRandomBytesCarrierToPool"/>'s non-empty balance.
    /// </summary>
    [TestMethod]
    public async Task CompletedGetRandomOfZeroOctetsFramesTheEmptyDigestAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-slots-getrandom-empty").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        using var recorder = new TpmRecorder();
        using IDisposable subscription = tpm.Subscribe(recorder);
        TpmResponseRegistry registry = CreateRegistry();
        byte[] expectedParameters = [0x00, 0x00];

        long baseline = trackingPool.OutstandingCount;
        {
            var input = new GetRandomInput(0);
            TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_GetRandom(0) failed: '{result.ResponseCode}'.");

            using GetRandomResponse random = result.Value;
            Assert.IsTrue(random.RandomBytes.IsEmpty, "A zero-octet request must yield an empty randomBytes carrier.");
            Assert.AreEqual(sizeof(ushort), random.RandomBytes.SerializedSize, "An empty TPM2B_DIGEST frames as its size field alone.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The sentinel rents nothing, so a zero-octet draw must leave the pool exactly as it found it.");

        ReadOnlyMemory<byte> wire = recorder.GetExchanges()[^1].Response;
        int wireLength = wire.Length;
        Assert.AreEqual(TpmHeader.HeaderSize + sizeof(ushort), wireLength, "The response is the header plus a bare TPM2B size field.");
        Assert.AreSequenceEqual(
            expectedParameters, wire.Span[TpmHeader.HeaderSize..].ToArray(),
            "randomBytes must frame as an empty TPM2B_DIGEST on the wire.");
    }

    /// <summary>
    /// A completed <c>TPM2_ActivateCredential()</c> that recovers a zero-length credential frames the empty
    /// <c>TPM2B_DIGEST</c> <c>certInfo</c> — a bare <c>0x0000</c> size field (Table 27, TPM 2.0 Library Part 3,
    /// clause 12.5) — and rents nothing for it: the recovered value rides the dispose-immune shared empty digest,
    /// so the serializer's release of it is a no-op rather than a double return of a segment nothing owns. This
    /// is the sentinel counterpart of
    /// <see cref="CompletedActivateCredentialReturnsTheCertInfoCarrierToPool"/>'s non-empty balance.
    /// </summary>
    [TestMethod]
    public async Task CompletedActivateCredentialOfAnEmptyCredentialFramesTheEmptyCertInfoAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-slots-activatecredential-empty").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        using var recorder = new TpmRecorder();
        using IDisposable subscription = tpm.Subscribe(recorder);
        TpmResponseRegistry registry = CreateRegistry();
        byte[] expectedParameters = [0x00, 0x00];

        using CreatePrimaryResponse credentialKey = await CreateStoragePrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        using CreatePrimaryResponse activateObject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        byte[] activateName = activateObject.Name.Span.ToArray();

        using MakeCredentialResponse made = await MakeCredentialAsync(
            tpm, registry, trackingPool.Pool, credentialKey.ObjectHandle, activateName, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using ActivateCredentialInput input = ActivateCredentialInput.Create(
                activateObject.ObjectHandle, credentialKey.ObjectHandle, made.CredentialBlob.Span, made.Secret.Span, trackingPool.Pool);
            using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

            TpmResult<ActivateCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                tpm, input, [activateAuth, keyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_ActivateCredential failed: '{result.ResponseCode}'.");

            using ActivateCredentialResponse activated = result.Value;
            Assert.IsTrue(activated.CertInfo.IsEmpty, "A zero-length credential must recover as an empty certInfo carrier.");
            Assert.AreEqual(sizeof(ushort), activated.CertInfo.SerializedSize, "An empty TPM2B_DIGEST frames as its size field alone.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The sentinel rents nothing, so recovering an empty credential must leave the pool exactly as it found it.");

        ReadOnlyMemory<byte> wire = recorder.GetExchanges()[^1].Response;
        int wireLength = wire.Length;
        Assert.AreEqual(TpmHeader.HeaderSize + sizeof(ushort), wireLength, "The response is the header plus a bare TPM2B size field.");
        Assert.AreSequenceEqual(
            expectedParameters, wire.Span[TpmHeader.HeaderSize..].ToArray(),
            "certInfo must frame as an empty TPM2B_DIGEST on the wire.");

        await FlushAsync(tpm, registry, trackingPool.Pool, activateObject.ObjectHandle.Value).ConfigureAwait(false);
        await FlushAsync(tpm, registry, trackingPool.Pool, credentialKey.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>Creates a simulator with an ECC signing backend, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool every command runs against.</param>
    /// <param name="tpmId">The simulated TPM's run identifier.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string tpmId)
    {
        var simulator = new TpmSimulator(tpmId, signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

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
        result.Value.Dispose();
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);

        return simulator;
    }

    /// <summary>Creates the response codec registry covering the commands these proofs issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature);

        return registry;
    }

    /// <summary>Creates an empty-auth ECC P-256 storage parent in the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateStoragePrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an empty-auth ECC P-256 signing key in the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Seals <see cref="SealedSecret"/> beneath the given storage parent through the real wire path.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <returns>The Create response (the caller owns it).</returns>
    private async Task<CreateResponse> SealAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
        using CreateInput input = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Create (seal) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Wraps the given credential to the given credential key, bound to the supplied object Name.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The credential key whose public area wraps the seed.</param>
    /// <param name="objectName">The activate object's Name the credential is bound to.</param>
    /// <param name="credential">The credential octets to wrap; empty exercises the zero-length sentinel path.</param>
    /// <returns>The MakeCredential response (the caller owns it).</returns>
    private async Task<MakeCredentialResponse> MakeCredentialAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] objectName, ReadOnlyMemory<byte> credential)
    {
        using MakeCredentialInput input = MakeCredentialInput.Create(keyHandle, credential.Span, objectName, pool);

        TpmResult<MakeCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_MakeCredential failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Defines the empty-auth Index the NV proofs read.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DefineIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using var publicInfo = new TpmsNvPublic(NvIndexHandle, SessionAlg, IndexAttributes, Tpm2bDigest.Empty, NvDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, Tpm2bAuth.Empty, publicInfo);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace failed: '{result.ResponseCode}'.");
    }

    /// <summary>Fills the defined Index's data area with <see cref="NvWriteData"/>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task WriteIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using Tpm2bMaxNvBuffer inputBuffer = Tpm2bMaxNvBuffer.Create(NvWriteData, pool);
        var input = new NvWriteInput(NvIndexHandle, NvIndexHandle, inputBuffer, Offset: 0);
        using TpmPasswordSession writeAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, input, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Write failed: '{result.ResponseCode}'.");
    }

    /// <summary>Flushes a transient object or session handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        var input = FlushContextInput.ForHandle(handle);
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_FlushContext failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Re-parses a public area into a fresh carrier, so a loaded object's <c>inPublic</c> is an independent
    /// instance rather than an alias of the response the seal step still owns.
    /// </summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool backing the clone.</param>
    /// <returns>The cloned public area (the caller owns it).</returns>
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
    /// Concatenates an ECDSA signature's r and s components into the fixed-width IEEE P1363 form the verify
    /// path takes.
    /// </summary>
    /// <param name="r">The r component.</param>
    /// <param name="s">The s component.</param>
    /// <param name="pool">The memory pool backing the returned signature.</param>
    /// <returns>The P1363 signature (the caller owns it).</returns>
    private static Signature ConcatenateP1363(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s, BaseMemoryPool pool)
    {
        const int P256ComponentSize = 32;
        IMemoryOwner<byte> owner = pool.Rent(2 * P256ComponentSize);
        Span<byte> destination = owner.Memory.Span[..(2 * P256ComponentSize)];
        destination.Clear();
        CopyFixed(r, destination[..P256ComponentSize]);
        CopyFixed(s, destination.Slice(P256ComponentSize, P256ComponentSize));

        return new Signature(owner, CryptoTags.P256Signature);

        //Copies a component right-aligned into the fixed field width, truncating leading octets when over-long.
        static void CopyFixed(ReadOnlySpan<byte> value, Span<byte> destination)
        {
            if(value.Length <= destination.Length)
            {
                value.CopyTo(destination[^value.Length..]);
            }
            else
            {
                value[^destination.Length..].CopyTo(destination);
            }
        }
    }
}
