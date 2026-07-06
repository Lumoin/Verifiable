using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
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
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_CreatePrimary()</c> across nameAlg values against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with a caller-chosen-nameAlg
/// <see cref="CreatePrimaryInput"/> and the real response codec).
/// </summary>
/// <remarks>
/// <para>
/// Each case builds an ECC signing-key template with a caller-chosen nameAlg directly
/// (<see cref="Tpm2bPublic.CreateEccSigningTemplate"/>), bypassing <see cref="CreatePrimaryInput.ForEccSigningKey"/>
/// (which hardcodes SHA-256), and recomputes the object Name <b>off-TPM</b> from the wire-exported public area
/// through the registered digest seam (TPM 2.0 Library Part 1, clause 16) — firewalled: the verifier never calls
/// into the production <c>TpmObjectName</c> helper, only an independent recomputation, matching the sibling
/// Certify/Sign/Quote tests' oracle style.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorNameAlgTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA256, 32)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA384, 48)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA512, 64)]
    public async Task CreatePrimaryRecomputesNameForEachSupportedNameAlg(TpmAlgIdConstants nameAlg, int digestSize)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreatePrimaryWithNameAlgAsync(tpm, registry, pool, nameAlg).ConfigureAwait(false);

        //name = nameAlg || H_nameAlg(TPMT_PUBLIC) (TPM 2.0 Library Part 1, clause 16), recomputed independently
        //from the wire-exported public area, off-TPM, through the registered digest seam — proving the digest
        //itself is agile, not always a SHA-256 digest under a relabeled prefix.
        byte[] marshaledPublic = MarshalPublicArea(primary.OutPublic, pool);
        byte[] expectedDigest = await ComputeDigestAsync(marshaledPublic, nameAlg, digestSize, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((ushort)nameAlg, primary.Name.NameAlgorithm, "The Name must carry the requested nameAlg.");
        Assert.AreEqual(digestSize, primary.Name.Digest.Length, "The Name digest width must match the requested nameAlg, not a fixed SHA-256 width.");
        Assert.IsTrue(
            expectedDigest.AsSpan().SequenceEqual(primary.Name.Digest),
            "The Name digest must be H_nameAlg(TPMT_PUBLIC) for the requested nameAlg, not always a SHA-256 digest.");
    }

    [TestMethod]
    public async Task CreatePrimaryWithSha1NameAlgSucceeds()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //SHA-1 is still a profile-listed object nameAlg value (TPM 2.0 Library Part 1, clause 16), and this model
        //computes it, so creation succeeds. No deep off-TPM matrix here — the shared nameAlg-agile digest routing
        //is already exercised by the SHA-256/384/512 matrix above.
        using CreatePrimaryResponse primary = await CreatePrimaryWithNameAlgAsync(tpm, registry, pool, TpmAlgIdConstants.TPM_ALG_SHA1).ConfigureAwait(false);

        Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_SHA1, primary.Name.NameAlgorithm);
        Assert.AreEqual(20, primary.Name.Digest.Length, "A SHA-1 Name digest is 20 octets.");
    }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of inPublic and the sensitive-create buffer transfers to input, which is disposed by its using declaration.")]
    public async Task CreatePrimaryWithUnsupportedNameAlgReturnsHash()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //TPM_ALG_NULL is a syntactically valid TPMI_ALG_HASH value on the wire but names no hash function this
        //model can compute, so it must fail closed with TPM_RC_HASH rather than silently default to SHA-256
        //(TPM 2.0 Library Part 3, CreatePrimary error conditions).
        TpmaObject objectAttributes =
            TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN | TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_NULL, objectAttributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        using CreatePrimaryInput input = new(
            TpmRh.TPM_RH_OWNER, Tpm2bSensitiveCreate.CreateEmpty(pool), inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, result.ResponseCode);
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the owner hierarchy with a caller-chosen nameAlg, built
    /// directly from <see cref="Tpm2bPublic.CreateEccSigningTemplate"/> rather than the SHA-256-only
    /// <see cref="CreatePrimaryInput.ForEccSigningKey"/> convenience factory, and returns the response (the
    /// caller owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nameAlg">The Name algorithm to request in the template.</param>
    /// <returns>The CreatePrimary response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of inPublic and the sensitive-create buffer transfers to input, which is disposed by its using declaration.")]
    private async Task<CreatePrimaryResponse> CreatePrimaryWithNameAlgAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmAlgIdConstants nameAlg)
    {
        TpmaObject objectAttributes =
            TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN | TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA;

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            nameAlg, objectAttributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));

        using CreatePrimaryInput input = new(
            TpmRh.TPM_RH_OWNER, Tpm2bSensitiveCreate.CreateEmpty(pool), inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, nameAlg={nameAlg}) failed: '{result.ResponseCode}'.");

        return result.Value;
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
    /// Computes a digest through the registered digest seam (not a direct framework hash), for one of the
    /// nameAlg values this model supports.
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="nameAlg">The Name algorithm selecting the hash function.</param>
    /// <param name="digestSize">The expected digest width in octets.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The digest.</returns>
    private static async Task<byte[]> ComputeDigestAsync(ReadOnlyMemory<byte> message, TpmAlgIdConstants nameAlg, int digestSize, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        Tag tag = nameAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA1 => Tag.Create(HashAlgorithmName.SHA1),
            TpmAlgIdConstants.TPM_ALG_SHA256 => Tag.Create(HashAlgorithmName.SHA256),
            TpmAlgIdConstants.TPM_ALG_SHA384 => Tag.Create(HashAlgorithmName.SHA384),
            TpmAlgIdConstants.TPM_ALG_SHA512 => Tag.Create(HashAlgorithmName.SHA512),
            _ => throw new NotSupportedException($"Test oracle does not support nameAlg '{nameAlg}'.")
        };
        tag = tag.With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message), digestSize, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-namealg", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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

        return registry;
    }
}
