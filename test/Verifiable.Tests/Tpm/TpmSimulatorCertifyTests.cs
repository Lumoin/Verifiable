using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.TestInfrastructure.TpmSimulator;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance test for TPM2_Certify (object attestation) against the TCG ms-tpm-20-ref software TPM simulator.
/// </summary>
/// <remarks>
/// <para>
/// The test creates a subject signing key (under the owner hierarchy) and a separate attestation key (AK, under
/// the endorsement hierarchy, so the two are genuinely distinct keys), then has the AK certify the subject over a
/// caller nonce through the production command path
/// (<see cref="CertifyInput"/> / <see cref="CertifyResponse"/> / <see cref="Tpm2bAttest"/>). It verifies the
/// result <b>off-TPM</b> from wire bytes only: the magic / type / nonce fields, that the attested Name equals the
/// subject's Name recomputed independently from its exported public area (<c>nameAlg || H(TPMT_PUBLIC)</c>), and
/// the ECDSA signature over the raw attestation bytes against the AK's exported public key. The verifier shares
/// no in-memory state with the signer beyond wire bytes.
/// </para>
/// <para>
/// TPM2_Certify authorizes two handles — the certified object (ADMIN role) and the signing key (USER role) — so
/// the executor receives two authorization sessions in handle order. ADMIN-role authorization of the object with
/// its authValue works because the signing-key template leaves <c>adminWithPolicy</c> clear.
/// </para>
/// <para>
/// The test is gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); it
/// reports <see cref="Assert.Inconclusive(string)"/> when none is reachable, so it is safe in any run.
/// </para>
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorCertifyTests
{
    /// <summary>
    /// The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.
    /// </summary>
    private const int P256ComponentSize = 32;

    /// <summary>
    /// The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.
    /// </summary>
    private static byte[] Nonce { get; } =
    [
        0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x79, 0x20, 0x6E, 0x6F, 0x6E, 0x63, 0x65, 0x20, 0x66, 0x6F,
        0x72, 0x20, 0x54, 0x50, 0x4D, 0x32, 0x5F, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x79, 0x2E, 0x2E
    ];

    /// <summary>
    /// The connection to the simulator, established once for the class.
    /// </summary>
    private static MsTpmSimulatorConnection? Connection { get; set; }

    /// <summary>
    /// The TPM device created over the simulator connection.
    /// </summary>
    private static TpmDevice? Tpm { get; set; }

    /// <summary>
    /// Whether a simulator was reachable at class initialization.
    /// </summary>
    private static bool HasSimulator { get; set; }

    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Connects to the simulator (if one is reachable) and brings up a TPM device for the class.
    /// </summary>
    /// <param name="context">The class-level test context.</param>
    [ClassInitialize]
    public static async Task ClassInit(TestContext context)
    {
        if(!MsTpmSimulatorConnection.IsAvailable("localhost", MsTpmSimulatorConnection.DefaultCommandPort, TimeSpan.FromSeconds(1)))
        {
            return;
        }

        Connection = await MsTpmSimulatorConnection.ConnectAsync(
            "localhost", MsTpmSimulatorConnection.DefaultCommandPort, context.CancellationToken).ConfigureAwait(false);
        Tpm = TpmDevice.Create(Connection.SubmitAsync);
        HasSimulator = true;
    }

    /// <summary>
    /// Releases the TPM device and simulator connection.
    /// </summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Tpm?.Dispose();
        Connection?.Dispose();
    }

    /// <summary>
    /// Skips the test when no simulator is reachable.
    /// </summary>
    [TestInitialize]
    public void TestInit()
    {
        if(!HasSimulator)
        {
            Assert.Inconclusive("No TPM simulator is reachable on localhost:2321/2322. Start the container from TestInfrastructure/TpmSimulator/Dockerfile.");
        }
    }

    [TestMethod]
    public async Task EcdsaP256CertifyVerifiesAgainstSimulator()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        //The subject (certified) key under the owner hierarchy and the AK (signer) under the endorsement
        //hierarchy: distinct hierarchy seeds give genuinely distinct keys, so this is a real cross-key
        //certification rather than a self-certify.
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
            try
            {
                //Certify the subject with the AK. objectHandle (ADMIN) auth first, signHandle (USER) auth second;
                //both empty-auth password sessions (an attestation carries no secret, so no HMAC/encrypt session).
                using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                    subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

                TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                    tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(certifyResult.IsSuccess, $"TPM2_Certify failed: '{certifyResult.ResponseCode}'.");

                using CertifyResponse certify = certifyResult.Value;
                Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, certify.SignatureAlgorithm);
                Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, certify.HashAlgorithm);

                //1. Attestation envelope: TPM-generated marker, certify type, and the nonce echoed verbatim.
                TpmsAttest attest = certify.CertifyInfo.AttestationData;
                Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
                Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_CERTIFY, attest.Type);
                Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
                Assert.IsNotNull(attest.Attested.Certify);

                //2. Name binding: the attested Name must equal the subject's Name recomputed independently from its
                //exported public area (nameAlg || H(TPMT_PUBLIC)) — firewalled, not taken from the TPM's own
                //CreatePrimary name field.
                byte[] expectedName = ComputeObjectName(subject.OutPublic);
                Assert.IsTrue(
                    attest.Attested.Certify!.Name.Span.SequenceEqual(expectedName),
                    "The certified Name must equal the subject's Name recomputed from its exported public area.");

                //Cross-check: the recomputation matches the Name the TPM returned for the subject at creation.
                Assert.IsTrue(expectedName.AsSpan().SequenceEqual(subject.Name.Span),
                    "The independently recomputed Name must match the TPM-reported subject Name.");

                //3. Signature: over the RAW attestation bytes, against the AK public key reconstructed from the
                //TPM's exported public area only.
                byte[] attestDigest = SHA256.HashData(certify.CertifyInfo.GetRawBytes());

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
                ToFixed(certify.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
                ToFixed(certify.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

                using ECDsa ecdsa = ECDsa.Create(ecParameters);
                Assert.IsTrue(
                    ecdsa.VerifyHash(attestDigest, p1363Signature),
                    "The certify signature must verify over the raw attestation bytes against the AK's exported public key.");
            }
            finally
            {
                await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, subject.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy and returns the response (the caller
    /// owns it and flushes <see cref="CreatePrimaryResponse.ObjectHandle"/>).
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
    /// Recomputes a loaded object's Name from its exported public area: <c>nameAlg || H_nameAlg(TPMT_PUBLIC)</c>
    /// (TPM 2.0 Library Part 1, Section 16). The test keys use a SHA-256 nameAlg.
    /// </summary>
    /// <param name="outPublic">The object's exported public area.</param>
    /// <returns>The recomputed Name (2-byte nameAlg prefix + digest).</returns>
    private static byte[] ComputeObjectName(Tpm2bPublic outPublic)
    {
        TpmAlgIdConstants nameAlg = outPublic.PublicArea.NameAlg;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, nameAlg, "This test assumes a SHA-256 nameAlg.");

        byte[] digest = SHA256.HashData(outPublic.GetRawBytes());
        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Creates a response codec registry covering the commands this test issues.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Flushes a transient object or session handle, ignoring the result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="handle">The handle to flush.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle, MemoryPool<byte> pool)
    {
        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 / ECPoint encodings require. The TPM
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
            //Defensive: drop any leading zero padding the TPM may have included.
            value[^length..].CopyTo(result);
        }

        return result;
    }
}
