using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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
/// Acceptance tests for TPM2_Sign against the TCG ms-tpm-20-ref software TPM simulator, covering every
/// signature scheme the command supports: ECDSA, RSASSA, and RSAPSS.
/// </summary>
/// <remarks>
/// <para>
/// Each test creates a primary signing key, signs an externally-computed digest through the production
/// command path (<see cref="SignInput"/> / <see cref="SignResponse"/> / <see cref="TpmuSignature"/>), then
/// verifies the signature <b>off-TPM</b> against a public key reconstructed solely from the TPM's exported
/// public area (<c>TPM2_CreatePrimary</c> <c>outPublic</c>). The verifier shares no in-memory state with the
/// signer beyond the wire bytes, so a divergence between what the host serialized and what a genuine TPM
/// signed fails here rather than only against hardware.
/// </para>
/// <para>
/// The tests are gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); they
/// report <see cref="Assert.Inconclusive(string)"/> when none is reachable, so they are safe in any run.
/// </para>
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorSignTests
{
    /// <summary>
    /// The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.
    /// </summary>
    private const int P256ComponentSize = 32;

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
    /// The fixed message whose SHA-256 digest is signed in every test.
    /// </summary>
    private static byte[] MessageBytes { get; } = "Verifiable TPM signing acceptance test."u8.ToArray();

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
    public async Task EcdsaP256SignVerifiesAgainstSimulator()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        try
        {
            byte[] digest = SHA256.HashData(MessageBytes);

            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(primary.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (ECDSA) failed: '{signResult.ResponseCode}'.");

            using SignResponse signature = signResult.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, signature.SignatureAlgorithm);
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);
            Assert.IsNotNull(signature.Signature.SignatureR);
            Assert.IsNotNull(signature.Signature.SignatureS);

            //Firewalled verify: reconstruct the public key from the TPM's exported public area only.
            TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;
            var ecParameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                    Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
                }
            };

            //.NET's VerifyHash expects the raw IEEE P1363 r || s concatenation, each component fixed-width.
            byte[] p1363Signature = new byte[2 * P256ComponentSize];
            ToFixed(signature.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
            ToFixed(signature.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

            using ECDsa ecdsa = ECDsa.Create(ecParameters);
            Assert.IsTrue(
                ecdsa.VerifyHash(digest, p1363Signature),
                "An ECDSA signature produced by the simulator must verify against its exported public key.");
        }
        finally
        {
            await FlushAsync(tpm, registry, primary.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task RsaSignVerifiesAgainstSimulator()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        //A NULL scheme makes this an unrestricted signing key, so the scheme (RSASSA or RSAPSS) is chosen per
        //TPM2_Sign call. This exercises both RSA schemes against one (expensive) RSA key generation.
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER,
            password: null,
            keyBits: 2048,
            TpmtRsaScheme.Null,
            pool,
            noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (RSA 2048) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        try
        {
            //Reconstruct the verifier's RSA public key from the exported modulus. A TPM template with a zero
            //exponent uses the default F4 (65537), which the TPM reports as a zero-length exponent.
            byte[] modulus = primary.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
            var rsaParameters = new RSAParameters { Modulus = modulus, Exponent = [0x01, 0x00, 0x01] };
            byte[] digest = SHA256.HashData(MessageBytes);

            await SignAndVerifyRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, rsaParameters, usePss: false).ConfigureAwait(false);
            await SignAndVerifyRsaAsync(tpm, registry, pool, primary.ObjectHandle, digest, rsaParameters, usePss: true).ConfigureAwait(false);
        }
        finally
        {
            await FlushAsync(tpm, registry, primary.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "The PrivateKey takes ownership of the handle memory and is disposed by its using declaration.")]
    public async Task TpmBackedPrivateKeySignsAndVerifiesThroughTheVerifiableAbstraction()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        try
        {
            //Surface the TPM key as a first-class Verifiable signing key: the private-key memory carries only
            //the handle, and the TPM signing function is bound as the SigningDelegate. The TpmDevice and scheme
            //travel through the per-call context, not a closure. The PrivateKey owns the handle memory.
            using var privateKey = new PrivateKey(
                TpmCryptographicFunctions.CreateHandleKeyMemory(primary.ObjectHandle.Value, CryptoTags.P256PrivateKey, pool),
                "tpm-p256",
                TpmCryptographicFunctions.SignAsync,
                TpmCryptographicFunctions.CreateP256SigningContext(tpm));

            using Signature signature = await privateKey.SignAsync(MessageBytes, pool).ConfigureAwait(false);

            //Verify with the registry's software P-256 verifier, from a public key reconstructed solely from the
            //TPM's exported public area (compressed SEC1 point, as the verifier requires).
            byte[] compressedPublicKey = BuildCompressedPublicKey(primary.OutPublic.PublicArea.Unique.Ecc!, P256ComponentSize);

            VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
                CryptoAlgorithm.P256, Purpose.Verification);

            bool verified = await verify(MessageBytes, signature.AsReadOnlyMemory(), compressedPublicKey, null, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(verified, "A signature produced by a TPM-backed PrivateKey must verify through the library's P-256 verifier.");
        }
        finally
        {
            await FlushAsync(tpm, registry, primary.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Signs <paramref name="digest"/> with the given RSA scheme and verifies the result off-TPM against
    /// <paramref name="rsaParameters"/>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The handle of the loaded RSA signing key.</param>
    /// <param name="digest">The pre-computed SHA-256 digest to sign.</param>
    /// <param name="rsaParameters">The public key reconstructed from the TPM's exported modulus.</param>
    /// <param name="usePss">When <see langword="true"/>, signs and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task SignAndVerifyRsaAsync(
        TpmDevice tpm,
        TpmResponseRegistry registry,
        MemoryPool<byte> pool,
        TpmiDhObject keyHandle,
        byte[] digest,
        RSAParameters rsaParameters,
        bool usePss)
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
        Assert.AreEqual(usePss ? TpmAlgIdConstants.TPM_ALG_RSAPSS : TpmAlgIdConstants.TPM_ALG_RSASSA, signature.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, signature.HashAlgorithm);
        Assert.IsFalse(signature.Signature.RsaSignature.IsEmpty, $"The {schemeName} signature buffer must not be empty.");

        byte[] signatureBytes = signature.Signature.RsaSignature.Buffer.ToArray();
        RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(digest, signatureBytes, HashAlgorithmName.SHA256, padding),
            $"An {schemeName} signature produced by the simulator must verify against its exported public key.");
    }

    /// <summary>
    /// Creates a response codec registry covering the commands these tests issue.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
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
    /// Builds the compressed SEC1 public-key encoding the library's ECDSA verifier expects, from a TPM ECC
    /// point, via <see cref="EllipticCurveUtilities.Compress"/>. Kept synchronous so the stack coordinate
    /// buffers never span an await.
    /// </summary>
    /// <param name="point">The TPM-exported public point.</param>
    /// <param name="componentSize">The curve coordinate size in bytes.</param>
    /// <returns>The compressed point.</returns>
    private static byte[] BuildCompressedPublicKey(TpmsEccPoint point, int componentSize)
    {
        Span<byte> x = stackalloc byte[componentSize];
        Span<byte> y = stackalloc byte[componentSize];
        LeftPadInto(point.X.AsReadOnlySpan(), x);
        LeftPadInto(point.Y.AsReadOnlySpan(), y);

        return EllipticCurveUtilities.Compress(x, y);
    }

    /// <summary>
    /// Left-pads a big-endian value into a fixed-width destination, zero-filling the leading bytes.
    /// </summary>
    /// <param name="value">The big-endian value (the TPM may omit leading zero bytes).</param>
    /// <param name="destination">The fixed-width destination span.</param>
    private static void LeftPadInto(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        destination.Clear();
        value.CopyTo(destination[(destination.Length - value.Length)..]);
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
