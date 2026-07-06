using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.X509;
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
/// Exemplifies the attestation-key (AK) certificate profile against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="CreatePrimaryInput"/>, <see cref="QuoteInput"/>, and response codecs): a restricted signing key
/// created under the endorsement hierarchy (TPM 2.0 Library Part 1, clause 25.1: an AK's <c>sign</c> attribute is
/// SET, unlike the EK's restricted-decrypt role) stands in for the AK, is certified by a test manufacturer CA over
/// its wire-exported public key, and then quotes through <c>TPM2_Quote()</c>. The verifier side never touches the
/// AK's in-memory key: it validates the certificate chain to the CA and verifies the quote signature against the
/// public key extracted from the certificate itself — wire bytes and certificate only, the same firewalled
/// discipline <see cref="TpmInHouseSimulatorEndorsementTrustTests"/> and <see cref="TpmInHouseSimulatorQuoteTests"/>
/// use.
/// </summary>
/// <remarks>
/// <para>
/// The AK certificate's shape mirrors the EK certificate's (<see cref="TpmInHouseSimulatorEndorsementTrustTests"/>):
/// a CN subject, <c>BasicConstraints CA=false</c> (critical), a Subject Key Identifier, and an Authority Key
/// Identifier chained to the manufacturer CA's own Subject Key Identifier (the repo's cross-platform
/// chain-validation rule — non-Windows, OpenSSL-based validators need the AKI to disambiguate the issuer). Key
/// Usage differs: an AK signs, so its Key Usage is <c>digitalSignature</c> only, never the EK's
/// <c>keyEncipherment</c>/<c>keyAgreement</c>.
/// </para>
/// <para>
/// Extended Key Usage is deliberately omitted. The TCG EK Credential Profile for TPM Family 2.0 defines only the
/// <c>tcg-kp-EKCertificate</c> key-purpose OID (its §4 TCG OID namespace: <c>{tcg-kp 1}</c> = 2.23.133.8.1) — that
/// OID explicitly identifies an EK certificate and reusing it here would misrepresent this as an EK certificate.
/// The TCG TPM 2.0 Provisioning Guidance document discusses the Attestation Identity Key (AIK) by name but defines
/// no certificate profile or key-purpose OID for it. No document among this repository's referenced TPM
/// specifications supplies an AK/AIK certificate key-purpose OID, so none is asserted; see the comment at the
/// Extended Key Usage step in <see cref="IssueAkCertificate"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorAkCertificateTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The PCR bank the quote selects from.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The single PCR the quote covers; PCR binding itself is out of scope for this file (covered by <see cref="TpmInHouseSimulatorQuoteTests"/>).</summary>
    private static int[] PcrIndices { get; } = [0];

    /// <summary>The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.</summary>
    private static byte[] Nonce { get; } = "AK certificate nonce for the in-house TPM."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies the full AK-certificate flow end to end: <c>TPM2_CreatePrimary()</c> mints a restricted ECC P-256
    /// signing key (the AK) under the endorsement hierarchy; a test manufacturer CA certifies its wire-exported
    /// public key; the AK quotes through <c>TPM2_Quote()</c> (TPM 2.0 Library Part 3, clause 18.4). The verifier
    /// then (a) validates the AK certificate chain to the manufacturer CA through the shared
    /// <see cref="MicrosoftX509Functions.ValidateChainAsync"/> seam and (b) verifies the quote signature using the
    /// public key extracted from the certificate (<see cref="X509Certificate2.GetECDsaPublicKey()"/>), never from
    /// the in-memory AK key — wire bytes and certificate only.
    /// </summary>
    [TestMethod]
    public async Task AkCertificateChainsAndVerifiesAttestation()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        TimeProvider time = TimeProvider.System;

        using CreatePrimaryResponse ak = await CreateAkPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            //Reconstruct the AK public key from the TPM's exported public area only, then mint an X.509 leaf
            //certificate over it signed by a test manufacturer CA. The certificate and the quote below both derive
            //independently from the same wire-exported public area — no shared in-memory state crosses to the
            //verifier beyond that.
            ECParameters akParameters = ExportAkPublicParameters(ak);
            using ECDsa akPublicKey = ECDsa.Create(akParameters);

            using X509ChainTestRingNode manufacturerCa = X509ChainTestRing.CreateRootCa(time, "TPM Vendor Test AK Root CA");
            using X509Certificate2 akCertificate = IssueAkCertificate(manufacturerCa, akPublicKey, time);

            using QuoteResponse quote = await QuoteAsync(tpm, registry, pool, ak.ObjectHandle).ConfigureAwait(false);

            //1. Attestation envelope: TPM-generated marker, quote type, and the nonce echoed verbatim.
            TpmsAttest attest = quote.Quoted.AttestationData;
            Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
            Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_QUOTE, attest.Type);
            Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");

            //2. Chain of trust: the AK certificate must validate to the manufacturer CA through the shared chain
            //seam (the same MicrosoftX509Functions.ValidateChainAsync the EK certificate trust check uses), which
            //builds an X509Chain with the CA as the sole custom trust anchor.
            using PkiCertificateMemory akCertMemory = ToPkiCertificate(akCertificate.RawData, pool);
            using PkiCertificateMemory caCertMemory = ToPkiCertificate(manufacturerCa.Certificate.RawData, pool);

            using PublicKeyMemory validatedLeafKey = await MicrosoftX509Functions.ValidateChainAsync(
                [akCertMemory], [caCertMemory], time.GetUtcNow(), pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(validatedLeafKey.AsReadOnlySpan().IsEmpty, "Validation must yield the certified AK public key.");

            //3. Signature: over the RAW attestation bytes, verified against the public key extracted from the
            //ISSUED CERTIFICATE — not the in-memory key used to mint it, and not the TPM's exported public area
            //directly — firewalled from any backchannel key sharing.
            byte[] attestDigest = await ComputeSha256Async(quote.Quoted.GetRawBytes().ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);

            byte[] p1363Signature = new byte[2 * P256ComponentSize];
            ToFixed(quote.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
            ToFixed(quote.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

            using ECDsa? certifiedPublicKey = akCertificate.GetECDsaPublicKey();
            Assert.IsNotNull(certifiedPublicKey, "The AK certificate must carry an extractable ECDSA public key.");
            Assert.IsTrue(
                certifiedPublicKey!.VerifyHash(attestDigest, p1363Signature),
                "The quote signature must verify against the public key extracted from the AK certificate.");
        }
        finally
        {
            await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that an AK certificate issued by one CA is rejected when validated against a different, unrelated
    /// CA: the certificate must not chain to a CA it was not minted under (mirroring
    /// <see cref="TpmInHouseSimulatorEndorsementTrustTests.EndorsementKeyCertificateFromUntrustedCaIsRejected"/>).
    /// </summary>
    [TestMethod]
    public async Task AkCertificateFromUntrustedCaFailsChainValidation()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        TimeProvider time = TimeProvider.System;

        using CreatePrimaryResponse ak = await CreateAkPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
        try
        {
            ECParameters akParameters = ExportAkPublicParameters(ak);
            using ECDsa akPublicKey = ECDsa.Create(akParameters);

            //The AK certificate is issued by one CA, but validation is attempted against a different, unrelated CA.
            using X509ChainTestRingNode issuingCa = X509ChainTestRing.CreateRootCa(time, "TPM Vendor Test AK Root CA");
            using X509ChainTestRingNode unrelatedCa = X509ChainTestRing.CreateRootCa(time, "Unrelated Root CA");
            using X509Certificate2 akCertificate = IssueAkCertificate(issuingCa, akPublicKey, time);

            using PkiCertificateMemory akCertMemory = ToPkiCertificate(akCertificate.RawData, pool);
            using PkiCertificateMemory unrelatedCaMemory = ToPkiCertificate(unrelatedCa.Certificate.RawData, pool);

            bool rejected = false;
            try
            {
                using PublicKeyMemory _ = await MicrosoftX509Functions.ValidateChainAsync(
                    [akCertMemory], [unrelatedCaMemory], time.GetUtcNow(), pool, TestContext.CancellationToken).ConfigureAwait(false);
            }
            catch(System.Security.SecurityException)
            {
                rejected = true;
            }

            Assert.IsTrue(rejected, "An AK certificate that does not chain to the trusted CA must be rejected.");
        }
        finally
        {
            await FlushAsync(tpm, registry, ak.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Reconstructs the AK public key as <see cref="ECParameters"/> from the TPM's exported public area, with the
    /// coordinates left-padded to the fixed P-256 width.
    /// </summary>
    /// <param name="ak">The CreatePrimary response for the attestation key.</param>
    /// <returns>The public EC parameters.</returns>
    private static ECParameters ExportAkPublicParameters(CreatePrimaryResponse ak)
    {
        TpmsEccPoint point = ak.OutPublic.PublicArea.Unique.Ecc!;

        return new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };
    }

    /// <summary>
    /// Issues an end-entity AK certificate over <paramref name="akPublicKey"/>, signed by the manufacturer CA.
    /// </summary>
    /// <param name="manufacturerCa">The CA node standing in for the TPM vendor.</param>
    /// <param name="akPublicKey">The TPM's AK public key (public-only).</param>
    /// <param name="time">The time provider for validity bounds.</param>
    /// <returns>The issued AK certificate (public-only).</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned certificate transfers to the caller's using declaration.")]
    private static X509Certificate2 IssueAkCertificate(X509ChainTestRingNode manufacturerCa, ECDsa akPublicKey, TimeProvider time)
    {
        DateTimeOffset now = time.GetUtcNow();
        var request = new CertificateRequest("CN=TPM AK, O=Verifiable Test Infrastructure", akPublicKey, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));

        //An AK is a restricted SIGNING key (TPM 2.0 Library Part 1, clause 25.1: the sign attribute is SET) —
        //digitalSignature only, unlike the EK's restricted-decrypt keyEncipherment/keyAgreement.
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

        //Subject Key Identifier for this AK certificate itself (non-critical).
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, X509SubjectKeyIdentifierHashAlgorithm.Sha256, critical: false));

        //Extended Key Usage: deliberately OMITTED. The TCG EK Credential Profile for TPM Family 2.0 defines only
        //the tcg-kp-EKCertificate key-purpose OID (its TCG OID namespace clause: {tcg-kp 1} = 2.23.133.8.1),
        //explicitly scoped to identifying an EK certificate — reusing it here would misrepresent this as an EK
        //certificate. The TCG TPM 2.0 Provisioning Guidance document discusses the Attestation Identity Key (AIK)
        //by name but defines no certificate profile or key-purpose OID for it. No document among this
        //repository's referenced TPM specifications supplies an AK/AIK certificate key-purpose OID, so none is
        //asserted here rather than inventing one.

        //Authority Key Identifier (non-critical), matching the manufacturer CA's own Subject Key Identifier —
        //same cross-platform chain-resolution requirement as the EK certificate.
        X509SubjectKeyIdentifierExtension? issuerSubjectKeyId = X509ChainTestRing.FindSubjectKeyIdentifier(manufacturerCa.Certificate);
        if(issuerSubjectKeyId is not null)
        {
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerSubjectKeyId));
        }

        byte[] serialNumber = RandomNumberGenerator.GetBytes(8);
        using X509Certificate2 caWithKey = manufacturerCa.Certificate.CopyWithPrivateKey(manufacturerCa.SigningKey);

        return request.Create(
            caWithKey,
            notBefore: now.AddDays(-1).UtcDateTime,
            notAfter: now.AddYears(2).UtcDateTime,
            serialNumber: serialNumber);
    }

    /// <summary>
    /// Wraps DER certificate bytes in a pooled <see cref="PkiCertificateMemory"/>.
    /// </summary>
    /// <param name="der">The DER-encoded certificate.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The pooled certificate (the caller owns it).</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PkiCertificateMemory transfers to the caller.")]
    private static PkiCertificateMemory ToPkiCertificate(byte[] der, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy — the AK — and returns the response (the
    /// caller owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateAkPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 AK, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Quotes the fixed PCR selection over the fixed nonce with the given signing key and returns the response
    /// (the caller owns it). A quote is public, so it carries an empty-auth password session.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="signHandle">The signing (attestation) key handle.</param>
    /// <returns>The Quote response.</returns>
    private async Task<QuoteResponse> QuoteAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmiDhObject signHandle)
    {
        using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using QuoteInput quoteInput = QuoteInput.ForEcdsa(signHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

        TpmResult<QuoteResponse> quoteResult = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
            tpm, quoteInput, [keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(quoteResult.IsSuccess, $"TPM2_Quote failed: '{quoteResult.ResponseCode}'.");

        return quoteResult.Value;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The ECC backend is required so the simulator
    /// services <c>TPM2_CreatePrimary()</c> for the AK and signs the <c>TPM2_Quote()</c> attestation.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-ak-certificate", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Flushes a transient object handle, ignoring the result.
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
    /// Left-pads a big-endian value to a fixed width, as the ECParameters coordinate and IEEE P1363 signature
    /// encodings require. The simulator returns TPM2B integers that may omit leading zero bytes.
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
