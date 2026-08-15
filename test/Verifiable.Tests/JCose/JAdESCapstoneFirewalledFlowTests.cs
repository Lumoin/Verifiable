using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.JCose;

/// <summary>
/// The firewalled capstone for JAdES: a signing party mints a B-B signature carrying an abbreviated <c>cSig</c>
/// countersignature and raises it through B-T, B-LT and B-LTA entirely through the shipped
/// <see cref="JAdESSignatureCreation"/>/<see cref="JAdESSignatureAugmentation"/>/<see cref="JAdESCounterSign"/>
/// surfaces, emits nothing but wire octets, and a verifying party that never saw the signing party's objects
/// reconstructs every input from those octets alone and runs the shipped JAdES binding
/// (<see cref="JAdESSignatureFacts"/>) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> clause 5.3 (the validation process for Basic Signatures) to a real
/// <c>TOTAL-PASSED</c>, mirroring <c>CBAdESCapstoneFirewalledFlowTests</c>'s own shape one document removed.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Basic Signatures, not Long Term Availability (a deliberate, disclosed scope cut, mirroring the
/// CB-AdES capstone's identical posture).</strong> <see cref="JAdESSignatureFacts"/> does not wire
/// <c>StateTimestampCoverage</c>/<c>StateTimestampProtectsObject</c> (see that binding's own remarks on decoding
/// <c>sigTst</c>/<c>arcTst</c> tokens' raw bytes only, never opening/verifying their RFC 3161 content), so the
/// proof-of-existence extraction the <c>LongTermAvailability</c> process (clause 5.6.3) needs is not reachable
/// from this binding. The lifecycle is still minted all the way through B-LTA with a genuine countersignature —
/// proving the shipped creation/augmentation/countersign surfaces compose correctly end to end — but the EN 319
/// 102-1 CONCLUSION asserted below is the Basic Signatures process's own <c>TOTAL-PASSED</c>/<c>TOTAL-FAILED</c>/
/// <c>INDETERMINATE</c>, reached from the resulting B-LTA signature's current-time certificate-chain validity
/// alone, not from any archive-time-stamp-derived proof of existence.
/// </para>
/// <para>
/// <strong>The firewall.</strong> <see cref="MintCapstoneWorldAsync"/> builds the Root CA, the Time-Stamping
/// Authority and the signer entirely inside a local scope, mints B-B through B-LTA (with an abbreviated <c>cSig</c>
/// countersignature spliced in immediately after B-B), copies out octets into a <see cref="CapstoneWireMessage"/>,
/// and disposes every certificate, key and carrier before returning. The verifying party reconstructs its own
/// inputs and seams from the received octets alone via <see cref="ReconstructInputsAndSeams"/> — an assertion
/// that passes here cannot be passing because the two sides share an object.
/// </para>
/// <para>
/// <strong>Signing under a Verifiable-native key that is also the certificate's own key.</strong>
/// <see cref="JAdESSignatureCreation.SignAsync"/> demands a <see cref="PrivateKeyMemory"/>/<see cref="SigningDelegate"/>
/// pair; <see cref="X509ChainTestRingNode"/> exposes its key as a raw <see cref="ECDsa"/> instead. Rather than
/// minting two independent, mismatched keys (one for the certificate, one for signing), <see cref="SignWithEcdsaAsync"/>
/// is a <see cref="SigningDelegate"/> closing over the leaf's own <see cref="ECDsa"/> directly (RFC 7518 §3.4's
/// ES256 wire format is the identical IEEE P1363 fixed-field concatenation COSE ES256 uses) — the
/// <paramref name="privateKeyBytes"/> parameter every other <see cref="SigningDelegate"/> in this codebase
/// consumes is deliberately unused here, so the <see cref="PrivateKeyMemory"/> handed to <c>SignAsync</c> carries
/// no meaningful bytes of its own (any well-formed placeholder does).
/// </para>
/// <para>
/// <strong>Splicing <c>cSig</c> without a raw-byte splice seam.</strong> Unlike CB-AdES's CBOR substrate,
/// <c>etsiU</c> is a JSON array a fresh <see cref="JAdESUnsignedHeaders"/> instance represents directly — no
/// analogue of <c>TrySpliceCBAdESUnprotectedHeader</c> is needed. <see cref="MintCapstoneWorldAsync"/> mints B-B
/// with no <c>etsiU</c>, countersigns the resulting JWS Signature Value (JA-5.3.2-03), then builds a NEW
/// <see cref="JwsSignatureComponent"/> sharing the SAME <c>Protected</c>/<c>ProtectedHeader</c>/<c>Signature</c>
/// as the original — only the <c>UnprotectedHeader</c> differs, carrying the one-element <c>etsiU</c> array.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JAdESCapstoneFirewalledFlowTests
{
    /// <summary>The Time-Stamping Authority URI every acquisition context states; never dialled over a socket.</summary>
    private static string TsaUri { get; } = "https://tsa.jades-capstone.example.test/";

    /// <summary>The DNS name the signer's leaf certificate carries.</summary>
    private static string SignerDnsName { get; } = "jades-capstone.example.test";

    /// <summary>The content every minted signature encapsulates and covers.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the JAdES capstone content"u8.ToArray());

    /// <summary>Encodes the countersigner's own plain RFC 7515 header (JA-5.3.2-04) to UTF-8 JSON bytes.</summary>
    private static readonly JwtPartEncoder<Dictionary<string, object>> CounterSignerHeaderEncoder =
        static header => new TaggedMemory<byte>(JsonSerializer.SerializeToUtf8Bytes(header), Tag.Create(Purpose.Data));


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The TOTAL-PASSED-shaped leg: the reconstructed B-LTA signature, validated at the current time under the
    /// Root CA it chains to, reaches <c>TOTAL-PASSED</c> through the Basic Signatures process.
    /// </summary>
    [TestMethod]
    public async Task FirewalledCapstoneReachesTotalPassedFromWireBytesAlone()
    {
        CapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using ReconstructedParty verifier = ReconstructInputsAndSeams(message, trustSigner: true);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            verifier.Inputs, verifier.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, message.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalPassed, outcome.Conclusion.Indication,
            "Clause 5.3: a B-LTA signature whose JWS signature value verifies under a currently-valid, trusted certificate chain reaches TOTAL-PASSED.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.Basic, outcome.Conclusion.ProcessIdentifier,
            "The conclusion states the process that produced it.");
        Assert.IsEmpty(outcome.Conclusion.SubIndications,
            "Table 5's PASSED row carries no sub-indication (BuildingBlockConclusion.Passed's own convention, clause 5.1.3) — killing enum-default vacuity by pinning the empty set explicitly, not merely leaving it unasserted.");
    }


    /// <summary>
    /// The FAILED leg: the JWS Payload's own base64url text is swapped on the wire, so the JWS signature value no
    /// longer verifies over the tampered Signing Input — Table 15's <c>SIG_CRYPTO_FAILURE</c>, promoted to the
    /// process-level <c>TOTAL-FAILED</c> per clause 5.1.3's Table 5.
    /// </summary>
    [TestMethod]
    public async Task FirewalledCapstoneReachesTotalFailedWhenThePayloadIsTamperedOnTheWire()
    {
        CapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string originalBase64Url = TestSetup.Base64UrlEncoder(Content.Span);
        byte[] tamperedContentBytes = Content.ToArray();
        tamperedContentBytes[^1] ^= 0xFF;
        string tamperedBase64Url = TestSetup.Base64UrlEncoder(tamperedContentBytes);

        string wireText = Encoding.UTF8.GetString(message.SignedDataObject);
        int index = wireText.IndexOf(originalBase64Url, StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, index, "The base64url-encoded JWS Payload must occur verbatim in the wire text (an attached, encoded payload).");

        string tamperedText = string.Concat(wireText.AsSpan(0, index), tamperedBase64Url, wireText.AsSpan(index + originalBase64Url.Length));
        CapstoneWireMessage tamperedMessage = message with { SignedDataObject = Encoding.UTF8.GetBytes(tamperedText) };

        using ReconstructedParty verifier = ReconstructInputsAndSeams(tamperedMessage, trustSigner: true);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            verifier.Inputs, verifier.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, message.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalFailed, outcome.Conclusion.Indication,
            "Table 5: the cryptographic checks failed (the signature value no longer verifies over the tampered Signing Input), so the process reports TOTAL-FAILED, fail-closed.");
        Assert.Contains(SignatureValidationSubIndication.SignatureCryptographicFailure, outcome.Conclusion.SubIndications,
            "SIG_CRYPTO_FAILURE, not HASH_FAILURE: JAdESSignatureFacts has no reachable HashFailure arm (its own type remarks), so a tampered Signing Input fails at Jws.VerifySignatureAsync's boolean result, mapped by CryptographicVerification's own table to SignatureCryptographicFailure — pinning the exact sub-indication this fixture produces, not merely that SOME failure occurred.");
    }


    /// <summary>
    /// The INDETERMINATE leg: the SAME genuine B-LTA wire bytes validate under a Driving Application that does
    /// not trust the signer's Root CA — clause 5.2.6.4's chain-building step finds no certificate chain from a
    /// trust anchor, Table 6's <c>NO_CERTIFICATE_CHAIN_FOUND</c> — the vocabulary's own semantics for "the
    /// available information is insufficient to ascertain TOTAL-PASSED or TOTAL-FAILED" (clause 5.1.3), distinct
    /// from the deterministic cryptographic failure of the FAILED leg above.
    /// </summary>
    [TestMethod]
    public async Task FirewalledCapstoneReachesIndeterminateWhenTheSignerIsNotTrusted()
    {
        CapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using ReconstructedParty verifier = ReconstructInputsAndSeams(message, trustSigner: false);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            verifier.Inputs, verifier.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, message.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.Indeterminate, outcome.Conclusion.Indication,
            "Clause 5.1.3/Table 5: no certificate chain to a trusted anchor is 'insufficient information', not a determinate failure -- INDETERMINATE, not TOTAL-FAILED.");
        Assert.Contains(SignatureValidationSubIndication.NoCertificateChainFound, outcome.Conclusion.SubIndications,
            "NO_CERTIFICATE_CHAIN_FOUND: with no configured trust anchor, CertificateChainCompleter.CompleteAsync exhausts its offline CA store (which still holds the Root CA as a plain, untrusted candidate certificate) without reaching a trust anchor and throws, which X509CertificateValidation's step 2)a) maps to this exact sub-indication -- pinning it, not the enum default.");
    }


    /// <summary>
    /// The signing party: mints a Root CA, a Time-Stamping Authority and a signer leaf of one
    /// <see cref="X509ChainTestRing"/>, produces a JAdES B-B signature through <see cref="JAdESSignatureCreation"/>,
    /// splices in an abbreviated <c>cSig</c> countersignature, raises it to B-T, B-LT and B-LTA through
    /// <see cref="JAdESSignatureAugmentation"/>, and releases every certificate, key and carrier before returning
    /// the wire message.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The wire message. Nothing else survives this call.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "JAdESSignatureCreationResult on a successful SignAsync call, which is 'using'-disposed below -- " +
            "mirroring JAdESLifecycleFlowTests.ConformantHeaders's own identical CA2000 justification. " +
            "newSignatureComponent shares embeddingSignature's own Signature object by reference (only " +
            "UnprotectedHeader differs); both it and creationResult are 'using'-disposed, double-disposing that " +
            "shared Signature -- safe, since every disposable carrier in this codebase is idempotently " +
            "disposable, mirroring CBAdESCapstoneFirewalledFlowTests's identical CoseSign1Message-sharing trick.")]
    private static async ValueTask<CapstoneWireMessage> MintCapstoneWorldAsync(CancellationToken cancellationToken)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset archiveTimestampTime = signingTime.AddHours(2);
        DateTimeOffset validationTime = signingTime.AddDays(1);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, SignerDnsName, timeProvider, notBefore: notBefore, notAfter: notAfter);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> placeholderKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory placeholderPrivateKey = placeholderKeyMaterial.PrivateKey;
        placeholderKeyMaterial.PublicKey.Dispose();
        SigningDelegate signingDelegate = (privateKeyBytes, dataToSign, signaturePool, context, ct) =>
            SignWithEcdsaAsync(signer.SigningKey, dataToSign, signaturePool);

        DigestValue signingCertificateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.Certificate.RawData, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

        byte[] bbWireWithCounterSignature;
        {
            //JA-5.1.7-04: at least one of x5t#S256/x5c/x5t#o/sigX5ts must be present -- x5t#S256 here, over the
            //REAL signer certificate's own DER bytes (this binding never re-derives the signing certificate from
            //it -- only its presence satisfies the B-B conformance rule this file's own flow exercises).
            var headers = new JAdESProtectedHeaders(
                WellKnownJwaValues.Es256, issuedAt: new JAdESClaimedSigningTime(signingTime), x5tHashS256: signingCertificateDigest);
            var payloadInput = new JAdESAttachedPayloadInput(Content);

            using JAdESSignatureCreationResult creationResult = await JAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                JAdESProtectedHeaderJson.Encode, JAdESEtsiUJson.Encode, TestSetup.Base64UrlEncoder,
                placeholderPrivateKey, signingDelegate,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

            //An abbreviated countersignature over the B-B JWS Signature Value -- proves JAdESCounterSign composes
            //with the JAdES creation surface end to end; the EN 319 102-1 Basic process asserted below never
            //inspects it (out of this binding's scope).
            var counterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PrivateKeyMemory counterSignerPrivateKey = counterSignerKeyMaterial.PrivateKey;
            counterSignerKeyMaterial.PublicKey.Dispose();

            JwsSignatureComponent embeddingSignature = creationResult.Message.Signatures[0];
            using JwsMessage counterSignature = await JAdESCounterSign.CountersignAsync(
                embeddingSignature.SignatureBytes,
                new Dictionary<string, object> { ["alg"] = WellKnownJwaValues.Es256 },
                CounterSignerHeaderEncoder,
                TestSetup.Base64UrlEncoder,
                counterSignerPrivateKey,
                MicrosoftCryptographicFunctions.SignP256Async,
                BaseMemoryPool.Shared,
                counterSignerUnprotectedHeader: null,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            string compact = JwsSerialization.SerializeCompact(counterSignature, TestSetup.Base64UrlEncoder);
            string cSigWireText = $"{{\"cSig\":\"{compact}\"}}";

            using var unsignedHeaders = new JAdESUnsignedHeaders(
                JAdESEtsiUIncorporationMode.ClearJson,
                [new JAdESUnsignedHeaderElementCounterSignature(
                    PooledMemory.FromBytes(Encoding.UTF8.GetBytes(cSigWireText), BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

            IReadOnlyDictionary<string, object>? unprotectedHeader = JAdESEtsiUJson.Encode(unsignedHeaders);

            using var newSignatureComponent = new JwsSignatureComponent(
                embeddingSignature.Protected, embeddingSignature.ProtectedHeader, embeddingSignature.Signature, unprotectedHeader);
            using var message = new JwsMessage(creationResult.Message.Payload, newSignatureComponent, creationResult.Message.IsDetachedPayload);

            bbWireWithCounterSignature = JwsSerialization.Serialize(message, JoseSerializationFormat.FlattenedJson, TestSetup.Base64UrlEncoder, JsonSerialize);
        }

        var signatureResponder = new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime);
        byte[] btWireCopy = await JAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = bbWireWithCounterSignature,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = signatureResponder.FetchAsync,
                EnforceSigningCertificateValidity = false,
                TargetLevel = AdESBaselineLevel.BT
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory rootCertificate = ToCarrier(root.Certificate.RawData, PkiCertificateTags.X509Certificate);

        //Clause 5.2.6.4's revocation step needs a status for the leaf certificate: without a CRL, the Basic
        //process cannot rule out revocation and reports TRY_LATER (INDETERMINATE), not TOTAL-PASSED. A clean CRL
        //(nothing revoked) placed as B-LT material, mirroring the CB-AdES capstone's own choice; JAdESLevelRules'
        //own JA-6.3-38/j service is satisfied by construction through the AnyValData placement below.
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(
            root, signingTime, signingTime.AddYears(1), []);
        byte[] revocationListBytes = revocationList.AsReadOnlySpan().ToArray();

        byte[] bltWireCopy = await JAdESSignatureAugmentation.AddValidationDataAsync(
            new JAdESValidationDataContext
            {
                WireBytes = btWireCopy,
                Material = new JAdESValidationMaterial { Certificates = [rootCertificate], CertificateRevocationLists = [revocationList] },
                Placement = JAdESValidationDataPlacement.AnyValData,
                TargetLevel = AdESBaselineLevel.BLT
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory signerCertificateForArcTst = ToCarrier(signer.Certificate.RawData, PkiCertificateTags.X509Certificate);
        var archiveResponder = new MintingTimestampResponder(authority, [authority, root], archiveTimestampTime);
        byte[] bltaWireCopy = await JAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new JAdESArchiveTimestampContext
            {
                WireBytes = bltWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                PayloadSource = Base64UrlPayloadSource(Content),
                TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = TsaUri, FetchResponse = archiveResponder.FetchAsync }],
                SigningCertificate = signerCertificateForArcTst,
                ChainCompletenessAttested = true,
                CanonAlg = "urn:test:canon",
                Canonicalize = StubCanonicalizeAsync,
                TargetLevel = AdESBaselineLevel.BLTA
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        return new CapstoneWireMessage
        {
            SignedDataObject = bltaWireCopy,
            TrustAnchorCertificate = root.Certificate.RawData,
            SigningCertificate = signer.Certificate.RawData,
            CertificateRevocationList = revocationListBytes,
            ValidationTime = validationTime
        };
    }


    /// <summary>A <see cref="SigningDelegate"/> that signs with a captured <see cref="ECDsa"/> directly, ignoring the <c>privateKeyBytes</c> parameter every other implementation in this codebase consumes.</summary>
    /// <param name="ecdsa">The key to sign with.</param>
    /// <param name="dataToSign">The bytes to sign.</param>
    /// <param name="signaturePool">The memory pool the returned <see cref="Signature"/> is rented from.</param>
    /// <returns>The JOSE-native (IEEE P1363 fixed-field) signature.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the minted Signature transfers into the ValueTask tuple this method " +
            "returns, which JAdESSignatureCreation.SignAsync's own caller (this test's mint scope) disposes " +
            "through the JAdESSignatureCreationResult it produces.")]
    private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignWithEcdsaAsync(ECDsa ecdsa, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool)
    {
        byte[] signatureBytes = ecdsa.SignData(dataToSign.Span, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        IMemoryOwner<byte> owner = signaturePool.Rent(signatureBytes.Length);
        signatureBytes.CopyTo(owner.Memory.Span);

        return ValueTask.FromResult<(Signature, CryptoEvent?)>((new Signature(owner, CryptoTags.P256Signature), null));
    }


    /// <summary>
    /// Builds the <c>arcTst</c> payload contribution matching the minted headers' own state (<c>sigD</c> absent,
    /// <c>b64</c> absent — JA-5.3.6.2.3-03's base64url arm), mirroring <c>JAdESLifecycleFlowTests</c>'s identical
    /// helper.
    /// </summary>
    /// <param name="payload">The JWS Payload bytes.</param>
    /// <returns>The payload contribution.</returns>
    private static JAdESBase64UrlPayloadImprintSource Base64UrlPayloadSource(ReadOnlyMemory<byte> payload) =>
        new(Encoding.ASCII.GetBytes(TestSetup.Base64UrlEncoder(payload.Span)));


    /// <summary>
    /// A canonicalization stub sufficient to mint a clear-JSON <c>arcTst</c> element — deterministic by
    /// <c>canonAlg</c>/<see cref="JAdESUnsignedHeaderElement.Kind"/>, mirroring <c>JAdESLifecycleFlowTests</c>'s
    /// own stub. The capstone's FAILED leg tampers the JWS Payload, not the <c>arcTst</c> token content, so this
    /// stub does not need that file's own content-sensitivity.
    /// </summary>
    private static ValueTask<PooledMemory> StubCanonicalizeAsync(string canonAlg, JAdESUnsignedHeaderElement element, BaseMemoryPool pool, CancellationToken cancellationToken) =>
        ValueTask.FromResult(PooledMemory.FromBytes(Encoding.UTF8.GetBytes($"{canonAlg}:{element.Kind}"), pool, CryptoTags.JAdESMessageImprintInput));


    /// <summary>Serializes <paramref name="value"/> to UTF-8 JSON bytes — the <c>jsonSerializer</c> seam every JAdES creation/augmentation call needs.</summary>
    private static byte[] JsonSerialize(object value) => JsonSerializer.SerializeToUtf8Bytes(value);


    /// <summary>
    /// The verifying party: reconstructs the inputs and seams one run of the EN 319 102-1 validation algorithm
    /// takes, from the received octets alone.
    /// </summary>
    /// <param name="message">The received wire message.</param>
    /// <param name="trustSigner">Whether the Root CA is configured as a trust anchor (the INDETERMINATE leg passes <see langword="false"/>).</param>
    /// <returns>The reconstructed party; the caller disposes it.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every carrier constructed below transfers into the returned " +
            "ReconstructedParty, which the caller disposes via 'using verifier'.")]
    private static ReconstructedParty ReconstructInputsAndSeams(CapstoneWireMessage message, bool trustSigner)
    {
        SensitiveMemoryHolder signedDataObject = new(ToCarrier(message.SignedDataObject, PkiCertificateTags.X509Certificate));
        PkiCertificateMemory signingCertificate = ToCarrier(message.SigningCertificate, PkiCertificateTags.X509Certificate);
        PkiCertificateMemory trustAnchor = ToCarrier(message.TrustAnchorCertificate, PkiCertificateTags.X509Certificate);
        PkiCertificateMemory revocationList = ToCarrier(message.CertificateRevocationList, PkiCertificateTags.X509Crl);

        var x509Constraints = new X509ValidationConstraints
        {
            TrustAnchors = trustSigner ? [new TrustAnchorConstraint(trustAnchor, SunsetDate: null)] : []
        };

        var cryptographicConstraints = new CryptographicConstraints
        {
            Entries =
            [
                //JAdESSignatureFacts does not populate AlgorithmUse.KeySizeBits for the signature-value use
                //(it has no independent key-size fact at extraction time -- see that binding's own scope
                //remarks), so this entry enforces no minimum for it; the certificate's own key size is a
                //separate concern the X.509 chain-validation seam covers.
                new AlgorithmReliabilityEntry(new AlgorithmIdentifier(WellKnownJwaValues.Es256) { Name = WellKnownJwaValues.Es256 }, MinimumKeySizeBits: null, TrustedUntil: null),
                new AlgorithmReliabilityEntry(
                    new AlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid), MinimumKeySizeBits: X509ChainTestRing.SigningKeySizeBits, TrustedUntil: null),
                new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null)
            ]
        };

        var constraints = new SignatureValidationConstraints
        {
            Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
            X509 = x509Constraints,
            Cryptographic = cryptographicConstraints,
            SignatureElements = new SignatureElementsConstraints()
        };

        var completer = new CertificateChainCompleter([trustAnchor]);
        var revocationChecker = new CrlRevocationChecker([revocationList]);

        var seams = new SignatureValidationSeams
        {
            Format = JAdESSignatureFacts.CreateSeam(
                JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESProtectedHeaderJson.DetectX5tPresence,
                JAdESEtsiUJson.TryParse, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder),
            CompleteCertificateChain = completer.CompleteAsync,
            ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync,
            CheckRevocation = revocationChecker.CheckAsync
        };

        var inputs = new SignatureValidationInputs
        {
            SignedDataObject = signedDataObject.Memory,
            Constraints = constraints,
            SigningCertificate = signingCertificate
        };

        return new ReconstructedParty(signedDataObject, signingCertificate, trustAnchor, revocationList, inputs, seams);
    }


    /// <summary>Copies received octets into a pooled carrier of the stated kind.</summary>
    /// <param name="bytes">The octets to copy.</param>
    /// <param name="tag">The kind discriminator the carrier states.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCarrier(byte[] bytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// Everything that crosses the firewall: the JAdES JWS wire octets raised through B-LTA, the DER octets of
    /// the trust anchor and signing certificates, and the instant the verifier validates at.
    /// </summary>
    private sealed record CapstoneWireMessage
    {
        /// <summary>The UTF-8 JSON <c>JAdES</c> wire octets the signing party produced, raised through B-LTA.</summary>
        public required byte[] SignedDataObject { get; init; }

        /// <summary>The DER-encoded Root CA certificate the verifier may be configured to trust.</summary>
        public required byte[] TrustAnchorCertificate { get; init; }

        /// <summary>The DER-encoded signer leaf certificate, supplied directly as Table 18's "Signing Certificate" input.</summary>
        public required byte[] SigningCertificate { get; init; }

        /// <summary>The DER-encoded, clean (nothing revoked) certificate revocation list the Root CA issued.</summary>
        public required byte[] CertificateRevocationList { get; init; }

        /// <summary>The instant the verifier validates at.</summary>
        public required DateTimeOffset ValidationTime { get; init; }
    }


    /// <summary>Wraps a <see cref="PkiCertificateMemory"/> so it can stand in for the format-neutral engine's <see cref="SensitiveMemory"/> Signed Data Object slot.</summary>
    /// <param name="carrier">The owned carrier.</param>
    private sealed class SensitiveMemoryHolder(PkiCertificateMemory carrier): IDisposable
    {
        /// <summary>Gets the carrier as the engine's own Signed Data Object type.</summary>
        public SensitiveMemory Memory => carrier;

        /// <inheritdoc/>
        public void Dispose() => carrier.Dispose();
    }


    /// <summary>The verifying party's reconstructed carriers, inputs and seams, disposed together.</summary>
    /// <param name="SignedDataObject">The reconstructed Signed Data Object holder.</param>
    /// <param name="SigningCertificate">The reconstructed signing certificate.</param>
    /// <param name="TrustAnchor">The reconstructed trust anchor certificate.</param>
    /// <param name="RevocationList">The reconstructed certificate revocation list.</param>
    /// <param name="Inputs">The assembled validation inputs.</param>
    /// <param name="Seams">The assembled validation seams.</param>
    private sealed record ReconstructedParty(
        SensitiveMemoryHolder SignedDataObject,
        PkiCertificateMemory SigningCertificate,
        PkiCertificateMemory TrustAnchor,
        PkiCertificateMemory RevocationList,
        SignatureValidationInputs Inputs,
        SignatureValidationSeams Seams): IDisposable
    {
        /// <inheritdoc/>
        public void Dispose()
        {
            SignedDataObject.Dispose();
            SigningCertificate.Dispose();
            TrustAnchor.Dispose();
            RevocationList.Dispose();
        }
    }
}
