using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.JCose;

/// <summary>
/// The firewalled capstone for CB-AdES: a signing party mints a B-B signature carrying an abbreviated
/// countersignature and raises it through B-T, B-LT and B-LTA entirely through the shipped
/// <see cref="CBAdESSignatureCreation"/>/<see cref="CBAdESSignatureAugmentation"/>/<see cref="CoseCounterSign"/>
/// surfaces, emits nothing but wire octets, and a verifying party that never saw the signing party's objects
/// reconstructs every input from those octets alone and runs the shipped CB-AdES binding
/// (<see cref="CBAdESSignatureFacts"/>) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> clause 5.3 (the validation process for Basic Signatures) to a real
/// <c>TOTAL-PASSED</c>, mirroring <c>CAdESCapstoneFirewalledFlowTests</c>'s own shape.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Basic Signatures, not Long Term Availability (a deliberate, disclosed scope cut).</strong> This
/// binding does not wire <c>StateTimestampCoverage</c>/<c>StateTimestampProtectsObject</c> (see
/// <see cref="CBAdESSignatureFacts"/>'s own remarks on decoding <c>sigTst</c>/<c>arcTst</c> tokens' raw bytes
/// only, never opening/verifying their RFC 3161 content), so the proof-of-existence extraction the
/// <c>LongTermAvailability</c> process (clause 5.6.3) needs is not reachable from this binding — exactly the
/// "Basic only" scope this library commits to for
/// a first CB-AdES capstone ("CB-AdES has no long-term-availability-material process of its own distinct from
/// B-LTA/arcTst"). The lifecycle is still minted all the way through B-LTA with a genuine countersignature —
/// proving the shipped creation/augmentation/countersign surfaces compose correctly end to end — but the EN 319
/// 102-1 CONCLUSION asserted below is the Basic Signatures process's own <c>TOTAL-PASSED</c>/<c>TOTAL-FAILED</c>/
/// <c>INDETERMINATE</c>, reached from the resulting B-LTA signature's current-time certificate-chain validity
/// alone, not from any archive-time-stamp-derived proof of existence.
/// </para>
/// <para>
/// <strong>The firewall.</strong> <see cref="MintCapstoneWorldAsync"/> builds the Root CA, the Time-Stamping
/// Authority and the signer entirely inside a local scope, mints B-B through B-LTA (with an abbreviated
/// countersignature spliced in immediately after B-B), copies out DER octets into a
/// <see cref="CapstoneWireMessage"/>, and disposes every certificate, key and carrier before returning. The
/// verifying party reconstructs its own inputs and seams from the received octets alone via
/// <see cref="ReconstructInputsAndSeams"/> — an assertion that passes here cannot be passing because the two
/// sides share an object.
/// </para>
/// <para>
/// <strong>Signing under a Verifiable-native key that is also the certificate's own key.</strong>
/// <see cref="CBAdESSignatureCreation.SignAsync"/> demands a <see cref="PrivateKeyMemory"/>/<see cref="SigningDelegate"/>
/// pair; <see cref="X509ChainTestRingNode"/> exposes its key as a raw <see cref="ECDsa"/> instead. Rather than
/// minting two independent, mismatched keys (one for the certificate, one for signing), <see cref="SignWithEcdsaAsync"/>
/// is a <see cref="SigningDelegate"/> closing over the leaf's own <see cref="ECDsa"/> directly — the
/// <paramref name="privateKeyBytes"/> parameter every other <see cref="SigningDelegate"/> in this codebase
/// consumes is deliberately unused here, so the <see cref="PrivateKeyMemory"/> handed to <c>SignAsync</c> carries
/// no meaningful bytes of its own (any well-formed placeholder does).
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESCapstoneFirewalledFlowTests
{
    /// <summary>The Time-Stamping Authority URI every acquisition context states; never dialled over a socket.</summary>
    private static string TsaUri { get; } = "https://tsa.cbades-capstone.example.test/";

    /// <summary>The DNS name the signer's leaf certificate carries.</summary>
    private static string SignerDnsName { get; } = "cbades-capstone.example.test";

    /// <summary>The content every minted signature encapsulates and covers.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the CB-AdES capstone content"u8.ToArray());


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
            "Clause 5.3: a B-LTA signature whose COSE signature value verifies under a currently-valid, trusted certificate chain reaches TOTAL-PASSED.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.Basic, outcome.Conclusion.ProcessIdentifier,
            "The conclusion states the process that produced it.");
        Assert.IsEmpty(outcome.Conclusion.SubIndications,
            "Table 5's PASSED row carries no sub-indication (BuildingBlockConclusion.Passed's own convention, clause 5.1.3) — killing enum-default vacuity by pinning the empty set explicitly, not merely leaving it unasserted.");
    }


    /// <summary>
    /// The FAILED leg: one payload byte of the B-LTA wire bytes is flipped after minting, so the COSE signature
    /// value no longer verifies over the tampered content — Table 15's <c>SIG_CRYPTO_FAILURE</c>, promoted to
    /// the process-level <c>TOTAL-FAILED</c> per clause 5.1.3's Table 5.
    /// </summary>
    [TestMethod]
    public async Task FirewalledCapstoneReachesTotalFailedWhenThePayloadIsTamperedOnTheWire()
    {
        CapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        int offset = IndexOfSubsequence(message.SignedDataObject, Content.Span);
        Assert.IsGreaterThanOrEqualTo(0, offset, "The signed content must occur verbatim in the wire bytes (an attached COSE Payload).");

        byte[] tampered = (byte[])message.SignedDataObject.Clone();
        tampered[offset] ^= 0xFF;
        CapstoneWireMessage tamperedMessage = message with { SignedDataObject = tampered };

        using ReconstructedParty verifier = ReconstructInputsAndSeams(tamperedMessage, trustSigner: true);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            verifier.Inputs, verifier.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, message.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalFailed, outcome.Conclusion.Indication,
            "Table 5: the cryptographic checks failed (the signature value no longer verifies over the tampered content), so the process reports TOTAL-FAILED, fail-closed.");
        Assert.Contains(SignatureValidationSubIndication.SignatureCryptographicFailure, outcome.Conclusion.SubIndications,
            "SIG_CRYPTO_FAILURE, not HASH_FAILURE: CBAdESSignatureFacts has no reachable HashFailure arm (its own type remarks), so a tampered Sig_structure input fails at Cose.VerifyAsync's boolean result, mapped by CryptographicVerification's own table to SignatureCryptographicFailure — pinning the exact sub-indication this fixture produces, not merely that SOME failure occurred.");
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
    /// <see cref="X509ChainTestRing"/>, produces a CB-AdES B-B signature through <see cref="CBAdESSignatureCreation"/>,
    /// splices in an abbreviated countersignature, raises it to B-T, B-LT and B-LTA through
    /// <see cref="CBAdESSignatureAugmentation"/>, and releases every certificate, key and carrier before
    /// returning the wire message.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The wire message. Nothing else survives this call.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "signingCertificateThumbprint's Digest ownership transfers into the AdESCertificateThumbprint, " +
            "then into headers (the x5t parameter), then into creationResult on a successful SignAsync call, which " +
            "is 'using'-disposed below -- Roslyn's CA2000 analysis cannot see across that multi-hop transfer.")]
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
        var signingCertificateThumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), signingCertificateDigest);

        byte[] bbWireWithCounterSignature;
        {
            //CB-5.2.2-07: at least one of x5t/x5ts/x5chain must be present -- x5t here, over the REAL signer
            //certificate's own DER bytes (never the RFC 3161 style test placeholder the sibling lifecycle file
            //uses, since this binding never re-derives the signing certificate from it -- only its presence
            //satisfies the B-B conformance rule this file's Table 14 flow actually exercises).
            using var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(signingTime), x5t: signingCertificateThumbprint);
            var payloadInput = new CBAdESAttachedPayloadInput(Content);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, placeholderPrivateKey, signingDelegate,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

            //An abbreviated (label 12) countersignature over the B-B body layer, spliced in as the first
            //uHeaders element -- proves CoseCounterSign composes with the CB-AdES creation surface end to end;
            //the EN 319 102-1 Basic process asserted below never inspects it (out of this binding's scope).
            var counterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PrivateKeyMemory counterSignerPrivateKey = counterSignerKeyMaterial.PrivateKey;
            counterSignerKeyMaterial.PublicKey.Dispose();

            var target = new CoseSign1CountersignTarget(
                creationResult.Message.ProtectedHeader.AsReadOnlyMemory(), creationResult.Message.Payload, creationResult.Message.Signature.AsReadOnlyMemory());
            using CounterSignature0V2 counterSignature = await CoseCounterSign.CountersignAbbreviatedAsync(
                target, externalAad: ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
                counterSignerPrivateKey, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            using EncodedCoseCounterSignature encoded = CoseSerialization.WriteCounterSignature0V2(counterSignature, BaseMemoryPool.Shared);
            var element = new CBAdESUnsignedHeaderElementAbbreviatedCounterSignature(encoded.AsReadOnlyMemory().ToArray());

            bool spliced = CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader(
                rawUnsignedHeaders: null, decodedElementCount: 0, skipDecodedIndexes: null, newElement: element,
                BaseMemoryPool.Shared, out IReadOnlyDictionary<int, object>? unprotectedHeader);
            Assert.IsTrue(spliced, "Splicing a single new element into an absent uHeaders must always succeed.");

            using var message = new CoseSign1Message(creationResult.Message.ProtectedHeader, unprotectedHeader, creationResult.Message.Payload, creationResult.Message.Signature);
            using EncodedCoseSign1 wireBytes = CBAdESSignatureSerialization.SerializeCBAdESSign1(message, payloadIsDetached: false, BaseMemoryPool.Shared);
            bbWireWithCounterSignature = wireBytes.AsReadOnlySpan().ToArray();
        }

        var signatureResponder = new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime);
        byte[] btWireCopy;
        {
            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = bbWireWithCounterSignature,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = signatureResponder.FetchAsync,
                    EnforceSigningCertificateValidity = false,
                    TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            btWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using PkiCertificateMemory rootCertificate = ToCarrier(root.Certificate.RawData, PkiCertificateTags.X509Certificate);

        //Clause 5.2.6.4's revocation step needs a status for the leaf certificate: without a CRL, the Basic
        //process cannot rule out revocation and reports TRY_LATER (INDETERMINATE), not TOTAL-PASSED. A clean
        //CRL (nothing revoked) placed as B-LT material, mirroring CAdES's own capstone.
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(
            root, signingTime, signingTime.AddYears(1), []);
        byte[] revocationListBytes = revocationList.AsReadOnlySpan().ToArray();

        byte[] bltWireCopy;
        {
            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddValidationDataAsync(
                new CBAdESValidationDataContext
                {
                    WireBytes = btWireCopy,
                    Material = new CBAdESValidationMaterial { Certificates = [rootCertificate], CertificateRevocationLists = [revocationList] },
                    TargetLevel = AdESBaselineLevel.BLT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            bltWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using PkiCertificateMemory signerCertificateForArcTst = ToCarrier(signer.Certificate.RawData, PkiCertificateTags.X509Certificate);
        var archiveResponder = new MintingTimestampResponder(authority, [authority, root], archiveTimestampTime);
        byte[] bltaWireCopy;
        {
            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CBAdESArchiveTimestampContext
                {
                    WireBytes = bltWireCopy,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = TsaUri, FetchResponse = archiveResponder.FetchAsync }],
                    SigningCertificate = signerCertificateForArcTst,
                    ChainCompletenessAttested = true,
                    TargetLevel = AdESBaselineLevel.BLTA
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                BaseMemoryPool.Shared,
                parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
                isCounterSignatureMaterialComplete: _ => true,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            bltaWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

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
    /// <returns>The COSE-native (IEEE P1363 fixed-field) signature.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the minted Signature transfers into the ValueTask tuple this method " +
            "returns, which CBAdESSignatureCreation.SignAsync's own caller (this test's mint scope) disposes " +
            "through the CBAdESSignatureCreationResult it produces.")]
    private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignWithEcdsaAsync(ECDsa ecdsa, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool)
    {
        byte[] signatureBytes = ecdsa.SignData(dataToSign.Span, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        IMemoryOwner<byte> owner = signaturePool.Rent(signatureBytes.Length);
        signatureBytes.CopyTo(owner.Memory.Span);

        return ValueTask.FromResult<(Signature, CryptoEvent?)>((new Signature(owner, CryptoTags.P256Signature), null));
    }


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
                //CBAdESSignatureFacts does not populate AlgorithmUse.KeySizeBits for the signature-value use
                //(it has no independent key-size fact at extraction time -- see that binding's own scope
                //remarks), so this entry enforces no minimum for it; the certificate's own key size is a
                //separate concern the X.509 chain-validation seam covers.
                new AlgorithmReliabilityEntry(new AlgorithmIdentifier("-7") { Name = "ES256" }, MinimumKeySizeBits: null, TrustedUntil: null),
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
            Format = CBAdESSignatureFacts.CreateSeam(CBAdESSignatureSerialization.ParseCBAdESSign1, CoseSerialization.BuildSigStructure),
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


    /// <summary>Finds the first byte offset at which <paramref name="needle"/> occurs verbatim inside <paramref name="haystack"/>.</summary>
    /// <param name="haystack">The array to search.</param>
    /// <param name="needle">The byte sequence to locate.</param>
    /// <returns>The zero-based offset, or <c>-1</c> when no occurrence exists.</returns>
    private static int IndexOfSubsequence(byte[] haystack, ReadOnlySpan<byte> needle)
    {
        if(needle.Length == 0 || needle.Length > haystack.Length)
        {
            return -1;
        }

        for(int start = 0; start <= haystack.Length - needle.Length; ++start)
        {
            if(haystack.AsSpan(start, needle.Length).SequenceEqual(needle))
            {
                return start;
            }
        }

        return -1;
    }


    /// <summary>Copies received DER octets into a pooled carrier of the stated kind.</summary>
    /// <param name="derBytes">The octets to copy.</param>
    /// <param name="tag">The kind discriminator the carrier states.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// Everything that crosses the firewall: the DER octets of the B-LTA <c>COSE_Sign1</c>, the DER octets of
    /// the trust anchor and signing certificates, and the instant the verifier validates at.
    /// </summary>
    private sealed record CapstoneWireMessage
    {
        /// <summary>The DER... rather, CBOR-encoded <c>COSE_Sign1</c> octets the signing party produced, raised through B-LTA.</summary>
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
