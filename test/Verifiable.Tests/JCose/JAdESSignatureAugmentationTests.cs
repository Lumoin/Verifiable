using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Coverage for <see cref="JAdESSignatureAugmentation"/> — the augmentation verbs (<c>sigTst</c>, <c>xVals</c>/
/// <c>rVals</c>/<c>anyValData</c>, <c>xRefs</c>/<c>rRefs</c>, <c>sigRTst</c>/<c>rfsTst</c>, <c>arcTst</c>) per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Key material.</strong> The JAdES signing key is P-256, minted through
/// <see cref="TestKeyMaterialProvider.CreateP256KeyMaterial"/> and wired through
/// <see cref="MicrosoftCryptographicFunctionsAdapter.SignP256Async"/>, mirroring <c>JAdESSignatureCreationTests</c>'s own
/// composition pattern.
/// </para>
/// <para>
/// <strong>Real Time-Stamping Authority round trips, in process.</strong> Every TSA-calling test uses
/// <see cref="MintingTimestampResponder"/> — the same double the CB-AdES wire-flow tests drive — over a
/// genuine BouncyCastle-signed RFC 3161 token; no stub ever fabricates a token. <see cref="StubFetchResponseAsync"/>
/// is reserved for refusal-arm tests that must never reach a Time-Stamping Authority at all — its own
/// <see cref="CountingFetchResponse"/> wrapper proves that with a call count, not just an absence of exceptions.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JAdESSignatureAugmentationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>The classified constructor carries the supplied <see cref="JAdESAugmentationFailureKind"/> and message.</summary>
    [TestMethod]
    public void JAdESAugmentationException_ClassifiedConstructor_CarriesFailureKindAndMessage()
    {
        var exception = new JAdESAugmentationException(JAdESAugmentationFailureKind.ReferencesElementRequired, "a message");

        Assert.AreEqual(JAdESAugmentationFailureKind.ReferencesElementRequired, exception.FailureKind);
        Assert.AreEqual("a message", exception.Message);
    }


    /// <summary>The parameterless constructor classifies as <see cref="JAdESAugmentationFailureKind.MalformedEncoding"/>.</summary>
    [TestMethod]
    public void JAdESAugmentationException_DefaultConstructor_ClassifiesAsMalformedEncoding()
    {
        var exception = new JAdESAugmentationException();

        Assert.AreEqual(JAdESAugmentationFailureKind.MalformedEncoding, exception.FailureKind);
    }

    /// <summary>A B-B signature raised to B-T over a real TSA round trip carries exactly one clear-JSON <c>sigTst</c> element and remains parseable/level-conformant.</summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_HappyPath_AppendsOneSigTstElement()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] augmented = await AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "urn:test:tsa",
                FetchResponse = tsa.Responder.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders unsignedHeaders = DecodeUnsignedHeaders(augmented);

        Assert.AreEqual(1, unsignedHeaders.Count);
        var element = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(unsignedHeaders[0]);
        var clear = Assert.IsInstanceOfType<JAdESClearUnsignedValue<AdESTimestampContainer>>(element.Carriage);
        Assert.HasCount(1, clear.Value.TstTokens);
        Assert.IsNull(clear.Value.CanonAlg, "JA-5.3.4-05: sigTst shall not contain canonAlg.");
    }


    /// <summary>A malformed (wrong-kind) signing certificate refuses before the Time-Stamping Authority is ever contacted.</summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_MalformedSigningCertificate_NeverBillsTsa()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory notACertificate = CreatePkiCarrier(PkiCertificateTags.OcspResponse);
        var counting = new CountingFetchResponse(StubFetchResponseAsync);

        JAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<JAdESAugmentationException>(
            () => AddSignatureTimestampAsync(
                new JAdESSignatureTimestampContext
                {
                    WireBytes = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = "urn:test:tsa",
                    FetchResponse = counting.FetchAsync,
                    SigningCertificate = notACertificate,
                    TargetLevel = AdESBaselineLevel.BT
                },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(JAdESAugmentationFailureKind.SigningCertificateMalformed, exception.FailureKind);
        Assert.AreEqual(0, counting.CallCount, "A malformed signing certificate must refuse before any Time-Stamping Authority round trip.");
    }


    /// <summary>
    /// An <c>etsiU</c> that already declares base64url
    /// incorporation no longer refuses augmentation — the new <c>sigTst</c> element mints in the SAME mode
    /// (opaque, over a real Time-Stamping Authority round trip), and the RETAINED <c>cSig</c> element's own wire
    /// text survives byte-exact, proving the mode-neutral rewrite never touches what it does not build.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult; " +
            "opaqueUnsignedHeaders is never taken ownership of by SignAsync (only projected via " +
            "EncodeJAdESUnprotectedHeaderDelegate) and is disposed explicitly via its own 'using' declaration.")]
    [TestMethod]
    public async Task AddSignatureTimestampAsync_Base64UrlIncorporation_MintsOpaqueSigTstAndKeepsRetainedElementByteExact()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        //A base64url-incorporated cSig element: the array entry's own wire TEXT must itself decode (base64url)
        //to a single-member {"cSig": ...} JSON object (JAdESEtsiUJson's own decode contract) -- unlike the
        //clear-JSON arm, this is not literal JSON text.
        string cSigBase64Url = TestSetup.Base64UrlEncoder("{\"cSig\":\"x\"}"u8);
        byte[] cSigWireTextBytes = System.Text.Encoding.ASCII.GetBytes(cSigBase64Url);
        using var opaqueUnsignedHeaders = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.Base64Url,
            [new JAdESUnsignedHeaderElementCounterSignature(PooledMemory.FromBytes(cSigWireTextBytes, BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        using JAdESSignatureCreationResult created = await SignAsync(
            ConformantHeaders(), new JAdESAttachedPayloadInput(new byte[] { 1, 2, 3 }), opaqueUnsignedHeaders, privateKey, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] baseline = Serialize(created, JoseSerializationFormat.FlattenedJson);

        byte[] augmented = await AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "urn:test:tsa",
                FetchResponse = tsa.Responder.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders unsignedHeaders = DecodeUnsignedHeaders(augmented);

        Assert.AreEqual(JAdESEtsiUIncorporationMode.Base64Url, unsignedHeaders.Mode, "The new element mints in the CONTAINER'S existing mode.");
        Assert.AreEqual(2, unsignedHeaders.Count, "cSig (retained), then sigTst (new) -- JA-5.3.1-03 append-at-end.");

        var cSig = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementCounterSignature>(unsignedHeaders[0]);
        Assert.IsTrue(cSigWireTextBytes.AsSpan().SequenceEqual(cSig.WireText.AsReadOnlySpan()), "The retained cSig element's own wire text must survive byte-exact -- Append never touches what it does not build.");

        var sigTst = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(unsignedHeaders[1]);
        var opaque = Assert.IsInstanceOfType<JAdESOpaqueUnsignedValue<AdESTimestampContainer>>(sigTst.Carriage);
        Assert.HasCount(1, opaque.DecodedValue.TstTokens, "The decode-for-inspection view mirrors the clear arm's own shape.");
        Assert.IsNull(opaque.DecodedValue.CanonAlg, "JA-5.3.4-05: sigTst shall not contain canonAlg, in either incorporation mode.");
    }


    /// <summary>A repeated call at B-T (Table 1 NOTE 7, multi-TSA) appends a SECOND, sibling <c>sigTst</c> element rather than a second token inside one container, and the FIRST element's own wire content is untouched (byte-exact retained-element regression).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-26.
    /// </remarks>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_RepeatedCall_AppendsSiblingElementWithoutMutatingTheFirst()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        var context = new JAdESSignatureTimestampContext
        {
            WireBytes = baseline,
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            TsaUri = "urn:test:tsa",
            FetchResponse = tsa.Responder.FetchAsync,
            SigningCertificate = signingCertificate,
            TargetLevel = AdESBaselineLevel.BT
        };

        byte[] onceAugmented = await AddSignatureTimestampAsync(context, TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders firstOnly = DecodeUnsignedHeaders(onceAugmented);
        byte[] firstTokenValBefore = ExtractSigTstTokenBytes(firstOnly, 0);

        byte[] twiceAugmented = await AddSignatureTimestampAsync(WithWireBytes(context, onceAugmented), TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders both = DecodeUnsignedHeaders(twiceAugmented);
        Assert.AreEqual(2, both.Count);
        Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(both[0]);
        Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(both[1]);

        byte[] firstTokenValAfter = ExtractSigTstTokenBytes(both, 0);
        Assert.AreSequenceEqual(firstTokenValBefore, firstTokenValAfter, "The first sigTst instance's own token bytes must be untouched by the second call.");
    }

    /// <summary>Separate placement appends one <c>xVals</c> element and one <c>rVals</c> element, in that order.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-27, JA-6.3-32.
    /// </remarks>
    [TestMethod]
    public async Task AddValidationDataAsync_SeparatePlacement_AppendsXValsThenRVals()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] withSigTst = await CreateWireBytesWithSigTstAsync(privateKey, tsa, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory certificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory crl = CreatePkiCarrier(PkiCertificateTags.X509Crl);

        byte[] augmented = await AddValidationDataAsync(
            new JAdESValidationDataContext
            {
                WireBytes = withSigTst,
                Material = new JAdESValidationMaterial { Certificates = [certificate], CertificateRevocationLists = [crl] },
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = true,
                TargetLevel = AdESBaselineLevel.BLT
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders unsignedHeaders = DecodeUnsignedHeaders(augmented);
        Assert.AreEqual(3, unsignedHeaders.Count);
        Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(unsignedHeaders[0]);
        Assert.IsInstanceOfType<JAdESUnsignedHeaderElementCertificateValues>(unsignedHeaders[1]);
        Assert.IsInstanceOfType<JAdESUnsignedHeaderElementRevocationValues>(unsignedHeaders[2]);
    }


    /// <summary><see cref="JAdESValidationDataPlacement.AnyValData"/> combines both into a single <c>anyValData</c> element, satisfying the JA-6.3-38/j service by construction.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-28, JA-6.3-41.
    /// </remarks>
    [TestMethod]
    public async Task AddValidationDataAsync_AnyValDataPlacement_AppendsSingleElement()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] withSigTst = await CreateWireBytesWithSigTstAsync(privateKey, tsa, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory certificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);

        byte[] augmented = await AddValidationDataAsync(
            new JAdESValidationDataContext
            {
                WireBytes = withSigTst,
                Material = new JAdESValidationMaterial { Certificates = [certificate] },
                Placement = JAdESValidationDataPlacement.AnyValData,
                TargetLevel = AdESBaselineLevel.BLT
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders unsignedHeaders = DecodeUnsignedHeaders(augmented);
        Assert.AreEqual(2, unsignedHeaders.Count);
        Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(unsignedHeaders[0]);
        Assert.IsInstanceOfType<JAdESUnsignedHeaderElementAnyValidationData>(unsignedHeaders[1]);
    }


    /// <summary>Letters e/i: a candidate byte-equal to material already present in an earlier <c>xVals</c> element is skipped.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-e, JA-6.3-i.
    /// </remarks>
    [TestMethod]
    public async Task AddValidationDataAsync_DuplicateAgainstExistingXVals_IsSkipped()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] withSigTst = await CreateWireBytesWithSigTstAsync(privateKey, tsa, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory certificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);

        byte[] firstRound = await AddValidationDataAsync(
            new JAdESValidationDataContext
            {
                WireBytes = withSigTst,
                Material = new JAdESValidationMaterial { Certificates = [certificate] },
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = true,
                TargetLevel = AdESBaselineLevel.BLT
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory sameCertificateAgain = CreatePkiCarrier(PkiCertificateTags.X509Certificate);

        byte[] secondRound = await AddValidationDataAsync(
            new JAdESValidationDataContext
            {
                WireBytes = firstRound,
                Material = new JAdESValidationMaterial { Certificates = [sameCertificateAgain] },
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = true,
                TargetLevel = AdESBaselineLevel.BLT
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders unsignedHeaders = DecodeUnsignedHeaders(secondRound);
        Assert.AreEqual(2, unsignedHeaders.Count, "The duplicate candidate must not have produced a second xVals element (sigTst plus the one xVals element from the first round).");
    }


    /// <summary>Empty material refuses with <see cref="ArgumentException"/>.</summary>
    [TestMethod]
    public async Task AddValidationDataAsync_EmptyMaterial_Throws()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentException>(
            () => AddValidationDataAsync(
                new JAdESValidationDataContext { WireBytes = baseline, Material = JAdESValidationMaterial.None, TargetLevel = AdESBaselineLevel.BLT },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);
    }


    /// <summary>A wrong-kind carrier (an OCSP response placed as a certificate) refuses with <see cref="JAdESAugmentationFailureKind.UnsupportedValidationObject"/>.</summary>
    [TestMethod]
    public async Task AddValidationDataAsync_WrongKindCertificate_Throws()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory notACertificate = CreatePkiCarrier(PkiCertificateTags.OcspResponse);

        JAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<JAdESAugmentationException>(
            () => AddValidationDataAsync(
                new JAdESValidationDataContext
                {
                    WireBytes = baseline,
                    Material = new JAdESValidationMaterial { Certificates = [notACertificate] },
                    TargetLevel = AdESBaselineLevel.BLT
                },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(JAdESAugmentationFailureKind.UnsupportedValidationObject, exception.FailureKind);
    }

    /// <summary>A conformant call at B-B appends one <c>xRefs</c> element and one <c>rRefs</c> element.</summary>
    [TestMethod]
    public async Task AddReferencesAsync_HappyPath_AppendsXRefsThenRRefs()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory otherCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate, fill: 9);
        using PkiCertificateMemory crl = CreatePkiCarrier(PkiCertificateTags.X509Crl);

        byte[] augmented = await AddReferencesAsync(
            new JAdESReferencesContext
            {
                WireBytes = baseline,
                SigningCertificate = signingCertificate,
                CertificatesToReference = [otherCertificate],
                CrlsToReference = [crl],
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TargetLevel = AdESBaselineLevel.BB
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders unsignedHeaders = DecodeUnsignedHeaders(augmented);
        Assert.AreEqual(2, unsignedHeaders.Count);
        var xRefs = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementCertificateReferences>(unsignedHeaders[0]);
        var clearXRefs = Assert.IsInstanceOfType<JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>>(xRefs.Carriage);
        Assert.HasCount(1, clearXRefs.Value.Items);
        Assert.AreEqual(new AdESDigestAlgorithmTextIdentifier(WellKnownHashAlgorithms.Sha256Iana), clearXRefs.Value.Items[0].HashAlgorithm);
        Assert.IsInstanceOfType<JAdESUnsignedHeaderElementRevocationReferences>(unsignedHeaders[1]);
    }


    /// <summary>JA-A.1.1-02: referencing the signature's own signing certificate refuses.</summary>
    [TestMethod]
    public async Task AddReferencesAsync_SigningCertificateSelfReference_Throws()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory sameBytesAgain = CreatePkiCarrier(PkiCertificateTags.X509Certificate);

        JAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<JAdESAugmentationException>(
            () => AddReferencesAsync(
                new JAdESReferencesContext
                {
                    WireBytes = baseline,
                    SigningCertificate = signingCertificate,
                    CertificatesToReference = [sameBytesAgain],
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TargetLevel = AdESBaselineLevel.BB
                },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(JAdESAugmentationFailureKind.SigningCertificateReferenceRefused, exception.FailureKind);
    }


    /// <summary>A declared target level of B-LT or above refuses <c>xRefs</c>/<c>rRefs</c> generation (JA-6.3-29/-33).</summary>
    [TestMethod]
    public async Task AddReferencesAsync_TargetLevelBLT_Throws()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory otherCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate, fill: 9);

        JAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<JAdESAugmentationException>(
            () => AddReferencesAsync(
                new JAdESReferencesContext
                {
                    WireBytes = baseline,
                    SigningCertificate = signingCertificate,
                    CertificatesToReference = [otherCertificate],
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TargetLevel = AdESBaselineLevel.BLT
                },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(JAdESAugmentationFailureKind.ReferencesFamilyNotPermittedAtTargetLevel, exception.FailureKind);
    }

    /// <summary>With <c>xRefs</c> already present, <c>sigRTst</c> is generated over a real TSA round trip.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-36.
    /// </remarks>
    [TestMethod]
    public async Task AddSignatureAndReferencesTimestampAsync_HappyPath_AppendsSigRTst()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] withXRefs = await CreateWireBytesWithXRefsAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] augmented = await AddSignatureAndReferencesTimestampAsync(
            new JAdESReferencesFamilyTimestampContext
            {
                WireBytes = withXRefs,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "urn:test:tsa",
                FetchResponse = tsa.Responder.FetchAsync,
                CanonAlg = "urn:test:canon",
                Canonicalize = StubCanonicalizeAsync,
                //B-B: sigRTst carries no JA-6.3-26 cumulative sigTst prerequisite of its own (that floor only
                //binds from B-T onward); B-B isolates sigRTst placement from the sigTst ladder for this test.
                TargetLevel = AdESBaselineLevel.BB
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders unsignedHeaders = DecodeUnsignedHeaders(augmented);
        Assert.AreEqual(2, unsignedHeaders.Count);
        var element = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp>(unsignedHeaders[1]);
        var clear = Assert.IsInstanceOfType<JAdESClearUnsignedValue<AdESTimestampContainer>>(element.Carriage);
        Assert.AreEqual("urn:test:canon", clear.Value.CanonAlg, "JA-5.3.1-14: a clear-mode sigRTst must declare canonAlg.");
    }


    /// <summary>With no <c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/<c>arRefs</c> present, <c>sigRTst</c> refuses before any Time-Stamping Authority round trip.</summary>
    [TestMethod]
    public async Task AddSignatureAndReferencesTimestampAsync_NoReferencesElement_NeverBillsTsa()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        var counting = new CountingFetchResponse(StubFetchResponseAsync);

        JAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<JAdESAugmentationException>(
            () => AddSignatureAndReferencesTimestampAsync(
                new JAdESReferencesFamilyTimestampContext
                {
                    WireBytes = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = "urn:test:tsa",
                    FetchResponse = counting.FetchAsync,
                    CanonAlg = "urn:test:canon",
                    Canonicalize = StubCanonicalizeAsync,
                    TargetLevel = AdESBaselineLevel.BT
                },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(JAdESAugmentationFailureKind.ReferencesElementRequired, exception.FailureKind);
        Assert.AreEqual(0, counting.CallCount);
    }


    /// <summary>A declared target level of B-LT or above refuses <c>rfsTst</c> generation before any Time-Stamping Authority round trip.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-37.
    /// </remarks>
    [TestMethod]
    public async Task AddReferencesTimestampAsync_TargetLevelBLT_NeverBillsTsa()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] withXRefs = await CreateWireBytesWithXRefsAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        var counting = new CountingFetchResponse(StubFetchResponseAsync);

        JAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<JAdESAugmentationException>(
            () => AddReferencesTimestampAsync(
                new JAdESReferencesFamilyTimestampContext
                {
                    WireBytes = withXRefs,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = "urn:test:tsa",
                    FetchResponse = counting.FetchAsync,
                    CanonAlg = "urn:test:canon",
                    Canonicalize = StubCanonicalizeAsync,
                    TargetLevel = AdESBaselineLevel.BLT
                },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(JAdESAugmentationFailureKind.ReferencesFamilyNotPermittedAtTargetLevel, exception.FailureKind);
        Assert.AreEqual(0, counting.CallCount);
    }


    /// <summary>Generation-side regression: a SECOND <c>xRefs</c> appended AFTER a <c>sigRTst</c> instance never mutates that instance's own already-committed token bytes.</summary>
    [TestMethod]
    public async Task AddSignatureAndReferencesTimestampAsync_ThenLaterXRefs_DoesNotMutateEarlierSigRTst()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] withXRefs = await CreateWireBytesWithXRefsAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] withSigRTst = await AddSignatureAndReferencesTimestampAsync(
            new JAdESReferencesFamilyTimestampContext
            {
                WireBytes = withXRefs,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "urn:test:tsa",
                FetchResponse = tsa.Responder.FetchAsync,
                CanonAlg = "urn:test:canon",
                Canonicalize = StubCanonicalizeAsync,
                TargetLevel = AdESBaselineLevel.BB
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders beforeLateAppend = DecodeUnsignedHeaders(withSigRTst);
        byte[] sigRTstTokenBefore = ExtractSigRTstTokenBytes(beforeLateAppend, 1);

        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory anotherCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate, fill: 42);

        byte[] withLateXRefs = await AddReferencesAsync(
            new JAdESReferencesContext
            {
                WireBytes = withSigRTst,
                SigningCertificate = signingCertificate,
                CertificatesToReference = [anotherCertificate],
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TargetLevel = AdESBaselineLevel.BB
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders afterLateAppend = DecodeUnsignedHeaders(withLateXRefs);
        Assert.AreEqual(3, afterLateAppend.Count, "The late xRefs must land AFTER the sigRTst (JA-5.3.1-03 append-at-end).");
        byte[] sigRTstTokenAfter = ExtractSigRTstTokenBytes(afterLateAppend, 1);

        Assert.AreSequenceEqual(sigRTstTokenBefore, sigRTstTokenAfter, "The sigRTst instance's own token bytes must be untouched by a later, unrelated append.");
    }

    /// <summary>The full B-B→B-T→B-LTA ladder: sigTst then a gap-filled arcTst over a real TSA round trip.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-42.
    /// </remarks>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_HappyPath_ReachesBLTAWithGapFill()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] withSigTst = await AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "urn:test:tsa",
                FetchResponse = tsa.Responder.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory gapFillCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);

        byte[] withArcTst = await AddArchiveTimestampAsync(
            new JAdESArchiveTimestampContext
            {
                WireBytes = withSigTst,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                PayloadSource = new JAdESRawPayloadImprintSource(new byte[] { 1, 2, 3 }),
                TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = "urn:test:tsa", FetchResponse = tsa.Responder.FetchAsync }],
                GapFillValidationMaterial = new JAdESValidationMaterial { Certificates = [gapFillCertificate] },
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                //JA-6.3-38/j: the gap-filled xVals element does not itself satisfy the "incorporation of
                //validation data for electronic time-stamps" service (only tstVD/anyValData do); attesting the
                //embedded-in-token fact satisfies it instead, matching this fixture's minted-token reality.
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = true,
                CanonAlg = "urn:test:canon",
                Canonicalize = StubCanonicalizeAsync,
                TargetLevel = AdESBaselineLevel.BLTA
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders unsignedHeaders = DecodeUnsignedHeaders(withArcTst);
        Assert.AreEqual(3, unsignedHeaders.Count, "sigTst, the gap-filled xVals, then arcTst, in that order (JA-5.3.1-03).");
        Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(unsignedHeaders[0]);
        Assert.IsInstanceOfType<JAdESUnsignedHeaderElementCertificateValues>(unsignedHeaders[1]);
        var arcTst = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementArchiveTimestamp>(unsignedHeaders[2]);
        var clear = Assert.IsInstanceOfType<JAdESClearUnsignedValue<AdESTimestampContainer>>(arcTst.Carriage);
        Assert.AreEqual("urn:test:canon", clear.Value.CanonAlg);
    }


    /// <summary>A declared target level other than B-LTA refuses before any Time-Stamping Authority round trip (JA-6.3-42).</summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_TargetLevelNotBLTA_NeverBillsTsa()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);
        var counting = new CountingFetchResponse(StubFetchResponseAsync);

        JAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<JAdESAugmentationException>(
            () => AddArchiveTimestampAsync(
                new JAdESArchiveTimestampContext
                {
                    WireBytes = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    PayloadSource = new JAdESRawPayloadImprintSource(new byte[] { 1 }),
                    TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = "urn:test:tsa", FetchResponse = counting.FetchAsync }],
                    SigningCertificate = signingCertificate,
                    ChainCompletenessAttested = true,
                    CanonAlg = "urn:test:canon",
                    Canonicalize = StubCanonicalizeAsync,
                    TargetLevel = AdESBaselineLevel.BLT
                },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(JAdESAugmentationFailureKind.ArchiveTimestampNotPermittedAtTargetLevel, exception.FailureKind);
        Assert.AreEqual(0, counting.CallCount);
    }


    /// <summary>An unattested chain-completeness fact refuses before any Time-Stamping Authority round trip (letter m, JA-6.3-m1/m2).</summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_ChainCompletenessNotAttested_NeverBillsTsa()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        //A REAL, parseable certificate: gate (3) (signing-certificate readability) runs before gate (4)
        //(ChainCompletenessAttested), so this test must clear (3) to actually exercise (4).
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var counting = new CountingFetchResponse(StubFetchResponseAsync);

        JAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<JAdESAugmentationException>(
            () => AddArchiveTimestampAsync(
                new JAdESArchiveTimestampContext
                {
                    WireBytes = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    PayloadSource = new JAdESRawPayloadImprintSource(new byte[] { 1 }),
                    TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = "urn:test:tsa", FetchResponse = counting.FetchAsync }],
                    SigningCertificate = signingCertificate,
                    ChainCompletenessAttested = false,
                    CanonAlg = "urn:test:canon",
                    Canonicalize = StubCanonicalizeAsync,
                    TargetLevel = AdESBaselineLevel.BLTA
                },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(JAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete, exception.FailureKind);
        Assert.AreEqual(0, counting.CallCount);
    }


    /// <summary>JA-6.3-26's cumulative prerequisite: no prior <c>sigTst</c> instance refuses before any Time-Stamping Authority round trip.</summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_NoSignatureTimestampInstance_NeverBillsTsa()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        //A REAL, parseable certificate: gate (3) (signing-certificate readability) runs before gate (5) (the
        //sigTst prerequisite), so this test must clear (3) to actually exercise (5).
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var counting = new CountingFetchResponse(StubFetchResponseAsync);

        JAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<JAdESAugmentationException>(
            () => AddArchiveTimestampAsync(
                new JAdESArchiveTimestampContext
                {
                    WireBytes = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    PayloadSource = new JAdESRawPayloadImprintSource(new byte[] { 1 }),
                    TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = "urn:test:tsa", FetchResponse = counting.FetchAsync }],
                    SigningCertificate = signingCertificate,
                    ChainCompletenessAttested = true,
                    CanonAlg = "urn:test:canon",
                    Canonicalize = StubCanonicalizeAsync,
                    TargetLevel = AdESBaselineLevel.BLTA
                },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(JAdESAugmentationFailureKind.ArchiveTimestampSignatureTimestampPrerequisiteMissing, exception.FailureKind);
        Assert.AreEqual(0, counting.CallCount);
    }


    /// <summary>A reference-family element still incorporated refuses arcTst generation, even though a sigTst prerequisite is satisfied, before any Time-Stamping Authority round trip.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-29.
    /// </remarks>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_ReferencesFamilyElementStillPresent_NeverBillsTsa()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] withXRefs = await CreateWireBytesWithXRefsAsync(privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] withSigTst = await AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = withXRefs,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "urn:test:tsa",
                FetchResponse = tsa.Responder.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        var counting = new CountingFetchResponse(StubFetchResponseAsync);

        JAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<JAdESAugmentationException>(
            () => AddArchiveTimestampAsync(
                new JAdESArchiveTimestampContext
                {
                    WireBytes = withSigTst,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    PayloadSource = new JAdESRawPayloadImprintSource(new byte[] { 1, 2, 3 }),
                    TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = "urn:test:tsa", FetchResponse = counting.FetchAsync }],
                    SigningCertificate = signingCertificate,
                    ChainCompletenessAttested = true,
                    CanonAlg = "urn:test:canon",
                    Canonicalize = StubCanonicalizeAsync,
                    TargetLevel = AdESBaselineLevel.BLTA
                },
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(JAdESAugmentationFailureKind.ArchiveTimestampReferencesFamilyElementPresent, exception.FailureKind);
        Assert.AreEqual(0, counting.CallCount);
    }


    /// <summary>Metered custody: the full B-B→B-T→B-LTA ladder returns every pooled rental it borrowed along the way.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult " +
            "on a successful SignAsync call, disposed here via 'using created'.")]
    [TestMethod]
    public async Task FullLadder_MeteredPool_LeavesNoOutstandingRentals()
    {
        using var metered = new MeteredHousePool();
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JAdESSignatureCreationResult created = await SignAsync(
            ConformantHeaders(), new JAdESAttachedPayloadInput(new byte[] { 1, 2, 3 }), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] baseline = Serialize(created, JoseSerializationFormat.Compact);

        byte[] withSigTst = await AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "urn:test:tsa",
                FetchResponse = tsa.Responder.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            TestContext.CancellationToken, metered.Pool).ConfigureAwait(false);

        byte[] withArcTst = await AddArchiveTimestampAsync(
            new JAdESArchiveTimestampContext
            {
                WireBytes = withSigTst,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                PayloadSource = new JAdESRawPayloadImprintSource(new byte[] { 1, 2, 3 }),
                TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = "urn:test:tsa", FetchResponse = tsa.Responder.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = true,
                CanonAlg = "urn:test:canon",
                Canonicalize = StubCanonicalizeAsync,
                TargetLevel = AdESBaselineLevel.BLTA
            },
            TestContext.CancellationToken, metered.Pool).ConfigureAwait(false);

        Assert.IsGreaterThan(0, withArcTst.Length);
        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "Every intermediate rental across the whole ladder must be returned.");
    }


    private static ValueTask<byte[]> AddSignatureTimestampAsync(JAdESSignatureTimestampContext context, CancellationToken cancellationToken, BaseMemoryPool? pool = null) =>
        JAdESSignatureAugmentation.AddSignatureTimestampAsync(
            context, JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, pool ?? BaseMemoryPool.Shared, cancellationToken);


    private static ValueTask<byte[]> AddValidationDataAsync(JAdESValidationDataContext context, CancellationToken cancellationToken, BaseMemoryPool? pool = null) =>
        JAdESSignatureAugmentation.AddValidationDataAsync(
            context, JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, pool ?? BaseMemoryPool.Shared, cancellationToken);


    private static ValueTask<byte[]> AddReferencesAsync(JAdESReferencesContext context, CancellationToken cancellationToken, BaseMemoryPool? pool = null) =>
        JAdESSignatureAugmentation.AddReferencesAsync(
            context, JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, pool ?? BaseMemoryPool.Shared, cancellationToken);


    private static ValueTask<byte[]> AddSignatureAndReferencesTimestampAsync(JAdESReferencesFamilyTimestampContext context, CancellationToken cancellationToken, BaseMemoryPool? pool = null) =>
        JAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync(
            context, JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, pool ?? BaseMemoryPool.Shared, cancellationToken);


    private static ValueTask<byte[]> AddReferencesTimestampAsync(JAdESReferencesFamilyTimestampContext context, CancellationToken cancellationToken, BaseMemoryPool? pool = null) =>
        JAdESSignatureAugmentation.AddReferencesTimestampAsync(
            context, JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, pool ?? BaseMemoryPool.Shared, cancellationToken);


    private static ValueTask<byte[]> AddArchiveTimestampAsync(JAdESArchiveTimestampContext context, CancellationToken cancellationToken, BaseMemoryPool? pool = null) =>
        JAdESSignatureAugmentation.AddArchiveTimestampAsync(
            context, JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, pool ?? BaseMemoryPool.Shared, cancellationToken);


    private static ValueTask<JAdESSignatureCreationResult> SignAsync(
        JAdESProtectedHeaders headers, JAdESSigningPayloadInput payloadInput, JAdESUnsignedHeaders? unsignedHeaders,
        PrivateKeyMemory privateKey, CancellationToken cancellationToken) =>
        JAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders,
            JAdESProtectedHeaderJson.Encode, JAdESEtsiUJson.Encode, TestSetup.Base64UrlEncoder,
            privateKey, MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, cancellationToken: cancellationToken);


    private static byte[] Serialize(JAdESSignatureCreationResult result, JoseSerializationFormat format) =>
        JAdESSignatureCreation.Serialize(result, format, TestSetup.Base64UrlEncoder, JsonSerialize);


    /// <summary>Signs and serializes a conformant B-B signature over a fixed attached payload, no <c>etsiU</c>.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult " +
            "on a successful SignAsync call, disposed here via 'using created'.")]
    private static async ValueTask<byte[]> CreateBaselineWireBytesAsync(PrivateKeyMemory privateKey, CancellationToken cancellationToken)
    {
        using JAdESSignatureCreationResult created = await SignAsync(
            ConformantHeaders(), new JAdESAttachedPayloadInput(new byte[] { 1, 2, 3 }), unsignedHeaders: null, privateKey, cancellationToken).ConfigureAwait(false);

        return Serialize(created, JoseSerializationFormat.Compact);
    }


    /// <summary>Signs, serializes, then augments with one <c>xRefs</c> element — the shared fixture the sigRTst/rfsTst/arcTst-refusal tests build on.</summary>
    private static async ValueTask<byte[]> CreateWireBytesWithXRefsAsync(PrivateKeyMemory privateKey, CancellationToken cancellationToken)
    {
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, cancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory referencedCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate, fill: 7);

        return await AddReferencesAsync(
            new JAdESReferencesContext
            {
                WireBytes = baseline,
                SigningCertificate = signingCertificate,
                CertificatesToReference = [referencedCertificate],
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TargetLevel = AdESBaselineLevel.BB
            },
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Signs, serializes, then raises to B-T with a real TSA round trip — the shared fixture the B-LT-targeted xVals/rVals/anyValData tests build on (JA-6.3-26's cumulative sigTst-from-B-T floor applies to every level-B-T-or-above call, not only ones that add sigTst itself).</summary>
    private static async ValueTask<byte[]> CreateWireBytesWithSigTstAsync(PrivateKeyMemory privateKey, TsaFixture tsa, CancellationToken cancellationToken)
    {
        byte[] baseline = await CreateBaselineWireBytesAsync(privateKey, cancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();

        return await AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "urn:test:tsa",
                FetchResponse = tsa.Responder.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            cancellationToken).ConfigureAwait(false);
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TestDigest()'s ownership transfers into the returned JAdESProtectedHeaders; every " +
            "caller disposes that return value via its own 'using' declaration.")]
    private static JAdESProtectedHeaders ConformantHeaders() =>
        new(
            WellKnownJwaValues.Es256,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            x5tHashS256: TestDigest());


    private static DigestValue TestDigest()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[32].CopyTo(owner.Memory);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    /// <summary>Parses <paramref name="wireBytes"/> and decodes its <c>etsiU</c> set; the caller disposes the result.</summary>
    private static JAdESUnsignedHeaders DecodeUnsignedHeaders(byte[] wireBytes)
    {
        bool parsed = JAdESMessageJson.TryParse(wireBytes, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out UnverifiedJAdESMessage? message, out _);
        Assert.IsTrue(parsed, "The augmented wire bytes must remain parseable.");

        using(message)
        {
            Assert.IsNotNull(message!.EtsiURawBytes, "An augmentation verb always leaves an etsiU member behind.");

            bool etsiUParsed = JAdESEtsiUJson.TryParse(
                message.EtsiURawBytes!.AsReadOnlySpan(), TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? unsignedHeaders);
            Assert.IsTrue(etsiUParsed);

            return unsignedHeaders!;
        }
    }


    /// <summary>Extracts the sole token's own <c>val</c> bytes from the <c>sigTst</c> element at <paramref name="index"/>, as a fresh array (independent of <paramref name="unsignedHeaders"/>'s own lifetime).</summary>
    private static byte[] ExtractSigTstTokenBytes(JAdESUnsignedHeaders unsignedHeaders, int index)
    {
        var element = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(unsignedHeaders[index]);
        var clear = Assert.IsInstanceOfType<JAdESClearUnsignedValue<AdESTimestampContainer>>(element.Carriage);

        return clear.Value.TstTokens[0].Val.ToArray();
    }


    /// <summary>Extracts the sole token's own <c>val</c> bytes from the <c>sigRTst</c> element at <paramref name="index"/>, as a fresh array.</summary>
    private static byte[] ExtractSigRTstTokenBytes(JAdESUnsignedHeaders unsignedHeaders, int index)
    {
        var element = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp>(unsignedHeaders[index]);
        var clear = Assert.IsInstanceOfType<JAdESClearUnsignedValue<AdESTimestampContainer>>(element.Carriage);

        return clear.Value.TstTokens[0].Val.ToArray();
    }


    /// <summary>Rents pool memory of the given tag and a fixed 4-byte fill, for a PKI-object-shaped carrier fixture. The content is never DER-parsed by <see cref="JAdESSignatureAugmentation"/> (only the tag-based kind check and byte-equality dedup/self-reference checks consult it), so an arbitrary fill distinguishes otherwise-identical carriers.</summary>
    private static PkiCertificateMemory CreatePkiCarrier(Tag tag, byte fill = 1)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(4);
        new byte[] { fill, fill, fill, fill }.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>Copies <paramref name="source"/>, replacing only its wire bytes, so a second time-stamp runs over the first call's output under otherwise identical settings.</summary>
    private static JAdESSignatureTimestampContext WithWireBytes(JAdESSignatureTimestampContext source, ReadOnlyMemory<byte> wireBytes) =>
        new()
        {
            WireBytes = wireBytes,
            MessageImprintAlgorithm = source.MessageImprintAlgorithm,
            TsaUri = source.TsaUri,
            FetchResponse = source.FetchResponse,
            ReqPolicyOid = source.ReqPolicyOid,
            NonceByteLength = source.NonceByteLength,
            IncludeNonce = source.IncludeNonce,
            SigningCertificate = source.SigningCertificate,
            SigningCertificateRevokedAt = source.SigningCertificateRevokedAt,
            EnforceSigningCertificateValidity = source.EnforceSigningCertificateValidity,
            TargetLevel = source.TargetLevel
        };


    /// <summary>A canonicalization stub sufficient to exercise the clear-JSON message-imprint path without depending on <c>Verifiable.Json</c>'s own canonicalization semantics (tested separately at <c>JAdESMessageImprintTests</c>).</summary>
    private static ValueTask<PooledMemory> StubCanonicalizeAsync(string canonAlg, JAdESUnsignedHeaderElement element, BaseMemoryPool pool, CancellationToken cancellationToken) =>
        ValueTask.FromResult(PooledMemory.FromBytes(System.Text.Encoding.UTF8.GetBytes(element.Kind), pool, CryptoTags.JAdESMessageImprintInput));


    /// <summary>A transport stub that never actually runs (every test using it either never calls acquisition, or fails before reaching it).</summary>
    private static ValueTask<PkiCertificateMemory?> StubFetchResponseAsync(
        TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken) =>
        ValueTask.FromResult<PkiCertificateMemory?>(null);


    private static byte[] JsonSerialize(object value) => JsonSerializer.SerializeToUtf8Bytes(value);


    /// <summary>Counts how many times the wrapped <see cref="FetchTimestampResponseAsyncDelegate"/> is invoked — the never-bills-a-doomed-call proof.</summary>
    private sealed class CountingFetchResponse(FetchTimestampResponseAsyncDelegate inner)
    {
        public int CallCount { get; private set; }

        public ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            ++CallCount;

            return inner(context, pool, cancellationToken);
        }
    }


    /// <summary>A genuine in-process Time-Stamping Authority: a root CA, a TSA leaf certificate under it, and <see cref="MintingTimestampResponder"/> minting real RFC 3161 tokens over whatever message imprint a call sends — no network socket involved.</summary>
    private sealed class TsaFixture: IDisposable
    {
        private X509ChainTestRingNode Root { get; }
        private X509ChainTestRingNode Authority { get; }

        public MintingTimestampResponder Responder { get; }


        private TsaFixture(X509ChainTestRingNode root, X509ChainTestRingNode authority, MintingTimestampResponder responder)
        {
            this.Root = root;
            this.Authority = authority;
            Responder = responder;
        }


        public static TsaFixture Create(CancellationToken cancellationToken)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider);
            var responder = new MintingTimestampResponder(authority, [authority, root], timeProvider.GetUtcNow());

            return new TsaFixture(root, authority, responder);
        }


        /// <summary>A DER-encoded X.509 certificate carrier (the root's own) suitable for the augmentation contexts' <c>SigningCertificate</c> field — a REAL certificate, since the readability/validity-window checks actually parse it.</summary>
        public PkiCertificateMemory SignerCertificate() => OcspTestFixtures.ToCertificateCarrier(Root.Certificate);


        public void Dispose()
        {
            Authority.Dispose();
            Root.Dispose();
        }
    }
}
