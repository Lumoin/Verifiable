using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Formats.Cbor;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Smoke-level construction and wiring tests for the CB-AdES augmentation orchestrator
/// (<see cref="CBAdESSignatureAugmentation"/>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// Behavioral coverage (TSA round trips through a real Time-Stamping Authority, byte-exact message-imprint
/// vectors, level-rule interaction across a real signed-then-augmented signature) is out of scope here,
/// covered elsewhere in this suite. This file validates only that every context record this
/// orchestrator declares constructs and round-trips its properties, that the two source-union constructor
/// invariants hold, and that the fail-closed parse path integrates with the REAL <see cref="Verifiable.Cbor"/>
/// implementation of <see cref="ParseCBAdESSign1Delegate"/> (never a hand-rolled stub) end to end.
/// </remarks>
[TestClass]
internal sealed class CBAdESSignatureAugmentationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>The classified constructor carries the supplied <see cref="CBAdESAugmentationFailureKind"/> and message.</summary>
    [TestMethod]
    public void CBAdESAugmentationException_ClassifiedConstructor_CarriesFailureKindAndMessage()
    {
        var exception = new CBAdESAugmentationException(CBAdESAugmentationFailureKind.ReferencesElementRequired, "a message");

        Assert.AreEqual(CBAdESAugmentationFailureKind.ReferencesElementRequired, exception.FailureKind);
        Assert.AreEqual("a message", exception.Message);
    }


    /// <summary>The parameterless constructor classifies as <see cref="CBAdESAugmentationFailureKind.MalformedEncoding"/>, mirroring the CAdES exemplar's default.</summary>
    [TestMethod]
    public void CBAdESAugmentationException_DefaultConstructor_ClassifiesAsMalformedEncoding()
    {
        var exception = new CBAdESAugmentationException();

        Assert.AreEqual(CBAdESAugmentationFailureKind.MalformedEncoding, exception.FailureKind);
    }


    /// <summary><see cref="CBAdESValidationMaterial.None"/> names nothing to place.</summary>
    [TestMethod]
    public void CBAdESValidationMaterial_None_IsEmpty()
    {
        Assert.IsTrue(CBAdESValidationMaterial.None.IsEmpty);
    }


    /// <summary>Material carrying at least one certificate is not empty.</summary>
    [TestMethod]
    public void CBAdESValidationMaterial_WithCertificate_IsNotEmpty()
    {
        using PkiCertificateMemory certificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);
        var material = new CBAdESValidationMaterial { Certificates = [certificate] };

        Assert.IsFalse(material.IsEmpty);
    }


    /// <summary><see cref="CBAdESSignatureTimestampContext"/> constructs and its optional members carry the documented defaults.</summary>
    [TestMethod]
    public void CBAdESSignatureTimestampContext_Construction_CarriesDocumentedDefaults()
    {
        var context = new CBAdESSignatureTimestampContext
        {
            WireBytes = new byte[] { 1, 2, 3 },
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            TsaUri = "https://tsa.example/",
            FetchResponse = StubFetchResponseAsync,
            TargetLevel = AdESBaselineLevel.BT
        };

        Assert.AreEqual(AdESBaselineLevel.BT, context.TargetLevel);
        Assert.AreEqual(32, context.NonceByteLength);
        Assert.IsTrue(context.IncludeNonce);
        Assert.IsTrue(context.EnforceSigningCertificateValidity);
        Assert.IsNull(context.SigningCertificate);
    }


    /// <summary>The attached-payload acquisition source arm carries its bytes.</summary>
    [TestMethod]
    public void CBAdESPayloadTimestampAcquisitionContext_AttachedSource_Construction_CarriesSource()
    {
        var context = new CBAdESPayloadTimestampAcquisitionContext
        {
            Source = new CBAdESAttachedPayloadTimestampAcquisitionSource(new byte[] { 1 }),
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha384,
            TsaUri = "https://tsa.example/",
            FetchResponse = StubFetchResponseAsync
        };

        Assert.IsInstanceOfType<CBAdESAttachedPayloadTimestampAcquisitionSource>(context.Source);
        Assert.IsNull(context.Dereference);
    }


    /// <summary>CB-5.2.8-06: the sigD-referenced acquisition source refuses an empty reference list.</summary>
    [TestMethod]
    public void CBAdESSigDReferencedPayloadTimestampAcquisitionSource_EmptyReferences_Throws()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESSigDReferencedPayloadTimestampAcquisitionSource([]));
    }


    /// <summary>The sigD-referenced acquisition source carries its references, in order.</summary>
    [TestMethod]
    public void CBAdESSigDReferencedPayloadTimestampAcquisitionSource_Construction_CarriesReferences()
    {
        var source = new CBAdESSigDReferencedPayloadTimestampAcquisitionSource(["urn:example:one", "urn:example:two"]);

        Assert.HasCount(2, source.References);
        Assert.AreEqual("urn:example:one", source.References[0]);
    }


    /// <summary><see cref="CBAdESValidationDataContext"/> constructs and defaults <see cref="CBAdESValidationDataContext.DeduplicateAgainstExisting"/> to <see langword="true"/>.</summary>
    [TestMethod]
    public void CBAdESValidationDataContext_Construction_DefaultsDeduplicateToTrue()
    {
        using PkiCertificateMemory certificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);
        var context = new CBAdESValidationDataContext
        {
            WireBytes = new byte[] { 1 },
            Material = new CBAdESValidationMaterial { Certificates = [certificate] },
            TargetLevel = AdESBaselineLevel.BLT
        };

        Assert.IsTrue(context.DeduplicateAgainstExisting);
        Assert.AreEqual(AdESBaselineLevel.BLT, context.TargetLevel);
    }


    /// <summary><see cref="CBAdESReferencesFamilyTimestampContext"/> constructs and round-trips its target level.</summary>
    [TestMethod]
    public void CBAdESReferencesFamilyTimestampContext_Construction_RoundTripsTargetLevel()
    {
        var context = new CBAdESReferencesFamilyTimestampContext
        {
            WireBytes = new byte[] { 1 },
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha512,
            TsaUri = "https://tsa.example/",
            FetchResponse = StubFetchResponseAsync,
            TargetLevel = AdESBaselineLevel.BB
        };

        Assert.AreEqual(AdESBaselineLevel.BB, context.TargetLevel);
    }


    /// <summary><see cref="CBAdESReferencesContext"/> constructs with only the required members and every optional list absent.</summary>
    [TestMethod]
    public void CBAdESReferencesContext_Construction_OptionalListsAbsentByDefault()
    {
        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(PkiCertificateTags.X509Certificate);
        var context = new CBAdESReferencesContext
        {
            WireBytes = new byte[] { 1 },
            SigningCertificate = signingCertificate,
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            TargetLevel = AdESBaselineLevel.BB
        };

        Assert.IsNull(context.CertificatesToReference);
        Assert.IsNull(context.CrlsToReference);
        Assert.IsNull(context.OcspResponsesToReference);
    }


    /// <summary><see cref="CBAdESOcspReferenceInput"/> constructs and carries both members.</summary>
    [TestMethod]
    public void CBAdESOcspReferenceInput_Construction_CarriesResponseAndIdentifier()
    {
        using PkiCertificateMemory response = CreatePkiCarrier(PkiCertificateTags.OcspResponse);
        var identifier = new CBAdESOcspIdentifier(
            new CBAdESOcspResponderIdentifierByName(new byte[] { 1 }), DateTimeOffset.UnixEpoch);

        var input = new CBAdESOcspReferenceInput(response, identifier);

        Assert.AreEqual(response, input.Response);
        Assert.AreEqual(identifier, input.Identifier);
    }


    /// <summary><see cref="CBAdESStripReferencesContext"/> constructs and round-trips its target level.</summary>
    [TestMethod]
    public void CBAdESStripReferencesContext_Construction_RoundTripsTargetLevel()
    {
        var context = new CBAdESStripReferencesContext { WireBytes = new byte[] { 1 }, TargetLevel = AdESBaselineLevel.BLT };

        Assert.AreEqual(AdESBaselineLevel.BLT, context.TargetLevel);
    }


    /// <summary>
    /// A malformed input signature (a caller composition fault for augmentation, per the class remarks) is
    /// reported as <see cref="CBAdESAugmentationFailureKind.MalformedEncoding"/> — exercised through the REAL
    /// <see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/> implementation (never a hand-rolled parse
    /// stub), confirming <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/> integrates with
    /// it end to end.
    /// </summary>
    [TestMethod]
    public void StripReferencesForLongTerm_MalformedWireBytes_ThrowsMalformedEncoding()
    {
        var context = new CBAdESStripReferencesContext
        {
            WireBytes = new byte[] { 0xFF, 0x00, 0x01 },
            TargetLevel = AdESBaselineLevel.BLT
        };

        CBAdESAugmentationException exception = Assert.ThrowsExactly<CBAdESAugmentationException>(() =>
            CBAdESSignatureAugmentation.StripReferencesForLongTerm(
                context,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                BaseMemoryPool.Shared));

        Assert.AreEqual(CBAdESAugmentationFailureKind.MalformedEncoding, exception.FailureKind);
    }


    /// <summary>
    /// Table 14 additional requirement (d) enforcement requires a signing certificate when enforcement is
    /// requested (the default) — refused before any Time-Stamping Authority round trip.
    /// </summary>
    [TestMethod]
    public void CBAdESSignatureTimestampContext_EnforceValidityWithNoCertificate_IsRepresentableButRefusedLater()
    {
        //Construction itself does not enforce the pairing (SigningCertificate is independently optional per
        //the type) -- EnsureSigningCertificateValidAtTimestamp (private to the orchestrator) is what refuses
        //this combination once AddSignatureTimestampAsync runs; this smoke test only confirms the context
        //remains constructible so a caller can express "enforce, but forgot the certificate" and have THAT
        //call refuse it, rather than the type itself.
        var context = new CBAdESSignatureTimestampContext
        {
            WireBytes = new byte[] { 1 },
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            TsaUri = "https://tsa.example/",
            FetchResponse = StubFetchResponseAsync,
            TargetLevel = AdESBaselineLevel.BT
        };

        Assert.IsTrue(context.EnforceSigningCertificateValidity);
        Assert.IsNull(context.SigningCertificate);
    }


    // CB-6.3-c: sigTst append round trip, through the shipped Time-Stamping Authority client, over a genuine
    // BC-minted token, verified independently.

    /// <summary>
    /// <see cref="CBAdESSignatureAugmentation.AddSignatureTimestampAsync"/> appends exactly one <c>sigTst</c>
    /// element encapsulating exactly one genuine, correctly-bound RFC 3161 token (CB-6.3-c), which the
    /// independent BouncyCastle validator accepts under the authority's own certificate, and which the shipped
    /// level-aware <see cref="CBAdESSignatureValidation.ValidateAsync"/> reports valid at level B-T.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_AppendsOneConformantSigTst_VerifiesIndependentlyAndValidatesAtLevelBT()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(tsa.Root.Certificate.RawData);
            var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(1));

            byte[] augmentedWireBytes;
            byte[] mintedTokenBytes;
            using(EncodedCoseSign1 augmented = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = wireBytes,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = "https://tsa.example/",
                    FetchResponse = responder.FetchAsync,
                    SigningCertificate = signingCertificate,
                    TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                augmentedWireBytes = augmented.AsReadOnlySpan().ToArray();
            }

            CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(augmentedWireBytes, BaseMemoryPool.Shared);
            using(parsed)
            {
                Assert.IsTrue(parsed.IsSuccess);
                Assert.HasCount(1, parsed.UnsignedHeaders!);
                var sigTstElement = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementSignatureTimestamp>(parsed.UnsignedHeaders![0]);
                Assert.HasCount(1, sigTstElement.SignatureTimestamp.TimestampContainer.TstTokens, "CB-6.3-c: exactly one token per sigTst instance.");
                mintedTokenBytes = sigTstElement.SignatureTimestamp.TimestampContainer.TstTokens[0].Val.ToArray();
            }

            using PkiCertificateMemory tokenCarrier = ToTokenCarrier(mintedTokenBytes);
            Assert.IsTrue(X509ChainTestRingTimestamping.VerifiesUnderAuthorityCertificate(tokenCarrier, tsa.Authority),
                "The attached token is the one the authority signed, and the independent oracle accepts it under the authority's certificate.");

            using CBAdESValidationResult validation = await CBAdESSignatureValidation.ValidateAsync(
                augmentedWireBytes, CBAdESSignatureSerialization.ParseCBAdESSign1, CoseSerialization.BuildSigStructure, publicKey,
                dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
                AdESBaselineLevel.BT,
                CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(validation.IsValid, "The round-tripped, augmented signature must validate at level B-T.");
        }
    }


    /// <summary>
    /// A leak regression: a pre-existing leak reproduced elsewhere in the suite — the level-aware <see cref="CBAdESSignatureValidation.ValidateAsync"/> SUCCESS path must return
    /// every pooled carrier it rents when the protected headers carry <c>x5t</c>. A single genuine
    /// <c>sigTst</c> instance (no <c>arcTst</c>) validated at the declared level <see cref="AdESBaselineLevel.BB"/>
    /// — below <see cref="AdESBaselineLevel.BT"/>, so neither the cumulative-<c>sigTst</c>-count check nor the
    /// per-token signer-certificate-coverage check (gated from B-LT onward) runs — is the minimal shape that
    /// isolates the leak from every other level-scoped code path.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncWithLevel_SuccessPathWithX5tAndSingleSigTst_DeclaredLevelBB_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(tsa.Root.Certificate.RawData);
            var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(1));

            byte[] augmentedWireBytes;
            using(EncodedCoseSign1 augmented = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = wireBytes,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = "https://tsa.example/",
                    FetchResponse = responder.FetchAsync,
                    SigningCertificate = signingCertificate,
                    TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                augmentedWireBytes = augmented.AsReadOnlySpan().ToArray();
            }

            using var metered = new MeteredHousePool();

            using(CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
                augmentedWireBytes, CBAdESSignatureSerialization.ParseCBAdESSign1, CoseSerialization.BuildSigStructure, publicKey,
                dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
                AdESBaselineLevel.BB,
                CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
                metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
            {
                Assert.IsTrue(result.IsValid, "A single genuine sigTst at a declared level below B-T is a soft-negative presence, not a violation.");
            }

            Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised by the call under test, or the balance assertion below is vacuous.");
            Assert.AreEqual(0, metered.OutstandingCount,
                "The level-aware ValidateAsync success path must not leak a pooled digest carrier when the protected headers carry x5t.");
        }
    }


    /// <summary>
    /// Two successive <see cref="CBAdESSignatureAugmentation.AddSignatureTimestampAsync"/> calls (Table 14
    /// note 7's multi-Time-Stamping-Authority pattern) append TWO sibling <c>sigTst</c> elements, each still
    /// encapsulating exactly one token (CB-6.3-c) — never a second token folded into the first instance.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_CalledTwice_AppendsTwoDistinctSigTstInstancesEachWithOneToken()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(tsa.Root.Certificate.RawData);
            var firstResponder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(1));

            byte[] onceAugmented;
            using(EncodedCoseSign1 augmented = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/one/",
                    FetchResponse = firstResponder.FetchAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                onceAugmented = augmented.AsReadOnlySpan().ToArray();
            }

            var secondResponder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(2));
            byte[] twiceAugmented;
            using(EncodedCoseSign1 augmented = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = onceAugmented, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/two/",
                    FetchResponse = secondResponder.FetchAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                twiceAugmented = augmented.AsReadOnlySpan().ToArray();
            }

            CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(twiceAugmented, BaseMemoryPool.Shared);
            using(parsed)
            {
                Assert.IsTrue(parsed.IsSuccess);
                Assert.HasCount(2, parsed.UnsignedHeaders!, "Multi-TSA is repeated calls appending sibling elements (Table 14 note 7).");
                var first = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementSignatureTimestamp>(parsed.UnsignedHeaders![0]);
                var second = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementSignatureTimestamp>(parsed.UnsignedHeaders![1]);
                Assert.HasCount(1, first.SignatureTimestamp.TimestampContainer.TstTokens, "CB-6.3-c holds for the first instance too.");
                Assert.HasCount(1, second.SignatureTimestamp.TimestampContainer.TstTokens, "CB-6.3-c holds for the second instance too.");
                Assert.IsFalse(
                    first.SignatureTimestamp.TimestampContainer.TstTokens[0].Val.Span.SequenceEqual(second.SignatureTimestamp.TimestampContainer.TstTokens[0].Val.Span),
                    "The two calls minted genuinely distinct tokens (different generation times).");
            }
        }
    }


    /// <summary>
    /// The legal arm: appending a second <c>sigTst</c> instance (multi-TSA, Table 14
    /// note 7) at <see cref="AdESBaselineLevel.BT"/> over a signature that already carries one succeeds — the
    /// TargetLevel guard refuses only B-LT and above, never B-B/B-T.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_TargetLevelBTWithExistingSigTst_Succeeds()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(tsa.Root.Certificate.RawData);
            var firstResponder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(1));

            byte[] withOneSigTst;
            using(EncodedCoseSign1 augmented = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/one/",
                    FetchResponse = firstResponder.FetchAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                withOneSigTst = augmented.AsReadOnlySpan().ToArray();
            }

            var secondResponder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(2));

            byte[] withTwoSigTsts;
            using(EncodedCoseSign1 augmented = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = withOneSigTst, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/two/",
                    FetchResponse = secondResponder.FetchAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                withTwoSigTsts = augmented.AsReadOnlySpan().ToArray();
            }

            CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(withTwoSigTsts, BaseMemoryPool.Shared);
            using(parsed)
            {
                Assert.IsTrue(parsed.IsSuccess);
                Assert.HasCount(2, parsed.UnsignedHeaders!, "The legal arm: a second sigTst appended at TargetLevel=BT succeeds.");
            }
        }
    }


    /// <summary>
    /// The strict arm: <see cref="CBAdESSignatureAugmentation.AddSignatureTimestampAsync"/>
    /// at <see cref="AdESBaselineLevel.BLT"/> throws
    /// <see cref="CBAdESAugmentationFailureKind.SignatureTimestampNotPermittedAtTargetLevel"/> BEFORE any
    /// digest computation or Time-Stamping Authority round trip — nothing is appended (the caller's own wire
    /// bytes are read, never mutated), the responder is never contacted, and every parse-side carrier rented
    /// before the refusal is disposed, matching every sibling refusal test's own
    /// <see cref="MeteredHousePool"/>/zero-outstanding shape.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_TargetLevelBLT_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        byte[] originalWireBytes = (byte[])wireBytes.Clone();
        using(publicKey)
        using(privateKey)
        {
            var responder = new CallCountingTimestampResponder();
            using var metered = new MeteredHousePool();
            var context = new CBAdESSignatureTimestampContext
            {
                WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                FetchResponse = responder.FetchAsync, TargetLevel = AdESBaselineLevel.BLT
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.SignatureTimestampNotPermittedAtTargetLevel, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "TargetLevel >= B-LT must never contact a Time-Stamping Authority.");
            Assert.IsTrue(originalWireBytes.AsSpan().SequenceEqual(wireBytes), "The caller's own wire bytes are never mutated by a refused call.");
            Assert.AreEqual(0, metered.OutstandingCount, "Every parse carrier rented before the pre-check refusal must be disposed.");
        }
    }


    /// <summary>
    /// A signing-certificate carrier tagged with a non-certificate <see cref="PkiObjectKind"/> is
    /// refused as <see cref="CBAdESAugmentationFailureKind.SigningCertificateMalformed"/> before any digest
    /// computation or Time-Stamping Authority round trip — the kind-tag check runs ahead of even
    /// <see cref="CertificateValidityPeriod.TryRead"/>, so the responder is never invoked and the metered pool
    /// balances exactly.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_SigningCertificateWrongKindCarrier_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            IMemoryOwner<byte> wrongKindOwner = BaseMemoryPool.Shared.Rent(3);
            new byte[] { 0x01, 0x02, 0x03 }.CopyTo(wrongKindOwner.Memory.Span);
            using var wrongKindCarrier = new PkiCertificateMemory(wrongKindOwner, PkiCertificateTags.TimestampToken);

            var responder = new CallCountingTimestampResponder();
            using var metered = new MeteredHousePool();
            var context = new CBAdESSignatureTimestampContext
            {
                WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                FetchResponse = responder.FetchAsync, SigningCertificate = wrongKindCarrier, TargetLevel = AdESBaselineLevel.BT
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.SigningCertificateMalformed, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "A wrong-kind signing-certificate carrier must never reach the Time-Stamping Authority.");
            Assert.AreEqual(0, metered.OutstandingCount, "Every parse carrier rented before the pre-check refusal must be disposed.");
        }
    }


    /// <summary>
    /// A signing certificate whose <c>issuer</c> field is a NULL TLV rather than a SEQUENCE (the
    /// shape-strictness regression above) fails <see cref="CertificateValidityPeriod.TryRead"/> and is
    /// refused as <see cref="CBAdESAugmentationFailureKind.SigningCertificateMalformed"/> before any digest
    /// computation or Time-Stamping Authority round trip — the responder is never invoked and the metered pool
    /// balances exactly.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_NullIssuerSigningCertificate_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(PkiCertificateMemory signingCertificate = BuildNullIssuerCertificate())
        {
            var responder = new CallCountingTimestampResponder();
            using var metered = new MeteredHousePool();
            var context = new CBAdESSignatureTimestampContext
            {
                WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                FetchResponse = responder.FetchAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.SigningCertificateMalformed, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "An unreadable signing certificate must never reach the Time-Stamping Authority.");
            Assert.AreEqual(0, metered.OutstandingCount, "Every parse carrier rented before the pre-check refusal must be disposed.");
        }
    }


    // Table 14 additional requirement (d): the acquired token's genTime must precede the signing
    // certificate's expiry and any known revocation instant, or the call refuses -- nothing appended, the
    // acquired token disposed, the metered pool balanced.

    /// <summary>
    /// Requirement (d): a genuine token whose <c>genTime</c> falls AFTER the signing certificate's own
    /// <c>notAfter</c> is refused as <see cref="CBAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp"/>
    /// — nothing is appended, and the metered pool shows every rented carrier (the acquired token, the parse
    /// and digest buffers) returned exactly once.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_TokenGenTimeAfterCertificateExpiry_ThrowsTypedFailure_NothingAppended_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            using X509ChainTestRingNode narrowCert = X509ChainTestRing.CreateRootCa(
                new FakeTimeProvider(TestClock.CanonicalEpoch),
                subjectCn: "Narrow Validity Signing Certificate",
                notBefore: TestClock.CanonicalEpoch.AddDays(-1),
                notAfter: TestClock.CanonicalEpoch.AddDays(1));
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(narrowCert.Certificate.RawData);

            //genTime (canonical epoch + 2 days) falls one day after the certificate's own notAfter.
            var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddDays(2));

            using var metered = new MeteredHousePool();
            var context = new CBAdESSignatureTimestampContext
            {
                WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                FetchResponse = responder.FetchAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp, exception.FailureKind);
            Assert.AreEqual(0, metered.OutstandingCount,
                "The acquired token and every parse/digest carrier must be disposed on this refused path -- nothing appended, nothing leaked.");
        }
    }


    /// <summary>
    /// Requirement (d), lower edge: a genuine token whose <c>genTime</c> falls BEFORE the
    /// signing certificate's own <c>notBefore</c> is refused as
    /// <see cref="CBAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp"/> too -- the validity
    /// window is a two-sided check, not just an expiry check -- and the metered pool balances exactly like
    /// the <c>notAfter</c> upper-edge twin above.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_TokenGenTimeBeforeCertificateNotBefore_ThrowsTypedFailure_NothingAppended_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            using X509ChainTestRingNode narrowCert = X509ChainTestRing.CreateRootCa(
                new FakeTimeProvider(TestClock.CanonicalEpoch),
                subjectCn: "Narrow Validity Signing Certificate Lower Edge",
                notBefore: TestClock.CanonicalEpoch.AddDays(1),
                notAfter: TestClock.CanonicalEpoch.AddDays(3));
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(narrowCert.Certificate.RawData);

            //genTime (canonical epoch) falls one day before the certificate's own notBefore (epoch + 1 day).
            var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch);

            using var metered = new MeteredHousePool();
            var context = new CBAdESSignatureTimestampContext
            {
                WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                FetchResponse = responder.FetchAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp, exception.FailureKind);
            Assert.AreEqual(0, metered.OutstandingCount,
                "The acquired token and every parse/digest carrier must be disposed on this refused path too -- nothing appended, nothing leaked.");
        }
    }


    /// <summary>
    /// Requirement (d): a genuine token whose <c>genTime</c> falls AT OR AFTER the caller-supplied revocation
    /// instant is refused as <see cref="CBAdESAugmentationFailureKind.SigningCertificateRevokedBeforeTimestamp"/>
    /// — nothing is appended, and the metered pool balances.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_TokenGenTimeAtOrAfterRevocationInstant_ThrowsTypedFailure_NothingAppended_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(tsa.Root.Certificate.RawData);

            //genTime (canonical epoch + 2 hours) falls after the caller-supplied revocation instant (epoch + 1 hour).
            var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(2));

            using var metered = new MeteredHousePool();
            var context = new CBAdESSignatureTimestampContext
            {
                WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                FetchResponse = responder.FetchAsync, SigningCertificate = signingCertificate,
                SigningCertificateRevokedAt = TestClock.CanonicalEpoch.AddHours(1), TargetLevel = AdESBaselineLevel.BT
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.SigningCertificateRevokedBeforeTimestamp, exception.FailureKind);
            Assert.AreEqual(0, metered.OutstandingCount, "This refused path must leave the metered pool exactly balanced too.");
        }
    }


    // CB-A.1.2.1-03/CB-A.1.2.2-03: the sigRTst/rfsTst generation gate refuses BEFORE any Time-Stamping
    // Authority round trip when no refs element precedes it.

    /// <summary>
    /// CB-A.1.2.1-03: <see cref="CBAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync"/> refuses
    /// with <see cref="CBAdESAugmentationFailureKind.ReferencesElementRequired"/> when no <c>refs</c> element
    /// precedes it, and the gate is checked BEFORE the transport delegate is ever invoked.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureAndReferencesTimestampAsync_NoPrecedingReferences_ThrowsReferencesElementRequired_NeverContactsAuthority()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            var responder = new CallCountingTimestampResponder();
            var context = new CBAdESReferencesFamilyTimestampContext
            {
                WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                FetchResponse = responder.FetchAsync, TargetLevel = AdESBaselineLevel.BT
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                    CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                    BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.ReferencesElementRequired, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "A doomed sigRTst call must never bill a Time-Stamping Authority round trip.");
        }
    }


    /// <summary>
    /// CB-A.1.2.2-03: <see cref="CBAdESSignatureAugmentation.AddReferencesTimestampAsync"/> refuses with
    /// <see cref="CBAdESAugmentationFailureKind.ReferencesElementRequired"/> when no <c>refs</c> element
    /// precedes it, and the gate is checked BEFORE the transport delegate is ever invoked.
    /// </summary>
    [TestMethod]
    public async Task AddReferencesTimestampAsync_NoPrecedingReferences_ThrowsReferencesElementRequired_NeverContactsAuthority()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            var responder = new CallCountingTimestampResponder();
            var context = new CBAdESReferencesFamilyTimestampContext
            {
                WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                FetchResponse = responder.FetchAsync, TargetLevel = AdESBaselineLevel.BT
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddReferencesTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                    CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                    BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.ReferencesElementRequired, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "A doomed rfsTst call must never bill a Time-Stamping Authority round trip.");
        }
    }


    // CB-A.1.1-02: refs shall not reference the signature's own signing certificate.

    /// <summary>
    /// CB-A.1.1-02: <see cref="CBAdESSignatureAugmentation.AddReferencesAsync"/> refuses a candidate that
    /// byte-equals <see cref="CBAdESReferencesContext.SigningCertificate"/> with
    /// <see cref="CBAdESAugmentationFailureKind.SigningCertificateReferenceRefused"/>.
    /// </summary>
    [TestMethod]
    public async Task AddReferencesAsync_CertificateToReferenceEqualsSigningCertificate_ThrowsSigningCertificateReferenceRefused()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            using X509ChainTestRingNode signerNode = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch));
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(signerNode.Certificate.RawData);

            var context = new CBAdESReferencesContext
            {
                WireBytes = wireBytes,
                SigningCertificate = signingCertificate,
                CertificatesToReference = [signingCertificate],
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TargetLevel = AdESBaselineLevel.BB
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddReferencesAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.SigningCertificateReferenceRefused, exception.FailureKind);
        }
    }


    /// <summary>
    /// A THREE-entry <c>CertificatesToReference</c> fixture whose first two candidates are
    /// genuinely distinct certificates -- each successfully digested and appended to the in-progress
    /// <c>certificateReferences</c> list -- and whose THIRD candidate is the signing certificate itself, refused
    /// with <see cref="CBAdESAugmentationFailureKind.SigningCertificateReferenceRefused"/> AFTER two
    /// <see cref="DigestValue"/> rentals already happened. The <c>catch</c>'s own cleanup
    /// (<c>DisposeEntries(certificateReferences)</c>, since <c>transferred</c> never became <see langword="true"/>)
    /// must return both already-rented digests, not just skip the one that never got a chance to be computed.
    /// </summary>
    [TestMethod]
    public async Task AddReferencesAsync_ThirdEntryTriggersThrowAfterTwoDigestsComputed_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            using X509ChainTestRingNode signerNode = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch));
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(signerNode.Certificate.RawData);

            using X509ChainTestRingNode firstNode = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), subjectCn: "AddReferencesAsync Metered First Certificate");
            using PkiCertificateMemory firstCertificate = ToCertificateCarrier(firstNode.Certificate.RawData);

            using X509ChainTestRingNode secondNode = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), subjectCn: "AddReferencesAsync Metered Second Certificate");
            using PkiCertificateMemory secondCertificate = ToCertificateCarrier(secondNode.Certificate.RawData);

            using var metered = new MeteredHousePool();
            var context = new CBAdESReferencesContext
            {
                WireBytes = wireBytes,
                SigningCertificate = signingCertificate,
                CertificatesToReference = [firstCertificate, secondCertificate, signingCertificate],
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TargetLevel = AdESBaselineLevel.BB
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddReferencesAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.SigningCertificateReferenceRefused, exception.FailureKind);
            Assert.AreEqual(0, metered.OutstandingCount,
                "The two digests already computed for the first and second candidates before the third throws must be disposed by the catch's own DisposeEntries cleanup, not leaked.");
        }
    }


    // Table 14 additional requirements (e)/(f): duplication of already-present valData material is avoided.

    /// <summary>
    /// Requirements (e)/(f): a certificate already present in an EARLIER <c>valData</c> element of this
    /// signature is skipped on a later <see cref="CBAdESSignatureAugmentation.AddValidationDataAsync"/> call —
    /// only the genuinely new candidate is placed, as a new, sibling <c>valData</c> element — and a call
    /// offering nothing but already-present material leaves the wire bytes byte-for-byte unchanged.
    /// </summary>
    [TestMethod]
    public async Task AddValidationDataAsync_DeduplicatesAgainstMaterialAlreadyPresent_AndLeavesWireBytesUnchangedWhenNothingNew()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            using X509ChainTestRingNode certNodeA = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), subjectCn: "Validation Data Certificate A");
            using X509ChainTestRingNode certNodeB = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), subjectCn: "Validation Data Certificate B");
            using PkiCertificateMemory certificateA = ToCertificateCarrier(certNodeA.Certificate.RawData);
            using PkiCertificateMemory certificateB = ToCertificateCarrier(certNodeB.Certificate.RawData);

            byte[] firstPlacement;
            using(EncodedCoseSign1 firstResult = await CBAdESSignatureAugmentation.AddValidationDataAsync(
                new CBAdESValidationDataContext { WireBytes = wireBytes, Material = new CBAdESValidationMaterial { Certificates = [certificateA] }, TargetLevel = AdESBaselineLevel.BB },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                firstPlacement = firstResult.AsReadOnlySpan().ToArray();
            }

            //Certificate A is already present; only certificate B is genuinely new.
            byte[] secondPlacement;
            using(EncodedCoseSign1 secondResult = await CBAdESSignatureAugmentation.AddValidationDataAsync(
                new CBAdESValidationDataContext { WireBytes = firstPlacement, Material = new CBAdESValidationMaterial { Certificates = [certificateA, certificateB] }, TargetLevel = AdESBaselineLevel.BB },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                secondPlacement = secondResult.AsReadOnlySpan().ToArray();
            }

            CBAdESSign1ParseResult parsedAfterSecond = CBAdESSignatureSerialization.ParseCBAdESSign1(secondPlacement, BaseMemoryPool.Shared);
            using(parsedAfterSecond)
            {
                Assert.HasCount(2, parsedAfterSecond.UnsignedHeaders!,
                    "Requirements (e)/(f): the duplicate A is skipped, so a SECOND valData element carries only the new certificate B.");
                var secondValData = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementValidationData>(parsedAfterSecond.UnsignedHeaders![1]);
                Assert.HasCount(1, secondValData.ValidationData.CertificateValues!, "Only certificate B is new.");
            }

            //A third call offering ONLY certificate A again finds nothing new to add at all.
            using EncodedCoseSign1 thirdResult = await CBAdESSignatureAugmentation.AddValidationDataAsync(
                new CBAdESValidationDataContext { WireBytes = secondPlacement, Material = new CBAdESValidationMaterial { Certificates = [certificateA] }, TargetLevel = AdESBaselineLevel.BB },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(secondPlacement.AsSpan().SequenceEqual(thirdResult.AsReadOnlySpan()),
                "With nothing new to add, the signature stands octet for octet as it was.");
        }
    }


    /// <summary>
    /// <see cref="CBAdESSignatureAugmentation.AddValidationDataAsync"/> refuses a candidate
    /// certificate that is not a genuine DER-encoded X.509 certificate with
    /// <see cref="CBAdESAugmentationFailureKind.UnsupportedValidationObject"/>, BEFORE <c>finalUnsignedHeaders</c>
    /// is ever built (<c>transferred</c> stays <see langword="false"/>) -- the metered pool shows every
    /// parse-side carrier disposed and nothing appended.
    /// </summary>
    [TestMethod]
    public async Task AddValidationDataAsync_WrongKindCertificateCandidate_ThrowsTypedFailure_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            using PkiCertificateMemory notACertificate = CreatePkiCarrier(PkiCertificateTags.OcspResponse);

            using var metered = new MeteredHousePool();
            var context = new CBAdESValidationDataContext
            {
                WireBytes = wireBytes,
                Material = new CBAdESValidationMaterial { Certificates = [notACertificate] },
                TargetLevel = AdESBaselineLevel.BLT
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddValidationDataAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.UnsupportedValidationObject, exception.FailureKind);
            Assert.AreEqual(0, metered.OutstandingCount,
                "A refused candidate must leave every parse-side carrier disposed -- nothing appended, nothing leaked.");
        }
    }


    /// <summary>
    /// <see cref="CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync"/>'s
    /// <c>sigD</c>-referenced source, when the dereference delegate reports failure for its one reference,
    /// propagates <see cref="CBAdESDetachedObjectDereferenceException"/> (raised by
    /// <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/>) before the
    /// Time-Stamping Authority is ever contacted. Nothing is ever rented for a reference that never
    /// dereferenced, so a metered-pool balance assertion here would be vacuous; the sibling test below covers
    /// the genuinely discriminating metered-pool leg, once the dereference succeeds and the authority itself
    /// is what fails.
    /// </summary>
    [TestMethod]
    public async Task AcquirePayloadTimestampAsync_SigDDereferenceFails_NeverContactsAuthority()
    {
        var responder = new CallCountingTimestampResponder();

        CBAdESDetachedObjectDereferenceDelegate alwaysFails = (uriReference, dereferenceContext, rentPool, cancellationToken) =>
            ValueTask.FromResult<CBAdESDetachedObjectDereferenceResult>(new CBAdESDetachedObjectDereferenceFailure("unreachable in this test"));

        var context = new CBAdESPayloadTimestampAcquisitionContext
        {
            Source = new CBAdESSigDReferencedPayloadTimestampAcquisitionSource(["https://example.org/unreachable-object"]),
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            TsaUri = "https://tsa.example/",
            FetchResponse = responder.FetchAsync,
            Dereference = alwaysFails,
            DereferenceContext = new CBAdESDetachedObjectDereferenceContext(null, null)
        };

        await Assert.ThrowsExactlyAsync<CBAdESDetachedObjectDereferenceException>(async () =>
            await CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync(
                context, CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(0, responder.CallCount, "A doomed sigD dereference must never reach the Time-Stamping Authority round trip.");
    }


    /// <summary>
    /// The genuinely discriminating metered-pool leg: <see cref="CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync"/>'s
    /// <c>sigD</c>-referenced source, once the dereference SUCCEEDS -- renting the reconstructed payload
    /// carrier from the metered pool -- still propagates
    /// <see cref="Verifiable.Cryptography.Pki.TimestampAcquisitionException"/> when the Time-Stamping Authority
    /// itself is unreachable, and leaves a <see cref="MeteredHousePool"/> exactly balanced: the reconstructed
    /// payload carrier, the message-imprint input, and the computed digest -- every carrier rented before the
    /// unreachable authority is discovered -- are all disposed, so a missed dispose on any of the three fails
    /// this test (unlike the sibling test above, where the dereference itself never rents anything).
    /// </summary>
    [TestMethod]
    public async Task AcquirePayloadTimestampAsync_SigDDereferenceSucceedsButAuthorityUnreachable_PropagatesAndLeavesMeteredPoolBalanced()
    {
        var responder = new CallCountingTimestampResponder();
        using var metered = new MeteredHousePool();

        CBAdESDetachedObjectDereferenceDelegate alwaysSucceeds = (uriReference, dereferenceContext, rentPool, cancellationToken) =>
        {
            PooledMemory pooled = PooledMemory.FromBytes("metered-pool dereferenced content"u8.ToArray(), rentPool, Tag.Create(Purpose.Data));
            return ValueTask.FromResult<CBAdESDetachedObjectDereferenceResult>(new CBAdESDetachedObjectDereferenceSuccess(pooled));
        };

        var context = new CBAdESPayloadTimestampAcquisitionContext
        {
            Source = new CBAdESSigDReferencedPayloadTimestampAcquisitionSource(["https://example.org/reachable-object"]),
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            TsaUri = "https://tsa.example/",
            FetchResponse = responder.FetchAsync,
            Dereference = alwaysSucceeds,
            DereferenceContext = new CBAdESDetachedObjectDereferenceContext(null, null)
        };

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(async () =>
            await CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync(
                context, CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.TransportFailure, exception.FailureKind, "The responder reports the authority unreachable by returning null.");
        Assert.AreEqual(1, responder.CallCount, "The dereference having succeeded, acquisition must reach the Time-Stamping Authority round trip -- which then reports itself unreachable.");
        Assert.AreEqual(0, metered.OutstandingCount,
            "The reconstructed sigD payload carrier, the message-imprint input, and the computed digest -- every carrier rented before the unreachable authority is discovered -- must all be disposed, never leaked.");
    }


    // Strip-on-upgrade (CB-6.3-23/-24/-25): the refs family is removed, retained elements survive byte-exact,
    // and uHeaders is absent entirely once nothing is left.

    /// <summary>
    /// <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/> removes every refs-family element
    /// (<c>refs</c> and <c>sigRTst</c> here) while leaving the retained <c>sigTst</c> element's own token bytes
    /// byte-exact — the ownership-transfer discipline the class remarks document (retained elements are the
    /// SAME object reference the parsed input already held, never re-minted).
    /// </summary>
    [TestMethod]
    public async Task StripReferencesForLongTerm_RemovesRefsFamilyElements_RetainsOthersByteExact()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(tsa.Root.Certificate.RawData);
            var firstResponder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(1));

            byte[] withSigTst;
            using(EncodedCoseSign1 step1 = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/sigtst/",
                    FetchResponse = firstResponder.FetchAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                withSigTst = step1.AsReadOnlySpan().ToArray();
            }

            byte[] retainedSignatureTimestampTokenBytesBeforeStrip;
            CBAdESSign1ParseResult beforeStripParse = CBAdESSignatureSerialization.ParseCBAdESSign1(withSigTst, BaseMemoryPool.Shared);
            using(beforeStripParse)
            {
                var sigTstElement = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementSignatureTimestamp>(beforeStripParse.UnsignedHeaders![0]);
                retainedSignatureTimestampTokenBytesBeforeStrip = sigTstElement.SignatureTimestamp.TimestampContainer.TstTokens[0].Val.ToArray();
            }

            using X509ChainTestRingNode referencedNode = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), subjectCn: "Strip Test Referenced Certificate");
            using PkiCertificateMemory referencedCertificate = ToCertificateCarrier(referencedNode.Certificate.RawData);

            byte[] withRefs;
            using(EncodedCoseSign1 step2 = await CBAdESSignatureAugmentation.AddReferencesAsync(
                new CBAdESReferencesContext
                {
                    WireBytes = withSigTst, SigningCertificate = signingCertificate, CertificatesToReference = [referencedCertificate],
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                withRefs = step2.AsReadOnlySpan().ToArray();
            }

            var secondResponder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(2));
            byte[] withSigRTst;
            using(EncodedCoseSign1 step3 = await CBAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync(
                new CBAdESReferencesFamilyTimestampContext
                {
                    WireBytes = withRefs, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/sigrtst/",
                    FetchResponse = secondResponder.FetchAsync, TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                withSigRTst = step3.AsReadOnlySpan().ToArray();
            }

            CBAdESSign1ParseResult beforeStrip = CBAdESSignatureSerialization.ParseCBAdESSign1(withSigRTst, BaseMemoryPool.Shared);
            using(beforeStrip)
            {
                Assert.HasCount(3, beforeStrip.UnsignedHeaders!, "sigTst + refs + sigRTst, in append order, before the strip.");
            }

            //TargetLevel B-T here (not B-LT): B-LT additionally requires the validation-data-for-time-stamps
            //service (CB-6.3-26), which this fixture never places -- the strip mechanics under test are
            //independent of that separate requirement, so B-T keeps EnsureConformant satisfied on the one
            //sigTst element that remains, without pulling in an unrelated fixture just to satisfy it.
            using EncodedCoseSign1 stripped = CBAdESSignatureAugmentation.StripReferencesForLongTerm(
                new CBAdESStripReferencesContext { WireBytes = withSigRTst, TargetLevel = AdESBaselineLevel.BT },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared);

            CBAdESSign1ParseResult afterStrip = CBAdESSignatureSerialization.ParseCBAdESSign1(stripped.AsReadOnlySpan().ToArray(), BaseMemoryPool.Shared);
            using(afterStrip)
            {
                Assert.HasCount(1, afterStrip.UnsignedHeaders!, "refs and sigRTst are removed (CB-6.3-23/-24); only sigTst remains.");
                var retained = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementSignatureTimestamp>(afterStrip.UnsignedHeaders![0]);
                Assert.IsTrue(
                    retainedSignatureTimestampTokenBytesBeforeStrip.AsSpan().SequenceEqual(retained.SignatureTimestamp.TimestampContainer.TstTokens[0].Val.Span),
                    "The retained sigTst element survives the strip byte-exact.");
            }
        }
    }


    /// <summary>
    /// When EVERY <c>uHeaders</c> element is refs-family, <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/>
    /// leaves the result carrying no <c>uHeaders</c> member at all, rather than an empty array (CB-5.3.1-07
    /// forbids an empty <c>uHeaders</c> array, so its absence is the only legal representation of "nothing left").
    /// </summary>
    [TestMethod]
    public async Task StripReferencesForLongTerm_WhenEveryElementIsRefsFamily_ResultCarriesNoUHeadersMember()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            using X509ChainTestRingNode signerNode = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch));
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(signerNode.Certificate.RawData);
            using X509ChainTestRingNode referencedNode = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), subjectCn: "Referenced Certificate Only");
            using PkiCertificateMemory referencedCertificate = ToCertificateCarrier(referencedNode.Certificate.RawData);

            //TargetLevel B-B throughout: with refs as the only element ever present, B-B keeps every level rule
            //this test does not care about (sigTst presence, the valData service) out of scope entirely.
            byte[] withRefs;
            using(EncodedCoseSign1 step = await CBAdESSignatureAugmentation.AddReferencesAsync(
                new CBAdESReferencesContext
                {
                    WireBytes = wireBytes, SigningCertificate = signingCertificate, CertificatesToReference = [referencedCertificate],
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TargetLevel = AdESBaselineLevel.BB
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                withRefs = step.AsReadOnlySpan().ToArray();
            }

            using EncodedCoseSign1 stripped = CBAdESSignatureAugmentation.StripReferencesForLongTerm(
                new CBAdESStripReferencesContext { WireBytes = withRefs, TargetLevel = AdESBaselineLevel.BB },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared);

            CBAdESSign1ParseResult afterStrip = CBAdESSignatureSerialization.ParseCBAdESSign1(stripped.AsReadOnlySpan().ToArray(), BaseMemoryPool.Shared);
            using(afterStrip)
            {
                Assert.IsNull(afterStrip.UnsignedHeaders, "With refs the only element, stripping it away leaves no uHeaders member at all.");
            }
        }
    }


    /// <summary>
    /// The one-step choreography: with
    /// <see cref="CBAdESStripReferencesContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/> attested
    /// <see langword="true"/>, <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/> reaches
    /// <see cref="AdESBaselineLevel.BLT"/> in this ONE call, with no <c>valData</c> element present at all —
    /// the CB-6.3-26 validation-data-for-time-stamps service is satisfied through the embedded-material SPO
    /// instead of the <c>valData</c> SPO <see cref="CBAdESSignatureAugmentation.AddValidationDataAsync"/> would
    /// otherwise need to place first.
    /// </summary>
    [TestMethod]
    public async Task StripReferencesForLongTerm_TargetLevelBLTWithEmbeddedMaterialFactAttested_SucceedsWithNoValDataPresent()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(tsa.Root.Certificate.RawData);
            var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(1));

            byte[] withSigTst;
            using(EncodedCoseSign1 step = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                    FetchResponse = responder.FetchAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                withSigTst = step.AsReadOnlySpan().ToArray();
            }

            using EncodedCoseSign1 stripped = CBAdESSignatureAugmentation.StripReferencesForLongTerm(
                new CBAdESStripReferencesContext
                {
                    WireBytes = withSigTst,
                    TargetLevel = AdESBaselineLevel.BLT,
                    AnyTimestampTokenCarriesEmbeddedValidationMaterial = true
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared);

            CBAdESSign1ParseResult afterStrip = CBAdESSignatureSerialization.ParseCBAdESSign1(stripped.AsReadOnlySpan().ToArray(), BaseMemoryPool.Shared);
            using(afterStrip)
            {
                Assert.HasCount(1, afterStrip.UnsignedHeaders!, "The retained sigTst survives; no refs-family element was ever present to strip away.");
                Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementSignatureTimestamp>(afterStrip.UnsignedHeaders![0]);
            }
        }
    }


    // Ownership regressions: no double-dispose, no leaked rental on the metered pool.

    /// <summary>
    /// A successful <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/> call leaves a metered
    /// pool exactly balanced: the refs-family element disposed individually, the retained <c>sigTst</c> element
    /// reachable only through the freshly built result, and the abandoned source container never
    /// cascade-disposed (which would double-dispose the retained element once the result is disposed too).
    /// A non-zero <see cref="MeteredHousePool.OutstandingCount"/> would mean either a leak (positive) or a
    /// double-dispose (negative, since a double return would push <c>ReturnedCount</c> above <c>RentedCount</c>).
    /// </summary>
    [TestMethod]
    public async Task StripReferencesForLongTerm_MeteredPoolBalancedAfterSuccessfulStrip()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(tsa.Root.Certificate.RawData);
            var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(1));

            byte[] withSigTst;
            using(EncodedCoseSign1 step1 = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CBAdESSignatureTimestampContext
                {
                    WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                    FetchResponse = responder.FetchAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                withSigTst = step1.AsReadOnlySpan().ToArray();
            }

            using X509ChainTestRingNode referencedNode = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch), subjectCn: "Metered Strip Referenced Certificate");
            using PkiCertificateMemory referencedCertificate = ToCertificateCarrier(referencedNode.Certificate.RawData);

            byte[] withRefs;
            using(EncodedCoseSign1 step2 = await CBAdESSignatureAugmentation.AddReferencesAsync(
                new CBAdESReferencesContext
                {
                    WireBytes = withSigTst, SigningCertificate = signingCertificate, CertificatesToReference = [referencedCertificate],
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TargetLevel = AdESBaselineLevel.BT
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                withRefs = step2.AsReadOnlySpan().ToArray();
            }

            using var metered = new MeteredHousePool();
            using(EncodedCoseSign1 stripped = CBAdESSignatureAugmentation.StripReferencesForLongTerm(
                new CBAdESStripReferencesContext { WireBytes = withRefs, TargetLevel = AdESBaselineLevel.BT },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, metered.Pool))
            {
                Assert.IsGreaterThan(0, stripped.Length, "The strip produced a genuine, non-empty result.");
            }

            Assert.AreEqual(0, metered.OutstandingCount, "A successful strip must leave the metered pool exactly balanced -- no leak, no double-dispose.");
        }
    }


    /// <summary>
    /// A cancellation observed mid-flight during the Time-Stamping Authority round trip (the transport
    /// delegate itself throwing <see cref="OperationCanceledException"/>) propagates out of
    /// <see cref="CBAdESSignatureAugmentation.AddSignatureTimestampAsync"/> unmodified, and the metered pool
    /// shows every carrier the call rented before the cancellation (the parse-side carriers; no token was ever
    /// acquired) returned exactly once.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_CancellationDuringAuthorityRoundTrip_PropagatesAndLeavesMeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            using X509ChainTestRingNode signerNode = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch));
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(signerNode.Certificate.RawData);
            using var metered = new MeteredHousePool();

            var context = new CBAdESSignatureTimestampContext
            {
                WireBytes = wireBytes, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256, TsaUri = "https://tsa.example/",
                FetchResponse = ThrowsOperationCanceledFetchResponseAsync, SigningCertificate = signingCertificate, TargetLevel = AdESBaselineLevel.BT
            };

            await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(0, metered.OutstandingCount,
                "A cancellation observed mid-flight during the Time-Stamping Authority round trip must still leave the parse-side carriers and the (never-acquired) token fully disposed -- no leak on this path.");
        }
    }


    // Augmentation raw-splices retained uHeaders elements from the parse-captured wire bytes
    // instead of re-encoding them from the decoded model -- the byte-preservation regressions below.

    /// <summary>
    /// Byte-preservation regression (a): a hand-assembled signature whose <c>refs</c> element carries an
    /// <c>ocspId.producedAt</c> with a SUB-SECOND, non-<c>Z</c>-offset <c>tdate</c> (legal per Annex A CDDL
    /// <c>#6.0(tstr)</c>, but a form <see cref="CBAdESSerialization.WriteTDate"/> can never itself PRODUCE,
    /// since that writer always forces whole-second, <c>Z</c>-suffixed output) survives
    /// <see cref="CBAdESSignatureAugmentation.AddSignatureTimestampAsync"/> -- an operation with nothing to do
    /// with <c>refs</c> at all -- byte-identical, and the <c>rfsTst</c> element already covering it still
    /// verifies at level B-T validation afterwards. Before this fix, EVERY augmentation verb re-encoded the whole
    /// <c>uHeaders</c> array from the decoded model, which would have normalized this <c>producedAt</c> to
    /// whole-second/forced-<c>Z</c> and broken <c>rfsTst</c>'s own message-imprint coverage of it.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_PreservesRefsElementWithSubSecondNonZOffsetProducedAtByteExact_AndRfsTstStillVerifies()
    {
        (byte[] bbWireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) =
            await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            const string subSecondNonZOffsetProducedAt = "2024-06-15T10:30:45.123456+02:00";

            byte[] ocspResponseDigestBytes = await ComputeArbitraryFixtureDigestAsync(
                "ocsp response fixture"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
            byte[] refsUHeaderInstance = BuildRefsUHeaderInstanceWithOcspProducedAt(subSecondNonZOffsetProducedAt, ocspResponseDigestBytes);
            byte[] oneElementImprintArray = BuildRawUHeadersArray(refsUHeaderInstance);

            using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
                tsa.Authority, [tsa.Authority], oneElementImprintArray, TestClock.CanonicalEpoch.AddMinutes(5), BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            byte[] rfsTstUHeaderInstance = BuildRfsTstUHeaderInstance(token.AsReadOnlySpan().ToArray());
            byte[] handAssembledWireBytes = BuildHandAssembledWireBytesWithCustomUHeaders(bbWireBytes, refsUHeaderInstance, rfsTstUHeaderInstance);

            byte[] refsElementBeforeAugmentation;
            CBAdESSign1ParseResult beforeAugmentation = CBAdESSignatureSerialization.ParseCBAdESSign1(handAssembledWireBytes, BaseMemoryPool.Shared);
            using(beforeAugmentation)
            {
                Assert.IsTrue(beforeAugmentation.IsSuccess, "The hand-assembled fixture must itself parse as a well-formed CB-AdES COSE_Sign1.");
                Assert.HasCount(2, beforeAugmentation.UnsignedHeaders!, "refs and rfsTst only, before any augmentation.");
                refsElementBeforeAugmentation = ReadRawUnsignedHeaderElement(beforeAugmentation.RawUnsignedHeaders!, 0);
            }

            var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddMinutes(10));
            var timestampContext = new CBAdESSignatureTimestampContext
            {
                WireBytes = handAssembledWireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "https://tsa.example/",
                FetchResponse = responder.FetchAsync,
                EnforceSigningCertificateValidity = false,
                TargetLevel = AdESBaselineLevel.BT
            };

            byte[] augmentedWireBytes;
            using(EncodedCoseSign1 augmented = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                timestampContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                augmentedWireBytes = augmented.AsReadOnlySpan().ToArray();
            }

            byte[] refsElementAfterAugmentation;
            CBAdESSign1ParseResult afterAugmentation = CBAdESSignatureSerialization.ParseCBAdESSign1(augmentedWireBytes, BaseMemoryPool.Shared);
            using(afterAugmentation)
            {
                Assert.IsTrue(afterAugmentation.IsSuccess);
                Assert.HasCount(3, afterAugmentation.UnsignedHeaders!, "refs, rfsTst, and the newly-appended sigTst.");
                refsElementAfterAugmentation = ReadRawUnsignedHeaderElement(afterAugmentation.RawUnsignedHeaders!, 0);
            }

            Assert.IsTrue(refsElementBeforeAugmentation.AsSpan().SequenceEqual(refsElementAfterAugmentation),
                "An augmentation verb with nothing to do with refs must never change its wire bytes -- a " +
                "re-encode from the decoded model would normalize the sub-second, non-Z-offset producedAt to " +
                "whole-second, forced-Z.");

            using CBAdESValidationResult validation = await CBAdESSignatureValidation.ValidateAsync(
                augmentedWireBytes, CBAdESSignatureSerialization.ParseCBAdESSign1, CoseSerialization.BuildSigStructure, publicKey,
                dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
                AdESBaselineLevel.BT,
                CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(validation.IsValid,
                "The rfsTst token, minted over the ORIGINAL refs bytes, must still verify: this byte-exact " +
                "preservation keeps the message imprint stable across the unrelated sigTst augmentation.");
        }
    }


    /// <summary>
    /// Byte-preservation regression (b): a retained <c>Unknown</c>-label <c>uHeaders</c> element (an unspecified catch-all
    /// component, CB-5.3.1-11) carrying an arbitrary, non-trivial inner encoding survives
    /// <see cref="CBAdESSignatureAugmentation.AddSignatureTimestampAsync"/> byte-exact -- proving the
    /// raw-splice seam treats every retained element opaquely at the array level, regardless of whether this
    /// library models its inner shape at all.
    /// </summary>
    [TestMethod]
    public async Task AddSignatureTimestampAsync_PreservesUnknownLabelElementByteExact()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario tsa = CreateTsaScenario())
        {
            byte[] unknownUHeaderInstance = BuildUnknownUHeaderInstance();
            byte[] handAssembledWireBytes = BuildHandAssembledWireBytesWithCustomUHeaders(wireBytes, unknownUHeaderInstance);

            byte[] unknownElementBeforeAugmentation;
            CBAdESSign1ParseResult beforeAugmentation = CBAdESSignatureSerialization.ParseCBAdESSign1(handAssembledWireBytes, BaseMemoryPool.Shared);
            using(beforeAugmentation)
            {
                Assert.IsTrue(beforeAugmentation.IsSuccess);
                var unknown = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementUnknown>(beforeAugmentation.UnsignedHeaders![0]);
                Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementIntegerLabel>(unknown.Label);
                unknownElementBeforeAugmentation = ReadRawUnsignedHeaderElement(beforeAugmentation.RawUnsignedHeaders!, 0);
            }

            var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddMinutes(1));
            var timestampContext = new CBAdESSignatureTimestampContext
            {
                WireBytes = handAssembledWireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "https://tsa.example/",
                FetchResponse = responder.FetchAsync,
                EnforceSigningCertificateValidity = false,
                TargetLevel = AdESBaselineLevel.BT
            };

            byte[] unknownElementAfterAugmentation;
            using(EncodedCoseSign1 augmented = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                timestampContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
            {
                byte[] augmentedWireBytes = augmented.AsReadOnlySpan().ToArray();
                CBAdESSign1ParseResult afterAugmentation = CBAdESSignatureSerialization.ParseCBAdESSign1(augmentedWireBytes, BaseMemoryPool.Shared);
                using(afterAugmentation)
                {
                    Assert.IsTrue(afterAugmentation.IsSuccess);
                    Assert.HasCount(2, afterAugmentation.UnsignedHeaders!, "The unknown element and the newly-appended sigTst.");
                    unknownElementAfterAugmentation = ReadRawUnsignedHeaderElement(afterAugmentation.RawUnsignedHeaders!, 0);
                }
            }

            Assert.IsTrue(unknownElementBeforeAugmentation.AsSpan().SequenceEqual(unknownElementAfterAugmentation),
                "A retained, entirely opaque uHeaders element must survive an unrelated augmentation " +
                "byte-exact -- the raw-splice seam never inspects, decodes, or re-derives a retained element's " +
                "inner bytes.");
        }
    }


    /// <summary>
    /// Byte-preservation regression (c): when the raw <c>uHeaders</c> array's own element count does not match the caller-
    /// stated decoded count, <see cref="CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader"/>
    /// reports the typed failure and emits nothing -- an internal parse/splice consistency check (never
    /// reachable from a genuine <see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/> result, whose raw
    /// and decoded counts always agree by construction), exercised directly against the delegate.
    /// </summary>
    [TestMethod]
    public void TrySpliceCBAdESUnprotectedHeader_RawElementCountMismatchesDecodedCount_FailsClosed()
    {
        byte[] oneElementRawArray = BuildRawUHeadersArray(BuildUnknownUHeaderInstance());
        using EncodedCBAdESUnsignedHeaders rawUnsignedHeaders = EncodedCBAdESUnsignedHeaders.FromBytes(oneElementRawArray, BaseMemoryPool.Shared);

        bool spliced = CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader(
            rawUnsignedHeaders, decodedElementCount: 2, skipDecodedIndexes: null, newElement: null, BaseMemoryPool.Shared,
            out IReadOnlyDictionary<int, object>? result);

        Assert.IsFalse(spliced, "The raw array holds one element but the caller claims two were decoded -- an internal inconsistency the splice must refuse.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> appends exactly one <c>arcTst</c>
    /// element encapsulating exactly one genuine RFC 3161 token, whose own message imprint -- rebuilt
    /// independently through the shipped VALIDATION-mode builder over the final wire bytes -- matches, proving
    /// generation and validation agree on the same clause 5.3.5.3 byte sequence, and that the level-aware
    /// validator accepts the result at B-LTA.
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_SingleTsa_AppendsOneConformantArcTst_TokenImprintVerifiesIndependently()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario sigTstTsa = CreateTsaScenario())
        using(TsaScenario arcTstTsa = CreateTsaScenario())
        {
            byte[] btWireBytes = await AugmentToSignatureTimestampAsync(wireBytes, sigTstTsa, TestContext.CancellationToken).ConfigureAwait(false);

            var arcTstResponder = new MintingTimestampResponder(arcTstTsa.Authority, [arcTstTsa.Authority], TestClock.CanonicalEpoch.AddHours(2));
            byte[] externallySuppliedData = "arcTst fixture externally-supplied data"u8.ToArray();
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(arcTstTsa.Root.Certificate.RawData);

            byte[] ltaWireBytes;
            using(EncodedCoseSign1 ltaAugmented = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CBAdESArchiveTimestampContext
                {
                    WireBytes = btWireBytes,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    ExternallySuppliedData = externallySuppliedData,
                    TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://arctst-tsa.example/", FetchResponse = arcTstResponder.FetchAsync }],
                    SigningCertificate = signingCertificate,
                    ChainCompletenessAttested = true,
                    TargetLevel = AdESBaselineLevel.BLTA
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
            {
                ltaWireBytes = ltaAugmented.AsReadOnlySpan().ToArray();
            }

            CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(ltaWireBytes, BaseMemoryPool.Shared);
            using(parsed)
            {
                Assert.IsTrue(parsed.IsSuccess);
                Assert.HasCount(2, parsed.UnsignedHeaders!, "sigTst, then arcTst.");
                var arcTstElement = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementArchiveTimestamp>(parsed.UnsignedHeaders![1]);
                Assert.HasCount(1, arcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens, "One TSA leg, one token.");

                await AssertArchiveTimestampTokenImprintMatchesAsync(
                    parsed, externallySuppliedData, arcTstElementIndex: 1,
                    arcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens[0], TestContext.CancellationToken).ConfigureAwait(false);
            }

            using CBAdESValidationResult validation = await CBAdESSignatureValidation.ValidateAsync(
                ltaWireBytes, CBAdESSignatureSerialization.ParseCBAdESSign1, CoseSerialization.BuildSigStructure, publicKey,
                dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
                AdESBaselineLevel.BLTA,
                CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
                BaseMemoryPool.Shared, externallySuppliedData, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(validation.IsValid, "The round-tripped, augmented signature must validate at level B-LTA.");
        }
    }


    /// <summary>
    /// Additional requirement (j): configuring TWO Time-Stamping Authority legs mints ONE new
    /// <c>arcTst</c> instance carrying TWO tokens -- never two sibling instances -- each independently
    /// verifiable under its own authority's certificate and each bound to the SAME message imprint.
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_MultiTsa_AppendsOneArcTstInstanceCarryingTwoTokens()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario sigTstTsa = CreateTsaScenario())
        using(TsaScenario firstArcTsa = CreateTsaScenario())
        using(TsaScenario secondArcTsa = CreateTsaScenario())
        {
            byte[] btWireBytes = await AugmentToSignatureTimestampAsync(wireBytes, sigTstTsa, TestContext.CancellationToken).ConfigureAwait(false);

            var firstResponder = new MintingTimestampResponder(firstArcTsa.Authority, [firstArcTsa.Authority], TestClock.CanonicalEpoch.AddHours(2));
            var secondResponder = new MintingTimestampResponder(secondArcTsa.Authority, [secondArcTsa.Authority], TestClock.CanonicalEpoch.AddHours(2).AddMinutes(1));
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(firstArcTsa.Root.Certificate.RawData);

            byte[] ltaWireBytes;
            using(EncodedCoseSign1 ltaAugmented = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CBAdESArchiveTimestampContext
                {
                    WireBytes = btWireBytes,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaLegs =
                    [
                        new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://arctst-tsa-one.example/", FetchResponse = firstResponder.FetchAsync },
                        new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://arctst-tsa-two.example/", FetchResponse = secondResponder.FetchAsync }
                    ],
                    SigningCertificate = signingCertificate,
                    ChainCompletenessAttested = true,
                    TargetLevel = AdESBaselineLevel.BLTA
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
            {
                ltaWireBytes = ltaAugmented.AsReadOnlySpan().ToArray();
            }

            CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(ltaWireBytes, BaseMemoryPool.Shared);
            using(parsed)
            {
                Assert.IsTrue(parsed.IsSuccess);
                Assert.HasCount(2, parsed.UnsignedHeaders!, "sigTst, then ONE arcTst instance -- never two sibling instances.");
                var arcTstElement = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementArchiveTimestamp>(parsed.UnsignedHeaders![1]);
                Assert.HasCount(2, arcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens, "Two configured legs, two tokens, one instance.");

                using PkiCertificateMemory firstTokenCarrier = ToTokenCarrier(arcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens[0].Val.ToArray());
                using PkiCertificateMemory secondTokenCarrier = ToTokenCarrier(arcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens[1].Val.ToArray());
                Assert.IsTrue(X509ChainTestRingTimestamping.VerifiesUnderAuthorityCertificate(firstTokenCarrier, firstArcTsa.Authority), "The first token is genuinely the first authority's own.");
                Assert.IsTrue(X509ChainTestRingTimestamping.VerifiesUnderAuthorityCertificate(secondTokenCarrier, secondArcTsa.Authority), "The second token is genuinely the second authority's own.");

                await AssertArchiveTimestampTokenImprintMatchesAsync(
                    parsed, default, arcTstElementIndex: 1,
                    arcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens[0], TestContext.CancellationToken).ConfigureAwait(false);
                await AssertArchiveTimestampTokenImprintMatchesAsync(
                    parsed, default, arcTstElementIndex: 1,
                    arcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens[1], TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
    }


    /// <summary>
    /// Write-strict: a declared <see cref="CBAdESArchiveTimestampContext.TargetLevel"/> other than
    /// <see cref="AdESBaselineLevel.BLTA"/> refuses BEFORE any digest computation or Time-Stamping Authority
    /// round trip -- nothing is appended, the responder is never contacted, and every parse-side carrier
    /// rented before the refusal is disposed.
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_TargetLevelNotBLTA_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            var responder = new CallCountingTimestampResponder();
            using var metered = new MeteredHousePool();
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(BuildSelfContainedRootCertificateBytes());
            var context = new CBAdESArchiveTimestampContext
            {
                WireBytes = wireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://tsa.example/", FetchResponse = responder.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                TargetLevel = AdESBaselineLevel.BLT
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                    CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                    metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.ArchiveTimestampNotPermittedAtTargetLevel, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "A declared level other than B-LTA must never contact a Time-Stamping Authority.");
            Assert.AreEqual(0, metered.OutstandingCount, "Every parse carrier rented before the pre-check refusal must be disposed.");
        }
    }


    /// <summary>
    /// CB-6.3-k: a hand-assembled <c>sigTst</c> element whose own token bytes are not a
    /// well-formed CMS structure at all -- so its signer certificate is resolvable neither in <c>valData</c>
    /// nor embedded in the token itself -- refuses <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/>
    /// BEFORE any Time-Stamping Authority round trip, citing <see cref="CBAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete"/>.
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_ExistingTokenSignerCertificateUnresolvableEverywhere_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        (byte[] baselineWireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            byte[] sigTstElement = BuildSignatureTimestampUHeaderInstance([0x01, 0x02, 0x03, 0x04]);
            byte[] wireBytes = BuildHandAssembledWireBytesWithCustomUHeaders(baselineWireBytes, sigTstElement);

            var responder = new CallCountingTimestampResponder();
            using var metered = new MeteredHousePool();
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(BuildSelfContainedRootCertificateBytes());
            var context = new CBAdESArchiveTimestampContext
            {
                WireBytes = wireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://tsa.example/", FetchResponse = responder.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                TargetLevel = AdESBaselineLevel.BLTA
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                    CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                    metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "CB-6.3-k: an existing token whose signer certificate is unresolvable anywhere must never reach the Time-Stamping Authority.");
            Assert.AreEqual(0, metered.OutstandingCount, "Every carrier rented before the pre-check refusal must be disposed.");
        }
    }


    /// <summary>
    /// An unattested call (<see cref="CBAdESArchiveTimestampContext.ChainCompletenessAttested"/>
    /// left at its fail-closed default) refuses BEFORE any Time-Stamping Authority round trip, citing
    /// <see cref="CBAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete"/>, independent of
    /// whether every existing token's own signer certificate would otherwise resolve.
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_ChainCompletenessNotAttested_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            var responder = new CallCountingTimestampResponder();
            using var metered = new MeteredHousePool();
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(BuildSelfContainedRootCertificateBytes());
            var context = new CBAdESArchiveTimestampContext
            {
                WireBytes = wireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://tsa.example/", FetchResponse = responder.FetchAsync }],
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BLTA
            };

            Assert.IsFalse(context.ChainCompletenessAttested, "Fail-closed default.");

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                    CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                    metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "An unattested call must never contact a Time-Stamping Authority.");
            Assert.AreEqual(0, metered.OutstandingCount, "Every parse carrier rented before the pre-check refusal must be disposed.");
        }
    }


    /// <summary>
    /// Table 14's B-LTA ladder prerequisite (CB-6.3-21): a signature carrying no <c>sigTst</c> instance
    /// at all refuses <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> BEFORE any
    /// Time-Stamping Authority round trip, distinctly from every other gate (<see cref="CBAdESArchiveTimestampContext.ChainCompletenessAttested"/>
    /// is attested here, isolating this assertion to the NEW gate alone).
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_NoSignatureTimestampInstance_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        {
            var responder = new CallCountingTimestampResponder();
            using var metered = new MeteredHousePool();
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(BuildSelfContainedRootCertificateBytes());
            var context = new CBAdESArchiveTimestampContext
            {
                WireBytes = wireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://tsa.example/", FetchResponse = responder.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                TargetLevel = AdESBaselineLevel.BLTA
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                    CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                    metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.ArchiveTimestampSignatureTimestampPrerequisiteMissing, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "CB-6.3-21: a signature with no sigTst instance must never contact a Time-Stamping Authority.");
            Assert.AreEqual(0, metered.OutstandingCount, "Every parse carrier rented before the pre-check refusal must be disposed.");
        }
    }


    /// <summary>
    /// CB-5.3.5.1-02, existence half: a signature that already clears every OTHER pre-TSA
    /// gate but carries a genuine <c>uHeaders</c> counter-signature element (label 12) refuses BEFORE any
    /// Time-Stamping Authority round trip when NEITHER opt-in delegate
    /// (<c>parseCounterSignatureHeaderValue</c>/<c>isCounterSignatureMaterialComplete</c>) is supplied -- this
    /// call cannot confirm the requirement holds without them, so it refuses rather than silently skipping the
    /// check the way the element's mere presence is (correctly) never a level-rule violation (CB-6.3-30).
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_CounterSignatureElementPresent_NoDecodeDelegatesSupplied_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario sigTstTsa = CreateTsaScenario())
        {
            byte[] btWireBytes = await AugmentToSignatureTimestampAsync(wireBytes, sigTstTsa, TestContext.CancellationToken).ConfigureAwait(false);

            var counterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PrivateKeyMemory counterSignerPrivateKey = counterSignerKeyMaterial.PrivateKey;
            counterSignerKeyMaterial.PublicKey.Dispose();

            byte[] withCounterSignatureWireBytes = await SpliceGenuineAbbreviatedCounterSignatureAsync(
                btWireBytes, wireBytes, counterSignerPrivateKey, TestContext.CancellationToken).ConfigureAwait(false);

            var responder = new CallCountingTimestampResponder();
            using var metered = new MeteredHousePool();
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(BuildSelfContainedRootCertificateBytes());
            var context = new CBAdESArchiveTimestampContext
            {
                WireBytes = withCounterSignatureWireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://tsa.example/", FetchResponse = responder.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                TargetLevel = AdESBaselineLevel.BLTA
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                    CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                    metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.ArchiveTimestampCounterSignatureMaterialIncomplete, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "CB-5.3.5.1-02: a counter-signature element present with no decode delegate supplied must never contact a Time-Stamping Authority.");
            Assert.AreEqual(0, metered.OutstandingCount, "Every carrier rented before the pre-check refusal must be disposed.");
        }
    }


    /// <summary>
    /// CB-5.3.5.1-02, material-completeness half: the SAME fixture as the no-delegate test
    /// above, but with both opt-in delegates supplied and the completeness resolver reporting
    /// <see langword="false"/> -- the decode succeeds (the element IS a well-formed countersignature), yet the
    /// call still refuses, because the resolver -- the only party this certificate-path-neutral orchestrator
    /// trusts to answer "is the material already incorporated" -- says it is not.
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_CounterSignatureElementPresent_ResolverReportsIncomplete_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario sigTstTsa = CreateTsaScenario())
        {
            byte[] btWireBytes = await AugmentToSignatureTimestampAsync(wireBytes, sigTstTsa, TestContext.CancellationToken).ConfigureAwait(false);

            var counterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PrivateKeyMemory counterSignerPrivateKey = counterSignerKeyMaterial.PrivateKey;
            counterSignerKeyMaterial.PublicKey.Dispose();

            byte[] withCounterSignatureWireBytes = await SpliceGenuineAbbreviatedCounterSignatureAsync(
                btWireBytes, wireBytes, counterSignerPrivateKey, TestContext.CancellationToken).ConfigureAwait(false);

            var responder = new CallCountingTimestampResponder();
            using var metered = new MeteredHousePool();
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(BuildSelfContainedRootCertificateBytes());
            var context = new CBAdESArchiveTimestampContext
            {
                WireBytes = withCounterSignatureWireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://tsa.example/", FetchResponse = responder.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                TargetLevel = AdESBaselineLevel.BLTA
            };

            CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
            {
                using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                    context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                    CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                    CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                    metered.Pool,
                    parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
                    isCounterSignatureMaterialComplete: _ => false,
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);

            Assert.AreEqual(CBAdESAugmentationFailureKind.ArchiveTimestampCounterSignatureMaterialIncomplete, exception.FailureKind);
            Assert.AreEqual(0, responder.CallCount, "CB-5.3.5.1-02: a resolver reporting incomplete material must never contact a Time-Stamping Authority.");
            Assert.AreEqual(0, metered.OutstandingCount, "Every carrier rented before the pre-check refusal must be disposed.");
        }
    }


    /// <summary>
    /// CB-5.3.5.1-02, the closing positive leg: the SAME fixture again, but the resolver
    /// confirms completeness -- the new gate does not block a legitimately-complete signature, and the new
    /// <c>arcTst</c> mints normally, proving the opt-in seam is genuinely usable end to end (never merely a
    /// refusal-only stub).
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_CounterSignatureElementPresent_ResolverConfirmsComplete_Succeeds()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario sigTstTsa = CreateTsaScenario())
        using(TsaScenario arcTstTsa = CreateTsaScenario())
        {
            byte[] btWireBytes = await AugmentToSignatureTimestampAsync(wireBytes, sigTstTsa, TestContext.CancellationToken).ConfigureAwait(false);

            var counterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PrivateKeyMemory counterSignerPrivateKey = counterSignerKeyMaterial.PrivateKey;
            counterSignerKeyMaterial.PublicKey.Dispose();

            byte[] withCounterSignatureWireBytes = await SpliceGenuineAbbreviatedCounterSignatureAsync(
                btWireBytes, wireBytes, counterSignerPrivateKey, TestContext.CancellationToken).ConfigureAwait(false);

            var arcTstResponder = new MintingTimestampResponder(arcTstTsa.Authority, [arcTstTsa.Authority], TestClock.CanonicalEpoch.AddHours(2));
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(arcTstTsa.Root.Certificate.RawData);
            var context = new CBAdESArchiveTimestampContext
            {
                WireBytes = withCounterSignatureWireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://arctst-tsa.example/", FetchResponse = arcTstResponder.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                TargetLevel = AdESBaselineLevel.BLTA
            };

            using EncodedCoseSign1 ltaAugmented = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                BaseMemoryPool.Shared,
                parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
                isCounterSignatureMaterialComplete: _ => true,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(ltaAugmented.AsReadOnlySpan().ToArray(), BaseMemoryPool.Shared);
            using(parsed)
            {
                Assert.IsTrue(parsed.IsSuccess);
                Assert.HasCount(3, parsed.UnsignedHeaders!, "sigTst, the counter-signature element, then arcTst -- the new gate does not block a legitimately-complete signature.");
                Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementArchiveTimestamp>(parsed.UnsignedHeaders![2]);
            }
        }
    }


    /// <summary>
    /// Countersigns <paramref name="originalCoseSign1WireBytes"/>'s own body-layer protected header/payload/
    /// signature with <paramref name="counterSignerPrivateKey"/> through <see cref="CoseCounterSign"/>, encodes
    /// the result as a <see cref="CBAdESUnsignedHeaderElementAbbreviatedCounterSignature"/> (label 12), and
    /// splices it into <paramref name="wireBytesToSpliceInto"/>'s own <c>uHeaders</c> -- mirroring
    /// <c>CBAdESCounterSignatureVisibilityTests</c>'s own identically-shaped fixture builder.
    /// </summary>
    /// <param name="wireBytesToSpliceInto">The wire bytes to splice the counter-signature element into.</param>
    /// <param name="originalCoseSign1WireBytes">
    /// The ORIGINAL B-B wire bytes whose protected header/payload/signature the countersignature covers --
    /// these three fields never change through B-T augmentation, so this may be a distinct, earlier copy of
    /// the same signature than <paramref name="wireBytesToSpliceInto"/>.
    /// </param>
    /// <param name="counterSignerPrivateKey">The countersigner's private key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The final wire bytes, carrying the spliced-in counter-signature element.</returns>
    private static async ValueTask<byte[]> SpliceGenuineAbbreviatedCounterSignatureAsync(
        byte[] wireBytesToSpliceInto, byte[] originalCoseSign1WireBytes, PrivateKeyMemory counterSignerPrivateKey, CancellationToken cancellationToken)
    {
        using CBAdESSign1ParseResult originalParsed = CBAdESSignatureSerialization.ParseCBAdESSign1(originalCoseSign1WireBytes, BaseMemoryPool.Shared);
        Assert.IsTrue(originalParsed.IsSuccess);

        var target = new CoseSign1CountersignTarget(
            originalParsed.RawProtectedHeader!.AsReadOnlyMemory(), originalParsed.Payload, originalParsed.Signature!.AsReadOnlyMemory());

        using CounterSignature0V2 counterSignature = await CoseCounterSign.CountersignAbbreviatedAsync(
            target, externalAad: ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
            counterSignerPrivateKey, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        using EncodedCoseCounterSignature encoded = CoseSerialization.WriteCounterSignature0V2(counterSignature, BaseMemoryPool.Shared);
        var element = new CBAdESUnsignedHeaderElementAbbreviatedCounterSignature(encoded.AsReadOnlyMemory().ToArray());

        return SpliceElementIntoWireBytes(wireBytesToSpliceInto, element);
    }


    /// <summary>
    /// Parses <paramref name="wireBytes"/>, splices <paramref name="element"/> in as a new, final <c>uHeaders</c>
    /// element (retaining every element already present), and re-serializes around the SAME protected header,
    /// payload, and signature carriers the parse captured -- mirroring
    /// <c>CBAdESSignatureAugmentation.EncodeAndSerialize</c>'s own exact pattern (and
    /// <c>CBAdESCounterSignatureVisibilityTests.SpliceElementAndSerialize</c>'s identically-shaped test-side
    /// twin), generalized here to splice onto wire bytes that may already carry other elements (e.g. a prior
    /// <c>sigTst</c>).
    /// </summary>
    /// <param name="wireBytes">The wire bytes to splice into.</param>
    /// <param name="element">The new <c>uHeaders</c> element to append.</param>
    /// <returns>The final wire bytes.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "message borrows parsed's own RawProtectedHeader/Payload/Signature carriers verbatim -- " +
            "read-only, never disposed here; parsed's own using disposes them once this method has extracted " +
            "the re-serialized byte[] copy.")]
    private static byte[] SpliceElementIntoWireBytes(byte[] wireBytes, CBAdESUnsignedHeaderElement element)
    {
        using CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(wireBytes, BaseMemoryPool.Shared);
        Assert.IsTrue(parsed.IsSuccess);

        bool spliced = CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader(
            parsed.RawUnsignedHeaders, parsed.UnsignedHeaders?.Count ?? 0, skipDecodedIndexes: null, element, BaseMemoryPool.Shared,
            out IReadOnlyDictionary<int, object>? unprotectedHeader);
        Assert.IsTrue(spliced);

        var message = new CoseSign1Message(parsed.RawProtectedHeader!, unprotectedHeader, parsed.Payload, parsed.Signature!);
        using EncodedCoseSign1 reserialized = CBAdESSignatureSerialization.SerializeCBAdESSign1(message, payloadIsDetached: !parsed.PayloadIsPresent, BaseMemoryPool.Shared);

        return reserialized.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// CB-A.1.1-30: a hand-assembled signature carrying a genuine <c>sigTst</c> instance
    /// (clearing every OTHER pre-Time-Stamping-Authority gate) plus a <c>refs</c> certificate reference that
    /// resolves to NOTHING present in its own <c>valData</c> element refuses
    /// <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> BEFORE any Time-Stamping Authority
    /// round trip, citing CB-A.1.1-30 — the producer twin of
    /// <c>ValidateAsyncCollectsReferencesValidationDataConsistencyViolationWhenACertificateReferenceDoesNotResolve</c>
    /// (<c>CBAdESLevelValidationNegativeTests</c>): the same shape the validator would reject is never minted.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "certificateReference (and its own AdESCertificateThumbprint) becomes reachable " +
            "through the CBAdESUnsignedHeaderElementReferences entry of `unsignedHeaders`, disposed by the " +
            "'using(var unsignedHeaders = ...)' block below via CBAdESUnsignedHeaders.Dispose's own cascade " +
            "(CBAdESUnsignedHeaderElementReferences -> CBAdESReferences -> CBAdESCertificateReference -> " +
            "AdESCertificateThumbprint); the sigTst element's CBAdESSignatureTimestamp/AdESTimestampContainer " +
            "cascade the same way. x5t (its own AdESCertificateThumbprint) becomes reachable through `headers`, " +
            "which transfers to the returned CBAdESSignatureCreationResult on a successful SignAsync call " +
            "(that method's own SuppressMessage remarks), disposed here via 'using CBAdESSignatureCreationResult " +
            "creationResult'. Roslyn tracks the locally-constructed values themselves, not the fact that they " +
            "are reachable through one of those two disposed containers several constructor calls later.")]
    [TestMethod]
    public async Task AddArchiveTimestampAsync_ReferencesEntryUnresolvedAgainstValidationData_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaScenario tsa = CreateTsaScenario();

        using PkiCertificateMemory sigTstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], "producer-refusal-twin sigTst fixture"u8.ToArray(),
            TestClock.CanonicalEpoch, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        byte[] sigTstTokenBytes = sigTstToken.AsReadOnlySpan().ToArray();

        DigestValue wrongPreimageDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            "this is not the certificate valData carries"u8.ToArray(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var certificateReference = new CBAdESCertificateReference(
            new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), wrongPreimageDigest));
        byte[] unrelatedValDataCertificateBytes = "the actual certificate bytes placed in valData"u8.ToArray();

        DigestValue x5tDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            "producer-refusal-twin signing certificate"u8.ToArray(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var x5t = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), x5tDigest);

        byte[] wireBytes;
        using(var unsignedHeaders = new CBAdESUnsignedHeaders(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(
                new AdESTimestampContainer([new AdESTimestampToken { Val = sigTstTokenBytes }]))),
            new CBAdESUnsignedHeaderElementReferences(new CBAdESReferences(certificateReferences: [certificateReference])),
            new CBAdESUnsignedHeaderElementValidationData(new CBAdESValidationData(
                certificateValues: [new CBAdESX509Certificate(new AdESPkiObject { Val = unrelatedValDataCertificateBytes })]))
        ]))
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: x5t);
            var payloadInput = new CBAdESAttachedPayloadInput("producer-refusal-twin payload"u8.ToArray());

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 encoded = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            wireBytes = encoded.AsReadOnlySpan().ToArray();
        }

        var responder = new CallCountingTimestampResponder();
        using var metered = new MeteredHousePool();
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(BuildSelfContainedRootCertificateBytes());
        var context = new CBAdESArchiveTimestampContext
        {
            WireBytes = wireBytes,
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://tsa.example/", FetchResponse = responder.FetchAsync }],
            SigningCertificate = signingCertificate,
            ChainCompletenessAttested = true,
            TargetLevel = AdESBaselineLevel.BLTA
        };

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);

        Assert.IsTrue(exception.Message.Contains("CB-A.1.1-30", StringComparison.Ordinal), "The pre-append refusal must name CB-A.1.1-30.");
        Assert.AreEqual(0, responder.CallCount, "An unresolved refs entry must refuse before contacting any Time-Stamping Authority.");
        Assert.AreEqual(0, metered.OutstandingCount, "Every carrier rented before the pre-append refusal must be disposed.");
    }


    /// <summary>
    /// A hand-assembled signature carrying a genuine <c>sigTst</c> instance (clearing
    /// the B-LTA ladder prerequisite) plus a <c>refs</c> element whose sole certificate reference DOES resolve
    /// against its own <c>valData</c> element -- clearing CB-A.1.1-30 immediately before this
    /// gate -- still refuses <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> BEFORE any
    /// Time-Stamping Authority round trip: Table 14 hard-forbids the whole refs/sigRTst/rfsTst family from
    /// B-LT onward (CB-6.3-23/-24/-25) regardless of whether its own cross-references resolve. Proves the NEW
    /// gate independently of
    /// <see cref="AddArchiveTimestampAsync_ReferencesEntryUnresolvedAgainstValidationData_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced"/>
    /// (the producer-refusal-twin test above), whose own refs entry does NOT resolve and therefore surfaces the CB-A.1.1-30 failure first,
    /// never reaching this gate at all -- the two tests together prove both gates run, in order, independently.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "certificateReference (and its own AdESCertificateThumbprint) becomes reachable " +
            "through the CBAdESUnsignedHeaderElementReferences entry of `unsignedHeaders`, disposed by the " +
            "'using(var unsignedHeaders = ...)' block below via CBAdESUnsignedHeaders.Dispose's own cascade " +
            "(CBAdESUnsignedHeaderElementReferences -> CBAdESReferences -> CBAdESCertificateReference -> " +
            "AdESCertificateThumbprint); the sigTst element's CBAdESSignatureTimestamp/AdESTimestampContainer " +
            "cascade the same way. x5t (its own AdESCertificateThumbprint) becomes reachable through `headers`, " +
            "which transfers to the returned CBAdESSignatureCreationResult on a successful SignAsync call " +
            "(that method's own SuppressMessage remarks), disposed here via 'using CBAdESSignatureCreationResult " +
            "creationResult'. Roslyn tracks the locally-constructed values themselves, not the fact that they " +
            "are reachable through one of those two disposed containers several constructor calls later.")]
    [TestMethod]
    public async Task AddArchiveTimestampAsync_RefsFamilyElementPresent_ThrowsTypedFailure_NeverContactsAuthority_MeteredPoolBalanced()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaScenario tsa = CreateTsaScenario();

        using PkiCertificateMemory sigTstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], "r2 refs-family-present sigTst fixture"u8.ToArray(),
            TestClock.CanonicalEpoch, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        byte[] sigTstTokenBytes = sigTstToken.AsReadOnlySpan().ToArray();

        byte[] valDataCertificateBytes = "r2 refs-family-present valData certificate bytes"u8.ToArray();
        DigestValue matchingDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            valDataCertificateBytes, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var certificateReference = new CBAdESCertificateReference(
            new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), matchingDigest));

        DigestValue x5tDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            "r2 refs-family-present signing certificate"u8.ToArray(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var x5t = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), x5tDigest);

        byte[] wireBytes;
        using(var unsignedHeaders = new CBAdESUnsignedHeaders(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(
                new AdESTimestampContainer([new AdESTimestampToken { Val = sigTstTokenBytes }]))),
            new CBAdESUnsignedHeaderElementReferences(new CBAdESReferences(certificateReferences: [certificateReference])),
            new CBAdESUnsignedHeaderElementValidationData(new CBAdESValidationData(
                certificateValues: [new CBAdESX509Certificate(new AdESPkiObject { Val = valDataCertificateBytes })]))
        ]))
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: x5t);
            var payloadInput = new CBAdESAttachedPayloadInput("r2 refs-family-present payload"u8.ToArray());

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 encoded = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            wireBytes = encoded.AsReadOnlySpan().ToArray();
        }

        var responder = new CallCountingTimestampResponder();
        using var metered = new MeteredHousePool();
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(BuildSelfContainedRootCertificateBytes());
        var context = new CBAdESArchiveTimestampContext
        {
            WireBytes = wireBytes,
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://tsa.example/", FetchResponse = responder.FetchAsync }],
            SigningCertificate = signingCertificate,
            ChainCompletenessAttested = true,
            TargetLevel = AdESBaselineLevel.BLTA
        };

        CBAdESAugmentationException exception = await Assert.ThrowsExactlyAsync<CBAdESAugmentationException>(async () =>
        {
            using EncodedCoseSign1 _ = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                context, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                metered.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);

        Assert.AreEqual(CBAdESAugmentationFailureKind.ArchiveTimestampReferencesFamilyElementPresent, exception.FailureKind);
        Assert.AreEqual(0, responder.CallCount, "CB-6.3-23/-24/-25: a refs-family element still present must never contact a Time-Stamping Authority.");
        Assert.AreEqual(0, metered.OutstandingCount, "Every carrier rented before the pre-append refusal must be disposed.");
    }


    /// <summary>
    /// Clause 5.3.5.2 step 1: when <see cref="CBAdESArchiveTimestampContext.GapFillValidationMaterial"/> is
    /// supplied, the new <c>valData</c> element is incorporated BEFORE the message imprint is computed -- the
    /// imprint then covers it. Proven at byte level by an INDEPENDENT oracle: the gap-filled element's own raw
    /// wire bytes are a byte-exact substring of the arcTst message-imprint input rebuilt through the shipped
    /// VALIDATION-mode builder, and the minted token's own message imprint verifies against that exact input.
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_GapFillValidationData_ImprintCoversNewValDataElement()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario sigTstTsa = CreateTsaScenario())
        using(TsaScenario arcTstTsa = CreateTsaScenario())
        using(PkiCertificateMemory gapFillCertificate = ToCertificateCarrier(arcTstTsa.Root.Certificate.RawData))
        {
            byte[] btWireBytes = await AugmentToSignatureTimestampAsync(wireBytes, sigTstTsa, TestContext.CancellationToken).ConfigureAwait(false);

            var arcTstResponder = new MintingTimestampResponder(arcTstTsa.Authority, [arcTstTsa.Authority], TestClock.CanonicalEpoch.AddHours(2));
            using PkiCertificateMemory signingCertificate = ToCertificateCarrier(arcTstTsa.Root.Certificate.RawData);

            byte[] ltaWireBytes;
            using(EncodedCoseSign1 ltaAugmented = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CBAdESArchiveTimestampContext
                {
                    WireBytes = btWireBytes,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = "https://arctst-tsa.example/", FetchResponse = arcTstResponder.FetchAsync }],
                    GapFillValidationMaterial = new CBAdESValidationMaterial { Certificates = [gapFillCertificate] },
                    SigningCertificate = signingCertificate,
                    ChainCompletenessAttested = true,
                    TargetLevel = AdESBaselineLevel.BLTA
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
            {
                ltaWireBytes = ltaAugmented.AsReadOnlySpan().ToArray();
            }

            CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(ltaWireBytes, BaseMemoryPool.Shared);
            using(parsed)
            {
                Assert.IsTrue(parsed.IsSuccess);
                Assert.HasCount(3, parsed.UnsignedHeaders!, "sigTst, gap-filled valData, then arcTst -- valData BEFORE arcTst (clause 5.3.5.2 step 1's ordering).");
                Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementValidationData>(parsed.UnsignedHeaders![1]);
                var arcTstElement = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementArchiveTimestamp>(parsed.UnsignedHeaders![2]);
                Assert.HasCount(1, arcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens);

                byte[] gapFilledValDataElementBytes = ReadRawUnsignedHeaderElement(parsed.RawUnsignedHeaders!, index: 1);

                PooledMemory? expectedImprintInput = null;
                bool built = false;
                try
                {
                    built = CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput(
                        CBAdESImprintCoseSign1StructureContext.Instance,
                        parsed.RawProtectedHeader!.AsReadOnlyMemory(), signerProtectedHeader: null, default,
                        new CBAdESAttachedPayloadTimestampImprintSource(parsed.Payload), countersignatureOtherFields: null,
                        parsed.Signature!.AsReadOnlyMemory(),
                        parsed.RawUnsignedHeaders?.AsReadOnlyMemory(), arcTstElementIndex: 2, BaseMemoryPool.Shared, out expectedImprintInput);

                    Assert.IsTrue(built, "The validation-mode arcTst message-imprint input must build over the final wire bytes.");

                    int substringIndex = expectedImprintInput!.AsReadOnlySpan().IndexOf((ReadOnlySpan<byte>)gapFilledValDataElementBytes);
                    Assert.IsGreaterThanOrEqualTo(0, substringIndex,
                        "The independent oracle: the gap-filled valData element's own raw wire bytes must be a byte-exact substring of the arcTst imprint input -- proving the imprint was computed AFTER, not before, gap-fill incorporation.");
                }
                finally
                {
                    expectedImprintInput?.Dispose();
                }

                Assert.IsTrue(built);

                await AssertArchiveTimestampTokenImprintMatchesAsync(
                    parsed, default, arcTstElementIndex: 2,
                    arcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens[0], TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
    }


    /// <summary>
    /// A second <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> call (a genuine renewal)
    /// appends a SECOND, sibling <c>arcTst</c> instance whose own message imprint -- rebuilt independently
    /// through the shipped VALIDATION-mode builder, prefix-bounded to this instance's own position -- covers
    /// the FIRST <c>arcTst</c> instance (the repeated-instance cross-check, cross-validated against
    /// the validation-side machinery elsewhere in this suite).
    /// </summary>
    [TestMethod]
    public async Task AddArchiveTimestampAsync_RepeatedCall_SecondInstanceImprintCoversFirst()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await CreateBaselineSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        using(privateKey)
        using(TsaScenario sigTstTsa = CreateTsaScenario())
        using(TsaScenario firstArcTsa = CreateTsaScenario())
        using(TsaScenario secondArcTsa = CreateTsaScenario())
        {
            byte[] btWireBytes = await AugmentToSignatureTimestampAsync(wireBytes, sigTstTsa, TestContext.CancellationToken).ConfigureAwait(false);

            byte[] firstArcTstWireBytes = await AugmentToArchiveTimestampAsync(
                btWireBytes, firstArcTsa, "https://first-arctst-tsa.example/", TestClock.CanonicalEpoch.AddHours(2), TestContext.CancellationToken).ConfigureAwait(false);

            byte[] secondArcTstWireBytes = await AugmentToArchiveTimestampAsync(
                firstArcTstWireBytes, secondArcTsa, "https://second-arctst-tsa.example/", TestClock.CanonicalEpoch.AddHours(3), TestContext.CancellationToken).ConfigureAwait(false);

            CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(secondArcTstWireBytes, BaseMemoryPool.Shared);
            using(parsed)
            {
                Assert.IsTrue(parsed.IsSuccess);
                Assert.HasCount(3, parsed.UnsignedHeaders!, "sigTst, arcTst#1, arcTst#2.");
                Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementArchiveTimestamp>(parsed.UnsignedHeaders![1]);
                var secondArcTstElement = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementArchiveTimestamp>(parsed.UnsignedHeaders![2]);
                Assert.HasCount(1, secondArcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens);

                await AssertArchiveTimestampTokenImprintMatchesAsync(
                    parsed, default, arcTstElementIndex: 2,
                    secondArcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens[0], TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
    }


    /// <summary>Raises <paramref name="wireBytes"/> to CB-AdES-B-T through the shipped <see cref="CBAdESSignatureAugmentation.AddSignatureTimestampAsync"/> path, minting a genuine token under <paramref name="tsa"/>'s authority.</summary>
    /// <param name="wireBytes">The B-B signature's wire bytes.</param>
    /// <param name="tsa">The Time-Stamping Authority scenario the <c>sigTst</c> token is minted under.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The B-T signature's wire bytes.</returns>
    private static async ValueTask<byte[]> AugmentToSignatureTimestampAsync(byte[] wireBytes, TsaScenario tsa, CancellationToken cancellationToken)
    {
        var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], TestClock.CanonicalEpoch.AddHours(1));
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(tsa.Root.Certificate.RawData);

        using EncodedCoseSign1 augmented = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CBAdESSignatureTimestampContext
            {
                WireBytes = wireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = "https://sigtst-tsa.example/",
                FetchResponse = responder.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
            CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        return augmented.AsReadOnlySpan().ToArray();
    }


    /// <summary>Raises <paramref name="wireBytes"/> with a new <c>arcTst</c> instance through the shipped <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> path, minting a genuine single-TSA token under <paramref name="tsa"/>'s authority.</summary>
    /// <param name="wireBytes">The signature's wire bytes to augment.</param>
    /// <param name="tsa">The Time-Stamping Authority scenario the <c>arcTst</c> token is minted under.</param>
    /// <param name="tsaUri">The Time-Stamping Authority address this call states.</param>
    /// <param name="generationTime">The <c>genTime</c> the minted token states.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's wire bytes.</returns>
    private static async ValueTask<byte[]> AugmentToArchiveTimestampAsync(
        byte[] wireBytes, TsaScenario tsa, string tsaUri, DateTimeOffset generationTime, CancellationToken cancellationToken)
    {
        var responder = new MintingTimestampResponder(tsa.Authority, [tsa.Authority], generationTime);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(tsa.Root.Certificate.RawData);

        using EncodedCoseSign1 augmented = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CBAdESArchiveTimestampContext
            {
                WireBytes = wireBytes,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = tsaUri, FetchResponse = responder.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                TargetLevel = AdESBaselineLevel.BLTA
            },
            CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
            CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
            BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

        return augmented.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Opens <paramref name="token"/> and asserts its own message imprint matches the clause 5.3.5.3
    /// VALIDATION-mode imprint input built via the shipped
    /// <see cref="CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput"/>
    /// for the <c>arcTst</c> instance at <paramref name="arcTstElementIndex"/> -- an INDEPENDENT cross-check
    /// against the VALIDATION half of the imprint machinery (never the GENERATION-mode builder the
    /// augmentation call under test itself used), proving the token was genuinely minted over that exact byte
    /// sequence. Assumes an attached payload (every fixture in this file uses one).
    /// </summary>
    /// <param name="parsed">The final, re-parsed signature.</param>
    /// <param name="externallySuppliedData">The externally supplied application data the original call bound.</param>
    /// <param name="arcTstElementIndex">The <c>arcTst</c> instance's own zero-based position within <c>uHeaders</c>.</param>
    /// <param name="token">The token to verify.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask AssertArchiveTimestampTokenImprintMatchesAsync(
        CBAdESSign1ParseResult parsed,
        ReadOnlyMemory<byte> externallySuppliedData,
        int arcTstElementIndex,
        AdESTimestampToken token,
        CancellationToken cancellationToken)
    {
        bool built = CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput(
            CBAdESImprintCoseSign1StructureContext.Instance,
            parsed.RawProtectedHeader!.AsReadOnlyMemory(),
            signerProtectedHeader: null,
            externallySuppliedData,
            new CBAdESAttachedPayloadTimestampImprintSource(parsed.Payload),
            countersignatureOtherFields: null,
            parsed.Signature!.AsReadOnlyMemory(),
            parsed.RawUnsignedHeaders?.AsReadOnlyMemory(),
            arcTstElementIndex,
            BaseMemoryPool.Shared,
            out PooledMemory? expectedInput);

        Assert.IsTrue(built, "The validation-mode arcTst message-imprint input must build over the final wire bytes.");
        using(expectedInput)
        {
            using PkiCertificateMemory tokenCarrier = ToTokenCarrier(token.Val.ToArray());
            using TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(tokenCarrier, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            Assert.IsTrue(tokenInfo.IsRead, "The minted arcTst token must be readable.");

            bool matches = await tokenInfo.VerifyMessageImprintAsync(expectedInput!.AsReadOnlyMemory(), BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            Assert.IsTrue(matches, "The arcTst token's message imprint must match the validation-mode imprint input rebuilt independently over the final wire bytes (clause 5.3.5.3).");
        }
    }


    /// <summary>
    /// Hand-assembles (independent <see cref="CborWriter"/>) a <c>sigTst</c> <c>UHeaderInstance</c> (clause
    /// 5.3.3) encapsulating exactly one electronic time-stamp token -- mirroring
    /// <see cref="BuildRfsTstUHeaderInstance"/>'s own shape for the sibling <c>rfsTst</c> label.
    /// </summary>
    /// <param name="tokenDerBytes">The token's own octets; need not be a well-formed DER token (e.g. an arbitrary garbage byte sequence, for a token that is genuinely unreadable).</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes (label 1, unwrapped).</returns>
    private static byte[] BuildSignatureTimestampUHeaderInstance(byte[] tokenDerBytes)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);

        writer.WriteStartMap(1); //UHeaderInstance: { 1 => sigTst }
        writer.WriteInt32(CBAdESUnsignedHeaderElement.SignatureTimestampLabel);
        writer.WriteStartMap(1); //tstContainer: { 1 => [TstToken] }
        writer.WriteInt32(CBAdESWireKeys.TimestampContainerTstTokens);
        writer.WriteStartArray(1);
        writer.WriteStartMap(1); //TstToken: { 1 => val }
        writer.WriteInt32(CBAdESWireKeys.TimestampTokenVal);
        writer.WriteByteString(tokenDerBytes);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>Builds a self-contained, well-formed X.509 certificate DER blob, standing in for a readable signing certificate the letter-k/level refusal tests never actually need to reach a Time-Stamping Authority under.</summary>
    /// <returns>The DER-encoded certificate bytes.</returns>
    private static byte[] BuildSelfContainedRootCertificateBytes()
    {
        using TsaScenario scenario = CreateTsaScenario();
        return scenario.Root.Certificate.RawData;
    }


    /// <summary>Computes a SHA-256 digest over an arbitrary fixture byte sequence, through the registered digest delegate.</summary>
    /// <param name="content">The bytes to digest.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>An independent copy of the digest bytes.</returns>
    private static async ValueTask<byte[]> ComputeArbitraryFixtureDigestAsync(byte[] content, CancellationToken cancellationToken)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            content, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Hand-assembles (independent <see cref="CborWriter"/>, never any writer this library ships) a <c>refs</c>
    /// <c>UHeaderInstance</c> (Annex A.1.1) carrying exactly one OCSP revocation reference, whose
    /// <c>ocspId.producedAt</c> is the caller-supplied RFC 3339 string verbatim -- deliberately bypassing
    /// <see cref="CBAdESSerialization.WriteTDate"/>'s whole-second/forced-<c>Z</c> writer so the fixture can
    /// carry a form that writer can never itself produce.
    /// </summary>
    /// <param name="producedAtRfc3339">The <c>ocspId.producedAt</c> RFC 3339 string to write verbatim.</param>
    /// <param name="ocspResponseDigestBytes">The OCSP response's SHA-256 digest bytes.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes (label 4, unwrapped -- the caller bstr-wraps it as an array element).</returns>
    private static byte[] BuildRefsUHeaderInstanceWithOcspProducedAt(string producedAtRfc3339, byte[] ocspResponseDigestBytes)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);

        writer.WriteStartMap(1); //UHeaderInstance: { 4 => refs }
        writer.WriteInt32(CBAdESUnsignedHeaderElement.ReferencesLabel);

        writer.WriteStartMap(1); //refs: { 2 => rRefs } (rRefs only; no xRefs)
        writer.WriteInt32(CBAdESReferences.RevocationReferencesKey);

        writer.WriteStartMap(1); //rRefs: { 2 => [OCSPRef] }
        writer.WriteInt32(CBAdESRevocationReferences.OcspReferencesKey);
        writer.WriteStartArray(1);

        writer.WriteStartMap(2); //OCSPRef: { 1 => DigAlgVal, 2 => OCSPId }
        writer.WriteInt32(CBAdESOcspReference.DigAlgValKey);
        writer.WriteStartArray(2); //DigAlgVal: [hashAlg, hashValue]
        writer.WriteInt32(WellKnownCoseAlgorithms.Sha256);
        writer.WriteByteString(ocspResponseDigestBytes);
        writer.WriteEndArray();

        writer.WriteInt32(CBAdESOcspReference.OcspIdentifierKey);
        writer.WriteStartMap(2); //OCSPId: { 1 => ResponderIdChoice, 2 => producedAt }
        writer.WriteInt32(CBAdESOcspIdentifier.ResponderKey);
        writer.WriteStartMap(1); //ResponderIdChoice: { byNameKey => bstr }
        writer.WriteInt32(CBAdESOcspResponderIdentifier.ByNameKey);
        writer.WriteByteString("fixture responder name"u8);
        writer.WriteEndMap();

        writer.WriteInt32(CBAdESOcspIdentifier.ProducedAtKey);
        writer.WriteTag(CborTag.DateTimeString); //#6.0(tstr) -- deliberately sub-second, non-Z-offset.
        writer.WriteTextString(producedAtRfc3339);
        writer.WriteEndMap(); //end OCSPId

        writer.WriteEndMap(); //end OCSPRef
        writer.WriteEndArray(); //end [OCSPRef]
        writer.WriteEndMap(); //end rRefs
        writer.WriteEndMap(); //end refs
        writer.WriteEndMap(); //end UHeaderInstance

        return writer.Encode();
    }


    /// <summary>
    /// Hand-assembles (independent <see cref="CborWriter"/>) an <c>rfsTst</c> <c>UHeaderInstance</c> (Annex
    /// A.1.2.2.1) encapsulating exactly one electronic time-stamp token.
    /// </summary>
    /// <param name="tokenDerBytes">The DER-encoded RFC 3161 token bytes.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes (label 6, unwrapped).</returns>
    private static byte[] BuildRfsTstUHeaderInstance(byte[] tokenDerBytes)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);

        writer.WriteStartMap(1); //UHeaderInstance: { 6 => rfsTst }
        writer.WriteInt32(CBAdESUnsignedHeaderElement.ReferencesTimestampLabel);
        writer.WriteStartMap(1); //tstContainer: { 1 => [TstToken] }
        writer.WriteInt32(CBAdESWireKeys.TimestampContainerTstTokens);
        writer.WriteStartArray(1);
        writer.WriteStartMap(1); //TstToken: { 1 => val }
        writer.WriteInt32(CBAdESWireKeys.TimestampTokenVal);
        writer.WriteByteString(tokenDerBytes);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>
    /// Hand-assembles (independent <see cref="CborWriter"/>) an <c>Unknown</c>-arm <c>UHeaderInstance</c>
    /// (CB-5.3.1-11's catch-all) under an integer label this document does not itself specify, carrying an
    /// arbitrary, non-trivial nested map as its inner value -- standing in for whatever a future, unspecified
    /// CB-AdES component might carry; this library never decodes it.
    /// </summary>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes, unwrapped.</returns>
    private static byte[] BuildUnknownUHeaderInstance()
    {
        const int unknownLabel = 100;

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(unknownLabel);

        writer.WriteStartMap(2);
        writer.WriteTextString("fixture-key");
        writer.WriteStartArray(3);
        writer.WriteInt32(1);
        writer.WriteInt32(2);
        writer.WriteInt32(3);
        writer.WriteEndArray();
        writer.WriteTextString("second-key");
        writer.WriteTextString("second-value");
        writer.WriteEndMap();

        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>
    /// Hand-assembles (independent <see cref="CborWriter"/>) a <c>uHeaders</c> array from already-encoded
    /// <c>UHeaderInstance</c> map bytes, bstr-wrapping each (CB-5.3.1-04).
    /// </summary>
    /// <param name="uHeaderInstances">Each element's own encoded <c>UHeaderInstance</c> map bytes, in wire order.</param>
    /// <returns>The encoded <c>uHeaders</c> array bytes.</returns>
    private static byte[] BuildRawUHeadersArray(params byte[][] uHeaderInstances)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(uHeaderInstances.Length);
        foreach(byte[] instance in uHeaderInstances)
        {
            writer.WriteByteString(instance);
        }

        writer.WriteEndArray();
        return writer.Encode();
    }


    /// <summary>
    /// Hand-assembles a complete CB-AdES <c>COSE_Sign1</c>, reusing <paramref name="baselineWireBytes"/>'s
    /// OWN protected header, payload, and signature bytes VERBATIM (parsed then re-written unchanged, so the
    /// signature stays genuinely valid over them) while replacing the unprotected map with a hand-built
    /// <c>uHeaders</c> array from <paramref name="uHeaderInstances"/> -- the "independent CBOR assembly"
    /// technique this file's regression fixtures use to construct wire content the shipped creation path
    /// cannot itself produce.
    /// </summary>
    /// <param name="baselineWireBytes">A genuinely-signed CB-AdES B-B signature's wire bytes to borrow the protected header/payload/signature from.</param>
    /// <param name="uHeaderInstances">Each new <c>uHeaders</c> element's own encoded <c>UHeaderInstance</c> map bytes, in wire order.</param>
    /// <returns>The hand-assembled wire bytes.</returns>
    private static byte[] BuildHandAssembledWireBytesWithCustomUHeaders(byte[] baselineWireBytes, params byte[][] uHeaderInstances)
    {
        CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(baselineWireBytes, BaseMemoryPool.Shared);
        using(parsed)
        {
            Assert.IsTrue(parsed.IsSuccess, "The baseline signature this fixture borrows its protected header/payload/signature from must itself parse.");

            byte[] protectedHeaderBytes = parsed.RawProtectedHeader!.AsReadOnlySpan().ToArray();
            byte[] signatureBytes = parsed.Signature!.AsReadOnlySpan().ToArray();
            bool payloadIsPresent = parsed.PayloadIsPresent;
            byte[] payloadBytes = parsed.Payload.ToArray();

            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteTag((CborTag)CoseTags.Sign1);
            writer.WriteStartArray(4);

            writer.WriteByteString(protectedHeaderBytes);

            writer.WriteStartMap(1);
            writer.WriteInt32(CBAdESHeaderParameters.UHeaders);
            writer.WriteStartArray(uHeaderInstances.Length);
            foreach(byte[] instance in uHeaderInstances)
            {
                writer.WriteByteString(instance);
            }

            writer.WriteEndArray();
            writer.WriteEndMap();

            if(payloadIsPresent)
            {
                writer.WriteByteString(payloadBytes);
            }
            else
            {
                writer.WriteNull();
            }

            writer.WriteByteString(signatureBytes);
            writer.WriteEndArray();

            return writer.Encode();
        }
    }


    /// <summary>
    /// Reads one <c>uHeaders</c> array element's own FULL encoded bytes (the <c>bstr</c> wrapper's header and
    /// content together) at <paramref name="index"/>, through an INDEPENDENT <see cref="CborReader"/> over
    /// <paramref name="rawUnsignedHeaders"/>'s own wire bytes -- the byte-exactness oracle the regressions above
    /// compare against, never the library's own decode/re-encode path.
    /// </summary>
    /// <param name="rawUnsignedHeaders">The raw captured <c>uHeaders</c> array wire bytes.</param>
    /// <param name="index">The zero-based element position to read.</param>
    /// <returns>That element's own encoded bytes, verbatim.</returns>
    private static byte[] ReadRawUnsignedHeaderElement(EncodedCBAdESUnsignedHeaders rawUnsignedHeaders, int index)
    {
        var reader = new CborReader(rawUnsignedHeaders.AsReadOnlyMemory(), CborConformanceMode.Canonical);
        int? count = reader.ReadStartArray();
        Assert.IsNotNull(count);

        for(int i = 0; i < count.Value; ++i)
        {
            ReadOnlyMemory<byte> element = reader.ReadEncodedValue();
            if(i == index)
            {
                return element.ToArray();
            }
        }

        throw new ArgumentOutOfRangeException(nameof(index), index, $"The uHeaders array has only {count.Value} element(s).");
    }


    /// <summary>Rents pool memory of the given tag and length 4, for a PKI-object-shaped carrier fixture.</summary>
    /// <param name="tag">The <see cref="PkiObjectKind"/>-carrying tag to stamp the carrier with.</param>
    /// <returns>The rented carrier.</returns>
    private static PkiCertificateMemory CreatePkiCarrier(Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(4);
        new byte[] { 1, 2, 3, 4 }.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>A transport stub that never actually runs (every test above either never calls acquisition, or fails before reaching it).</summary>
    /// <param name="context">The fetch context; unused.</param>
    /// <param name="pool">The memory pool; unused.</param>
    /// <param name="cancellationToken">The cancellation token; unused.</param>
    /// <returns>Always <see langword="null"/> (the "authority unreachable" signal), never actually observed by these tests.</returns>
    private static ValueTask<PkiCertificateMemory?> StubFetchResponseAsync(
        TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken) =>
        ValueTask.FromResult<PkiCertificateMemory?>(null);


    /// <summary>
    /// A transport stub that always throws <see cref="OperationCanceledException"/>, simulating a cancellation
    /// observed mid-flight during the Time-Stamping Authority round trip — the mechanism the cancellation-path
    /// leak regression test uses to exercise <see cref="CBAdESSignatureAugmentation"/>'s <c>finally</c>-block
    /// dispose discipline without needing a real network round trip to interrupt.
    /// </summary>
    /// <param name="context">The fetch context; unused.</param>
    /// <param name="pool">The memory pool; unused.</param>
    /// <param name="cancellationToken">The cancellation token; unused.</param>
    /// <returns>Never returns; always throws.</returns>
    private static ValueTask<PkiCertificateMemory?> ThrowsOperationCanceledFetchResponseAsync(
        TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken) =>
        throw new OperationCanceledException("Simulated cancellation observed mid-flight during the Time-Stamping Authority round trip.");


    /// <summary>
    /// Builds a minimal, conformant CB-AdES-B-B signature (<c>alg</c>+<c>iat</c>+<c>x5t</c>, attached payload)
    /// through the SHIPPED <see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
    /// path — the fixture every augmentation test in this file starts from, per the "flow tests run the shipped
    /// path" convention.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The signature's wire bytes, and the matching key pair. The caller owns and disposes the keys.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "method disposes via 'using creationResult' -- the identical pattern CBAdESSignatureFlowTests uses.")]
    private static async ValueTask<(byte[] WireBytes, PublicKeyMemory PublicKey, PrivateKeyMemory PrivateKey)> CreateBaselineSignatureAsync(
        CancellationToken cancellationToken)
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        PublicKeyMemory publicKey = keyMaterial.PublicKey;
        PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            "CBAdESSignatureAugmentationTests placeholder signing certificate"u8.ToArray(),
            32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);

        byte[] payloadBytes = "CBAdESSignatureAugmentationTests baseline fixture payload"u8.ToArray();
        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
        var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure, privateKey,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);

        return (wireBytes.AsReadOnlySpan().ToArray(), publicKey, privateKey);
    }


    /// <summary>Wraps DER bytes in a pool-rented <see cref="PkiCertificateMemory"/> tagged as an X.509 certificate.</summary>
    /// <param name="certificate">The DER-encoded certificate.</param>
    /// <returns>The rented carrier. The caller disposes it.</returns>
    private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
        certificate.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>Wraps DER bytes in a pool-rented <see cref="PkiCertificateMemory"/> tagged as an RFC 3161 time-stamp token.</summary>
    /// <param name="token">The DER-encoded token.</param>
    /// <returns>The rented carrier. The caller disposes it.</returns>
    private static PkiCertificateMemory ToTokenCarrier(byte[] token)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(token.Length);
        token.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
    }


    /// <summary>
    /// Assembles a structurally pseudo, otherwise well-formed X.509 certificate whose <c>issuer</c> field is a
    /// NULL TLV rather than a SEQUENCE (RFC 5280 §4.1.2.4) — a shape-strictness
    /// regression, fed here as <see cref="CBAdESSignatureTimestampContext.SigningCertificate"/> to prove the
    /// pre-Time-Stamping-Authority readability check (<see cref="CertificateValidityPeriod.TryRead"/>)
    /// closes over it.
    /// </summary>
    /// <returns>The pooled certificate carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory BuildNullIssuerCertificate()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                        //Certificate.
        {
            using(writer.PushSequence())                                    //tbsCertificate.
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteInteger(2);                                 //version v3.
                }

                writer.WriteInteger(1);                                     //serialNumber stand-in.
                using(writer.PushSequence())                                //signature AlgorithmIdentifier stand-in.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                }

                writer.WriteNull();                                         //issuer -- NOT a SEQUENCE.
                using(writer.PushSequence())                                //validity.
                {
                    writer.WriteUtcTime(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
                    writer.WriteUtcTime(new DateTimeOffset(2034, 1, 1, 0, 0, 0, TimeSpan.Zero));
                }

                using(writer.PushSequence())                                //subject -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //subjectPublicKeyInfo stand-in, never reached.
                {
                }
            }

            using(writer.PushSequence())                                    //signatureAlgorithm stand-in.
            {
                writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            writer.WriteBitString([]);                                      //signatureValue stand-in.
        }

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        _ = writer.Encode(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>Builds a Root CA and Time-Stamping Authority anchored to <see cref="TestClock.CanonicalEpoch"/>.</summary>
    /// <returns>The scenario; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both nodes transfers to the returned TsaScenario, which the caller disposes; the catch disposes the root on a partial failure.")]
    private static TsaScenario CreateTsaScenario()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
        try
        {
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider);
            return new TsaScenario(root, authority);
        }
        catch
        {
            root.Dispose();
            throw;
        }
    }


    /// <summary>The minted Root CA and Time-Stamping Authority nodes for one scenario, disposed together.</summary>
    /// <param name="Root">The Root CA node.</param>
    /// <param name="Authority">The Time-Stamping Authority node, issued by <see cref="Root"/>.</param>
    private sealed record TsaScenario(X509ChainTestRingNode Root, X509ChainTestRingNode Authority): IDisposable
    {
        /// <inheritdoc/>
        public void Dispose()
        {
            Authority.Dispose();
            Root.Dispose();
        }
    }


    /// <summary>
    /// A <see cref="FetchTimestampResponseAsyncDelegate"/> test double that counts its own invocations and
    /// always reports the authority unreachable — proves a refused call never bills a Time-Stamping Authority
    /// round trip (the sigRTst/rfsTst generation-gate tests).
    /// </summary>
    private sealed class CallCountingTimestampResponder
    {
        /// <summary>Gets the number of times <see cref="FetchAsync"/> was invoked.</summary>
        internal int CallCount { get; private set; }


        /// <summary>Implements <see cref="FetchTimestampResponseAsyncDelegate"/>: records the call and reports the authority as unreachable.</summary>
        /// <param name="context">The fetch context; unused, as this test double never answers a request.</param>
        /// <param name="pool">The memory pool; unused, as nothing is ever returned.</param>
        /// <param name="cancellationToken">A cancellation token; unused, as this double performs no input or output.</param>
        /// <returns>Always <see langword="null"/>, simulating an unreachable authority.</returns>
        internal ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            ++CallCount;
            return ValueTask.FromResult<PkiCertificateMemory?>(null);
        }
    }
}
