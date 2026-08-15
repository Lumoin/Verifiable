using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
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
/// Firewalled lifecycle end-to-end flow tests for CB-AdES B-T/B-LT augmentation and validation, through the
/// SHIPPED <see cref="CBAdESSignatureCreation"/> -&gt; <see cref="CBAdESSignatureAugmentation"/> -&gt;
/// <see cref="CBAdESSignatureValidation"/> composition, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Firewall discipline (identical to <see cref="CBAdESSignatureFlowTests"/>).</strong> Every step a
/// signer performs -- creation, every augmentation verb, every Time-Stamping Authority acquisition -- runs
/// inside its own nested block scope and disposes every creation/augmentation-side carrier before the block
/// ends, copying ONLY the serialized wire bytes into an independent, GC-owned <c>byte[]</c> that crosses to the
/// next step. The final <see cref="CBAdESSignatureValidation.ValidateAsync"/> call of every flow below
/// reconstructs everything from that wire-bytes copy alone -- never a creation-side object, model, or
/// in-memory decoded fact -- and, for flow 10's detached leg, its OWN dereference delegate instance and
/// context over the shared published-object store (mirroring flows 3/4 of the sibling file).
/// </para>
/// <para>
/// <strong>Time-Stamping Authority, recorded here.</strong> Every <c>sigTst</c>/<c>sigRTst</c>/<c>rfsTst</c>/<c>adoTst</c> acquisition below goes
/// through <see cref="MintingTimestampResponder"/> -- an in-process transport fake (no sockets; the
/// wire-socket leg over a real loopback HTTP TSA host is a separate concern, out of this file's scope) that GENUINELY decodes
/// the <c>TimeStampReq</c> it is handed and mints a real RFC&#160;3161 token over the imprint the request
/// actually states, through the independent BouncyCastle protocol oracle
/// (<see cref="X509ChainTestRingTimestamping.MintTimestampTokenOverImprint"/>). This is used instead of a
/// canned, request-independent responder in the shape of
/// <see cref="Verifiable.Tests.Cryptography.TimestampAcquisitionTests"/>'s own <c>FixedTimestampResponder</c>
/// because none of this file's flows know the exact message-imprint bytes ahead of the production call that
/// derives them (a COSE signature value, a raw <c>uHeaders</c> array slice, or a dereferenced payload the
/// orchestrator itself assembles) -- answering genuinely, from whatever the actual request states, is both
/// simpler and more faithful to a real Time-Stamping Authority than pre-baking a fixed response that would
/// otherwise have to guess those bytes.
/// </para>
/// <para>
/// <strong>Table 14 additional requirement (d) is out of this file's scope.</strong> Every
/// <see cref="CBAdESSignatureTimestampContext"/> below sets
/// <see cref="CBAdESSignatureTimestampContext.EnforceSigningCertificateValidity"/> to <see langword="false"/>
/// explicitly: that requirement (an acquired token's generation time against the signing certificate's
/// validity window) needs a REAL, ASN.1-parseable signing certificate, which these lifecycle flows -- about
/// level transitions and message-imprint binding, not certificate validity -- have no independent need to
/// mint; that positive/negative behavioral coverage belongs to the dedicated rule unit tests elsewhere in this suite.
/// </para>
/// <para>
/// <strong>Table 14 additional requirement (h) at B-LT: the two legal choreographies.</strong>
/// <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/>'s own internal
/// <see cref="CBAdESLevelRules.EnsureConformant"/> call requires requirement (h)'s disjunction satisfied at
/// <see cref="AdESBaselineLevel.BLT"/>: validation material is either present as a <c>valData</c> element, or
/// attested as embedded in an already-present token's own CMS content via
/// <see cref="CBAdESStripReferencesContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/> (a caller-
/// ATTESTED fact, fail-closed default <see langword="false"/>) — a dedicated unit test in
/// <see cref="CBAdESSignatureAugmentationTests"/> exercises the resulting one-step choreography directly. Flow
/// 8 below exercises the OTHER, equally legal two-step choreography: strip at
/// <see cref="CBAdESStripReferencesContext.TargetLevel"/> <see cref="AdESBaselineLevel.BT"/> (the level that
/// only PREPARES the B-LT transition when the embedded-material fact is left at its default) followed by the
/// immediately-following <see cref="CBAdESSignatureAugmentation.AddValidationDataAsync"/> call that places
/// <c>valData</c> and reaches <see cref="AdESBaselineLevel.BLT"/> — the ordering every B-LT upgrade below
/// uses. Genuinely exercising the SPO through a real minted token's own CMS-embedded material (rather than a
/// caller-attested bool) is a residual flow-coverage gap (see the CB-6.3-28 matrix row).
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESLifecycleFlowTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The Time-Stamping Authority URI every acquisition context below states; never dialled over a socket -- the transport is <see cref="MintingTimestampResponder"/>.</summary>
    private static string TsaUri { get; } = "https://tsa.example.test/";

    /// <summary>The tag every test-side detached-object-store fixture buffer carries (flow 10).</summary>
    private static Tag DetachedObjectContentTag { get; } = Tag.Create(Purpose.Data);


    /// <summary>
    /// Flow 7, positive leg: creates a B-B signature, augments it to B-T with <c>sigTst</c> (validating the
    /// intermediate B-T wire bytes on their own), then upgrades to B-LT with <c>valData</c>, and validates the
    /// FINAL B-LT wire bytes -- the signature verifies, the <c>sigTst</c> imprint binds the signature value,
    /// and Table 14 additional requirement (h)'s validation-data-for-time-stamps service is satisfied through
    /// the <c>valData</c> SPO.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.3.3-02, CB-6.1-01, CB-6.3-01, CB-6.3-21, CB-6.3-22, CB-6.3-27.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult', mirroring CBAdESSignatureFlowTests's own convention.")]
    [TestMethod]
    public async Task LifecycleFlowCreatesBBAugmentsToBTThenBLTAndValidatesAtEachStage()
    {
        byte[] payloadBytes = "CB-AdES flow 7 -- full lifecycle B-B to B-T to B-LT payload"u8.ToArray();
        (AdESCertificateThumbprint thumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] bbWireCopy;
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            bbWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using TsaScenario scenario = BuildTsaScenario();
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], TestClock.CanonicalEpoch);

        byte[] btWireCopy;
        {
            var timestampContext = new CBAdESSignatureTimestampContext
            {
                WireBytes = bbWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                EnforceSigningCertificateValidity = false,
                TargetLevel = AdESBaselineLevel.BT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                timestampContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            btWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        //Firewall: the intermediate B-T bytes validate from wire bytes alone before the chain continues to B-LT.
        using(CBAdESValidationResult btResult = await ValidateAtLevelAsync(
            btWireCopy, publicKey, AdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(btResult.IsValid, "The intermediate B-T signature must validate at level B-T: its sigTst imprint binds the signature value.");
            Assert.HasCount(1, btResult.Verified!.Value.Value.UnsignedHeaders!, "Only the sigTst element has been added at this point.");
            Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementSignatureTimestamp>(btResult.Verified.Value.Value.UnsignedHeaders![0]);
        }

        byte[] bltWireCopy;
        {
            using PkiCertificateMemory validationCertificate = CreatePkiCarrier([0x30, 0x05, 0x02, 0x01, 0x2A], PkiCertificateTags.X509Certificate);
            var validationDataContext = new CBAdESValidationDataContext
            {
                WireBytes = btWireCopy,
                Material = new CBAdESValidationMaterial { Certificates = [validationCertificate] },
                TargetLevel = AdESBaselineLevel.BLT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddValidationDataAsync(
                validationDataContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            bltWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        //Firewall: only bltWireCopy crosses from here on for the final validation.
        using CBAdESValidationResult bltResult = await ValidateAtLevelAsync(
            bltWireCopy, publicKey, AdESBaselineLevel.BLT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(bltResult.IsValid, "A genuine B-LT signature (sigTst + valData) must validate at level B-LT.");
        Assert.HasCount(2, bltResult.Verified!.Value.Value.UnsignedHeaders!, "sigTst and valData are both present; no other element was added.");

        bool hasValidationData = false;
        for(int i = 0; i < bltResult.Verified.Value.Value.UnsignedHeaders!.Count; ++i)
        {
            hasValidationData |= bltResult.Verified.Value.Value.UnsignedHeaders[i] is CBAdESUnsignedHeaderElementValidationData;
        }

        Assert.IsTrue(hasValidationData, "The B-LT signature must carry the valData element the service check (CB-6.3-26) is satisfied through.");
    }


    /// <summary>
    /// Flow 7, negative leg: the B-B bytes -- carrying no <c>sigTst</c> at all -- fail closed when validated at
    /// level B-T, collecting the CB-6.3-21 sigTst-missing violation, never a thrown exception.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult', mirroring CBAdESSignatureFlowTests's own convention.")]
    [TestMethod]
    public async Task LifecycleFlowBBBytesFailClosedWhenValidatedAtBTForMissingSignatureTimestamp()
    {
        byte[] payloadBytes = "CB-AdES flow 7 negative -- B-B bytes validated at B-T payload"u8.ToArray();
        (AdESCertificateThumbprint thumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] bbWireCopy;
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            bbWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult result = await ValidateAtLevelAsync(
            bbWireCopy, publicKey, AdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A B-B signature carrying no sigTst must not validate at level B-T.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);

        bool hasMissingSigTst = false;
        for(int i = 0; i < failure.Violations.Count; ++i)
        {
            hasMissingSigTst |= failure.Violations[i] is CBAdESSignatureTimestampMissingViolation;
        }

        Assert.IsTrue(hasMissingSigTst, "The collected violations must include the CB-6.3-21 sigTst-missing violation.");
    }


    /// <summary>
    /// Flow 8, positive leg: creates a B-B signature, adds <c>refs</c>, augments to B-T with <c>sigTst</c>,
    /// then adds BOTH <c>sigRTst</c> and <c>rfsTst</c> (validating the resulting B-T wire bytes -- every
    /// imprint verifies against the RAW wire <c>uHeaders</c> slice), then upgrades to B-LT by stripping the
    /// whole <c>refs</c> family and placing <c>valData</c>, and validates the FINAL B-LT wire bytes -- the
    /// refs family is gone and CB-A.1.1-30 is (trivially) satisfied once <c>refs</c> no longer exists.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-6.3-23, CB-6.3-24, CB-6.3-25.
    /// </remarks>
    [TestMethod]
    public async Task ReferencesFamilyFlowCreatesRefsSigRTstAndRfsTstThenUpgradesToBLTStrippingTheFamily()
    {
        byte[] payloadBytes = "CB-AdES flow 8 -- refs family through B-T to B-LT payload"u8.ToArray();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        (byte[] btWireCopy, byte[] _) = await BuildReferencesFamilyBaselineAtBTAsync(
            privateKey, payloadBytes, TestContext.CancellationToken).ConfigureAwait(false);

        using(CBAdESValidationResult btResult = await ValidateAtLevelAsync(
            btWireCopy, publicKey, AdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(btResult.IsValid, "The refs family (refs+sigTst+sigRTst+rfsTst) must validate at level B-T: every imprint binds the RAW wire uHeaders bytes.");
            Assert.HasCount(4, btResult.Verified!.Value.Value.UnsignedHeaders!, "refs, sigTst, sigRTst, and rfsTst are all present.");
        }

        byte[] strippedWireCopy;
        {
            var stripContext = new CBAdESStripReferencesContext { WireBytes = btWireCopy, TargetLevel = AdESBaselineLevel.BT };
            using EncodedCoseSign1 wireBytes = CBAdESSignatureAugmentation.StripReferencesForLongTerm(
                stripContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared);
            strippedWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] bltWireCopy;
        {
            using PkiCertificateMemory validationCertificate = CreatePkiCarrier([0x30, 0x05, 0x02, 0x01, 0x3A], PkiCertificateTags.X509Certificate);
            var validationDataContext = new CBAdESValidationDataContext
            {
                WireBytes = strippedWireCopy,
                Material = new CBAdESValidationMaterial { Certificates = [validationCertificate] },
                TargetLevel = AdESBaselineLevel.BLT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddValidationDataAsync(
                validationDataContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            bltWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult bltResult = await ValidateAtLevelAsync(
            bltWireCopy, publicKey, AdESBaselineLevel.BLT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(bltResult.IsValid, "The stripped-and-valData-augmented signature must validate at level B-LT: CB-A.1.1-30 is trivially satisfied once refs is gone.");
        Assert.HasCount(2, bltResult.Verified!.Value.Value.UnsignedHeaders!, "sigTst and valData survive the strip-then-valData upgrade; the whole refs family is gone.");

        for(int i = 0; i < bltResult.Verified.Value.Value.UnsignedHeaders!.Count; ++i)
        {
            CBAdESUnsignedHeaderElement element = bltResult.Verified.Value.Value.UnsignedHeaders[i];
            Assert.IsFalse(element is CBAdESUnsignedHeaderElementReferences, "refs must be gone at B-LT (CB-6.3-23).");
            Assert.IsFalse(element is CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp, "sigRTst must be gone at B-LT (CB-6.3-24).");
            Assert.IsFalse(element is CBAdESUnsignedHeaderElementReferencesTimestamp, "rfsTst must be gone at B-LT (CB-6.3-25).");
        }
    }


    /// <summary>
    /// Flow 8, negative leg: an independent copy of the B-T refs-family baseline gets ONE byte of its
    /// <c>refs</c> certificate-reference digest flipped directly on the wire bytes (independent CBOR surgery --
    /// a byte-level mutation of an already-encoded <c>bstr</c> content region, never a re-encode through any
    /// writer this library ships); B-T validation must collect BOTH the <c>sigRTst</c> and <c>rfsTst</c>
    /// imprint mismatches, since both time-stamps cover the tampered <c>refs</c> element's raw bytes.
    /// </summary>
    [TestMethod]
    public async Task ReferencesFamilyFlowFailsClosedWhenAReferenceDigestByteIsTamperedOnTheWire()
    {
        byte[] payloadBytes = "CB-AdES flow 8 negative -- refs digest byte tampered on the wire payload"u8.ToArray();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        (byte[] btWireCopy, byte[] referencedCertificateDigestBytes) = await BuildReferencesFamilyBaselineAtBTAsync(
            privateKey, payloadBytes, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tampered = FlipFirstOccurrenceByte(btWireCopy, referencedCertificateDigestBytes);

        using CBAdESValidationResult result = await ValidateAtLevelAsync(
            tampered, publicKey, AdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A tampered refs digest must invalidate both sigRTst and rfsTst, whose imprint inputs cover the refs element's raw bytes.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);

        bool sigRTstMismatch = false;
        bool rfsTstMismatch = false;
        for(int i = 0; i < failure.Violations.Count; ++i)
        {
            if(failure.Violations[i] is CBAdESTimestampTokenBindingViolation binding
                && binding.Reason == CBAdESTimestampTokenBindingFailureReason.ImprintMismatch)
            {
                sigRTstMismatch |= binding.Kind == CBAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp;
                rfsTstMismatch |= binding.Kind == CBAdESTimestampTokenBindingKind.ReferencesTimestamp;
            }
        }

        Assert.IsTrue(sigRTstMismatch, "sigRTst's message imprint must mismatch once the refs digest it covers is tampered.");
        Assert.IsTrue(rfsTstMismatch, "rfsTst's message imprint must mismatch once the refs digest it covers is tampered.");
    }


    /// <summary>
    /// The repeated-<c>sigTst</c>-after-<c>sigRTst</c> scenario, positive leg: <c>refs</c> -&gt;
    /// <c>sigTst</c>#1 -&gt; <c>sigRTst</c> -&gt; <c>sigTst</c>#2 (Table 14 note 7's legal repeated-<c>sigTst</c>
    /// pattern, appended AFTER <c>sigRTst</c>) validates GREEN at level B-T: the SECOND <c>sigTst</c> instance
    /// must never fold into <c>sigRTst</c>'s own expected message-imprint input at validation time, since the
    /// Time-Stamping Authority that minted <c>sigRTst</c> never attested it.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-A.1.2.1.2-03, CB-A.1.2.1.2-04.
    /// </remarks>
    [TestMethod]
    public async Task ReferencesFamilyFlowWithSecondSignatureTimestampAfterSigRTstValidatesAtLevelBT()
    {
        byte[] payloadBytes = "CB-AdES flow 11 -- refs, sigTst, sigRTst, then a second sigTst payload"u8.ToArray();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        (byte[] btWireCopy, byte[] _) = await BuildD15RepeatedSignatureTimestampBaselineAtBTAsync(
            privateKey, payloadBytes, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await ValidateAtLevelAsync(
            btWireCopy, publicKey, AdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid,
            "A sigTst instance appended AFTER sigRTst (Table 14 note 7) must not break sigRTst's own " +
            "message-imprint verification -- the validation-time prefix bound must exclude it.");
        Assert.HasCount(4, result.Verified!.Value.Value.UnsignedHeaders!, "refs, sigTst#1, sigRTst, and sigTst#2 are all present.");

        int signatureTimestampCount = 0;
        for(int i = 0; i < result.Verified.Value.Value.UnsignedHeaders!.Count; ++i)
        {
            if(result.Verified.Value.Value.UnsignedHeaders[i] is CBAdESUnsignedHeaderElementSignatureTimestamp)
            {
                ++signatureTimestampCount;
            }
        }

        Assert.AreEqual(2, signatureTimestampCount, "Both sigTst instances (Table 14 note 7) must decode back out of the wire bytes.");
    }


    /// <summary>
    /// The scenario above, negative leg: the SAME <c>refs</c> -&gt; <c>sigTst</c>#1 -&gt; <c>sigRTst</c> -&gt;
    /// <c>sigTst</c>#2 baseline, with one byte of the <c>refs</c> certificate-reference digest flipped
    /// directly on the wire bytes -- validation at B-T must still collect the <c>sigRTst</c> imprint mismatch
    /// (the tamper, not the trailing second <c>sigTst</c>, is what breaks it).
    /// </summary>
    [TestMethod]
    public async Task ReferencesFamilyFlowWithSecondSignatureTimestampAfterSigRTstFailsClosedWhenReferenceDigestIsTampered()
    {
        byte[] payloadBytes = "CB-AdES flow 11 negative -- refs digest tampered payload"u8.ToArray();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        (byte[] btWireCopy, byte[] referencedCertificateDigestBytes) = await BuildD15RepeatedSignatureTimestampBaselineAtBTAsync(
            privateKey, payloadBytes, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tampered = FlipFirstOccurrenceByte(btWireCopy, referencedCertificateDigestBytes);

        using CBAdESValidationResult result = await ValidateAtLevelAsync(
            tampered, publicKey, AdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A tampered refs digest must still invalidate sigRTst even with a later sigTst instance present.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);

        bool sigRTstMismatch = false;
        for(int i = 0; i < failure.Violations.Count; ++i)
        {
            if(failure.Violations[i] is CBAdESTimestampTokenBindingViolation binding
                && binding.Kind == CBAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp
                && binding.Reason == CBAdESTimestampTokenBindingFailureReason.ImprintMismatch)
            {
                sigRTstMismatch = true;
            }
        }

        Assert.IsTrue(sigRTstMismatch, "sigRTst's message imprint must mismatch once the refs digest it covers is tampered, the validation-time prefix bound notwithstanding.");
    }


    /// <summary>
    /// Builds a CB-AdES-B-T signature exercising the repeated-<c>sigTst</c> scenario: <c>refs</c>, a first <c>sigTst</c>, <c>sigRTst</c> (covering the signature value
    /// plus the <c>sigTst</c>/<c>refs</c> elements that precede IT), then a SECOND, sibling <c>sigTst</c>
    /// appended AFTER <c>sigRTst</c> (Table 14 note 7's legal multi-Time-Stamping-Authority pattern). Shared by the regression's positive and negative legs above.
    /// </summary>
    /// <param name="privateKey">The signing key. Not disposed here; the caller owns it.</param>
    /// <param name="payloadBytes">The attached payload to sign.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The B-T wire bytes (owned by the caller) and the referenced certificate's independently-computed SHA-256 digest bytes (the negative leg's tamper-search needle).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignAsync call (see that type's own ownership " +
            "remarks), which this method disposes via 'using creationResult'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    private static async ValueTask<(byte[] WireCopy, byte[] ReferencedCertificateDigestBytes)> BuildD15RepeatedSignatureTimestampBaselineAtBTAsync(
        PrivateKeyMemory privateKey,
        byte[] payloadBytes,
        CancellationToken cancellationToken)
    {
        (AdESCertificateThumbprint thumbprint, byte[] _) = await CreateSigningCertificateThumbprintAsync(cancellationToken).ConfigureAwait(false);

        byte[] signingCertificateBytes = [0x30, 0x05, 0x02, 0x01, 0x51];
        byte[] referencedCertificateBytes = [0x30, 0x05, 0x02, 0x01, 0x52];
        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(signingCertificateBytes, PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory referencedCertificate = CreatePkiCarrier(referencedCertificateBytes, PkiCertificateTags.X509Certificate);

        byte[] referencedCertificateDigestBytes;
        using(DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            referencedCertificateBytes, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            referencedCertificateDigestBytes = digest.AsReadOnlySpan().ToArray();
        }

        byte[] bbWireCopy;
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            bbWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] refsWireCopy;
        {
            var referencesContext = new CBAdESReferencesContext
            {
                WireBytes = bbWireCopy,
                SigningCertificate = signingCertificate,
                CertificatesToReference = [referencedCertificate],
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TargetLevel = AdESBaselineLevel.BB
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddReferencesAsync(
                referencesContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            refsWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using TsaScenario scenario = BuildTsaScenario();

        byte[] firstSigTstWireCopy;
        {
            var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], TestClock.CanonicalEpoch.AddMinutes(10));
            var timestampContext = new CBAdESSignatureTimestampContext
            {
                WireBytes = refsWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                EnforceSigningCertificateValidity = false,
                TargetLevel = AdESBaselineLevel.BT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                timestampContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            firstSigTstWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] sigRTstWireCopy;
        {
            var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], TestClock.CanonicalEpoch.AddMinutes(20));
            var familyContext = new CBAdESReferencesFamilyTimestampContext
            {
                WireBytes = firstSigTstWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                TargetLevel = AdESBaselineLevel.BT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync(
                familyContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            sigRTstWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        //The scenario itself: a SECOND, sibling sigTst appended AFTER sigRTst (Table 14 note 7) -- this is
        //what a full-final-array reading of Annex A.1.2.1.2 would incorrectly fold into sigRTst's own expected
        //message-imprint input at validation time.
        byte[] finalWireCopy;
        {
            var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], TestClock.CanonicalEpoch.AddMinutes(30));
            var timestampContext = new CBAdESSignatureTimestampContext
            {
                WireBytes = sigRTstWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                EnforceSigningCertificateValidity = false,
                TargetLevel = AdESBaselineLevel.BT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                timestampContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            finalWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        return (finalWireCopy, referencedCertificateDigestBytes);
    }


    /// <summary>
    /// Flow 9, positive leg: acquires an <c>adoTst</c> over the attached payload BEFORE signing (clause 5.2.6),
    /// places it into the protected headers, signs, and validates from wire bytes alone -- the token's message
    /// imprint verifies against the wire payload.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.2.6-04, CB-5.2.6-05, CB-5.2.6-07.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "adoTst and headers are deliberately not using-scoped: adoTst's ownership passes into " +
            "headers's own construction (payloadTimestamps:), and headers's ownership passes into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult' -- the identical pattern flow 5 of the sibling file uses " +
            "for its own adoTst construction.")]
    [TestMethod]
    public async Task PayloadTimestampFlowAcquiresAdoTstOverAttachedPayloadAndValidatesImprint()
    {
        byte[] payloadBytes = "CB-AdES flow 9 -- adoTst over attached payload"u8.ToArray();
        (AdESCertificateThumbprint thumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] wireCopy;
        {
            using TsaScenario scenario = BuildTsaScenario();
            var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], TestClock.CanonicalEpoch);

            var acquisitionContext = new CBAdESPayloadTimestampAcquisitionContext
            {
                Source = new CBAdESAttachedPayloadTimestampAcquisitionSource(payloadBytes),
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync
            };

            CBAdESPayloadTimestamp adoTst = await CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync(
                acquisitionContext, CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            var headers = new CBAdESProtectedHeaders(
                WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint, payloadTimestamps: adoTst);
            var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult result = await ValidateAtLevelAsync(
            wireCopy, publicKey, AdESBaselineLevel.BB, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A genuine adoTst acquired over the attached payload must validate: its message imprint binds the wire payload.");
        Assert.IsNotNull(result.Verified!.Value.Value.Headers.PayloadTimestamps);
    }


    /// <summary>
    /// Flow 9, negative leg: an <c>adoTst</c> acquired over one payload, but the signature actually attaches a
    /// DIFFERENT payload -- validation must collect the adoTst imprint-mismatch violation, never a thrown
    /// exception.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "adoTst and headers are deliberately not using-scoped -- see the positive leg's own " +
            "identical justification.")]
    [TestMethod]
    public async Task PayloadTimestampFlowFailsClosedWhenAdoTstWasAcquiredOverADifferentPayload()
    {
        byte[] acquiredOverPayloadBytes = "CB-AdES flow 9 negative -- adoTst acquired over THIS payload"u8.ToArray();
        byte[] actuallySignedPayloadBytes = "CB-AdES flow 9 negative -- but THIS different payload gets signed"u8.ToArray();
        (AdESCertificateThumbprint thumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] wireCopy;
        {
            using TsaScenario scenario = BuildTsaScenario();
            var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], TestClock.CanonicalEpoch);

            var acquisitionContext = new CBAdESPayloadTimestampAcquisitionContext
            {
                Source = new CBAdESAttachedPayloadTimestampAcquisitionSource(acquiredOverPayloadBytes),
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync
            };

            CBAdESPayloadTimestamp adoTst = await CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync(
                acquisitionContext, CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            var headers = new CBAdESProtectedHeaders(
                WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint, payloadTimestamps: adoTst);
            var payloadInput = new CBAdESAttachedPayloadInput(actuallySignedPayloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult result = await ValidateAtLevelAsync(
            wireCopy, publicKey, AdESBaselineLevel.BB, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "An adoTst acquired over a different payload than the one actually signed must not validate.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);

        bool payloadTimestampMismatch = false;
        for(int i = 0; i < failure.Violations.Count; ++i)
        {
            if(failure.Violations[i] is CBAdESTimestampTokenBindingViolation binding
                && binding.Kind == CBAdESTimestampTokenBindingKind.PayloadTimestamp
                && binding.Reason == CBAdESTimestampTokenBindingFailureReason.ImprintMismatch)
            {
                payloadTimestampMismatch = true;
            }
        }

        Assert.IsTrue(payloadTimestampMismatch, "The collected violations must include the adoTst imprint mismatch.");
    }


    /// <summary>
    /// Flow 10: acquires an <c>adoTst</c> over the <c>sigD</c>-processed, dereferenced-and-concatenated payload
    /// (clause 5.2.8.2.2's reconstruction, reused per CB-5.2.6-06's NOTE) for a detached <c>ObjectIdByURI</c>
    /// signature, signs, and validates from wire bytes alone with the validation side's OWN dereference
    /// delegate instance and context over the shared object store -- both the signature-verification payload
    /// AND the <c>adoTst</c> imprint resolve correctly, exercising the CB-5.2.8.2.3-07 <c>adoTst</c> half.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.3.3-02.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "adoTst and headers are deliberately not using-scoped -- see flow 9's identical " +
            "justification.")]
    [TestMethod]
    public async Task PayloadTimestampFlowAcquiresAdoTstOverSigDReconstructedPayloadAndValidatesImprint()
    {
        const string alphaReference = "https://example.org/objects/flow10-alpha";
        const string betaReference = "https://example.org/objects/flow10-beta";
        byte[] alphaContent = "CB-AdES flow 10 -- sigD object alpha"u8.ToArray();
        byte[] betaContent = "CB-AdES flow 10 -- sigD object beta, a little bit longer than alpha"u8.ToArray();
        var store = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [alphaReference] = alphaContent,
            [betaReference] = betaContent
        };

        (AdESCertificateThumbprint thumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] wireCopy;
        {
            using TsaScenario scenario = BuildTsaScenario();
            var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], TestClock.CanonicalEpoch);

            var creationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);
            CBAdESDetachedObjectDereferenceDelegate creationDereference = DereferenceFromObjectStore;

            var acquisitionContext = new CBAdESPayloadTimestampAcquisitionContext
            {
                Source = new CBAdESSigDReferencedPayloadTimestampAcquisitionSource([alphaReference, betaReference]),
                Dereference = creationDereference,
                DereferenceContext = creationContext,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync
            };

            CBAdESPayloadTimestamp adoTst = await CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync(
                acquisitionContext, CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            var headers = new CBAdESProtectedHeaders(
                WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint, payloadTimestamps: adoTst);
            var references = new[]
            {
                new CBAdESDetachedObjectReferenceInput(alphaReference, ContentType: null),
                new CBAdESDetachedObjectReferenceInput(betaReference, ContentType: null)
            };
            var payloadInput = new CBAdESDetachedSigDPayloadInput(CBAdESDetachedMechanisms.ObjectIdByURI, references, hashAlgorithm: null);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: creationDereference, dereferenceContext: creationContext, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CBAdESSignatureSerialization.SerializeCBAdESSign1(
                creationResult.Message, payloadIsDetached: true, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        //Firewall: the verifier builds its OWN delegate instance and OWN context, over the same store.
        var verificationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);
        CBAdESDetachedObjectDereferenceDelegate verificationDereference = DereferenceFromObjectStore;

        using CBAdESValidationResult result = await ValidateAtLevelAsync(
            wireCopy, publicKey, AdESBaselineLevel.BB, verificationDereference, verificationContext, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A genuine adoTst acquired over the sigD-reconstructed payload must validate: the CB-5.2.8.2.3-07 adoTst half.");
        Assert.IsTrue(result.Verified!.Value.Value.PayloadIsDetached, "The ObjectIdByURI flow's payload must decode as detached.");
        Assert.IsNotNull(result.Verified.Value.Value.Headers.PayloadTimestamps);
    }


    /// <summary>
    /// Flow 12, positive leg: creates a B-B signature carrying <c>refs</c>, augments
    /// to B-T with <c>sigTst</c>, strips the <c>refs</c> family and places <c>valData</c> to reach B-LT (the
    /// SAME two-step choreography flow 8 uses), then augments to B-LTA with a FIRST <c>arcTst</c> instance and a
    /// REPEATED, RENEWAL second <c>arcTst</c> instance -- both bound to the SAME non-empty externally-supplied-
    /// data value (a deliberate trap: clause 5.3.5.3 step 5 binds it into the message imprint, so a flow
    /// exercising it non-empty at least once is required) -- and validates the FINAL wire bytes at the declared
    /// level B-LTA: the whole chain (the COSE signature value, the <c>sigTst</c> imprint, the B-LT validation-
    /// data-for-time-stamps service, both <c>arcTst</c> instances' own prefix-bound message imprints, and every
    /// token's per-token signer-certificate coverage, CB-6.3-h) is re-verified from wire bytes alone with zero
    /// collected violations.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.3.3-09, CB-6.3-29.
    /// </remarks>
    [TestMethod]
    public async Task LifecycleFlowCreatesBBThroughBLTAWithARepeatedArchiveTimestampAndValidatesAtDeclaredBLTA()
    {
        byte[] payloadBytes = "CB-AdES flow 12 -- full lifecycle B-B to B-LTA with a repeated arcTst payload"u8.ToArray();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        (byte[] finalWireCopy, byte[] externallySuppliedData, byte[] _) = await BuildArchiveTimestampLifecycleBaselineAsync(
            privateKey, payloadBytes, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            finalWireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BLTA,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared, externallySuppliedData, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The full B-B-to-B-LTA chain, with a repeated arcTst and a non-empty externally-supplied-data value, must validate at the declared level B-LTA with zero collected violations.");
        Assert.IsNotNull(result.Verified!.Value.Value.UnsignedHeaders);
        Assert.HasCount(4, result.Verified.Value.Value.UnsignedHeaders!, "sigTst, valData, arcTst#1, arcTst#2 -- refs (and its family) was stripped away before B-LT.");

        int archiveTimestampCount = 0;
        for(int i = 0; i < result.Verified.Value.Value.UnsignedHeaders!.Count; ++i)
        {
            if(result.Verified.Value.Value.UnsignedHeaders[i] is CBAdESUnsignedHeaderElementArchiveTimestamp)
            {
                ++archiveTimestampCount;
            }
        }

        Assert.AreEqual(2, archiveTimestampCount, "Two SIBLING arcTst instances -- the renewal call appends a new instance, never folding into the first.");
    }


    /// <summary>
    /// Flow 12, negative leg: an independent copy of the SAME B-B-to-B-LTA baseline gets the FIRST <c>arcTst</c>
    /// instance's own token content tampered (one byte flipped, directly on the wire -- the needle is the
    /// token's own DER content, never the enclosing <c>bstr</c> wrapper's CBOR framing bytes, so the outer
    /// <c>uHeaders</c> array stays parseable; never a re-encode through any writer this library ships) -- bytes
    /// the SECOND (renewal) <c>arcTst</c> instance's own message-imprint input covers as part of its
    /// validation-time prefix (5.3.5.3's validation variant, "elements that precede..."). B-LTA validation must
    /// collect the second instance's own imprint mismatch, never a thrown exception.
    /// </summary>
    [TestMethod]
    public async Task LifecycleFlowCreatesBBThroughBLTAAndFailsClosedWhenTheFirstArchiveTimestampIsTamperedOnTheWire()
    {
        byte[] payloadBytes = "CB-AdES flow 12 negative -- first arcTst tampered on the wire payload"u8.ToArray();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        (byte[] finalWireCopy, byte[] externallySuppliedData, byte[] firstArchiveTimestampTokenBytes) =
            await BuildArchiveTimestampLifecycleBaselineAsync(privateKey, payloadBytes, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tampered = FlipFirstOccurrenceByte(finalWireCopy, firstArchiveTimestampTokenBytes);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            tampered,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BLTA,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared, externallySuppliedData, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Tampering the first arcTst instance's own token content must invalidate the second (renewal) instance's own prefix-bound imprint.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);

        //Asserts the ORDINAL it claims -- sigTst=0, valData=1, arcTst#1=2, arcTst#2=3
        //(the same wire layout BuildArchiveTimestampLifecycleBaselineAsync's own comment states) -- proving the
        //mismatch is attributed to the SECOND (renewal) instance specifically, not merely "some ArchiveTimestamp
        //violation somewhere" (today's Reason-only filter could not distinguish instance #1 from #2 at all).
        bool secondArchiveTimestampMismatch = false;
        for(int i = 0; i < failure.Violations.Count; ++i)
        {
            if(failure.Violations[i] is CBAdESTimestampTokenBindingViolation binding
                && binding.Kind == CBAdESTimestampTokenBindingKind.ArchiveTimestamp
                && binding.Reason == CBAdESTimestampTokenBindingFailureReason.ImprintMismatch)
            {
                Assert.AreEqual(3, binding.InstanceOrdinal, "The mismatch must be attributed to arcTst#2's own uHeaders position (index 3), not arcTst#1's.");
                secondArchiveTimestampMismatch = true;
            }
        }

        Assert.IsTrue(secondArchiveTimestampMismatch, "The second (renewal) arcTst instance's own message imprint must mismatch once the first instance's raw bytes -- which its own prefix covers -- are tampered.");
    }


    /// <summary>
    /// CB-5.3.5.1-02/CB-5.3.5.1-03: the countersignature lifecycle flow --
    /// creates a COSE_Sign1 B-B signature, countersigns it (abbreviated, label 12), raises it through
    /// <c>refs</c>, <c>sigTst</c> (B-T), the B-LT strip/<c>valData</c> upgrade, a FIRST <c>arcTst</c> minted
    /// with the CB-5.3.5.1-02 material-completeness gate satisfied (a resolver decoding and confirming the
    /// countersignature's own completeness before the mint is allowed to proceed), and a SECOND (renewal)
    /// <c>arcTst</c> with the SAME gate satisfied again -- then asserts the counter-signature element's own raw
    /// wire bytes are BYTE-IDENTICAL immediately after the first <c>arcTst</c> and in the FINAL wire bytes,
    /// proving the renewal choreography never touches it: the library exposes no verb that could (append-only
    /// <c>uHeaders</c> carriage), so this is a proof of the ABSENCE of any code path that reaches those
    /// bytes, not merely an assertion that one particular call happened not to. The final wire bytes then
    /// undergo a FULL FIREWALLED validation (wire bytes and the two independently-known public keys alone,
    /// never a creation-side object) at the declared level B-LTA with the counter-signature element
    /// CRYPTOGRAPHICALLY VERIFIED against its own countersigner's public key, closing the gate this class's
    /// sibling byte-preservation proof left open.
    /// </summary>
    [TestMethod]
    public async Task LifecycleFlowPreservesACounterSignatureElementByteExactThroughAnArchiveTimestampRenewalAndValidatesItCryptographically()
    {
        ReadOnlySpan<byte> payloadContent = "CB-AdES counter-signature preservation through an arcTst renewal payload"u8;
        using IMemoryOwner<byte> payloadOwner = BaseMemoryPool.Shared.Rent(payloadContent.Length);
        payloadContent.CopyTo(payloadOwner.Memory.Span);
        ReadOnlyMemory<byte> payloadBytes = payloadOwner.Memory;

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var counterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory counterSignerPublicKey = counterSignerKeyMaterial.PublicKey;
        using PrivateKeyMemory counterSignerPrivateKey = counterSignerKeyMaterial.PrivateKey;

        (byte[] finalWireCopy, byte[] counterSignatureBytesAfterFirstArchiveTimestamp) =
            await BuildArchiveTimestampLifecycleWithCounterSignatureBaselineAsync(
                privateKey, counterSignerPrivateKey, payloadBytes, TestContext.CancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> counterSignatureBytesInFinalWireCopyOwner;
        {
            using CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(finalWireCopy, BaseMemoryPool.Shared);
            Assert.IsTrue(parsed.IsSuccess);
            Assert.HasCount(5, parsed.UnsignedHeaders!, "counter-signature, sigTst, valData, arcTst#1, arcTst#2.");

            var element = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementAbbreviatedCounterSignature>(parsed.UnsignedHeaders![0]);
            counterSignatureBytesInFinalWireCopyOwner = BaseMemoryPool.Shared.Rent(element.Value.Length);
            element.Value.Span.CopyTo(counterSignatureBytesInFinalWireCopyOwner.Memory.Span);
        }

        using(counterSignatureBytesInFinalWireCopyOwner)
        {
            Assert.IsTrue(
                counterSignatureBytesAfterFirstArchiveTimestamp.AsSpan().SequenceEqual(counterSignatureBytesInFinalWireCopyOwner.Memory.Span),
                "CB-5.3.5.1-03: the counter-signature element's own bytes must be byte-identical before and " +
                "after the SECOND (renewal) arcTst -- append-only uHeaders carriage exposes no verb that could " +
                "change them.");
        }

        using CBAdESValidationResult validation = await CBAdESSignatureValidation.ValidateAsync(
            finalWireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BLTA,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            archiveTimestampExternallySuppliedData: default,
            parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
            buildCountersignStructure: CoseSerialization.BuildCountersignStructure,
            resolveCounterSignaturePublicKey: _ => counterSignerPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsValid, "The final wire bytes, carrying the preserved counter-signature element through two arcTst instances, must validate at the declared level B-LTA with zero collected violations, its own countersignature cryptographically verified against the countersigner's public key.");
    }


    /// <summary>
    /// Builds the identical B-B-to-B-LTA-with-a-repeated-arcTst chain <see cref="BuildArchiveTimestampLifecycleBaselineAsync"/>
    /// builds, with one addition: a genuine, abbreviated (label 12) counter-signature element -- countersigning
    /// the B-B signature's own body-layer protected header/payload/signature -- is spliced in as the FIRST
    /// <c>uHeaders</c> element immediately after B-B creation, so it rides along, byte-exact, through every
    /// later augmentation's own append-only splice (each verb retains every element already present).
    /// </summary>
    /// <param name="privateKey">The primary signer's private key.</param>
    /// <param name="counterSignerPrivateKey">The countersigner's private key.</param>
    /// <param name="payloadBytes">The payload to sign.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The final (post-renewal) wire bytes, and the counter-signature element's own raw value bytes captured
    /// immediately after the FIRST <c>arcTst</c> instance was minted (before the renewal).
    /// </returns>
    private static async ValueTask<(byte[] FinalWireCopy, byte[] CounterSignatureBytesAfterFirstArchiveTimestamp)>
        BuildArchiveTimestampLifecycleWithCounterSignatureBaselineAsync(
        PrivateKeyMemory privateKey,
        PrivateKeyMemory counterSignerPrivateKey,
        ReadOnlyMemory<byte> payloadBytes,
        CancellationToken cancellationToken)
    {
        (AdESCertificateThumbprint thumbprint, byte[] _) = await CreateSigningCertificateThumbprintAsync(cancellationToken).ConfigureAwait(false);

        byte[] signingCertificateBytes = [0x30, 0x05, 0x02, 0x01, 0x04];
        byte[] referencedCertificateBytes = [0x30, 0x05, 0x02, 0x01, 0x05];
        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(signingCertificateBytes, PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory referencedCertificate = CreatePkiCarrier(referencedCertificateBytes, PkiCertificateTags.X509Certificate);

        byte[] bbWireCopyWithCounterSignature;
        {
            using var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

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
            bbWireCopyWithCounterSignature = wireBytes.AsReadOnlySpan().ToArray();
        }

        //The wire-bytes snapshot crossing into the NEXT
        //augmentation stage stays the pooled EncodedCoseSign1 carrier the augmentation verb itself
        //returned -- never a naked heap byte[] -- disposed once its own last downstream use is past.
        EncodedCoseSign1 refsWireCopy;
        {
            var referencesContext = new CBAdESReferencesContext
            {
                WireBytes = bbWireCopyWithCounterSignature,
                SigningCertificate = signingCertificate,
                CertificatesToReference = [referencedCertificate],
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TargetLevel = AdESBaselineLevel.BB
            };

            refsWireCopy = await CBAdESSignatureAugmentation.AddReferencesAsync(
                referencesContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        }

        using TsaScenario sigTstScenario = BuildTsaScenario();
        var sigTstResponder = new MintingTimestampResponder(sigTstScenario.Authority, [sigTstScenario.Authority], TestClock.CanonicalEpoch.AddHours(1));

        EncodedCoseSign1 btWireCopy;
        {
            var timestampContext = new CBAdESSignatureTimestampContext
            {
                WireBytes = refsWireCopy.AsReadOnlyMemory(),
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = sigTstResponder.FetchAsync,
                EnforceSigningCertificateValidity = false,
                TargetLevel = AdESBaselineLevel.BT
            };

            btWireCopy = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                timestampContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            refsWireCopy.Dispose();
        }

        EncodedCoseSign1 strippedWireCopy;
        {
            var stripContext = new CBAdESStripReferencesContext { WireBytes = btWireCopy.AsReadOnlyMemory(), TargetLevel = AdESBaselineLevel.BT };
            strippedWireCopy = CBAdESSignatureAugmentation.StripReferencesForLongTerm(
                stripContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared);
            btWireCopy.Dispose();
        }

        byte[] bltWireCopy;
        {
            using PkiCertificateMemory validationCertificate = CreatePkiCarrier([0x30, 0x05, 0x02, 0x01, 0x06], PkiCertificateTags.X509Certificate);
            var validationDataContext = new CBAdESValidationDataContext
            {
                WireBytes = strippedWireCopy.AsReadOnlyMemory(),
                Material = new CBAdESValidationMaterial { Certificates = [validationCertificate] },
                TargetLevel = AdESBaselineLevel.BLT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddValidationDataAsync(
                validationDataContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            bltWireCopy = wireBytes.AsReadOnlySpan().ToArray();
            strippedWireCopy.Dispose();
        }

        using TsaScenario arcTstScenario = BuildTsaScenario();
        using PkiCertificateMemory arcTstSigningCertificate = CreatePkiCarrier(arcTstScenario.Root.Certificate.RawData, PkiCertificateTags.X509Certificate);

        EncodedCoseSign1 firstArcTstWireCopy;
        {
            var firstResponder = new MintingTimestampResponder(arcTstScenario.Authority, [arcTstScenario.Authority], TestClock.CanonicalEpoch.AddHours(2));
            firstArcTstWireCopy = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CBAdESArchiveTimestampContext
                {
                    WireBytes = bltWireCopy,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = TsaUri, FetchResponse = firstResponder.FetchAsync }],
                    SigningCertificate = arcTstSigningCertificate,
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
        }

        byte[] counterSignatureBytesAfterFirstArchiveTimestamp;
        {
            using CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(firstArcTstWireCopy.AsReadOnlyMemory(), BaseMemoryPool.Shared);
            Assert.IsTrue(parsed.IsSuccess);
            var element = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementAbbreviatedCounterSignature>(parsed.UnsignedHeaders![0]);
            counterSignatureBytesAfterFirstArchiveTimestamp = element.Value.ToArray();
        }

        byte[] finalWireCopy;
        {
            var secondResponder = new MintingTimestampResponder(arcTstScenario.Authority, [arcTstScenario.Authority], TestClock.CanonicalEpoch.AddHours(3));
            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CBAdESArchiveTimestampContext
                {
                    WireBytes = firstArcTstWireCopy.AsReadOnlyMemory(),
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = TsaUri, FetchResponse = secondResponder.FetchAsync }],
                    SigningCertificate = arcTstSigningCertificate,
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
            finalWireCopy = wireBytes.AsReadOnlySpan().ToArray();
            firstArcTstWireCopy.Dispose();
        }

        return (finalWireCopy, counterSignatureBytesAfterFirstArchiveTimestamp);
    }


    /// <summary>
    /// Validates <paramref name="wireCopy"/> at <paramref name="level"/> through the level-aware, registry-
    /// resolved <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload, wiring the four shipped
    /// <see cref="CBAdESLevelMessageImprintAdapters"/> message-imprint-input seams every flow below needs --
    /// shared so each flow's call site states only what varies (the wire bytes, the key, the level, and the
    /// <c>sigD</c> dereference pair when detached).
    /// </summary>
    /// <param name="wireCopy">The candidate CB-AdES wire bytes.</param>
    /// <param name="publicKey">The verifying public key.</param>
    /// <param name="level">The baseline level to check against.</param>
    /// <param name="dereference">The <c>sigD</c> dereference seam, or <see langword="null"/> for an attached/no-<c>sigD</c> flow.</param>
    /// <param name="dereferenceContext">The per-call context for <paramref name="dereference"/>.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The validation result.</returns>
    private static ValueTask<CBAdESValidationResult> ValidateAtLevelAsync(
        byte[] wireCopy,
        PublicKeyMemory publicKey,
        AdESBaselineLevel level,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        CancellationToken cancellationToken) =>
        CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference,
            dereferenceContext,
            externalDetachedPayload: null,
            unknownMechanismHandler: null,
            level,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken);


    /// <summary>
    /// Builds a CB-AdES-B-T signature carrying the whole Annex A <c>refs</c> family (<c>refs</c> referencing
    /// one placeholder certificate, <c>sigTst</c>, <c>sigRTst</c>, and <c>rfsTst</c>) over
    /// <paramref name="privateKey"/>, through a fresh in-process Time-Stamping Authority scenario this call
    /// creates and disposes internally -- signer-side infrastructure flow 8's validation side never touches.
    /// Shared by flow 8's positive and negative legs so each builds an identical baseline before diverging.
    /// </summary>
    /// <param name="privateKey">The signing key. Not disposed here; the caller owns it.</param>
    /// <param name="payloadBytes">The attached payload to sign.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The B-T wire bytes (owned by the caller) and the referenced certificate's independently-computed SHA-256 digest bytes (the negative leg's tamper-search needle).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignAsync call (see that type's own ownership " +
            "remarks), which this method disposes via 'using creationResult'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    private static async ValueTask<(byte[] WireCopy, byte[] ReferencedCertificateDigestBytes)> BuildReferencesFamilyBaselineAtBTAsync(
        PrivateKeyMemory privateKey,
        byte[] payloadBytes,
        CancellationToken cancellationToken)
    {
        (AdESCertificateThumbprint thumbprint, byte[] _) = await CreateSigningCertificateThumbprintAsync(cancellationToken).ConfigureAwait(false);

        byte[] signingCertificateBytes = [0x30, 0x05, 0x02, 0x01, 0x01];
        byte[] referencedCertificateBytes = [0x30, 0x05, 0x02, 0x01, 0x02];
        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(signingCertificateBytes, PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory referencedCertificate = CreatePkiCarrier(referencedCertificateBytes, PkiCertificateTags.X509Certificate);

        byte[] referencedCertificateDigestBytes;
        using(DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            referencedCertificateBytes, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            referencedCertificateDigestBytes = digest.AsReadOnlySpan().ToArray();
        }

        byte[] bbWireCopy;
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            bbWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] refsWireCopy;
        {
            var referencesContext = new CBAdESReferencesContext
            {
                WireBytes = bbWireCopy,
                SigningCertificate = signingCertificate,
                CertificatesToReference = [referencedCertificate],
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TargetLevel = AdESBaselineLevel.BB
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddReferencesAsync(
                referencesContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            refsWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using TsaScenario scenario = BuildTsaScenario();
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], TestClock.CanonicalEpoch);

        byte[] sigTstWireCopy;
        {
            var timestampContext = new CBAdESSignatureTimestampContext
            {
                WireBytes = refsWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                EnforceSigningCertificateValidity = false,
                TargetLevel = AdESBaselineLevel.BT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                timestampContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            sigTstWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] sigRTstWireCopy;
        {
            var familyContext = new CBAdESReferencesFamilyTimestampContext
            {
                WireBytes = sigTstWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                TargetLevel = AdESBaselineLevel.BT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync(
                familyContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            sigRTstWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] finalWireCopy;
        {
            var familyContext = new CBAdESReferencesFamilyTimestampContext
            {
                WireBytes = sigRTstWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                TargetLevel = AdESBaselineLevel.BT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddReferencesTimestampAsync(
                familyContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            finalWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        return (finalWireCopy, referencedCertificateDigestBytes);
    }


    /// <summary>
    /// Builds flow 12's shared B-B-to-B-LTA baseline: a B-B signature carrying <c>refs</c>
    /// (referencing one placeholder certificate), augmented to B-T with <c>sigTst</c>, then stripped of the
    /// <c>refs</c> family and augmented with <c>valData</c> to reach B-LT -- the SAME two-step choreography
    /// <see cref="ReferencesFamilyFlowCreatesRefsSigRTstAndRfsTstThenUpgradesToBLTStrippingTheFamily"/> uses --
    /// then augmented to B-LTA with a FIRST <c>arcTst</c> instance and a REPEATED, RENEWAL second <c>arcTst</c>
    /// instance, both bound to the SAME non-empty externally-supplied-data value (clause 5.3.5.3 step 5;
    /// <see cref="CBAdESSignatureValidation.ValidateAsync"/> applies ONE externally-supplied-data value across
    /// every <c>arcTst</c> instance one call checks, so both generation calls below must agree). Shared by flow
    /// 12's positive and negative legs so each builds an identical baseline before diverging.
    /// </summary>
    /// <param name="privateKey">The signing key. Not disposed here; the caller owns it.</param>
    /// <param name="payloadBytes">The attached payload to sign.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The final B-LTA wire bytes (owned by the caller), the externally-supplied-data bytes both <c>arcTst</c>
    /// calls bound (the value the final validation call must also supply), and the FIRST <c>arcTst</c>
    /// instance's own first token's DER content bytes (the negative leg's tamper-search needle -- deliberately
    /// content only, never the enclosing <c>bstr</c> wrapper's own CBOR framing, so a flipped byte changes what
    /// the second instance's imprint covers without corrupting the outer <c>uHeaders</c> array's own parse).
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful SignAsync call (see that type's own ownership " +
            "remarks), which this method disposes via 'using creationResult'. Roslyn's CA2000 analysis of 'new " +
            "CBAdESProtectedHeaders(...)' cannot see across that async call boundary into the transfer.")]
    private static async ValueTask<(byte[] FinalWireCopy, byte[] ExternallySuppliedData, byte[] FirstArchiveTimestampTokenBytes)> BuildArchiveTimestampLifecycleBaselineAsync(
        PrivateKeyMemory privateKey,
        byte[] payloadBytes,
        CancellationToken cancellationToken)
    {
        (AdESCertificateThumbprint thumbprint, byte[] _) = await CreateSigningCertificateThumbprintAsync(cancellationToken).ConfigureAwait(false);

        byte[] signingCertificateBytes = [0x30, 0x05, 0x02, 0x01, 0x04];
        byte[] referencedCertificateBytes = [0x30, 0x05, 0x02, 0x01, 0x05];
        using PkiCertificateMemory signingCertificate = CreatePkiCarrier(signingCertificateBytes, PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory referencedCertificate = CreatePkiCarrier(referencedCertificateBytes, PkiCertificateTags.X509Certificate);

        byte[] bbWireCopy;
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            bbWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] refsWireCopy;
        {
            var referencesContext = new CBAdESReferencesContext
            {
                WireBytes = bbWireCopy,
                SigningCertificate = signingCertificate,
                CertificatesToReference = [referencedCertificate],
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TargetLevel = AdESBaselineLevel.BB
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddReferencesAsync(
                referencesContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            refsWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using TsaScenario sigTstScenario = BuildTsaScenario();
        var sigTstResponder = new MintingTimestampResponder(sigTstScenario.Authority, [sigTstScenario.Authority], TestClock.CanonicalEpoch.AddHours(1));

        byte[] btWireCopy;
        {
            var timestampContext = new CBAdESSignatureTimestampContext
            {
                WireBytes = refsWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = sigTstResponder.FetchAsync,
                EnforceSigningCertificateValidity = false,
                TargetLevel = AdESBaselineLevel.BT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                timestampContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            btWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] strippedWireCopy;
        {
            var stripContext = new CBAdESStripReferencesContext { WireBytes = btWireCopy, TargetLevel = AdESBaselineLevel.BT };
            using EncodedCoseSign1 wireBytes = CBAdESSignatureAugmentation.StripReferencesForLongTerm(
                stripContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared);
            strippedWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] bltWireCopy;
        {
            using PkiCertificateMemory validationCertificate = CreatePkiCarrier([0x30, 0x05, 0x02, 0x01, 0x06], PkiCertificateTags.X509Certificate);
            var validationDataContext = new CBAdESValidationDataContext
            {
                WireBytes = strippedWireCopy,
                Material = new CBAdESValidationMaterial { Certificates = [validationCertificate] },
                TargetLevel = AdESBaselineLevel.BLT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddValidationDataAsync(
                validationDataContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            bltWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] externallySuppliedData = "CB-AdES flow 12 -- arcTst externally-supplied data"u8.ToArray();

        using TsaScenario arcTstScenario = BuildTsaScenario();
        using PkiCertificateMemory arcTstSigningCertificate = CreatePkiCarrier(arcTstScenario.Root.Certificate.RawData, PkiCertificateTags.X509Certificate);

        byte[] firstArcTstWireCopy;
        {
            var firstResponder = new MintingTimestampResponder(arcTstScenario.Authority, [arcTstScenario.Authority], TestClock.CanonicalEpoch.AddHours(2));
            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CBAdESArchiveTimestampContext
                {
                    WireBytes = bltWireCopy,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    ExternallySuppliedData = externallySuppliedData,
                    TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = TsaUri, FetchResponse = firstResponder.FetchAsync }],
                    SigningCertificate = arcTstSigningCertificate,
                    ChainCompletenessAttested = true,
                    TargetLevel = AdESBaselineLevel.BLTA
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
            firstArcTstWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] firstArchiveTimestampTokenBytes;
        {
            CBAdESSign1ParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign1(firstArcTstWireCopy, BaseMemoryPool.Shared);
            using(parsed)
            {
                Assert.IsTrue(parsed.IsSuccess);
                //sigTst, valData, arcTst#1 -- the first arcTst instance's own position is index 2. The tamper
                //needle is the token's own DER content (never the bstr wrapper's own CBOR framing bytes, which
                //a byte flip there would corrupt into a CBOR-level CBAdESMalformedEncodingFailure rather than
                //the intended imprint-mismatch RULE VIOLATION on the second, renewal instance).
                var firstArcTstElement = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementArchiveTimestamp>(parsed.UnsignedHeaders![2]);
                firstArchiveTimestampTokenBytes = firstArcTstElement.ArchiveTimestamp.TimestampContainer.TstTokens[0].Val.ToArray();
            }
        }

        byte[] finalWireCopy;
        {
            var secondResponder = new MintingTimestampResponder(arcTstScenario.Authority, [arcTstScenario.Authority], TestClock.CanonicalEpoch.AddHours(3));
            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CBAdESArchiveTimestampContext
                {
                    WireBytes = firstArcTstWireCopy,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    ExternallySuppliedData = externallySuppliedData,
                    TsaLegs = [new CBAdESArchiveTimestampTsaLeg { TsaUri = TsaUri, FetchResponse = secondResponder.FetchAsync }],
                    SigningCertificate = arcTstSigningCertificate,
                    ChainCompletenessAttested = true,
                    TargetLevel = AdESBaselineLevel.BLTA
                },
                CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampGenerationMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
            finalWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        return (finalWireCopy, externallySuppliedData, firstArchiveTimestampTokenBytes);
    }


    /// <summary>
    /// Builds a signing certificate's <c>x5t</c> thumbprint fixture (SHA-256, via the registered digest
    /// delegate seam -- never a hand-rolled hash) together with an independently-kept copy of the expected
    /// digest bytes, mirroring <see cref="CBAdESSignatureFlowTests"/>'s own identically-named private helper.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The thumbprint (ownership transfers to whatever aggregate it is supplied to) and the independent digest-bytes copy.</returns>
    private static async ValueTask<(AdESCertificateThumbprint Thumbprint, byte[] ExpectedDigestBytes)> CreateSigningCertificateThumbprintAsync(
        CancellationToken cancellationToken)
    {
        byte[] certificateBytes = "CB-AdES lifecycle flow test -- placeholder signing certificate bytes"u8.ToArray();
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(certificateBytes), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        byte[] expectedDigestBytes = digest.AsReadOnlySpan().ToArray();
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);

        return (thumbprint, expectedDigestBytes);
    }


    /// <summary>
    /// Rents pool memory of <paramref name="content"/>'s length, copies it in, and wraps it as a
    /// <see cref="PkiCertificateMemory"/> tagged <paramref name="tag"/> -- a placeholder PKI-object-shaped
    /// carrier for the flows that only need something of the right kind (the augmentation verbs below check
    /// only the tag, never ASN.1-parse these bytes; the one check that would, requirement (d), is disabled
    /// explicitly on every context this file builds -- see the class remarks).
    /// </summary>
    /// <param name="content">The bytes to copy into the rented carrier.</param>
    /// <param name="tag">The tag to stamp the carrier with.</param>
    /// <returns>The rented carrier. The caller disposes it.</returns>
    private static PkiCertificateMemory CreatePkiCarrier(ReadOnlySpan<byte> content, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(content.Length);
        content.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// Builds a Root CA and a Time-Stamping Authority certificate anchored to <see cref="TestClock.CanonicalEpoch"/>,
    /// mirroring <see cref="Verifiable.Tests.Cryptography.TimestampAcquisitionTests"/>'s own identically-shaped
    /// private helper (duplicated here per this repo's convention of copying a sibling test file's exact
    /// fixture shape rather than sharing a cross-file test utility).
    /// </summary>
    /// <returns>The scenario, which the caller disposes.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both nodes transfers to the returned TsaScenario, which the caller disposes; the catch disposes the root on a partial failure.")]
    private static TsaScenario BuildTsaScenario()
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


    /// <summary>
    /// The test-side detached-object dereference delegate flow 10 wires -- explicit per-call state only (no
    /// closure capture): resolves <paramref name="context"/>'s <see cref="CBAdESDetachedObjectDereferenceContext.State"/>
    /// as an <see cref="IReadOnlyDictionary{TKey, TValue}"/> object store (the published-location analogue)
    /// and looks up <paramref name="uriReference"/> in it. Mirrors <see cref="CBAdESSignatureFlowTests"/>'s own
    /// identically-named private helper exactly.
    /// </summary>
    /// <param name="uriReference">The URI-reference to dereference (one <c>pars</c> element).</param>
    /// <param name="context">The per-call caller state; its <see cref="CBAdESDetachedObjectDereferenceContext.State"/> is the object store.</param>
    /// <param name="pool">Memory pool the fetched content is rented from.</param>
    /// <param name="cancellationToken">Cancellation token (unused; the in-memory store never awaits).</param>
    /// <returns>The dereferenced content, or a failure signal when the store carries no entry for <paramref name="uriReference"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned PooledMemory transfers to the CBAdESDetachedObjectDereferenceSuccess result, which the caller (CBAdESSignatureCreation/CBAdESSignatureAugmentation/CBAdESSignatureValidation) disposes.")]
    private static ValueTask<CBAdESDetachedObjectDereferenceResult> DereferenceFromObjectStore(
        string uriReference,
        CBAdESDetachedObjectDereferenceContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        var store = (IReadOnlyDictionary<string, byte[]>)context.State!;
        if(!store.TryGetValue(uriReference, out byte[]? content))
        {
            return ValueTask.FromResult<CBAdESDetachedObjectDereferenceResult>(
                new CBAdESDetachedObjectDereferenceFailure($"No object is registered in this test store for '{uriReference}'."));
        }

        PooledMemory pooled = PooledMemory.FromBytes(content, pool, DetachedObjectContentTag);

        return ValueTask.FromResult<CBAdESDetachedObjectDereferenceResult>(new CBAdESDetachedObjectDereferenceSuccess(pooled));
    }


    /// <summary>
    /// Returns a copy of <paramref name="haystack"/> with the first byte of the first verbatim occurrence of
    /// <paramref name="needle"/> flipped -- flow 8's negative leg uses this to corrupt exactly the referenced
    /// certificate's digest region of already-augmented wire bytes, without disturbing any other field (flow
    /// 12's negative leg reuses it identically to tamper an <c>arcTst</c> token's own DER content).
    /// Mirrors <see cref="CBAdESSignatureFlowTests"/>'s own identically-named private helper exactly.
    /// </summary>
    /// <param name="haystack">The wire bytes to copy and mutate.</param>
    /// <param name="needle">The bytes whose first occurrence's first byte is flipped.</param>
    /// <returns>An independent, mutated copy of <paramref name="haystack"/>.</returns>
    private static byte[] FlipFirstOccurrenceByte(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        int offset = haystack.IndexOf(needle);
        Assert.IsGreaterThanOrEqualTo(0, offset, "The needle bytes must appear verbatim within the haystack for this mutation to be meaningful.");

        byte[] mutated = haystack.ToArray();
        mutated[offset] ^= 0xFF;

        return mutated;
    }


    /// <summary>The minted Root CA and Time-Stamping Authority nodes for one Time-Stamping Authority scenario, disposed together.</summary>
    /// <param name="Root">The self-signed Root CA node.</param>
    /// <param name="Authority">The Time-Stamping Authority node issued from <paramref name="Root"/>.</param>
    private sealed record TsaScenario(X509ChainTestRingNode Root, X509ChainTestRingNode Authority): IDisposable
    {
        /// <summary>Disposes <see cref="Authority"/> then <see cref="Root"/>.</summary>
        public void Dispose()
        {
            Authority.Dispose();
            Root.Dispose();
        }
    }
}
