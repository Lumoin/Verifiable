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
/// <strong>Time-Stamping Authority, recorded loudly (a deviation from the task's literal example, with
/// grounds).</strong> Every <c>sigTst</c>/<c>sigRTst</c>/<c>rfsTst</c>/<c>adoTst</c> acquisition below goes
/// through <see cref="MintingTimestampResponder"/> -- an in-process transport fake (no sockets; the
/// wire-socket leg over a real Kestrel TSA host is a separate wave agent's own scope) that GENUINELY decodes
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
/// mint; that positive/negative behavioral coverage belongs to the wave's dedicated rule unit tests.
/// </para>
/// <para>
/// <strong>A discovered ordering catch-22, flagged for the review wave.</strong>
/// <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/>'s own internal
/// <see cref="CBAdESLevelRules.EnsureConformant"/> call can NEVER succeed at <see cref="CBAdESBaselineLevel.BLT"/>
/// unless a <c>valData</c> element is ALREADY present: Table 14 additional requirement (h)'s disjunction
/// (<c>valData</c> present OR embedded-in-token material) has an embedded-in-token arm only the ASYNC
/// validation orchestrator can ever assert true (it alone inspects a token's CMS content); the SYNCHRONOUS
/// strip verb never does, so it always supplies <see cref="CBAdESLevelRuleContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/>
/// as its default <see langword="false"/>. Flow 8 below therefore targets
/// <see cref="CBAdESStripReferencesContext.TargetLevel"/> at <see cref="CBAdESBaselineLevel.BT"/> (the strip
/// verb's own doc comment already calls this a level that only PREPARES the B-LT transition, never claims to
/// reach it) and reserves <see cref="CBAdESBaselineLevel.BLT"/> for the immediately-following
/// <see cref="CBAdESSignatureAugmentation.AddValidationData"/> call that actually places <c>valData</c> -- the
/// ordering every B-LT upgrade below uses.
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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult', mirroring CBAdESSignatureFlowTests's own convention.")]
    [TestMethod]
    public async Task LifecycleFlowCreatesBBAugmentsToBTThenBLTAndValidatesAtEachStage()
    {
        byte[] payloadBytes = "CB-AdES flow 7 -- full lifecycle B-B to B-T to B-LT payload"u8.ToArray();
        (CBAdESCertificateThumbprint thumbprint, byte[] _) =
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
                TargetLevel = CBAdESBaselineLevel.BT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddSignatureTimestampAsync(
                timestampContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            btWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        //Firewall: the intermediate B-T bytes validate from wire bytes alone before the chain continues to B-LT.
        using(CBAdESValidationResult btResult = await ValidateAtLevelAsync(
            btWireCopy, publicKey, CBAdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(btResult.IsValid, "The intermediate B-T signature must validate at level B-T: its sigTst imprint binds the signature value.");
            Assert.HasCount(1, btResult.UnsignedHeaders!, "Only the sigTst element has been added at this point.");
            Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementSignatureTimestamp>(btResult.UnsignedHeaders![0]);
        }

        byte[] bltWireCopy;
        {
            using PkiCertificateMemory validationCertificate = CreatePkiCarrier([0x30, 0x05, 0x02, 0x01, 0x2A], PkiCertificateTags.X509Certificate);
            var validationDataContext = new CBAdESValidationDataContext
            {
                WireBytes = btWireCopy,
                Material = new CBAdESValidationMaterial { Certificates = [validationCertificate] },
                TargetLevel = CBAdESBaselineLevel.BLT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddValidationData(
                validationDataContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            bltWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        //Firewall: only bltWireCopy crosses from here on for the final validation.
        using CBAdESValidationResult bltResult = await ValidateAtLevelAsync(
            bltWireCopy, publicKey, CBAdESBaselineLevel.BLT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(bltResult.IsValid, "A genuine B-LT signature (sigTst + valData) must validate at level B-LT.");
        Assert.HasCount(2, bltResult.UnsignedHeaders!, "sigTst and valData are both present; no other element was added.");

        bool hasValidationData = false;
        for(int i = 0; i < bltResult.UnsignedHeaders!.Count; ++i)
        {
            hasValidationData |= bltResult.UnsignedHeaders[i] is CBAdESUnsignedHeaderElementValidationData;
        }

        Assert.IsTrue(hasValidationData, "The B-LT signature must carry the valData element the service check (CB-6.3-26) is satisfied through.");
    }


    /// <summary>
    /// Flow 7, negative leg: the B-B bytes -- carrying no <c>sigTst</c> at all -- fail closed when validated at
    /// level B-T, collecting the CB-6.3-21 sigTst-missing violation, never a thrown exception (R-5).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult', mirroring CBAdESSignatureFlowTests's own convention.")]
    [TestMethod]
    public async Task LifecycleFlowBBBytesFailClosedWhenValidatedAtBTForMissingSignatureTimestamp()
    {
        byte[] payloadBytes = "CB-AdES flow 7 negative -- B-B bytes validated at B-T payload"u8.ToArray();
        (CBAdESCertificateThumbprint thumbprint, byte[] _) =
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
            bbWireCopy, publicKey, CBAdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

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
            btWireCopy, publicKey, CBAdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(btResult.IsValid, "The refs family (refs+sigTst+sigRTst+rfsTst) must validate at level B-T: every imprint binds the RAW wire uHeaders bytes.");
            Assert.HasCount(4, btResult.UnsignedHeaders!, "refs, sigTst, sigRTst, and rfsTst are all present.");
        }

        byte[] strippedWireCopy;
        {
            var stripContext = new CBAdESStripReferencesContext { WireBytes = btWireCopy, TargetLevel = CBAdESBaselineLevel.BT };
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
                TargetLevel = CBAdESBaselineLevel.BLT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddValidationData(
                validationDataContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            bltWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult bltResult = await ValidateAtLevelAsync(
            bltWireCopy, publicKey, CBAdESBaselineLevel.BLT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(bltResult.IsValid, "The stripped-and-valData-augmented signature must validate at level B-LT: CB-A.1.1-30 is trivially satisfied once refs is gone.");
        Assert.HasCount(2, bltResult.UnsignedHeaders!, "sigTst and valData survive the strip-then-valData upgrade; the whole refs family is gone.");

        for(int i = 0; i < bltResult.UnsignedHeaders!.Count; ++i)
        {
            CBAdESUnsignedHeaderElement element = bltResult.UnsignedHeaders[i];
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
            tampered, publicKey, CBAdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

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
    /// D15 regression, positive leg (wavecb-contract.md R-6, wavecb S4 FX-B): <c>refs</c> -&gt;
    /// <c>sigTst</c>#1 -&gt; <c>sigRTst</c> -&gt; <c>sigTst</c>#2 (Table 14 note 7's legal repeated-<c>sigTst</c>
    /// pattern, appended AFTER <c>sigRTst</c>) validates GREEN at level B-T: the SECOND <c>sigTst</c> instance
    /// must never fold into <c>sigRTst</c>'s own expected message-imprint input at validation time, since the
    /// Time-Stamping Authority that minted <c>sigRTst</c> never attested it.
    /// </summary>
    [TestMethod]
    public async Task ReferencesFamilyFlowWithSecondSignatureTimestampAfterSigRTstValidatesAtLevelBT()
    {
        byte[] payloadBytes = "CB-AdES flow 11 (D15) -- refs, sigTst, sigRTst, then a second sigTst payload"u8.ToArray();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        (byte[] btWireCopy, byte[] _) = await BuildD15RepeatedSignatureTimestampBaselineAtBTAsync(
            privateKey, payloadBytes, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await ValidateAtLevelAsync(
            btWireCopy, publicKey, CBAdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid,
            "D15: a sigTst instance appended AFTER sigRTst (Table 14 note 7) must not break sigRTst's own " +
            "message-imprint verification -- the validation-time prefix bound (D15) must exclude it.");
        Assert.HasCount(4, result.UnsignedHeaders!, "refs, sigTst#1, sigRTst, and sigTst#2 are all present.");

        int signatureTimestampCount = 0;
        for(int i = 0; i < result.UnsignedHeaders!.Count; ++i)
        {
            if(result.UnsignedHeaders[i] is CBAdESUnsignedHeaderElementSignatureTimestamp)
            {
                ++signatureTimestampCount;
            }
        }

        Assert.AreEqual(2, signatureTimestampCount, "Both sigTst instances (Table 14 note 7) must decode back out of the wire bytes.");
    }


    /// <summary>
    /// D15 regression, negative leg: the SAME <c>refs</c> -&gt; <c>sigTst</c>#1 -&gt; <c>sigRTst</c> -&gt;
    /// <c>sigTst</c>#2 baseline, with one byte of the <c>refs</c> certificate-reference digest flipped
    /// directly on the wire bytes -- validation at B-T must still collect the <c>sigRTst</c> imprint mismatch
    /// (the tamper, not the trailing second <c>sigTst</c>, is what breaks it).
    /// </summary>
    [TestMethod]
    public async Task ReferencesFamilyFlowWithSecondSignatureTimestampAfterSigRTstFailsClosedWhenReferenceDigestIsTampered()
    {
        byte[] payloadBytes = "CB-AdES flow 11 (D15) negative -- refs digest tampered payload"u8.ToArray();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        (byte[] btWireCopy, byte[] referencedCertificateDigestBytes) = await BuildD15RepeatedSignatureTimestampBaselineAtBTAsync(
            privateKey, payloadBytes, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tampered = FlipFirstOccurrenceByte(btWireCopy, referencedCertificateDigestBytes);

        using CBAdESValidationResult result = await ValidateAtLevelAsync(
            tampered, publicKey, CBAdESBaselineLevel.BT, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

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

        Assert.IsTrue(sigRTstMismatch, "sigRTst's message imprint must mismatch once the refs digest it covers is tampered, D15 prefix bound notwithstanding.");
    }


    /// <summary>
    /// Builds a CB-AdES-B-T signature exercising D15's repeated-<c>sigTst</c> scenario (wavecb-contract.md
    /// R-6, wavecb S4 FX-B): <c>refs</c>, a first <c>sigTst</c>, <c>sigRTst</c> (covering the signature value
    /// plus the <c>sigTst</c>/<c>refs</c> elements that precede IT), then a SECOND, sibling <c>sigTst</c>
    /// appended AFTER <c>sigRTst</c> (Table 14 note 7's legal multi-Time-Stamping-Authority pattern) -- the
    /// exact sequence D15's ruling exists for. Shared by the D15 regression's positive and negative legs.
    /// </summary>
    /// <param name="privateKey">The signing key. Not disposed here; the caller owns it.</param>
    /// <param name="payloadBytes">The attached payload to sign.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The B-T wire bytes (owned by the caller) and the referenced certificate's independently-computed SHA-256 digest bytes (the negative leg's tamper-search needle).</returns>
    private static async ValueTask<(byte[] WireCopy, byte[] ReferencedCertificateDigestBytes)> BuildD15RepeatedSignatureTimestampBaselineAtBTAsync(
        PrivateKeyMemory privateKey,
        byte[] payloadBytes,
        CancellationToken cancellationToken)
    {
        (CBAdESCertificateThumbprint thumbprint, byte[] _) = await CreateSigningCertificateThumbprintAsync(cancellationToken).ConfigureAwait(false);

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
                TargetLevel = CBAdESBaselineLevel.BB
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
                TargetLevel = CBAdESBaselineLevel.BT
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
                TargetLevel = CBAdESBaselineLevel.BT
            };

            using EncodedCoseSign1 wireBytes = await CBAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync(
                familyContext, CBAdESSignatureSerialization.ParseCBAdESSign1, CBAdESSignatureSerialization.SerializeCBAdESSign1,
                CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            sigRTstWireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        //The D15 scenario itself: a SECOND, sibling sigTst appended AFTER sigRTst (Table 14 note 7) -- this is
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
                TargetLevel = CBAdESBaselineLevel.BT
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
        (CBAdESCertificateThumbprint thumbprint, byte[] _) =
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
            wireCopy, publicKey, CBAdESBaselineLevel.BB, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A genuine adoTst acquired over the attached payload must validate: its message imprint binds the wire payload.");
        Assert.IsNotNull(result.Headers!.PayloadTimestamps);
    }


    /// <summary>
    /// Flow 9, negative leg: an <c>adoTst</c> acquired over one payload, but the signature actually attaches a
    /// DIFFERENT payload -- validation must collect the adoTst imprint-mismatch violation, never a thrown
    /// exception (R-5).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "adoTst and headers are deliberately not using-scoped -- see the positive leg's own " +
            "identical justification.")]
    [TestMethod]
    public async Task PayloadTimestampFlowFailsClosedWhenAdoTstWasAcquiredOverADifferentPayload()
    {
        byte[] acquiredOverPayloadBytes = "CB-AdES flow 9 negative -- adoTst acquired over THIS payload"u8.ToArray();
        byte[] actuallySignedPayloadBytes = "CB-AdES flow 9 negative -- but THIS different payload gets signed"u8.ToArray();
        (CBAdESCertificateThumbprint thumbprint, byte[] _) =
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
            wireCopy, publicKey, CBAdESBaselineLevel.BB, dereference: null, dereferenceContext: null, TestContext.CancellationToken).ConfigureAwait(false);

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

        (CBAdESCertificateThumbprint thumbprint, byte[] _) =
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
            var payloadInput = new CBAdESDetachedSigDPayloadInput(CBAdESDetachedMechanisms.ObjectIdByURI, references, HashAlgorithm: null);

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
            wireCopy, publicKey, CBAdESBaselineLevel.BB, verificationDereference, verificationContext, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A genuine adoTst acquired over the sigD-reconstructed payload must validate: the CB-5.2.8.2.3-07 adoTst half.");
        Assert.IsTrue(result.PayloadIsDetached, "The ObjectIdByURI flow's payload must decode as detached.");
        Assert.IsNotNull(result.Headers!.PayloadTimestamps);
    }


    /// <summary>
    /// Validates <paramref name="wireCopy"/> at <paramref name="level"/> through the level-aware, registry-
    /// resolved <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload, wiring the three shipped
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
        CBAdESBaselineLevel level,
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
            BaseMemoryPool.Shared,
            cancellationToken);


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
    private static async ValueTask<(byte[] WireCopy, byte[] ReferencedCertificateDigestBytes)> BuildReferencesFamilyBaselineAtBTAsync(
        PrivateKeyMemory privateKey,
        byte[] payloadBytes,
        CancellationToken cancellationToken)
    {
        (CBAdESCertificateThumbprint thumbprint, byte[] _) = await CreateSigningCertificateThumbprintAsync(cancellationToken).ConfigureAwait(false);

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
                TargetLevel = CBAdESBaselineLevel.BB
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
                TargetLevel = CBAdESBaselineLevel.BT
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
                TargetLevel = CBAdESBaselineLevel.BT
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
                TargetLevel = CBAdESBaselineLevel.BT
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
    /// Builds a signing certificate's <c>x5t</c> thumbprint fixture (SHA-256, via the registered digest
    /// delegate seam -- never a hand-rolled hash) together with an independently-kept copy of the expected
    /// digest bytes, mirroring <see cref="CBAdESSignatureFlowTests"/>'s own identically-named private helper.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The thumbprint (ownership transfers to whatever aggregate it is supplied to) and the independent digest-bytes copy.</returns>
    private static async ValueTask<(CBAdESCertificateThumbprint Thumbprint, byte[] ExpectedDigestBytes)> CreateSigningCertificateThumbprintAsync(
        CancellationToken cancellationToken)
    {
        byte[] certificateBytes = "CB-AdES lifecycle flow test -- placeholder signing certificate bytes"u8.ToArray();
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(certificateBytes), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        byte[] expectedDigestBytes = digest.AsReadOnlySpan().ToArray();
        var thumbprint = new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);

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
    /// certificate's digest region of already-augmented wire bytes, without disturbing any other field. Mirrors
    /// <see cref="CBAdESSignatureFlowTests"/>'s own identically-named private helper exactly.
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
