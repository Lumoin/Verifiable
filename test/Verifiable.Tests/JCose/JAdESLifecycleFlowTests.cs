using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Encodings.Web;
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
/// Firewalled lifecycle end-to-end flow tests for JAdES B-T/B-LT/B-LTA augmentation and LEVEL-AWARE validation,
/// through the SHIPPED <see cref="JAdESSignatureCreation"/> -&gt; <see cref="JAdESSignatureAugmentation"/> -&gt;
/// <see cref="JAdESSignatureValidation"/> composition, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>. Mirrors <c>CBAdESLifecycleFlowTests</c>'s own
/// discipline, transposed to JWS/JSON.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Firewall discipline.</strong> Every step a signer performs — creation, every augmentation verb, every
/// Time-Stamping Authority acquisition — runs inside its own nested block scope, copying ONLY the serialized
/// wire bytes into an independent <c>byte[]</c> that crosses to the next step. Every level-aware
/// <see cref="JAdESSignatureValidation.ValidateAsync(ReadOnlyMemory{byte}, TryParseJAdESMessageDelegate, DecodeJAdESProtectedHeaderDelegate, DetectJAdESX5tPresenceDelegate, TryParseJAdESEtsiUDelegate, PublicKeyMemory, DecodeDelegate, EncodeDelegate, JAdESDetachedObjectDereferenceDelegate?, JAdESDetachedObjectDereferenceContext?, ReadOnlyMemory{byte}?, JAdESHttpHeadersCanonicalizationContext?, JAdESUnknownDetachedObjectMechanismDelegate?, AdESBaselineLevel, JAdESCanonicalizeUnsignedElementDelegate, BaseMemoryPool, CancellationToken)"/>
/// call below reconstructs everything from that wire-bytes copy alone — never a creation-side object, model, or
/// in-memory decoded fact.
/// </para>
/// <para>
/// <strong>Time-Stamping Authority, in process.</strong> Every <c>sigTst</c>/<c>arcTst</c> acquisition below
/// goes through <see cref="MintingTimestampResponder"/> — no sockets; the real loopback-HTTP wire leg is
/// <c>JAdESMultiServerWireFlowTests</c>'s own scope.
/// </para>
/// <para>
/// <strong>Canonicalization.</strong> Every clear-JSON <c>arcTst</c>/<c>sigRTst</c>/<c>rfsTst</c> message-imprint
/// input below is built through a deterministic-by-<c>Kind</c> stub canonicalizer
/// (<see cref="StubCanonicalizeAsync"/>, mirroring <c>JAdESSignatureAugmentationTests</c>'s own): sufficient to
/// exercise the imprint algorithm's own byte-assembly and prefix-bound plumbing (the property this file
/// tests) without depending on <c>Verifiable.Json</c>'s own canonicalization semantics, which
/// <c>JAdESMessageImprintTests</c> covers separately. The SAME stub composes both the augmentation (generation)
/// and validation (JAdESSignatureValidation's level-aware pass) calls below, since both sides must agree on what
/// "canonical" means for the byte comparison to be meaningful at all.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JAdESLifecycleFlowTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The Time-Stamping Authority URI every acquisition context below states; never dialled over a socket.</summary>
    private static string TsaUri { get; } = "urn:test:jades-lifecycle-tsa";


    /// <summary>
    /// The full B-B -&gt; B-T -&gt; B-LT -&gt; B-LTA ladder: creates a B-B signature, raises it to B-T with a real
    /// TSA round trip (<c>sigTst</c>), to B-LT with an <c>anyValData</c> element (satisfying JA-6.3-38/j by
    /// construction), and to B-LTA with a genuine <c>arcTst</c> round trip — validating the wire bytes at EACH
    /// intermediate stage, at that stage's own declared level, reconstructed from wire bytes alone every time.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.1-01, JA-6.1-02, JA-6.1-03, JA-6.1-04, JA-6.3-01, JA-6.3-42.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "JAdESSignatureCreationResult on a successful JAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult'.")]
    [TestMethod]
    public async Task LifecycleFlowCreatesBBAugmentsThroughBTBLTBLTAWithLevelAwareValidationAtEachStage()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] payloadBytes = "JAdES lifecycle flow -- B-B to B-LTA payload"u8.ToArray();

        byte[] bbWireCopy;
        {
            using JAdESSignatureCreationResult created = await SignAsync(
                ConformantHeaders(), new JAdESAttachedPayloadInput(payloadBytes), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);
            bbWireCopy = Serialize(created, JoseSerializationFormat.FlattenedJson);
        }

        using(JAdESValidationResult bbResult = await ValidateAtLevelAsync(bbWireCopy, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(bbResult.IsValid, "A freshly-created B-B signature must validate at its own declared level B-B.");
            Assert.IsNull(bbResult.Verified!.Value.Value.UnsignedHeaders, "No etsiU has been added yet.");
        }

        byte[] btWireCopy = await JAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = bbWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = tsa.Responder.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using(JAdESValidationResult btResult = await ValidateAtLevelAsync(btWireCopy, publicKey, AdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(btResult.IsValid, "The intermediate B-T signature must validate at level B-T: its sigTst imprint binds the base64url-encoded JWS Signature Value.");
            Assert.HasCount(1, btResult.Verified!.Value.Value.UnsignedHeaders!, "Only the sigTst element has been added at this point.");
            Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(btResult.Verified.Value.Value.UnsignedHeaders![0]);
        }

        byte[] bltWireCopy = await JAdESSignatureAugmentation.AddValidationDataAsync(
            new JAdESValidationDataContext
            {
                WireBytes = btWireCopy,
                Material = new JAdESValidationMaterial { Certificates = [signingCertificate] },
                Placement = JAdESValidationDataPlacement.AnyValData,
                TargetLevel = AdESBaselineLevel.BLT
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using(JAdESValidationResult bltResult = await ValidateAtLevelAsync(bltWireCopy, publicKey, AdESBaselineLevel.BLT, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(bltResult.IsValid, "The intermediate B-LT signature must validate at level B-LT: sigTst binds and the anyValData element satisfies JA-6.3-38/j.");
            Assert.HasCount(2, bltResult.Verified!.Value.Value.UnsignedHeaders!, "sigTst then anyValData, in that order (JA-5.3.1-03 append-at-end).");
        }

        byte[] bltaWireCopy = await JAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new JAdESArchiveTimestampContext
            {
                WireBytes = bltWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                PayloadSource = Base64UrlPayloadSource(payloadBytes),
                TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = TsaUri, FetchResponse = tsa.Responder.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                CanonAlg = "urn:test:canon",
                Canonicalize = StubCanonicalizeAsync,
                TargetLevel = AdESBaselineLevel.BLTA
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using(JAdESValidationResult bltaResult = await ValidateAtLevelAsync(bltaWireCopy, publicKey, AdESBaselineLevel.BLTA, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(bltaResult.IsValid, "The final B-LTA signature must validate at the declared level B-LTA: sigTst, anyValData, and the arcTst prefix-bound imprint all check out.");
            Assert.HasCount(3, bltaResult.Verified!.Value.Value.UnsignedHeaders!, "sigTst, anyValData, arcTst, in that order.");
            Assert.IsInstanceOfType<JAdESUnsignedHeaderElementArchiveTimestamp>(bltaResult.Verified.Value.Value.UnsignedHeaders![2]);
            Assert.AreEqual(AdESBaselineLevel.BLTA, bltaResult.Level, "A level-aware success result carries the level it was checked against.");
        }
    }


    /// <summary>
    /// Table 1 NOTE 7 (multi-TSA <c>sigTst</c>): two SIBLING <c>sigTst</c> instances are appended via two
    /// separate <see cref="JAdESSignatureAugmentation.AddSignatureTimestampAsync"/> calls. Tampering the SECOND
    /// instance's own token bytes on the wire must fail closed with a
    /// <see cref="JAdESTimestampTokenBindingViolation"/> attributed to instance ordinal 1 — never the first,
    /// untouched instance (ordinal 0) — proving per-instance ordinal attribution, the CB-AdES precedent
    /// transposed.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-26.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult; " +
            "every caller disposes that return value via its own 'using' declaration.")]
    [TestMethod]
    public async Task LifecycleFlowWithTwoSignatureTimestampsFailsClosedWithSecondInstanceOrdinalWhenTheSecondTokenIsTamperedOnTheWire()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] payloadBytes = "JAdES lifecycle flow -- two sigTst instances payload"u8.ToArray();

        byte[] bbWireCopy;
        {
            using JAdESSignatureCreationResult created = await SignAsync(
                ConformantHeaders(), new JAdESAttachedPayloadInput(payloadBytes), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);
            bbWireCopy = Serialize(created, JoseSerializationFormat.FlattenedJson);
        }

        var context = new JAdESSignatureTimestampContext
        {
            WireBytes = bbWireCopy,
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            TsaUri = TsaUri,
            FetchResponse = tsa.Responder.FetchAsync,
            SigningCertificate = signingCertificate,
            TargetLevel = AdESBaselineLevel.BT
        };

        byte[] withFirst = await AddSignatureTimestampAsync(context, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] withBoth = await AddSignatureTimestampAsync(WithWireBytes(context, withFirst), TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders decoded = DecodeUnsignedHeaders(withBoth);
        Assert.AreEqual(2, decoded.Count);
        byte[] secondTokenBytes = ExtractSigTstTokenBytes(decoded, 1);

        byte[] tampered = TamperBase64EncodedBytesOnWire(withBoth, secondTokenBytes);

        using JAdESValidationResult result = await ValidateAtLevelAsync(tampered, publicKey, AdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Tampering the second sigTst instance's own token content must invalidate that specific instance's imprint check.");
        var failure = Assert.IsInstanceOfType<JAdESRuleViolationsFailure>(result.Failure);

        //A single-byte flip inside a genuine CMS-signed RFC 3161 token most often breaks the token's OWN CMS
        //signature (TokenNotRead) rather than surviving a valid-but-wrong-imprint read (ImprintMismatch) -- either
        //reason proves the SAME property under test here (ordinal attribution), so both are accepted.
        bool secondInstanceMismatch = false;
        for(int i = 0; i < failure.Violations.Count; ++i)
        {
            if(failure.Violations[i] is JAdESTimestampTokenBindingViolation binding
                && binding.Kind == JAdESTimestampTokenBindingKind.SignatureTimestamp)
            {
                Assert.AreEqual(1, binding.InstanceOrdinal, "The mismatch must be attributed to the SECOND sigTst instance's own etsiU position (index 1), not the first (index 0).");
                secondInstanceMismatch = true;
            }
        }

        Assert.IsTrue(secondInstanceMismatch, "The second sigTst instance's own token binding must fail once its token bytes are tampered.");
    }


    /// <summary>
    /// A renewal at B-LTA: a signature already at B-LTA (one <c>arcTst</c> instance) receives a SECOND,
    /// independent <see cref="JAdESSignatureAugmentation.AddArchiveTimestampAsync"/> call — a genuine renewal,
    /// appending a SIBLING <c>arcTst</c> instance (never folding into the first). Both instances' own
    /// prefix-bound message imprints re-verify from wire bytes alone at the declared level B-LTA.
    /// </summary>
    [TestMethod]
    public async Task LifecycleFlowRenewsArchiveTimestampAndValidatesBothInstancesAtBLTA()
    {
        (byte[] finalWireCopy, PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = await BuildRenewedArchiveTimestampBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory ownedPublicKey = publicKey;
        using PrivateKeyMemory ownedPrivateKey = privateKey;

        using JAdESValidationResult result = await ValidateAtLevelAsync(finalWireCopy, ownedPublicKey, AdESBaselineLevel.BLTA, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A genuine renewal (two arcTst instances, each with its own message imprint) must validate at the declared level B-LTA with zero collected violations.");
        Assert.HasCount(3, result.Verified!.Value.Value.UnsignedHeaders!, "sigTst, arcTst#1, arcTst#2 -- the renewal call appends a sibling, never mutating the first.");

        int archiveTimestampCount = 0;
        for(int i = 0; i < result.Verified.Value.Value.UnsignedHeaders!.Count; ++i)
        {
            if(result.Verified.Value.Value.UnsignedHeaders[i] is JAdESUnsignedHeaderElementArchiveTimestamp)
            {
                ++archiveTimestampCount;
            }
        }

        Assert.AreEqual(2, archiveTimestampCount);
    }


    /// <summary>
    /// The SAME renewed-B-LTA baseline as above, but the FIRST <c>arcTst</c>
    /// instance's own token content is tampered on the wire — bytes the SECOND (renewal) instance's own
    /// validation-time prefix (only <c>etsiU</c> elements strictly BEFORE an instance's own position
    /// contribute to ITS imprint) covers. Validation must collect the SECOND instance's own imprint mismatch,
    /// attributed to ITS OWN ordinal (index 2), never the untouched first instance's (index 1) — proving the
    /// prefix bound is wired correctly rather than merely documented.
    /// </summary>
    [TestMethod]
    public async Task LifecycleFlowFailsClosedWhenTheFirstArchiveTimestampIsTamperedAndTheSecondInstanceOwnPrefixCoversIt()
    {
        (byte[] finalWireCopy, PublicKeyMemory publicKey, PrivateKeyMemory privateKey, byte[] firstArchiveTimestampTokenBytes) =
            await BuildRenewedArchiveTimestampBaselineWithFirstTokenAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory ownedPublicKey = publicKey;
        using PrivateKeyMemory ownedPrivateKey = privateKey;

        byte[] tampered = TamperBase64EncodedBytesOnWire(finalWireCopy, firstArchiveTimestampTokenBytes);

        using JAdESValidationResult result = await ValidateAtLevelAsync(tampered, ownedPublicKey, AdESBaselineLevel.BLTA, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Tampering the first arcTst instance's own token content must invalidate the second (renewal) instance's own prefix-bound imprint.");
        var failure = Assert.IsInstanceOfType<JAdESRuleViolationsFailure>(result.Failure);

        //arcTst#1's own DIRECT token-open check also fires (its own content changed, ordinal=1) -- this assertion
        //narrows to the PREFIX-BOUND proof specifically: arcTst#2 (ordinal=2) must ALSO report a mismatch,
        //proving its own imprint genuinely covers arcTst#1's content, not merely that arcTst#1 itself
        //fails its own direct check.
        bool secondArchiveTimestampMismatch = false;
        for(int i = 0; i < failure.Violations.Count; ++i)
        {
            if(failure.Violations[i] is JAdESTimestampTokenBindingViolation binding
                && binding.Kind == JAdESTimestampTokenBindingKind.ArchiveTimestamp
                && binding.InstanceOrdinal == 2)
            {
                secondArchiveTimestampMismatch = true;
            }
        }

        Assert.IsTrue(secondArchiveTimestampMismatch, "The second (renewal) arcTst instance's own message imprint must mismatch once the first instance's raw bytes -- which its own prefix covers -- are tampered.");
    }


    /// <summary>
    /// Mode-neutral augmentation and the letter-j inversion together: the full B-B -&gt; B-T -&gt; B-LTA ladder, bootstrapped in BASE64URL incorporation from the
    /// first element (never clear-JSON), validating at each intermediate level from wire bytes alone. UNLIKE the
    /// clear-mode ladder above, no <c>xVals</c>/<c>rVals</c>/<c>anyValData</c> is ever added — the B-LT/B-LTA
    /// "incorporation of validation data for electronic time-stamps" service (JA-6.3-38/j) is satisfied SOLELY
    /// by the <c>sigTst</c> token's own embedded certificates (<see cref="TsaFixture"/>'s <c>[authority, root]</c>
    /// chain), a fact that both-modes verification is what makes derivable at all under base64url
    /// incorporation — before that fix, the whole per-instance verification pass never ran under
    /// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>, so this level would have failed closed with
    /// <c>JAdESTimestampValidationDataServiceViolation</c> for every conformant base64url-mode signature.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-40.
    /// </remarks>
    [TestMethod]
    public async Task LifecycleFlowInBase64UrlModeReachesBLTAAndValidatesAtEachLevelRelyingOnEmbeddedCertificates()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();

        (byte[] btWireCopy, byte[] bltaWireCopy, PublicKeyMemory publicKey, PrivateKeyMemory privateKey, byte[] _) =
            await BuildBase64UrlModeBaselineAsync(tsa, signingCertificate, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory ownedPublicKey = publicKey;
        using PrivateKeyMemory ownedPrivateKey = privateKey;

        using(JAdESValidationResult btResult = await ValidateAtLevelAsync(btWireCopy, ownedPublicKey, AdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(btResult.IsValid, "The base64url-mode B-T signature must validate at B-T: its opaque sigTst carriage's own decoded view binds the base64url-encoded JWS Signature Value.");
            Assert.AreEqual(JAdESEtsiUIncorporationMode.Base64Url, btResult.Verified!.Value.Value.UnsignedHeaders!.Mode);
        }

        using(JAdESValidationResult bltResult = await ValidateAtLevelAsync(btWireCopy, ownedPublicKey, AdESBaselineLevel.BLT, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(bltResult.IsValid, "Relying solely on the sigTst token's own embedded certificates must satisfy JA-6.3-38/j, even under base64url incorporation (the letter-j inversion).");
            var failure = bltResult.Failure as JAdESRuleViolationsFailure;
            Assert.IsNull(failure, "No JAdESTimestampValidationDataServiceViolation -- or any other violation -- when the embedded-material path alone satisfies the service.");
        }

        using(JAdESValidationResult bltaResult = await ValidateAtLevelAsync(bltaWireCopy, ownedPublicKey, AdESBaselineLevel.BLTA, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(bltaResult.IsValid, "The full base64url-mode B-B -> B-T -> B-LTA ladder must validate at B-LTA.");
            Assert.HasCount(3, bltaResult.Verified!.Value.Value.UnsignedHeaders!, "cSig (the bootstrap element), sigTst, then arcTst.");
            Assert.IsInstanceOfType<JAdESUnsignedHeaderElementArchiveTimestamp>(bltaResult.Verified.Value.Value.UnsignedHeaders![2]);
        }
    }


    /// <summary>
    /// THE EXPLOIT BECOMES THE REGRESSION. A valid
    /// base64url-mode B-LTA signature's own <c>arcTst</c> array-element TEXT is swapped, on the wire, for a
    /// DIFFERENT, attacker-chosen <c>tstContainer</c> — a genuinely valid RFC 3161 token (the signature's own
    /// <c>sigTst</c> token, reused), so the CMS signature itself still opens and verifies; only the message
    /// imprint it was computed over differs. Before the fix, this attack was undetectable: the whole per-instance
    /// verification pass never ran under base64url incorporation, so the signature would have reported VALID
    /// despite the substitution. Now it fails closed with an <see cref="JAdESTimestampTokenBindingFailureReason.ImprintMismatch"/>
    /// attributed to the <c>arcTst</c> element's OWN <c>etsiU</c> position.
    /// </summary>
    [TestMethod]
    public async Task LifecycleFlowInBase64UrlModeFailsClosedWhenArcTstTextIsSwappedForAnAttackerChosenTstContainer()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();

        (byte[] btWireCopy, byte[] bltaWireCopy, PublicKeyMemory publicKey, PrivateKeyMemory privateKey, byte[] _) =
            await BuildBase64UrlModeBaselineAsync(tsa, signingCertificate, TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory ownedPublicKey = publicKey;
        using PrivateKeyMemory ownedPrivateKey = privateKey;

        byte[] attackerTokenBytes;
        using(JAdESUnsignedHeaders btDecoded = DecodeUnsignedHeaders(btWireCopy))
        {
            attackerTokenBytes = ExtractOpaqueSigTstTokenBytes(btDecoded, 1); //index 0 is the bootstrap cSig element.
        }

        int arcTstOrdinal;
        using(JAdESUnsignedHeaders bltaDecoded = DecodeUnsignedHeaders(bltaWireCopy))
        {
            arcTstOrdinal = FindArcTstOrdinal(bltaDecoded);
        }

        byte[] tampered = SwapBase64UrlArcTstElementText(bltaWireCopy, attackerTokenBytes);

        using JAdESValidationResult result = await ValidateAtLevelAsync(tampered, ownedPublicKey, AdESBaselineLevel.BLTA, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A valid base64url-mode B-LTA signature whose arcTst text is swapped for an attacker-chosen tstContainer must fail -- the exploit this fix closes.");
        var failure = Assert.IsInstanceOfType<JAdESRuleViolationsFailure>(result.Failure);

        bool imprintMismatchFound = false;
        for(int i = 0; i < failure.Violations.Count; ++i)
        {
            if(failure.Violations[i] is JAdESTimestampTokenBindingViolation binding
                && binding.Kind == JAdESTimestampTokenBindingKind.ArchiveTimestamp
                && binding.Reason == JAdESTimestampTokenBindingFailureReason.ImprintMismatch)
            {
                Assert.AreEqual(arcTstOrdinal, binding.InstanceOrdinal, "The mismatch must be attributed to the arcTst element's own etsiU position, ordinal-attributed.");
                imprintMismatchFound = true;
            }
        }

        Assert.IsTrue(imprintMismatchFound, "The attacker-substituted token -- valid CMS, wrong message imprint -- must surface as an ImprintMismatch, never a silently-accepted input.");
    }


    /// <summary>
    /// Closing the <see cref="JAdESLevelRules.CheckCounterSignaturesAsync"/> wiring gap: a
    /// genuine <c>cSig</c> countersignature -- computed over the embedding signature's own JWS Signature Value,
    /// so it targets a fact that can only be known once the embedding signature already exists, then spliced
    /// onto the wire AFTER signing -- is tampered (one base64url character flipped inside its own signature
    /// segment, leaving it structurally decodable but cryptographically wrong). Level-aware validation opted
    /// into the countersignature check (a decode delegate plus a key resolver, the CBAdESSignatureValidation
    /// opt-in precedent) must fail closed with a <see cref="JAdESCounterSignatureVerificationViolation"/>; a
    /// companion assertion over the SAME wire bytes with the opt-in omitted confirms the established convention
    /// -- structural acceptance only, the check unreachable without it -- which is what made this wiring gap
    /// invisible before this fix.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult, " +
            "disposed by the local 'using JAdESSignatureCreationResult created'; BuildCounterSignatureElement()'s " +
            "ownership transfers into AppendCounterSignatureElement's own callee-owned working " +
            "JAdESUnsignedHeaders (see that method's own remarks), disposed there.")]
    [TestMethod]
    public async Task LifecycleFlowWithTamperedCounterSignatureFailsClosedOnlyWhenTheCounterSignatureCheckIsOptedInto()
    {
        var embeddingKeyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = embeddingKeyPair.PublicKey;
        using PrivateKeyMemory privateKey = embeddingKeyPair.PrivateKey;

        var counterKeyPair = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory counterPublicKey = counterKeyPair.PublicKey;
        using PrivateKeyMemory counterPrivateKey = counterKeyPair.PrivateKey;

        byte[] payloadBytes = "JAdES lifecycle flow -- countersignature payload"u8.ToArray();

        byte[] bbWireCopy;
        byte[] embeddingSignatureValue;
        {
            using JAdESSignatureCreationResult created = await SignAsync(
                ConformantHeaders(), new JAdESAttachedPayloadInput(payloadBytes), unsignedHeaders: null, privateKey, TestContext.CancellationToken).ConfigureAwait(false);
            embeddingSignatureValue = created.Message.Signatures[0].SignatureBytes.ToArray();
            bbWireCopy = Serialize(created, JoseSerializationFormat.FlattenedJson);
        }

        string compactCounterSignature;
        using(JwsMessage countersignature = await JAdESCounterSign.CountersignAsync(
            embeddingSignatureValue,
            new Dictionary<string, object> { ["alg"] = "ES256" },
            CounterSignerHeaderEncoder,
            TestSetup.Base64UrlEncoder,
            counterPrivateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            counterSignerUnprotectedHeader: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            compactCounterSignature = JwsSerialization.SerializeCompact(countersignature, TestSetup.Base64UrlEncoder);
        }

        byte[] withCSigWireCopy = AppendCounterSignatureElement(
            bbWireCopy, BuildCounterSignatureElement($"{{\"cSig\":\"{compactCounterSignature}\"}}"));
        byte[] tampered = TamperCounterSignatureCompactText(withCSigWireCopy, compactCounterSignature);

        using(JAdESValidationResult optedIn = await ValidateAtLevelAsync(
            tampered, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken,
            JAdESCounterSignatureJson.TryDecode, _ => counterPublicKey).ConfigureAwait(false))
        {
            Assert.IsFalse(optedIn.IsValid, "A tampered cSig countersignature must fail closed once the caller opts into the countersignature check.");
            var failure = Assert.IsInstanceOfType<JAdESRuleViolationsFailure>(optedIn.Failure);

            bool counterSignatureViolationFound = false;
            for(int i = 0; i < failure.Violations.Count; ++i)
            {
                if(failure.Violations[i] is JAdESCounterSignatureVerificationViolation)
                {
                    counterSignatureViolationFound = true;
                }
            }

            Assert.IsTrue(counterSignatureViolationFound, "CheckCounterSignaturesAsync must be reachable from the level-aware ValidateAsync orchestrator once the decode delegate is supplied.");
        }

        using JAdESValidationResult withoutOptIn = await ValidateAtLevelAsync(tampered, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(withoutOptIn.IsValid, "Without the opt-in decode delegate, a cSig element -- tampered or not -- is structurally accepted only (the established convention).");
    }


    /// <summary>
    /// Closing the <see cref="JAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/>
    /// wiring gap -- also a missing real-CMS-fixture test: an <c>xRefs</c> certificate reference with NO
    /// <c>xVals</c>/<c>axVals</c> anywhere in the signature resolves solely against the certificate a genuine
    /// <c>arcTst</c> instance's own RFC 3161 token embeds -- the CB-A.1.1-30 analog
    /// (<c>CBAdESLevelValidationNegativeTests.ValidateAsyncSucceedsWhenACertificateReferenceResolvesToAnArchiveTimestampTokenEmbeddedCertificate</c>),
    /// exercised end to end through the SHIPPED creation -&gt; validation composition over a real TSA-minted
    /// token, never a hand-rolled one. <c>xRefs</c> and <c>arcTst</c> coexisting is only Table-1-legal below
    /// B-LT (xRefs) and at B-LTA-exclusive generation (arcTst) respectively, so this validates at B-B, where
    /// both rows are soft (<see cref="AdESPresence.ShouldNotBePresent"/>, never enforced) rather than mutually
    /// forbidden -- mirroring the CB-AdES precedent's own choice of its loosest level for the identical reason.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions building the certificate-reference/archive-timestamp elements " +
            "are constructor arguments passed straight into the enclosing 'using var unsignedHeaders' aggregate's " +
            "own construction; ownership passes to unsignedHeaders, which the local using disposes. " +
            "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult, disposed " +
            "by the local 'using JAdESSignatureCreationResult created'.")]
    [TestMethod]
    public async Task LifecycleFlowResolvesCertificateReferenceAgainstArchiveTimestampTokenEmbeddedCertificate()
    {
        using TsaFixture tsa = TsaFixture.Create(TestContext.CancellationToken);
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] payloadBytes = "JAdES lifecycle flow -- refs resolves against arcTst token payload"u8.ToArray();

        DigestValue referenceDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            tsa.Authority.Certificate.RawDataMemory, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tokenBytes;
        using(PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], payloadBytes, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            tokenBytes = token.AsReadOnlySpan().ToArray();
        }

        using var unsignedHeaders = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.ClearJson,
        [
            new JAdESUnsignedHeaderElementCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(
                new JAdESCertificateReferenceCollection([new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), referenceDigest)]))),
            new JAdESUnsignedHeaderElementArchiveTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(
                new AdESTimestampContainer([new AdESTimestampToken { Val = tokenBytes }], "urn:test:canon")))
        ]);

        byte[] bbWireCopy;
        {
            using JAdESSignatureCreationResult created = await SignAsync(
                ConformantHeaders(), new JAdESAttachedPayloadInput(payloadBytes), unsignedHeaders, privateKey, TestContext.CancellationToken).ConfigureAwait(false);
            bbWireCopy = Serialize(created, JoseSerializationFormat.FlattenedJson);
        }

        using JAdESValidationResult result = await ValidateAtLevelAsync(bbWireCopy, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The xRefs certificate reference must resolve against the arcTst token's own embedded certificate -- no xVals/axVals element anywhere -- widening the candidate set beyond declared validation data alone.");
    }


    /// <summary>Builds a B-B -&gt; B-T -&gt; B-LTA -&gt; (renewed) B-LTA baseline: sigTst, then a first arcTst, then a second (renewal) arcTst -- three etsiU elements total.</summary>
    private static async ValueTask<(byte[] FinalWireCopy, PublicKeyMemory PublicKey, PrivateKeyMemory PrivateKey)> BuildRenewedArchiveTimestampBaselineAsync(CancellationToken cancellationToken)
    {
        (byte[] finalWireCopy, PublicKeyMemory publicKey, PrivateKeyMemory privateKey, byte[] _) =
            await BuildRenewedArchiveTimestampBaselineWithFirstTokenAsync(cancellationToken).ConfigureAwait(false);

        return (finalWireCopy, publicKey, privateKey);
    }


    /// <summary>Same as <see cref="BuildRenewedArchiveTimestampBaselineAsync"/>, additionally returning the FIRST arcTst instance's own token bytes for tamper targeting.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult; " +
            "every caller disposes that return value via its own 'using' declaration.")]
    private static async ValueTask<(byte[] FinalWireCopy, PublicKeyMemory PublicKey, PrivateKeyMemory PrivateKey, byte[] FirstArchiveTimestampTokenBytes)> BuildRenewedArchiveTimestampBaselineWithFirstTokenAsync(CancellationToken cancellationToken)
    {
        using TsaFixture tsa = TsaFixture.Create(cancellationToken);
        using PkiCertificateMemory signingCertificate = tsa.SignerCertificate();
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        PublicKeyMemory publicKey = keyPair.PublicKey;
        PrivateKeyMemory privateKey = keyPair.PrivateKey;

        byte[] payloadBytes = "JAdES lifecycle flow -- renewed arcTst payload"u8.ToArray();

        byte[] bbWireCopy;
        {
            using JAdESSignatureCreationResult created = await SignAsync(
                ConformantHeaders(), new JAdESAttachedPayloadInput(payloadBytes), unsignedHeaders: null, privateKey, cancellationToken).ConfigureAwait(false);
            bbWireCopy = Serialize(created, JoseSerializationFormat.FlattenedJson);
        }

        byte[] btWireCopy = await JAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = bbWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = tsa.Responder.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        var archiveTimestampContext = new JAdESArchiveTimestampContext
        {
            WireBytes = btWireCopy,
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            PayloadSource = Base64UrlPayloadSource(payloadBytes),
            TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = TsaUri, FetchResponse = tsa.Responder.FetchAsync }],
            SigningCertificate = signingCertificate,
            ChainCompletenessAttested = true,
            AnyTimestampTokenCarriesEmbeddedValidationMaterial = true,
            CanonAlg = "urn:test:canon",
            Canonicalize = StubCanonicalizeAsync,
            TargetLevel = AdESBaselineLevel.BLTA
        };

        byte[] firstArchiveTimestampWireCopy = await JAdESSignatureAugmentation.AddArchiveTimestampAsync(
            WithWireBytes(archiveTimestampContext, btWireCopy),
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        using JAdESUnsignedHeaders afterFirst = DecodeUnsignedHeaders(firstArchiveTimestampWireCopy);
        byte[] firstArchiveTimestampTokenBytes = ExtractArcTstTokenBytes(afterFirst, 1);

        byte[] finalWireCopy = await JAdESSignatureAugmentation.AddArchiveTimestampAsync(
            WithWireBytes(archiveTimestampContext, firstArchiveTimestampWireCopy),
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        return (finalWireCopy, publicKey, privateKey, firstArchiveTimestampTokenBytes);
    }


    /// <summary>
    /// Builds a BASE64URL-incorporated B-B -&gt; B-T -&gt; B-LTA ladder: bootstraps
    /// with a base64url-incorporated <c>cSig</c> element (the mode-agnostic arm, the only way to declare
    /// base64url incorporation from the FIRST element -- <c>etsiU</c> is non-empty by construction, JA-5.3.1-07),
    /// raises to B-T over a real Time-Stamping Authority round trip, then to B-LTA over a second real round trip
    /// -- <c>AnyTimestampTokenCarriesEmbeddedValidationMaterial = true</c> attests, at the AUGMENTATION side, the
    /// SAME embedded-certificate fact <see cref="TsaFixture"/>'s tokens genuinely carry (this call cannot itself
    /// open CMS structure to derive it); VALIDATION derives it independently, from the real tokens, which is
    /// what both regressions this baseline feeds actually exercise.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ConformantHeaders()'s ownership transfers into the returned JAdESSignatureCreationResult, " +
            "disposed via 'using created'; the cSig element's ownership transfers into opaqueUnsignedHeaders, " +
            "disposed via its own 'using' declaration; opaqueUnsignedHeaders is never taken ownership of by " +
            "SignAsync (only projected via EncodeJAdESUnprotectedHeaderDelegate).")]
    private static async ValueTask<(byte[] BtWireCopy, byte[] BltaWireCopy, PublicKeyMemory PublicKey, PrivateKeyMemory PrivateKey, byte[] PayloadBytes)>
        BuildBase64UrlModeBaselineAsync(TsaFixture tsa, PkiCertificateMemory signingCertificate, CancellationToken cancellationToken)
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        PublicKeyMemory publicKey = keyPair.PublicKey;
        PrivateKeyMemory privateKey = keyPair.PrivateKey;
        byte[] payloadBytes = "JAdES lifecycle flow -- base64url-mode ladder payload"u8.ToArray();

        byte[] bbWireCopy;
        {
            string cSigBase64Url = TestSetup.Base64UrlEncoder("{\"cSig\":\"x\"}"u8);
            using var opaqueUnsignedHeaders = new JAdESUnsignedHeaders(
                JAdESEtsiUIncorporationMode.Base64Url,
                [new JAdESUnsignedHeaderElementCounterSignature(PooledMemory.FromBytes(Encoding.ASCII.GetBytes(cSigBase64Url), BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

            using JAdESSignatureCreationResult created = await SignAsync(
                ConformantHeaders(), new JAdESAttachedPayloadInput(payloadBytes), opaqueUnsignedHeaders, privateKey, cancellationToken).ConfigureAwait(false);
            bbWireCopy = Serialize(created, JoseSerializationFormat.FlattenedJson);
        }

        byte[] btWireCopy = await JAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new JAdESSignatureTimestampContext
            {
                WireBytes = bbWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = tsa.Responder.FetchAsync,
                SigningCertificate = signingCertificate,
                TargetLevel = AdESBaselineLevel.BT
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        byte[] bltaWireCopy = await JAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new JAdESArchiveTimestampContext
            {
                WireBytes = btWireCopy,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                PayloadSource = Base64UrlPayloadSource(payloadBytes),
                TsaLegs = [new JAdESArchiveTimestampTsaLeg { TsaUri = TsaUri, FetchResponse = tsa.Responder.FetchAsync }],
                SigningCertificate = signingCertificate,
                ChainCompletenessAttested = true,
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = true,
                CanonAlg = "urn:test:canon",
                Canonicalize = StubCanonicalizeAsync,
                TargetLevel = AdESBaselineLevel.BLTA
            },
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        return (btWireCopy, bltaWireCopy, publicKey, privateKey, payloadBytes);
    }


    /// <summary>Extracts the sole token's own <c>val</c> bytes from the OPAQUE-carriage <c>sigTst</c> element at <paramref name="index"/> (the decoded view), as a fresh array.</summary>
    private static byte[] ExtractOpaqueSigTstTokenBytes(JAdESUnsignedHeaders unsignedHeaders, int index)
    {
        var element = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(unsignedHeaders[index]);
        var opaque = Assert.IsInstanceOfType<JAdESOpaqueUnsignedValue<AdESTimestampContainer>>(element.Carriage);

        return opaque.DecodedValue.TstTokens[0].Val.ToArray();
    }


    /// <summary>Finds the zero-based <c>etsiU</c> position of the sole <c>arcTst</c> element.</summary>
    private static int FindArcTstOrdinal(JAdESUnsignedHeaders unsignedHeaders)
    {
        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            if(unsignedHeaders[i] is JAdESUnsignedHeaderElementArchiveTimestamp)
            {
                return i;
            }
        }

        Assert.Fail("No arcTst element found.");

        return -1;
    }


    /// <summary>
    /// Swaps the base64url-incorporated <c>arcTst</c> array element's own wire TEXT for a DIFFERENT, attacker-
    /// chosen <c>tstContainer</c> wrapping <paramref name="attackerTokenBytes"/> (a genuinely valid RFC 3161
    /// token computed over a DIFFERENT message imprint) — THE EXPLOIT this fix closes (see the calling test's
    /// own remarks). A plain string substitution: JSON tolerates the replacement text differing in length from
    /// the original, unlike <see cref="TamperBase64EncodedBytesOnWire"/>'s same-length in-place flip.
    /// </summary>
    private static byte[] SwapBase64UrlArcTstElementText(byte[] wireBytes, byte[] attackerTokenBytes)
    {
        string attackerJson = $"{{\"arcTst\":{{\"tstTokens\":[{{\"val\":\"{Convert.ToBase64String(attackerTokenBytes)}\"}}]}}}}";
        string attackerBase64Url = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(attackerJson));

        string originalBase64Url;
        using(JAdESUnsignedHeaders decoded = DecodeUnsignedHeaders(wireBytes))
        {
            int arcTstIndex = FindArcTstOrdinal(decoded);
            var element = (JAdESUnsignedHeaderElementArchiveTimestamp)decoded[arcTstIndex];
            var opaque = Assert.IsInstanceOfType<JAdESOpaqueUnsignedValue<AdESTimestampContainer>>(element.Carriage);
            originalBase64Url = Encoding.ASCII.GetString(opaque.WireText.AsReadOnlySpan());
        }

        string wireText = Encoding.UTF8.GetString(wireBytes);
        int index = wireText.IndexOf(originalBase64Url, StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, index, "The arcTst element's own base64url wire text must be found verbatim in the JSON document.");

        string swapped = string.Concat(wireText.AsSpan(0, index), attackerBase64Url, wireText.AsSpan(index + originalBase64Url.Length));

        return Encoding.UTF8.GetBytes(swapped);
    }


    private static ValueTask<byte[]> AddSignatureTimestampAsync(JAdESSignatureTimestampContext context, CancellationToken cancellationToken) =>
        JAdESSignatureAugmentation.AddSignatureTimestampAsync(
            context, JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESEtsiUJson.TryParse, JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, JsonSerialize, BaseMemoryPool.Shared, cancellationToken);


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


    private static ValueTask<JAdESValidationResult> ValidateAtLevelAsync(
        byte[] wireBytes, PublicKeyMemory publicKey, AdESBaselineLevel level, CancellationToken cancellationToken,
        TryDecodeJAdESCounterSignatureDelegate? tryDecodeCounterSignature = null,
        ResolveJAdESCounterSignaturePublicKeyDelegate? resolvePublicKey = null) =>
        JAdESSignatureValidation.ValidateAsync(
            wireBytes,
            JAdESMessageJson.TryParse,
            JAdESProtectedHeaderJson.Decode,
            JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null,
            httpHeadersContext: null, unknownMechanismHandler: null,
            level, StubCanonicalizeAsync,
            BaseMemoryPool.Shared,
            tryDecodeCounterSignature, resolvePublicKey,
            cancellationToken: cancellationToken);


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
        Assert.IsTrue(parsed, "The wire bytes must remain parseable.");

        using(message)
        {
            Assert.IsNotNull(message!.EtsiURawBytes);

            bool etsiUParsed = JAdESEtsiUJson.TryParse(
                message.EtsiURawBytes!.AsReadOnlySpan(), TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out JAdESUnsignedHeaders? unsignedHeaders);
            Assert.IsTrue(etsiUParsed);

            return unsignedHeaders!;
        }
    }


    /// <summary>Extracts the sole token's own <c>val</c> bytes from the <c>sigTst</c> element at <paramref name="index"/>, as a fresh array.</summary>
    private static byte[] ExtractSigTstTokenBytes(JAdESUnsignedHeaders unsignedHeaders, int index)
    {
        var element = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementSignatureTimestamp>(unsignedHeaders[index]);
        var clear = Assert.IsInstanceOfType<JAdESClearUnsignedValue<AdESTimestampContainer>>(element.Carriage);

        return clear.Value.TstTokens[0].Val.ToArray();
    }


    /// <summary>Extracts the sole token's own <c>val</c> bytes from the <c>arcTst</c> element at <paramref name="index"/>, as a fresh array.</summary>
    private static byte[] ExtractArcTstTokenBytes(JAdESUnsignedHeaders unsignedHeaders, int index)
    {
        var element = Assert.IsInstanceOfType<JAdESUnsignedHeaderElementArchiveTimestamp>(unsignedHeaders[index]);
        var clear = Assert.IsInstanceOfType<JAdESClearUnsignedValue<AdESTimestampContainer>>(element.Carriage);

        return clear.Value.TstTokens[0].Val.ToArray();
    }


    /// <summary>
    /// Finds <paramref name="originalTokenBytes"/>'s own standard-base64 wire TEXT within
    /// <paramref name="wireBytes"/> (the JAdES <c>val</c> member's own wire encoding, JA-5.4.3.3-12 — plain
    /// base64, distinct from the rest of the message's base64URL segments) and replaces it with the base64 text
    /// of the SAME bytes with their last octet flipped — a same-length substitution, so no other offset in the
    /// JSON document shifts.
    /// </summary>
    private static byte[] TamperBase64EncodedBytesOnWire(byte[] wireBytes, byte[] originalTokenBytes)
    {
        string originalBase64 = Convert.ToBase64String(originalTokenBytes);

        byte[] tamperedTokenBytes = (byte[])originalTokenBytes.Clone();
        tamperedTokenBytes[^1] ^= 0xFF;
        string tamperedBase64 = Convert.ToBase64String(tamperedTokenBytes);

        string wireText = Encoding.UTF8.GetString(wireBytes);
        int index = wireText.IndexOf(originalBase64, StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, index, "The token's own base64 wire text must be found verbatim in the JSON document.");

        string tamperedText = string.Concat(wireText.AsSpan(0, index), tamperedBase64, wireText.AsSpan(index + originalBase64.Length));

        return Encoding.UTF8.GetBytes(tamperedText);
    }


    /// <summary>
    /// Flips one base64url character within <paramref name="originalCompact"/>'s own SIGNATURE segment (after
    /// its last '.') as found verbatim inside <paramref name="wireBytes"/>'s own <c>cSig</c> JSON string value —
    /// keeps the nested compact JWS structurally decodable (still three dot-separated segments) while
    /// invalidating its own cryptographic signature, a same-length substitution so no other wire offset shifts.
    /// </summary>
    private static byte[] TamperCounterSignatureCompactText(byte[] wireBytes, string originalCompact)
    {
        string wireText = Encoding.UTF8.GetString(wireBytes);
        int index = wireText.IndexOf(originalCompact, StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, index, "The countersignature's own compact wire text must be found verbatim in the JSON document.");

        int lastDot = originalCompact.LastIndexOf('.');
        char[] chars = originalCompact.ToCharArray();
        int flipIndex = lastDot + 1;
        chars[flipIndex] = chars[flipIndex] == 'A' ? 'B' : 'A';
        string tamperedCompact = new string(chars);

        string tamperedText = string.Concat(wireText.AsSpan(0, index), tamperedCompact, wireText.AsSpan(index + originalCompact.Length));

        return Encoding.UTF8.GetBytes(tamperedText);
    }


    /// <summary>Builds a <c>cSig</c> element carrying <paramref name="clearJsonWireText"/> verbatim, in clear-JSON incorporation.</summary>
    private static JAdESUnsignedHeaderElementCounterSignature BuildCounterSignatureElement(string clearJsonWireText) =>
        new(PooledMemory.FromBytes(Encoding.UTF8.GetBytes(clearJsonWireText), BaseMemoryPool.Shared, Tag.Create(Purpose.Data)));


    /// <summary>
    /// Splices <paramref name="cSigElement"/> onto <paramref name="wireBytes"/>'s own unprotected header AFTER
    /// signing — mirrors <c>JAdESSignatureAugmentation</c>'s own private <c>SerializeAugmented</c> shape (a
    /// fresh <see cref="JwsSignatureComponent"/> over a COPY of the original signature bytes, carrying the new
    /// unprotected header projection) since a countersignature's own target — the embedding signature's JWS
    /// Signature Value — can only be known once <paramref name="wireBytes"/> already carries it, ruling out
    /// passing a genuine <c>cSig</c> element through <see cref="SignAsync"/> directly. Takes ownership of
    /// <paramref name="cSigElement"/> (disposed via the local working <see cref="JAdESUnsignedHeaders"/>).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "component's ownership transfers into newMessage, disposed by the local 'using var newMessage' below.")]
    private static byte[] AppendCounterSignatureElement(byte[] wireBytes, JAdESUnsignedHeaderElementCounterSignature cSigElement)
    {
        bool parsed = JAdESMessageJson.TryParse(wireBytes, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, out UnverifiedJAdESMessage? message, out _);
        Assert.IsTrue(parsed, "The wire bytes must remain parseable.");

        using(message)
        {
            UnverifiedJwsSignature originalSignature = message!.Wire.Signatures[0];
            Signature signatureCopy = originalSignature.SignatureBytes.Memory.Span.ToSignature(CryptoTags.AlgorithmAgnosticSignature, BaseMemoryPool.Shared);

            using var unsignedHeaders = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.ClearJson, [cSigElement]);
            IReadOnlyDictionary<string, object>? unprotectedHeader = JAdESEtsiUJson.Encode(unsignedHeaders);

            var component = new JwsSignatureComponent(originalSignature.Protected, EmptyProtectedHeaderDictionary, signatureCopy, unprotectedHeader);
            using var newMessage = new JwsMessage(message.Wire.Payload, component, message.Wire.IsDetachedPayload);

            return JwsSerialization.Serialize(newMessage, JoseSerializationFormat.FlattenedJson, TestSetup.Base64UrlEncoder, JsonSerialize);
        }
    }


    //Never read by JwsSerialization -- JwsSignatureComponent.Protected is the wire truth for every serialization
    //form (never a re-derived encoding of the decoded model), mirroring JAdESSignatureAugmentation's own
    //identically-purposed private field.
    private static Dictionary<string, object> EmptyProtectedHeaderDictionary { get; } = [];


    private static JwtPartEncoder<Dictionary<string, object>> CounterSignerHeaderEncoder { get; } =
        static header => new TaggedMemory<byte>(JsonSerializer.SerializeToUtf8Bytes(header), Tag.Create(Purpose.Data));


    /// <summary>
    /// Builds the <c>arcTst</c> payload contribution matching <see cref="ConformantHeaders"/>'s own state
    /// (<c>sigD</c> absent, <c>b64</c> absent — JA-5.3.6.2.3-03's base64url arm): the SAME arm
    /// <c>JAdESSignatureValidation</c>'s own level-aware pass independently derives from those header facts, so
    /// generation and validation agree on what is being hashed.
    /// </summary>
    private static JAdESBase64UrlPayloadImprintSource Base64UrlPayloadSource(byte[] payloadBytes) =>
        new JAdESBase64UrlPayloadImprintSource(Encoding.ASCII.GetBytes(TestSetup.Base64UrlEncoder(payloadBytes)));


    /// <summary>
    /// Copies <paramref name="source"/>, replacing only its wire bytes, so a second augmentation runs over the
    /// first call's output under otherwise identical settings.
    /// </summary>
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


    /// <summary>
    /// Copies <paramref name="source"/>, replacing only its wire bytes, so a second archive time-stamp runs over
    /// the first call's output under otherwise identical settings.
    /// </summary>
    private static JAdESArchiveTimestampContext WithWireBytes(JAdESArchiveTimestampContext source, ReadOnlyMemory<byte> wireBytes) =>
        new()
        {
            WireBytes = wireBytes,
            MessageImprintAlgorithm = source.MessageImprintAlgorithm,
            PayloadSource = source.PayloadSource,
            TsaLegs = source.TsaLegs,
            GapFillValidationMaterial = source.GapFillValidationMaterial,
            SigningCertificate = source.SigningCertificate,
            ChainCompletenessAttested = source.ChainCompletenessAttested,
            CanonAlg = source.CanonAlg,
            Canonicalize = source.Canonicalize,
            AnyTimestampTokenCarriesEmbeddedValidationMaterial = source.AnyTimestampTokenCarriesEmbeddedValidationMaterial,
            TargetLevel = source.TargetLevel
        };


    /// <summary>
    /// A canonicalization stub sufficient to exercise the clear-JSON message-imprint path without depending on
    /// <c>Verifiable.Json</c>'s own canonicalization semantics (tested separately at
    /// <c>JAdESMessageImprintTests</c>) — deterministic by <see cref="JAdESUnsignedHeaderElement.Kind"/> for every
    /// non-<c>tstContainer</c> arm, mirroring <c>JAdESSignatureAugmentationTests</c>'s own. UNLIKE that stub, a
    /// <c>tstContainer</c>-typed arm's fingerprint additionally folds in its own token <c>val</c> bytes — this
    /// file's own tamper regressions (prefix-bound imprints) need a CONTENT-sensitive stub: a purely
    /// kind-keyed one would make tampering an earlier <c>arcTst</c>/<c>sigTst</c> instance's own token
    /// invisible to a LATER instance's prefix-bound canonicalization, defeating the very property under test.
    /// </summary>
    private static ValueTask<PooledMemory> StubCanonicalizeAsync(string canonAlg, JAdESUnsignedHeaderElement element, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] fingerprint = element switch
        {
            JAdESUnsignedHeaderElementSignatureTimestamp e => Fingerprint(e.Kind, e.Carriage),
            JAdESUnsignedHeaderElementArchiveTimestamp e => Fingerprint(e.Kind, e.Carriage),
            JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp e => Fingerprint(e.Kind, e.Carriage),
            JAdESUnsignedHeaderElementReferencesTimestamp e => Fingerprint(e.Kind, e.Carriage),
            _ => Encoding.UTF8.GetBytes(element.Kind)
        };

        return ValueTask.FromResult(PooledMemory.FromBytes(fingerprint, pool, CryptoTags.JAdESMessageImprintInput));

        static byte[] Fingerprint(string kind, JAdESUnsignedValue<AdESTimestampContainer> carriage)
        {
            if(carriage is not JAdESClearUnsignedValue<AdESTimestampContainer> clear)
            {
                return Encoding.UTF8.GetBytes(kind);
            }

            using var buffer = new System.IO.MemoryStream();
            buffer.Write(Encoding.UTF8.GetBytes(kind));
            for(int i = 0; i < clear.Value.TstTokens.Count; ++i)
            {
                buffer.Write(clear.Value.TstTokens[i].Val.Span);
            }

            return buffer.ToArray();
        }
    }


    //UnsafeRelaxedJsonEscaping (never '+'/'/' escaped as \uXXXX): the default JavaScriptEncoder escapes '+',
    //which would otherwise defeat TamperBase64EncodedBytesOnWire's own literal substring search over a
    //standard-base64 tstToken.val (JA-5.4.3.3-12) -- a decode-side non-issue either way (System.Text.Json's own
    //JsonElement.GetString()/GetBytesFromBase64() unescape \uXXXX transparently), so this is purely a test-side
    //wire-text-search convenience, not a conformance concession.
    private static JsonSerializerOptions RelaxedJsonOptions { get; } = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };


    private static byte[] JsonSerialize(object value) => JsonSerializer.SerializeToUtf8Bytes(value, RelaxedJsonOptions);


    /// <summary>A genuine in-process Time-Stamping Authority: a root CA, a TSA leaf certificate under it, and <see cref="MintingTimestampResponder"/> minting real RFC 3161 tokens over whatever message imprint a call sends — no network socket involved. Mirrors <c>JAdESSignatureAugmentationTests.TsaFixture</c>.</summary>
    private sealed class TsaFixture: IDisposable
    {
        private X509ChainTestRingNode Root { get; }
        private X509ChainTestRingNode AuthorityNode { get; }

        public MintingTimestampResponder Responder { get; }

        /// <summary>The Time-Stamping Authority node whose key signs every token <see cref="Responder"/> mints — the same node a directly-minted token (bypassing the responder) is signed by.</summary>
        public X509ChainTestRingNode Authority => AuthorityNode;


        private TsaFixture(X509ChainTestRingNode root, X509ChainTestRingNode authority, MintingTimestampResponder responder)
        {
            this.Root = root;
            this.AuthorityNode = authority;
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


        /// <summary>A DER-encoded X.509 certificate carrier (the root's own) suitable for <c>SigningCertificate</c>.</summary>
        public PkiCertificateMemory SignerCertificate() => OcspTestFixtures.ToCertificateCarrier(Root.Certificate);


        public void Dispose()
        {
            AuthorityNode.Dispose();
            Root.Dispose();
        }
    }
}
