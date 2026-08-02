using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Firewalled end-to-end flow tests for CB-AdES B-B creation and validation, through the SHIPPED
/// <see cref="CBAdESSignatureCreation"/>/<see cref="CBAdESSignatureValidation"/> composition over
/// <see cref="Cose"/> and the <see cref="CBAdESSignatureSerialization"/>/<see cref="CoseSerialization"/> CBOR
/// seams, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Firewall discipline.</strong> Every test's creation side runs inside its own nested block scope,
/// disposing every creation-side carrier (the signed-header-set aggregate, the <see cref="CoseSign1Message"/>)
/// before the block ends, and copies the wire bytes into an independent, GC-owned <c>byte[]</c>
/// (<c>wireCopy</c>) that alone crosses to the validation call below it. The verifier never touches a
/// creation-side object, model, or in-memory decoded fact — it reconstructs everything from
/// <c>wireCopy</c> and, for the detached flows, its OWN dereference delegate instance and context over the
/// shared object store (the published-location analogue clause 5.2.8.2.1 describes — never a decoded-state
/// backchannel).
/// </para>
/// <para>
/// <strong>Keys.</strong> Minted via <see cref="TestKeyMaterialProvider"/> (the exemplar's own pattern,
/// <c>Verifiable.Tests.Cose.CoseTests</c>), routed through the registry-resolved
/// <c>CBAdESSignatureCreation.SignAsync</c>/<c>CBAdESSignatureValidation.ValidateAsync</c> overloads so the
/// real <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> resolves the signing/
/// verification delegates from each key's <see cref="Tag"/>, exactly as a real caller would.
/// </para>
/// <para>
/// <strong>Algorithm agility (task instruction: "record which").</strong> <see cref="Cose.CoseTests"/> wires
/// three signature algorithms (ES256, ES384, ES512 — <c>SignAndVerifyWithExplicitDelegateSucceeds</c>,
/// <c>SignAndVerifyWithP384ExplicitDelegateSucceeds</c>, <c>SignAndVerifyWithP521ExplicitDelegateSucceeds</c>),
/// so flow 1 below carries a second-algorithm leg on ES384/P-384
/// (<see cref="AttachedBaselineFlowRoundTripsAndVerifiesWithEs384SecondAlgorithm"/>) in addition to its
/// primary ES256 leg — algorithm agility beyond this pair remains a standing arc concern, not exercised here.
/// </para>
/// <para>
/// <strong>New production seam, recorded loudly (deviation beyond this file, flagged for the review wave).</strong>
/// Flows 3 and 4 (detached, <c>sigD</c>) failed closed with a spurious <c>CB-5.2.8-03</c> rule violation the
/// first time this suite ran them: the only shipped envelope serializer,
/// <see cref="CoseSerialization.SerializeCoseSign1"/>, always writes the COSE Payload slot as a byte string —
/// it has no way to write the RFC 9052 <c>nil</c> sentinel clause 4.5 requires for a detached payload ("the
/// bytes of the detached COSE Payload ... if the COSE Payload is detached (the <c>payload</c> field is
/// absent)"), because <see cref="CoseSign1Message.Payload"/> is a plain <see cref="ReadOnlyMemory{T}"/> with no
/// "absent" arm of its own. An empty <c>bstr</c> parses back as PRESENT (<see cref="CBAdESSign1ParseResult.PayloadIsPresent"/>
/// <see langword="true"/>), so <see cref="CBAdESSignatureValidation"/> saw every genuinely detached
/// <c>sigD</c> signature this suite built as ATTACHED, and <see cref="CBAdESHeaderRules.Check"/> then rejected
/// it. This is the identical problem this codebase's own mdoc device-signed <c>COSE_Sign1</c> path already
/// solved with a private, file-scoped nil-payload writer — the fix here (<c>SerializeCBAdESSign1Delegate</c> +
/// <see cref="CBAdESSignatureSerialization.SerializeCBAdESSign1"/>) generalizes that same fix into a reusable
/// seam, since CB-AdES's creation/validation orchestrators are format-agnostic callers that cannot embed a
/// CBOR writer directly. Flows 1, 2, and 5 (attached) still use the pre-existing, unmodified
/// <see cref="CoseSerialization.SerializeCoseSign1"/>, per the task's explicit instruction for flow 1; flow 6
/// (wavecb S3 FX-M — detached, no <c>sigD</c>, clause 4.5's out-of-band-agreement arm,
/// <see cref="CBAdESDetachedExternalPayloadInput"/>) needs the identical wire-detach fix flows 3 and 4 needed,
/// since that arm also resolves <c>payloadIsDetached</c> <see langword="true"/> inside
/// <see cref="CBAdESSignatureCreation"/> — <see cref="AssertWirePayloadIsNil"/> is flow 6's own direct proof of
/// that fact, asserted on the wire bytes before either flow 6 test crosses the firewall.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESSignatureFlowTests
{
    /// <summary>The tag every test-side detached-object-store fixture buffer carries.</summary>
    private static Tag DetachedObjectContentTag { get; } = Tag.Create(Purpose.Data);

    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Flow 1 (attached B-B, ES256): builds a minimal conformant aggregate (<c>alg</c> + <c>iat</c> +
    /// <c>x5t</c>), creates through <see cref="CBAdESSignatureCreation"/>, serializes via the shipped
    /// <see cref="CoseSerialization.SerializeCoseSign1"/> delegate, passes ONLY the wire bytes to
    /// <see cref="CBAdESSignatureValidation"/>, and asserts the decoded facts (algorithm, <c>iat</c>, the
    /// <c>x5t</c> digest bytes) equal independently-kept expectations rather than the creation-side objects.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. Roslyn's " +
            "CA2000 analysis of 'new CBAdESProtectedHeaders(...)' cannot see across that async call boundary " +
            "into the transfer.")]
    [TestMethod]
    public async Task AttachedBaselineFlowRoundTripsAndVerifiesWithEs256()
    {
        const int expectedAlgorithm = WellKnownCoseAlgorithms.Es256;
        DateTimeOffset expectedIssuedAt = TestClock.CanonicalEpoch;
        byte[] payloadBytes = "CB-AdES flow 1 -- attached ES256 baseline payload"u8.ToArray();

        (CBAdESCertificateThumbprint thumbprint, byte[] expectedDigestBytes) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] wireCopy;
        {
            var headers = new CBAdESProtectedHeaders(expectedAlgorithm, new CBAdESCwtClaims(expectedIssuedAt), x5t: thumbprint);
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

        //Firewall: only wireCopy crosses from here on -- no creation-side object survives the block above.
        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid, "A genuine attached B-B CB-AdES signature must validate successfully.");
        Assert.IsFalse(validationResult.PayloadIsDetached, "The attached flow's payload must decode as not detached.");
        Assert.AreEqual(expectedAlgorithm, validationResult.Headers!.Algorithm);
        Assert.AreEqual(expectedIssuedAt, validationResult.Headers.CwtClaims!.IssuedAt);
        Assert.IsNotNull(validationResult.Headers.X5T);
        Assert.IsTrue(expectedDigestBytes.AsSpan().SequenceEqual(validationResult.Headers.X5T!.Digest.AsReadOnlySpan()));
    }


    /// <summary>
    /// Flow 1, second-algorithm leg (attached B-B, ES384/P-384) -- see the class remarks' algorithm-agility
    /// paragraph for why ES384 was chosen.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. Roslyn's " +
            "CA2000 analysis of 'new CBAdESProtectedHeaders(...)' cannot see across that async call boundary " +
            "into the transfer.")]
    [TestMethod]
    public async Task AttachedBaselineFlowRoundTripsAndVerifiesWithEs384SecondAlgorithm()
    {
        const int expectedAlgorithm = WellKnownCoseAlgorithms.Es384;
        DateTimeOffset expectedIssuedAt = TestClock.CanonicalEpoch;
        byte[] payloadBytes = "CB-AdES flow 1 -- attached ES384 second-algorithm payload"u8.ToArray();

        (CBAdESCertificateThumbprint thumbprint, byte[] expectedDigestBytes) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] wireCopy;
        {
            var headers = new CBAdESProtectedHeaders(expectedAlgorithm, new CBAdESCwtClaims(expectedIssuedAt), x5t: thumbprint);
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

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid, "A genuine ES384 attached B-B CB-AdES signature must validate successfully.");
        Assert.AreEqual(expectedAlgorithm, validationResult.Headers!.Algorithm);
        Assert.AreEqual(expectedIssuedAt, validationResult.Headers.CwtClaims!.IssuedAt);
        Assert.IsTrue(expectedDigestBytes.AsSpan().SequenceEqual(validationResult.Headers.X5T!.Digest.AsReadOnlySpan()));
    }


    /// <summary>
    /// Flow 1, negative leg: flipping one payload byte in the wire bytes (post-creation, pre-validation) must
    /// fail closed as <see cref="CBAdESSignatureInvalidFailure"/> -- the COSE signature value no longer
    /// verifies over the mutated payload.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. Roslyn's " +
            "CA2000 analysis of 'new CBAdESProtectedHeaders(...)' cannot see across that async call boundary " +
            "into the transfer.")]
    [TestMethod]
    public async Task AttachedBaselineFlowFailsClosedWhenPayloadByteIsFlipped()
    {
        byte[] payloadBytes = "CB-AdES flow 1 negative -- one byte of this payload gets flipped after signing"u8.ToArray();

        (CBAdESCertificateThumbprint thumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] wireCopy;
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
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        byte[] mutated = FlipFirstOccurrenceByte(wireCopy, payloadBytes);

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            mutated, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(validationResult.IsValid, "A signature over a mutated payload must not validate.");
        Assert.IsInstanceOfType<CBAdESSignatureInvalidFailure>(validationResult.Failure);
    }


    /// <summary>
    /// Flow 2 (attached B-B with <c>uHeaders</c>): the same attached aggregate as flow 1, plus a
    /// <see cref="CBAdESUnsignedHeaders"/> carrying exactly one legal-at-B-B element -- an unsigned
    /// <c>x5chain</c> element (label 33, CB-5.1.8-02), carried opaque per the S2
    /// <see cref="CBAdESUnsignedHeaderElementCertificateChain"/> model. Asserts the verifier sees exactly that
    /// one element back, byte-exact, from wire bytes alone.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. Roslyn's " +
            "CA2000 analysis of 'new CBAdESProtectedHeaders(...)' cannot see across that async call boundary " +
            "into the transfer.")]
    [TestMethod]
    public async Task AttachedFlowWithUnsignedCertificateChainElementRoundTripsExactlyOneUHeadersElement()
    {
        byte[] payloadBytes = "CB-AdES flow 2 -- attached ES256 with one uHeaders element"u8.ToArray();

        //The unsigned x5chain arm (label 33) carries a raw, already-CBOR-encoded RFC 9360 §2 COSE_X509 value
        //(bstr / [2*certs: bstr]) -- this must itself be one well-formed CBOR item, since the wire writer
        //splices it verbatim (WriteEncodedValue). A single-certificate arm is the bstr form: a placeholder
        //DER-shaped payload, wrapped as one CBOR byte string via an independent writer, never a raw byte
        //literal (which is not itself valid CBOR).
        byte[] placeholderCertificateDer = [0x30, 0x82, 0x01, 0x0A, 0x02, 0x01, 0x00, 0x30, 0x0D];
        var chainWriter = new CborWriter(CborConformanceMode.Canonical);
        chainWriter.WriteByteString(placeholderCertificateDer);
        byte[] expectedChainBytes = chainWriter.Encode();

        (CBAdESCertificateThumbprint thumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] wireCopy;
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            using var unsignedHeaders = new CBAdESUnsignedHeaders([new CBAdESUnsignedHeaderElementCertificateChain(expectedChainBytes)]);
            var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid, "An attached B-B signature carrying one legal uHeaders element must validate successfully.");
        Assert.IsNotNull(validationResult.UnsignedHeaders);
        Assert.HasCount(1, validationResult.UnsignedHeaders!);
        var chainElement = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementCertificateChain>(validationResult.UnsignedHeaders![0]);
        Assert.IsTrue(expectedChainBytes.AsSpan().SequenceEqual(chainElement.Value.Span));
    }


    /// <summary>
    /// Flow 3 (detached, <c>ObjectIdByURI</c>, CB-5.2.8.2.2): two objects live in a shared test-side store;
    /// creation signs their order-preserving concatenation (CB-5.2.8.2.2-05) and the wire payload is nil; the
    /// verifier uses its OWN <see cref="CBAdESDetachedObjectDereferenceDelegate"/> instance and its OWN
    /// <see cref="CBAdESDetachedObjectDereferenceContext"/> over the SAME store (the published-location
    /// analogue) to reconstruct the payload from wire bytes alone and validate successfully.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. Roslyn's " +
            "CA2000 analysis of 'new CBAdESProtectedHeaders(...)' cannot see across that async call boundary " +
            "into the transfer.")]
    [TestMethod]
    public async Task DetachedObjectIdByUriFlowReconstructsAndValidatesFromWireBytesOnly()
    {
        const string alphaReference = "https://example.org/objects/alpha";
        const string betaReference = "https://example.org/objects/beta";
        byte[] alphaContent = "CB-AdES flow 3 -- detached object alpha"u8.ToArray();
        byte[] betaContent = "CB-AdES flow 3 -- detached object beta, a little bit longer than alpha"u8.ToArray();
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
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var references = new[]
            {
                new CBAdESDetachedObjectReferenceInput(alphaReference, ContentType: null),
                new CBAdESDetachedObjectReferenceInput(betaReference, ContentType: null)
            };
            var payloadInput = new CBAdESDetachedSigDPayloadInput(CBAdESDetachedMechanisms.ObjectIdByURI, references, HashAlgorithm: null);
            var creationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);
            CBAdESDetachedObjectDereferenceDelegate creationDereference = DereferenceFromObjectStore;

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

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: verificationDereference, dereferenceContext: verificationContext, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid, "A genuine ObjectIdByURI detached signature must validate once the verifier can dereference every object.");
        Assert.IsTrue(validationResult.PayloadIsDetached, "The ObjectIdByURI flow's payload must decode as detached (the wire nil sentinel).");
    }


    /// <summary>
    /// Flow 3, negative leg: the verifier's OWN store is missing one referenced object -- reconstruction must
    /// fail closed as <see cref="CBAdESDetachedObjectUnresolvableFailure"/>, never a thrown exception (R-5).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. Roslyn's " +
            "CA2000 analysis of 'new CBAdESProtectedHeaders(...)' cannot see across that async call boundary " +
            "into the transfer.")]
    [TestMethod]
    public async Task DetachedObjectIdByUriFlowFailsClosedWhenVerifierStoreIsMissingAnObject()
    {
        const string alphaReference = "https://example.org/objects/alpha-missing-case";
        const string betaReference = "https://example.org/objects/beta-missing-case";
        byte[] alphaContent = "CB-AdES flow 3 negative -- object alpha, present at creation"u8.ToArray();
        byte[] betaContent = "CB-AdES flow 3 negative -- object beta, MISSING from the verifier's store"u8.ToArray();
        var creationStore = new Dictionary<string, byte[]>(StringComparer.Ordinal)
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
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var references = new[]
            {
                new CBAdESDetachedObjectReferenceInput(alphaReference, ContentType: null),
                new CBAdESDetachedObjectReferenceInput(betaReference, ContentType: null)
            };
            var payloadInput = new CBAdESDetachedSigDPayloadInput(CBAdESDetachedMechanisms.ObjectIdByURI, references, HashAlgorithm: null);
            var creationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: creationStore);
            CBAdESDetachedObjectDereferenceDelegate creationDereference = DereferenceFromObjectStore;

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

        //The verifier's own store lacks 'betaReference' entirely -- simulating an object never published, or
        //no longer reachable, at the published location.
        var verifierStore = new Dictionary<string, byte[]>(StringComparer.Ordinal) { [alphaReference] = alphaContent };
        var verificationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: verifierStore);
        CBAdESDetachedObjectDereferenceDelegate verificationDereference = DereferenceFromObjectStore;

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: verificationDereference, dereferenceContext: verificationContext, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(validationResult.IsValid, "Validation must fail closed when the verifier cannot dereference every referenced object.");
        Assert.IsInstanceOfType<CBAdESDetachedObjectUnresolvableFailure>(validationResult.Failure);
    }


    /// <summary>
    /// Flow 4 (detached, <c>ObjectIdByURIHash</c>, CB-5.2.8.2.3): an empty-payload signature over two
    /// referenced objects, each digested by creation itself (S3 coordinator ruling (4)); the verifier
    /// independently re-derives and checks every <c>hashV</c> against its OWN store, through the registered
    /// digest delegate, from wire bytes alone.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. Roslyn's " +
            "CA2000 analysis of 'new CBAdESProtectedHeaders(...)' cannot see across that async call boundary " +
            "into the transfer.")]
    [TestMethod]
    public async Task DetachedObjectIdByUriHashFlowVerifiesEveryDigestFromWireBytesOnly()
    {
        const string alphaReference = "https://example.org/objects/hash-alpha";
        const string betaReference = "https://example.org/objects/hash-beta";
        byte[] alphaContent = "CB-AdES flow 4 -- hashed object alpha"u8.ToArray();
        byte[] betaContent = "CB-AdES flow 4 -- hashed object beta"u8.ToArray();
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
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var references = new[]
            {
                new CBAdESDetachedObjectReferenceInput(alphaReference, ContentType: null),
                new CBAdESDetachedObjectReferenceInput(betaReference, ContentType: null)
            };
            var hashAlgorithm = new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256);
            var payloadInput = new CBAdESDetachedSigDPayloadInput(CBAdESDetachedMechanisms.ObjectIdByURIHash, references, hashAlgorithm);
            var creationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);
            CBAdESDetachedObjectDereferenceDelegate creationDereference = DereferenceFromObjectStore;

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

        var verificationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);
        CBAdESDetachedObjectDereferenceDelegate verificationDereference = DereferenceFromObjectStore;

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: verificationDereference, dereferenceContext: verificationContext, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid, "A genuine ObjectIdByURIHash detached signature must validate once every hashV re-verifies.");
        Assert.IsTrue(validationResult.PayloadIsDetached);
    }


    /// <summary>
    /// Flow 4, negative leg: flipping one byte of one referenced object, ON THE VERIFIER'S SIDE ONLY, must fail
    /// closed as <see cref="CBAdESDetachedObjectDigestMismatchFailure"/> -- the creation-side signature and
    /// signed <c>hashV</c> entries are untouched; only the object the verifier independently re-fetches and
    /// re-digests has changed.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. Roslyn's " +
            "CA2000 analysis of 'new CBAdESProtectedHeaders(...)' cannot see across that async call boundary " +
            "into the transfer.")]
    [TestMethod]
    public async Task DetachedObjectIdByUriHashFlowFailsClosedWhenVerifierStoreObjectByteIsFlipped()
    {
        const string alphaReference = "https://example.org/objects/hash-tamper-alpha";
        const string betaReference = "https://example.org/objects/hash-tamper-beta";
        byte[] alphaContent = "CB-AdES flow 4 negative -- object alpha, untouched"u8.ToArray();
        byte[] betaContent = "CB-AdES flow 4 negative -- object beta, tampered on the verifier side only"u8.ToArray();
        var creationStore = new Dictionary<string, byte[]>(StringComparer.Ordinal)
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
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var references = new[]
            {
                new CBAdESDetachedObjectReferenceInput(alphaReference, ContentType: null),
                new CBAdESDetachedObjectReferenceInput(betaReference, ContentType: null)
            };
            var hashAlgorithm = new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256);
            var payloadInput = new CBAdESDetachedSigDPayloadInput(CBAdESDetachedMechanisms.ObjectIdByURIHash, references, hashAlgorithm);
            var creationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: creationStore);
            CBAdESDetachedObjectDereferenceDelegate creationDereference = DereferenceFromObjectStore;

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

        //The verifier's own store carries a bit-flipped copy of 'betaReference' -- the creation-side signature
        //and its signed hashV entries never see this mutation.
        byte[] tamperedBetaContent = (byte[])betaContent.Clone();
        tamperedBetaContent[0] ^= 0xFF;
        var verifierStore = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [alphaReference] = alphaContent,
            [betaReference] = tamperedBetaContent
        };
        var verificationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: verifierStore);
        CBAdESDetachedObjectDereferenceDelegate verificationDereference = DereferenceFromObjectStore;

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: verificationDereference, dereferenceContext: verificationContext, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(validationResult.IsValid, "Validation must fail closed when a re-digested object no longer matches its signed hashV.");
        Assert.IsInstanceOfType<CBAdESDetachedObjectDigestMismatchFailure>(validationResult.Failure);
    }


    /// <summary>
    /// Flow 5 (attached B-B, full-house aggregate, wavecb S3 FX-L): every clause 5.1/5.2 signed header this
    /// stage models that flows 1/2 leave unpopulated -- <c>kid</c>, <c>x5u</c>, <c>x5t</c> (the tri-way),
    /// <c>content type</c>, <c>srCms</c>, <c>sigPl</c>, <c>srAts</c>, and <c>adoTst</c> -- all present on the
    /// SAME message, created, serialized, wire-copied, and validated, with each decoded member asserted against
    /// an independently-kept expectation, never the creation-side objects (the class remarks' firewall
    /// discipline). <c>content type</c> joins this flow per the wavecb S3 FX-P note: it is legal on an attached,
    /// no-<c>sigD</c> message (CB-5.1.3-03 excludes only the <c>sigD</c> pairing), so this is the one flow that
    /// can wire-exercise it alongside every other clause 5.1/5.2 member without conflicting with any B-B rule.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. The nested " +
            "adoTst (CBAdESPayloadTimestamp/CBAdESTimestampContainer) construction is a constructor argument " +
            "passed straight into headers's own construction, so its ownership passes to headers and then " +
            "onward with it; Roslyn's CA2000 analysis flags each nested 'new' expression independently of the " +
            "enclosing aggregate that actually owns and disposes them.")]
    [TestMethod]
    public async Task FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader()
    {
        byte[] payloadBytes = "CB-AdES flow 5 -- full-house attached ES256 payload"u8.ToArray();
        byte[] expectedKeyId = [0x30, 0x05, 0x02, 0x01, 0x2A, 0x0C, 0x00]; // An opaque kid -- CB-5.1.4-03's DER-IssuerSerial content shape is a SHOULD, left untested here per the flow's own remarks.
        var expectedX5u = new Uri("https://example.org/flow5/signing-certificate.cer");
        var expectedCommitmentId = new Uri("urn:cbades:flow5:commitment:proof-of-origin");
        const string expectedLocality = "Tallinn";
        const string expectedCountry = "EE";
        const string expectedClaimedMediaType = "application/vnd.example.flow5-claimed+json";
        const string expectedContentType = "application/octet-stream";
        byte[] timestampTokenDerBytes =
        [
            0x30, 0x09, // SEQUENCE, length 9.
            0x02, 0x01, 0x01, // INTEGER 1 (a placeholder version field).
            0x0C, 0x04, 0x66, 0x6C, 0x6F, 0x77 // UTF8String "flow" (4 bytes).
        ];

        (CBAdESCertificateThumbprint thumbprint, byte[] expectedDigestBytes) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //CBAdESSignerAttributeOpaqueQualifyingValue.EncodedValue must itself be one well-formed CBOR data item
        //(D3, mirroring the S1 exemplar's TryParseSignerAttributesPreservesOpaqueQualifyingValueBytesExactly
        //fixture) -- never a raw byte literal, which is not itself valid CBOR.
        var qualifyingValueWriter = new CborWriter(CborConformanceMode.Canonical);
        qualifyingValueWriter.WriteTextString("flow5-claimed-value");
        byte[] claimedQualifyingValueBytes = qualifyingValueWriter.Encode();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] wireCopy;
        {
            var srCms = new CBAdESSignerCommitments
            {
                Commitments = [new CBAdESCommitment(new CBAdESObjectIdentifier(expectedCommitmentId))]
            };
            var sigPl = new CBAdESSignatureProductionPlace { AddressLocality = expectedLocality, AddressCountry = expectedCountry };
            var srAts = new CBAdESSignerAttributes(claimed:
            [
                new CBAdESSignerAttributeNotCertifiedItem
                {
                    MediaType = expectedClaimedMediaType,
                    QualifyingValues = [new CBAdESSignerAttributeOpaqueQualifyingValue(CBAdESSignerAttributeOpaqueQualifyingValueKind.Unspecified, claimedQualifyingValueBytes)]
                }
            ]);
            var adoTst = new CBAdESPayloadTimestamp(new CBAdESTimestampContainer { TstTokens = [new CBAdESTimestampToken { Val = timestampTokenDerBytes }] });

            var headers = new CBAdESProtectedHeaders(
                WellKnownCoseAlgorithms.Es256,
                new CBAdESCwtClaims(TestClock.CanonicalEpoch),
                contentType: new CBAdESContentTypeText(expectedContentType),
                keyId: expectedKeyId,
                x5u: expectedX5u,
                x5t: thumbprint,
                signerCommitments: srCms,
                signatureProductionPlace: sigPl,
                signerAttributes: srAts,
                payloadTimestamps: adoTst);
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

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid, "A genuine full-house attached B-B CB-AdES signature must validate successfully.");
        Assert.IsFalse(validationResult.PayloadIsDetached);
        CBAdESProtectedHeaders decoded = validationResult.Headers!;

        Assert.IsNotNull(decoded.KeyId);
        Assert.IsTrue(expectedKeyId.AsSpan().SequenceEqual(decoded.KeyId!.Value.Span));

        Assert.AreEqual(expectedX5u, decoded.X5U);

        Assert.IsNotNull(decoded.X5T);
        Assert.IsTrue(expectedDigestBytes.AsSpan().SequenceEqual(decoded.X5T!.Digest.AsReadOnlySpan()));

        Assert.IsNotNull(decoded.ContentType);
        var decodedContentType = Assert.IsInstanceOfType<CBAdESContentTypeText>(decoded.ContentType);
        Assert.AreEqual(expectedContentType, decodedContentType.Value);

        Assert.IsNotNull(decoded.SignerCommitments);
        Assert.HasCount(1, decoded.SignerCommitments!.Commitments);
        Assert.AreEqual(expectedCommitmentId, decoded.SignerCommitments.Commitments[0].CommitmentId.Id);

        Assert.IsNotNull(decoded.SignatureProductionPlace);
        Assert.AreEqual(expectedLocality, decoded.SignatureProductionPlace!.AddressLocality);
        Assert.AreEqual(expectedCountry, decoded.SignatureProductionPlace.AddressCountry);

        Assert.IsNotNull(decoded.SignerAttributes);
        Assert.IsNotNull(decoded.SignerAttributes!.Claimed);
        Assert.HasCount(1, decoded.SignerAttributes.Claimed!);
        Assert.AreEqual(expectedClaimedMediaType, decoded.SignerAttributes.Claimed[0].MediaType);

        Assert.IsNotNull(decoded.PayloadTimestamps);
        Assert.HasCount(1, decoded.PayloadTimestamps!.TimestampContainer.TstTokens);
        Assert.IsTrue(timestampTokenDerBytes.AsSpan().SequenceEqual(decoded.PayloadTimestamps.TimestampContainer.TstTokens[0].Val.Span));
    }


    /// <summary>
    /// Flow 6, positive leg (detached, no <c>sigD</c>, clause 4.5's out-of-band-agreement arm,
    /// <see cref="CBAdESDetachedExternalPayloadInput"/>, wavecb S3 FX-M): the wire payload is the RFC 9052
    /// clause 4.5 <c>nil</c> sentinel -- asserted directly on the freshly serialized bytes, INSIDE the creation
    /// block, before any firewall crossing (see <see cref="AssertWirePayloadIsNil"/>) -- and the verifier
    /// supplies the same bytes as its own out-of-band agreement (<c>externalDetachedPayload</c>, never a
    /// creation-side object: this arm's whole premise is that the verifier already holds these bytes through a
    /// channel this library never carries) and validates successfully.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. Roslyn's " +
            "CA2000 analysis of 'new CBAdESProtectedHeaders(...)' cannot see across that async call boundary " +
            "into the transfer.")]
    [TestMethod]
    public async Task DetachedExternalPayloadFlowRoundTripsAndVerifies()
    {
        byte[] payloadBytes = "CB-AdES flow 6 -- detached, out-of-band-agreed payload"u8.ToArray();

        (CBAdESCertificateThumbprint thumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] wireCopy;
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var payloadInput = new CBAdESDetachedExternalPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CBAdESSignatureSerialization.SerializeCBAdESSign1(
                creationResult.Message, payloadIsDetached: true, BaseMemoryPool.Shared);

            AssertWirePayloadIsNil(wireBytes.AsReadOnlySpan());

            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: payloadBytes, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validationResult.IsValid, "A genuine detached-external B-B CB-AdES signature must validate once the verifier supplies the agreed out-of-band payload.");
        Assert.IsTrue(validationResult.PayloadIsDetached);
    }


    /// <summary>
    /// Flow 6, negative leg (wavecb S3 FX-M): the same detached-external message, but the verifier supplies no
    /// out-of-band payload at all -- validation must fail closed as
    /// <see cref="CBAdESDetachedObjectUnresolvableFailure"/> (clause 5.2.6's closing paragraph), never a thrown
    /// exception (R-5).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which this test disposes via 'using creationResult'. Roslyn's " +
            "CA2000 analysis of 'new CBAdESProtectedHeaders(...)' cannot see across that async call boundary " +
            "into the transfer.")]
    [TestMethod]
    public async Task DetachedExternalPayloadFlowFailsClosedWhenNoOutOfBandPayloadSupplied()
    {
        byte[] payloadBytes = "CB-AdES flow 6 negative -- payload the verifier never receives"u8.ToArray();

        (CBAdESCertificateThumbprint thumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        byte[] wireCopy;
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var payloadInput = new CBAdESDetachedExternalPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CBAdESSignatureSerialization.SerializeCBAdESSign1(
                creationResult.Message, payloadIsDetached: true, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESValidationResult validationResult = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure, publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(validationResult.IsValid, "Validation must fail closed when the payload is detached, sigD is absent, and no out-of-band payload was supplied.");
        var failure = Assert.IsInstanceOfType<CBAdESDetachedObjectUnresolvableFailure>(validationResult.Failure);
        Assert.IsNull(failure.Reference);
        Assert.Contains("clause 5.2.6", failure.Reason, StringComparison.Ordinal);
    }


    /// <summary>
    /// Builds a signing certificate's <c>x5t</c> thumbprint fixture (SHA-256, via the registered digest
    /// delegate seam -- never a hand-rolled hash) together with an independently-kept copy of the expected
    /// digest bytes, so callers can assert a validated result's decoded <c>x5t</c> digest against the copy
    /// rather than the creation-side <see cref="CBAdESCertificateThumbprint"/> object.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The thumbprint (ownership transfers to whatever aggregate it is supplied to) and the independent digest-bytes copy.</returns>
    private static async ValueTask<(CBAdESCertificateThumbprint Thumbprint, byte[] ExpectedDigestBytes)> CreateSigningCertificateThumbprintAsync(
        CancellationToken cancellationToken)
    {
        byte[] certificateBytes = "CB-AdES flow test -- placeholder signing certificate bytes"u8.ToArray();
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(certificateBytes), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        byte[] expectedDigestBytes = digest.AsReadOnlySpan().ToArray();
        var thumbprint = new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);

        return (thumbprint, expectedDigestBytes);
    }


    /// <summary>
    /// The test-side detached-object dereference delegate every flow 3/4 test wires -- explicit per-call state
    /// only (no closure capture): resolves <paramref name="context"/>'s <see cref="CBAdESDetachedObjectDereferenceContext.State"/>
    /// as an <see cref="IReadOnlyDictionary{TKey, TValue}"/> object store (the published-location analogue) and
    /// looks up <paramref name="uriReference"/> in it.
    /// </summary>
    /// <param name="uriReference">The URI-reference to dereference (one <c>pars</c> element).</param>
    /// <param name="context">The per-call caller state; its <see cref="CBAdESDetachedObjectDereferenceContext.State"/> is the object store.</param>
    /// <param name="pool">Memory pool the fetched content is rented from.</param>
    /// <param name="cancellationToken">Cancellation token (unused; the in-memory store never awaits).</param>
    /// <returns>The dereferenced content, or a failure signal when the store carries no entry for <paramref name="uriReference"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the returned PooledMemory transfers to the CBAdESDetachedObjectDereferenceSuccess result, which the caller (CBAdESSignatureCreation/CBAdESSignatureValidation) disposes.")]
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
    /// <paramref name="needle"/> flipped -- the mutation helper flow 1's negative leg uses to corrupt exactly
    /// the attached payload region of already-signed wire bytes, without disturbing any other field.
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


    /// <summary>
    /// Asserts that <paramref name="wireBytes"/>'s COSE Payload array slot (the third element of the
    /// <c>COSE_Sign1</c> 4-tuple) is the RFC 9052 clause 4.5 <c>nil</c> sentinel -- read independently via a
    /// fresh <see cref="CborReader"/> walk rather than through <see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/>
    /// (the SUT the validation call already exercises further down each flow 6 test), proving
    /// <see cref="CBAdESSignatureSerialization.SerializeCBAdESSign1"/> genuinely wrote the wire-detach sentinel
    /// the class remarks' "New production seam" paragraph documents, before the bytes cross the firewall.
    /// </summary>
    /// <param name="wireBytes">The freshly serialized <c>COSE_Sign1</c> wire bytes.</param>
    private static void AssertWirePayloadIsNil(ReadOnlySpan<byte> wireBytes)
    {
        var reader = new CborReader(wireBytes.ToArray(), CborConformanceMode.Canonical);
        if(reader.PeekState() == CborReaderState.Tag)
        {
            reader.ReadTag();
        }

        reader.ReadStartArray();
        reader.SkipValue(); // body_protected bstr.
        reader.SkipValue(); // the unprotected headers map.
        Assert.AreEqual(CborReaderState.Null, reader.PeekState(),
            "A genuinely detached COSE Payload must serialize the RFC 9052 clause 4.5 nil sentinel, not an empty byte string.");
    }
}
