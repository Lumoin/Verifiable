using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Veritas.Cbor;
using System.Linq;
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
/// CB-AdES over <c>COSE_Sign</c> (multi-signer) end to end — creation
/// (<see cref="CBAdESSignatureCreation.SignCoseSignAsync"/>) through level-aware validation
/// (<see cref="CBAdESSignatureValidation.ValidateCoseSignAsync"/>), and the <c>arcTst</c> validation-mode
/// message-imprint builder's own COSE_Sign structure-context threading (clause 5.3.5.3 steps 2/4/10) over a
/// genuinely parsed <c>COSE_Sign</c> message.
/// </summary>
/// <remarks>
/// <strong>Recorded scope.</strong> This landing covers an attached payload, an empty body layer, and B-B/
/// level-rule structural conformance per signer — see <see cref="CBAdESCoseSignValidationResult"/>'s own
/// remarks for the full boundary. The <c>COSE_Sign1</c> paths (<see cref="CBAdESSignatureFlowTests"/> and
/// siblings) are untouched by any change in this file.
/// </remarks>
[TestClass]
internal sealed class CBAdESCoseSignSignatureFlowTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous test observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Two independently-keyed signers, each with their own conformant B-B header set, sign the SAME attached
    /// payload over a genuine <c>COSE_Sign</c> structure; the resulting wire bytes validate cleanly at B-B with
    /// both signers reported valid and cryptographically verified — an end-to-end creation-through-validation
    /// round trip over the real substrate, never a hand-built fixture.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-4.2-01, CB-4.3-02, CB-5.1.2-06, CB-5.1.7-04, CB-5.1.9-07.
    /// </remarks>
    [TestMethod]
    public async Task SignCoseSignAsyncThenValidateCoseSignAsyncSucceedsForTwoConformantSigners()
    {
        byte[] payloadBytes = "CB-AdES COSE_Sign end-to-end payload"u8.ToArray();

        var firstKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory firstPublicKey = firstKeyMaterial.PublicKey;
        using PrivateKeyMemory firstPrivateKey = firstKeyMaterial.PrivateKey;

        var secondKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory secondPublicKey = secondKeyMaterial.PublicKey;
        using PrivateKeyMemory secondPrivateKey = secondKeyMaterial.PrivateKey;

        CBAdESProtectedHeaders firstHeaders = await BuildConformantHeadersAsync("first signer", TestContext.CancellationToken).ConfigureAwait(false);
        CBAdESProtectedHeaders secondHeaders = await BuildConformantHeadersAsync("second signer", TestContext.CancellationToken).ConfigureAwait(false);

        var signers = new List<CBAdESCoseSignSignerInput>
        {
            new(firstHeaders, unsignedHeaders: null, firstPrivateKey),
            new(secondHeaders, unsignedHeaders: null, secondPrivateKey)
        };

        byte[] wireCopy;
        using(CBAdESCoseSignSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignCoseSignAsync(
            new CBAdESAttachedPayloadInput(payloadBytes), signers,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.HasCount(2, creationResult.Message.Signatures);

            using EncodedCoseSign wireBytes = CoseSerialization.SerializeCoseSign(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESCoseSignValidationResult validation = await CBAdESSignatureValidation.ValidateCoseSignAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign, CBAdESSignatureSerialization.DecodeCBAdESProtectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, [firstPublicKey, secondPublicKey], AdESBaselineLevel.BB,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(validation.IsMalformed);
        Assert.IsTrue(validation.IsValid, "Two genuinely-signed, B-B-conformant COSE_Sign signers must validate cleanly at the declared level B-B.");
        Assert.HasCount(2, validation.Signers);
        Assert.IsTrue(validation.Signers[0].IsValid);
        Assert.IsTrue(validation.Signers[0].SignatureVerified);
        Assert.IsTrue(validation.Signers[1].IsValid);
        Assert.IsTrue(validation.Signers[1].SignatureVerified);
    }


    /// <summary>
    /// The SAME two-signer fixture, but the SECOND signer's own headers omit <c>CwtClaims</c> (CB-6.3-10) --
    /// the FIRST signer, whose own headers are unaffected, must still validate cleanly: the B-B rule body runs
    /// independently per signer, never contaminating a sibling's own outcome.
    /// </summary>
    /// <remarks>
    /// The wire bytes are composed through the LOWER-LEVEL <see cref="CoseSign"/> substrate directly, never
    /// <see cref="CBAdESSignatureCreation.SignCoseSignAsync"/> -- that creation path itself correctly REFUSES
    /// to produce a message with any non-conformant signer (its own PASS-1-before-any-signing gate,
    /// <see cref="CBAdESHeaderRules.EnsureConformant"/>), so a non-conformant fixture must simulate wire bytes
    /// from elsewhere (a foreign producer) to isolate VALIDATION's own per-signer behavior specifically.
    /// </remarks>
    [TestMethod]
    public async Task ValidateCoseSignAsyncIsolatesAConformanceViolationToItsOwnSigner()
    {
        byte[] payloadBytes = "CB-AdES COSE_Sign isolation payload"u8.ToArray();

        var firstKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory firstPublicKey = firstKeyMaterial.PublicKey;
        using PrivateKeyMemory firstPrivateKey = firstKeyMaterial.PrivateKey;

        var secondKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory secondPublicKey = secondKeyMaterial.PublicKey;
        using PrivateKeyMemory secondPrivateKey = secondKeyMaterial.PrivateKey;

        using CBAdESProtectedHeaders firstHeaders = await BuildConformantHeadersAsync("conformant signer", TestContext.CancellationToken).ConfigureAwait(false);

        (AdESCertificateThumbprint thumbprint, byte[] _) = await CreateSigningCertificateThumbprintAsync("non-conformant signer", TestContext.CancellationToken).ConfigureAwait(false);
        using var secondHeaders = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, cwtClaims: null, x5t: thumbprint); //CB-6.3-10: CwtClaims omitted.

        EncodedCoseProtectedHeader bodyProtectedHeader = EncodedCoseProtectedHeader.FromBytes(ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
        EncodedCoseProtectedHeader firstEncodedHeader = CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader(firstHeaders, BaseMemoryPool.Shared);
        EncodedCoseProtectedHeader secondEncodedHeader = CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader(secondHeaders, BaseMemoryPool.Shared);

        var signers = new List<CoseSignerInput>
        {
            new(firstEncodedHeader, null, firstPrivateKey),
            new(secondEncodedHeader, null, secondPrivateKey)
        };

        byte[] wireCopy;
        using(CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, bodyUnprotectedHeader: null, payloadBytes, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            using EncodedCoseSign wireBytes = CoseSerialization.SerializeCoseSign(message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESCoseSignValidationResult validation = await CBAdESSignatureValidation.ValidateCoseSignAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign, CBAdESSignatureSerialization.DecodeCBAdESProtectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, [firstPublicKey, secondPublicKey], AdESBaselineLevel.BB,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(validation.IsValid, "One non-conformant signer must fail the overall result.");
        Assert.HasCount(2, validation.Signers);
        Assert.IsTrue(validation.Signers[0].IsValid, "The FIRST, conformant signer must remain valid -- the rule body runs independently per signer.");
        Assert.IsFalse(validation.Signers[1].IsValid);
        Assert.HasCount(1, validation.Signers[1].Violations);
        Assert.IsInstanceOfType<CBAdESCwtClaimsMissingViolation>(validation.Signers[1].Violations[0]);
    }


    /// <summary>
    /// The SAME conformant two-signer fixture, but the caller supplies the WRONG public key for the second
    /// signer -- that signer alone is reported <see cref="CBAdESCoseSignSignerValidationResult.SignatureVerified"/>
    /// <see langword="false"/>, the first (correctly keyed) signer remains valid.
    /// </summary>
    [TestMethod]
    public async Task ValidateCoseSignAsyncReportsSignatureInvalidForTheWrongPublicKeyOnOneSigner()
    {
        byte[] payloadBytes = "CB-AdES COSE_Sign wrong-key payload"u8.ToArray();

        var firstKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory firstPublicKey = firstKeyMaterial.PublicKey;
        using PrivateKeyMemory firstPrivateKey = firstKeyMaterial.PrivateKey;

        var secondKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PrivateKeyMemory secondPrivateKey = secondKeyMaterial.PrivateKey;
        secondKeyMaterial.PublicKey.Dispose();

        var wrongKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongPublicKey = wrongKeyMaterial.PublicKey;
        wrongKeyMaterial.PrivateKey.Dispose();

        CBAdESProtectedHeaders firstHeaders = await BuildConformantHeadersAsync("first signer", TestContext.CancellationToken).ConfigureAwait(false);
        CBAdESProtectedHeaders secondHeaders = await BuildConformantHeadersAsync("second signer", TestContext.CancellationToken).ConfigureAwait(false);

        var signers = new List<CBAdESCoseSignSignerInput>
        {
            new(firstHeaders, unsignedHeaders: null, firstPrivateKey),
            new(secondHeaders, unsignedHeaders: null, secondPrivateKey)
        };

        byte[] wireCopy;
        using(CBAdESCoseSignSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignCoseSignAsync(
            new CBAdESAttachedPayloadInput(payloadBytes), signers,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            using EncodedCoseSign wireBytes = CoseSerialization.SerializeCoseSign(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESCoseSignValidationResult validation = await CBAdESSignatureValidation.ValidateCoseSignAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign, CBAdESSignatureSerialization.DecodeCBAdESProtectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, [firstPublicKey, wrongPublicKey], AdESBaselineLevel.BB,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(validation.IsValid);
        Assert.IsTrue(validation.Signers[0].IsValid);
        Assert.IsTrue(validation.Signers[0].SignatureVerified);
        Assert.IsFalse(validation.Signers[1].IsValid);
        Assert.IsFalse(validation.Signers[1].SignatureVerified);
    }


    /// <summary>
    /// <c>arcTst</c> generation (clause 5.3.5.3) steps 2/4/10, exercised over
    /// a GENUINELY PARSED <c>COSE_Sign</c> signer -- not the hand-built <see cref="CBAdESArchiveTimestampImprintContext"/>
    /// fixtures <c>CBAdESMessageImprintTests</c> already covers at the byte-assembly level. The wire bytes are
    /// assembled directly with a fresh <see cref="CborWriter"/> (an independent oracle, mirroring
    /// <c>CBAdESSignParseResultTests</c>'s own convention), parsed through <see cref="CBAdESSignatureSerialization.ParseCBAdESSign"/>,
    /// and the signer's own captured raw protected header/<c>uHeaders</c> bytes are threaded straight into
    /// <see cref="CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput"/>
    /// with <see cref="CBAdESImprintCoseSignStructureContext.Instance"/> -- proving the VALIDATION-mode arm of
    /// the message-imprint threading accepts real, wire-sourced COSE_Sign material,
    /// end to end, and reproduces an independently hand-assembled expected byte sequence exactly.
    /// </summary>
    [TestMethod]
    public void TryBuildArchiveTimestampValidationMessageImprintInputAcceptsAGenuinelyParsedCoseSignSigner()
    {
        byte[] bodyProtectedHeaderBytes = [0xA1, 0x01, 0x26]; //{1: -7} -- an arbitrary, well-formed protected header map.
        byte[] payloadBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] signerProtectedHeaderBytes = [0xA1, 0x01, 0x26];
        byte[] signerSignatureBytes = [0x03, 0x04, 0x05];
        byte[] precedingElement = EncodeUnknownUHeaderInstance(9001);
        byte[] followingElement = EncodeUnknownUHeaderInstance(9002);

        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(4);
        writer.WriteByteString(bodyProtectedHeaderBytes);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(payloadBytes);
        writer.WriteStartArray(1);
        writer.WriteStartArray(3);
        writer.WriteByteString(signerProtectedHeaderBytes);
        writer.WriteStartMap(1);
        writer.WriteInt32(CBAdESHeaderParameters.UHeaders);
        writer.WriteStartArray(2);
        writer.WriteByteString(precedingElement);
        writer.WriteByteString(followingElement);
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteByteString(signerSignatureBytes);
        writer.WriteEndArray();
        writer.WriteEndArray();
        writer.WriteEndArray();

        using CBAdESSignParseResult parsed = CBAdESSignatureSerialization.ParseCBAdESSign(writerBuffer.WrittenSpan.ToArray(), BaseMemoryPool.Shared);
        Assert.IsTrue(parsed.IsSuccess);
        Assert.HasCount(1, parsed.Signers!);

        CBAdESSignerParseResult signer = parsed.Signers![0];
        Assert.IsNotNull(signer.RawUnsignedHeaders);

        byte[] externallySuppliedData = [0xEE];

        bool built = CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput(
            CBAdESImprintCoseSignStructureContext.Instance,
            parsed.RawBodyProtectedHeader!.AsReadOnlyMemory(),
            signer.RawProtectedHeader.AsReadOnlyMemory(),
            externallySuppliedData,
            new CBAdESAttachedPayloadTimestampImprintSource(parsed.Payload),
            countersignatureOtherFields: null,
            signer.Signature.AsReadOnlyMemory(),
            signer.RawUnsignedHeaders!.AsReadOnlyMemory(),
            arcTstElementIndex: 1, //only the FIRST (preceding) element contributes -- the validation-time prefix bound.
            BaseMemoryPool.Shared,
            out PooledMemory? result);

        Assert.IsTrue(built, "The validation-mode arcTst message-imprint input must build over a genuinely parsed COSE_Sign signer's own raw protected header (steps 2/4/10 threading).");

        using(result)
        {
            var oracleWriterBuffer = new ArrayBufferWriter<byte>();
            var oracleWriter = new CborWriter(oracleWriterBuffer, CborOptions.RfcCanonical);
            oracleWriter.WriteStartArray(7);
            oracleWriter.WriteTextString("Signature"); //step 2: COSE_Sign context text.
            oracleWriter.WriteByteString(bodyProtectedHeaderBytes); //step 3.
            oracleWriter.WriteByteString(signerProtectedHeaderBytes); //step 4: the GENUINELY PARSED signer's own raw bytes.
            oracleWriter.WriteByteString(externallySuppliedData); //step 5.
            oracleWriter.WriteByteString(payloadBytes); //steps 6/7.
            oracleWriter.WriteByteString(signerSignatureBytes); //step 9.
            oracleWriter.WriteByteString(precedingElement); //steps 10/11: only the element preceding index 1 -- the array element is itself a bstr wrapping the UHeaderInstance map ([+bstr .cbor UHeaderInstance]), so the accumulator carries the bstr-wrapped encoding, not the bare map bytes.
            oracleWriter.WriteEndArray();
            byte[] expected = oracleWriterBuffer.WrittenSpan.ToArray();

            Assert.IsTrue(expected.AsSpan().SequenceEqual(result!.AsReadOnlySpan()),
                "The threaded-through, wire-sourced imprint input must match the independent oracle exactly.");
        }
    }


    /// <summary>
    /// A nil-payload <c>COSE_Sign</c> signer
    /// with NO <c>sigD</c> and no caller-supplied out-of-band payload must NOT validate against an empty
    /// payload -- the detached data must resolve and bind (ETSI TS 119 152-1 V1.1.1, clause 5.2.6). The SAME
    /// wire bytes DO validate once the caller supplies the matching out-of-band payload, proving the failure
    /// above is resolution-shaped, never a mis-signed fixture.
    /// </summary>
    [TestMethod]
    public async Task ValidateCoseSignAsyncRejectsANilPayloadSignerWithNoSigDInsteadOfVerifyingAgainstAnEmptyPayload()
    {
        byte[] payloadBytes = "CB-AdES COSE_Sign detached-no-sigD payload"u8.ToArray();

        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        CBAdESProtectedHeaders headers = await BuildConformantHeadersAsync("nil-payload signer", TestContext.CancellationToken).ConfigureAwait(false);
        var signers = new List<CBAdESCoseSignSignerInput> { new(headers, unsignedHeaders: null, privateKey) };

        byte[] wireCopy;
        using(CBAdESCoseSignSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignCoseSignAsync(
            new CBAdESDetachedExternalPayloadInput(payloadBytes), signers,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(creationResult.Message.IsDetachedPayload, "clause 4.5's detached-no-sigD arm wire-detaches the payload to nil.");

            using EncodedCoseSign wireBytes = CoseSerialization.SerializeCoseSign(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESCoseSignValidationResult withoutOutOfBandPayload = await CBAdESSignatureValidation.ValidateCoseSignAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign, CBAdESSignatureSerialization.DecodeCBAdESProtectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, [publicKey], AdESBaselineLevel.BB,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(withoutOutOfBandPayload.IsValid, "A nil-payload signer with no sigD and no out-of-band payload must NOT validate against an empty payload (the exploit this fix closes).");
        Assert.IsFalse(withoutOutOfBandPayload.Signers[0].IsValid);
        Assert.IsFalse(withoutOutOfBandPayload.Signers[0].SignatureVerified);
        Assert.IsEmpty(withoutOutOfBandPayload.Signers[0].Violations, "Detached-with-no-sigD is not itself a B-B/level rule violation -- the failure is resolution, not a collected violation.");

        using CBAdESCoseSignValidationResult withOutOfBandPayload = await CBAdESSignatureValidation.ValidateCoseSignAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign, CBAdESSignatureSerialization.DecodeCBAdESProtectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, [publicKey], AdESBaselineLevel.BB,
            BaseMemoryPool.Shared, externalDetachedPayload: payloadBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(withOutOfBandPayload.IsValid, "The SAME wire bytes must validate once the caller supplies the matching out-of-band detached payload -- the detached data resolves and binds.");
        Assert.IsTrue(withOutOfBandPayload.Signers[0].SignatureVerified);
    }


    /// <summary>
    /// CB-5.2.8-26 (Group B): <c>sigD</c> (<c>ObjectIdByURI</c>) is wired end to end
    /// through <see cref="CBAdESSignatureCreation.SignCoseSignAsync"/> and <see cref="CBAdESSignatureValidation.ValidateCoseSignAsync"/>
    /// for a two-signer message sharing the ONE detached payload description (RFC 9052 §4.1). Also proves the
    /// sibling nil-payload test's "no spurious attached-payload violation" claim: neither signer collects a
    /// <see cref="CBAdESDetachedObjectsAttachedPayloadViolation"/> now that <c>payloadIsDetached</c> reflects
    /// the real wire state instead of a hardcoded <see langword="false"/>.
    /// </summary>
    [TestMethod]
    public async Task SignCoseSignAsyncThenValidateCoseSignAsyncRoundTripsADetachedSigDPayloadViaObjectIdByUri()
    {
        const string reference = "https://example.org/cose-sign/objects/alpha";
        byte[] content = "CBAdESCoseSignSignatureFlowTests detached sigD object"u8.ToArray();
        var store = new Dictionary<string, byte[]>(StringComparer.Ordinal) { [reference] = content };

        var firstKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory firstPublicKey = firstKeyMaterial.PublicKey;
        using PrivateKeyMemory firstPrivateKey = firstKeyMaterial.PrivateKey;

        var secondKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory secondPublicKey = secondKeyMaterial.PublicKey;
        using PrivateKeyMemory secondPrivateKey = secondKeyMaterial.PrivateKey;

        CBAdESProtectedHeaders firstHeaders = await BuildConformantHeadersAsync("first sigD signer", TestContext.CancellationToken).ConfigureAwait(false);
        CBAdESProtectedHeaders secondHeaders = await BuildConformantHeadersAsync("second sigD signer", TestContext.CancellationToken).ConfigureAwait(false);
        var signers = new List<CBAdESCoseSignSignerInput>
        {
            new(firstHeaders, unsignedHeaders: null, firstPrivateKey),
            new(secondHeaders, unsignedHeaders: null, secondPrivateKey)
        };

        var references = new[] { new CBAdESDetachedObjectReferenceInput(reference, ContentType: null) };
        var payloadInput = new CBAdESDetachedSigDPayloadInput(CBAdESDetachedMechanisms.ObjectIdByURI, references, hashAlgorithm: null);
        var creationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);
        CBAdESDetachedObjectDereferenceDelegate creationDereference = DereferenceFromStore;

        byte[] wireCopy;
        using(CBAdESCoseSignSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignCoseSignAsync(
            payloadInput, signers,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, BaseMemoryPool.Shared,
            dereference: creationDereference, dereferenceContext: creationContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(creationResult.Message.IsDetachedPayload);
            Assert.IsNotNull(creationResult.SignerHeaders[0].DetachedObjects, "CB-5.2.8-26: sigD lands on the signer layer's own completed headers.");
            Assert.IsNotNull(creationResult.SignerHeaders[1].DetachedObjects);

            using EncodedCoseSign wireBytes = CoseSerialization.SerializeCoseSign(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        //Firewall: the verifier builds its OWN delegate instance and OWN context over the same store.
        var verificationContext = new CBAdESDetachedObjectDereferenceContext(DefaultBaseUri: null, State: store);
        CBAdESDetachedObjectDereferenceDelegate verificationDereference = DereferenceFromStore;

        using CBAdESCoseSignValidationResult validation = await CBAdESSignatureValidation.ValidateCoseSignAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign, CBAdESSignatureSerialization.DecodeCBAdESProtectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, [firstPublicKey, secondPublicKey], AdESBaselineLevel.BB,
            BaseMemoryPool.Shared, dereference: verificationDereference, dereferenceContext: verificationContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsValid, "A genuine two-signer sigD (ObjectIdByURI) COSE_Sign must validate cleanly once the verifier can dereference the referenced object.");
        Assert.IsTrue(validation.Signers[0].SignatureVerified);
        Assert.IsTrue(validation.Signers[1].SignatureVerified);
        Assert.IsEmpty(validation.Signers[0].Violations, "No spurious CBAdESDetachedObjectsAttachedPayloadViolation now that payloadIsDetached reflects the real wire state.");
        Assert.IsEmpty(validation.Signers[1].Violations);
        Assert.IsEmpty(validation.BodyLayerViolations);
    }


    /// <summary>
    /// A signer whose <c>uHeaders</c> carries a
    /// <c>refs</c> element (a genuinely pool-owned <see cref="DigestValue"/> reachable through
    /// <see cref="CBAdESCoseSignSignerValidationResult.UnsignedHeaders"/>) still holds its ORIGINAL, unzeroed
    /// digest bytes after <see cref="CBAdESSignatureValidation.ValidateCoseSignAsync"/> returns and BEFORE the
    /// caller disposes the result -- proving the parse result's own carriers are never blanket-disposed via a
    /// <c>using(parseResult)</c> out from under a carrier whose ownership already transferred out (the house
    /// pool zeros a buffer's content the moment it is returned, so a premature return would be observable here
    /// as all-zero bytes). The metered pool then proves no double return: outstanding rentals are strictly
    /// positive while the returned result -- <c>validation</c> -- is still alive, and exactly zero once it is
    /// disposed (a double return would drive this negative).
    /// </summary>
    [TestMethod]
    public async Task ValidateCoseSignAsyncNeverDisposesASignersUnsignedHeadersBeforeReturningItAndNeverDoubleReturnsThePool()
    {
        using var meteredPool = new MeteredHousePool();
        byte[] payloadBytes = "CBAdESCoseSignSignatureFlowTests metered ownership payload"u8.ToArray();
        byte[] referencedCertificateBytes = "CBAdESCoseSignSignatureFlowTests referenced certificate"u8.ToArray();

        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        DigestValue signerDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            "CBAdESCoseSignSignatureFlowTests signer certificate"u8.ToArray(), 32, CryptoTags.Sha256Digest, meteredPool.Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var signerThumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), signerDigest);
        using var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: signerThumbprint);

        DigestValue referencedDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            referencedCertificateBytes, 32, CryptoTags.Sha256Digest, meteredPool.Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        byte[] expectedReferencedDigestBytes = referencedDigest.AsReadOnlySpan().ToArray();
        using var referencedThumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referencedDigest);
        using var referencedCertificate = new CBAdESCertificateReference(referencedThumbprint);
        using var references = new CBAdESReferences(certificateReferences: [referencedCertificate]);
        using var refsElement = new CBAdESUnsignedHeaderElementReferences(references);

        byte[] wireCopy;
        using(var unsignedHeaders = new CBAdESUnsignedHeaders([refsElement]))
        {
            //Borrowed by SignCoseSignAsync (mirrors CBAdESSignatureFlowTests's own `using var unsignedHeaders`
            //convention) -- the caller that constructed this fixture disposes it itself; only Headers/
            //SignerHeaders ownership transfers into the creation result.
            var signers = new List<CBAdESCoseSignSignerInput> { new(headers, unsignedHeaders, privateKey) };

            using CBAdESCoseSignSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignCoseSignAsync(
                new CBAdESAttachedPayloadInput(payloadBytes), signers,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildCoseSignatureSigStructure, meteredPool.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign wireBytes = CoseSerialization.SerializeCoseSign(creationResult.Message, meteredPool.Pool);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        CBAdESCoseSignValidationResult validation = await CBAdESSignatureValidation.ValidateCoseSignAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign, CBAdESSignatureSerialization.DecodeCBAdESProtectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, [publicKey], AdESBaselineLevel.BB,
            meteredPool.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsValid);
        var returnedRefs = (CBAdESUnsignedHeaderElementReferences)validation.Signers[0].UnsignedHeaders![0];
        byte[] observedDigestBytes = returnedRefs.References.CertificateReferences![0].Thumbprint.Digest.AsReadOnlySpan().ToArray();

        Assert.AreSequenceEqual(expectedReferencedDigestBytes, observedDigestBytes,
            "The returned signer result's UnsignedHeaders must still carry its ORIGINAL digest bytes -- a premature dispose via a blanket using(parseResult) would have zeroed this house-pool rental before the caller ever got to read it.");
        Assert.IsGreaterThan(0L, meteredPool.OutstandingCount, "While validation is still alive and undisposed, its own owned carriers (including the transferred UnsignedHeaders) must still be outstanding.");

        validation.Dispose();

        Assert.AreEqual(0L, meteredPool.OutstandingCount,
            "Exactly zero once the caller disposes the result: a leak would leave this positive, a double return (ownership held twice) would drive it negative.");
    }


    /// <summary>
    /// A signer-layer-only component placed at the <c>COSE_Sign</c> BODY
    /// layer instead -- <c>kid</c>, <c>x5u</c>, content type, and <c>sigD</c> (a representative
    /// set) -- each becomes a collected <see cref="CBAdESCoseSignBodyLayerPlacementViolation"/>, never a thrown
    /// exception or a silently-accepted message. Built through the LOWER-LEVEL <see cref="CoseSign"/> substrate
    /// directly (mirroring <see cref="ValidateCoseSignAsyncIsolatesAConformanceViolationToItsOwnSigner"/>'s own
    /// rationale): <see cref="CBAdESSignatureCreation.SignCoseSignAsync"/> never places anything at the body
    /// layer, so a misplaced-component fixture must come from a foreign producer.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-4.4-02.
    /// </remarks>
    [TestMethod]
    public async Task ValidateCoseSignAsyncCollectsBodyLayerPlacementViolationsForKidX5UContentTypeAndSigD()
    {
        byte[] payloadBytes = "CB-AdES COSE_Sign body-layer-misplacement payload"u8.ToArray();

        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        var sigDEntries = new List<CBAdESDetachedObjectEntry> { new("https://example.org/misplaced-sigd", digest: null, contentType: null) };
        using var misplacedDetachedObjects = new CBAdESDetachedObjects(CBAdESDetachedMechanisms.ObjectIdByURI, sigDEntries, hashAlgorithm: null);
        using var misplacedBodyHeaders = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            cwtClaims: null,
            contentType: new CBAdESContentTypeText("text/plain"),
            keyId: new CoseKeyIdentifier(System.Text.Encoding.UTF8.GetBytes("misplaced-kid")),
            x5u: new Uri("https://example.org/misplaced-x5u"),
            detachedObjects: misplacedDetachedObjects,
            criticalLabels: [new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigD)]);

        using CBAdESProtectedHeaders signerHeaders = await BuildConformantHeadersAsync("body-layer-misplacement signer", TestContext.CancellationToken).ConfigureAwait(false);

        EncodedCoseProtectedHeader bodyProtectedHeader = CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader(misplacedBodyHeaders, BaseMemoryPool.Shared);
        EncodedCoseProtectedHeader signerProtectedHeader = CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader(signerHeaders, BaseMemoryPool.Shared);
        var signers = new List<CoseSignerInput> { new(signerProtectedHeader, null, privateKey) };

        byte[] wireCopy;
        using(CoseSignMessage message = await CoseSign.SignAsync(
            bodyProtectedHeader, bodyUnprotectedHeader: null, payloadBytes, signers, CoseSerialization.BuildCoseSignatureSigStructure,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            using EncodedCoseSign wireBytes = CoseSerialization.SerializeCoseSign(message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESCoseSignValidationResult validation = await CBAdESSignatureValidation.ValidateCoseSignAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign, CBAdESSignatureSerialization.DecodeCBAdESProtectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, [publicKey], AdESBaselineLevel.BB,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(validation.IsValid, "A body layer carrying signer-layer-only components must fail the overall result.");
        Assert.IsTrue(validation.Signers[0].IsValid, "The signer's OWN layer is unaffected -- body-layer placement is a message-level fact, never contaminating a signer's own outcome.");

        CBAdESCoseSignBodyLayerComponentKind[] observedKinds = [.. validation.BodyLayerViolations
            .OfType<CBAdESCoseSignBodyLayerPlacementViolation>()
            .Select(v => v.Kind)];

        Assert.Contains(CBAdESCoseSignBodyLayerComponentKind.Algorithm, observedKinds, "alg must decode at all for this body layer to be inspectable, so it is -- by construction -- itself misplaced (CB-5.1.2-06).");
        Assert.Contains(CBAdESCoseSignBodyLayerComponentKind.ContentType, observedKinds);
        Assert.Contains(CBAdESCoseSignBodyLayerComponentKind.KeyId, observedKinds);
        Assert.Contains(CBAdESCoseSignBodyLayerComponentKind.X5U, observedKinds);
        Assert.Contains(CBAdESCoseSignBodyLayerComponentKind.DetachedObjects, observedKinds);
    }


    /// <summary>
    /// CB-5.1.3-05 (Group B): "content type shall not be present if the COSE Payload
    /// is a (counter-signed) signature" -- a caller-attested fact <see cref="CBAdESHeaderRules.Check"/> cannot
    /// derive from <see cref="CBAdESProtectedHeaders"/> alone. Unattested (the default) never raises the
    /// violation; attesting <see langword="true"/> does, over the IDENTICAL headers instance.
    /// </summary>
    [TestMethod]
    public async Task CheckCollectsContentTypeCountersignedPayloadViolationOnlyWhenCallerAttestsTheFact()
    {
        (AdESCertificateThumbprint thumbprint, byte[] _) = await CreateSigningCertificateThumbprintAsync("CB-5.1.3-05 fixture", TestContext.CancellationToken).ConfigureAwait(false);
        using var headers = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch),
            contentType: new CBAdESContentTypeText("application/cose"), x5t: thumbprint);

        IReadOnlyList<CBAdESRuleViolation> unattested = CBAdESHeaderRules.Check(headers, payloadIsDetached: false, unsignedHeaders: null);
        Assert.IsEmpty(unattested.OfType<CBAdESContentTypeCountersignedPayloadViolation>(),
            "Unattested (the default, fail-closed-safe direction) must never raise CB-5.1.3-05 on its own.");

        IReadOnlyList<CBAdESRuleViolation> attested = CBAdESHeaderRules.Check(headers, payloadIsDetached: false, unsignedHeaders: null, payloadIsCountersignedSignature: true);
        Assert.IsNotEmpty(attested.OfType<CBAdESContentTypeCountersignedPayloadViolation>(),
            "CB-5.1.3-05: content type shall not be present when the caller attests the COSE Payload is itself a (counter-signed) signature.");
    }


    /// <summary>
    /// Every clause 5.1/5.2 signed header this document profiles beyond
    /// <c>alg</c>/<c>x5t</c>/<c>iat</c> (already proven placed at the <c>COSE_Sign</c> signer layer by
    /// <see cref="SignCoseSignAsyncThenValidateCoseSignAsyncSucceedsForTwoConformantSigners"/>'s own
    /// <see cref="CBAdESCoseSignValidationResult.IsValid"/> AND-reduction over
    /// <see cref="CBAdESCoseSignValidationResult.BodyLayerViolations"/>) -- content type, <c>kid</c>, <c>x5u</c>,
    /// <c>x5chain</c>, <c>crit</c>, <c>x5ts</c>, <c>srCms</c>, <c>sigPl</c>, <c>srAts</c>, <c>adoTst</c>, and
    /// <c>sigPId</c> -- all present on the SAME signer, created, serialized, wire-copied, and validated, with
    /// each decoded member asserted off the per-signer VALIDATION result alone
    /// (<see cref="CBAdESCoseSignSignerValidationResult.Headers"/>), never the creation-side objects -- mirroring
    /// <c>CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader</c>'s own
    /// firewall discipline for the <c>COSE_Sign1</c> substrate.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.1.3-07, CB-5.1.4-06, CB-5.1.5-05, CB-5.1.8-01, CB-5.1.8-03,
    /// CB-5.1.8-04, CB-5.1.8-06, CB-5.1.10-05, CB-5.2.1-01, CB-5.2.1-02, CB-5.2.2-08, CB-5.2.3-09, CB-5.2.4-06,
    /// CB-5.2.5-15, CB-5.2.6-08, CB-5.2.7-01, CB-5.2.7-14.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESCoseSignSignatureCreationResult on a successful CBAdESSignatureCreation.SignCoseSignAsync " +
            "call (see that type's own ownership remarks), which this test disposes via 'using creationResult'. " +
            "The nested srCms/sigPl/srAts/adoTst/sigPId constructions are constructor arguments passed straight " +
            "into headers's own construction, so their ownership passes to headers and then onward with it; " +
            "Roslyn's CA2000 analysis flags each nested 'new' expression independently of the enclosing " +
            "aggregate that actually owns and disposes them.")]
    [TestMethod]
    public async Task FullHouseCoseSignFlowRoundTripsAndVerifiesEveryClause5SignedHeaderOnOneSigner()
    {
        byte[] payloadBytes = "CB-AdES COSE_Sign full-house payload"u8.ToArray();
        byte[] expectedKeyId = [0x30, 0x05, 0x02, 0x01, 0x2A, 0x0C, 0x00]; //An opaque kid -- CB-5.1.4-03's DER-IssuerSerial content shape is a SHOULD, left untested here.
        var expectedX5u = new Uri("https://example.org/cose-sign/full-house/signing-certificate.cer");
        var expectedCommitmentId = "urn:cbades:cose-sign:full-house:commitment:proof-of-origin";
        const string expectedLocality = "Tallinn";
        const string expectedCountry = "EE";
        const string expectedClaimedMediaType = "application/vnd.example.cose-sign-full-house-claimed+json";
        const string expectedContentType = "application/octet-stream";
        var expectedPolicyId = "https://policy.example.org/cose-sign-full-house";
        byte[] x5chainBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] timestampTokenDerBytes =
        [
            0x30, 0x09, // SEQUENCE, length 9.
            0x02, 0x01, 0x01, // INTEGER 1 (a placeholder version field).
            0x0C, 0x04, 0x66, 0x6C, 0x6F, 0x77 // UTF8String "flow" (4 bytes).
        ];

        (AdESCertificateThumbprint thumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync("full-house signer x5t", TestContext.CancellationToken).ConfigureAwait(false);
        (AdESCertificateThumbprint firstX5tsThumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync("full-house x5ts first", TestContext.CancellationToken).ConfigureAwait(false);
        (AdESCertificateThumbprint secondX5tsThumbprint, byte[] _) =
            await CreateSigningCertificateThumbprintAsync("full-house x5ts second", TestContext.CancellationToken).ConfigureAwait(false);

        DigestValue policyDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            "full-house policy document"u8.ToArray(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var qualifyingValueWriterBuffer = new ArrayBufferWriter<byte>();
        var qualifyingValueWriter = new CborWriter(qualifyingValueWriterBuffer, CborOptions.RfcCanonical);
        qualifyingValueWriter.WriteTextString("cose-sign-full-house-claimed-value");
        byte[] claimedQualifyingValueBytes = qualifyingValueWriterBuffer.WrittenSpan.ToArray();

        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] wireCopy;
        {
            var srCms = new AdESSignerCommitments([new AdESCommitment(new AdESObjectIdentifier(expectedCommitmentId))]);
            var sigPl = new AdESSignatureProductionPlace { AddressLocality = expectedLocality, AddressCountry = expectedCountry };
            var srAts = new AdESSignerAttributes(claimed:
            [
                new CBAdESSignerAttributeNotCertifiedItem
                {
                    MediaType = expectedClaimedMediaType,
                    QualifyingValues = [new CBAdESSignerAttributeOpaqueQualifyingValue(CBAdESSignerAttributeOpaqueQualifyingValueKind.Unspecified, claimedQualifyingValueBytes)]
                }
            ]);
            var adoTst = new CBAdESPayloadTimestamp(new AdESTimestampContainer([new AdESTimestampToken { Val = timestampTokenDerBytes }]));
            var sigPId = new AdESSignaturePolicyIdentifier(
                new AdESObjectIdentifier(expectedPolicyId),
                new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
                policyDigest);

            var headers = new CBAdESProtectedHeaders(
                WellKnownCoseAlgorithms.Es256,
                new CBAdESCwtClaims(TestClock.CanonicalEpoch),
                contentType: new CBAdESContentTypeText(expectedContentType),
                keyId: new CoseKeyIdentifier(expectedKeyId),
                x5u: expectedX5u,
                x5t: thumbprint,
                x5chain: new CBAdESX5ChainSingleCertificate(x5chainBytes),
                certificateDigests: new AdESCertificateThumbprints([firstX5tsThumbprint, secondX5tsThumbprint]),
                signerCommitments: srCms,
                signatureProductionPlace: sigPl,
                signerAttributes: srAts,
                payloadTimestamps: adoTst,
                signaturePolicyIdentifier: sigPId,
                criticalLabels: [new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigPId)]);

            var signers = new List<CBAdESCoseSignSignerInput> { new(headers, unsignedHeaders: null, privateKey) };

            using CBAdESCoseSignSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignCoseSignAsync(
                new CBAdESAttachedPayloadInput(payloadBytes), signers,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildCoseSignatureSigStructure, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign wireBytes = CoseSerialization.SerializeCoseSign(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        using CBAdESCoseSignValidationResult validation = await CBAdESSignatureValidation.ValidateCoseSignAsync(
            wireCopy, CBAdESSignatureSerialization.ParseCBAdESSign, CBAdESSignatureSerialization.DecodeCBAdESProtectedHeader,
            CoseSerialization.BuildCoseSignatureSigStructure, [publicKey], AdESBaselineLevel.BB,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsValid, "A genuine full-house COSE_Sign signer carrying every clause 5.1/5.2 signed header must validate cleanly at B-B.");
        Assert.IsEmpty(validation.BodyLayerViolations);
        Assert.HasCount(1, validation.Signers);
        CBAdESCoseSignSignerValidationResult signer = validation.Signers[0];
        Assert.IsTrue(signer.IsValid);
        Assert.IsTrue(signer.SignatureVerified);
        Assert.IsEmpty(signer.Violations);

        CBAdESProtectedHeaders decoded = signer.Headers!;

        Assert.IsNotNull(decoded.ContentType); //CB-5.1.3-07.
        var decodedContentType = Assert.IsInstanceOfType<CBAdESContentTypeText>(decoded.ContentType);
        Assert.AreEqual(expectedContentType, decodedContentType.Value);

        Assert.IsNotNull(decoded.KeyId); //CB-5.1.4-06.
        Assert.IsTrue(expectedKeyId.AsSpan().SequenceEqual(decoded.KeyId!.Value.Span));

        Assert.AreEqual(expectedX5u, decoded.X5U); //CB-5.1.5-05.

        Assert.IsNotNull(decoded.X5Chain); //CB-5.1.8-06.

        Assert.IsNotNull(decoded.CriticalLabels); //CB-5.1.10-05.
        Assert.Contains(new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigPId), decoded.CriticalLabels!);

        Assert.IsNotNull(decoded.CertificateDigests); //CB-5.2.2-08.
        Assert.HasCount(2, decoded.CertificateDigests!.Thumbprints);

        Assert.IsNotNull(decoded.SignerCommitments); //CB-5.2.3-09.
        Assert.AreEqual(expectedCommitmentId, decoded.SignerCommitments!.Commitments[0].CommitmentId.Id);

        Assert.IsNotNull(decoded.SignatureProductionPlace); //CB-5.2.4-06.
        Assert.AreEqual(expectedLocality, decoded.SignatureProductionPlace!.AddressLocality);
        Assert.AreEqual(expectedCountry, decoded.SignatureProductionPlace.AddressCountry);

        Assert.IsNotNull(decoded.SignerAttributes); //CB-5.2.5-15.
        Assert.IsNotNull(decoded.SignerAttributes!.Claimed);
        Assert.HasCount(1, decoded.SignerAttributes.Claimed!);
        Assert.AreEqual(expectedClaimedMediaType, ((CBAdESSignerAttributeNotCertifiedItem)decoded.SignerAttributes.Claimed[0]).MediaType);

        Assert.IsNotNull(decoded.PayloadTimestamps); //CB-5.2.6-08.
        Assert.HasCount(1, decoded.PayloadTimestamps!.TimestampContainer.TstTokens);
        Assert.IsTrue(timestampTokenDerBytes.AsSpan().SequenceEqual(decoded.PayloadTimestamps.TimestampContainer.TstTokens[0].Val.Span));

        Assert.IsNotNull(decoded.SignaturePolicyIdentifier); //CB-5.2.7-14.
        Assert.AreEqual(expectedPolicyId, decoded.SignaturePolicyIdentifier!.Id.Id);
    }


    /// <summary>
    /// Dereferences <paramref name="uriReference"/> against <paramref name="context"/>'s own object store — the
    /// SAME closure-free, per-call-context pattern <c>CBAdESSignatureFlowTests.DereferenceFromObjectStore</c>
    /// uses, duplicated locally since this file's own fixtures are self-contained.
    /// </summary>
    /// <param name="uriReference">The URI to dereference.</param>
    /// <param name="context">The per-call caller state; its <see cref="CBAdESDetachedObjectDereferenceContext.State"/> is the object store.</param>
    /// <param name="pool">Memory pool for the reconstructed content.</param>
    /// <param name="cancellationToken">Cancellation token (unused; the test store is synchronous).</param>
    /// <returns>The dereference result.</returns>
    private static ValueTask<CBAdESDetachedObjectDereferenceResult> DereferenceFromStore(
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

        PooledMemory pooled = PooledMemory.FromBytes(content, pool, Tag.Create(Purpose.Data));

        return ValueTask.FromResult<CBAdESDetachedObjectDereferenceResult>(new CBAdESDetachedObjectDereferenceSuccess(pooled));
    }


    /// <summary>Builds a B-B-conformant <see cref="CBAdESProtectedHeaders"/> aggregate (ES256, CwtClaims, an x5t thumbprint) for one signer.</summary>
    /// <param name="certificateLabel">A label distinguishing this signer's placeholder certificate bytes from a sibling signer's own.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The conformant headers aggregate.</returns>
    private static async ValueTask<CBAdESProtectedHeaders> BuildConformantHeadersAsync(string certificateLabel, CancellationToken cancellationToken)
    {
        (AdESCertificateThumbprint thumbprint, byte[] _) = await CreateSigningCertificateThumbprintAsync(certificateLabel, cancellationToken).ConfigureAwait(false);

        return new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
    }


    /// <summary>Builds a signing certificate's <c>x5t</c> thumbprint fixture (SHA-256, via the registered digest delegate seam).</summary>
    /// <param name="certificateLabel">A label distinguishing this signer's placeholder certificate bytes from a sibling signer's own.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The thumbprint (ownership transfers to whatever aggregate it is supplied to) and the independent digest-bytes copy.</returns>
    private static async ValueTask<(AdESCertificateThumbprint Thumbprint, byte[] ExpectedDigestBytes)> CreateSigningCertificateThumbprintAsync(
        string certificateLabel, CancellationToken cancellationToken)
    {
        byte[] certificateBytes = System.Text.Encoding.UTF8.GetBytes($"CBAdESCoseSignSignatureFlowTests placeholder signing certificate -- {certificateLabel}");
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            certificateBytes, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

        byte[] expectedDigestBytes = digest.AsReadOnlySpan().ToArray();
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);

        return (thumbprint, expectedDigestBytes);
    }


    /// <summary>Encodes a trivial catch-all <c>UHeaderInstance</c> one-entry map (an arbitrary unrecognized label), mirroring <c>CBAdESSignParseResultTests</c>'s own identically-shaped helper.</summary>
    /// <param name="label">The unrecognized integer label to use as the map's sole key.</param>
    /// <returns>The encoded map bytes.</returns>
    private static byte[] EncodeUnknownUHeaderInstance(int label)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(label);
        writer.WriteInt32(1);
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }
}
