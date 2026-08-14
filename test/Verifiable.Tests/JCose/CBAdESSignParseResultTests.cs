using System;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for <see cref="CBAdESSignatureSerialization.ParseCBAdESSign"/> — the generalization of the CB-AdES wire parse to accept <c>COSE_Sign</c> (multi-signer)-built
/// signatures, which <see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/>'s unconditional element-3
/// <c>bstr</c> read cannot express.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Independent oracle.</strong> Every fixture in this file is assembled directly with a fresh
/// <see cref="CborWriter"/> against RFC 9052 §4.1's own CDDL, never via <see cref="CoseSerialization.SerializeCoseSign"/>
/// (that generic writer's unprotected-header-map encoding does not reproduce the CB-AdES-specific
/// <c>{268 =&gt; bstr .cbor UHeaderInstance-array}</c> shape this parser's signer-layer decode expects) or any
/// production encoder this test exercises.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESSignParseResultTests
{
    /// <summary>
    /// A well-formed, untagged, two-signer <c>COSE_Sign</c> — empty body-layer unprotected map (CB-4.4-02: no
    /// <c>uHeaders</c> at the body layer), signer 0 with no <c>uHeaders</c>, signer 1 carrying a <c>uHeaders</c>
    /// array whose sole element is a full counter-signature (label 11) — parses successfully, capturing every
    /// layer's protected header raw and byte-exact, and decoding the signer-1 <c>uHeaders</c> element visibly
    /// (the generalized parse surfaces a label-11 element regardless of which layer
    /// carries it).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-4.2-01, CB-4.3-01, CB-4.4-04, CB-5.1.6-01, CB-5.3.1-08.
    /// </remarks>
    [TestMethod]
    public void ParseCBAdESSignSucceedsForWellFormedUntaggedTwoSignerMessage()
    {
        byte[] bodyProtectedHeaderBytes = [0xA1, 0x01, 0x26]; //{1: -7} -- an arbitrary, well-formed protected header map.
        byte[] payloadBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] signer0ProtectedHeaderBytes = [0xA0];
        byte[] signer0SignatureBytes = [0x01, 0x02];
        byte[] signer1ProtectedHeaderBytes = [0xA1, 0x01, 0x26];
        byte[] signer1SignatureBytes = [0x03, 0x04, 0x05];
        byte[] counterSignatureOpaqueValue = [0x83, 0x40, 0xA0, 0x41, 0x00]; //A well-formed 3-array: [bstr, {}, bstr].

        byte[] wireBytes = BuildCoseSignBytes(
            tagged: false,
            bodyProtectedHeaderBytes,
            bodyUnprotectedMemberCount: 0,
            payloadBytes,
            [
                (signer0ProtectedHeaderBytes, signerHasUHeaders: false, signer0SignatureBytes),
                (signer1ProtectedHeaderBytes, signerHasUHeaders: true, signer1SignatureBytes)
            ],
            counterSignatureOpaqueValue);

        using CBAdESSignParseResult result = CBAdESSignatureSerialization.ParseCBAdESSign(wireBytes, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, "A well-formed, untagged COSE_Sign message must parse successfully.");
        Assert.IsTrue(bodyProtectedHeaderBytes.AsSpan().SequenceEqual(result.RawBodyProtectedHeader!.AsReadOnlySpan()), "The body-layer protected header must be captured byte-exact.");
        Assert.IsTrue(result.PayloadIsPresent);
        Assert.IsTrue(payloadBytes.AsSpan().SequenceEqual(result.Payload.Span));
        Assert.HasCount(2, result.Signers!);

        CBAdESSignerParseResult firstSigner = result.Signers![0];
        Assert.IsTrue(signer0ProtectedHeaderBytes.AsSpan().SequenceEqual(firstSigner.RawProtectedHeader.AsReadOnlySpan()));
        Assert.IsTrue(signer0SignatureBytes.AsSpan().SequenceEqual(firstSigner.Signature.AsReadOnlySpan()));
        Assert.IsNull(firstSigner.UnsignedHeaders, "Signer 0 carries no uHeaders member.");

        CBAdESSignerParseResult secondSigner = result.Signers![1];
        Assert.IsTrue(signer1ProtectedHeaderBytes.AsSpan().SequenceEqual(secondSigner.RawProtectedHeader.AsReadOnlySpan()));
        Assert.IsTrue(signer1SignatureBytes.AsSpan().SequenceEqual(secondSigner.Signature.AsReadOnlySpan()));
        Assert.IsNotNull(secondSigner.UnsignedHeaders, "Signer 1's own uHeaders (signer-layer, CB-4.4-03) must decode.");
        Assert.AreEqual(1, secondSigner.UnsignedHeaders!.Count);

        var fullCounterSignature = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementFullCounterSignature>(secondSigner.UnsignedHeaders[0]);
        Assert.IsTrue(
            counterSignatureOpaqueValue.AsSpan().SequenceEqual(fullCounterSignature.Value.Span),
            "A label-11 element carried at the SIGNER layer under COSE_Sign must decode visibly (flags 5 and 7/8), byte-exact.");
    }


    /// <summary>The tagged form (CBOR tag 98, <c>COSE_Sign_Tagged</c>) parses identically to the untagged form (clause 4.3).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-4.3-02.
    /// </remarks>
    [TestMethod]
    public void ParseCBAdESSignAcceptsTheTaggedForm()
    {
        byte[] wireBytes = BuildCoseSignBytes(
            tagged: true,
            bodyProtectedHeaderBytes: [0xA0],
            bodyUnprotectedMemberCount: 0,
            payloadBytes: [0x01],
            [([0xA0], signerHasUHeaders: false, [0x02])],
            counterSignatureOpaqueValue: null);

        using CBAdESSignParseResult result = CBAdESSignatureSerialization.ParseCBAdESSign(wireBytes, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, "The tagged COSE_Sign_Tagged form (tag 98) must be accepted (clause 4.3).");
    }


    /// <summary>An unrelated CBOR tag (e.g. <c>COSE_Sign1_Tagged</c>, 18) fails closed rather than being silently accepted.</summary>
    [TestMethod]
    public void ParseCBAdESSignFailsClosedOnWrongTag()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)CoseTags.Sign1);
        writer.WriteStartArray(4);
        writer.WriteByteString([0xA0]);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString([0x01]);
        writer.WriteStartArray(1);
        writer.WriteStartArray(3);
        writer.WriteByteString([0xA0]);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString([0x02]);
        writer.WriteEndArray();
        writer.WriteEndArray();
        writer.WriteEndArray();

        using CBAdESSignParseResult result = CBAdESSignatureSerialization.ParseCBAdESSign(writer.Encode(), BaseMemoryPool.Shared);

        Assert.IsFalse(result.IsSuccess, "A tag other than 98 (here, COSE_Sign1_Tagged) must fail closed, never silently accepted.");
    }


    /// <summary>
    /// A body-layer unprotected map carrying ANY member (here, a spurious <c>uHeaders</c> entry) fails closed —
    /// clause 4.4: "CB-AdES signatures supported by a COSE_Sign structure... shall not contain the uHeaders
    /// unprotected header parameter in the body layer" (CB-4.4-02), and clause 4.4's opening sentence permits
    /// no other member either.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-4.4-03.
    /// </remarks>
    [TestMethod]
    public void ParseCBAdESSignFailsClosedOnNonEmptyBodyLayerUnprotectedMap()
    {
        byte[] wireBytes = BuildCoseSignBytes(
            tagged: false,
            bodyProtectedHeaderBytes: [0xA0],
            bodyUnprotectedMemberCount: 1,
            payloadBytes: [0x01],
            [([0xA0], signerHasUHeaders: false, [0x02])],
            counterSignatureOpaqueValue: null);

        using CBAdESSignParseResult result = CBAdESSignatureSerialization.ParseCBAdESSign(wireBytes, BaseMemoryPool.Shared);

        Assert.IsFalse(result.IsSuccess, "A non-empty body-layer unprotected map under COSE_Sign must fail closed (clause 4.4, CB-4.4-02).");
    }


    /// <summary>RFC 9052 §4.1's <c>signatures: [+ COSE_Signature]</c> is non-empty by construction; a zero-signer array fails closed.</summary>
    [TestMethod]
    public void ParseCBAdESSignFailsClosedOnZeroSigners()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(4);
        writer.WriteByteString([0xA0]);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString([0x01]);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndArray();

        using CBAdESSignParseResult result = CBAdESSignatureSerialization.ParseCBAdESSign(writer.Encode(), BaseMemoryPool.Shared);

        Assert.IsFalse(result.IsSuccess, "signatures: [+ COSE_Signature] must be non-empty; a zero-signer array must fail closed.");
    }


    /// <summary>Truncated/garbage bytes fail closed rather than throwing an uncaught exception.</summary>
    [TestMethod]
    public void ParseCBAdESSignFailsClosedOnGarbageBytes()
    {
        byte[] garbage = [0xFF, 0x00, 0xDE, 0xAD];

        using CBAdESSignParseResult result = CBAdESSignatureSerialization.ParseCBAdESSign(garbage, BaseMemoryPool.Shared);

        Assert.IsFalse(result.IsSuccess, "Garbage bytes must fail closed, never throw.");
    }


    /// <summary>
    /// Assembles a well-formed <c>COSE_Sign</c> message directly with a fresh <see cref="CborWriter"/>, per RFC
    /// 9052 §4.1's own CDDL — an independent oracle, never <see cref="CoseSerialization.SerializeCoseSign"/>.
    /// </summary>
    /// <param name="tagged">Whether to prefix the CBOR tag 98 (<c>COSE_Sign_Tagged</c>).</param>
    /// <param name="bodyProtectedHeaderBytes">The body layer's protected header bytes.</param>
    /// <param name="bodyUnprotectedMemberCount">
    /// The number of members to write in the body layer's unprotected map (0 for a conformant CB-AdES message;
    /// a spurious entry otherwise, for the negative test).
    /// </param>
    /// <param name="payloadBytes">The COSE Payload bytes.</param>
    /// <param name="signers">Each signer's (protected header bytes, whether to carry a uHeaders member, signature bytes).</param>
    /// <param name="counterSignatureOpaqueValue">
    /// When non-null, the last signer's <c>uHeaders</c> carries exactly one element: a full counter-signature
    /// (label 11) whose opaque value is this array's own bytes.
    /// </param>
    /// <returns>The encoded wire bytes.</returns>
    private static byte[] BuildCoseSignBytes(
        bool tagged,
        byte[] bodyProtectedHeaderBytes,
        int bodyUnprotectedMemberCount,
        byte[] payloadBytes,
        (byte[] ProtectedHeaderBytes, bool signerHasUHeaders, byte[] SignatureBytes)[] signers,
        byte[]? counterSignatureOpaqueValue)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);

        if(tagged)
        {
            writer.WriteTag((CborTag)CoseTags.Sign);
        }

        writer.WriteStartArray(4);

        writer.WriteByteString(bodyProtectedHeaderBytes);

        writer.WriteStartMap(bodyUnprotectedMemberCount);
        for(int i = 0; i < bodyUnprotectedMemberCount; ++i)
        {
            writer.WriteInt32(CBAdESHeaderParameters.UHeaders);
            writer.WriteStartArray(1);
            writer.WriteByteString(EncodeUnknownUHeaderInstance());
            writer.WriteEndArray();
        }
        writer.WriteEndMap();

        writer.WriteByteString(payloadBytes);

        writer.WriteStartArray(signers.Length);
        for(int i = 0; i < signers.Length; ++i)
        {
            (byte[] protectedHeaderBytes, bool signerHasUHeaders, byte[] signatureBytes) = signers[i];

            writer.WriteStartArray(3);
            writer.WriteByteString(protectedHeaderBytes);

            if(signerHasUHeaders)
            {
                writer.WriteStartMap(1);
                writer.WriteInt32(CBAdESHeaderParameters.UHeaders);
                writer.WriteStartArray(1);
                writer.WriteByteString(counterSignatureOpaqueValue is not null
                    ? EncodeFullCounterSignatureUHeaderInstance(counterSignatureOpaqueValue)
                    : EncodeUnknownUHeaderInstance());
                writer.WriteEndArray();
                writer.WriteEndMap();
            }
            else
            {
                writer.WriteStartMap(0);
                writer.WriteEndMap();
            }

            writer.WriteByteString(signatureBytes);
            writer.WriteEndArray();
        }
        writer.WriteEndArray();

        writer.WriteEndArray();

        return writer.Encode();
    }


    /// <summary>Encodes a trivial catch-all <c>UHeaderInstance</c> one-entry map (an arbitrary unrecognized label), for fixtures where the exact content does not matter.</summary>
    /// <returns>The encoded map bytes.</returns>
    private static byte[] EncodeUnknownUHeaderInstance()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(9999);
        writer.WriteInt32(1);
        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>Encodes the full-counter-signature-shaped <c>UHeaderInstance</c> one-entry map (label 11, clause 5.3.1 CDDL; IETF RFC 9338).</summary>
    /// <param name="counterSignatureValueBytes">The already-encoded opaque value bytes.</param>
    /// <returns>The encoded map bytes.</returns>
    private static byte[] EncodeFullCounterSignatureUHeaderInstance(byte[] counterSignatureValueBytes)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(CBAdESUnsignedHeaderElement.FullCounterSignatureLabel);
        writer.WriteEncodedValue(counterSignatureValueBytes);
        writer.WriteEndMap();
        return writer.Encode();
    }
}
