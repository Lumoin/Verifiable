using System;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapBioEnrollmentRequestCborReader"/>: round-tripping against the paired
/// <see cref="CtapBioEnrollmentRequestCborWriter"/> across the SIX-key envelope (Finding A — a
/// genuinely different key numbering from <see cref="CtapCredentialManagementRequestCborReader"/>'s
/// four keys), the <c>subCommandParams</c> nesting, unknown-key tolerance, and wrong-CBOR-type
/// negatives. Unlike every other CTAP request reader this codebase ships, NO top-level member is
/// Required — mandatory-ness is a per-subcommand dispatch decision the transition layer enforces.
/// </summary>
[TestClass]
internal sealed class CtapBioEnrollmentRequestCborReaderTests
{
    /// <summary>A fixed 16-byte template identifier pattern, distinguishable byte-by-byte.</summary>
    private static byte[] TemplateIdBytes => [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF];

    /// <summary>A fixed 4-byte <c>pinUvAuthParam</c> pattern.</summary>
    private static byte[] PinUvAuthParamBytes => [0xDE, 0xAD, 0xBE, 0xEF];


    /// <summary>
    /// Round-tripping an empty envelope (every one of the six top-level members omitted) recovers
    /// every member as <see langword="null"/> — the empty-optional-omission case: since nothing is
    /// Required on this request, an all-absent map is legal, unlike every other CTAP request this
    /// codebase decodes.
    /// </summary>
    [TestMethod]
    public void RoundTripsEmptyEnvelope()
    {
        var written = new CtapBioEnrollmentRequest();

        TaggedMemory<byte> encoded = CtapBioEnrollmentRequestCborWriter.Write(written);
        CtapBioEnrollmentRequest decoded = CtapBioEnrollmentRequestCborReader.Read(encoded.Memory);

        Assert.IsNull(decoded.Modality);
        Assert.IsNull(decoded.SubCommand);
        Assert.IsNull(decoded.SubCommandParams);
        Assert.IsNull(decoded.TemplateId);
        Assert.IsNull(decoded.TemplateFriendlyName);
        Assert.IsNull(decoded.TimeoutMilliseconds);
        Assert.IsNull(decoded.PinUvAuthProtocol);
        Assert.IsNull(decoded.PinUvAuthParam);
        Assert.IsNull(decoded.GetModality);
    }


    /// <summary>
    /// Round-tripping a request carrying every one of the six top-level members, with a fully
    /// populated <c>subCommandParams</c> (all three nested fields), recovers each one exactly.
    /// </summary>
    [TestMethod]
    public void RoundTripsEveryTopLevelMemberAndFullSubCommandParams()
    {
        var written = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint,
            SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample,
            TemplateId: TemplateIdBytes,
            TemplateFriendlyName: "left-index",
            TimeoutMilliseconds: 5000,
            PinUvAuthProtocol: 2,
            PinUvAuthParam: PinUvAuthParamBytes);

        TaggedMemory<byte> encoded = CtapBioEnrollmentRequestCborWriter.Write(written);
        CtapBioEnrollmentRequest decoded = CtapBioEnrollmentRequestCborReader.Read(encoded.Memory);

        Assert.AreEqual(WellKnownCtapBioEnrollmentModalities.Fingerprint, decoded.Modality);
        Assert.AreEqual(WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample, decoded.SubCommand);
        Assert.IsNotNull(decoded.SubCommandParams);
        Assert.IsTrue(decoded.TemplateId!.Value.Span.SequenceEqual(TemplateIdBytes));
        Assert.AreEqual("left-index", decoded.TemplateFriendlyName);
        Assert.AreEqual(5000, decoded.TimeoutMilliseconds);
        Assert.AreEqual(2, decoded.PinUvAuthProtocol);
        Assert.IsTrue(decoded.PinUvAuthParam!.Value.Span.SequenceEqual(PinUvAuthParamBytes));
        Assert.IsNull(decoded.GetModality);
    }


    /// <summary>
    /// <c>subCommandParams</c> carrying only <c>templateId</c> (the shape <c>setFriendlyName</c>/
    /// <c>removeEnrollment</c> both send) omits the other two nested fields from the wire, and the
    /// reader recovers only <c>templateId</c>, leaving <c>templateFriendlyName</c>/
    /// <c>timeoutMilliseconds</c> <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public void RoundTripsSubCommandParamsWithOnlyTemplateId()
    {
        var written = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint,
            SubCommand: WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment,
            TemplateId: TemplateIdBytes);

        TaggedMemory<byte> encoded = CtapBioEnrollmentRequestCborWriter.Write(written);
        CtapBioEnrollmentRequest decoded = CtapBioEnrollmentRequestCborReader.Read(encoded.Memory);

        Assert.IsTrue(decoded.TemplateId!.Value.Span.SequenceEqual(TemplateIdBytes));
        Assert.IsNull(decoded.TemplateFriendlyName);
        Assert.IsNull(decoded.TimeoutMilliseconds);
    }


    /// <summary>The <c>getModality</c> (<c>0x06</c>) boolean round-trips independently of every other member — §6.7.2's own bare flow.</summary>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public void RoundTripsGetModalityAlone(bool getModality)
    {
        var written = new CtapBioEnrollmentRequest(GetModality: getModality);

        TaggedMemory<byte> encoded = CtapBioEnrollmentRequestCborWriter.Write(written);
        CtapBioEnrollmentRequest decoded = CtapBioEnrollmentRequestCborReader.Read(encoded.Memory);

        Assert.AreEqual(getModality, decoded.GetModality);
        Assert.IsNull(decoded.SubCommand);
    }


    /// <summary>
    /// A <c>subCommandParams</c> map carrying an unrecognized member key is decoded successfully with
    /// that entry ignored, per CTAP 2.3 section 8's forward-compatibility rule.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedSubCommandParamsKey()
    {
        var subCommandParamsWriter = new CborWriter(CborConformanceMode.Ctap2Canonical);
        subCommandParamsWriter.WriteStartMap(2);
        subCommandParamsWriter.WriteInt32(WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateId);
        subCommandParamsWriter.WriteByteString(TemplateIdBytes);
        subCommandParamsWriter.WriteInt32(0x7F);
        subCommandParamsWriter.WriteBoolean(true);
        subCommandParamsWriter.WriteEndMap();

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapBioEnrollmentRequestKeys.SubCommandParams);
        writer.WriteEncodedValue(subCommandParamsWriter.Encode());
        writer.WriteEndMap();

        CtapBioEnrollmentRequest decoded = CtapBioEnrollmentRequestCborReader.Read(writer.Encode());

        Assert.IsTrue(decoded.TemplateId!.Value.Span.SequenceEqual(TemplateIdBytes));
    }


    /// <summary>
    /// A request carrying an unrecognized top-level member key (here <c>0x07</c>, sorted after
    /// <c>getModality</c>) decodes successfully with the unknown member ignored.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedTopLevelMemberKey()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCtapBioEnrollmentRequestKeys.Modality);
        writer.WriteInt32(WellKnownCtapBioEnrollmentModalities.Fingerprint);
        writer.WriteInt32(0x07);
        writer.WriteBoolean(true);
        writer.WriteEndMap();

        CtapBioEnrollmentRequest decoded = CtapBioEnrollmentRequestCborReader.Read(writer.Encode());

        Assert.AreEqual(WellKnownCtapBioEnrollmentModalities.Fingerprint, decoded.Modality);
    }


    /// <summary>A <c>modality</c> member carrying the wrong CBOR type (a text string, not an unsigned integer) is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenModalityHasWrongCborType()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapBioEnrollmentRequestKeys.Modality);
        writer.WriteTextString("not-an-integer");
        writer.WriteEndMap();

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapBioEnrollmentRequestCborReader.Read(writer.Encode()));
    }


    /// <summary>A <c>getModality</c> member carrying the wrong CBOR type (an integer, not a boolean) is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenGetModalityHasWrongCborType()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapBioEnrollmentRequestKeys.GetModality);
        writer.WriteInt32(1);
        writer.WriteEndMap();

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapBioEnrollmentRequestCborReader.Read(writer.Encode()));
    }


    /// <summary>A parameter map carrying the same top-level key twice is rejected.</summary>
    [TestMethod]
    public void ThrowsOnDuplicateTopLevelKey()
    {
        //Hand-built rather than produced by CborWriter (which enforces canonical key ordering at write
        //time and would refuse to emit this): {1: 1, 1: 1} — a duplicate top-level key, which
        //CtapParameterMapReader's shared first pass must reject regardless of which command reader
        //composes it.
        byte[] duplicateKeyMap = [0xA2, 0x01, 0x01, 0x01, 0x01];

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapBioEnrollmentRequestCborReader.Read(duplicateKeyMap));
    }
}
