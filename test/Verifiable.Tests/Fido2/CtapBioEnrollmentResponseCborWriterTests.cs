using System;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness tests for <see cref="CtapBioEnrollmentResponseCborWriter"/>, plus round-trips against
/// the paired <see cref="CtapBioEnrollmentResponseCborReader"/>. The response map's eight keys
/// (<c>modality</c>=1 .. <c>maxTemplateFriendlyName</c>=8) are already ascending, so any present subset
/// writes in that fixed order with no run-time sort. <c>templateInfos</c> (<c>0x07</c>) is this
/// codebase's first CBOR-array-of-maps CTAP response member — covered here single- and multi-element.
/// </summary>
[TestClass]
internal sealed class CtapBioEnrollmentResponseCborWriterTests
{
    /// <summary>An empty response (every member absent) encodes to a zero-entry map — the empty-optional-omission case.</summary>
    [TestMethod]
    public void WriteEncodesEmptyResponseToExactCanonicalBytes()
    {
        var response = new CtapBioEnrollmentResponse();

        TaggedMemory<byte> result = CtapBioEnrollmentResponseCborWriter.Write(response);

        byte[] expected = [0xA0];
        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>getModality</c>'s own response shape: a single-member map reporting <c>modality</c> (<c>0x01</c>) = 1 (fingerprint).
    /// </summary>
    [TestMethod]
    public void WriteEncodesGetModalityResponseToExactCanonicalBytes()
    {
        var response = new CtapBioEnrollmentResponse(Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint);

        TaggedMemory<byte> result = CtapBioEnrollmentResponseCborWriter.Write(response);

        byte[] expected = [0xA1, 0x01, 0x01];
        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>getFingerprintSensorInfo</c>'s own response shape: <c>fingerprintKind</c> (<c>0x02</c>) = 1,
    /// <c>maxCaptureSamplesRequiredForEnroll</c> (<c>0x03</c>) = 4,
    /// <c>maxTemplateFriendlyName</c> (<c>0x08</c>) = 64 — the only value here ≥ 24, so it alone
    /// requires CBOR's 1-additional-byte unsigned-integer form (<c>0x18</c> followed by the raw byte).
    /// </summary>
    [TestMethod]
    public void WriteEncodesGetFingerprintSensorInfoResponseToExactCanonicalBytes()
    {
        var response = new CtapBioEnrollmentResponse(
            FingerprintKind: WellKnownCtapFingerprintKinds.Touch,
            MaxCaptureSamplesRequiredForEnroll: 4,
            MaxTemplateFriendlyName: 64);

        TaggedMemory<byte> result = CtapBioEnrollmentResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA3, //map(3): fingerprintKind, maxCaptureSamplesRequiredForEnroll, maxTemplateFriendlyName
            0x02, 0x01, //key 2 (fingerprintKind) -> 1 (touch)
            0x03, 0x04, //key 3 (maxCaptureSamplesRequiredForEnroll) -> 4
            0x08, 0x18, 0x40 //key 8 (maxTemplateFriendlyName) -> 64, 1-byte extra form
        ];
        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A <c>templateId</c> (<c>0x04</c>) byte-string member, <c>enrollBegin</c>'s own response shape
    /// alongside <c>lastEnrollSampleStatus</c> (<c>0x05</c>) and <c>remainingSamples</c> (<c>0x06</c>).
    /// </summary>
    [TestMethod]
    public void WriteEncodesEnrollBeginResponseToExactCanonicalBytes()
    {
        byte[] templateId = [0x01, 0x02, 0x03, 0x04];
        var response = new CtapBioEnrollmentResponse(TemplateId: templateId, LastEnrollSampleStatus: 0x00, RemainingSamples: 3);

        TaggedMemory<byte> result = CtapBioEnrollmentResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA3, //map(3): templateId, lastEnrollSampleStatus, remainingSamples
            0x04, 0x44, 0x01, 0x02, 0x03, 0x04, //key 4 (templateId) -> bytes(4)
            0x05, 0x00, //key 5 (lastEnrollSampleStatus) -> 0 (good)
            0x06, 0x03 //key 6 (remainingSamples) -> 3
        ];
        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>templateInfos</c> (<c>0x07</c>) with exactly ONE element: an array(1) of one nested map
    /// carrying only the Required <c>templateId</c> (<c>0x01</c>), <c>templateFriendlyName</c>
    /// (<c>0x02</c>) omitted (never set).
    /// </summary>
    [TestMethod]
    public void WriteEncodesSingleTemplateInfoToExactCanonicalBytes()
    {
        byte[] templateId = [0x01, 0x02];
        var response = new CtapBioEnrollmentResponse(TemplateInfos: [new CtapBioEnrollmentTemplateInfo(templateId)]);

        TaggedMemory<byte> result = CtapBioEnrollmentResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA1, //map(1): templateInfos
            0x07, 0x81, //key 7 (templateInfos) -> array(1)
                0xA1, 0x01, 0x42, 0x01, 0x02 //element: map(1) {templateId (0x01) -> bytes(2)}
        ];
        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>templateInfos</c> with TWO elements: the first carrying only <c>templateId</c>, the second
    /// carrying both <c>templateId</c> and <c>templateFriendlyName</c> — proving each array element
    /// independently omits/includes its own Optional <c>templateFriendlyName</c>.
    /// </summary>
    [TestMethod]
    public void WriteEncodesMultipleTemplateInfosToExactCanonicalBytes()
    {
        byte[] firstTemplateId = [0xAA];
        byte[] secondTemplateId = [0xBB];
        var response = new CtapBioEnrollmentResponse(TemplateInfos:
        [
            new CtapBioEnrollmentTemplateInfo(firstTemplateId),
            new CtapBioEnrollmentTemplateInfo(secondTemplateId, "a")
        ]);

        TaggedMemory<byte> result = CtapBioEnrollmentResponseCborWriter.Write(response);

        byte[] expected =
        [
            0xA1,
            0x07, 0x82, //key 7 (templateInfos) -> array(2)
                0xA1, 0x01, 0x41, 0xAA, //element 0: map(1) {templateId -> bytes(1) 0xAA}
                0xA2, 0x01, 0x41, 0xBB, 0x02, 0x61, 0x61 //element 1: map(2) {templateId -> bytes(1) 0xBB, templateFriendlyName -> "a"}
        ];
        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>Round-tripping the full response surface (every member present, two-element <c>templateInfos</c>) recovers every value exactly.</summary>
    [TestMethod]
    public void RoundTripsFullResponseSurface()
    {
        byte[] templateId = [0x10, 0x20, 0x30];
        byte[] firstEntryTemplateId = [0x01];
        byte[] secondEntryTemplateId = [0x02];
        var written = new CtapBioEnrollmentResponse(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint,
            FingerprintKind: WellKnownCtapFingerprintKinds.Touch,
            MaxCaptureSamplesRequiredForEnroll: 4,
            TemplateId: templateId,
            LastEnrollSampleStatus: WellKnownCtapLastEnrollSampleStatuses.PoorQuality,
            RemainingSamples: 2,
            TemplateInfos:
            [
                new CtapBioEnrollmentTemplateInfo(firstEntryTemplateId, "right-thumb"),
                new CtapBioEnrollmentTemplateInfo(secondEntryTemplateId)
            ],
            MaxTemplateFriendlyName: 64);

        TaggedMemory<byte> encoded = CtapBioEnrollmentResponseCborWriter.Write(written);
        CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(encoded.Memory);

        Assert.AreEqual(WellKnownCtapBioEnrollmentModalities.Fingerprint, decoded.Modality);
        Assert.AreEqual(WellKnownCtapFingerprintKinds.Touch, decoded.FingerprintKind);
        Assert.AreEqual(4, decoded.MaxCaptureSamplesRequiredForEnroll);
        Assert.IsTrue(decoded.TemplateId!.Value.Span.SequenceEqual(templateId));
        Assert.AreEqual(WellKnownCtapLastEnrollSampleStatuses.PoorQuality, decoded.LastEnrollSampleStatus);
        Assert.AreEqual(2, decoded.RemainingSamples);
        Assert.IsNotNull(decoded.TemplateInfos);
        Assert.HasCount(2, decoded.TemplateInfos!);
        Assert.IsTrue(decoded.TemplateInfos![0].TemplateId.Span.SequenceEqual(firstEntryTemplateId));
        Assert.AreEqual("right-thumb", decoded.TemplateInfos![0].TemplateFriendlyName);
        Assert.IsTrue(decoded.TemplateInfos![1].TemplateId.Span.SequenceEqual(secondEntryTemplateId));
        Assert.IsNull(decoded.TemplateInfos![1].TemplateFriendlyName);
        Assert.AreEqual(64, decoded.MaxTemplateFriendlyName);
    }


    /// <summary>
    /// A response carrying an unrecognized member key is decoded successfully with the unknown member
    /// ignored, per CTAP 2.3 section 8's forward-compatibility rule.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedResponseMemberKey()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCtapBioEnrollmentResponseKeys.Modality);
        writer.WriteInt32(WellKnownCtapBioEnrollmentModalities.Fingerprint);
        writer.WriteInt32(0x09);
        writer.WriteBoolean(true);
        writer.WriteEndMap();

        CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(writer.Encode());

        Assert.AreEqual(WellKnownCtapBioEnrollmentModalities.Fingerprint, decoded.Modality);
    }


    /// <summary>A <c>templateInfos</c> element missing the Required <c>templateId</c> member is rejected.</summary>
    [TestMethod]
    public void ThrowsWhenTemplateInfoEntryIsMissingTemplateId()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapBioEnrollmentResponseKeys.TemplateInfos);
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateFriendlyName);
        writer.WriteTextString("orphan");
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapBioEnrollmentResponseCborReader.Read(writer.Encode()));
    }
}
