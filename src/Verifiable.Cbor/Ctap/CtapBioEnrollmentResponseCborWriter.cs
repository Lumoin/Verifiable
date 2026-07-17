using System;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapBioEnrollmentResponseDelegate"/>: encodes an
/// <c>authenticatorBioEnrollment</c> response model into its CTAP2-canonical CBOR payload bytes — the
/// authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the response structure table
/// (snapshot lines 6484-6533). The response map's keys (<c>modality</c>=1 .. <c>maxTemplateFriendlyName</c>=8)
/// are already in ascending numeric order, so writing any present member in that fixed order is
/// sufficient — no run-time sort is needed, mirroring <see cref="CtapCredentialManagementResponseCborWriter"/>'s
/// convention. <c>templateInfos</c> (<c>0x07</c>) is a CBOR ARRAY of nested maps, written via the SHARED
/// <see cref="TemplateInfoCborCodec"/> — this codebase's first array-of-maps CTAP response member.
/// </remarks>
public static class CtapBioEnrollmentResponseCborWriter
{
    /// <summary>
    /// Encodes <paramref name="response"/> into its CTAP2-canonical CBOR payload bytes.
    /// Method-group-compatible with <see cref="EncodeCtapBioEnrollmentResponseDelegate"/>.
    /// </summary>
    /// <param name="response">The response model to encode.</param>
    /// <returns>The encoded payload, tagged <see cref="Fido2BufferTags.CtapBioEnrollmentResponsePayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="response"/> is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapBioEnrollmentResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (response.Modality is not null ? 1 : 0)
            + (response.FingerprintKind is not null ? 1 : 0)
            + (response.MaxCaptureSamplesRequiredForEnroll is not null ? 1 : 0)
            + (response.TemplateId is not null ? 1 : 0)
            + (response.LastEnrollSampleStatus is not null ? 1 : 0)
            + (response.RemainingSamples is not null ? 1 : 0)
            + (response.TemplateInfos is not null ? 1 : 0)
            + (response.MaxTemplateFriendlyName is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(response.Modality is int modality)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentResponseKeys.Modality);
            writer.WriteInt32(modality);
        }

        if(response.FingerprintKind is int fingerprintKind)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentResponseKeys.FingerprintKind);
            writer.WriteInt32(fingerprintKind);
        }

        if(response.MaxCaptureSamplesRequiredForEnroll is int maxCaptureSamplesRequiredForEnroll)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentResponseKeys.MaxCaptureSamplesRequiredForEnroll);
            writer.WriteInt32(maxCaptureSamplesRequiredForEnroll);
        }

        if(response.TemplateId is ReadOnlyMemory<byte> templateId)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentResponseKeys.TemplateId);
            writer.WriteByteString(templateId.Span);
        }

        if(response.LastEnrollSampleStatus is int lastEnrollSampleStatus)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentResponseKeys.LastEnrollSampleStatus);
            writer.WriteInt32(lastEnrollSampleStatus);
        }

        if(response.RemainingSamples is int remainingSamples)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentResponseKeys.RemainingSamples);
            writer.WriteInt32(remainingSamples);
        }

        if(response.TemplateInfos is not null)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentResponseKeys.TemplateInfos);
            TemplateInfoCborCodec.WriteArray(writer, response.TemplateInfos);
        }

        if(response.MaxTemplateFriendlyName is int maxTemplateFriendlyName)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentResponseKeys.MaxTemplateFriendlyName);
            writer.WriteInt32(maxTemplateFriendlyName);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapBioEnrollmentResponsePayload);
    }
}
