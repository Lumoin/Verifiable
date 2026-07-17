using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapBioEnrollmentResponseDelegate"/>: decodes an
/// <c>authenticatorBioEnrollment</c> response's CTAP2-canonical CBOR payload into its typed model — the
/// RP/platform-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>. Read with
/// <see cref="CborConformanceMode.Ctap2Canonical"/>, mirroring <see cref="CtapCredentialManagementResponseCborReader"/>.
/// Per section 8's forward-compatibility rule, any member key this reader does not model is skipped
/// rather than rejected. <c>templateInfos</c> reuses the SHARED <see cref="TemplateInfoCborCodec"/>.
/// </remarks>
public static class CtapBioEnrollmentResponseCborReader
{
    /// <summary>
    /// Decodes <paramref name="payload"/> into a <see cref="CtapBioEnrollmentResponse"/>.
    /// Method-group-compatible with <see cref="DecodeCtapBioEnrollmentResponseDelegate"/>.
    /// </summary>
    /// <param name="payload">The CBOR-encoded response payload.</param>
    /// <returns>The decoded response model.</returns>
    /// <exception cref="Fido2FormatException"><paramref name="payload"/> is not valid CTAP2 canonical CBOR.</exception>
    public static CtapBioEnrollmentResponse Read(ReadOnlyMemory<byte> payload)
    {
        try
        {
            var reader = new CborReader(payload, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            int? modality = null;
            int? fingerprintKind = null;
            int? maxCaptureSamplesRequiredForEnroll = null;
            ReadOnlyMemory<byte>? templateId = null;
            int? lastEnrollSampleStatus = null;
            int? remainingSamples = null;
            List<CtapBioEnrollmentTemplateInfo>? templateInfos = null;
            int? maxTemplateFriendlyName = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int key = checked((int)reader.ReadInt64());
                entriesRead++;

                if(key == WellKnownCtapBioEnrollmentResponseKeys.Modality)
                {
                    modality = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapBioEnrollmentResponseKeys.FingerprintKind)
                {
                    fingerprintKind = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapBioEnrollmentResponseKeys.MaxCaptureSamplesRequiredForEnroll)
                {
                    maxCaptureSamplesRequiredForEnroll = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapBioEnrollmentResponseKeys.TemplateId)
                {
                    templateId = reader.ReadByteString();
                }
                else if(key == WellKnownCtapBioEnrollmentResponseKeys.LastEnrollSampleStatus)
                {
                    lastEnrollSampleStatus = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapBioEnrollmentResponseKeys.RemainingSamples)
                {
                    remainingSamples = checked((int)reader.ReadInt64());
                }
                else if(key == WellKnownCtapBioEnrollmentResponseKeys.TemplateInfos)
                {
                    templateInfos = TemplateInfoCborCodec.ReadArray(reader);
                }
                else if(key == WellKnownCtapBioEnrollmentResponseKeys.MaxTemplateFriendlyName)
                {
                    maxTemplateFriendlyName = checked((int)reader.ReadInt64());
                }
                else
                {
                    reader.SkipValue();
                }
            }

            reader.ReadEndMap();

            return new CtapBioEnrollmentResponse(
                modality, fingerprintKind, maxCaptureSamplesRequiredForEnroll, templateId, lastEnrollSampleStatus,
                remainingSamples, templateInfos, maxTemplateFriendlyName);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException("The authenticatorBioEnrollment response bytes are not valid CTAP2 canonical CBOR.", exception);
        }
    }
}
