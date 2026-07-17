using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="DecodeCtapBioEnrollmentRequestDelegate"/>: decodes an
/// <c>authenticatorBioEnrollment</c> request's CTAP2-canonical CBOR parameter map into its typed
/// model — the authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>. Uses
/// <see cref="CtapParameterMapReader"/> to capture every top-level key's still-encoded value in one
/// pass, mirroring <see cref="CtapCredentialManagementRequestCborReader"/> — but unlike that reader, NO
/// top-level member is Required (the input parameter table, snapshot lines 6386-6417, marks all six
/// Optional); mandatory-ness is a per-subcommand dispatch decision the transition layer enforces, not a
/// decode-time rejection. <c>subCommandParams</c> (<c>0x03</c>)'s still-encoded bytes are captured as
/// <see cref="CtapBioEnrollmentRequest.SubCommandParams"/> UNCHANGED (a slice of
/// <paramref name="parametersCbor"/> itself, via <see cref="CborReader.ReadEncodedValue"/> — never
/// re-encoded) and, when present, decoded a second time for <c>templateId</c>/
/// <c>templateFriendlyName</c>/<c>timeoutMilliseconds</c>.
/// </remarks>
public static class CtapBioEnrollmentRequestCborReader
{
    /// <summary>
    /// Decodes <paramref name="parametersCbor"/> into a <see cref="CtapBioEnrollmentRequest"/>.
    /// Method-group-compatible with <see cref="DecodeCtapBioEnrollmentRequestDelegate"/>.
    /// </summary>
    /// <param name="parametersCbor">The CBOR-encoded parameter map.</param>
    /// <returns>The decoded request model.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR (classified
    /// <see cref="Fido2FormatFailureKind.MalformedCbor"/>), or carries a member of the wrong CBOR type
    /// (classified <see cref="Fido2FormatFailureKind.UnexpectedStructure"/>).
    /// </exception>
    public static CtapBioEnrollmentRequest Read(ReadOnlyMemory<byte> parametersCbor)
    {
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters = CtapParameterMapReader.Read(parametersCbor);

        try
        {
            int? modality = ReadOptionalInt(parameters, WellKnownCtapBioEnrollmentRequestKeys.Modality);
            int? subCommand = ReadOptionalInt(parameters, WellKnownCtapBioEnrollmentRequestKeys.SubCommand);
            ReadOnlyMemory<byte>? subCommandParams = ReadOptionalRawValue(parameters, WellKnownCtapBioEnrollmentRequestKeys.SubCommandParams);

            (ReadOnlyMemory<byte>? templateId, string? templateFriendlyName, int? timeoutMilliseconds) =
                subCommandParams is ReadOnlyMemory<byte> paramsCbor ? ReadSubCommandParams(paramsCbor) : (null, null, null);

            int? pinUvAuthProtocol = ReadOptionalInt(parameters, WellKnownCtapBioEnrollmentRequestKeys.PinUvAuthProtocol);
            ReadOnlyMemory<byte>? pinUvAuthParam = ReadOptionalByteString(parameters, WellKnownCtapBioEnrollmentRequestKeys.PinUvAuthParam);

            bool? getModality = null;
            if(parameters.TryGetValue(WellKnownCtapBioEnrollmentRequestKeys.GetModality, out ReadOnlyMemory<byte> getModalityCbor))
            {
                getModality = new CborReader(getModalityCbor, CborConformanceMode.Ctap2Canonical).ReadBoolean();
            }

            return new CtapBioEnrollmentRequest(
                modality, subCommand, subCommandParams, templateId, templateFriendlyName, timeoutMilliseconds,
                pinUvAuthProtocol, pinUvAuthParam, getModality);
        }
        catch(CborContentException exception)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.MalformedCbor, "The authenticatorBioEnrollment request parameter bytes are not valid CTAP2 canonical CBOR.", exception);
        }
        catch(Exception exception) when(exception is InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The authenticatorBioEnrollment request carries a member of an unexpected CBOR type.", exception);
        }

        //Looks up an Optional integer member, or returns null when the member is absent.
        static int? ReadOptionalInt(IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters, int key) =>
            parameters.TryGetValue(key, out ReadOnlyMemory<byte> valueCbor)
                ? checked((int)new CborReader(valueCbor, CborConformanceMode.Ctap2Canonical).ReadInt64())
                : null;

        //Looks up an Optional member's still-encoded bytes verbatim, or returns null when the member is
        //absent — the if/else shape avoids the documented ternary trap on ReadOnlyMemory<byte>?.
        static ReadOnlyMemory<byte>? ReadOptionalRawValue(IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters, int key)
        {
            if(parameters.TryGetValue(key, out ReadOnlyMemory<byte> valueCbor))
            {
                return valueCbor;
            }

            return null;
        }

        //Looks up an Optional byte-string member and decodes it, or returns null when the member is
        //absent — mirrors ReadOptionalRawValue's own if/else shape for the identical trap.
        static ReadOnlyMemory<byte>? ReadOptionalByteString(IReadOnlyDictionary<int, ReadOnlyMemory<byte>> parameters, int key)
        {
            if(parameters.TryGetValue(key, out ReadOnlyMemory<byte> valueCbor))
            {
                return new CborReader(valueCbor, CborConformanceMode.Ctap2Canonical).ReadByteString();
            }

            return null;
        }
    }


    /// <summary>
    /// Decodes <c>subCommandParams</c>'s own three members (CTAP 2.3 §6.7, snapshot lines 6459-6482):
    /// <c>templateId</c> (<c>0x01</c>, byte string), <c>templateFriendlyName</c> (<c>0x02</c>, text
    /// string), <c>timeoutMilliseconds</c> (<c>0x03</c>, unsigned integer) — every one Optional here;
    /// per-subcommand required-ness is enforced by the transition layer.
    /// </summary>
    /// <param name="subCommandParamsCbor">The still-encoded <c>subCommandParams</c> map bytes.</param>
    /// <returns>The three decoded members, each <see langword="null"/> when its own key is absent.</returns>
    private static (ReadOnlyMemory<byte>? TemplateId, string? TemplateFriendlyName, int? TimeoutMilliseconds) ReadSubCommandParams(
        ReadOnlyMemory<byte> subCommandParamsCbor)
    {
        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> members = CtapParameterMapReader.Read(subCommandParamsCbor);

        ReadOnlyMemory<byte>? templateId = null;
        if(members.TryGetValue(WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateId, out ReadOnlyMemory<byte> templateIdCbor))
        {
            templateId = new CborReader(templateIdCbor, CborConformanceMode.Ctap2Canonical).ReadByteString();
        }

        string? templateFriendlyName = null;
        if(members.TryGetValue(WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateFriendlyName, out ReadOnlyMemory<byte> templateFriendlyNameCbor))
        {
            templateFriendlyName = new CborReader(templateFriendlyNameCbor, CborConformanceMode.Ctap2Canonical).ReadTextString();
        }

        int? timeoutMilliseconds = null;
        if(members.TryGetValue(WellKnownCtapBioEnrollmentSubCommandParamsKeys.TimeoutMilliseconds, out ReadOnlyMemory<byte> timeoutMillisecondsCbor))
        {
            timeoutMilliseconds = checked((int)new CborReader(timeoutMillisecondsCbor, CborConformanceMode.Ctap2Canonical).ReadInt64());
        }

        return (templateId, templateFriendlyName, timeoutMilliseconds);
    }
}
