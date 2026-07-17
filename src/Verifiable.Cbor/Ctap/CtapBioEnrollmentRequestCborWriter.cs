using System;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapBioEnrollmentRequestDelegate"/>: encodes an
/// <c>authenticatorBioEnrollment</c> request model into its CTAP2-canonical CBOR parameter map — the
/// RP/platform-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>. The request map's keys
/// (<c>modality</c>=1 .. <c>getModality</c>=6) are already in ascending numeric order, so writing them
/// in that fixed order is sufficient — no run-time sort is needed, mirroring
/// <see cref="CtapCredentialManagementRequestCborWriter"/>'s convention. <c>subCommandParams</c>
/// (<c>0x03</c>) is encoded FRESH from <see cref="CtapBioEnrollmentRequest"/>'s own decoded convenience
/// fields (<see cref="WriteSubCommandParams"/>) — never from <see cref="CtapBioEnrollmentRequest.SubCommandParams"/>'s
/// raw bytes, which are a decode-side-only artifact.
/// </remarks>
public static class CtapBioEnrollmentRequestCborWriter
{
    /// <summary>
    /// Encodes <paramref name="request"/> into its CTAP2-canonical CBOR parameter map bytes.
    /// Method-group-compatible with <see cref="EncodeCtapBioEnrollmentRequestDelegate"/>.
    /// </summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The encoded parameter map, tagged <see cref="Fido2BufferTags.CtapBioEnrollmentRequestPayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapBioEnrollmentRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        bool hasSubCommandParams = request.TemplateId is not null || request.TemplateFriendlyName is not null || request.TimeoutMilliseconds is not null;

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (request.Modality is not null ? 1 : 0)
            + (request.SubCommand is not null ? 1 : 0)
            + (hasSubCommandParams ? 1 : 0)
            + (request.PinUvAuthProtocol is not null ? 1 : 0)
            + (request.PinUvAuthParam is not null ? 1 : 0)
            + (request.GetModality is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(request.Modality is int modality)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentRequestKeys.Modality);
            writer.WriteInt32(modality);
        }

        if(request.SubCommand is int subCommand)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentRequestKeys.SubCommand);
            writer.WriteInt32(subCommand);
        }

        if(hasSubCommandParams)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentRequestKeys.SubCommandParams);
            writer.WriteEncodedValue(WriteSubCommandParams(request.TemplateId, request.TemplateFriendlyName, request.TimeoutMilliseconds).Span);
        }

        if(request.PinUvAuthProtocol is int pinUvAuthProtocol)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentRequestKeys.PinUvAuthProtocol);
            writer.WriteInt32(pinUvAuthProtocol);
        }

        if(request.PinUvAuthParam is ReadOnlyMemory<byte> pinUvAuthParam)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentRequestKeys.PinUvAuthParam);
            writer.WriteByteString(pinUvAuthParam.Span);
        }

        if(request.GetModality is bool getModality)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentRequestKeys.GetModality);
            writer.WriteBoolean(getModality);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapBioEnrollmentRequestPayload);
    }


    /// <summary>
    /// Encodes <c>subCommandParams</c>' own three members (CTAP 2.3 §6.7, snapshot lines 6459-6482)
    /// from their typed values — the exact bytes <see cref="Write"/> embeds for that member, and (when
    /// this is the platform-side request under construction) the exact bytes every gated subcommand's
    /// own verify message must cover byte-for-byte.
    /// </summary>
    /// <param name="templateId">The <c>templateId</c> member (<c>0x01</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="templateFriendlyName">The <c>templateFriendlyName</c> member (<c>0x02</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="timeoutMilliseconds">The <c>timeoutMilliseconds</c> member (<c>0x03</c>), or <see langword="null"/> to omit it.</param>
    /// <returns>The encoded <c>subCommandParams</c> map, tagged <see cref="Fido2BufferTags.CtapBioEnrollmentSubCommandParamsPayload"/>.</returns>
    public static TaggedMemory<byte> WriteSubCommandParams(ReadOnlyMemory<byte>? templateId, string? templateFriendlyName, int? timeoutMilliseconds)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (templateId is not null ? 1 : 0) + (templateFriendlyName is not null ? 1 : 0) + (timeoutMilliseconds is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(templateId is ReadOnlyMemory<byte> templateIdValue)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateId);
            writer.WriteByteString(templateIdValue.Span);
        }

        if(templateFriendlyName is string templateFriendlyNameValue)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateFriendlyName);
            writer.WriteTextString(templateFriendlyNameValue);
        }

        if(timeoutMilliseconds is int timeoutMillisecondsValue)
        {
            writer.WriteInt32(WellKnownCtapBioEnrollmentSubCommandParamsKeys.TimeoutMilliseconds);
            writer.WriteInt32(timeoutMillisecondsValue);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapBioEnrollmentSubCommandParamsPayload);
    }
}
