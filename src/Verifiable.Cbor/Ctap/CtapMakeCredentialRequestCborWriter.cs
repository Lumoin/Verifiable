using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapMakeCredentialRequestDelegate"/>: encodes an
/// <c>authenticatorMakeCredential</c> request model into its CTAP2-canonical CBOR parameter map — the
/// client/RP-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>. The outer map's keys
/// (<c>clientDataHash</c>=1 .. <c>attestationFormatsPreference</c>=11) are already in ascending numeric
/// order, so writing the Required members first, then any present Optional member, in that fixed order,
/// is sufficient — no run-time sort is needed, mirroring
/// <see cref="CtapGetInfoResponseCborWriter"/>'s own convention.
/// </remarks>
public static class CtapMakeCredentialRequestCborWriter
{
    /// <summary>
    /// Encodes <paramref name="request"/> into its CTAP2-canonical CBOR parameter map bytes.
    /// Method-group-compatible with <see cref="EncodeCtapMakeCredentialRequestDelegate"/>.
    /// </summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The encoded parameter map, tagged <see cref="Fido2BufferTags.CtapMakeCredentialRequestPayload"/>.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="request"/>, its <c>ClientDataHash</c>, <c>Rp</c>, <c>User</c>, or
    /// <c>PubKeyCredParams</c> member is <see langword="null"/>.
    /// </exception>
    public static TaggedMemory<byte> Write(CtapMakeCredentialRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.ClientDataHash);
        ArgumentNullException.ThrowIfNull(request.Rp);
        ArgumentNullException.ThrowIfNull(request.User);
        ArgumentNullException.ThrowIfNull(request.PubKeyCredParams);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = 4
            + (request.ExcludeList is not null ? 1 : 0)
            + (request.Extensions is not null ? 1 : 0)
            + (request.Options is not null ? 1 : 0)
            + (request.PinUvAuthParam is not null ? 1 : 0)
            + (request.PinUvAuthProtocol is not null ? 1 : 0)
            + (request.EnterpriseAttestation is not null ? 1 : 0)
            + (request.AttestationFormatsPreference is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.ClientDataHash);
        writer.WriteByteString(request.ClientDataHash.AsReadOnlySpan());

        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.Rp);
        CtapCommandEntityCborCodec.WriteRpEntity(writer, request.Rp);

        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.User);
        CtapCommandEntityCborCodec.WriteUserEntity(writer, request.User);

        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams);
        CtapCommandEntityCborCodec.WriteParametersArray(writer, request.PubKeyCredParams);

        if(request.ExcludeList is IReadOnlyList<PublicKeyCredentialDescriptor> excludeList)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.ExcludeList);
            CtapCommandEntityCborCodec.WriteDescriptorArray(writer, excludeList);
        }

        if(request.Extensions is ReadOnlyMemory<byte> extensions)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.Extensions);
            writer.WriteEncodedValue(extensions.Span);
        }

        if(request.Options is CtapCommandOptions options)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.Options);
            CtapCommandEntityCborCodec.WriteOptions(writer, options);
        }

        if(request.PinUvAuthParam is ReadOnlyMemory<byte> pinUvAuthParam)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.PinUvAuthParam);
            writer.WriteByteString(pinUvAuthParam.Span);
        }

        if(request.PinUvAuthProtocol is int pinUvAuthProtocol)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.PinUvAuthProtocol);
            writer.WriteInt32(pinUvAuthProtocol);
        }

        if(request.EnterpriseAttestation is int enterpriseAttestation)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.EnterpriseAttestation);
            writer.WriteInt32(enterpriseAttestation);
        }

        if(request.AttestationFormatsPreference is IReadOnlyList<string> attestationFormatsPreference)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.AttestationFormatsPreference);
            CtapCommandEntityCborCodec.WriteStringArray(writer, attestationFormatsPreference);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapMakeCredentialRequestPayload);
    }
}
