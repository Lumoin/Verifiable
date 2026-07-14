using System;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapCredentialManagementRequestDelegate"/>: encodes an
/// <c>authenticatorCredentialManagement</c> request model into its CTAP2-canonical CBOR parameter map —
/// the RP/platform-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>. The request map's keys
/// (<c>subCommand</c>=1 .. <c>pinUvAuthParam</c>=4) are already in ascending numeric order, so writing
/// them in that fixed order is sufficient — no run-time sort is needed, mirroring
/// <see cref="CtapAuthenticatorConfigRequestCborWriter"/>'s convention. <c>subCommandParams</c>
/// (<c>0x02</c>) is encoded FRESH from <see cref="CtapCredentialManagementRequest"/>'s own decoded
/// convenience fields (<see cref="WriteSubCommandParams"/>) — never from
/// <see cref="CtapCredentialManagementRequest.SubCommandParams"/>'s raw bytes, which are a
/// decode-side-only artifact the authenticator populates for its own message reconstruction.
/// </remarks>
public static class CtapCredentialManagementRequestCborWriter
{
    /// <summary>
    /// Encodes <paramref name="request"/> into its CTAP2-canonical CBOR parameter map bytes.
    /// Method-group-compatible with <see cref="EncodeCtapCredentialManagementRequestDelegate"/>.
    /// </summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The encoded parameter map, tagged <see cref="Fido2BufferTags.CtapCredentialManagementRequestPayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapCredentialManagementRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        bool hasSubCommandParams = request.RpIdHash is not null || request.CredentialId is not null || request.User is not null;

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = 1
            + (hasSubCommandParams ? 1 : 0)
            + (request.PinUvAuthProtocol is not null ? 1 : 0)
            + (request.PinUvAuthParam is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(WellKnownCtapCredentialManagementRequestKeys.SubCommand);
        writer.WriteInt32(request.SubCommand);

        if(hasSubCommandParams)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementRequestKeys.SubCommandParams);
            writer.WriteEncodedValue(WriteSubCommandParams(request.RpIdHash, request.CredentialId, request.User).Span);
        }

        if(request.PinUvAuthProtocol is int pinUvAuthProtocol)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementRequestKeys.PinUvAuthProtocol);
            writer.WriteInt32(pinUvAuthProtocol);
        }

        if(request.PinUvAuthParam is ReadOnlyMemory<byte> pinUvAuthParam)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementRequestKeys.PinUvAuthParam);
            writer.WriteByteString(pinUvAuthParam.Span);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapCredentialManagementRequestPayload);
    }


    /// <summary>
    /// Encodes <c>subCommandParams</c>' own three members (CTAP 2.3 §6.8, lines 7005-7024) from their
    /// typed values — the exact bytes <see cref="Write"/> embeds for that member, and (when this is the
    /// platform-side request under construction) the exact bytes <c>enumerateCredentialsBegin</c>/
    /// <c>deleteCredential</c>/<c>updateUserInformation</c>'s own verify message must cover byte-for-byte
    /// (CTAP 2.3, lines 7265/7367/7417).
    /// </summary>
    /// <param name="rpIdHash">The <c>rpIDHash</c> member (<c>0x01</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="credentialId">The <c>credentialID</c> member (<c>0x02</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="user">The <c>user</c> member (<c>0x03</c>), or <see langword="null"/> to omit it.</param>
    /// <returns>The encoded <c>subCommandParams</c> map, tagged <see cref="Fido2BufferTags.CtapCredentialManagementSubCommandParamsPayload"/>.</returns>
    public static TaggedMemory<byte> WriteSubCommandParams(
        ReadOnlyMemory<byte>? rpIdHash, PublicKeyCredentialDescriptor? credentialId, CtapPublicKeyCredentialUserEntity? user)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (rpIdHash is not null ? 1 : 0) + (credentialId is not null ? 1 : 0) + (user is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(rpIdHash is ReadOnlyMemory<byte> rpIdHashValue)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementSubCommandParamsKeys.RpIdHash);
            writer.WriteByteString(rpIdHashValue.Span);
        }

        if(credentialId is PublicKeyCredentialDescriptor credentialIdValue)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementSubCommandParamsKeys.CredentialId);
            CtapCommandEntityCborCodec.WriteDescriptor(writer, credentialIdValue);
        }

        if(user is CtapPublicKeyCredentialUserEntity userValue)
        {
            writer.WriteInt32(WellKnownCtapCredentialManagementSubCommandParamsKeys.User);
            CtapCommandEntityCborCodec.WriteUserEntity(writer, userValue);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapCredentialManagementSubCommandParamsPayload);
    }
}
