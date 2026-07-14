using System;
using System.Formats.Cbor;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.JCose;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapClientPinRequestDelegate"/>: encodes an
/// <c>authenticatorClientPIN</c> request model into its CTAP2-canonical CBOR parameter map — the
/// RP/platform-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN (0x06) Command Definition</see>. The request map's
/// keys (<c>pinUvAuthProtocol</c>=1 .. <c>rpId</c>=0x0A) are already in ascending numeric order, so
/// writing <c>subCommand</c> and any present Optional member in that fixed order is sufficient — no
/// run-time sort is needed, mirroring <see cref="CtapMakeCredentialRequestCborWriter"/>'s convention.
/// <c>keyAgreement</c>'s nested COSE_Key reuses <see cref="CredentialPublicKeyCborWriter"/> — the same
/// already-shipped, already-canonical COSE_Key encoder <c>attestedCredentialData</c> uses — spliced in
/// via <see cref="CborWriter.WriteEncodedValue(ReadOnlySpan{byte})"/> rather than a second COSE_Key
/// writer.
/// </remarks>
public static class CtapClientPinRequestCborWriter
{
    /// <summary>
    /// Encodes <paramref name="request"/> into its CTAP2-canonical CBOR parameter map bytes.
    /// Method-group-compatible with <see cref="EncodeCtapClientPinRequestDelegate"/>.
    /// </summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The encoded parameter map, tagged <see cref="Fido2BufferTags.CtapClientPinRequestPayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapClientPinRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = 1
            + (request.PinUvAuthProtocol is not null ? 1 : 0)
            + (request.KeyAgreement is not null ? 1 : 0)
            + (request.PinUvAuthParam is not null ? 1 : 0)
            + (request.NewPinEnc is not null ? 1 : 0)
            + (request.PinHashEnc is not null ? 1 : 0)
            + (request.Permissions is not null ? 1 : 0)
            + (request.RpId is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(request.PinUvAuthProtocol is int pinUvAuthProtocol)
        {
            writer.WriteInt32(WellKnownCtapClientPinRequestKeys.PinUvAuthProtocol);
            writer.WriteInt32(pinUvAuthProtocol);
        }

        writer.WriteInt32(WellKnownCtapClientPinRequestKeys.SubCommand);
        writer.WriteInt32(request.SubCommand);

        if(request.KeyAgreement is CoseKey keyAgreement)
        {
            writer.WriteInt32(WellKnownCtapClientPinRequestKeys.KeyAgreement);
            writer.WriteEncodedValue(CredentialPublicKeyCborWriter.Write(keyAgreement).Span);
        }

        if(request.PinUvAuthParam is ReadOnlyMemory<byte> pinUvAuthParam)
        {
            writer.WriteInt32(WellKnownCtapClientPinRequestKeys.PinUvAuthParam);
            writer.WriteByteString(pinUvAuthParam.Span);
        }

        if(request.NewPinEnc is ReadOnlyMemory<byte> newPinEnc)
        {
            writer.WriteInt32(WellKnownCtapClientPinRequestKeys.NewPinEnc);
            writer.WriteByteString(newPinEnc.Span);
        }

        if(request.PinHashEnc is ReadOnlyMemory<byte> pinHashEnc)
        {
            writer.WriteInt32(WellKnownCtapClientPinRequestKeys.PinHashEnc);
            writer.WriteByteString(pinHashEnc.Span);
        }

        if(request.Permissions is int permissions)
        {
            writer.WriteInt32(WellKnownCtapClientPinRequestKeys.Permissions);
            writer.WriteInt32(permissions);
        }

        if(request.RpId is string rpId)
        {
            writer.WriteInt32(WellKnownCtapClientPinRequestKeys.RpId);
            writer.WriteTextString(rpId);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapClientPinRequestPayload);
    }
}
