using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapAuthenticatorConfigRequestDelegate"/>: encodes an
/// <c>authenticatorConfig</c> request model into its CTAP2-canonical CBOR parameter map — the
/// RP/platform-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">
/// CTAP 2.3, section 6.11: authenticatorConfig (0x0D)</see>. The request map's keys
/// (<c>subCommand</c>=1 .. <c>pinUvAuthParam</c>=4) are already in ascending numeric order, so writing
/// them in that fixed order is sufficient — no run-time sort is needed, mirroring
/// <see cref="CtapClientPinRequestCborWriter"/>'s convention. <c>subCommandParams</c> (<c>0x02</c>) is
/// encoded FRESH from <see cref="CtapAuthenticatorConfigRequest"/>'s own decoded convenience fields
/// (<see cref="WriteSubCommandParams"/>) — never from <see cref="CtapAuthenticatorConfigRequest.SubCommandParams"/>'s
/// raw bytes, which are a decode-side-only artifact the authenticator populates for its own message
/// reconstruction.
/// </remarks>
public static class CtapAuthenticatorConfigRequestCborWriter
{
    /// <summary>
    /// Encodes <paramref name="request"/> into its CTAP2-canonical CBOR parameter map bytes.
    /// Method-group-compatible with <see cref="EncodeCtapAuthenticatorConfigRequestDelegate"/>.
    /// </summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The encoded parameter map, tagged <see cref="Fido2BufferTags.CtapAuthenticatorConfigRequestPayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapAuthenticatorConfigRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        bool hasSubCommandParams = request.NewMinPinLength is not null || request.MinPinLengthRpIds is not null
            || request.ForceChangePin is not null || request.PinComplexityPolicy is not null;

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = 1
            + (hasSubCommandParams ? 1 : 0)
            + (request.PinUvAuthProtocol is not null ? 1 : 0)
            + (request.PinUvAuthParam is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(WellKnownCtapAuthenticatorConfigRequestKeys.SubCommand);
        writer.WriteInt32(request.SubCommand);

        if(hasSubCommandParams)
        {
            writer.WriteInt32(WellKnownCtapAuthenticatorConfigRequestKeys.SubCommandParams);
            writer.WriteEncodedValue(WriteSubCommandParams(
                request.NewMinPinLength, request.MinPinLengthRpIds, request.ForceChangePin, request.PinComplexityPolicy).Span);
        }

        if(request.PinUvAuthProtocol is int pinUvAuthProtocol)
        {
            writer.WriteInt32(WellKnownCtapAuthenticatorConfigRequestKeys.PinUvAuthProtocol);
            writer.WriteInt32(pinUvAuthProtocol);
        }

        if(request.PinUvAuthParam is ReadOnlyMemory<byte> pinUvAuthParam)
        {
            writer.WriteInt32(WellKnownCtapAuthenticatorConfigRequestKeys.PinUvAuthParam);
            writer.WriteByteString(pinUvAuthParam.Span);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapAuthenticatorConfigRequestPayload);
    }


    /// <summary>
    /// Encodes <c>setMinPINLength</c>'s own <c>subCommandParams</c> map (CTAP 2.3 §6.11.4, lines
    /// 8087-8116) from its four typed fields — the exact bytes <see cref="Write"/> embeds for that
    /// member, and (when this is the platform-side request under construction) the exact bytes the
    /// authenticatorConfig verify message's own <c>subCommandParams</c> segment must cover byte-for-byte
    /// (CTAP 2.3, line 7947).
    /// </summary>
    /// <param name="newMinPinLength">The <c>newMinPINLength</c> member (<c>0x01</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="minPinLengthRpIds">The <c>minPinLengthRPIDs</c> member (<c>0x02</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="forceChangePin">The <c>forceChangePin</c> member (<c>0x03</c>), or <see langword="null"/> to omit it.</param>
    /// <param name="pinComplexityPolicy">The <c>pinComplexityPolicy</c> member (<c>0x04</c>), or <see langword="null"/> to omit it.</param>
    /// <returns>The encoded <c>subCommandParams</c> map, tagged <see cref="Fido2BufferTags.CtapAuthenticatorConfigSubCommandParamsPayload"/>.</returns>
    public static TaggedMemory<byte> WriteSubCommandParams(
        int? newMinPinLength, IReadOnlyList<string>? minPinLengthRpIds, bool? forceChangePin, bool? pinComplexityPolicy)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (newMinPinLength is not null ? 1 : 0)
            + (minPinLengthRpIds is not null ? 1 : 0)
            + (forceChangePin is not null ? 1 : 0)
            + (pinComplexityPolicy is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(newMinPinLength is int newMinPinLengthValue)
        {
            writer.WriteInt32(WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.NewMinPinLength);
            writer.WriteInt32(newMinPinLengthValue);
        }

        if(minPinLengthRpIds is not null)
        {
            writer.WriteInt32(WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.MinPinLengthRpIds);
            writer.WriteStartArray(minPinLengthRpIds.Count);
            foreach(string rpId in minPinLengthRpIds)
            {
                writer.WriteTextString(rpId);
            }

            writer.WriteEndArray();
        }

        if(forceChangePin is bool forceChangePinValue)
        {
            writer.WriteInt32(WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.ForceChangePin);
            writer.WriteBoolean(forceChangePinValue);
        }

        if(pinComplexityPolicy is bool pinComplexityPolicyValue)
        {
            writer.WriteInt32(WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.PinComplexityPolicy);
            writer.WriteBoolean(pinComplexityPolicyValue);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapAuthenticatorConfigSubCommandParamsPayload);
    }
}
