using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapGetAssertionRequestDelegate"/>: encodes an
/// <c>authenticatorGetAssertion</c> request model into its CTAP2-canonical CBOR parameter map — the
/// client/RP-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see>. The outer map's keys
/// (<c>rpId</c>=1 .. <c>pinUvAuthProtocol</c>=7) are already in ascending numeric order, so no run-time
/// sort is needed, mirroring <see cref="CtapGetInfoResponseCborWriter"/>'s own convention. Deliberately
/// capable of emitting an <c>options.rk</c> value if <see cref="CtapGetAssertionRequest.Options"/>
/// carries one — a conformant platform never does this (CTAP 2.3 forbids sending <c>rk</c> here), but a
/// capstone-level negative test needs exactly this writer to construct the wire vector that proves the
/// authenticator rejects it.
/// </remarks>
public static class CtapGetAssertionRequestCborWriter
{
    /// <summary>
    /// Encodes <paramref name="request"/> into its CTAP2-canonical CBOR parameter map bytes.
    /// Method-group-compatible with <see cref="EncodeCtapGetAssertionRequestDelegate"/>.
    /// </summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The encoded parameter map, tagged <see cref="Fido2BufferTags.CtapGetAssertionRequestPayload"/>.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="request"/>, its <c>RpId</c>, or its <c>ClientDataHash</c> member is
    /// <see langword="null"/>.
    /// </exception>
    public static TaggedMemory<byte> Write(CtapGetAssertionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.RpId);
        ArgumentNullException.ThrowIfNull(request.ClientDataHash);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = 2
            + (request.AllowList is not null ? 1 : 0)
            + (request.Extensions is not null ? 1 : 0)
            + (request.Options is not null ? 1 : 0)
            + (request.PinUvAuthParam is not null ? 1 : 0)
            + (request.PinUvAuthProtocol is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.RpId);
        writer.WriteTextString(request.RpId);

        writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.ClientDataHash);
        writer.WriteByteString(request.ClientDataHash.AsReadOnlySpan());

        if(request.AllowList is IReadOnlyList<PublicKeyCredentialDescriptor> allowList)
        {
            writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.AllowList);
            CtapCommandEntityCborCodec.WriteDescriptorArray(writer, allowList);
        }

        if(request.Extensions is ReadOnlyMemory<byte> extensions)
        {
            writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.Extensions);
            writer.WriteEncodedValue(extensions.Span);
        }

        if(request.Options is CtapCommandOptions options)
        {
            writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.Options);
            CtapCommandEntityCborCodec.WriteOptions(writer, options);
        }

        if(request.PinUvAuthParam is ReadOnlyMemory<byte> pinUvAuthParam)
        {
            writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.PinUvAuthParam);
            writer.WriteByteString(pinUvAuthParam.Span);
        }

        if(request.PinUvAuthProtocol is int pinUvAuthProtocol)
        {
            writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.PinUvAuthProtocol);
            writer.WriteInt32(pinUvAuthProtocol);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapGetAssertionRequestPayload);
    }
}
