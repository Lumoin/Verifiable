using System;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapLargeBlobsRequestDelegate"/>: encodes an
/// <c>authenticatorLargeBlobs</c> request model into its CTAP2-canonical CBOR parameter map — the
/// RP/platform-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10.2: Reading and writing serialised data</see>. The request map's keys
/// (<c>get</c>=1 .. <c>pinUvAuthProtocol</c>=6) are already in ascending numeric order, so writing any
/// present member in that fixed order is sufficient — no run-time sort is needed, mirroring
/// <see cref="CtapCredentialManagementRequestCborWriter"/>'s convention. This is a TEST-SIDE inverse
/// codec: no authenticator-side production code consumes <see cref="EncodeCtapLargeBlobsRequestDelegate"/>.
/// </remarks>
public static class CtapLargeBlobsRequestCborWriter
{
    /// <summary>
    /// Encodes <paramref name="request"/> into its CTAP2-canonical CBOR parameter map bytes.
    /// Method-group-compatible with <see cref="EncodeCtapLargeBlobsRequestDelegate"/>.
    /// </summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The encoded parameter map, tagged <see cref="Fido2BufferTags.CtapLargeBlobsRequestPayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapLargeBlobsRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (request.Get is not null ? 1 : 0)
            + (request.Set is not null ? 1 : 0)
            + (request.Offset is not null ? 1 : 0)
            + (request.Length is not null ? 1 : 0)
            + (request.PinUvAuthParam is not null ? 1 : 0)
            + (request.PinUvAuthProtocol is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(request.Get is int get)
        {
            writer.WriteInt32(WellKnownCtapLargeBlobsRequestKeys.Get);
            writer.WriteInt32(get);
        }

        if(request.Set is ReadOnlyMemory<byte> set)
        {
            writer.WriteInt32(WellKnownCtapLargeBlobsRequestKeys.Set);
            writer.WriteByteString(set.Span);
        }

        if(request.Offset is int offset)
        {
            writer.WriteInt32(WellKnownCtapLargeBlobsRequestKeys.Offset);
            writer.WriteInt32(offset);
        }

        if(request.Length is int length)
        {
            writer.WriteInt32(WellKnownCtapLargeBlobsRequestKeys.Length);
            writer.WriteInt32(length);
        }

        if(request.PinUvAuthParam is ReadOnlyMemory<byte> pinUvAuthParam)
        {
            writer.WriteInt32(WellKnownCtapLargeBlobsRequestKeys.PinUvAuthParam);
            writer.WriteByteString(pinUvAuthParam.Span);
        }

        if(request.PinUvAuthProtocol is int pinUvAuthProtocol)
        {
            writer.WriteInt32(WellKnownCtapLargeBlobsRequestKeys.PinUvAuthProtocol);
            writer.WriteInt32(pinUvAuthProtocol);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapLargeBlobsRequestPayload);
    }
}
