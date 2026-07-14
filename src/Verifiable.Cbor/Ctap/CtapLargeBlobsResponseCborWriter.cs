using System;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapLargeBlobsResponseDelegate"/>: encodes an
/// <c>authenticatorLargeBlobs</c> <c>get</c> response model into its CTAP2-canonical CBOR payload bytes —
/// the authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10.2: Reading and writing serialised data</see>, the response structure table
/// (lines 7688-7697). The smallest writer this library ships: exactly one Required member, always
/// written, no presence checks — unlike every other response writer's variable member count.
/// </remarks>
public static class CtapLargeBlobsResponseCborWriter
{
    /// <summary>
    /// Encodes <paramref name="response"/> into its CTAP2-canonical CBOR payload bytes.
    /// Method-group-compatible with <see cref="EncodeCtapLargeBlobsResponseDelegate"/>.
    /// </summary>
    /// <param name="response">The response model to encode.</param>
    /// <returns>The encoded payload, tagged <see cref="Fido2BufferTags.CtapLargeBlobsResponsePayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="response"/> is <see langword="null"/>.</exception>
    public static TaggedMemory<byte> Write(CtapLargeBlobsResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapLargeBlobsResponseKeys.Config);
        writer.WriteByteString(response.Config.Span);
        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapLargeBlobsResponsePayload);
    }
}
