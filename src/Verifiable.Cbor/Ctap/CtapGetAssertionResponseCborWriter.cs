using System;
using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="EncodeCtapGetAssertionResponseDelegate"/>: encodes an
/// <c>authenticatorGetAssertion</c> response model into its CTAP2-canonical CBOR payload — the
/// authenticator-side operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see>. The response's keys
/// (<c>credential</c>=1 .. <c>largeBlobKey</c>=7) are already in ascending order, so no run-time sort
/// is needed, mirroring <see cref="CtapGetInfoResponseCborWriter"/>'s own convention.
/// </remarks>
public static class CtapGetAssertionResponseCborWriter
{
    /// <summary>
    /// Encodes <paramref name="response"/> into its CTAP2-canonical CBOR payload bytes.
    /// Method-group-compatible with <see cref="EncodeCtapGetAssertionResponseDelegate"/>.
    /// </summary>
    /// <param name="response">The response model to encode.</param>
    /// <returns>The encoded payload, tagged <see cref="Fido2BufferTags.CtapGetAssertionResponsePayload"/>.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="response"/> or its <c>Credential</c> member is <see langword="null"/>.
    /// </exception>
    public static TaggedMemory<byte> Write(CtapGetAssertionResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(response.Credential);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = 3
            + (response.User is not null ? 1 : 0)
            + (response.NumberOfCredentials is not null ? 1 : 0)
            + (response.UserSelected is not null ? 1 : 0)
            + (response.LargeBlobKey is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.Credential);
        CtapCommandEntityCborCodec.WriteDescriptor(writer, response.Credential);

        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.AuthData);
        writer.WriteByteString(response.AuthData.Span);

        writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.Signature);
        writer.WriteByteString(response.Signature.Span);

        if(response.User is CtapPublicKeyCredentialUserEntity user)
        {
            writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.User);
            CtapCommandEntityCborCodec.WriteUserEntity(writer, user);
        }

        if(response.NumberOfCredentials is int numberOfCredentials)
        {
            writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.NumberOfCredentials);
            writer.WriteInt32(numberOfCredentials);
        }

        if(response.UserSelected is bool userSelected)
        {
            writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.UserSelected);
            writer.WriteBoolean(userSelected);
        }

        if(response.LargeBlobKey is ReadOnlyMemory<byte> largeBlobKey)
        {
            writer.WriteInt32(WellKnownCtapGetAssertionResponseKeys.LargeBlobKey);
            writer.WriteByteString(largeBlobKey.Span);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapGetAssertionResponsePayload);
    }
}
