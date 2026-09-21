using Lumoin.Veritas.Cbor;
using System.Buffers;
using Verifiable.Cbor.Fido2;
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
/// authenticator rejects it. <see cref="CtapGetAssertionRequest.Extensions"/>, when present, is the wire
/// truth and is written verbatim — a request built from a decoded wire message carries both the raw
/// bytes and the decoded convenience members, and the raw bytes win. When
/// <see cref="CtapGetAssertionRequest.Extensions"/> is absent, the <c>extensions</c> map is instead built
/// from whichever of <see cref="CtapGetAssertionRequest.HmacSecret"/> and
/// <see cref="CtapGetAssertionRequest.LargeBlobKey"/> are set, in CTAP2-canonical shorter-key-first order
/// (RFC 8949 §4.2.1): <c>"hmac-secret"</c> (11 characters) before <c>"largeBlobKey"</c> (12 characters).
/// When neither the raw bytes nor either decoded member is set, no <c>extensions</c> member is written.
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

        bool hasExtensions = request.Extensions is not null || request.LargeBlobKey is not null || request.HmacSecret is not null;

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Ctap2Canonical);

        int memberCount = 2
            + (request.AllowList is not null ? 1 : 0)
            + (hasExtensions ? 1 : 0)
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

        if(hasExtensions)
        {
            writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.Extensions);

            if(request.Extensions is ReadOnlyMemory<byte> extensions)
            {
                writer.WriteEncodedValue(extensions.Span);
            }
            else
            {
                WriteExtensionsMap(writer, request.HmacSecret, request.LargeBlobKey);
            }
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

        byte[] encoded = buffer.WrittenSpan.ToArray();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapGetAssertionRequestPayload);
    }

    /// <summary>
    /// Writes the <c>extensions</c> map body from whichever of <paramref name="hmacSecret"/> and
    /// <paramref name="largeBlobKey"/> are set, in the class's own documented CTAP2-canonical
    /// shorter-key-first order. Called only when at least one is set; <c>writer</c> is positioned
    /// immediately after the outer map's <c>extensions</c> key.
    /// </summary>
    private static void WriteExtensionsMap(CborWriter writer, CtapGetAssertionHmacSecretInput? hmacSecret, bool? largeBlobKey)
    {
        int memberCount = (hmacSecret is not null ? 1 : 0) + (largeBlobKey is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(hmacSecret is CtapGetAssertionHmacSecretInput hmacSecretValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecret);

            int innerMemberCount = 3 + (hmacSecretValue.PinUvAuthProtocol is not null ? 1 : 0);
            writer.WriteStartMap(innerMemberCount);
            writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.KeyAgreement);
            writer.WriteEncodedValue(CredentialPublicKeyCborWriter.Write(hmacSecretValue.KeyAgreement).Span);
            writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.SaltEnc);
            writer.WriteByteString(hmacSecretValue.SaltEnc.Span);
            writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.SaltAuth);
            writer.WriteByteString(hmacSecretValue.SaltAuth.Span);
            if(hmacSecretValue.PinUvAuthProtocol is int pinUvAuthProtocolValue)
            {
                writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.PinUvAuthProtocol);
                writer.WriteInt32(pinUvAuthProtocolValue);
            }

            writer.WriteEndMap();
        }

        if(largeBlobKey is bool largeBlobKeyValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey);
            writer.WriteBoolean(largeBlobKeyValue);
        }

        writer.WriteEndMap();
    }
}
