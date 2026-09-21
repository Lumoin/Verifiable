using Lumoin.Veritas.Cbor;
using System.Buffers;
using Verifiable.Cbor.Fido2;
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
/// <see cref="CtapGetInfoResponseCborWriter"/>'s own convention. <see cref="CtapMakeCredentialRequest.Extensions"/>,
/// when present, is the wire truth and is written verbatim, exactly as it arrived — a request built from
/// a decoded wire message carries both the raw bytes and the decoded convenience members, and the raw
/// bytes win. When <see cref="CtapMakeCredentialRequest.Extensions"/> is absent, the <c>extensions</c> map
/// is instead built from whichever of <see cref="CtapMakeCredentialRequest.CredProtect"/>,
/// <see cref="CtapMakeCredentialRequest.HmacSecret"/>, <see cref="CtapMakeCredentialRequest.LargeBlobKey"/>,
/// <see cref="CtapMakeCredentialRequest.MinPinLength"/>, and <see cref="CtapMakeCredentialRequest.HmacSecretMc"/>
/// are set, in CTAP2-canonical shorter-key-first order (ties broken bytewise, RFC 8949 §4.2.1):
/// <c>"credProtect"</c> (11 characters) &lt; <c>"hmac-secret"</c> (11 characters, tie broken by <c>'c'</c>
/// 0x63 &lt; <c>'h'</c> 0x68) &lt; <c>"largeBlobKey"</c> (12 characters) &lt; <c>"minPinLength"</c> (12
/// characters, tie broken by <c>'l'</c> &lt; <c>'m'</c>) &lt; <c>"hmac-secret-mc"</c> (14 characters,
/// strictly longest, sorts LAST regardless of its shared <c>hmac-secret</c> prefix) — the same fixed
/// order <see cref="CtapMakeCredentialExtensionOutputsCborWriter"/> already applies on the response side.
/// When neither the raw bytes nor any decoded member is set, no <c>extensions</c> member is written at all.
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

        bool hasExtensions = request.Extensions is not null
            || request.CredProtect is not null
            || request.MinPinLength is not null
            || request.LargeBlobKey is not null
            || request.HmacSecret is not null
            || request.HmacSecretMc is not null;

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Ctap2Canonical);

        int memberCount = 4
            + (request.ExcludeList is not null ? 1 : 0)
            + (hasExtensions ? 1 : 0)
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

        if(hasExtensions)
        {
            writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.Extensions);

            if(request.Extensions is ReadOnlyMemory<byte> extensions)
            {
                writer.WriteEncodedValue(extensions.Span);
            }
            else
            {
                WriteExtensionsMap(writer, request.CredProtect, request.HmacSecret, request.LargeBlobKey, request.MinPinLength, request.HmacSecretMc);
            }
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

        byte[] encoded = buffer.WrittenSpan.ToArray();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapMakeCredentialRequestPayload);
    }

    /// <summary>
    /// Writes the <c>extensions</c> map body from whichever of <paramref name="credProtect"/>,
    /// <paramref name="hmacSecret"/>, <paramref name="largeBlobKey"/>, <paramref name="minPinLength"/>,
    /// and <paramref name="hmacSecretMc"/> are set, in the class's own documented CTAP2-canonical
    /// shorter-key-first order. Called only when at least one is set; <c>writer</c> is positioned
    /// immediately after the outer map's <c>extensions</c> key.
    /// </summary>
    private static void WriteExtensionsMap(
        CborWriter writer, int? credProtect, bool? hmacSecret, bool? largeBlobKey, bool? minPinLength, CtapGetAssertionHmacSecretInput? hmacSecretMc)
    {
        int memberCount = (credProtect is not null ? 1 : 0) + (hmacSecret is not null ? 1 : 0)
            + (largeBlobKey is not null ? 1 : 0) + (minPinLength is not null ? 1 : 0) + (hmacSecretMc is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        if(credProtect is int credProtectValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.CredProtect);
            writer.WriteInt32(credProtectValue);
        }

        if(hmacSecret is bool hmacSecretValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecret);
            writer.WriteBoolean(hmacSecretValue);
        }

        if(largeBlobKey is bool largeBlobKeyValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey);
            writer.WriteBoolean(largeBlobKeyValue);
        }

        if(minPinLength is bool minPinLengthValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.MinPinLength);
            writer.WriteBoolean(minPinLengthValue);
        }

        if(hmacSecretMc is CtapGetAssertionHmacSecretInput hmacSecretMcValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc);

            int innerMemberCount = 3 + (hmacSecretMcValue.PinUvAuthProtocol is not null ? 1 : 0);
            writer.WriteStartMap(innerMemberCount);
            writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.KeyAgreement);
            writer.WriteEncodedValue(CredentialPublicKeyCborWriter.Write(hmacSecretMcValue.KeyAgreement).Span);
            writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.SaltEnc);
            writer.WriteByteString(hmacSecretMcValue.SaltEnc.Span);
            writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.SaltAuth);
            writer.WriteByteString(hmacSecretMcValue.SaltAuth.Span);
            if(hmacSecretMcValue.PinUvAuthProtocol is int hmacSecretMcProtocolValue)
            {
                writer.WriteInt32(WellKnownCtapHmacSecretExtensionKeys.PinUvAuthProtocol);
                writer.WriteInt32(hmacSecretMcProtocolValue);
            }

            writer.WriteEndMap();
        }

        writer.WriteEndMap();
    }
}
