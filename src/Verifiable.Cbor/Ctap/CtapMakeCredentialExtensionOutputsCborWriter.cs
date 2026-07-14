using System.Formats.Cbor;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="Verifiable.Fido2.Ctap.EncodeCtapMakeCredentialExtensionOutputsDelegate"/>:
/// encodes the resolved <c>credProtect</c>/<c>hmac-secret</c>/<c>minPinLength</c>/<c>hmac-secret-mc</c>
/// authenticator extension output values into the authData <c>extensions</c> CBOR map — the
/// authenticator-side operation.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1.2: authenticatorMakeCredential Algorithm</see>, lines 3555-3557: the
/// authenticator extension outputs map is CTAP2-canonical CBOR, keyed by extension identifier — sorted
/// shorter-key-first, ties broken bytewise (RFC 8949 §4.2.1). This writer's four possible keys sort
/// <c>"credProtect"</c> (11 characters) &lt; <c>"hmac-secret"</c> (11 characters, tie broken by
/// <c>'c'</c> 0x63 &lt; <c>'h'</c> 0x68) &lt; <c>"minPinLength"</c> (12 characters) &lt;
/// <c>"hmac-secret-mc"</c> (14 characters) — <c>hmac-secret-mc</c> sorts LAST, despite sharing
/// <c>hmac-secret</c>'s name prefix, purely because it is the longest key. Writing the four slots in
/// exactly this fixed order whenever each is present is sufficient to satisfy the canonical sort rule —
/// no run-time sort is needed, mirroring <see cref="CtapGetInfoResponseCborWriter"/>'s own fixed-order
/// convention. When only <paramref name="credProtect"/>/<paramref name="minPinLength"/> are non-null, the
/// emitted bytes are BYTE-IDENTICAL to a plain two-slot encoding of just those two values (trap 17's
/// byte-fence) — <paramref name="hmacSecret"/>/<paramref name="hmacSecretMc"/> contribute no map entry
/// when absent, so their presence in this four-slot signature never perturbs the two-slot case's bytes.
/// </para>
/// <para>
/// Returns <see cref="TaggedMemory{T}.Empty"/> — never an encoded empty CBOR map (<c>0xA0</c>) — when
/// every parameter is absent: CTAP 2.3, section 12.1 line 12648's MUST NOT (no unsolicited
/// <c>credProtect</c> output), section 12.5's own "ignores the extension and does not return any
/// authenticator extension output" (an unauthorized <c>minPinLength</c> request), and this
/// authenticator's own hmac-secret/hmac-secret-mc call sites (contract R3/R6) all resolve to the KEY
/// being absent, and when every requested key is absent the whole map is absent, keeping the caller's
/// <c>ED</c> flag at zero rather than emitting a present-but-empty map <see cref="AuthenticatorDataReader"/>
/// would still have to parse.
/// </para>
/// </remarks>
public static class CtapMakeCredentialExtensionOutputsCborWriter
{
    /// <summary>
    /// Encodes <paramref name="credProtect"/>/<paramref name="hmacSecret"/>/<paramref name="minPinLength"/>/
    /// <paramref name="hmacSecretMc"/> into the authData <c>extensions</c> CBOR map bytes, in canonical
    /// key order. Method-group-compatible with
    /// <see cref="Verifiable.Fido2.Ctap.EncodeCtapMakeCredentialExtensionOutputsDelegate"/>.
    /// </summary>
    /// <param name="credProtect">The <c>credProtect</c> output value, or <see langword="null"/> to omit the key.</param>
    /// <param name="hmacSecret">The <c>hmac-secret</c> annotation, or <see langword="null"/> to omit the key. Faithful to a literal <see langword="false"/> if given one.</param>
    /// <param name="minPinLength">The <c>minPinLength</c> output value, or <see langword="null"/> to omit the key.</param>
    /// <param name="hmacSecretMc">The encrypted <c>hmac-secret-mc</c> output bytes, or <see langword="null"/> to omit the key.</param>
    /// <returns>
    /// The encoded map, tagged <see cref="Fido2BufferTags.CtapMakeCredentialExtensionOutputsPayload"/>;
    /// <see cref="TaggedMemory{T}.Empty"/> when every parameter is <see langword="null"/>.
    /// </returns>
    public static TaggedMemory<byte> Write(int? credProtect, bool? hmacSecret, int? minPinLength, ReadOnlyMemory<byte>? hmacSecretMc)
    {
        if(credProtect is null && hmacSecret is null && minPinLength is null && hmacSecretMc is null)
        {
            return TaggedMemory<byte>.Empty;
        }

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        int memberCount = (credProtect is not null ? 1 : 0) + (hmacSecret is not null ? 1 : 0)
            + (minPinLength is not null ? 1 : 0) + (hmacSecretMc is not null ? 1 : 0);
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

        if(minPinLength is int minPinLengthValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.MinPinLength);
            writer.WriteInt32(minPinLengthValue);
        }

        if(hmacSecretMc is ReadOnlyMemory<byte> hmacSecretMcValue)
        {
            writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc);
            writer.WriteByteString(hmacSecretMcValue.Span);
        }

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapMakeCredentialExtensionOutputsPayload);
    }
}
