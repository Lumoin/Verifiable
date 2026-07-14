using System.Formats.Cbor;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// The shipped default for <see cref="Verifiable.Fido2.Ctap.EncodeCtapGetAssertionExtensionOutputsDelegate"/>:
/// encodes the resolved <c>hmac-secret</c> authenticator extension output value into the
/// <c>authenticatorGetAssertion</c> authData <c>extensions</c> CBOR map — the authenticator-side
/// operation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion</see>. This writer's single possible key,
/// <c>"hmac-secret"</c>, needs no run-time sort (a one-member map is trivially canonical). Returns
/// <see cref="TaggedMemory{T}.Empty"/> — never an encoded empty CBOR map (<c>0xA0</c>) — when
/// <c>hmacSecret</c> is absent, keeping the caller's <c>ED</c> flag at zero: every pre-existing
/// <c>authenticatorGetAssertion</c> test's authData bytes are BYTE-IDENTICAL to before this writer
/// existed (trap 16).
/// </remarks>
public static class CtapGetAssertionExtensionOutputsCborWriter
{
    /// <summary>
    /// Encodes <paramref name="hmacSecret"/> into the authData <c>extensions</c> CBOR map bytes.
    /// Method-group-compatible with
    /// <see cref="Verifiable.Fido2.Ctap.EncodeCtapGetAssertionExtensionOutputsDelegate"/>.
    /// </summary>
    /// <param name="hmacSecret">The encrypted <c>hmac-secret</c> output bytes, or <see langword="null"/> to omit the key.</param>
    /// <returns>
    /// The encoded map, tagged <see cref="Fido2BufferTags.CtapGetAssertionExtensionOutputsPayload"/>;
    /// <see cref="TaggedMemory{T}.Empty"/> when <paramref name="hmacSecret"/> is <see langword="null"/>.
    /// </returns>
    public static TaggedMemory<byte> Write(ReadOnlyMemory<byte>? hmacSecret)
    {
        if(hmacSecret is null)
        {
            return TaggedMemory<byte>.Empty;
        }

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);

        writer.WriteStartMap(1);
        writer.WriteTextString(WellKnownWebAuthnExtensionIdentifiers.HmacSecret);
        writer.WriteByteString(hmacSecret.Value.Span);
        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CtapGetAssertionExtensionOutputsPayload);
    }
}
