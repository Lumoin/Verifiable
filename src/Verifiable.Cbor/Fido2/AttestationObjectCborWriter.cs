using System.Formats.Cbor;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// The shipped default for encoding a WebAuthn <c>attestationObject</c> — the production counterpart
/// to <see cref="AttestationObjectCborReader"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-generating-an-attestation-object">W3C Web
/// Authentication Level 3, section 6.5.4: Generating an Attestation Object</see> defines the
/// <c>attestationObject</c> as a CBOR map with exactly the members <c>fmt</c>, <c>attStmt</c>, and
/// <c>authData</c> — no other member, none repeated. Written with
/// <see cref="CborConformanceMode.Ctap2Canonical"/> per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All
/// Conformance Classes</see>.
/// </para>
/// <para>
/// <paramref name="attestationStatement"/> is spliced in verbatim via
/// <see cref="CborWriter.WriteEncodedValue(ReadOnlySpan{byte})"/> — it is already CBOR-encoded by the
/// caller's chosen attestation-format writer (for example the single byte
/// <see cref="NoneAttestation.CanonicalEmptyMap"/> for <c>fmt=none</c>), exactly the nested-item shape
/// <see cref="AttestationObjectCborReader.Parse"/> reads back via <see cref="CborReader.ReadEncodedValue"/>.
/// <paramref name="authenticatorData"/>, by contrast, is raw <c>authData</c> bytes wrapped in a CBOR byte
/// string via <see cref="CborWriter.WriteByteString(ReadOnlySpan{byte})"/> — the reader's own
/// byte-string-peeling helper confirms this member is a byte string wrapper around the content, not a
/// nested CBOR item.
/// </para>
/// </remarks>
public static class AttestationObjectCborWriter
{
    /// <summary>The CBOR map key for the attestation statement format identifier.</summary>
    private const string FormatKey = "fmt";

    /// <summary>The CBOR map key for the attestation statement.</summary>
    private const string AttestationStatementKey = "attStmt";

    /// <summary>The CBOR map key for the authenticator data byte string.</summary>
    private const string AuthenticatorDataKey = "authData";


    /// <summary>
    /// Encodes an <c>attestationObject</c> from its three parts.
    /// </summary>
    /// <param name="format">The <c>fmt</c> value — an IANA-registered attestation statement format identifier.</param>
    /// <param name="attestationStatement">
    /// The already CBOR-encoded <c>attStmt</c> bytes, spliced in verbatim (see the type-level remarks).
    /// </param>
    /// <param name="authenticatorData">The raw <c>authData</c> bytes, wrapped in a CBOR byte string.</param>
    /// <returns>The encoded <c>attestationObject</c> bytes, tagged <see cref="Fido2BufferTags.AttestationObjectPayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="format"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="attestationStatement"/> or <paramref name="authenticatorData"/> is empty.
    /// </exception>
    public static TaggedMemory<byte> Write(string format, ReadOnlyMemory<byte> attestationStatement, ReadOnlyMemory<byte> authenticatorData)
    {
        ArgumentNullException.ThrowIfNull(format);

        if(attestationStatement.IsEmpty)
        {
            throw new ArgumentException("The attestation statement must be at least one byte (the canonical CBOR encoding of an empty map is itself one byte).", nameof(attestationStatement));
        }

        if(authenticatorData.IsEmpty)
        {
            throw new ArgumentException("The authenticator data must be at least the section 6.1 minimum layout.", nameof(authenticatorData));
        }

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);

        writer.WriteTextString(FormatKey);
        writer.WriteTextString(format);

        writer.WriteTextString(AttestationStatementKey);
        writer.WriteEncodedValue(attestationStatement.Span);

        writer.WriteTextString(AuthenticatorDataKey);
        writer.WriteByteString(authenticatorData.Span);

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.AttestationObjectPayload);
    }
}
