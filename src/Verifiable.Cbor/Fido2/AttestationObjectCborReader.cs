using System.Formats.Cbor;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// The shipped default for <see cref="ParseAttestationObjectDelegate"/>: splits a WebAuthn
/// <c>attestationObject</c>'s CBOR bytes into its <c>fmt</c>/<c>attStmt</c>/<c>authData</c> parts
/// using System.Formats.Cbor.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-generating-an-attestation-object">W3C Web
/// Authentication Level 3, section 6.5.4: Generating an Attestation Object</see> defines the
/// <c>attestationObject</c> as a CBOR map with exactly the members <c>authData</c>, <c>fmt</c>, and
/// <c>attStmt</c> (its <c>attObj</c> / <c>attStmtTemplate</c> CDDL) — no other member is permitted and
/// none may repeat. Per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All
/// Conformance Classes</see>, "All CBOR encoding ... MUST be done using the CTAP2 canonical CBOR
/// encoding form ... All decoders ... SHOULD reject CBOR that is not validly encoded in the CTAP2
/// canonical CBOR encoding form and SHOULD reject messages with duplicate map keys." Reading with
/// <see cref="CborConformanceMode.Ctap2Canonical"/> already rejects a duplicate or out-of-order map
/// key at the framework level; this reader additionally rejects an unrecognised member, a missing
/// required member, or trailing bytes beyond the single root-level <c>attestationObject</c> map —
/// violations the conformance mode itself does not know to check — naming the specific violation in
/// every case.
/// </para>
/// <para>
/// <see cref="AttestationObjectParts.AttestationStatement"/> and
/// <see cref="AttestationObjectParts.AuthenticatorData"/> both alias the buffer passed to
/// <see cref="Parse"/> — no bytes are copied.
/// </para>
/// </remarks>
public static class AttestationObjectCborReader
{
    /// <summary>The CBOR map key for the attestation statement format identifier.</summary>
    private const string FormatKey = "fmt";

    /// <summary>The CBOR map key for the attestation statement.</summary>
    private const string AttestationStatementKey = "attStmt";

    /// <summary>The CBOR map key for the authenticator data byte string.</summary>
    private const string AuthenticatorDataKey = "authData";


    /// <summary>
    /// Splits <paramref name="attestationObject"/> into its <c>fmt</c>/<c>attStmt</c>/<c>authData</c>
    /// parts. Method-group-compatible with <see cref="ParseAttestationObjectDelegate"/>.
    /// </summary>
    /// <param name="attestationObject">The raw CBOR bytes of the <c>attestationObject</c>.</param>
    /// <returns>The decoded, alias-sliced parts.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="attestationObject"/> is not a CTAP2 canonical CBOR map carrying exactly the
    /// <c>fmt</c>, <c>attStmt</c>, and <c>authData</c> members with no trailing bytes.
    /// </exception>
    public static AttestationObjectParts Parse(ReadOnlyMemory<byte> attestationObject)
    {
        try
        {
            var reader = new CborReader(attestationObject, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            string? format = null;
            ReadOnlyMemory<byte>? attestationStatement = null;
            ReadOnlyMemory<byte>? authenticatorData = null;

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string key = reader.ReadTextString();
                entriesRead++;

                switch(key)
                {
                    case(FormatKey):
                    {
                        format = reader.ReadTextString();
                        break;
                    }
                    case(AttestationStatementKey):
                    {
                        attestationStatement = reader.ReadEncodedValue();
                        break;
                    }
                    case(AuthenticatorDataKey):
                    {
                        authenticatorData = ReadByteStringContentsAsSlice(reader);
                        break;
                    }
                    default:
                    {
                        throw new Fido2FormatException($"The attestationObject map carries the unrecognised member '{key}'; only 'fmt', 'attStmt', and 'authData' are permitted.");
                    }
                }
            }

            reader.ReadEndMap();

            if(reader.BytesRemaining != 0)
            {
                throw new Fido2FormatException($"The attestationObject buffer carries {reader.BytesRemaining} trailing byte(s) beyond its single CBOR map.");
            }

            if(format is null || attestationStatement is null || authenticatorData is null)
            {
                throw new Fido2FormatException("The attestationObject map is missing one or more of the required 'fmt', 'attStmt', and 'authData' members.");
            }

            return new AttestationObjectParts(format, attestationStatement.Value, authenticatorData.Value);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException or FormatException)
        {
            throw new Fido2FormatException("The attestationObject bytes are not valid CTAP2 canonical CBOR conforming to the attestationObject syntax.", exception);
        }

        //Reads the CBOR byte string at the reader's current position and returns a slice of the
        //original buffer covering only its content bytes (no header), so the caller receives an
        //aliasing view rather than a copy. The probe-reader pass mirrors EncodedCborItem.Read: the
        //byte string's content bytes always occupy the tail of its own encoded value for the
        //definite-length encoding CTAP2 canonical CBOR requires, so subtracting the decoded content
        //length from the encoded value's length locates the content's start offset.
        static ReadOnlyMemory<byte> ReadByteStringContentsAsSlice(CborReader reader)
        {
            ReadOnlyMemory<byte> encodedByteString = reader.ReadEncodedValue();
            var probe = new CborReader(encodedByteString);
            byte[] contents = probe.ReadByteString();
            int contentOffset = encodedByteString.Length - contents.Length;

            return encodedByteString.Slice(contentOffset, contents.Length);
        }
    }
}
