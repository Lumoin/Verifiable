using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// The shipped default for encoding a <see cref="CoseKey"/> <c>credentialPublicKey</c> — the production
/// counterpart to <see cref="CredentialPublicKeyCborReader"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication
/// Level 3, section 6.5.1: Attested Credential Data</see>: "credentialPublicKey ... The credential
/// public key encoded in COSE_Key format, as defined in Section 7 of [RFC9052], using the CTAP2
/// canonical CBOR encoding form." This writer emits with
/// <see cref="CborConformanceMode.Ctap2Canonical"/> and supports the same three key types
/// <see cref="CredentialPublicKeyCborReader"/> reads — EC2, OKP, and RSA
/// (<see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>).
/// </para>
/// <para>
/// Map entries are emitted in a convenient order (<c>kty</c>, <c>alg</c>, then the key-type-specific
/// parameters) rather than pre-sorted — <see cref="CborConformanceMode.Ctap2Canonical"/> itself sorts
/// the map's entries into canonical order when the map is closed, exactly as
/// <see cref="Verifiable.Cbor.Mdoc.MdocCborCoseKeyWriter"/> already relies on for its own
/// <see cref="CborConformanceMode.Canonical"/> map.
/// </para>
/// </remarks>
public static class CredentialPublicKeyCborWriter
{
    /// <summary>
    /// Encodes <paramref name="coseKey"/> as CTAP2 canonical COSE_Key CBOR.
    /// </summary>
    /// <param name="coseKey">The parsed COSE_Key view to encode.</param>
    /// <returns>The encoded COSE_Key bytes, tagged <see cref="Fido2BufferTags.CredentialPublicKeyPayload"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="coseKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="coseKey"/>'s <see cref="CoseKey.Kty"/> is not one of
    /// <see cref="CoseKeyTypes.Ec2"/>, <see cref="CoseKeyTypes.Okp"/>, or <see cref="CoseKeyTypes.Rsa"/>.
    /// </exception>
    public static TaggedMemory<byte> Write(CoseKey coseKey)
    {
        ArgumentNullException.ThrowIfNull(coseKey);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(CountEntries(coseKey));

        writer.WriteInt32(CoseKeyParameters.Kty);
        writer.WriteInt32(coseKey.Kty);

        if(coseKey.Alg is int alg)
        {
            writer.WriteInt32(CoseKeyParameters.Alg);
            writer.WriteInt32(alg);
        }

        _ = coseKey.Kty switch
        {
            CoseKeyTypes.Ec2 => WriteEc2Parameters(writer, coseKey),
            CoseKeyTypes.Okp => WriteOkpParameters(writer, coseKey),
            CoseKeyTypes.Rsa => WriteRsaParameters(writer, coseKey),
            _ => throw UnsupportedKeyType(coseKey.Kty)
        };

        writer.WriteEndMap();

        byte[] encoded = writer.Encode();

        return new TaggedMemory<byte>(encoded, Fido2BufferTags.CredentialPublicKeyPayload);

        //Writes the EC2 key type's crv/x/y parameters, choosing the compressed sign-bit encoding for
        //y when the key carries one instead of an uncompressed coordinate — mirrors
        //CredentialPublicKeyCborReader's own EC2 "y" duality.
        static int WriteEc2Parameters(CborWriter writer, CoseKey coseKey)
        {
            if(coseKey.Curve is int curve)
            {
                writer.WriteInt32(CoseKeyParameters.Crv);
                writer.WriteInt32(curve);
            }

            if(coseKey.X is ReadOnlyMemory<byte> x)
            {
                writer.WriteInt32(CoseKeyParameters.X);
                writer.WriteByteString(x.Span);
            }

            if(coseKey.Y is ReadOnlyMemory<byte> y)
            {
                writer.WriteInt32(CoseKeyParameters.Y);
                writer.WriteByteString(y.Span);
            }
            else if(coseKey.EncodedYCompressionSign is bool sign)
            {
                writer.WriteInt32(CoseKeyParameters.Y);
                writer.WriteBoolean(sign);
            }

            return 0;
        }

        //Writes the OKP key type's crv/x parameters (no y for octet key pairs).
        static int WriteOkpParameters(CborWriter writer, CoseKey coseKey)
        {
            if(coseKey.Curve is int curve)
            {
                writer.WriteInt32(CoseKeyParameters.Crv);
                writer.WriteInt32(curve);
            }

            if(coseKey.X is ReadOnlyMemory<byte> x)
            {
                writer.WriteInt32(CoseKeyParameters.X);
                writer.WriteByteString(x.Span);
            }

            return 0;
        }

        //Writes the RSA key type's n/e parameters per RFC 8230 §4, overloading the crv/x labels.
        static int WriteRsaParameters(CborWriter writer, CoseKey coseKey)
        {
            if(coseKey.N is ReadOnlyMemory<byte> n)
            {
                writer.WriteInt32(CoseKeyParameters.RsaN);
                writer.WriteByteString(n.Span);
            }

            if(coseKey.E is ReadOnlyMemory<byte> e)
            {
                writer.WriteInt32(CoseKeyParameters.RsaE);
                writer.WriteByteString(e.Span);
            }

            return 0;
        }

        //Counts the map entries this write will emit: kty always, alg when present, plus the
        //key-type-specific parameters present on `coseKey`.
        static int CountEntries(CoseKey coseKey)
        {
            int count = 1 + (coseKey.Alg is not null ? 1 : 0);

            count += coseKey.Kty switch
            {
                CoseKeyTypes.Ec2 => (coseKey.Curve is not null ? 1 : 0)
                    + (coseKey.X is not null ? 1 : 0)
                    + (coseKey.Y is not null || coseKey.EncodedYCompressionSign is not null ? 1 : 0),
                CoseKeyTypes.Okp => (coseKey.Curve is not null ? 1 : 0) + (coseKey.X is not null ? 1 : 0),
                CoseKeyTypes.Rsa => (coseKey.N is not null ? 1 : 0) + (coseKey.E is not null ? 1 : 0),
                _ => throw UnsupportedKeyType(coseKey.Kty)
            };

            return count;
        }

        //Builds the exception a caller-supplied CoseKey carrying an unsupported kty is rejected with.
        static ArgumentException UnsupportedKeyType(int kty) => new(
            $"COSE key type {kty} is not one of the EC2 ({CoseKeyTypes.Ec2}), OKP ({CoseKeyTypes.Okp}), or RSA ({CoseKeyTypes.Rsa}) types this writer supports.",
            nameof(coseKey));
    }
}
