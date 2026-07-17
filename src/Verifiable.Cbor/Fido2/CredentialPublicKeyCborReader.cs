using System.Formats.Cbor;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Cbor.Fido2;

/// <summary>
/// The shipped default for <see cref="ReadCredentialPublicKeyDelegate"/>: decodes the self-describing
/// COSE_Key <c>credentialPublicKey</c> at the start of a buffer using System.Formats.Cbor.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication
/// Level 3, section 6.5.1: Attested Credential Data</see>: "credentialPublicKey ... The credential
/// public key encoded in COSE_Key format, as defined in Section 7 of [RFC9052], using the CTAP2
/// canonical CBOR encoding form." This reader supports the three key types
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">section 6.5.1</see>'s
/// own worked examples cover — EC2, OKP, and RSA (<see href="https://www.rfc-editor.org/rfc/rfc8230#section-4">RFC 8230 §4</see>) —
/// closing the RSA gap of the mdoc-oriented COSE_Key reader this type otherwise mirrors.
/// </para>
/// <para>
/// Reading proceeds in two passes over the map: the first pass captures every top-level label's still-
/// encoded value (via <see cref="CborReader.ReadEncodedValue"/>) without interpreting it, so the
/// reader never has to assume <c>kty</c> (label 1) appears before the type-dependent labels <c>-1</c>/
/// <c>-2</c>/<c>-3</c> — RSA overloads the same integer labels EC2 and OKP use for unrelated
/// parameters (<c>n</c>/<c>e</c> versus <c>crv</c>/<c>x</c>/<c>y</c>), so the correct interpretation of
/// those labels is only knowable once <c>kty</c> itself has been decoded. The second pass decodes each
/// captured value according to the now-known <c>kty</c>. This reader is read with
/// <see cref="CborConformanceMode.Ctap2Canonical"/> per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">section 2.4: All
/// Conformance Classes</see>, which already fails closed on a duplicate label or any CBOR that is not
/// validly CTAP2-canonical-encoded at the framework level.
/// </para>
/// </remarks>
public static class CredentialPublicKeyCborReader
{
    /// <summary>
    /// Reads the self-describing COSE_Key at the start of <paramref name="source"/> and reports how
    /// many bytes it consumed. Method-group-compatible with <see cref="ReadCredentialPublicKeyDelegate"/>.
    /// </summary>
    /// <param name="source">
    /// The buffer whose leading bytes are a COSE_Key encoding; any bytes beyond the encoding (the
    /// extensions slice, if any) are left unconsumed and are not an error at this layer.
    /// </param>
    /// <returns>
    /// The parsed COSE_Key together with the number of bytes it occupied and the top-level labels
    /// encountered while parsing it, in wire order.
    /// </returns>
    /// <exception cref="Fido2FormatException">
    /// The COSE_Key is not valid CTAP2 canonical CBOR (including a duplicate or out-of-order label),
    /// omits the mandatory <c>kty</c> (1) label, or a label's value does not match the CBOR type its
    /// interpretation under the decoded <c>kty</c> requires.
    /// </exception>
    public static CredentialPublicKeyReadResult Read(ReadOnlyMemory<byte> source)
    {
        try
        {
            var reader = new CborReader(source, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            var labels = new List<int>();
            var rawValuesByLabel = new Dictionary<int, ReadOnlyMemory<byte>>();

            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int label = checked((int)reader.ReadInt64());
                entriesRead++;
                labels.Add(label);
                rawValuesByLabel[label] = reader.ReadEncodedValue();
            }

            reader.ReadEndMap();

            int bytesConsumed = source.Length - reader.BytesRemaining;

            if(!rawValuesByLabel.TryGetValue(CoseKeyParameters.Kty, out ReadOnlyMemory<byte> ktyRaw))
            {
                throw new Fido2FormatException("COSE_Key is missing the mandatory kty (1) parameter per RFC 9052 §7.1.");
            }

            int kty = DecodeInt(ktyRaw);
            int? alg = rawValuesByLabel.TryGetValue(CoseKeyParameters.Alg, out ReadOnlyMemory<byte> algRaw) ? DecodeInt(algRaw) : null;

            var coseKey = kty switch
            {
                CoseKeyTypes.Ec2 => BuildEc2Key(kty, alg, rawValuesByLabel),
                CoseKeyTypes.Okp => BuildOkpKey(kty, alg, rawValuesByLabel),
                CoseKeyTypes.Rsa => BuildRsaKey(kty, alg, rawValuesByLabel),

                //An unsupported/unrecognised kty carries no key-material fields at this layer;
                //AuthenticatorDataReader's WebAuthn L3 section 6.5.1 conformance enforcement
                //rejects it via CoseKeyConformance once the caller inspects the result.
                _ => new CoseKey(kty, alg)
            };

            return new CredentialPublicKeyReadResult(coseKey, bytesConsumed, labels);
        }
        catch(Exception exception) when(exception is CborContentException or InvalidOperationException or OverflowException or FormatException)
        {
            throw new Fido2FormatException("The COSE_Key bytes are not valid CTAP2 canonical CBOR conforming to RFC 9052 §7.1.", exception);
        }

        //Decodes a captured raw CBOR value as a signed integer.
        static int DecodeInt(ReadOnlyMemory<byte> encodedValue) => checked((int)new CborReader(encodedValue).ReadInt64());

        //Decodes a captured raw CBOR value as a byte string.
        static ReadOnlyMemory<byte> DecodeBytes(ReadOnlyMemory<byte> encodedValue) => new CborReader(encodedValue).ReadByteString();

        //Decodes a captured raw CBOR value as a boolean.
        static bool DecodeBoolean(ReadOnlyMemory<byte> encodedValue) => new CborReader(encodedValue).ReadBoolean();

        //Determines whether a captured raw CBOR value is a boolean, used to distinguish the EC2 "y"
        //label's two encodings: an uncompressed coordinate (byte string) versus a compressed sign bit
        //(boolean).
        static bool IsBooleanEncoding(ReadOnlyMemory<byte> encodedValue) => new CborReader(encodedValue).PeekState() == CborReaderState.Boolean;

        //Builds the EC2 key-material fields: crv (-1), x (-2), and y (-3), where y may be encoded
        //either as an uncompressed coordinate (byte string) or a compressed sign bit (boolean).
        static CoseKey BuildEc2Key(int kty, int? alg, Dictionary<int, ReadOnlyMemory<byte>> rawValuesByLabel)
        {
            int? curve = rawValuesByLabel.TryGetValue(CoseKeyParameters.Crv, out ReadOnlyMemory<byte> crvRaw) ? DecodeInt(crvRaw) : null;
            ReadOnlyMemory<byte>? x = rawValuesByLabel.TryGetValue(CoseKeyParameters.X, out ReadOnlyMemory<byte> xRaw) ? DecodeBytes(xRaw) : null;
            ReadOnlyMemory<byte>? y = null;
            bool? encodedYCompressionSign = null;

            if(rawValuesByLabel.TryGetValue(CoseKeyParameters.Y, out ReadOnlyMemory<byte> yRaw))
            {
                if(IsBooleanEncoding(yRaw))
                {
                    encodedYCompressionSign = DecodeBoolean(yRaw);
                }
                else
                {
                    y = DecodeBytes(yRaw);
                }
            }

            return new CoseKey(kty, alg, curve, x, y, encodedYCompressionSign);
        }

        //Builds the OKP key-material fields: crv (-1) and x (-2), the public-key bytes.
        static CoseKey BuildOkpKey(int kty, int? alg, Dictionary<int, ReadOnlyMemory<byte>> rawValuesByLabel)
        {
            int? curve = rawValuesByLabel.TryGetValue(CoseKeyParameters.Crv, out ReadOnlyMemory<byte> crvRaw) ? DecodeInt(crvRaw) : null;
            ReadOnlyMemory<byte>? x = rawValuesByLabel.TryGetValue(CoseKeyParameters.X, out ReadOnlyMemory<byte> xRaw) ? DecodeBytes(xRaw) : null;

            return new CoseKey(kty, alg, curve, x);
        }

        //Builds the RSA key-material fields: n (-1, the modulus) and e (-2, the public exponent), per
        //RFC 8230 §4, which overloads the EC2/OKP crv and x labels for unrelated RSA parameters.
        static CoseKey BuildRsaKey(int kty, int? alg, Dictionary<int, ReadOnlyMemory<byte>> rawValuesByLabel)
        {
            ReadOnlyMemory<byte>? n = rawValuesByLabel.TryGetValue(CoseKeyParameters.RsaN, out ReadOnlyMemory<byte> nRaw) ? DecodeBytes(nRaw) : null;
            ReadOnlyMemory<byte>? e = rawValuesByLabel.TryGetValue(CoseKeyParameters.RsaE, out ReadOnlyMemory<byte> eRaw) ? DecodeBytes(eRaw) : null;

            return new CoseKey(kty, alg, n: n, e: e);
        }
    }
}
