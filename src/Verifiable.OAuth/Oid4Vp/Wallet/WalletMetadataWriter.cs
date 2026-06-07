using System.Buffers;
using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Span-based, pool-allocating writer for the <c>wallet_metadata</c> the Wallet
/// POSTs to the Verifier's <c>request_uri</c> on the OID4VP 1.0 §5.10
/// <c>request_uri_method=post</c> path.
/// </summary>
/// <remarks>
/// <para>
/// Emits the FULL Wallet Authorization Server metadata document (OID4VP 1.0 §10,
/// layered on RFC 8414), not just the encryption subset: the discovery members
/// from <see cref="Oid4VpWalletCapabilities"/> (<c>vp_formats_supported</c>,
/// <c>response_types_supported</c>, <c>response_modes_supported</c>,
/// <c>client_id_prefixes_supported</c>, <c>request_object_signing_alg_values_supported</c>,
/// <c>authorization_encryption_alg_values_supported</c>/<c>..._enc_values_supported</c>)
/// plus the Wallet's exchange <c>jwks</c> and the optional
/// <c>authorization_encrypted_response_enc</c>. A strict Verifier validates the
/// whole document and rejects the POST if the discovery members are absent
/// (e.g. <c>response_types_supported: null</c>), so emitting only <c>jwks</c> +
/// <c>enc</c> is not interoperable.
/// </para>
/// <para>
/// Built with <see cref="JwkJsonWriter"/> for pool-rented, span-based output —
/// no JSON serialisation library. Array and nested-object members are written via
/// <see cref="JwkJsonWriter.WritePropertyRaw"/> from pre-built JSON value tokens
/// (the values are controlled wire tokens — algorithm/mode/scheme names and
/// base64url coordinates — so no JSON escaping is required); the buffer is rented
/// at a safe upper bound and sliced to the written length.
/// </para>
/// <para>
/// Mirrors <see cref="Verifiable.OAuth.Oid4Vp.Server.WalletMetadataReader"/> on the
/// inverse side. HAIP 1.0 §5.1 mandates P-256 ECDH-ES, and that stays the
/// interoperable default; the NIST P-384/P-521 and the RFC 5639 Brainpool curves are
/// additionally supported, so P-256, P-384, P-521 and Brainpool
/// P-256r1/P-320r1/P-384r1/P-512r1 exchange keys all emit the correct EC JWK
/// (<c>kty=EC</c>, the right <c>crv</c>, and field-sized <c>x</c>/<c>y</c>). X25519 throws
/// <see cref="NotSupportedException"/> pending a deployment that needs it — it is a
/// different (<c>kty=OKP</c>, single-coordinate) JWK shape.
/// </para>
/// </remarks>
[DebuggerDisplay("WalletMetadataWriter")]
public static class WalletMetadataWriter
{
    private const string IssuerMember = "issuer";
    private const string AuthorizationEndpointMember = "authorization_endpoint";
    private const string VpFormatsSupportedMember = "vp_formats_supported";
    private const string ResponseTypesSupportedMember = "response_types_supported";
    private const string ResponseModesSupportedMember = "response_modes_supported";
    private const string ClientIdPrefixesSupportedMember = "client_id_prefixes_supported";
    private const string RequestObjectSigningAlgValuesSupportedMember = "request_object_signing_alg_values_supported";
    private const string AuthorizationEncryptionAlgValuesSupportedMember = "authorization_encryption_alg_values_supported";
    private const string AuthorizationEncryptionEncValuesSupportedMember = "authorization_encryption_enc_values_supported";
    private const string EncMemberName = "authorization_encrypted_response_enc";
    private const string JwksMemberName = "jwks";
    private const string KeysMemberName = "keys";
    private const string UseMemberName = "use";
    private const string UseEncValue = "enc";

    //Buffer/capacity hints — see the call sites for what each covers.
    private const int StructuralSlackBytes = 256;             //outer braces, colons, commas, and quote bytes across all members
    private const int EncMemberPunctuationBytes = 8;          //comma, two quote pairs, and colon around authorization_encrypted_response_enc
    private const int EstimatedBytesPerArrayToken = 12;       //a quoted short wire token plus its comma (e.g. "ES256",)
    private const int ArrayBracketsBytes = 2;                 //the [ and ] of a JSON array literal


    /// <summary>
    /// Writes the full <c>wallet_metadata</c> JSON document: the Wallet's declared
    /// capabilities, its exchange public key as a <c>use=enc</c> JWKS entry, and —
    /// when supplied — the <c>authorization_encrypted_response_enc</c> the Wallet
    /// asks the Verifier to use when JWE-wrapping the JAR.
    /// </summary>
    /// <param name="walletExchangePublicKey">
    /// The wallet's ECDH-ES exchange public key. Its <see cref="Tag"/> drives the
    /// JWK shape; must carry <see cref="Purpose.Exchange"/>.
    /// </param>
    /// <param name="jarEncryptionEnc">
    /// Optional <c>authorization_encrypted_response_enc</c> value, e.g.
    /// <c>"A128GCM"</c>. <see langword="null"/> omits the member.
    /// </param>
    /// <param name="base64UrlEncoder">Base64url encoder for key coordinates.</param>
    /// <param name="pool">Memory pool for the transient JSON buffer.</param>
    /// <param name="capabilities">The Wallet's declared capabilities serialized into the discovery members.</param>
    public static string BuildForWalletPost(
        Oid4VpWalletCapabilities capabilities,
        PublicKeyMemory walletExchangePublicKey,
        string? jarEncryptionEnc,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(walletExchangePublicKey);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        Purpose purpose = walletExchangePublicKey.Tag.Get<Purpose>();
        if(!purpose.Equals(Purpose.Exchange))
        {
            throw new ArgumentException(
                $"Wallet exchange public key must carry Purpose.Exchange; " +
                $"got {purpose}.",
                nameof(walletExchangePublicKey));
        }

        //The JWK shape follows the key's tag. A Raw-encoded exchange key is OKP (a single
        //x coordinate, e.g. X25519 per RFC 8037); everything else is an EC uncompressed
        //point that splits into x and y. The discovery-member document is identical for
        //both, so only the coordinate extraction differs here.
        CryptoAlgorithm alg = walletExchangePublicKey.Tag.Get<CryptoAlgorithm>();
        EncodingScheme encoding = walletExchangePublicKey.Tag.Get<EncodingScheme>();
        ReadOnlySpan<byte> keyBytes = walletExchangePublicKey.AsReadOnlySpan();

        string kty;
        string crv;
        string x;
        string? y;
        if(encoding.Equals(EncodingScheme.Raw))
        {
            (crv, int rawLength) = ResolveOkpExchangeCurve(alg);
            if(keyBytes.Length != rawLength)
            {
                throw new ArgumentException(
                    $"{crv} exchange public key must be {rawLength} raw bytes.",
                    nameof(walletExchangePublicKey));
            }

            kty = WellKnownKeyTypeValues.Okp;
            x = base64UrlEncoder(keyBytes);
            y = null;
        }
        else
        {
            (crv, int coordinateLength) = ResolveEcExchangeCurve(alg);
            int expectedPointLength = 1 + (2 * coordinateLength);
            if(keyBytes.Length != expectedPointLength || keyBytes[0] != 0x04)
            {
                throw new ArgumentException(
                    $"{crv} exchange public key must be a {expectedPointLength}-byte uncompressed " +
                    "point (0x04 || X || Y).",
                    nameof(walletExchangePublicKey));
            }

            kty = WellKnownKeyTypeValues.Ec;
            x = base64UrlEncoder(keyBytes.Slice(1, coordinateLength));
            y = base64UrlEncoder(keyBytes.Slice(1 + coordinateLength, coordinateLength));
        }

        return BuildExchangeMetadata(kty, crv, x, y, jarEncryptionEnc, pool, capabilities);
    }


    //Maps a wallet OKP exchange algorithm to its JWK curve name and raw key length.
    //X25519 (RFC 8037) is the only OKP exchange curve supported.
    private static (string Crv, int RawLength) ResolveOkpExchangeCurve(CryptoAlgorithm alg)
    {
        if(alg.Equals(CryptoAlgorithm.X25519))
        {
            return (WellKnownCurveValues.X25519, 32);
        }

        throw new NotSupportedException(
            $"Wallet OKP exchange algorithm '{alg}' is not supported for §5.10 " +
            "wallet_metadata composition. Only X25519 is supported.");
    }


    //Maps a wallet exchange algorithm to its JWK curve name and field-coordinate
    //byte length. P-256 is the HAIP 1.0 §5.1 default; the NIST P-384/P-521 and the
    //RFC 5639 Brainpool curves are also supported. All of these are EC (kty=EC) curves
    //with a 0x04 || X || Y uncompressed point, so one EC JWK writer serves them; X25519
    //needs a separate OKP shape.
    private static (string Crv, int CoordinateLength) ResolveEcExchangeCurve(CryptoAlgorithm alg)
    {
        if(alg.Equals(CryptoAlgorithm.P256))
        {
            return (WellKnownCurveValues.P256, 32);
        }

        if(alg.Equals(CryptoAlgorithm.P384))
        {
            return (WellKnownCurveValues.P384, 48);
        }

        if(alg.Equals(CryptoAlgorithm.P521))
        {
            return (WellKnownCurveValues.P521, 66);
        }

        if(alg.Equals(CryptoAlgorithm.BrainpoolP256r1))
        {
            return (WellKnownCurveValues.BrainpoolP256r1, 32);
        }

        if(alg.Equals(CryptoAlgorithm.BrainpoolP320r1))
        {
            return (WellKnownCurveValues.BrainpoolP320r1, 40);
        }

        if(alg.Equals(CryptoAlgorithm.BrainpoolP384r1))
        {
            return (WellKnownCurveValues.BrainpoolP384r1, 48);
        }

        if(alg.Equals(CryptoAlgorithm.BrainpoolP512r1))
        {
            return (WellKnownCurveValues.BrainpoolP512r1, 64);
        }

        throw new NotSupportedException(
            $"Wallet exchange algorithm '{alg}' is not yet wired for §5.10 " +
            "wallet_metadata composition. HAIP 1.0 §5.1 mandates " +
            $"'{CryptoAlgorithm.P256}'; the NIST P-384/P-521 and RFC 5639 Brainpool " +
            "exchange curves are also supported.");
    }


    //Writes the wallet_metadata document for an already-extracted exchange JWK. The key
    //shape is carried by kty + the presence of y: EC keys pass both coordinates, OKP keys
    //(X25519) pass x only with y null. The discovery members are identical either way.
    private static string BuildExchangeMetadata(
        string kty,
        string crv,
        string x,
        string? y,
        string? jarEncryptionEnc,
        MemoryPool<byte> pool,
        Oid4VpWalletCapabilities capabilities)
    {
        //Discovery members written as raw JSON value tokens. Values are controlled
        //wire tokens (algorithm/mode/scheme/type names) — no JSON-significant
        //characters — so a quoted-join needs no escaping. vp_formats_supported is
        //already raw JSON.
        string responseTypes = JsonStringArray(capabilities.ResponseTypesSupported);
        string responseModes = JsonStringArray(capabilities.ResponseModesSupported);
        string clientIdSchemes = JsonStringArray(capabilities.ClientIdPrefixesSupported);
        string requestObjectSigningAlgs = JsonStringArray(capabilities.RequestObjectSigningAlgValuesSupported);
        string encryptionAlgs = JsonStringArray(capabilities.AuthorizationEncryptionAlgValuesSupported);
        string encryptionEncs = JsonStringArray(capabilities.AuthorizationEncryptionEncValuesSupported);

        //Rent a safe upper bound (sum of every byte we may write + structural
        //slack) and slice to the written length; JwkJsonWriter has no internal
        //bounds growth, so the buffer must be large enough.
        int upperBound =
            StructuralSlackBytes
            + IssuerMember.Length + Encoding.UTF8.GetByteCount(capabilities.Issuer)
            + AuthorizationEndpointMember.Length + Encoding.UTF8.GetByteCount(capabilities.AuthorizationEndpoint)
            + Encoding.UTF8.GetByteCount(capabilities.VpFormatsSupportedJson)
            + Encoding.UTF8.GetByteCount(responseTypes)
            + Encoding.UTF8.GetByteCount(responseModes)
            + Encoding.UTF8.GetByteCount(clientIdSchemes)
            + Encoding.UTF8.GetByteCount(requestObjectSigningAlgs)
            + Encoding.UTF8.GetByteCount(encryptionAlgs)
            + Encoding.UTF8.GetByteCount(encryptionEncs)
            + VpFormatsSupportedMember.Length
            + ResponseTypesSupportedMember.Length
            + ResponseModesSupportedMember.Length
            + ClientIdPrefixesSupportedMember.Length
            + RequestObjectSigningAlgValuesSupportedMember.Length
            + AuthorizationEncryptionAlgValuesSupportedMember.Length
            + AuthorizationEncryptionEncValuesSupportedMember.Length
            + JwksMemberName.Length + KeysMemberName.Length + UseMemberName.Length
            + WellKnownJwkMemberNames.Kty.Length + WellKnownJwkMemberNames.Crv.Length
            + WellKnownJwkMemberNames.X.Length
            + kty.Length + crv.Length + UseEncValue.Length
            + Encoding.UTF8.GetByteCount(x)
            + (y is null ? 0 : WellKnownJwkMemberNames.Y.Length + Encoding.UTF8.GetByteCount(y))
            + (jarEncryptionEnc is null ? 0 : EncMemberName.Length + jarEncryptionEnc.Length + EncMemberPunctuationBytes);

        using IMemoryOwner<byte> owner = pool.Rent(upperBound);
        Span<byte> buffer = owner.Memory.Span[..upperBound];
        JwkJsonWriter writer = new(buffer);

        writer.WriteObjectStart();

        //AS-metadata identity (RFC 8414 §2): issuer REQUIRED; authorization_endpoint
        //is the Wallet's custom invocation scheme (must end with "://").
        writer.WriteProperty(IssuerMember, capabilities.Issuer);
        writer.WritePropertySeparator();
        writer.WriteProperty(AuthorizationEndpointMember, capabilities.AuthorizationEndpoint);
        writer.WritePropertySeparator();

        //Discovery members (REQUIRED by a strict verifier; vp_formats_supported is
        //REQUIRED by the spec).
        writer.WritePropertyRaw(VpFormatsSupportedMember, capabilities.VpFormatsSupportedJson);
        writer.WritePropertySeparator();
        writer.WritePropertyRaw(ResponseTypesSupportedMember, responseTypes);
        writer.WritePropertySeparator();
        writer.WritePropertyRaw(ResponseModesSupportedMember, responseModes);
        writer.WritePropertySeparator();
        writer.WritePropertyRaw(ClientIdPrefixesSupportedMember, clientIdSchemes);
        writer.WritePropertySeparator();
        writer.WritePropertyRaw(RequestObjectSigningAlgValuesSupportedMember, requestObjectSigningAlgs);
        writer.WritePropertySeparator();
        writer.WritePropertyRaw(AuthorizationEncryptionAlgValuesSupportedMember, encryptionAlgs);
        writer.WritePropertySeparator();
        writer.WritePropertyRaw(AuthorizationEncryptionEncValuesSupportedMember, encryptionEncs);
        writer.WritePropertySeparator();

        //jwks: { "keys": [ { "kty":<kty>,"crv":<crv>,"use":"enc","x":..[,"y":..] } ] }
        //y is present only for EC keys; an OKP key (X25519) carries x alone.
        writer.WriteKey(JwksMemberName);
        writer.WriteObjectStart();
        writer.WriteKey(KeysMemberName);
        writer.WriteArrayStart();

        writer.WriteObjectStart();
        writer.WriteProperty(WellKnownJwkMemberNames.Kty, kty);
        writer.WritePropertySeparator();
        writer.WriteProperty(WellKnownJwkMemberNames.Crv, crv);
        writer.WritePropertySeparator();
        writer.WriteProperty(UseMemberName, UseEncValue);
        writer.WritePropertySeparator();
        writer.WriteProperty(WellKnownJwkMemberNames.X, x);

        if(y is not null)
        {
            writer.WritePropertySeparator();
            writer.WriteProperty(WellKnownJwkMemberNames.Y, y);
        }

        writer.WriteObjectEnd();

        writer.WriteArrayEnd();
        writer.WriteObjectEnd();

        if(jarEncryptionEnc is not null)
        {
            writer.WritePropertySeparator();
            writer.WriteProperty(EncMemberName, jarEncryptionEnc);
        }

        writer.WriteObjectEnd();

        return Encoding.UTF8.GetString(buffer[..writer.Position]);
    }


    //Builds a JSON string-array literal from controlled wire tokens. The tokens
    //(algorithm/mode/scheme/type names) carry no JSON-significant characters, so a
    //quoted comma-join is well-formed without escaping — matching the no-escape
    //contract JwkJsonWriter's own string writes rely on.
    private static string JsonStringArray(IReadOnlyList<string> values)
    {
        StringBuilder builder = new((values.Count * EstimatedBytesPerArrayToken) + ArrayBracketsBytes);
        builder.Append('[');
        for(int i = 0; i < values.Count; i++)
        {
            if(i > 0)
            {
                builder.Append(',');
            }

            builder.Append('"').Append(values[i]).Append('"');
        }

        builder.Append(']');

        return builder.ToString();
    }
}
