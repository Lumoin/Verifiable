using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.OAuth;

/// <summary>
/// Serializes an <see cref="AuthorizationRequestObject"/> sub-object to a JSON
/// string for embedding as a JWT payload claim.
/// </summary>
/// <typeparam name="T">The sub-object type to serialize.</typeparam>
/// <param name="value">The value to serialize.</param>
/// <returns>A JSON string representation of the value.</returns>
public delegate string JarClaimSerializer<T>(T value);


/// <summary>
/// Deserializes a JSON claim string into a typed value when parsing a JAR payload.
/// </summary>
/// <typeparam name="T">The target type to deserialize into.</typeparam>
/// <param name="json">The JSON string from the JWT payload claim.</param>
/// <returns>The deserialized value.</returns>
public delegate T JarClaimDeserializer<T>(string json);


/// <summary>
/// Signing and parsing operations for JWT Authorization Requests (JAR) per
/// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see> and
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5">OID4VP 1.0 §5</see>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="SignJarAsync"/> extends <see cref="AuthorizationRequestObject"/>
/// — the Verifier signs the typed request into a compact JWS ready to serve at
/// the <c>request_uri</c> endpoint.
/// </para>
/// <para>
/// <see cref="ParseJar"/> is the complementary Wallet-side operation — it parses
/// the compact JWS string fetched from <c>request_uri</c> back into a typed
/// <see cref="AuthorizationRequestObject"/>. It has no natural instance receiver
/// since the input is a raw wire string, not an existing typed object.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# 13 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class JarExtensions
{
    extension(AuthorizationRequestObject request)
    {
        /// <summary>
        /// Signs this <see cref="AuthorizationRequestObject"/> as a compact JWS JAR,
        /// producing a <see cref="SignedJar"/> ready to serve at the
        /// <c>request_uri</c> endpoint with media type
        /// <see cref="WellKnownMediaTypes.Application.OauthAuthzReqJwt"/>.
        /// </summary>
        /// <param name="signingKey">
        /// The Verifier's signing key. Its <see cref="Tag"/> resolves the signing
        /// algorithm via <see cref="CryptoFunctionRegistry{TAlgorithm,TPurpose}"/>.
        /// </param>
        /// <param name="headerSerializer">Delegate for serializing the JWT header.</param>
        /// <param name="payloadSerializer">Delegate for serializing the JWT payload.</param>
        /// <param name="dcqlQuerySerializer">
        /// Delegate for serializing <see cref="AuthorizationRequestObject.DcqlQuery"/>
        /// to a JSON string for embedding in the payload.
        /// </param>
        /// <param name="clientMetadataSerializer">
        /// Delegate for serializing <see cref="AuthorizationRequestObject.ClientMetadata"/>
        /// to a JSON string for embedding in the payload.
        /// </param>
        /// <param name="base64UrlEncoder">Delegate for Base64Url encoding.</param>
        /// <param name="memoryPool">Memory pool for allocations.</param>
        /// <param name="additionalHeaderClaims">
        /// Optional additional JOSE header parameters to merge into the header after
        /// the standard <c>alg</c> and <c>typ</c> claims are set. Use this to inject
        /// protocol-specific header extensions such as the <c>jwt</c> parameter for
        /// the <c>verifier_attestation:</c> Client Identifier Prefix per OID4VP 1.0 §12,
        /// or <c>x5c</c> for the <c>x509_san_dns:</c> prefix. Existing <c>alg</c> and
        /// <c>typ</c> entries are not overwritten.
        /// </param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// A <see cref="SignedJar"/> containing the signed compact JWS. The caller
        /// owns the returned instance and must dispose it.
        /// </returns>
        /// <remarks>
        /// <para>
        /// The JWT timing claims <c>iat</c>, <c>nbf</c>, and <c>exp</c> are written
        /// from <see cref="AuthorizationRequestObject.Iat"/>,
        /// <see cref="AuthorizationRequestObject.Nbf"/>, and
        /// <see cref="AuthorizationRequestObject.Exp"/> as JWT NumericDate values
        /// (seconds since the Unix epoch) per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 §2</see>.
        /// FAPI 2.0 §5.2.2 Clause 13 mandates <c>exp</c>; the library always writes
        /// all three to align with the most demanding profile.
        /// </para>
        /// <para>
        /// The <c>state</c> claim is always written. RFC 6749 §4.1.1 and RFC 9700
        /// §4.7 treat it as the CSRF binding between authorization request and
        /// response; the library does not permit a JAR to be issued without it.
        /// </para>
        /// </remarks>
        public async ValueTask<SignedJar> SignJarAsync(
            PrivateKeyMemory signingKey,
            JwtHeaderSerializer headerSerializer,
            JwtPayloadSerializer payloadSerializer,
            JarClaimSerializer<DcqlQuery> dcqlQuerySerializer,
            JarClaimSerializer<VerifierClientMetadata> clientMetadataSerializer,
            EncodeDelegate base64UrlEncoder,
            MemoryPool<byte> memoryPool,
            IReadOnlyDictionary<string, object>? additionalHeaderClaims = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signingKey);
            ArgumentNullException.ThrowIfNull(headerSerializer);
            ArgumentNullException.ThrowIfNull(payloadSerializer);
            ArgumentNullException.ThrowIfNull(dcqlQuerySerializer);
            ArgumentNullException.ThrowIfNull(clientMetadataSerializer);
            ArgumentNullException.ThrowIfNull(base64UrlEncoder);
            ArgumentNullException.ThrowIfNull(memoryPool);

            string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

            var header = new JwtHeader
            {
                [WellKnownJwkMemberNames.Alg] = algorithm,
                [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.OauthAuthzReqJwt
            };

            if(additionalHeaderClaims is not null)
            {
                foreach(KeyValuePair<string, object> claim in additionalHeaderClaims)
                {
                    if(claim.Key != WellKnownJwkMemberNames.Alg && claim.Key != WellKnownJoseHeaderNames.Typ)
                    {
                        header[claim.Key] = claim.Value;
                    }
                }
            }

            var payload = new JwtPayload
            {
                [OAuthRequestParameterNames.ResponseType] = request.ResponseType,
                [OAuthRequestParameterNames.ResponseMode] = request.ResponseMode,
                [WellKnownJwtClaimNames.ClientId] = request.ClientId,
                [Oid4VpAuthorizationRequestParameterNames.ResponseUri] = request.ResponseUri.ToString(),
                [WellKnownJwtClaimNames.Nonce] = request.Nonce,
                [OAuthRequestParameterNames.State] = request.State,
                [WellKnownJwtClaimNames.Iat] = request.Iat.ToUnixTimeSeconds(),
                [WellKnownJwtClaimNames.Nbf] = request.Nbf.ToUnixTimeSeconds(),
                [WellKnownJwtClaimNames.Exp] = request.Exp.ToUnixTimeSeconds()
            };

            if(request.ClientIdScheme is not null)
            {
                payload[Oid4VpAuthorizationRequestParameterNames.ClientIdScheme] = request.ClientIdScheme;
            }

            if(request.Iss is not null)
            {
                payload[WellKnownJwtClaimNames.Iss] = request.Iss;
            }

            if(request.Aud is not null)
            {
                payload[WellKnownJwtClaimNames.Aud] = request.Aud;
            }

            if(request.DcqlQuery is not null)
            {
                payload[Oid4VpAuthorizationRequestParameterNames.DcqlQuery] =
                    dcqlQuerySerializer(request.DcqlQuery);
            }

            if(request.ClientMetadata is not null)
            {
                payload[Oid4VpAuthorizationRequestParameterNames.ClientMetadata] =
                    clientMetadataSerializer(request.ClientMetadata);
            }

            UnsignedJwt unsignedJar = new(header, payload);
            JwsMessage signed = await unsignedJar.SignAsync(
                signingKey,
                headerSerializer,
                payloadSerializer,
                base64UrlEncoder,
                memoryPool,
                cancellationToken).ConfigureAwait(false);

            return new SignedJar(signed);
        }
    }


    /// <summary>
    /// Parses a compact JWS JAR string fetched from a <c>request_uri</c> endpoint
    /// into a typed <see cref="AuthorizationRequestObject"/>.
    /// </summary>
    /// <param name="compactJar">The compact JWS string to parse.</param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">Delegate for deserializing the JWT header.</param>
    /// <param name="payloadDeserializer">Delegate for deserializing the JWT payload claims.</param>
    /// <param name="dcqlQueryDeserializer">
    /// Delegate for deserializing the <c>dcql_query</c> claim JSON string into a
    /// <see cref="DcqlQuery"/>.
    /// </param>
    /// <param name="clientMetadataDeserializer">
    /// Delegate for deserializing the <c>client_metadata</c> claim JSON string into a
    /// <see cref="VerifierClientMetadata"/>.
    /// </param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <returns>
    /// The parsed <see cref="AuthorizationRequestObject"/>. Signature verification
    /// must be performed separately before trusting the returned claims, and the
    /// timing claims <c>nbf</c> and <c>exp</c> must be checked against the current
    /// time with the deployment's clock-skew tolerance.
    /// </returns>
    /// <exception cref="FormatException">
    /// Thrown when the compact JWS is malformed, the <c>typ</c> header is missing
    /// or not <see cref="WellKnownMediaTypes.Jwt.OauthAuthzReqJwt"/>, or a
    /// required claim is absent.
    /// </exception>
    public static AuthorizationRequestObject ParseJar(
        string compactJar,
        DecodeDelegate base64UrlDecoder,
        JarDictionaryDeserializer headerDeserializer,
        JarDictionaryDeserializer payloadDeserializer,
        JarClaimDeserializer<DcqlQuery> dcqlQueryDeserializer,
        JarClaimDeserializer<VerifierClientMetadata> clientMetadataDeserializer,
        MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(compactJar);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(dcqlQueryDeserializer);
        ArgumentNullException.ThrowIfNull(clientMetadataDeserializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        using UnverifiedJwsMessage unverified = JwsParsing.ParseCompact(
            compactJar,
            base64UrlDecoder,
            headerDeserializer.Invoke,
            memoryPool);

        UnverifiedJwtHeader unverifiedHeader = unverified.Signatures[0].ProtectedHeader;

        if(!unverifiedHeader.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typObj)
            || typObj is not string typ
            || !WellKnownMediaTypes.Jwt.IsOauthAuthzReqJwt(typ))
        {
            throw new FormatException(
                $"JAR typ header must be '{WellKnownMediaTypes.Jwt.OauthAuthzReqJwt}'. " +
                $"Wallets MUST NOT process Request Objects with an absent or incorrect typ per OID4VP 1.0 §5.");
        }

        IReadOnlyDictionary<string, object> claims =
            payloadDeserializer(unverified.Payload.Span);

        string clientId = RequireClaim(claims, WellKnownJwtClaimNames.ClientId);
        string responseType = RequireClaim(claims, OAuthRequestParameterNames.ResponseType);
        string responseMode = RequireClaim(claims, OAuthRequestParameterNames.ResponseMode);
        string responseUriString = RequireClaim(claims, Oid4VpAuthorizationRequestParameterNames.ResponseUri);
        string nonce = RequireClaim(claims, WellKnownJwtClaimNames.Nonce);
        string state = RequireClaim(claims, OAuthRequestParameterNames.State);

        if(!Uri.TryCreate(responseUriString, UriKind.Absolute, out Uri? responseUri))
        {
            throw new FormatException(
                $"JAR '{Oid4VpAuthorizationRequestParameterNames.ResponseUri}' claim is not a valid absolute URI: '{responseUriString}'.");
        }

        DateTimeOffset iat = RequireInstant(claims, WellKnownJwtClaimNames.Iat);
        DateTimeOffset nbf = RequireInstant(claims, WellKnownJwtClaimNames.Nbf);
        DateTimeOffset exp = RequireInstant(claims, WellKnownJwtClaimNames.Exp);

        string? clientIdScheme = OptionalClaim(claims, Oid4VpAuthorizationRequestParameterNames.ClientIdScheme);
        string? iss = OptionalClaim(claims, WellKnownJwtClaimNames.Iss);
        string? aud = OptionalClaim(claims, WellKnownJwtClaimNames.Aud);

        DcqlQuery? dcqlQuery = null;
        if(claims.TryGetValue(Oid4VpAuthorizationRequestParameterNames.DcqlQuery, out object? dcqlObj)
            && dcqlObj is string dcqlJson)
        {
            dcqlQuery = dcqlQueryDeserializer(dcqlJson);
        }

        VerifierClientMetadata? clientMetadata = null;
        if(claims.TryGetValue(Oid4VpAuthorizationRequestParameterNames.ClientMetadata, out object? metaObj)
            && metaObj is string metaJson)
        {
            clientMetadata = clientMetadataDeserializer(metaJson);
        }

        return new AuthorizationRequestObject
        {
            ClientId = clientId,
            ClientIdScheme = clientIdScheme,
            ResponseType = responseType,
            ResponseMode = responseMode,
            ResponseUri = responseUri,
            Nonce = nonce,
            State = state,
            Iss = iss,
            Aud = aud,
            Iat = iat,
            Nbf = nbf,
            Exp = exp,
            DcqlQuery = dcqlQuery,
            ClientMetadata = clientMetadata
        };
    }


    /// <summary>
    /// Verifies the signature of a compact JWS JAR and parses its payload into a typed
    /// <see cref="AuthorizationRequestObject"/> in a single operation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the correct Wallet-side entry point for processing a JAR fetched from a
    /// <c>request_uri</c> endpoint. It enforces that signature verification always
    /// precedes claim extraction — an invalid or unverified JAR never produces a usable
    /// <see cref="AuthorizationRequestObject"/>.
    /// </para>
    /// <para>
    /// Timing claims (<c>iat</c>, <c>nbf</c>, <c>exp</c>) are parsed but not validated
    /// here. Callers validate them against the current time with their deployment's
    /// clock-skew tolerance — see
    /// <see cref="Verifiable.OAuth.Server.TimingPolicy.ClockSkewTolerance"/> for the
    /// library's default value.
    /// </para>
    /// <para>
    /// The <paramref name="signingPublicKey"/> must be resolved by the caller before
    /// invoking this method. The resolution mechanism depends on the Client Identifier
    /// Prefix in the <c>client_id</c> parameter:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>
    ///     <c>verifier_attestation:</c> — resolved from the <c>cnf.jwk</c> claim of the
    ///     Verifier Attestation JWT carried in the <c>jwt</c> JOSE header, validated by
    ///     <see cref="VerifierAttestationKeyResolver.ResolveAsync"/>.
    ///   </description></item>
    ///   <item><description>
    ///     <c>x509_san_dns:</c> — resolved from the leaf certificate in the <c>x5c</c>
    ///     JOSE header after chain validation and DNS SAN check.
    ///   </description></item>
    ///   <item><description>
    ///     <c>decentralized_identifier:</c> — resolved via DID resolution from the
    ///     <c>verificationMethod</c> identified by the <c>kid</c> JOSE header.
    ///   </description></item>
    /// </list>
    /// </remarks>
    /// <param name="compactJar">The compact JWS string fetched from <c>request_uri</c>.</param>
    /// <param name="signingPublicKey">
    /// The Verifier's JAR signing public key, resolved via the appropriate Client
    /// Identifier Prefix mechanism before calling this method.
    /// </param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">Delegate for deserializing the JWT header.</param>
    /// <param name="payloadDeserializer">Delegate for deserializing the JWT payload claims.</param>
    /// <param name="dcqlQueryDeserializer">
    /// Delegate for deserializing the <c>dcql_query</c> claim JSON string into a
    /// <see cref="DcqlQuery"/>.
    /// </param>
    /// <param name="clientMetadataDeserializer">
    /// Delegate for deserializing the <c>client_metadata</c> claim JSON string into a
    /// <see cref="VerifierClientMetadata"/>.
    /// </param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The verified and parsed <see cref="AuthorizationRequestObject"/>. The signature
    /// has been cryptographically verified; timing claims are still subject to caller
    /// validation against the current time.
    /// </returns>
    /// <exception cref="System.Security.SecurityException">
    /// Thrown when the JAR signature does not verify against the provided public key.
    /// </exception>
    /// <exception cref="FormatException">
    /// Thrown when the compact JWS is malformed, the <c>typ</c> header is missing or
    /// incorrect, or a required claim is absent.
    /// </exception>
    public static async ValueTask<AuthorizationRequestObject> VerifyAndParseJarAsync(
        string compactJar,
        PublicKeyMemory signingPublicKey,
        DecodeDelegate base64UrlDecoder,
        JarDictionaryDeserializer headerDeserializer,
        JarDictionaryDeserializer payloadDeserializer,
        JarClaimDeserializer<DcqlQuery> dcqlQueryDeserializer,
        JarClaimDeserializer<VerifierClientMetadata> clientMetadataDeserializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(compactJar);
        ArgumentNullException.ThrowIfNull(signingPublicKey);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(dcqlQueryDeserializer);
        ArgumentNullException.ThrowIfNull(clientMetadataDeserializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        bool signatureValid = await Jws.VerifyAsync(
            compactJar,
            base64UrlDecoder,
            static (ReadOnlySpan<byte> _) => (object?)null,
            memoryPool,
            signingPublicKey,
            cancellationToken).ConfigureAwait(false);

        if(!signatureValid)
        {
            throw new System.Security.SecurityException(
                "JAR signature verification failed. The Request Object was not signed " +
                "by the key associated with the Verifier's Client Identifier. " +
                "Wallets MUST NOT process Request Objects with invalid signatures per OID4VP 1.0 §5.");
        }

        return ParseJar(
            compactJar,
            base64UrlDecoder,
            headerDeserializer,
            payloadDeserializer,
            dcqlQueryDeserializer,
            clientMetadataDeserializer,
            memoryPool);
    }


    private static string RequireClaim(
        IReadOnlyDictionary<string, object> claims,
        string name)
    {
        if(!claims.TryGetValue(name, out object? value) || value is not string str)
        {
            throw new FormatException(
                $"JAR payload is missing required claim '{name}'.");
        }

        return str;
    }


    private static string? OptionalClaim(
        IReadOnlyDictionary<string, object> claims,
        string name)
    {
        return claims.TryGetValue(name, out object? value) && value is string str ? str : null;
    }


    //Reads a required JWT timing claim as a NumericDate value per RFC 7519 §2.
    //Accepts the integer family produced by Verifiable.Json's narrowing
    //converters when materializing JSON numbers into an object-typed claim
    //dictionary. The library does not take a compile-time dependency on any
    //specific JSON library; the deserializer is supplied as a delegate.
    private static DateTimeOffset RequireInstant(
        IReadOnlyDictionary<string, object> claims,
        string name)
    {
        if(!claims.TryGetValue(name, out object? value) || value is null)
        {
            throw new FormatException(
                $"JAR payload is missing required timing claim '{name}'.");
        }

        if(value is DateTimeOffset dt)
        {
            return dt;
        }

        if(TryToInt64(value, out long unixSeconds))
        {
            return DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        }

        throw new FormatException(
            $"JAR payload claim '{name}' is not a JWT NumericDate value " +
            $"(observed runtime type: {value.GetType().FullName}).");
    }


    //Resolves a runtime claim value to a 64-bit integer for JWT NumericDate
    //interpretation. Accepts the integer types Verifiable.Json's narrowing
    //converters produce for JSON numbers materialized into an object-typed
    //claim dictionary.
    private static bool TryToInt64(object value, out long result)
    {
        switch(value)
        {
            case long l:
            {
                result = l;
                return true;
            }
            case int i:
            {
                result = i;
                return true;
            }
            case short s:
            {
                result = s;
                return true;
            }
            case byte b:
            {
                result = b;
                return true;
            }
            case uint ui:
            {
                result = ui;
                return true;
            }
            case ulong ul when ul <= long.MaxValue:
            {
                result = (long)ul;
                return true;
            }
            case sbyte sb:
            {
                result = sb;
                return true;
            }
            case ushort us:
            {
                result = us;
                return true;
            }
            case decimal d when d >= long.MinValue && d <= long.MaxValue && d == Math.Truncate(d):
            {
                result = (long)d;
                return true;
            }
        }

        result = 0;

        return false;
    }
}
