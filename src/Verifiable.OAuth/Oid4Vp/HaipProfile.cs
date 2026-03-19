using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp.Formats;
using Verifiable.OAuth.Oid4Vp.States;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Factory methods for constructing OID4VP protocol objects conformant to
/// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>.
/// </summary>
/// <remarks>
/// Isolating HAIP 1.0 construction logic here keeps the core POCOs
/// (<see cref="VerifierClientMetadata"/>, <see cref="AuthorizationRequestObject"/>,
/// <see cref="VpFormatsSupported"/>) profile-agnostic. Other profiles or
/// application-specific variants are added as separate classes following the
/// same pattern.
/// </remarks>
[DebuggerDisplay("HaipProfile")]
public static class HaipProfile
{
    /// <summary>
    /// Creates a <see cref="VpFormatsSupported"/> for the HAIP 1.0 SD-JWT VC
    /// profile: <c>dc+sd-jwt</c> with ES256 for both the SD-JWT and KB-JWT
    /// components.
    /// </summary>
    public static VpFormatsSupported CreateVpFormatsSupported()
    {
        IReadOnlyDictionary<string, IReadOnlyList<string>> dcSdJwtAlgs =
            ImmutableDictionary<string, IReadOnlyList<string>>.Empty
                .Add(WellKnownDcSdJwtFormatProperties.SdJwtAlgValues,
                    ImmutableArray.Create(WellKnownJwaValues.Es256))
                .Add(WellKnownDcSdJwtFormatProperties.KbJwtAlgValues,
                    ImmutableArray.Create(WellKnownJwaValues.Es256));

        return new VpFormatsSupported(
            ImmutableDictionary<string, IReadOnlyDictionary<string, IReadOnlyList<string>>>.Empty
                .Add(WellKnownMediaTypes.Jwt.DcSdJwt, dcSdJwtAlgs));
    }


    /// <summary>
    /// Creates a <see cref="VerifierClientMetadata"/> for the HAIP 1.0
    /// cross-device ECDH-ES encrypted response flow with SD-JWT VC.
    /// </summary>
    /// <param name="clientId">The Verifier's client identifier.</param>
    /// <param name="jwksJson">
    /// The raw JWKS JSON string carrying the ephemeral P-256 public key for
    /// ECDH-ES response encryption.
    /// </param>
    public static VerifierClientMetadata CreateVerifierClientMetadata(
        string clientId,
        string jwksJson)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(jwksJson);

        return new VerifierClientMetadata
        {
            ClientId = clientId,
            Jwks = jwksJson,
            VpFormatsSupported = CreateVpFormatsSupported(),
            EncryptedResponseAlgValuesSupported =
                ImmutableArray.Create(WellKnownJweAlgorithms.EcdhEs),
            EncryptedResponseEncValuesSupported =
                ImmutableArray.Create(
                    WellKnownJweEncryptionAlgorithms.A128Gcm,
                    WellKnownJweEncryptionAlgorithms.A256Gcm)
        };
    }


    /// <summary>
    /// Creates an <see cref="AuthorizationRequestObject"/> for the HAIP 1.0
    /// cross-device encrypted response flow using DCQL and
    /// <c>direct_post.jwt</c>.
    /// </summary>
    /// <param name="clientId">The Verifier's client identifier.</param>
    /// <param name="responseUri">The endpoint to POST the Authorization Response to.</param>
    /// <param name="nonce">A fresh transaction nonce.</param>
    /// <param name="dcqlQuery">The DCQL query specifying the requested credentials.</param>
    /// <param name="clientMetadata">The Verifier's client metadata including the JWKS.</param>
    /// <param name="state">An optional CSRF state value.</param>
    public static AuthorizationRequestObject CreateAuthorizationRequestObject(
        string clientId,
        Uri responseUri,
        string nonce,
        DcqlQuery dcqlQuery,
        VerifierClientMetadata clientMetadata,
        string? state = null)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(responseUri);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(dcqlQuery);
        ArgumentNullException.ThrowIfNull(clientMetadata);

        return new AuthorizationRequestObject
        {
            ClientId = clientId,
            ResponseType = AuthorizationRequestParameters.ResponseTypeVpToken,
            ResponseMode = WellKnownResponseModes.DirectPostJwt,
            ResponseUri = responseUri,
            Nonce = nonce,
            DcqlQuery = dcqlQuery,
            ClientMetadata = clientMetadata,
            State = state
        };
    }


    /// <summary>
    /// Verifier-side: signs the authorization request object into a compact JWS JAR
    /// ready to serve at the <c>request_uri</c> endpoint.
    /// </summary>
    /// <remarks>
    /// Builds the <see cref="AuthorizationRequestObject"/> from the supplied values,
    /// signs it with <paramref name="signingKey"/>, and returns both the
    /// <see cref="JarSigned"/> input for the PDA transition and the compact JWS string
    /// for serving over HTTP. Usable from both the client-side verifier flow and the
    /// server-side verifier flow without coupling to a specific state type.
    /// </remarks>
    /// <param name="nonce">The transaction nonce to embed in the JAR.</param>
    /// <param name="dcqlQuery">The prepared DCQL query to embed in the JAR.</param>
    /// <param name="clientId">The Verifier's client identifier.</param>
    /// <param name="responseUri">The endpoint to POST the Authorization Response to.</param>
    /// <param name="clientMetadata">The Verifier's client metadata including the JWKS.</param>
    /// <param name="signingKey">The Verifier's private signing key.</param>
    /// <param name="headerSerializer">Delegate for serializing the JWT header.</param>
    /// <param name="payloadSerializer">Delegate for serializing the JWT payload.</param>
    /// <param name="dcqlQuerySerializer">Delegate for serializing the DCQL query.</param>
    /// <param name="clientMetadataSerializer">Delegate for serializing client metadata.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A tuple of the <see cref="JarSigned"/> PDA input and the compact JWS string.
    /// </returns>
    public static async ValueTask<(JarSigned Input, string CompactJar)> BuildJarAsync(
        TransactionNonce nonce,
        PreparedDcqlQuery dcqlQuery,
        string clientId,
        Uri responseUri,
        VerifierClientMetadata clientMetadata,
        PrivateKeyMemory signingKey,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        JarClaimSerializer<DcqlQuery> dcqlQuerySerializer,
        JarClaimSerializer<VerifierClientMetadata> clientMetadataSerializer,
        EncodeDelegate encoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(dcqlQuery);
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(responseUri);
        ArgumentNullException.ThrowIfNull(clientMetadata);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(dcqlQuerySerializer);
        ArgumentNullException.ThrowIfNull(clientMetadataSerializer);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);

        AuthorizationRequestObject requestObject = CreateAuthorizationRequestObject(
            clientId: clientId,
            responseUri: responseUri,
            nonce: nonce.Value,
            dcqlQuery: dcqlQuery.Query,
            clientMetadata: clientMetadata);

        SignedJar signedJar = await requestObject.SignJarAsync(
            signingKey,
            headerSerializer,
            payloadSerializer,
            dcqlQuerySerializer,
            clientMetadataSerializer,
            encoder,
            pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJar = JwsSerialization.SerializeCompact(signedJar.Message, encoder);

        return (new JarSigned(signedJar), compactJar);
    }


    /// <summary>
    /// Convenience overload: signs the JAR using values from a
    /// <see cref="States.ParCompletedState"/> state.
    /// </summary>
    public static ValueTask<(JarSigned Input, string CompactJar)> BuildJarAsync(
        ParCompletedState state,
        string clientId,
        Uri responseUri,
        VerifierClientMetadata clientMetadata,
        PrivateKeyMemory signingKey,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        JarClaimSerializer<DcqlQuery> dcqlQuerySerializer,
        JarClaimSerializer<VerifierClientMetadata> clientMetadataSerializer,
        EncodeDelegate encoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);

        return BuildJarAsync(
            nonce: state.Nonce,
            dcqlQuery: state.Query,
            clientId: clientId,
            responseUri: responseUri,
            clientMetadata: clientMetadata,
            signingKey: signingKey,
            headerSerializer: headerSerializer,
            payloadSerializer: payloadSerializer,
            dcqlQuerySerializer: dcqlQuerySerializer,
            clientMetadataSerializer: clientMetadataSerializer,
            encoder: encoder,
            pool: pool,
            cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Wallet-side: encrypts a VP token payload to the Verifier's ephemeral P-256
    /// exchange key and produces a compact JWE for POSTing to the
    /// <c>response_uri</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Extracts the Verifier's P-256 public exchange key from
    /// <see cref="AuthorizationRequestObject.ClientMetadata"/> using
    /// <paramref name="jwkDeserializer"/> and <paramref name="decoder"/>, then
    /// performs ECDH-ES key agreement with AES-128-GCM content encryption as
    /// required by HAIP 1.0.
    /// </para>
    /// <para>
    /// The Wallet calls this after selecting disclosures and serializing the VP token
    /// presentations to JSON. The returned compact JWE is the body of the HTTP POST
    /// to <see cref="AuthorizationRequestObject.ResponseUri"/>.
    /// </para>
    /// </remarks>
    /// <param name="requestObject">
    /// The parsed and signature-verified <see cref="AuthorizationRequestObject"/>
    /// received from <c>request_uri</c>.
    /// </param>
    /// <param name="vpTokenPayloadBytes">
    /// The serialized VP token presentations as UTF-8 bytes. Typically the JSON
    /// serialization of the presentations keyed by DCQL credential query identifier.
    /// </param>
    /// <param name="headerSerializer">Delegate for serializing the JWE protected header.</param>
    /// <param name="jwkDeserializer">
    /// Delegate that parses a JWKS JSON string into a dictionary of claim names to
    /// values. Used to locate the Verifier's P-256 exchange key.
    /// </param>
    /// <param name="tagToEpkCrvConverter">
    /// Delegate mapping a key <see cref="Tag"/> to the JWK <c>crv</c> string embedded
    /// in the EPK header parameter.
    /// </param>
    /// <param name="keyAgreementEncryptDelegate">
    /// Delegate performing ECDH-ES P-256 key agreement and deriving the ephemeral key.
    /// </param>
    /// <param name="keyDerivationDelegate">
    /// Concat KDF delegate for deriving the content encryption key per RFC 7518 §4.6.2.
    /// </param>
    /// <param name="aeadEncryptDelegate">
    /// AES-GCM content encryption delegate.
    /// </param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="decoder">
    /// Delegate for Base64Url decoding, used when parsing the JWKS key coordinates.
    /// </param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The compact JWE serialization to POST to
    /// <see cref="AuthorizationRequestObject.ResponseUri"/>.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="AuthorizationRequestObject.ClientMetadata"/> or its
    /// JWKS is absent, or when no P-256 exchange key is found in the JWKS.
    /// </exception>
    /// <summary>
    /// Wallet-side: encrypts a VP token payload to the Verifier's ephemeral P-256
    /// exchange key and produces a compact JWE for POSTing to the <c>response_uri</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Extracts the Verifier's P-256 public exchange key from
    /// <see cref="AuthorizationRequestObject.ClientMetadata"/> using
    /// <see cref="JwksEpkExtractor"/>, then performs ECDH-ES key agreement with
    /// AES-128-GCM content encryption as required by HAIP 1.0.
    /// </para>
    /// <para>
    /// The Wallet calls this after selecting disclosures and serialising the VP token
    /// presentations. The returned compact JWE is the body of the HTTP POST to
    /// <see cref="AuthorizationRequestObject.ResponseUri"/>.
    /// </para>
    /// </remarks>
    /// <param name="requestObject">
    /// The parsed and signature-verified <see cref="AuthorizationRequestObject"/>
    /// received from <c>request_uri</c>.
    /// </param>
    /// <param name="vpTokenPayloadBytes">
    /// The serialised VP token presentations as UTF-8 bytes.
    /// </param>
    /// <param name="headerSerializer">Delegate for serialising the JWE protected header.</param>
    /// <param name="tagToEpkCrvConverter">
    /// Delegate mapping a key <see cref="Tag"/> to the JWK <c>crv</c> string for the
    /// EPK header parameter.
    /// </param>
    /// <param name="keyAgreementEncryptDelegate">ECDH-ES P-256 key agreement delegate.</param>
    /// <param name="keyDerivationDelegate">Concat KDF delegate per RFC 7518 §4.6.2.</param>
    /// <param name="aeadEncryptDelegate">AES-GCM content encryption delegate.</param>
    /// <param name="encoder">Delegate for Base64url encoding.</param>
    /// <param name="decoder">Delegate for Base64url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact JWE string to POST to <see cref="AuthorizationRequestObject.ResponseUri"/>.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <c>client_metadata.jwks</c> is absent or contains no valid P-256 exchange key.
    /// </exception>
    public static async ValueTask<string> EncryptResponseAsync(
        AuthorizationRequestObject requestObject,
        ReadOnlyMemory<byte> vpTokenPayloadBytes,
        JwtHeaderSerializer headerSerializer,
        TagToEpkCrvDelegate tagToEpkCrvConverter,
        KeyAgreementEncryptDelegate keyAgreementEncryptDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        EncodeDelegate encoder,
        DecodeDelegate decoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestObject);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(tagToEpkCrvConverter);
        ArgumentNullException.ThrowIfNull(keyAgreementEncryptDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(aeadEncryptDelegate);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(requestObject.ClientMetadata?.Jwks is not string jwksJson)
        {
            throw new InvalidOperationException(
                "The Authorization Request Object does not carry a client_metadata.jwks field. " +
                "The Verifier must include its ephemeral P-256 exchange key in the JAR for " +
                "HAIP 1.0 encrypted responses.");
        }

        //Select the enc algorithm from the Verifier's advertised set per HAIP 1.0 §5.1.
        //Prefer A256GCM when both are advertised; fall back to A128GCM otherwise.
        IReadOnlyList<string>? supportedEnc =
            requestObject.ClientMetadata?.EncryptedResponseEncValuesSupported;

        string selectedEnc = WellKnownJweEncryptionAlgorithms.A128Gcm;
        if(supportedEnc is not null)
        {
            foreach(string enc in supportedEnc)
            {
                if(string.Equals(enc, WellKnownJweEncryptionAlgorithms.A256Gcm,
                    StringComparison.Ordinal))
                {
                    selectedEnc = WellKnownJweEncryptionAlgorithms.A256Gcm;
                    break;
                }
            }
        }

        using PublicKeyMemory encryptionPublicKey =
            JwksEpkExtractor.ExtractP256EncryptionKey(jwksJson, decoder, pool);

        UnencryptedJwe unencrypted = UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            selectedEnc,
            vpTokenPayloadBytes);

        using JweMessage encrypted = await unencrypted.EncryptAsync(
            encryptionPublicKey,
            headerSerializer,
            encoder,
            tagToEpkCrvConverter,
            keyAgreementEncryptDelegate,
            keyDerivationDelegate,
            aeadEncryptDelegate,
            pool,
            cancellationToken).ConfigureAwait(false);

        return encrypted.ToCompactJwe(encoder);
    }


    /// <summary>
    /// Verifier-side: decrypts a compact JWE received at the <c>response_uri</c>
    /// endpoint, returning the plaintext VP token payload bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Peeks the <c>enc</c> value from the JWE protected header before any cryptographic
    /// operation. The peeked value is validated against <paramref name="allowedEncAlgorithms"/>
    /// to reject unsupported algorithms early and prevent algorithm confusion. This
    /// validation is a defense-in-depth check — the JWE header is not yet authenticated
    /// at this point. Cryptographic authentication of the header happens inside
    /// <c>DecryptAsync</c> when AES-GCM verifies the authentication tag over the AAD
    /// (which is the Base64url-encoded protected header). Tampering with <c>enc</c>
    /// causes tag verification to fail.
    /// </para>
    /// <para>
    /// HAIP 1.0 requires the Verifier to advertise both <c>A128GCM</c> and <c>A256GCM</c>
    /// in <c>encrypted_response_enc_values_supported</c> per
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0 §5.1</see>.
    /// The Wallet selects one; this method decrypts whichever was chosen.
    /// </para>
    /// </remarks>
    /// <param name="compactJwe">
    /// The compact JWE string received in the <c>direct_post.jwt</c> request body.
    /// </param>
    /// <param name="ephemeralPrivateKey">
    /// The Verifier's ephemeral P-256 private key. Its public half was embedded in
    /// <c>client_metadata.jwks</c> inside the JAR.
    /// </param>
    /// <param name="allowedEncAlgorithms">
    /// The content encryption algorithms the Verifier advertised in
    /// <c>encrypted_response_enc_values_supported</c>. The <c>enc</c> in the JWE header
    /// must be one of these values.
    /// </param>
    /// <param name="decoder">Delegate for Base64url decoding.</param>
    /// <param name="keyAgreementDecryptDelegate">ECDH-ES P-256 key agreement decrypt delegate.</param>
    /// <param name="keyDerivationDelegate">Concat KDF delegate per RFC 7518 §4.6.2.</param>
    /// <param name="aeadDecryptDelegate">AES-GCM content decryption delegate.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The decrypted VP token payload bytes. The caller owns and must dispose.
    /// </returns>
    /// <exception cref="FormatException">
    /// Thrown when the compact JWE is malformed, the <c>enc</c> header is missing,
    /// or the <c>enc</c> value is not in <paramref name="allowedEncAlgorithms"/>.
    /// </exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown when authentication tag verification fails.
    /// </exception>
    public static async ValueTask<DecryptedContent> DecryptResponseAsync(
        string compactJwe,
        PrivateKeyMemory ephemeralPrivateKey,
        IReadOnlyList<string> allowedEncAlgorithms,
        DecodeDelegate decoder,
        KeyAgreementDecryptDelegate keyAgreementDecryptDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactJwe);
        ArgumentNullException.ThrowIfNull(ephemeralPrivateKey);
        ArgumentNullException.ThrowIfNull(allowedEncAlgorithms);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(keyAgreementDecryptDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(aeadDecryptDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        //Peek the enc value from the JWE protected header before any crypto.
        //The header is the first dot-separated segment, Base64url-encoded.
        int firstDot = compactJwe.IndexOf('.', StringComparison.Ordinal);
        if(firstDot < 0)
        {
            throw new FormatException(
                "Compact JWE must contain at least one dot-separated segment.");
        }

        using IMemoryOwner<byte> headerBytes = decoder(
            compactJwe.AsSpan(0, firstDot).ToString(), pool);

        string? enc = JwkJsonReader.ExtractStringValue(
            headerBytes.Memory.Span, "enc"u8);

        if(enc is null)
        {
            throw new FormatException(
                "JWE protected header does not contain the 'enc' parameter.");
        }

        bool encAllowed = false;
        foreach(string allowed in allowedEncAlgorithms)
        {
            if(string.Equals(enc, allowed, StringComparison.Ordinal))
            {
                encAllowed = true;
                break;
            }
        }

        if(!encAllowed)
        {
            throw new FormatException(
                $"JWE 'enc' value '{enc}' is not in the advertised " +
                $"encrypted_response_enc_values_supported list.");
        }

        using AeadMessage message = JweParsing.ParseCompact(
            compactJwe,
            WellKnownJweAlgorithms.EcdhEs,
            enc,
            decoder,
            pool);

        return await message.DecryptAsync(
            ephemeralPrivateKey,
            keyAgreementDecryptDelegate,
            keyDerivationDelegate,
            aeadDecryptDelegate,
            pool,
            cancellationToken).ConfigureAwait(false);
    }
}
