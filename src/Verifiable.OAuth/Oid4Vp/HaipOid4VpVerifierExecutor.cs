using System.Buffers;
using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Creates a pre-wired <see cref="OAuthActionExecutor"/> for the HAIP 1.0
/// OID4VP Verifier server flow.
/// </summary>
/// <remarks>
/// <para>
/// Two factory methods are provided:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="Create"/> — full control. The caller supplies the three ECDH-ES
///       crypto delegates explicitly. Use in tests and in applications where the crypto
///       backend must be auditable at the call site.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="CreateWithRegistry"/> — convenient. The three crypto delegates
///       are resolved from
///       <see cref="KeyAgreementFunctionRegistry{TAlgorithm,TPurpose}"/> at decrypt time
///       using the decryption key's <see cref="Tag"/>. Use when the registry is
///       guaranteed to be populated at startup.
///     </description>
///   </item>
/// </list>
/// <para>
/// Key resolvers (<see cref="AuthorizationServerCryptography.SigningKeyResolver"/>,
/// <see cref="AuthorizationServerCryptography.DecryptionKeyResolver"/>),
/// client registration lookup (<see cref="AuthorizationServerIntegration.LoadClientRegistrationAsync"/>),
/// and the Base64url encoder (<see cref="AuthorizationServerCodecs.Encoder"/>) are
/// read from the <see cref="EndpointServer"/> instance at call time — they
/// are not captured at construction.
/// </para>
/// </remarks>
[DebuggerDisplay("HaipOid4VpVerifierExecutor")]
public static class HaipOid4VpVerifierExecutor
{
    /// <summary>
    /// Creates a pre-wired <see cref="OAuthActionExecutor"/> with the three ECDH-ES
    /// crypto delegates supplied explicitly by the caller.
    /// </summary>
    /// <param name="headerSerializer">Delegate for serializing JWT headers.</param>
    /// <param name="payloadSerializer">Delegate for serializing JWT payloads.</param>
    /// <param name="dcqlQuerySerializer">Delegate for serializing DCQL queries.</param>
    /// <param name="clientMetadataSerializer">Delegate for serializing client metadata.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="resolveIssuerKey">
    /// Resolves an issuer public key from its identifier for credential signature verification.
    /// </param>
    /// <param name="parseSdJwtToken">
    /// Parses an SD-JWT from its wire format. Wired to <c>SdJwtSerializer.ParseToken</c>.
    /// </param>
    /// <param name="computeSdJwtHashInput">
    /// Computes the <c>sd_hash</c> input string. Wired to <c>SdJwtSerializer.GetSdJwtForHashing</c>.
    /// </param>
    /// <param name="keyAgreementDecryptDelegate">
    /// ECDH-ES key agreement decryption delegate per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">RFC 7518 §4.6</see>.
    /// </param>
    /// <param name="keyDerivationDelegate">
    /// Concat KDF key derivation delegate per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6.2">RFC 7518 §4.6.2</see>.
    /// </param>
    /// <param name="aeadDecryptDelegate">AES-GCM content decryption delegate.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="keyAgreementEncryptDelegate">
    /// Optional ECDH-ES encryption delegate used by the
    /// <see cref="SignJarAction"/> handler to JWE-wrap the signed JAR per OID4VP
    /// 1.0 §5.10 when the Wallet supplies <c>wallet_metadata.jwks</c>. Required
    /// alongside <paramref name="aeadEncryptDelegate"/> when JAR encryption is
    /// to be supported; pass <see langword="null"/> for signed-JAR-only deployments.
    /// </param>
    /// <param name="aeadEncryptDelegate">
    /// Optional AES-GCM content encryption delegate paired with
    /// <paramref name="keyAgreementEncryptDelegate"/>. <see langword="null"/>
    /// when JAR encryption is not supported.
    /// </param>
    /// <param name="tagToEpkCrvConverter">
    /// Optional <see cref="Tag"/> → JWK <c>crv</c> converter used by the JAR
    /// encryption path to populate the EPK header. <see langword="null"/>
    /// when JAR encryption is not supported.
    /// </param>
    public static OAuthActionExecutor Create(
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        JarClaimSerializer<DcqlQuery> dcqlQuerySerializer,
        JarClaimSerializer<VerifierClientMetadata> clientMetadataSerializer,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ParseSdJwtTokenDelegate parseSdJwtToken,
        ComputeSdJwtHashInputDelegate computeSdJwtHashInput,
        ComputeDigestDelegate computeDigest,
        IReadOnlyDictionary<string, ClaimIssuer<ValidationContext>> vpValidators,
        KeyAgreementDecryptDelegate keyAgreementDecryptDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> pool,
        KeyAgreementEncryptDelegate? keyAgreementEncryptDelegate = null,
        AeadEncryptDelegate? aeadEncryptDelegate = null,
        TagToEpkCrvDelegate? tagToEpkCrvConverter = null,
        MdocVpVerificationSeams? mdocSeams = null,
        SdCwtVpVerificationSeams? sdCwtSeams = null,
        CommitmentReuseDetectionSeam? saltReuseSeam = null,
        AssessVpDisclosureDelegate? assessDisclosure = null)
    {
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(dcqlQuerySerializer);
        ArgumentNullException.ThrowIfNull(clientMetadataSerializer);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(parseSdJwtToken);
        ArgumentNullException.ThrowIfNull(computeSdJwtHashInput);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(vpValidators);
        ArgumentNullException.ThrowIfNull(keyAgreementDecryptDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(aeadDecryptDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        return BuildExecutor(
            headerSerializer,
            payloadSerializer,
            dcqlQuerySerializer,
            clientMetadataSerializer,
            decoder,
            encoder,
            resolveIssuerKey,
            parseSdJwtToken,
            computeSdJwtHashInput,
            computeDigest,
            vpValidators,
            keyAgreementDecryptDelegate,
            keyDerivationDelegate,
            aeadDecryptDelegate,
            pool,
            useRegistry: false,
            keyAgreementEncryptDelegate: keyAgreementEncryptDelegate,
            aeadEncryptDelegate: aeadEncryptDelegate,
            tagToEpkCrvConverter: tagToEpkCrvConverter,
            mdocSeams: mdocSeams,
            sdCwtSeams: sdCwtSeams,
            saltReuseSeam: saltReuseSeam,
            assessDisclosure: assessDisclosure);
    }


    /// <summary>
    /// Creates a pre-wired <see cref="OAuthActionExecutor"/> that resolves the three
    /// crypto delegates from
    /// <see cref="KeyAgreementFunctionRegistry{TAlgorithm,TPurpose}"/> at decrypt time.
    /// </summary>
    /// <remarks>
    /// The registry must be populated before the first <c>direct_post</c> request
    /// arrives. Delegates are resolved from the decryption key's <see cref="Tag"/>.
    /// </remarks>
    /// <param name="headerSerializer">Delegate for serializing JWT headers.</param>
    /// <param name="payloadSerializer">Delegate for serializing JWT payloads.</param>
    /// <param name="dcqlQuerySerializer">Delegate for serializing DCQL queries.</param>
    /// <param name="clientMetadataSerializer">Delegate for serializing client metadata.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="resolveIssuerKey">
    /// Resolves an issuer public key from its identifier for credential signature verification.
    /// </param>
    /// <param name="pool">Memory pool for allocations.</param>
    public static OAuthActionExecutor CreateWithRegistry(
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        JarClaimSerializer<DcqlQuery> dcqlQuerySerializer,
        JarClaimSerializer<VerifierClientMetadata> clientMetadataSerializer,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ParseSdJwtTokenDelegate parseSdJwtToken,
        ComputeSdJwtHashInputDelegate computeSdJwtHashInput,
        ComputeDigestDelegate computeDigest,
        IReadOnlyDictionary<string, ClaimIssuer<ValidationContext>> vpValidators,
        MemoryPool<byte> pool,
        MdocVpVerificationSeams? mdocSeams = null,
        SdCwtVpVerificationSeams? sdCwtSeams = null,
        CommitmentReuseDetectionSeam? saltReuseSeam = null,
        AssessVpDisclosureDelegate? assessDisclosure = null)
    {
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(dcqlQuerySerializer);
        ArgumentNullException.ThrowIfNull(clientMetadataSerializer);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(parseSdJwtToken);
        ArgumentNullException.ThrowIfNull(computeSdJwtHashInput);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(vpValidators);
        ArgumentNullException.ThrowIfNull(pool);

        return BuildExecutor(
            headerSerializer,
            payloadSerializer,
            dcqlQuerySerializer,
            clientMetadataSerializer,
            decoder,
            encoder,
            resolveIssuerKey,
            parseSdJwtToken,
            computeSdJwtHashInput,
            computeDigest,
            vpValidators,
            keyAgreementDecryptDelegate: null!,
            keyDerivationDelegate: null!,
            aeadDecryptDelegate: null!,
            pool,
            useRegistry: true,
            keyAgreementEncryptDelegate: null,
            aeadEncryptDelegate: null,
            tagToEpkCrvConverter: null,
            mdocSeams: mdocSeams,
            sdCwtSeams: sdCwtSeams,
            saltReuseSeam: saltReuseSeam,
            assessDisclosure: assessDisclosure);
    }


    private static OAuthActionExecutor BuildExecutor(
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        JarClaimSerializer<DcqlQuery> dcqlQuerySerializer,
        JarClaimSerializer<VerifierClientMetadata> clientMetadataSerializer,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ParseSdJwtTokenDelegate parseSdJwtToken,
        ComputeSdJwtHashInputDelegate computeSdJwtHashInput,
        ComputeDigestDelegate computeDigest,
        IReadOnlyDictionary<string, ClaimIssuer<ValidationContext>> vpValidators,
        KeyAgreementDecryptDelegate keyAgreementDecryptDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> pool,
        bool useRegistry,
        KeyAgreementEncryptDelegate? keyAgreementEncryptDelegate,
        AeadEncryptDelegate? aeadEncryptDelegate,
        TagToEpkCrvDelegate? tagToEpkCrvConverter,
        MdocVpVerificationSeams? mdocSeams,
        SdCwtVpVerificationSeams? sdCwtSeams,
        CommitmentReuseDetectionSeam? saltReuseSeam,
        AssessVpDisclosureDelegate? assessDisclosure)
    {
        var executor = new OAuthActionExecutor();

        executor.Register<SignJarAction>(async (action, context, ct) =>
        {
            EndpointServer server = context.Server!;
            var oauth = server.OAuth();

            TenantId tenantId = context.TenantId
                ?? throw new InvalidOperationException(
                    "Tenant identifier not found in context.");

            PrivateKeyMemory? signingKey = await oauth.Cryptography.SigningKeyResolver!(
                action.SigningKeyId, tenantId, context, ct).ConfigureAwait(false);

            if(signingKey is null)
            {
                throw new InvalidOperationException(
                    $"Signing key '{action.SigningKeyId}' not found.");
            }

            ClientRecord? registration = (ClientRecord?)await oauth.LoadClientRegistrationAsync!(
                tenantId, context, ct).ConfigureAwait(false);

            if(registration is null)
            {
                throw new InvalidOperationException(
                    $"Client registration for tenant '{tenantId.Value}' not found.");
            }

            if(registration.ResponseUri is null)
            {
                throw new InvalidOperationException(
                    $"ClientRecord for tenant '{tenantId.Value}' has no ResponseUri.");
            }

            if(registration.ClientMetadata is null)
            {
                throw new InvalidOperationException(
                    $"ClientRecord for tenant '{tenantId.Value}' has no ClientMetadata.");
            }

            //Stamp JAR timing claims using the dispatcher's per-request VerifiedAt
            //when available so all effectful work in this request shares one
            //instant; fall back to the active TimeProvider otherwise. The window
            //size is policy, sourced from oauth.Timings per FAPI 2.0 §5.2.2
            //Clause 13.
            DateTimeOffset now = context.VerifiedAt ?? server.TimeProvider.GetUtcNow();
            TimeSpan requestObjectLifetime = oauth.Timings.Oid4VpRequestObjectLifetime;

            //SignJarAction carries the per-flow response_mode (captured at
            //PAR time onto VerifierParReceivedState and propagated through
            //the action). Null lets HaipProfile default to direct_post.jwt
            //— the HAIP 1.0 §5.1 mandated path.
            (JarSigned jarInput, string compactJar) = await HaipProfile.BuildJarAsync(
                now: now,
                requestObjectLifetime: requestObjectLifetime,
                state: action.ParHandle,
                nonce: action.Nonce,
                dcqlQuery: action.Query,
                clientId: registration.ClientId,
                responseUri: registration.ResponseUri,
                clientMetadata: registration.ClientMetadata,
                signingKey: signingKey,
                headerSerializer: headerSerializer,
                payloadSerializer: payloadSerializer,
                dcqlQuerySerializer: dcqlQuerySerializer,
                clientMetadataSerializer: clientMetadataSerializer,
                encoder: oauth.Codecs.Encoder!,
                pool: pool,
                transactionData: action.TransactionData,
                walletNonce: action.WalletNonce,
                additionalHeaderClaims: action.AdditionalHeaderClaims,
                responseMode: action.ResponseMode,
                cancellationToken: ct).ConfigureAwait(false);

            //OID4VP 1.0 §5.10 JAR encryption: when the Wallet POSTed
            //wallet_metadata containing a jwks object to request_uri, the
            //library transition extracted the jwks JSON text and put it on
            //SignJarAction.WalletEncryptionJwksJson; JWE-wrap the signed JWS
            //using the wallet's public exchange key from that JWKS. The wire
            //body becomes a compact JWE; the wallet decrypts before
            //signature verification. Absent the JWKS this branch is skipped
            //and the signed JWS is served as-is.
            if(action.WalletEncryptionJwksJson is { } walletJwksJson)
            {
                //Recover the wallet's exchange key for any supported ECDH-ES curve
                //(P-256 — the HAIP 1.0 §5.1 default — or an RFC 5639 Brainpool curve).
                //The recovered key carries the matching exchange tag, which drives both
                //the epk crv emission and, in registry mode, the curve-specific delegate
                //resolution below.
                using PublicKeyMemory walletExchangePublicKey =
                    JwksEpkExtractor.ExtractEcdhEncryptionKey(walletJwksJson, decoder, pool);

                //Resolve the encrypt-side delegates. Registry mode dispatches them from
                //the wallet key's curve so any supported curve works without the caller
                //pinning a single curve at construction. Explicit mode uses the delegates
                //the caller wired (P-256 in practice).
                KeyAgreementEncryptDelegate encryptAgreement;
                KeyDerivationDelegate deriveKey;
                AeadEncryptDelegate encryptAead;
                TagToEpkCrvDelegate crvConverter;

                if(useRegistry)
                {
                    CryptoAlgorithm walletAlg = walletExchangePublicKey.Tag.Get<CryptoAlgorithm>();
                    Purpose walletPurpose = walletExchangePublicKey.Tag.Get<Purpose>();

                    encryptAgreement = KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>
                        .ResolveAgreementEncrypt(walletAlg, walletPurpose);
                    deriveKey = KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>
                        .ResolveKeyDerivation(walletAlg, walletPurpose);
                    encryptAead = KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>
                        .ResolveAeadEncrypt(walletAlg, walletPurpose);
                    crvConverter = CryptoFormatConversions.DefaultTagToEpkCrvConverter;
                }
                else
                {
                    if(keyAgreementEncryptDelegate is null
                        || aeadEncryptDelegate is null
                        || tagToEpkCrvConverter is null)
                    {
                        throw new InvalidOperationException(
                            "Wallet supplied wallet_metadata.jwks for JAR encryption " +
                            "per OID4VP 1.0 §5.10 but the executor was constructed " +
                            "without the encrypt-side delegates. Pass " +
                            "keyAgreementEncryptDelegate, aeadEncryptDelegate, and " +
                            "tagToEpkCrvConverter to HaipOid4VpVerifierExecutor.Create.");
                    }

                    encryptAgreement = keyAgreementEncryptDelegate;
                    deriveKey = keyDerivationDelegate;
                    encryptAead = aeadEncryptDelegate;
                    crvConverter = tagToEpkCrvConverter;
                }

                //Rent from the executor's pool rather than allocating a managed
                //array with Encoding.UTF8.GetBytes — keeps the JAR plaintext
                //inside the pool's accounting until JWE-wrapped, matching the
                //rest of the executor's buffer discipline.
                int jarByteCount = Encoding.UTF8.GetByteCount(compactJar);
                using IMemoryOwner<byte> jarBytes = pool.Rent(jarByteCount);
                int written = Encoding.UTF8.GetBytes(
                    compactJar, jarBytes.Memory.Span);

                //Default to A128GCM for JAR encryption — OID4VP §5.10 does
                //not pin an algorithm; production deployments should select
                //from the wallet_metadata-advertised set. The action's
                //JarEncryptionEnc carries the wallet's
                //authorization_encrypted_response_enc choice when supplied.
                string selectedEnc = action.JarEncryptionEnc
                    ?? WellKnownJweEncryptionAlgorithms.A128Gcm;

                compactJar = await HaipProfile.EncryptResponseAsync(
                    walletExchangePublicKey,
                    selectedEnc,
                    jarBytes.Memory[..written],
                    headerSerializer,
                    crvConverter,
                    encryptAgreement,
                    deriveKey,
                    encryptAead,
                    oauth.Codecs.Encoder!,
                    pool,
                    cancellationToken: ct).ConfigureAwait(false);
            }

            //Write the (signed-then-optionally-encrypted) JAR to context so the
            //application skin can serve it in the HTTP response body at the
            //JAR-fetch endpoint.
            context.SetJar(compactJar);

            DateTimeOffset servedAt = context.VerifiedAt
                ?? throw new InvalidOperationException(
                    "Request timestamp not found in context.");

            return new ServerJarSigned(jarInput.Jar, compactJar, servedAt);
        });

        executor.Register<DecryptResponseAction>(async (action, context, ct) =>
        {
            EndpointServer server = context.Server!;
            var oauth = server.OAuth();

            PrivateKeyMemory? decryptionKey = await oauth.Cryptography.DecryptionKeyResolver!(
                action.DecryptionKeyId, context, ct).ConfigureAwait(false);

            if(decryptionKey is null)
            {
                throw new InvalidOperationException(
                    $"Decryption key '{action.DecryptionKeyId}' not found.");
            }

            DecryptedContent decrypted;

            if(useRegistry)
            {
                //Peek enc from the JWE header before any cryptographic operation.
                //This is an early validation — not yet authenticated. The header is
                //authenticated by AES-GCM tag verification inside DecryptAsync.
                int firstDot = action.EncryptedResponseJwt.IndexOf(
                    '.', StringComparison.Ordinal);

                if(firstDot < 0)
                {
                    throw new FormatException(
                        "Compact JWE must contain at least one dot-separated segment.");
                }

                using IMemoryOwner<byte> headerBytes = decoder(
                    action.EncryptedResponseJwt.AsSpan(0, firstDot).ToString(), pool);

                string? enc = JwkJsonReader.ExtractStringValue(
                    headerBytes.Memory.Span, "enc"u8);

                if(enc is null)
                {
                    throw new FormatException(
                        "JWE protected header does not contain the 'enc' parameter.");
                }

                bool encAllowed = false;
                foreach(string allowed in action.AllowedEncAlgorithms)
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
                    action.EncryptedResponseJwt,
                    WellKnownJweAlgorithms.EcdhEs,
                    enc,
                    decoder,
                    pool);

                decrypted = await message.DecryptAsync(
                    decryptionKey, pool, ct).ConfigureAwait(false);
            }
            else
            {
                decrypted = await HaipProfile.DecryptResponseAsync(
                    compactJwe: action.EncryptedResponseJwt,
                    ephemeralPrivateKey: decryptionKey,
                    allowedEncAlgorithms: action.AllowedEncAlgorithms,
                    decoder: decoder,
                    keyAgreementDecryptDelegate: keyAgreementDecryptDelegate,
                    keyDerivationDelegate: keyDerivationDelegate,
                    aeadDecryptDelegate: aeadDecryptDelegate,
                    pool: pool,
                    cancellationToken: ct).ConfigureAwait(false);
            }

            using DecryptedContent ownedDecrypted = decrypted;

            //OID4VP 1.0 §8.3.1: the direct_post.jwt JWE plaintext is the response JWT
            //payload carrying the Authorization Response parameters as NAMED CLAIMS, so
            //the §8.1 DCQL-keyed vp_token object is under the "vp_token" claim — not at
            //the top level of the decrypted plaintext. Extract it once; every
            //per-credential presentation is read from this nested object.
            string vpTokenObjectJson =
                JwkJsonReader.ExtractObjectAsString(ownedDecrypted.AsReadOnlySpan(), "vp_token"u8)
                ?? throw new FormatException(
                    "The decrypted direct_post.jwt response carries no 'vp_token' claim; per " +
                    "OID4VP 1.0 §8.3.1 the response JWT payload must be {\"vp_token\": {...}, \"state\": ...}.");

            //Pool the vp_token object bytes (no naked byte[]). The owner is held across
            //the per-credential await loop; each read takes a fresh span off the Memory.
            using IMemoryOwner<byte> vpTokenObjectOwner =
                pool.Rent(Encoding.UTF8.GetByteCount(vpTokenObjectJson));
            int vpTokenObjectLength =
                Encoding.UTF8.GetBytes(vpTokenObjectJson, vpTokenObjectOwner.Memory.Span);
            ReadOnlyMemory<byte> vpTokenObject = vpTokenObjectOwner.Memory[..vpTokenObjectLength];

            context.SetTransactionNonce(action.Nonce);

            ClientRecord registration = context.ClientRegistration
                ?? throw new InvalidOperationException(
                    "Client registration not found in context.");

            TenantId tenantId = context.TenantId
                ?? throw new InvalidOperationException(
                    "Tenant identifier not found in context.");

            DateTimeOffset now = server.TimeProvider.GetUtcNow();

            //OID4VP 1.0 §8.4 — when the Verifier sent transaction_data, recompute
            //the expected hashes and surface them on the validation context so
            //ValidationChecks.CheckKbJwtTransactionDataHashes can compare against
            //the KB-JWT echo. Computed once and reused across per-credential
            //validation contexts.
            IReadOnlyList<string>? expectedTransactionDataHashes = null;
            if(action.TransactionData is { Count: > 0 } txData)
            {
                expectedTransactionDataHashes =
                    await TransactionDataHasher.ComputeSha256Async(
                        txData,
                        oauth.Codecs.Encoder!,
                        pool,
                        ct).ConfigureAwait(false);
            }

            //OID4VP 1.0 §8.1: vp_token is a JSON object whose keys are DCQL
            //credential query identifiers and whose values are arrays of one
            //or more compact presentations. Multi-credential presentations
            //carry several entries; single-credential is the trivial case
            //with one entry. The handler extracts and verifies each in turn
            //and aggregates the verified claims keyed by credential query id.
            Dictionary<string, IReadOnlyDictionary<string, string>> aggregatedClaims =
                new(StringComparer.Ordinal);

            //OID4VP 1.0 Appendix B.2.6.1: an mso_mdoc presentation's SessionTranscript
            //binds the wallet's fresh mdoc_generated_nonce, which the wallet carries in
            //the response JWE's 'apu' protected-header parameter (ISO/IEC 18013-7 §B.4.4).
            //Recover it once here from the same compact JWE the decrypt step consumed; the
            //per-credential mdoc branch reconstructs the transcript from it. SD-JWT-only
            //responses carry no mso_mdoc query and skip this entirely.
            using IMemoryOwner<byte>? mdocGeneratedNonce =
                action.CredentialQueries.Any(static q =>
                    string.Equals(q.Format, DcqlCredentialFormats.MsoMdoc, StringComparison.Ordinal))
                    ? ExtractMdocGeneratedNonce(action.EncryptedResponseJwt, mdocSeams, decoder, pool)
                    : null;

            foreach(CredentialQuery credentialQuery in action.CredentialQueries)
            {
                string credentialQueryId = credentialQuery.Id!;

                //Multi-format dispatch: the parse step differs per DCQL Format (SD-JWT
                //KB-JWT vs mdoc DeviceResponse), but the validate step below is uniform —
                //each format's VpTokenParsed flows through the format-keyed ClaimIssuer, so
                //every credential is checked on the same pipeline. A format with no
                //registered validator is a verifier-capability error.
                if(credentialQuery.Format is not { } credentialFormat
                    || !vpValidators.TryGetValue(credentialFormat, out ClaimIssuer<ValidationContext>? formatValidator))
                {
                    throw new NotSupportedException(
                        $"VP-token verification for credential format '{credentialQuery.Format}' is not wired " +
                        $"(credential query '{credentialQueryId}'); no validator is registered for that format.");
                }

                VpTokenParsed parsed;
                if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.SdJwt, StringComparison.Ordinal))
                {
                    string compactPresentation =
                        JwkJsonReader.ExtractFirstStringFromArrayProperty(
                            vpTokenObject.Span,
                            Encoding.UTF8.GetBytes(credentialQueryId))
                        ?? throw new FormatException(
                            $"vp_token does not contain a non-empty array of presentations " +
                            $"under credential query identifier '{credentialQueryId}'.");

                    parsed = await SdJwtVpTokenVerification.VerifyAsync(
                        compactPresentation, credentialQueryId, parseSdJwtToken, computeSdJwtHashInput,
                        resolveIssuerKey, computeDigest, decoder, encoder, pool, saltReuseSeam, ct)
                        .ConfigureAwait(false);
                }
                else if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.MsoMdoc, StringComparison.Ordinal))
                {
                    //client_id / response_uri / nonce are the verifier's own JAR inputs from
                    //persisted state; response_uri must be the byte-exact OriginalString the
                    //JAR emitted (the codebase serialises URIs via Uri.OriginalString) so the
                    //reconstructed transcript hashes identically to the wallet's.
                    string responseUri = registration.ResponseUri?.OriginalString
                        ?? throw new InvalidOperationException(
                            $"ClientRecord for the flow has no ResponseUri; it is required to reconstruct " +
                            $"the mdoc SessionTranscript for credential query '{credentialQueryId}'.");

                    string compactPresentation =
                        JwkJsonReader.ExtractFirstStringFromArrayProperty(
                            vpTokenObject.Span,
                            Encoding.UTF8.GetBytes(credentialQueryId))
                        ?? throw new FormatException(
                            $"vp_token does not contain a non-empty array of presentations " +
                            $"under credential query identifier '{credentialQueryId}'.");

                    //mdocGeneratedNonce is non-null here: ExtractMdocGeneratedNonce ran above
                    //because this response carries an mso_mdoc query, and it also asserted the
                    //mdoc seams were supplied.
                    parsed = await MdocVpTokenVerification.VerifyAsync(
                        compactPresentation, credentialQueryId, mdocSeams!.ResolveIssuerKey,
                        mdocSeams.ExtractAuthorityIdentifier,
                        registration.ClientId, responseUri, action.Nonce.Value, mdocGeneratedNonce!.Memory,
                        mdocSeams.ParseDeviceResponse, mdocSeams.EncodeSessionTranscript, mdocSeams.DecodeElementValue,
                        mdocSeams.ParseCoseSign1, mdocSeams.ParseCoseSign1AllowingNilPayload,
                        mdocSeams.EncodeDeviceAuthenticationBytes, mdocSeams.BuildSigStructure,
                        decoder, pool, ct).ConfigureAwait(false);
                }
                else if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.SdCwt, StringComparison.Ordinal))
                {
                    SdCwtVpVerificationSeams seams = sdCwtSeams
                        ?? throw new InvalidOperationException(
                            "The vp_token contains a dc+sd-cwt credential query but the executor was " +
                            "constructed without SD-CWT verification seams. Pass SdCwtVpVerificationSeams to " +
                            "HaipOid4VpVerifierExecutor.Create / CreateWithRegistry to enable dc+sd-cwt verification.");

                    string compactPresentation =
                        JwkJsonReader.ExtractFirstStringFromArrayProperty(
                            vpTokenObject.Span,
                            Encoding.UTF8.GetBytes(credentialQueryId))
                        ?? throw new FormatException(
                            $"vp_token does not contain a non-empty array of presentations " +
                            $"under credential query identifier '{credentialQueryId}'.");

                    parsed = await SdCwtVpTokenVerification.VerifyAsync(
                        compactPresentation, credentialQueryId, seams, decoder, saltReuseSeam, pool, ct)
                        .ConfigureAwait(false);
                }
                else
                {
                    throw new NotSupportedException(
                        $"VP-token verification for credential format '{credentialQuery.Format}' is not yet " +
                        $"supported (credential query '{credentialQueryId}').");
                }

                (bool dcqlSatisfied, bool dcqlOverDisclosed) = await AssessDcqlAsync(
                    assessDisclosure, credentialQuery, parsed, ct).ConfigureAwait(false);

                ValidationContext validationContext = new()
                {
                    Context = context,
                    Now = now,
                    ExpectedNonce = action.Nonce.Value,
                    ExpectedClientId = registration.ClientId,
                    KbJwtNonce = parsed.KbJwtNonce,
                    KbJwtAud = parsed.KbJwtAud,
                    KbJwtIat = parsed.KbJwtIat,
                    KbJwtSignatureValid = parsed.KbJwtSignatureValid,
                    CredentialSignatureValid = parsed.CredentialSignatureValid,
                    SdHashValid = parsed.SdHashValid,
                    SessionTranscriptValid = parsed.SessionTranscriptValid,
                    KbJwtTransactionDataHashes = parsed.KbJwtTransactionDataHashes,
                    ExpectedTransactionDataHashes = expectedTransactionDataHashes,
                    DcqlSatisfied = dcqlSatisfied,
                    DcqlOverDisclosed = dcqlOverDisclosed,
                    MinimumDisclosureSaltLengthBytes = parsed.MinimumDisclosureSaltLengthBytes,
                    SaltReused = parsed.SaltReused,
                };

                ClaimIssueResult verificationResult = await formatValidator.GenerateClaimsAsync(
                    validationContext, tenantId.Value, ct).ConfigureAwait(false);

                context.AddValidationResult(verificationResult);

                if(!verificationResult.IsComplete
                    || verificationResult.Claims.Any(static c => c.Outcome != ClaimOutcome.Success))
                {
                    DateTimeOffset failedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    return new Fail(
                        $"VP token verification failed for credential query '{credentialQueryId}'.",
                        failedAt);
                }

                //Multi-credential vp_token: merge this credential's extracted
                //claims into the aggregated dictionary under its own query id.
                //parsed.ExtractedClaims is keyed by credential query id already
                //(the per-format verifier wraps under the supplied id), so this
                //is a straight merge.
                foreach(KeyValuePair<string, IReadOnlyDictionary<string, string>> claim in parsed.ExtractedClaims)
                {
                    aggregatedClaims[claim.Key] = claim.Value;
                }
            }

            DateTimeOffset verifiedAt = context.VerifiedAt
                ?? throw new InvalidOperationException(
                    "Request timestamp not found in context.");

            return new VerificationSucceeded(
                aggregatedClaims,
                VerifiedAt: verifiedAt,
                RedirectUri: context.Oid4VpRedirectUri);
        });

        //Sibling handler for the unencrypted direct_post path per OID4VP 1.0
        //§8.2. Same verification pipeline as DecryptResponseAction above; the
        //only structural difference is the source of vp_token bytes — the
        //wallet POSTed them plaintext rather than wrapping them in a JWE so
        //the handler skips the JWE parse / decrypt / enc-allowlist gate.
        executor.Register<ProcessVpTokenAction>(async (action, context, ct) =>
        {
            EndpointServer server = context.Server!;
            var oauth = server.OAuth();

            context.SetTransactionNonce(action.Nonce);

            ClientRecord registration = context.ClientRegistration
                ?? throw new InvalidOperationException(
                    "Client registration not found in context.");

            TenantId tenantId = context.TenantId
                ?? throw new InvalidOperationException(
                    "Tenant identifier not found in context.");

            DateTimeOffset now = server.TimeProvider.GetUtcNow();

            IReadOnlyList<string>? expectedTransactionDataHashes = null;
            if(action.TransactionData is { Count: > 0 } txData)
            {
                expectedTransactionDataHashes =
                    await TransactionDataHasher.ComputeSha256Async(
                        txData,
                        oauth.Codecs.Encoder!,
                        pool,
                        ct).ConfigureAwait(false);
            }

            //OID4VP 1.0 §8.1: vp_token is a JSON object whose keys are DCQL
            //credential query identifiers and whose values are arrays of one
            //or more compact presentations. Multi-credential parity with the
            //encrypted-path handler above — extract, verify, aggregate. The
            //vp_token bytes are plaintext (no JWE), so they're materialised
            //once into a byte[] and re-scanned per credential query id.
            byte[] vpTokenBytes = Encoding.UTF8.GetBytes(action.VpTokenJson);

            Dictionary<string, IReadOnlyDictionary<string, string>> aggregatedClaims =
                new(StringComparer.Ordinal);

            foreach(CredentialQuery credentialQuery in action.CredentialQueries)
            {
                string credentialQueryId = credentialQuery.Id!;

                //mso_mdoc has no plaintext direct_post representation: its SessionTranscript
                //binds the wallet's mdoc_generated_nonce, carried only in an encrypted
                //response's JWE 'apu' header. HAIP never sends plaintext mdoc, so reject it
                //here rather than silently mis-binding.
                if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.MsoMdoc, StringComparison.Ordinal))
                {
                    throw new NotSupportedException(
                        $"mso_mdoc verification requires an encrypted response (direct_post.jwt); the wallet's " +
                        $"mdoc_generated_nonce is carried in the JWE 'apu' header and is absent from a plaintext " +
                        $"direct_post body (credential query '{credentialQueryId}').");
                }

                //Multi-format dispatch through the format-keyed ClaimIssuer — the same
                //pipeline as the encrypted path. Only dc+sd-jwt has a parse branch on the
                //plaintext path today.
                if(credentialQuery.Format is not { } credentialFormat
                    || !vpValidators.TryGetValue(credentialFormat, out ClaimIssuer<ValidationContext>? formatValidator))
                {
                    throw new NotSupportedException(
                        $"VP-token verification for credential format '{credentialQuery.Format}' is not wired " +
                        $"(credential query '{credentialQueryId}'); no validator is registered for that format.");
                }

                string compactPresentation =
                    JwkJsonReader.ExtractFirstStringFromArrayProperty(
                        vpTokenBytes, Encoding.UTF8.GetBytes(credentialQueryId))
                    ?? throw new FormatException(
                        $"vp_token does not contain a non-empty array of presentations " +
                        $"under credential query identifier '{credentialQueryId}'.");

                VpTokenParsed parsed;
                if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.SdJwt, StringComparison.Ordinal))
                {
                    parsed = await SdJwtVpTokenVerification.VerifyAsync(
                        compactPresentation, credentialQueryId, parseSdJwtToken, computeSdJwtHashInput,
                        resolveIssuerKey, computeDigest, decoder, encoder, pool, saltReuseSeam, ct)
                        .ConfigureAwait(false);
                }
                else if(string.Equals(credentialQuery.Format, DcqlCredentialFormats.SdCwt, StringComparison.Ordinal))
                {
                    SdCwtVpVerificationSeams seams = sdCwtSeams
                        ?? throw new InvalidOperationException(
                            "The vp_token contains a dc+sd-cwt credential query but the executor was " +
                            "constructed without SD-CWT verification seams. Pass SdCwtVpVerificationSeams to " +
                            "HaipOid4VpVerifierExecutor.Create / CreateWithRegistry to enable dc+sd-cwt verification.");

                    parsed = await SdCwtVpTokenVerification.VerifyAsync(
                        compactPresentation, credentialQueryId, seams, decoder, saltReuseSeam, pool, ct)
                        .ConfigureAwait(false);
                }
                else
                {
                    throw new NotSupportedException(
                        $"VP-token verification for credential format '{credentialQuery.Format}' is not yet " +
                        $"supported on the unencrypted direct_post path (credential query '{credentialQueryId}').");
                }

                (bool dcqlSatisfied, bool dcqlOverDisclosed) = await AssessDcqlAsync(
                    assessDisclosure, credentialQuery, parsed, ct).ConfigureAwait(false);

                ValidationContext validationContext = new()
                {
                    Context = context,
                    Now = now,
                    ExpectedNonce = action.Nonce.Value,
                    ExpectedClientId = registration.ClientId,
                    KbJwtNonce = parsed.KbJwtNonce,
                    KbJwtAud = parsed.KbJwtAud,
                    KbJwtIat = parsed.KbJwtIat,
                    KbJwtSignatureValid = parsed.KbJwtSignatureValid,
                    CredentialSignatureValid = parsed.CredentialSignatureValid,
                    SdHashValid = parsed.SdHashValid,
                    SessionTranscriptValid = parsed.SessionTranscriptValid,
                    KbJwtTransactionDataHashes = parsed.KbJwtTransactionDataHashes,
                    ExpectedTransactionDataHashes = expectedTransactionDataHashes,
                    DcqlSatisfied = dcqlSatisfied,
                    DcqlOverDisclosed = dcqlOverDisclosed,
                    MinimumDisclosureSaltLengthBytes = parsed.MinimumDisclosureSaltLengthBytes,
                    SaltReused = parsed.SaltReused,
                };

                ClaimIssueResult verificationResult = await formatValidator.GenerateClaimsAsync(
                    validationContext, tenantId.Value, ct).ConfigureAwait(false);

                context.AddValidationResult(verificationResult);

                if(!verificationResult.IsComplete
                    || verificationResult.Claims.Any(static c => c.Outcome != ClaimOutcome.Success))
                {
                    DateTimeOffset failedAt = context.VerifiedAt
                        ?? throw new InvalidOperationException(
                            "Request timestamp not found in context.");

                    return new Fail(
                        $"VP token verification failed for credential query '{credentialQueryId}'.",
                        failedAt);
                }

                foreach(KeyValuePair<string, IReadOnlyDictionary<string, string>> claim in parsed.ExtractedClaims)
                {
                    aggregatedClaims[claim.Key] = claim.Value;
                }
            }

            DateTimeOffset verifiedAt = context.VerifiedAt
                ?? throw new InvalidOperationException(
                    "Request timestamp not found in context.");

            return new VerificationSucceeded(
                aggregatedClaims,
                VerifiedAt: verifiedAt,
                RedirectUri: context.Oid4VpRedirectUri);
        });

        return executor;
    }


    /// <summary>
    /// Recovers the wallet's <c>mdoc_generated_nonce</c> from the
    /// <c>apu</c> protected-header parameter of the response JWE per
    /// <see href="https://www.iso.org/standard/82772.html">ISO/IEC 18013-7 §B.4.4</see>
    /// and OID4VP 1.0 Appendix B.2.6.1. Called only when the response carries an
    /// <c>mso_mdoc</c> credential query; doubles as the guard that the executor was
    /// constructed with mdoc verification seams.
    /// </summary>
    //Verifier-side DCQL satisfaction + no-over-disclosure, derived by dropping out
    //to the application-wired disclosure engine — the mirror of the wallet's
    //ProduceVpTokenPresentations seam. Behind AssessVpDisclosureDelegate the
    //application runs DcqlDisclosure.ComputeStrategyAsync over the disclosed claims
    //and returns graph.Satisfied (-> DcqlSatisfied) and whether any disclosed path
    //fell outside the engine's selected set (-> DcqlOverDisclosed). The library does
    //not run the engine itself. A query with no specific claims requests the whole
    //credential — satisfied, nothing extra — and needs no assessor. A claims-bearing
    //query with no assessor wired is a fail-closed configuration error: the
    //CheckDcqlSatisfaction / CheckNoOverDisclosure rules cannot be honoured.
    private static async ValueTask<(bool Satisfied, bool OverDisclosed)> AssessDcqlAsync(
        AssessVpDisclosureDelegate? assessDisclosure,
        CredentialQuery credentialQuery,
        VpTokenParsed parsed,
        CancellationToken cancellationToken)
    {
        if(credentialQuery.Claims is not { Count: > 0 })
        {
            return (Satisfied: true, OverDisclosed: false);
        }

        if(assessDisclosure is null)
        {
            throw new InvalidOperationException(
                "A DCQL credential query requests specific claims but the verifier executor was " +
                "constructed without a disclosure assessor. Pass assessDisclosure to " +
                "HaipOid4VpVerifierExecutor.Create / CreateWithRegistry (wiring DcqlDisclosure behind it) " +
                "to enable DCQL satisfaction / no-over-disclosure enforcement.");
        }

        IReadOnlyDictionary<CredentialPath, object?> disclosed =
            credentialQuery.Id is { } credentialQueryId
            && parsed.DisclosedClaimPaths.TryGetValue(
                credentialQueryId, out IReadOnlyDictionary<CredentialPath, object?>? d)
                ? d
                : EmptyDisclosedClaims;

        Oid4VpDisclosureAssessment assessment = await assessDisclosure(
            new Oid4VpDisclosureAssessmentContext
            {
                CredentialQuery = credentialQuery,
                DisclosedClaims = disclosed,
                Issuer = parsed.CredentialIssuer
            },
            cancellationToken).ConfigureAwait(false);

        return (assessment.Satisfied, assessment.OverDisclosed);
    }


    private static readonly IReadOnlyDictionary<CredentialPath, object?> EmptyDisclosedClaims =
        new Dictionary<CredentialPath, object?>();


    private static IMemoryOwner<byte> ExtractMdocGeneratedNonce(
        string encryptedResponseJwt,
        MdocVpVerificationSeams? mdocSeams,
        DecodeDelegate decoder,
        MemoryPool<byte> pool)
    {
        if(mdocSeams is null)
        {
            throw new InvalidOperationException(
                "The vp_token contains an mso_mdoc credential query but the executor was " +
                "constructed without mdoc verification seams. Pass MdocVpVerificationSeams to " +
                "HaipOid4VpVerifierExecutor.Create / CreateWithRegistry to enable mso_mdoc verification.");
        }

        int firstDot = encryptedResponseJwt.IndexOf('.', StringComparison.Ordinal);
        if(firstDot < 0)
        {
            throw new FormatException(
                "Compact JWE must contain at least one dot-separated segment to carry the 'apu' header.");
        }

        using IMemoryOwner<byte> headerBytes = decoder(
            encryptedResponseJwt.AsSpan(0, firstDot).ToString(), pool);

        string apu = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "apu"u8)
            ?? throw new FormatException(
                "An mso_mdoc Authorization Response JWE must carry the wallet's mdoc_generated_nonce " +
                "in the 'apu' protected-header parameter per ISO/IEC 18013-7 §B.4.4; none was present.");

        return decoder(apu, pool);
    }
}
