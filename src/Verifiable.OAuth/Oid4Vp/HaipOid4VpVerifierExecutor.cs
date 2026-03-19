using System.Buffers;
using System.Diagnostics;
using Verifiable.Core.Assessment;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp.Server;
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
/// Key resolvers (<see cref="AuthorizationServerOptions.SigningKeyResolver"/>,
/// <see cref="AuthorizationServerOptions.DecryptionKeyResolver"/>),
/// client registration lookup (<see cref="AuthorizationServerOptions.LoadClientRegistrationAsync"/>),
/// and the Base64url encoder (<see cref="AuthorizationServerOptions.Encoder"/>) are
/// read from <see cref="AuthorizationServerOptions"/> at call time — they are not
/// captured at construction.
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
        HashFunctionSelector hashFunctionSelector,
        ClaimIssuer<ValidationContext> vpValidator,
        KeyAgreementDecryptDelegate keyAgreementDecryptDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> pool)
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
        ArgumentNullException.ThrowIfNull(hashFunctionSelector);
        ArgumentNullException.ThrowIfNull(vpValidator);
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
            hashFunctionSelector,
            vpValidator,
            keyAgreementDecryptDelegate,
            keyDerivationDelegate,
            aeadDecryptDelegate,
            pool,
            useRegistry: false);
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
        HashFunctionSelector hashFunctionSelector,
        ClaimIssuer<ValidationContext> vpValidator,
        MemoryPool<byte> pool)
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
        ArgumentNullException.ThrowIfNull(hashFunctionSelector);
        ArgumentNullException.ThrowIfNull(vpValidator);
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
            hashFunctionSelector,
            vpValidator,
            keyAgreementDecryptDelegate: null!,
            keyDerivationDelegate: null!,
            aeadDecryptDelegate: null!,
            pool,
            useRegistry: true);
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
        HashFunctionSelector hashFunctionSelector,
        ClaimIssuer<ValidationContext> vpValidator,
        KeyAgreementDecryptDelegate keyAgreementDecryptDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> pool,
        bool useRegistry)
    {
        var executor = new OAuthActionExecutor();

        executor.Register<SignJarAction>(async (action, context, options, ct) =>
        {
            PrivateKeyMemory? signingKey = await options.SigningKeyResolver!(
                action.SigningKeyId.Value, context, ct).ConfigureAwait(false);

            if(signingKey is null)
            {
                throw new InvalidOperationException(
                    $"Signing key '{action.SigningKeyId}' not found.");
            }

            TenantId tenantId = context.TenantId
                ?? throw new InvalidOperationException(
                    "Tenant identifier not found in context.");

            ClientRegistration? registration = await options.LoadClientRegistrationAsync!(
                tenantId, context, ct).ConfigureAwait(false);

            if(registration is null)
            {
                throw new InvalidOperationException(
                    $"Client registration for tenant '{tenantId.Value}' not found.");
            }

            if(registration.ResponseUri is null)
            {
                throw new InvalidOperationException(
                    $"ClientRegistration for tenant '{tenantId.Value}' has no ResponseUri.");
            }

            if(registration.ClientMetadata is null)
            {
                throw new InvalidOperationException(
                    $"ClientRegistration for tenant '{tenantId.Value}' has no ClientMetadata.");
            }

            (JarSigned jarInput, string compactJar) = await HaipProfile.BuildJarAsync(
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
                encoder: options.Encoder!,
                pool: pool,
                cancellationToken: ct).ConfigureAwait(false);

            //Write the signed JAR to context so the ASP.NET skin can serve it
            //in the HTTP response body at the JAR request endpoint.
            context.SetJar(compactJar);

            DateTimeOffset servedAt = context.VerifiedAt
                ?? throw new InvalidOperationException(
                    "Request timestamp not found in context.");

            return new ServerJarSigned(jarInput.Jar, compactJar, servedAt);
        });

        executor.Register<DecryptResponseAction>(async (action, context, options, ct) =>
        {
            PrivateKeyMemory? decryptionKey = await options.DecryptionKeyResolver!(
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

            string vpTokenJson =
                System.Text.Encoding.UTF8.GetString(ownedDecrypted.AsReadOnlySpan());

            context.SetTransactionNonce(action.Nonce);

            //TODO: Add CredentialQueryId to DecryptResponseAction so the PDA
            //carries the matched credential query identifier through the flow.
            //For single-credential VP responses this is always the first query ID.
            const string credentialQueryId = "pid";

            VpTokenParsed parsed = await SdJwtVpTokenVerification.VerifyAsync(
                vpTokenJson, credentialQueryId, parseSdJwtToken, computeSdJwtHashInput,
                resolveIssuerKey, hashFunctionSelector, decoder, encoder, pool, ct)
                .ConfigureAwait(false);

            ClientRegistration registration = context.Registration
                ?? throw new InvalidOperationException(
                    "Client registration not found in context.");

            TenantId tenantId = context.TenantId
                ?? throw new InvalidOperationException(
                    "Tenant identifier not found in context.");

            DateTimeOffset now = options.TimeProvider?.GetUtcNow()
                ?? TimeProvider.System.GetUtcNow();

            ValidationContext validationContext = new()
            {
                Now = now,
                ExpectedNonce = action.Nonce.Value,
                ExpectedClientId = registration.ClientId,
                AllowedEncAlgorithms = action.AllowedEncAlgorithms,
                KbJwtNonce = parsed.KbJwtNonce,
                KbJwtAud = parsed.KbJwtAud,
                KbJwtIat = parsed.KbJwtIat,
                KbJwtSignatureValid = parsed.KbJwtSignatureValid,
                CredentialSignatureValid = parsed.CredentialSignatureValid,
                SdHashValid = parsed.SdHashValid,
                SessionTranscriptValid = parsed.SessionTranscriptValid,
            };

            ClaimIssueResult verificationResult = await vpValidator.GenerateClaimsAsync(
                validationContext, tenantId.Value, ct).ConfigureAwait(false);

            context.AddValidationResult(verificationResult);

            if(!verificationResult.IsComplete
                || verificationResult.Claims.Any(static c => c.Outcome != ClaimOutcome.Success))
            {
                DateTimeOffset failedAt = context.VerifiedAt
                    ?? throw new InvalidOperationException(
                        "Request timestamp not found in context.");

                return new Fail("VP token verification failed.", failedAt);
            }

            DateTimeOffset verifiedAt = context.VerifiedAt
                ?? throw new InvalidOperationException(
                    "Request timestamp not found in context.");

            return new VerificationSucceeded(
                parsed.ExtractedClaims,
                VerifiedAt: verifiedAt,
                RedirectUri: context.Oid4VpRedirectUri);
        });

        return executor;
    }
}
