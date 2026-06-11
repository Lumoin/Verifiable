using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// Typed accessor extensions for SIOPv2 Relying-Party request-preparation entries in an
/// <see cref="ExchangeContext"/>.
/// </summary>
/// <remarks>
/// Input entries are set by the Relying-Party application before dispatching the request-
/// preparation request; the preparation endpoint reads them to mint the
/// <see cref="States.SiopRequestPreparedState"/>. The output entry is set by the endpoint and read
/// by the application after dispatch. The underlying keys are defined in
/// <see cref="SiopVerifierContextKeys"/>. This mirrors
/// <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpServerExchangeContextExtensions"/>.
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 13 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class SiopVerifierExchangeContextExtensions
{
    extension(ExchangeContext context)
    {
        //Input accessors — set by the application before dispatching the preparation request.

        /// <summary>Gets the transaction nonce the Self-Issued ID Token must echo.</summary>
        public string? SiopNonce =>
            context.TryGetValue(SiopVerifierContextKeys.Nonce, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the transaction nonce. Called by the application before dispatching the preparation request.</summary>
        public void SetSiopNonce(string nonce)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(nonce);
            context[SiopVerifierContextKeys.Nonce] = nonce;
        }


        /// <summary>Gets the Relying Party's <c>client_id</c> (the expected ID Token <c>aud</c>), when set explicitly.</summary>
        public string? SiopClientId =>
            context.TryGetValue(SiopVerifierContextKeys.ClientId, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the Relying Party's <c>client_id</c>. Omit to fall back to the resolved registration's client id.</summary>
        public void SetSiopClientId(string clientId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
            context[SiopVerifierContextKeys.ClientId] = clientId;
        }


        /// <summary>Gets the accepted ID Token signing algorithms (alg allow-list).</summary>
        public IReadOnlyList<string>? SiopAllowedAlgorithms =>
            context.TryGetValue(SiopVerifierContextKeys.AllowedAlgorithms, out object? v)
                && v is IReadOnlyList<string> a ? a : null;

        /// <summary>Sets the accepted ID Token signing algorithms. Called by the application before dispatching the preparation request.</summary>
        public void SetSiopAllowedAlgorithms(IReadOnlyList<string> allowedAlgorithms)
        {
            ArgumentNullException.ThrowIfNull(allowedAlgorithms);
            context[SiopVerifierContextKeys.AllowedAlgorithms] = allowedAlgorithms;
        }


        /// <summary>Gets the requested <c>id_token_type</c> (§7), when constrained.</summary>
        public string? SiopIdTokenType =>
            context.TryGetValue(SiopVerifierContextKeys.IdTokenType, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the requested <c>id_token_type</c>. Omit when unconstrained.</summary>
        public void SetSiopIdTokenType(string idTokenType)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(idTokenType);
            context[SiopVerifierContextKeys.IdTokenType] = idTokenType;
        }


        /// <summary>
        /// Gets the decryption key id whose public half the Relying Party advertises as its encryption
        /// key, when the RP accepts encrypted Self-Issued ID Token responses.
        /// </summary>
        public string? SiopEncryptionKeyId =>
            context.TryGetValue(SiopVerifierContextKeys.EncryptionKeyId, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the decryption key id advertised as the RP's encryption key. Omit when the RP does not accept encrypted responses.</summary>
        public void SetSiopEncryptionKeyId(string encryptionKeyId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(encryptionKeyId);
            context[SiopVerifierContextKeys.EncryptionKeyId] = encryptionKeyId;
        }


        /// <summary>Gets the content encryption algorithms the Relying Party advertises for an encrypted response.</summary>
        public IReadOnlyList<string>? SiopAllowedEncAlgorithms =>
            context.TryGetValue(SiopVerifierContextKeys.AllowedEncAlgorithms, out object? v)
                && v is IReadOnlyList<string> a ? a : null;

        /// <summary>Sets the content encryption algorithms the RP advertises for an encrypted response. Pair with <see cref="SetSiopEncryptionKeyId"/>.</summary>
        public void SetSiopAllowedEncAlgorithms(IReadOnlyList<string> allowedEncAlgorithms)
        {
            ArgumentNullException.ThrowIfNull(allowedEncAlgorithms);
            context[SiopVerifierContextKeys.AllowedEncAlgorithms] = allowedEncAlgorithms;
        }


        /// <summary>
        /// Gets whether the §9.1 Request Object <c>aud</c> is the static-discovery value
        /// (<c>https://self-issued.me/v2</c>) rather than the dynamically discovered issuer. Defaults
        /// to <see langword="false"/> (dynamic discovery) when unset.
        /// </summary>
        public bool SiopUseStaticDiscoveryAudience =>
            context.TryGetValue(SiopVerifierContextKeys.UseStaticDiscoveryAudience, out object? v)
                && v is bool b && b;

        /// <summary>Sets whether the §9.1 Request Object <c>aud</c> uses the static-discovery value. Called by the application before dispatching the preparation request.</summary>
        public void SetSiopUseStaticDiscoveryAudience(bool useStaticDiscoveryAudience)
        {
            context[SiopVerifierContextKeys.UseStaticDiscoveryAudience] = useStaticDiscoveryAudience;
        }


        /// <summary>
        /// Gets the additional JOSE header claims to merge into the signed §9 Request Object header
        /// at sign time. Used to inject the client-id-prefix material the wallet resolves the RP
        /// signing key from — the federation <c>trust_chain</c>, the <c>x5c</c> certificate chain,
        /// the verifier-attestation <c>jwt</c>, or the <c>kid</c> verification-method DID URL. The
        /// SIOP parallel of
        /// <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpServerExchangeContextExtensions"/>'s
        /// <c>JarAdditionalHeaderClaims</c>. <see langword="null"/> on the bespoke direct-key path.
        /// </summary>
        public JwtHeader? SiopRequestObjectAdditionalHeaderClaims =>
            context.TryGetValue(SiopVerifierContextKeys.RequestObjectAdditionalHeaderClaims, out object? v)
                && v is JwtHeader h ? h : null;

        /// <summary>
        /// Sets the additional JOSE header claims to merge into the signed §9 Request Object. Called
        /// by the application before dispatching the preparation request when the client_id prefix
        /// requires header-side material (e.g. <c>x5c</c>, <c>trust_chain</c>, <c>jwt</c>, <c>kid</c>).
        /// </summary>
        /// <param name="additionalHeaderClaims">The header-claim entries to merge.</param>
        public void SetSiopRequestObjectAdditionalHeaderClaims(JwtHeader additionalHeaderClaims)
        {
            ArgumentNullException.ThrowIfNull(additionalHeaderClaims);
            context[SiopVerifierContextKeys.RequestObjectAdditionalHeaderClaims] = additionalHeaderClaims;
        }


        //Output accessor — set by the preparation endpoint, read by the application after dispatch.

        /// <summary>
        /// Gets the opaque per-flow request handle the preparation endpoint minted. The application
        /// echoes it as the <c>state</c> the Wallet returns on the response POST.
        /// </summary>
        public string? SiopRequestHandle =>
            context.TryGetValue(SiopVerifierContextKeys.RequestHandle, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the per-flow request handle. Called by the preparation endpoint's <see cref="BuildInputDelegate"/>.</summary>
        public void SetSiopRequestHandle(string requestHandle)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(requestHandle);
            context[SiopVerifierContextKeys.RequestHandle] = requestHandle;
        }


        /// <summary>
        /// Gets the signed §9 Request Object compact JWS produced by the request-object endpoint. The
        /// application reads this after dispatch to write into the HTTP response body with media type
        /// <c>application/oauth-authz-req+jwt</c>. <see langword="null"/> when the Request Object has
        /// not been produced. The SIOP parallel of
        /// <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpServerExchangeContextExtensions"/>'s <c>Jar</c>.
        /// </summary>
        public string? SiopRequestObject =>
            context.TryGetValue(SiopVerifierContextKeys.RequestObject, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the signed §9 Request Object compact JWS. Called by the <see cref="OAuthActionExecutor"/> after signing.</summary>
        public void SetSiopRequestObject(string requestObject)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(requestObject);
            context[SiopVerifierContextKeys.RequestObject] = requestObject;
        }


        /// <summary>
        /// Gets the absolute §9 <c>request_uri</c> the preparation endpoint composed for the
        /// by-reference flow, or <see langword="null"/> when the deployment did not configure
        /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>. The application reads
        /// it after dispatch to carry in a QR code or deep link.
        /// </summary>
        public Uri? SiopGeneratedRequestUri =>
            context.TryGetValue(SiopVerifierContextKeys.GeneratedRequestUri, out object? v)
                && v is Uri u ? u : null;

        /// <summary>Sets the composed §9 <c>request_uri</c>. Called by the preparation endpoint after it resolves the URL.</summary>
        public void SetSiopGeneratedRequestUri(Uri requestUri)
        {
            ArgumentNullException.ThrowIfNull(requestUri);
            context[SiopVerifierContextKeys.GeneratedRequestUri] = requestUri;
        }
    }
}
