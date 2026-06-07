using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;

using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Typed accessor extensions for OID4VP verifier-specific entries in a
/// <see cref="ExchangeContext"/>.
/// </summary>
/// <remarks>
/// <para>
/// Input entries are set by the application before dispatching. Library-internal
/// entries are placed on the context by library code before invoking application
/// delegates that need per-flow inputs. Output entries are set by the endpoint
/// delegates and read by the application after dispatch. The underlying keys
/// are defined in <see cref="Oid4VpContextKeys"/> and remain stable across versions.
/// </para>
/// <para>
/// These accessors correspond to the context bag values described in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>
/// and
/// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 13 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class Oid4VpServerExchangeContextExtensions
{
    extension(ExchangeContext context)
    {
        //Input accessors — set by the application before dispatching.

        /// <summary>
        /// Gets the prepared DCQL query describing the credentials the Verifier
        /// requires.
        /// </summary>
        /// <returns>
        /// The prepared query, or <see langword="null"/> when not set.
        /// </returns>
        public PreparedDcqlQuery? PreparedQuery =>
            context.TryGetValue(Oid4VpContextKeys.PreparedQuery, out object? v)
                && v is PreparedDcqlQuery q ? q : null;

        /// <summary>
        /// Sets the prepared DCQL query. Called by the application before
        /// dispatching the PAR request.
        /// </summary>
        /// <param name="query">The prepared DCQL query.</param>
        public void SetPreparedQuery(PreparedDcqlQuery query)
        {
            ArgumentNullException.ThrowIfNull(query);
            context[Oid4VpContextKeys.PreparedQuery] = query;
        }


        /// <summary>
        /// Gets the transaction nonce bound into the JAR and echoed in the VP token.
        /// </summary>
        /// <returns>
        /// The transaction nonce, or <see langword="null"/> when not set.
        /// </returns>
        public TransactionNonce? TransactionNonce =>
            context.TryGetValue(Oid4VpContextKeys.TransactionNonce, out object? v)
                && v is TransactionNonce n ? n : null;

        /// <summary>
        /// Sets the transaction nonce. Called by the application before dispatching
        /// the PAR request.
        /// </summary>
        /// <param name="nonce">The transaction nonce.</param>
        public void SetTransactionNonce(TransactionNonce nonce)
        {
            ArgumentNullException.ThrowIfNull(nonce);
            context[Oid4VpContextKeys.TransactionNonce] = nonce;
        }


        /// <summary>
        /// Gets the <c>transaction_data</c> descriptors the Verifier intends to bind
        /// into the JAR per OID4VP 1.0 §8.4.
        /// </summary>
        /// <returns>
        /// The base64url-encoded JSON descriptor strings, or <see langword="null"/>
        /// when not set.
        /// </returns>
        public IReadOnlyList<string>? TransactionData =>
            context.TryGetValue(Oid4VpContextKeys.TransactionData, out object? v)
                && v is IReadOnlyList<string> td ? td : null;

        /// <summary>
        /// Sets the <c>transaction_data</c> descriptors. Called by the application
        /// before dispatching the PAR request when transaction-data binding is
        /// required.
        /// </summary>
        /// <param name="transactionData">
        /// The base64url-encoded JSON descriptor strings.
        /// </param>
        public void SetTransactionData(IReadOnlyList<string> transactionData)
        {
            ArgumentNullException.ThrowIfNull(transactionData);
            context[Oid4VpContextKeys.TransactionData] = transactionData;
        }


        /// <summary>
        /// Gets the <c>response_mode</c> the application has selected for the JAR.
        /// Returns <see langword="null"/> when not set; callers default to
        /// <see cref="WellKnownResponseModes.DirectPostJwt"/> (HAIP 1.0 §5.1
        /// encrypted).
        /// </summary>
        public string? Oid4VpResponseMode =>
            context.TryGetValue(Oid4VpContextKeys.Oid4VpResponseMode, out object? v)
                && v is string m ? m : null;


        /// <summary>
        /// Sets the <c>response_mode</c> for the JAR. Called by the application
        /// before dispatching the PAR request when a non-default mode is
        /// required (e.g.
        /// <see cref="WellKnownResponseModes.DirectPost"/> for OID4VP §8.2
        /// plaintext).
        /// </summary>
        public void SetOid4VpResponseMode(string responseMode)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(responseMode);
            context[Oid4VpContextKeys.Oid4VpResponseMode] = responseMode;
        }




        /// <summary>
        /// Gets the additional JOSE header claims to merge into the JAR's signed
        /// header at JAR-sign time. Used to inject prefix-specific material such
        /// as the federation <c>trust_chain</c>, the <c>x5c</c> certificate
        /// chain, or the verifier-attestation <c>jwt</c>.
        /// </summary>
        public JwtHeader? JarAdditionalHeaderClaims =>
            context.TryGetValue(Oid4VpContextKeys.JarAdditionalHeaderClaims, out object? v)
                && v is JwtHeader h ? h : null;

        /// <summary>
        /// Sets the additional JOSE header claims to merge into the JAR. Called
        /// by the application before dispatching the PAR request when the
        /// client_id prefix requires header-side material.
        /// </summary>
        /// <param name="additionalHeaderClaims">
        /// The header-claim entries (e.g. <c>trust_chain</c>, <c>x5c</c>,
        /// <c>jwt</c>) to merge.
        /// </param>
        public void SetJarAdditionalHeaderClaims(JwtHeader additionalHeaderClaims)
        {
            ArgumentNullException.ThrowIfNull(additionalHeaderClaims);
            context[Oid4VpContextKeys.JarAdditionalHeaderClaims] = additionalHeaderClaims;
        }


        /// <summary>
        /// Gets the identifier of the decryption key the Verifier will use to
        /// decrypt the Wallet's Authorization Response JWE.
        /// </summary>
        /// <returns>
        /// The decryption key identifier, or <see langword="null"/> when not set.
        /// </returns>
        public KeyId? DecryptionKeyId
        {
            get
            {
                if(context.TryGetValue(Oid4VpContextKeys.DecryptionKeyId, out object? v)
                    && v is KeyId k)
                {
                    return k;
                }

                return null;
            }
        }

        /// <summary>
        /// Sets the decryption key identifier. Called by the application before
        /// dispatching the PAR request.
        /// </summary>
        /// <param name="keyId">The decryption key identifier.</param>
        public void SetDecryptionKeyId(KeyId keyId)
        {
            context[Oid4VpContextKeys.DecryptionKeyId] = keyId;
        }


        /// <summary>
        /// Gets the <c>redirect_uri</c> for same-device flows. When present, the
        /// Verifier includes it in the HTTP 200 response body so the Wallet can
        /// resume the user's browser session per
        /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §8.2</see>.
        /// </summary>
        /// <returns>
        /// The redirect URI, or <see langword="null"/> for cross-device flows.
        /// </returns>
        public Uri? Oid4VpRedirectUri =>
            context.TryGetValue(Oid4VpContextKeys.RedirectUri, out object? v)
                && v is Uri u ? u : null;

        /// <summary>
        /// Sets the <c>redirect_uri</c> for same-device flows. Called by the
        /// application before dispatching the direct_post request. Omit for
        /// cross-device flows.
        /// </summary>
        /// <param name="redirectUri">The redirect URI for browser session resumption.</param>
        public void SetOid4VpRedirectUri(Uri redirectUri)
        {
            ArgumentNullException.ThrowIfNull(redirectUri);
            context[Oid4VpContextKeys.RedirectUri] = redirectUri;
        }


        //Library-internal accessors — placed on the context by library code
        //before invoking application delegates that need per-flow inputs.

        /// <summary>
        /// Gets the per-flow opaque token the application's
        /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
        /// delegate uses when composing the <c>request_uri</c> URL.
        /// </summary>
        /// <returns>
        /// The opaque token, or <see langword="null"/> when the library has not
        /// yet placed it on the context.
        /// </returns>
        /// <remarks>
        /// The library's PAR endpoint generates a fresh random token and places
        /// it here immediately before invoking
        /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
        /// with key <see cref="Oid4VpEndpointKeys.RequestUri"/>. The token is
        /// unrelated to the internal flow identifier — it crosses the wire as
        /// part of the URL the Wallet dereferences and as the JAR's <c>state</c>
        /// claim that the Wallet echoes in the direct_post per
        /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §6.1</see>
        /// and <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>.
        /// </remarks>
        public string? ParHandle =>
            context.TryGetValue(Oid4VpContextKeys.ParHandle, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the per-flow opaque token. Called by the library's PAR endpoint
        /// before invoking <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>.
        /// </summary>
        /// <param name="token">The opaque token.</param>
        public void SetParHandle(string token)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(token);
            context[Oid4VpContextKeys.ParHandle] = token;
        }


        //Output accessors — set by endpoint delegates, read by the application
        //after dispatch.

        /// <summary>
        /// Gets the full <c>request_uri</c> generated by the PAR endpoint. The
        /// application reads this after PAR dispatch to encode into the QR code
        /// or deep link.
        /// </summary>
        /// <returns>
        /// The generated request URI, or <see langword="null"/> when PAR has
        /// not yet been dispatched.
        /// </returns>
        public Uri? GeneratedRequestUri =>
            context.TryGetValue(Oid4VpContextKeys.GeneratedRequestUri, out object? v)
                && v is Uri u ? u : null;

        /// <summary>
        /// Sets the generated <c>request_uri</c>. Called by the PAR endpoint's
        /// <see cref="BuildInputDelegate"/>.
        /// </summary>
        /// <param name="requestUri">The generated request URI.</param>
        public void SetGeneratedRequestUri(Uri requestUri)
        {
            ArgumentNullException.ThrowIfNull(requestUri);
            context[Oid4VpContextKeys.GeneratedRequestUri] = requestUri;
        }


        /// <summary>
        /// Gets the signed JAR JWT produced by the JAR request endpoint. The
        /// application reads this after JAR dispatch to write into the HTTP
        /// response body with media type <c>application/oauth-authz-req+jwt</c>.
        /// </summary>
        /// <returns>
        /// The JAR JWT string, or <see langword="null"/> when the JAR has not
        /// yet been produced.
        /// </returns>
        public string? Jar =>
            context.TryGetValue(Oid4VpContextKeys.CompactJar, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the signed JAR JWT. Called by the <see cref="OAuthActionExecutor"/>
        /// after signing the JAR.
        /// </summary>
        /// <param name="jar">The signed JAR JWT string per RFC 9101.</param>
        public void SetJar(string jar)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(jar);
            context[Oid4VpContextKeys.CompactJar] = jar;
        }
    }
}
