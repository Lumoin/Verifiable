using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Typed accessor extensions for OID4VP verifier-specific entries in a
/// <see cref="RequestContext"/>.
/// </summary>
/// <remarks>
/// <para>
/// Input entries are set by the application before dispatching. Output entries
/// are set by the endpoint delegates and read by the application after dispatch.
/// The underlying keys are defined in <see cref="Oid4VpContextKeys"/> and remain
/// stable across versions.
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
public static class Oid4VpRequestContextExtensions
{
    extension(RequestContext context)
    {
        //Input accessors — set by the application before dispatching.

        /// <summary>
        /// Gets the base URI used to construct the <c>request_uri</c>. The PAR
        /// endpoint appends the segment and flow identifier to produce the full URI.
        /// </summary>
        /// <returns>
        /// The base URI, or <see langword="null"/> when not set.
        /// </returns>
        public Uri? RequestUriBase =>
            context.TryGetValue(Oid4VpContextKeys.RequestUriBase, out object? v)
                && v is Uri u ? u : null;

        /// <summary>
        /// Sets the base URI for <c>request_uri</c> construction. Called by the
        /// application before dispatching the PAR request.
        /// </summary>
        /// <param name="baseUri">The server base URI.</param>
        public void SetRequestUriBase(Uri baseUri)
        {
            ArgumentNullException.ThrowIfNull(baseUri);
            context[Oid4VpContextKeys.RequestUriBase] = baseUri;
        }


        /// <summary>
        /// Gets the prepared DCQL query describing the credentials the Verifier requires.
        /// </summary>
        /// <returns>
        /// The prepared query, or <see langword="null"/> when not set.
        /// </returns>
        public PreparedDcqlQuery? PreparedQuery =>
            context.TryGetValue(Oid4VpContextKeys.PreparedQuery, out object? v)
                && v is PreparedDcqlQuery q ? q : null;

        /// <summary>
        /// Sets the prepared DCQL query. Called by the application before dispatching
        /// the PAR request.
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
        /// Gets the identifier of the decryption key the Verifier will use to decrypt
        /// the Wallet's Authorization Response JWE.
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
        /// resume the user's browser session.
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


        //Output accessors — set by endpoint delegates, read by the application after dispatch.

        /// <summary>
        /// Gets the flow identifier generated by the PAR endpoint. The application
        /// reads this after PAR dispatch to construct the QR code or deep link.
        /// </summary>
        /// <returns>
        /// The generated flow identifier, or <see langword="null"/> when PAR has
        /// not yet been dispatched.
        /// </returns>
        public string? GeneratedFlowId =>
            context.TryGetValue(Oid4VpContextKeys.GeneratedFlowId, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>
        /// Sets the generated flow identifier. Called by the PAR endpoint's
        /// <see cref="BuildInputDelegate"/>.
        /// </summary>
        /// <param name="flowId">The generated flow identifier.</param>
        public void SetGeneratedFlowId(string flowId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(flowId);
            context[Oid4VpContextKeys.GeneratedFlowId] = flowId;
        }


        /// <summary>
        /// Gets the full <c>request_uri</c> generated by the PAR endpoint. The
        /// application reads this after PAR dispatch to encode into the QR code
        /// or deep link.
        /// </summary>
        /// <returns>
        /// The generated request URI, or <see langword="null"/> when PAR has not
        /// yet been dispatched.
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
