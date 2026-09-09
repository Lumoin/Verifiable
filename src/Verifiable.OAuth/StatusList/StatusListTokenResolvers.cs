using System.Text;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.StatusList;

/// <summary>
/// Builds a <see cref="ResolveVerifiedStatusListTokenDelegate"/> that composes
/// <see cref="StatusListTokenFetch"/> and <see cref="StatusListTokenVerification"/> into the seam
/// <see cref="Core.StatusList.CredentialStatusGate"/> calls — the JWT-format Status List Token
/// resolver.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <c>ClientIdMetadataDocuments.BuildResolving</c>'s composition idiom: the returned
/// delegate closes over the injected transport, context, and codecs, and every caller-visible
/// failure surfaces as a typed <see cref="StatusListResolutionException"/> — never a raw fetch or
/// verification fault — so <see cref="Oid4Vp.Server.VpTokenCredentialStatus.CheckAsync"/> answers
/// <c>StatusUndeterminable</c> rather than faulting the request. <see cref="OperationCanceledException"/>
/// is the only exception besides that one that propagates.
/// </para>
/// <para>
/// The fetch always requests <see cref="StatusListTokenFormat.Jwt"/>: "When the status claim is
/// present and using the status_list mechanism, the associated Status List Token MUST be in JWT
/// format." (SD-JWT VC), so a CWT answer to a JWT-format request is a
/// <see cref="StatusListTokenFetchOutcome.ContentTypeMismatch"/> resolution failure, not a silent
/// fallback. This resolver serves the JWT-format token only; a CWT-format resolver composes
/// <c>StatusListTokenCborConverter</c> and a COSE_Sign1 verification directly.
/// </para>
/// </remarks>
/// <seealso href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-18.html#section-2.2.2.3">SD-JWT VC, status claim</seealso>
public static class StatusListTokenResolvers
{
    /// <summary>
    /// Builds a JWT-format <see cref="ResolveVerifiedStatusListTokenDelegate"/>.
    /// </summary>
    /// <param name="transport">The application-supplied single-hop transport the guarded fetch drives.</param>
    /// <param name="context">The per-call exchange context; the SSRF policy is read from it.</param>
    /// <param name="resolveIssuerKey">Resolves the Status Issuer's public key for signature verification.</param>
    /// <param name="base64UrlDecoder">Decodes base64url segments to pooled bytes.</param>
    /// <param name="partDecoder">Decodes a decoded JWT part's UTF-8 JSON bytes into its claim set.</param>
    /// <param name="memoryPool">Memory pool for fetch and decode allocations.</param>
    /// <param name="timeProvider">
    /// The clock the resolution's <see cref="ResolvedStatusListToken.ResolvedAt"/> is stamped from — the fetch
    /// instant, since this resolver always fetches fresh rather than caching.
    /// </param>
    /// <param name="maxResponseBytes">
    /// The upper bound on the fetched response body. Defaults to <see cref="Jws.DefaultMaxJwsLength"/> (1 MiB) —
    /// the same RFC 8725 §3.11 ceiling <see cref="Jws.VerifyAsync(string,DecodeDelegate,BaseMemoryPool,PublicKeyMemory,System.Threading.CancellationToken)"/>
    /// applies to the compact JWS it verifies, so a larger response could never verify anyway.
    /// </param>
    /// <returns>
    /// A resolve delegate that fetches, verifies, and returns the Status List Token fresh on every call.
    /// It reads the list URI from the resolution context's
    /// <see cref="Core.StatusList.StatusListResolutionContext.Reference"/> and threads the whole context
    /// through to <paramref name="resolveIssuerKey"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when any required argument is <see langword="null"/>.</exception>
    public static ResolveVerifiedStatusListTokenDelegate BuildResolving(
        OutboundTransportDelegate transport,
        ExchangeContext context,
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        BaseMemoryPool memoryPool,
        TimeProvider timeProvider,
        long maxResponseBytes = Jws.DefaultMaxJwsLength)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return async (resolutionContext, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(resolutionContext);

            string uri = resolutionContext.Reference.Uri;

            //Section 8.3 step 4.d needs the instant the token was resolved AT — the fetch instant for a
            //resolver that always fetches fresh, per ResolvedStatusListToken's own remarks — so the clock
            //is read here, before the fetch and verification run, rather than after they return.
            DateTimeOffset resolvedAt = timeProvider.GetUtcNow();

            if(!Uri.TryCreate(uri, UriKind.Absolute, out Uri? statusListUri))
            {
                throw new StatusListResolutionException(uri, $"'{uri}' is not an absolute URI.");
            }

            StatusListTokenFetchResult fetch = await StatusListTokenFetch.FetchAsync(
                statusListUri, StatusListTokenFormat.Jwt, context, transport, maxResponseBytes, cancellationToken)
                .ConfigureAwait(false);

            if(!fetch.IsFetched)
            {
                throw new StatusListResolutionException(
                    uri,
                    $"The Status List Token fetch for '{uri}' ended with {fetch.Outcome}" +
                    (fetch.DenyReason is not null ? $": {fetch.DenyReason}" : "."));
            }

            //OutboundRequest.MaxResponseBytes is a hint the transport MAY ignore, so the bound is
            //re-checked here on the bytes actually returned before anything is decoded from them.
            if(fetch.Body.Length > maxResponseBytes)
            {
                throw new StatusListResolutionException(
                    uri, $"The Status List Token fetch for '{uri}' returned {fetch.Body.Length} bytes, over the {maxResponseBytes}-byte bound.");
            }

            if(fetch.Body.Length == 0)
            {
                throw new StatusListResolutionException(uri, $"The Status Provider answered '{uri}' with no token.");
            }

            //RFC 7515 §7.1: the JWS Compact Serialization is three base64url segments joined by '.', so
            //every octet MUST fall within [A-Za-z0-9-_.] — checked before the ASCII decode below so a
            //transport that hands back arbitrary bytes under the right Content-Type cannot smuggle a
            //non-ASCII byte through as '?' and have it silently misread as claims-set noise.
            if(!IsJwsCompactSerializationAlphabet(fetch.Body.Span))
            {
                throw new StatusListResolutionException(
                    uri, $"The Status List Token fetch for '{uri}' did not return the JWS Compact Serialization alphabet.");
            }

            string compactJws = Encoding.ASCII.GetString(fetch.Body.Span);

            //The context travels whole into the verification, so the key resolution behind
            //resolveIssuerKey sees the Referenced Token's own issuer identity and key alongside the list
            //URI — what Section 11.3's same-key recommendation is evaluated against.
            StatusListTokenVerificationResult verification = await StatusListTokenVerification.VerifyAsync(
                compactJws, resolutionContext, resolveIssuerKey, base64UrlDecoder, partDecoder, memoryPool, cancellationToken)
                .ConfigureAwait(false);

            if(!verification.IsVerified || verification.Token is null)
            {
                throw new StatusListResolutionException(
                    uri,
                    $"The Status List Token for '{uri}' failed verification ({verification.Failure})" +
                    (verification.Defect is not null ? $": {verification.Defect}" : "."));
            }

            return new ResolvedStatusListToken
            {
                Token = verification.Token,
                ResolvedAt = resolvedAt,
                IsTokenOwned = true
            };
        };
    }


    /// <summary>
    /// Whether every byte of <paramref name="body"/> falls within the JWS Compact Serialization alphabet
    /// — base64url segments joined by <c>'.'</c> — per RFC 7515 §7.1, so an ASCII decode of it never
    /// silently substitutes <c>'?'</c> for a byte outside ASCII.
    /// </summary>
    /// <param name="body">The fetched response body.</param>
    /// <returns><see langword="true"/> when every byte is <c>A-Za-z0-9-_.</c>.</returns>
    private static bool IsJwsCompactSerializationAlphabet(ReadOnlySpan<byte> body)
    {
        foreach(byte value in body)
        {
            bool isAllowed = value is (>= (byte)'A' and <= (byte)'Z')
                or (>= (byte)'a' and <= (byte)'z')
                or (>= (byte)'0' and <= (byte)'9')
                or (byte)'-' or (byte)'_' or (byte)'.';

            if(!isAllowed)
            {
                return false;
            }
        }

        return true;
    }
}
