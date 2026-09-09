using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.StatusList;

/// <summary>
/// Resolves the public key that verifies a Status List Token's signature, keyed on the URI the token
/// was fetched from, its (not yet signature-verified) protected header, and the Referenced Token's own
/// verified issuer facts — the application's trust decision.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="StatusListKeyResolutionContext.Header"/> is offered <strong>before</strong> the signature
/// is checked, because <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519 §7.2</see>
/// reads the JOSE header (steps 1 through 5) to learn which key the signature is to be verified with
/// (step 8) — the header is the token's own self-description and every value in it is
/// attacker-controlled until the returned key verifies the signature. It therefore rides the
/// <see cref="UnverifiedJwtHeader"/> type rather than a verified carrier, and nothing read from it is
/// to be trusted beyond selecting which key to try.
/// </para>
/// </remarks>
/// <param name="context">
/// The list URI, the unverified protected header, and the Referenced Token's verified issuer identity
/// and key. See <see cref="StatusListKeyResolutionContext"/>.
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The issuer's public key together with whether the verification releases it (see
/// <see cref="ResolvedStatusListIssuerKey"/>), or <see langword="null"/> when
/// <paramref name="context"/> identifies no key the application trusts — an unverifiable token, not a
/// fault.
/// </returns>
public delegate ValueTask<ResolvedStatusListIssuerKey?> ResolveStatusListIssuerKeyDelegate(
    StatusListKeyResolutionContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Why <see cref="StatusListTokenVerification.VerifyAsync"/> did not produce a verified
/// <see cref="StatusListToken"/>.
/// </summary>
public enum StatusListTokenVerificationFailure
{
    /// <summary>Verification succeeded; see <see cref="StatusListTokenVerificationResult.Token"/>.</summary>
    None = 0,

    /// <summary>
    /// The input is not three non-empty, dot-separated segments (RFC 7519 §7.2 steps 1-4). Whether
    /// each segment is valid base64url is checked separately, surfacing as <see cref="HeaderUnreadable"/>
    /// for the header segment.
    /// </summary>
    MalformedCompactSerialization,

    /// <summary>
    /// The compact serialization is longer than the accepted maximum (RFC 8725 §3.11), refused before
    /// any base64url decode of it is attempted.
    /// </summary>
    InputTooLong,

    /// <summary>The protected header segment could not be base64url- or JSON-decoded.</summary>
    HeaderUnreadable,

    /// <summary>
    /// The header's <c>alg</c> is absent, is the forbidden <c>none</c> algorithm, is not a JWA this
    /// build understands, or does not equal the JWA derived from the resolved issuer key's own
    /// algorithm (algorithm confusion).
    /// </summary>
    AlgorithmUnsupported,

    /// <summary>The header's <c>typ</c> is absent or is not <c>statuslist+jwt</c>.</summary>
    TypeMismatch,

    /// <summary><see cref="ResolveStatusListIssuerKeyDelegate"/> resolved no key.</summary>
    IssuerKeyUnresolved,

    /// <summary>The JWS signature does not verify under the resolved key.</summary>
    SignatureInvalid,

    /// <summary>The verified payload segment could not be JSON-decoded.</summary>
    ClaimsUnreadable,

    /// <summary>A REQUIRED Section 5.1 claim (<c>sub</c>/<c>iat</c>/<c>status_list</c>/its <c>bits</c>/<c>lst</c>) is absent.</summary>
    RequiredClaimMissing,

    /// <summary>A present claim's value does not conform (e.g. a non-positive <c>ttl</c>).</summary>
    ClaimValueInvalid,

    /// <summary>The verified <c>sub</c> claim does not equal the URI the token was fetched for.</summary>
    SubjectMismatch
}


/// <summary>
/// The outcome of <see cref="StatusListTokenVerification.VerifyAsync"/>.
/// </summary>
public sealed record StatusListTokenVerificationResult
{
    /// <summary>Whether every check passed and <see cref="Token"/> is populated.</summary>
    public required bool IsVerified { get; init; }

    /// <summary>
    /// The verified Status List Token, or <see langword="null"/> when <see cref="IsVerified"/> is
    /// <see langword="false"/>. The token's pooled <see cref="StatusListToken.StatusList"/> is the
    /// caller's to dispose.
    /// </summary>
    public StatusListToken? Token { get; init; }

    /// <summary>Which check failed, or <see cref="StatusListTokenVerificationFailure.None"/> on success.</summary>
    public required StatusListTokenVerificationFailure Failure { get; init; }

    /// <summary>A human-readable description of the failure, or <see langword="null"/> on success.</summary>
    public string? Defect { get; init; }
}


/// <summary>
/// Establishes "a valid Status List Token in JWT format" per Section 8.3 step 3 — the compact shape,
/// the header, the signature, and the Section 5.1 claims rules — for a Status List Token fetched at
/// the resolution context's <see cref="StatusListReference.Uri"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Layering.</strong> This is the cryptographic-and-claims layer, mirroring
/// <c>JarVerification</c>/<c>BearerTokenValidation</c>'s resolve-then-verify idiom over the JCose
/// primitives: <see cref="Verifiable.JCose.JwsParsing.ParseCompact"/> decodes the header before any
/// key is resolved (rule ordering below), <see cref="Verifiable.JCose.Jws.VerifyAsync(string,DecodeDelegate,BaseMemoryPool,PublicKeyMemory,System.Threading.CancellationToken)"/>
/// checks the signature, and <see cref="StatusListTokenClaims.TryFromPayload"/> reads the claims only
/// once the signature holds. Section 8.3 steps 4 through 7 — the credential's own subject/freshness/
/// expiry/index-bounds evaluation against a <em>reference</em> — are NOT this method's job: they stay
/// <see cref="StatusListValidation.GetStatus"/>'s, run by the format-independent
/// <see cref="Core.StatusList.CredentialStatusGate"/> after a resolver composes this verification.
/// </para>
/// <para>
/// <strong>Ordering (RFC 7519 §7.2 steps 1-4/5; Section 8.3 steps 3.a/3.b; Section 5.1 rule 2; RFC
/// 8725 §3.11).</strong> (0) the input length, against <see cref="Jws.DefaultMaxJwsLength"/>; (1) the
/// compact shape — three non-empty, base64url, dot-separated segments; (2) the protected header —
/// <c>alg</c> present, not <c>none</c>, and a JWA this build understands, <c>typ</c> present and equal
/// to <c>statuslist+jwt</c> ("The JWT type MUST be statuslist+jwt."); (3) the issuer key, resolved
/// through <see cref="ResolveStatusListIssuerKeyDelegate"/> from the list URI, the still-unverified
/// header, and the Referenced Token's own issuer facts; (3b) algorithm confusion — <c>alg</c> equal to
/// the JWA the resolved key's own algorithm implies; (4) the signature ("Relying Parties MUST reject
/// JWTs with an invalid signature."), checked before any payload claim is read; (5) the payload claims
/// via <see cref="StatusListTokenClaims.TryFromPayload"/>; (6) <c>sub</c> equal to the list URI
/// ordinally ("The value MUST be equal to that of the uri claim contained in the status_list claim of
/// the Referenced Token.").
/// </para>
/// <para>
/// <strong>Key ownership.</strong> A resolver that mints its key per call answers an
/// <see cref="ResolvedStatusListIssuerKey.Owned(PublicKeyMemory)"/> key; the resolution is therefore
/// held in a <c>using</c> declaration from the moment it is obtained, so an owned key is released on
/// every exit past that point — a verified token, an algorithm mismatch, an invalid signature, an
/// unreadable or non-conforming claims set, and a subject mismatch alike. A
/// <see cref="ResolvedStatusListIssuerKey.Borrowed(PublicKeyMemory)"/> key is left untouched.
/// </para>
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>,
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section 8.3</see>, and
/// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-7.2">RFC 7519 §7.2</see>.
/// </remarks>
public static class StatusListTokenVerification
{
    /// <summary>
    /// Verifies a compact Status List Token JWT and reads its claims.
    /// </summary>
    /// <param name="compactJws">The compact-serialized Status List Token, exactly as fetched.</param>
    /// <param name="context">
    /// The Referenced Token's status reference and verified issuer facts. Its
    /// <see cref="StatusListReference.Uri"/> is the <c>uri</c> the token was fetched for — the value
    /// passed to <paramref name="resolveIssuerKey"/> and checked against the verified <c>sub</c> claim
    /// — and its issuer members are threaded onto the key resolution's own context.
    /// </param>
    /// <param name="resolveIssuerKey">Resolves the Status Issuer's public key. See its own remarks.</param>
    /// <param name="base64UrlDecoder">Decodes base64url segments to pooled bytes.</param>
    /// <param name="partDecoder">Decodes a decoded JWT part's UTF-8 JSON bytes into its claim set.</param>
    /// <param name="memoryPool">Memory pool for decoding allocations.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verification outcome; see <see cref="StatusListTokenVerificationResult"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="compactJws"/> is empty or whitespace.</exception>
    /// <exception cref="ArgumentNullException">Thrown when any other required argument is <see langword="null"/>.</exception>
    public static async ValueTask<StatusListTokenVerificationResult> VerifyAsync(
        string compactJws,
        StatusListResolutionContext context,
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey,
        DecodeDelegate base64UrlDecoder,
        JwtPartDecoder partDecoder,
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactJws);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(partDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        string expectedSubject = context.Reference.Uri;

        //RFC 8725 §3.11: an attacker-sized input is refused on its length before any base64url decode
        //of it is attempted, rather than reaching Jws.VerifyAsync's own cap after the header has
        //already been decoded — so a hostile or non-conforming transport that ignores
        //StatusListTokenFetch's MaxResponseBytes hint is turned away as cheaply as possible.
        if(compactJws.Length > Jws.DefaultMaxJwsLength)
        {
            return Failed(
                StatusListTokenVerificationFailure.InputTooLong,
                $"The Status List Token is {compactJws.Length} characters, over the accepted maximum of {Jws.DefaultMaxJwsLength}.");
        }

        //RFC 7519 §7.2 steps 1-4: three non-empty, dot-separated segments. Checked directly, ahead of
        //JwsParsing.ParseCompact, so a structural defect is distinguishable from a header-decode defect.
        string[] segments = compactJws.Split('.');
        if(segments.Length != 3 || Array.Exists(segments, string.IsNullOrEmpty))
        {
            return Failed(
                StatusListTokenVerificationFailure.MalformedCompactSerialization,
                "The Status List Token is not a well-formed compact JWS (three non-empty, dot-separated segments).");
        }

        UnverifiedJwsMessage unverified;
        try
        {
            unverified = JwsParsing.ParseCompact(
                compactJws, base64UrlDecoder, bytes => partDecoder(bytes), memoryPool);
        }
        catch(FormatException ex)
        {
            return Failed(
                StatusListTokenVerificationFailure.HeaderUnreadable,
                $"The Status List Token's protected header could not be decoded: {ex.Message}");
        }

        using(unverified)
        {
            //The header is read before any key is resolved — RFC 7519's alg/typ are the token's own
            //self-description and remain attacker-controlled until the signature this section resolves
            //toward is checked; nothing here is treated as trustworthy yet.
            UnverifiedJwtHeader unverifiedHeader = unverified.Signatures[0].ProtectedHeader;

            if(!unverifiedHeader.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algObject)
                || algObject is not string alg
                || string.IsNullOrEmpty(alg)
                || string.Equals(alg, WellKnownJwaValues.None, StringComparison.OrdinalIgnoreCase))
            {
                return Failed(
                    StatusListTokenVerificationFailure.AlgorithmUnsupported,
                    "The Status List Token header is missing 'alg' or carries the forbidden 'none' algorithm.");
            }

            //RFC 7519 §7.2 step 5: "Verify that the resulting JOSE Header includes only parameters and
            //values whose syntax and semantics are both understood". An 'alg' this build does not
            //recognize at all is refused here, before a key is resolved for it — distinct from the
            //algorithm-confusion check below, which runs once a key IS resolved and compares the wire
            //'alg' against that key's own algorithm.
            if(!IsRecognizedJwa(alg))
            {
                return Failed(
                    StatusListTokenVerificationFailure.AlgorithmUnsupported,
                    $"The Status List Token header 'alg' ('{alg}') is not a JWA this build understands.");
            }

            if(!unverifiedHeader.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typObject)
                || typObject is not string typ
                || !WellKnownMediaTypes.Jwt.IsStatusListJwt(typ))
            {
                return Failed(
                    StatusListTokenVerificationFailure.TypeMismatch,
                    $"The Status List Token header 'typ' must be '{WellKnownMediaTypes.Jwt.StatusListJwt}'.");
            }

            StatusListKeyResolutionContext keyContext = new()
            {
                StatusListUri = expectedSubject,
                Header = unverifiedHeader,
                ReferencedTokenIssuer = context.ReferencedTokenIssuer,
                ReferencedTokenIssuerKey = context.ReferencedTokenIssuerKey
            };

            //An owned key is the verification's to release, so the resolution is scoped from here on:
            //every exit below — verified, algorithm mismatch, invalid signature, unreadable or
            //non-conforming claims, subject mismatch — passes through this scope's disposal, while a
            //borrowed key's disposal is a no-op that leaves the resolver's own carrier alone.
            using ResolvedStatusListIssuerKey? resolvedIssuerKey = await resolveIssuerKey(
                keyContext, cancellationToken).ConfigureAwait(false);
            if(resolvedIssuerKey is null)
            {
                return Failed(
                    StatusListTokenVerificationFailure.IssuerKeyUnresolved,
                    $"No issuer key could be resolved for Status List Token '{expectedSubject}'.");
            }

            PublicKeyMemory issuerKey = resolvedIssuerKey.Key;

            //Algorithm confusion (RFC 7519 §7.2 step 5's own "semantics are … understood" read together
            //with Section 5.1's own signing rule): the wire 'alg' MUST equal the JWA that the RESOLVED
            //key's own algorithm implies, checked before the signature so a key that happens to verify
            //bytes under a different algorithm family (an HMAC secret over an EC key's raw bytes, say)
            //never reaches Jws.VerifyAsync at all.
            string expectedAlg;
            try
            {
                expectedAlg = CryptoFormatConversions.DefaultTagToJwaConverter(issuerKey.Tag);
            }
            catch(NotSupportedException)
            {
                return Failed(
                    StatusListTokenVerificationFailure.AlgorithmUnsupported,
                    $"The resolved issuer key's algorithm has no JWA mapping to compare against header 'alg' ('{alg}').");
            }

            if(!string.Equals(alg, expectedAlg, StringComparison.Ordinal))
            {
                return Failed(
                    StatusListTokenVerificationFailure.AlgorithmUnsupported,
                    $"The Status List Token header 'alg' ('{alg}') does not match the resolved issuer key's algorithm ('{expectedAlg}').");
            }

            //Rule 2: "Relying Parties MUST reject JWTs with an invalid signature." Checked before any
            //payload claim below is read. ArgumentException is caught alongside: Jws.VerifyAsync applies
            //RFC 8725 §3.11's length cap ahead of parsing, and a hostile or non-conforming transport that
            //ignores StatusListTokenFetch's MaxResponseBytes hint must still fail closed here, not fault.
            bool signatureValid;
            try
            {
                signatureValid = await Jws.VerifyAsync(
                    compactJws, base64UrlDecoder, memoryPool, issuerKey, cancellationToken).ConfigureAwait(false);
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException or ArgumentException)
            {
                return Failed(
                    StatusListTokenVerificationFailure.SignatureInvalid,
                    $"Status List Token signature verification raised: {ex.Message}");
            }

            if(!signatureValid)
            {
                return Failed(
                    StatusListTokenVerificationFailure.SignatureInvalid,
                    "Status List Token signature verification failed.");
            }

            JwtPayload payload;
            try
            {
                payload = new JwtPayload(partDecoder(unverified.Payload.Span));
            }
            catch(FormatException ex)
            {
                return Failed(
                    StatusListTokenVerificationFailure.ClaimsUnreadable,
                    $"The Status List Token payload could not be decoded: {ex.Message}");
            }

            bool isRead;
            StatusListToken? token;
            string? defect;
            StatusListTokenClaimsDefect defectKind;
            try
            {
                isRead = StatusListTokenClaims.TryFromPayload(
                    payload, base64UrlDecoder, memoryPool, out token, out defect, out defectKind);
            }
            catch(Exception ex) when(ex is FormatException or ArgumentException or System.IO.InvalidDataException)
            {
                //StatusListTokenClaims.TryFromPayload reports every malformation of the lst member as a
                //refusal itself; this guard is defence in depth against the payload path escaping as a
                //raw exception, never the primary route to a refusal.
                return Failed(
                    StatusListTokenVerificationFailure.ClaimValueInvalid,
                    $"The Status List Token claims set could not be read: {ex.Message}");
            }

            if(!isRead)
            {
                StatusListTokenVerificationFailure claimFailure = defectKind switch
                {
                    StatusListTokenClaimsDefect.RequiredClaimMissing => StatusListTokenVerificationFailure.RequiredClaimMissing,
                    StatusListTokenClaimsDefect.ClaimValueInvalid => StatusListTokenVerificationFailure.ClaimValueInvalid,
                    StatusListTokenClaimsDefect.ListUnreadable => StatusListTokenVerificationFailure.ClaimValueInvalid,
                    _ => StatusListTokenVerificationFailure.ClaimValueInvalid
                };

                return Failed(claimFailure, defect ?? "The Status List Token claims set is invalid.");
            }

            //Rule 6 (Section 5.1): "sub … MUST be equal to that of the uri claim contained in the
            //status_list claim of the Referenced Token." A refusal past this point must not hold onto
            //the pooled Status List TryFromPayload just minted — nothing below this method ever reads
            //it, so it is released on every remaining exit rather than leaked to the caller.
            if(!string.Equals(token!.Subject, expectedSubject, StringComparison.Ordinal))
            {
                token.StatusList.Dispose();

                return Failed(
                    StatusListTokenVerificationFailure.SubjectMismatch,
                    $"The Status List Token 'sub' ('{token.Subject}') does not equal the URI it was fetched for ('{expectedSubject}').");
            }

            return new StatusListTokenVerificationResult
            {
                IsVerified = true,
                Token = token,
                Failure = StatusListTokenVerificationFailure.None
            };
        }
    }


    /// <summary>
    /// Builds an unverified <see cref="StatusListTokenVerificationResult"/> naming why.
    /// </summary>
    /// <param name="failure">Which check refused the token.</param>
    /// <param name="defect">A human-readable description of the refusal.</param>
    /// <returns>The unverified result.</returns>
    private static StatusListTokenVerificationResult Failed(StatusListTokenVerificationFailure failure, string defect)
    {
        return new StatusListTokenVerificationResult
        {
            IsVerified = false,
            Failure = failure,
            Defect = defect
        };
    }


    /// <summary>
    /// Whether <paramref name="alg"/> is a JWA this build's cryptographic providers understand — the
    /// RFC 7519 §7.2 step 5 "syntax and semantics are both understood" gate, checked before an issuer
    /// key is resolved for it. Reuses the registered-algorithm predicates
    /// <see cref="WellKnownJwaValues"/> already exposes rather than a second, hand-rolled name list.
    /// </summary>
    /// <param name="alg">The header's <c>alg</c> value.</param>
    /// <returns><see langword="true"/> when <paramref name="alg"/> names a registered JWA signing or MAC algorithm.</returns>
    private static bool IsRecognizedJwa(string alg) =>
        WellKnownJwaValues.IsHs256(alg) || WellKnownJwaValues.IsHs384(alg) || WellKnownJwaValues.IsHs512(alg)
        || WellKnownJwaValues.IsEs256(alg) || WellKnownJwaValues.IsEs384(alg) || WellKnownJwaValues.IsEs512(alg)
        || WellKnownJwaValues.IsEs256K(alg)
        || WellKnownJwaValues.IsPs256(alg) || WellKnownJwaValues.IsPs384(alg) || WellKnownJwaValues.IsPs512(alg)
        || WellKnownJwaValues.IsRs256(alg) || WellKnownJwaValues.IsRs384(alg) || WellKnownJwaValues.IsRs512(alg)
        || WellKnownJwaValues.IsEdDsa(alg)
        || WellKnownJwaValues.IsMlDsa(alg)
        || WellKnownJwaValues.IsEsb(alg);
}
