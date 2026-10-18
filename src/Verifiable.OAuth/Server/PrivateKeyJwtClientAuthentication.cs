using System.Buffers;
using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode.Server;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.Server.Pipeline;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Consults a <c>jti</c> replay store for a client-authentication assertion, governed by the
/// same <see cref="JtiReplayPolicy"/>/<see cref="JtiReplayGuard"/> axis the JAR and DPoP paths
/// use. Its parameter shape matches <see cref="JtiReplayGuard.ConsultClientAssertionAsync"/>
/// exactly, which records the <c>jti</c> under <see cref="JtiReplayPurpose.ClientAssertion"/>, so a
/// caller wires that method directly as this delegate.
/// </summary>
/// <param name="server">The authorization server (its integration store and clock).</param>
/// <param name="context">The exchange context carrying the resolved policy and tenant.</param>
/// <param name="tenantId">The tenant the <c>jti</c> is scoped to.</param>
/// <param name="issuer">The assertion's <c>iss</c> (the composite-key prefix).</param>
/// <param name="jti">The presented <c>jti</c> value.</param>
/// <param name="expiresAt">When the recorded entry should expire.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<JtiReplayOutcome> CheckClientAssertionJtiReplayDelegate(
    EndpointServer server,
    ExchangeContext context,
    TenantId tenantId,
    string issuer,
    string jti,
    DateTimeOffset expiresAt,
    CancellationToken cancellationToken);


/// <summary>
/// Outcome of validating a <c>private_key_jwt</c> client-authentication assertion (RFC 7523 §2.2/§3.2)
/// presented to the token endpoint. Carries the authenticated <c>client_id</c> and <c>jti</c> on
/// success, or a typed failure reason on rejection.
/// </summary>
/// <remarks>
/// Same sealed-record-with-nullable-fields shape as
/// <see cref="FederationClientAuthenticationResult"/>; the token endpoint maps a
/// rejection onto an HTTP 401 <c>invalid_client</c> response (RFC 7523 §3.2).
/// </remarks>
[DebuggerDisplay("PrivateKeyJwtClientAuthenticationResult Valid={IsValid} Reason={FailureReason,nq}")]
public sealed record PrivateKeyJwtClientAuthenticationResult
{
    /// <summary>
    /// The authenticated <c>client_id</c> (the assertion's <c>iss</c> == <c>sub</c> ==
    /// <c>client_id</c>); <see langword="null"/> on failure.
    /// </summary>
    public string? ClientId { get; init; }


    /// <summary>
    /// The assertion's <c>jti</c>, surfaced so the caller can apply replay defense;
    /// <see langword="null"/> on failure.
    /// </summary>
    public string? Jti { get; init; }


    /// <summary>The assertion's expiry as written; <see langword="null"/> on failure.</summary>
    public NumericDate? Expiration { get; init; }


    /// <summary>The reason validation failed; <see langword="null"/> on success.</summary>
    public string? FailureReason { get; init; }


    /// <summary><see langword="true"/> when the client assertion validated.</summary>
    public bool IsValid => FailureReason is null;


    /// <summary>Builds a success result.</summary>
    public static PrivateKeyJwtClientAuthenticationResult Authenticated(
        string clientId, string jti, NumericDate expiration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(jti);
        ArgumentNullException.ThrowIfNull(expiration);

        //The one identifier contract the judgement of the claims refuses by, so no claims it accepts reach this throw.
        if(!ClientAssertionClaimRules.IsIdentifier(jti))
        {
            throw new ArgumentException("A client assertion's jti names an identifier: a string holding a character other than white space.", nameof(jti));
        }

        return new PrivateKeyJwtClientAuthenticationResult
        {
            ClientId = clientId,
            Jti = jti,
            Expiration = expiration
        };
    }


    /// <summary>Builds a failure result.</summary>
    public static PrivateKeyJwtClientAuthenticationResult Rejected(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        return new PrivateKeyJwtClientAuthenticationResult { FailureReason = reason };
    }
}


/// <summary>
/// Validates the RFC 7523 §3/§3.2 <c>private_key_jwt</c> client-authentication claim rules — the
/// method draft-ietf-oauth-client-id-metadata-document-02 §8.2 (CIMD-047/048/049/050) requires an
/// authorization server to enforce when a client declares <c>token_endpoint_auth_method</c> as
/// <c>private_key_jwt</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Validate"/> is crypto-agnostic: it operates on the already signature-verified,
/// decoded <see cref="JwtPayload"/>, mirroring <see cref="FederationClientAuthentication.Validate"/>'s
/// shape. <see cref="BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
/// and its explicit-<see cref="JwsAlgorithmVerification"/> overload compose the signature step around
/// it: they parse the compact <c>client_assertion</c>, resolve the verification key from the
/// registration's <see cref="ClientRecord.ClientJwks"/> — or, when that is absent, from
/// <see cref="ClientRecord.ClientJwksUri"/> through the OPTIONAL wired
/// <see cref="Pipeline.ResolveJwksUriDelegate"/> — via <see cref="JwkJsonReader"/> and
/// <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/> (through
/// <see cref="DpopJwkUtilities.PublicKeyFromJwk"/>), bind the header's algorithm to that key
/// (<see cref="JwsKeyAlgorithmBinding"/>), verify with <see cref="Jws.VerifyAsync(string,DecodeDelegate,BaseMemoryPool,PublicKeyMemory,CancellationToken)"/>,
/// and only then apply <see cref="Validate"/>. The compact form and the protected header are read
/// (<see cref="ClientAssertionHeaderRules.Read"/>) before any key set is read or resolved.
/// </para>
/// <para>
/// The <see cref="ClientAssertionAudiencePolicy"/> is applied by the validators
/// <see cref="BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
/// builds, not by <see cref="Validate"/>: under
/// <see cref="ClientAssertionAudiencePolicy.IssuerIdentifierOnly"/> the <c>aud</c> claim must be the
/// issuer identifier as a string or as a one-element array, checked before <see cref="Validate"/>
/// runs, while <see cref="Validate"/> itself checks membership only.
/// </para>
/// <para>
/// No validator reads the <c>typ</c> header parameter, so an assertion typed <c>JWT</c> and one typed
/// <c>client-authentication+jwt</c> both authenticate, following rfc7523bis-11
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">Section
/// 4</see>: "it is NOT RECOMMENDED for servers to reject JWTs that do not have explicit types."
/// </para>
/// <para>
/// The claim rules enforced by <see cref="Validate"/>:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>iss</c> and <c>sub</c> both equal <c>client_id</c> — RFC 7523 §3 items 1 and 2.B: "For
///     client authentication, the subject MUST be the &quot;client_id&quot; of the OAuth client."
///   </description></item>
///   <item><description>
///     <c>aud</c> (string or array) contains only values the caller accepts as this authorization
///     server's identity, and at least one is present (RFC 7523 Section 3 item 3). The validators
///     that <see cref="BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
///     returns pass the issuer identifier and the request's token endpoint
///     URL and pushed authorization request endpoint URL under
///     <see cref="ClientAssertionAudiencePolicy.AuthorizationServerIdentities"/> (RFC 9126 Section 2),
///     and the issuer identifier alone under
///     <see cref="ClientAssertionAudiencePolicy.IssuerIdentifierOnly"/> (rfc7523bis-11 Section 4
///     item b). An array carrying any other value is rejected outright, the same
///     anti-audience-injection posture <see cref="FederationClientAuthentication"/> and
///     <see cref="Rfc7523AssertionValidation"/> apply.
///   </description></item>
///   <item><description><c>jti</c> is present, surfaced for the caller's replay defense.</description></item>
///   <item><description>
///     <c>exp</c> is present and the assertion is neither expired nor internally inconsistent with
///     <c>iat</c>/<c>nbf</c> (RFC 7523 §3 items 4–5); a present <c>iat</c> must not sit in the
///     future beyond the clock-skew tolerance ("iat sanity").
///   </description></item>
/// </list>
/// </remarks>
public static class PrivateKeyJwtClientAuthentication
{
    /// <summary>
    /// Validates a decoded (signature-verified) <c>private_key_jwt</c> client-authentication
    /// assertion against the RFC 7523 §3/§3.2 claim rules.
    /// </summary>
    /// <param name="payload">The decoded, signature-verified assertion payload.</param>
    /// <param name="clientId">
    /// The client identifier the assertion authenticates — the value its <c>iss</c> and <c>sub</c>
    /// must both equal (RFC 7523 §3 items 1, 2.B).
    /// </param>
    /// <param name="acceptedAudiences">
    /// The values <c>aud</c> may name — this authorization server's issuer identifier and/or token
    /// endpoint URL (RFC 7523 §3 item 3: "The token endpoint URL of the authorization server MAY be
    /// used as a value for an &quot;aud&quot; element"). This method checks membership only: passing the issuer
    /// identifier alone does not refuse an array that repeats it, because the issuer-only rule is
    /// applied by <see cref="BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
    /// with <c>audiencePolicy</c>.
    /// </param>
    /// <param name="now">The instant expiry / not-before are evaluated against.</param>
    /// <param name="clockSkew">Tolerance applied to the <c>exp</c>, <c>nbf</c>, and <c>iat</c> comparisons.</param>
    /// <returns>
    /// A successful result carrying the authenticated <c>client_id</c>, <c>jti</c>, and expiry, or a
    /// failed result whose <see cref="PrivateKeyJwtClientAuthenticationResult.FailureReason"/> the
    /// caller maps onto an HTTP 401 <c>invalid_client</c> response (RFC 7523 §3.2).
    /// </returns>
    public static PrivateKeyJwtClientAuthenticationResult Validate(
        JwtPayload payload,
        string clientId,
        IReadOnlyCollection<string> acceptedAudiences,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(acceptedAudiences);

        //RFC 7523 Section 3: the claim rules every client assertion is judged by, whatever key or secret verified it, are the
        //library's one judgement of them.
        var judged = ClientAssertionClaimRules.Judge(payload, clientId, acceptedAudiences, now, clockSkew);

        if(judged.Refusal is not null || judged.Expiry is not NumericDate expiry)
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                $"The client assertion breaks the RFC 7523 Section 3 rule {judged.Refusal}.");
        }

        return PrivateKeyJwtClientAuthenticationResult.Authenticated(clientId, judged.Jti!, expiry);
    }


    /// <summary>
    /// Builds a <see cref="ValidateClientCredentialsDelegate"/> that parses the compact
    /// <c>client_assertion</c>, resolves the verification key from the registration's
    /// <see cref="ClientRecord.ClientJwks"/>, verifies the signature via
    /// <see cref="Jws.VerifyAsync(string,DecodeDelegate,BaseMemoryPool,PublicKeyMemory,CancellationToken)"/>'s
    /// registry-resolving overload, and applies <see cref="Validate"/>. Delegates the signature step
    /// to <see cref="BuildValidator(JwsAlgorithmVerification,System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>'s
    /// shared core once the key is resolved per request, so the verification logic is written once.
    /// </summary>
    /// <param name="additionalAcceptedAudiences">
    /// Extra values <c>aud</c> may name beyond the resolved issuer identifier and the request's token
    /// and pushed-authorization endpoint URLs, or <see langword="null"/> to add none. Refused (an
    /// <see cref="ArgumentException"/> at build time, before any wire input is read) when non-empty
    /// together with <paramref name="audiencePolicy"/> set to
    /// <see cref="ClientAssertionAudiencePolicy.IssuerIdentifierOnly"/>.
    /// </param>
    /// <param name="checkJtiReplayAsync">
    /// Replay-defense hook consulted after the claim rules pass, or <see langword="null"/> to skip
    /// replay defense (the caller relies on a different mechanism). Pass
    /// <see cref="JtiReplayGuard.ConsultClientAssertionAsync"/> directly to reuse the library's
    /// replay store. OpenID Connect Core Section 9 requires a client assertion to be used once
    /// (<see href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">"These
    /// tokens MUST only be used once, unless conditions for reuse were negotiated between the
    /// parties"</see>), so a <see langword="null"/> hook leaves that rule to the application's own
    /// mechanism.
    /// </param>
    /// <param name="resolveJwksUriAsync">
    /// The OPTIONAL key-set resolution seam for a registration that carries a
    /// <see cref="ClientRecord.ClientJwksUri"/> but no inline <see cref="ClientRecord.ClientJwks"/> —
    /// the RFC 7591 §2 <c>jwks_uri</c> registration a caller never dereferenced. <see langword="null"/>
    /// fails closed exactly as an unwired seam always has: the application owns what
    /// reaches the wire, so nothing here dereferences <see cref="ClientRecord.ClientJwksUri"/> on its
    /// own. Wire a delegate whose implementation calls
    /// <see cref="Verifiable.OAuth.Server.Pipeline.JwksUriResolver.ResolveAsync"/> here to resolve
    /// it — the caller supplies that attempt's own transport and size cap, reads the SSRF policy from
    /// the <see cref="ExchangeContext"/> this delegate is called with, and owns whatever caching sits
    /// in front of the attempt (see <see cref="Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate"/>).
    /// </param>
    /// <param name="audiencePolicy">
    /// The <c>aud</c> claim rule this validator applies,
    /// <see cref="ClientAssertionAudiencePolicy.AuthorizationServerIdentities"/> (also read from
    /// <see langword="null"/>) or <see cref="ClientAssertionAudiencePolicy.IssuerIdentifierOnly"/>. Every
    /// argument is required: a caller names what it passes, none of them defaulted.
    /// </param>
    public static ValidateClientCredentialsDelegate BuildValidator(
        IReadOnlyCollection<string>? additionalAcceptedAudiences,
        CheckClientAssertionJtiReplayDelegate? checkJtiReplayAsync,
        ResolveJwksUriDelegate? resolveJwksUriAsync,
        ClientAssertionAudiencePolicy? audiencePolicy)
    {
        ThrowIfAudiencePolicyCompositionIsContradictory(additionalAcceptedAudiences, audiencePolicy);

        return BuildValidatorCore(additionalAcceptedAudiences, checkJtiReplayAsync, resolveJwksUriAsync, verification: null, audiencePolicy);
    }


    /// <summary>
    /// Builds a <see cref="ValidateClientCredentialsDelegate"/> using an explicit verification bound to the one algorithm it
    /// performs (<see cref="JwsAlgorithmVerification"/>) rather than resolving one from
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1,TDiscriminator2}"/>: an assertion whose header names another
    /// algorithm, or an algorithm of another key type than the selected key's, is refused before the function runs
    /// (<see cref="JwsKeyAlgorithmBinding.JudgeSuppliedVerification"/>). The registry-resolving overload above shares this
    /// method's validation core, supplying no verification so the per-request signature step falls back to
    /// <see cref="Jws.VerifyAsync(string,DecodeDelegate,BaseMemoryPool,PublicKeyMemory,CancellationToken)"/>'s
    /// own registry resolution.
    /// </summary>
    /// <param name="verification">The verification to use, bound to the algorithm it performs.</param>
    /// <param name="additionalAcceptedAudiences">
    /// Extra values <c>aud</c> may name beyond the resolved issuer identifier and the request's token
    /// and pushed-authorization endpoint URLs, or <see langword="null"/> to add none. Refused (an
    /// <see cref="ArgumentException"/> at build time, before any wire input is read) when non-empty
    /// together with <paramref name="audiencePolicy"/> set to
    /// <see cref="ClientAssertionAudiencePolicy.IssuerIdentifierOnly"/>.
    /// </param>
    /// <param name="checkJtiReplayAsync">
    /// Replay-defense hook consulted after the claim rules pass, or <see langword="null"/> to skip
    /// replay defense. OpenID Connect Core Section 9 requires a client assertion to be used once
    /// (<see href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">"These
    /// tokens MUST only be used once, unless conditions for reuse were negotiated between the
    /// parties"</see>), so a <see langword="null"/> hook leaves that rule to the application's own
    /// mechanism.
    /// </param>
    /// <param name="resolveJwksUriAsync">
    /// The key-set resolution seam, or <see langword="null"/> for none; see the registry-resolving
    /// overload's parameter of the same name.
    /// </param>
    /// <param name="audiencePolicy">
    /// The <c>aud</c> claim rule this validator applies, or <see langword="null"/> for
    /// <see cref="ClientAssertionAudiencePolicy.AuthorizationServerIdentities"/>; see the
    /// registry-resolving overload's parameter of the same name.
    /// </param>
    public static ValidateClientCredentialsDelegate BuildValidator(
        JwsAlgorithmVerification verification,
        IReadOnlyCollection<string>? additionalAcceptedAudiences,
        CheckClientAssertionJtiReplayDelegate? checkJtiReplayAsync,
        ResolveJwksUriDelegate? resolveJwksUriAsync,
        ClientAssertionAudiencePolicy? audiencePolicy)
    {
        ArgumentNullException.ThrowIfNull(verification);
        ThrowIfAudiencePolicyCompositionIsContradictory(additionalAcceptedAudiences, audiencePolicy);

        return BuildValidatorCore(additionalAcceptedAudiences, checkJtiReplayAsync, resolveJwksUriAsync, verification, audiencePolicy);
    }


    /// <summary>
    /// Refuses a contradictory composition: <paramref name="audiencePolicy"/> set to
    /// <see cref="ClientAssertionAudiencePolicy.IssuerIdentifierOnly"/> together with a non-empty
    /// <paramref name="additionalAcceptedAudiences"/> asks for the accepted set to be closed to the
    /// issuer alone and widened by extra values in the same call. rfc7523bis-11
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">Section
    /// 4</see>'s narrower rule admits no additional accepted audience, so both
    /// <see cref="BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
    /// and its explicit-<see cref="JwsAlgorithmVerification"/> overload refuse this composition when the
    /// validator is BUILT, before any wire input is read.
    /// </summary>
    /// <param name="additionalAcceptedAudiences">The additional-audience argument as the caller passed it.</param>
    /// <param name="audiencePolicy">The audience-policy argument as the caller passed it.</param>
    private static void ThrowIfAudiencePolicyCompositionIsContradictory(
        IReadOnlyCollection<string>? additionalAcceptedAudiences,
        ClientAssertionAudiencePolicy? audiencePolicy)
    {
        if(audiencePolicy == ClientAssertionAudiencePolicy.IssuerIdentifierOnly
            && additionalAcceptedAudiences is { Count: > 0 })
        {
            throw new ArgumentException(
                $"{nameof(additionalAcceptedAudiences)} must be empty or null when {nameof(audiencePolicy)} is "
                + $"{nameof(ClientAssertionAudiencePolicy)}.{nameof(ClientAssertionAudiencePolicy.IssuerIdentifierOnly)} "
                + "(rfc7523bis-11 Section 4: the aud claim must indicate only the issuer identifier).");
        }
    }


    /// <summary>
    /// Builds the assertion validator using the admitted request wiring and the supplied replay policy.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3.2">RFC 7523 §3.2</see>:
    /// "The subject MUST be the client_id of the OAuth client." <see cref="Validate"/> anchors the
    /// assertion's <c>iss</c>/<c>sub</c> claims to the effective registration's own
    /// <see cref="ClientRecord.ClientId"/> (below), which is client authentication (RFC 6749 §2.3),
    /// never client identification (§2.2). This delegate does not read an accompanying
    /// <c>client_id</c> FORM field at all — every caller runs that comparison, before this delegate
    /// is invoked, through the shared identification helper in <c>AuthCodeEndpoints</c>.
    /// </summary>
    private static ValidateClientCredentialsDelegate BuildValidatorCore(
        IReadOnlyCollection<string>? additionalAcceptedAudiences,
        CheckClientAssertionJtiReplayDelegate? checkJtiReplayAsync,
        ResolveJwksUriDelegate? resolveJwksUriAsync,
        JwsAlgorithmVerification? verification,
        ClientAssertionAudiencePolicy? audiencePolicy)
    {
        return async (request, fields, registration, context, cancellationToken) =>
        {
            EndpointServer? server = context.RequestServer;
            if(server is null)
            {
                return false;
            }

            var oauth = server.OAuth();
            if(oauth.Codecs.Decoder is null
                || oauth.Codecs.JwtHeaderDeserializer is null
                || oauth.Codecs.JwtPayloadDeserializer is null)
            {
                return false;
            }

            //RFC 7523 §2.2 / RFC 7521 §4.2: client_assertion_type MUST select the JWT Bearer client
            //authentication profile before client_assertion is even attempted as this profile's
            //assertion — an AS-side check no other seam in this library performs today.
            if(!fields.TryGetValue(OAuthRequestParameterNames.ClientAssertionType, out string? assertionType)
                || !WellKnownClientAssertionTypes.IsJwtBearer(assertionType))
            {
                return false;
            }

            //RFC 7523 §2.2: "the client_assertion parameter contains a single JWT. It MUST NOT
            //contain more than one JWT" — satisfied structurally: RequestFields holds one string
            //per key, so a second client_assertion value can never be represented here.
            if(!fields.TryGetValue(OAuthRequestParameterNames.ClientAssertion, out string? clientAssertion)
                || string.IsNullOrWhiteSpace(clientAssertion))
            {
                return false;
            }

            //The compact form and the protected header are judged by the one reading every key source shares before any key set
            //is read or resolved and any key selected: three base64url segments no longer than the verifier reads, a header of
            //one JSON object naming each member once and an algorithm that is not none (RFC 8725 Section 3.1), and no critical
            //extension, this profile implementing none (RFC 7515 Section 4.1.11), so a refused assertion never reaches the key
            //set's resolution.
            var headerReading = ClientAssertionHeaderRules.Read(
                clientAssertion,
                oauth.Codecs.Decoder,
                oauth.Codecs.JwtHeaderDeserializer,
                oauth.MemoryPool!);

            if(headerReading is not { Algorithm: { } alg, Header: { } presentedHeader })
            {
                return false;
            }

            //draft-ietf-oauth-client-id-metadata-document-02 §8.2: no published key material means
            //the assertion cannot be verified. RFC 7591 §2 permits the client to register a jwks_uri
            //instead of an inline jwks; when the registration carries one and a resolver is wired,
            //resolve it now. With no inline set, no jwks_uri, or no resolver wired, this fails closed
            //rather than treat the client as unauthenticated — the application owns what reaches the
            //wire, so nothing here dereferences ClientJwksUri without an explicitly supplied seam.
            string? clientJwksJson = registration.ClientJwks;
            if(clientJwksJson is null)
            {
                if(registration.ClientJwksUri is null || resolveJwksUriAsync is null)
                {
                    return false;
                }

                JwksUriResolution jwksResolution = await resolveJwksUriAsync(
                    registration.ClientJwksUri, context, cancellationToken).ConfigureAwait(false);
                if(!jwksResolution.IsResolved || jwksResolution.Jwks is null)
                {
                    return false;
                }

                clientJwksJson = jwksResolution.Jwks;
            }

            UnverifiedJwsMessage unverified;
            try
            {
                unverified = JwsParsing.ParseCompact(
                    clientAssertion,
                    oauth.Codecs.Decoder,
                    bytes => oauth.Codecs.JwtHeaderDeserializer(bytes),
                    oauth.MemoryPool!);
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                return false;
            }

            using(unverified)
            {
                var kid = presentedHeader.TryGetValue(WellKnownJwkMemberNames.Kid, out var kidObj)
                    && kidObj is string kidValue
                    ? kidValue
                    : null;

                IReadOnlyDictionary<string, string>? jwkMembers = FindJwkMembers(clientJwksJson, kid, oauth.MemoryPool!);

                //A JWK carrying a private or symmetric member cannot be a verification key —
                //draft-ietf-oauth-client-id-metadata-document-02 §4.1 (CIMD-023) already forbids this
                //at the document-reader layer, so this is defense-in-depth for a directly-registered
                //ClientJwks the reader never validated. Mirrors DpopJwkUtilities.ContainsPrivateKeyMaterial.
                if(jwkMembers is null
                    || WellKnownJwkMemberNames.ContainsPrivateOrSymmetricMember(jwkMembers.Keys))
                {
                    return false;
                }

                PublicKeyMemory publicKey;
                try
                {
                    publicKey = DpopJwkUtilities.PublicKeyFromJwk(
                        jwkMembers, alg, oauth.Codecs.Decoder, oauth.MemoryPool!);
                }
                catch(Exception ex) when(ex is FormatException or InvalidOperationException or ArgumentException or NotSupportedException or RsaPublicKeyException)
                {
                    return false;
                }

                using(publicKey)
                {
                    //RFC 7515 Section 5.2 step 8 and RFC 8725 Section 3.1: the key was reconstructed from its material alone, so the
                    //algorithm the header names is bound to it here, before either verification runs - for a verification
                    //resolved from the key's tag, the one algorithm that function computes; for a verification the caller
                    //supplies, the one algorithm it is bound to, defined over the key's type - and an ES256 signature beneath an
                    //RS256 header, or an RS256 signature beneath a PS256 header, is refused unverified.
                    var binding = verification is not null
                        ? JwsKeyAlgorithmBinding.JudgeSuppliedVerification(alg, publicKey, verification)
                        : JwsKeyAlgorithmBinding.JudgeRegistryVerification(alg, publicKey);

                    if(binding is not null)
                    {
                        return false;
                    }

                    bool signatureValid;
                    try
                    {
                        signatureValid = verification is not null
                            ? await Jws.VerifyAsync(
                                clientAssertion, oauth.Codecs.Decoder, oauth.MemoryPool!,
                                publicKey, verification.Verification, cancellationToken).ConfigureAwait(false)
                            : await Jws.VerifyAsync(
                                clientAssertion, oauth.Codecs.Decoder, oauth.MemoryPool!,
                                publicKey, cancellationToken).ConfigureAwait(false);
                    }
                    catch(Exception ex) when(ex is FormatException or InvalidOperationException)
                    {
                        return false;
                    }

                    if(!signatureValid)
                    {
                        return false;
                    }

                    //RFC 7519 §4: the Claim Names within a JWT Claims Set MUST be unique. Gate the
                    //decoded payload for well-formedness before it reaches the wired deserializer,
                    //so a duplicate claim name is refused here rather than escaping the
                    //deserializer as an unhandled exception.
                    if(!JwkJsonReader.IsWellFormedJsonDocument(unverified.Payload.Span))
                    {
                        return false;
                    }

                    //RFC 7519 Section 2: a NumericDate may carry a fraction, and the claim rules judge it to the tick under their
                    //own tolerance, as the payload codec states every member as written.
                    JwtPayload payload;
                    try
                    {
                        payload = new(oauth.Codecs.JwtPayloadDeserializer(unverified.Payload.Span));
                    }
                    catch(Exception ex) when(ex is FormatException or InvalidOperationException or System.Text.Json.JsonException)
                    {
                        return false;
                    }

                    //A step endpoint (code redemption, refresh) resolves and carries the issuer
                    //BEFORE running declared authentication — read that carried value rather than
                    //resolving a second time for the same request. PAR, client credentials, and
                    //the other stepless callers carry nothing, so they resolve here as before.
                    //rfc7523bis-11 Section 4 item b: "The authorization server MUST have an issuer
                    //identifier to be used with this specification." A resolution that fails leaves
                    //no issuer identifier to compare the audience with, so the assertion is refused.
                    Uri issuerUri;
                    if(context.CorrelationStepIssuer is Uri carriedIssuer)
                    {
                        issuerUri = carriedIssuer;
                    }
                    else
                    {
                        try
                        {
                            issuerUri = oauth.ResolveIssuerAsync is not null
                                ? (await oauth.ResolveIssuerAsync(registration, context, cancellationToken)
                                    .ConfigureAwait(false))!
                                : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken)
                                    .ConfigureAwait(false);
                        }
                        catch(InvalidOperationException)
                        {
                            return false;
                        }
                    }

                    ClientAssertionAudiencePolicy effectiveAudiencePolicy =
                        audiencePolicy ?? ClientAssertionAudiencePolicy.AuthorizationServerIdentities;

                    List<string> acceptedAudiences = [issuerUri.OriginalString];
                    if(effectiveAudiencePolicy == ClientAssertionAudiencePolicy.IssuerIdentifierOnly)
                    {
                        //rfc7523bis-11 Section 4 item b: the authorization server "MUST reject any JWT
                        //that does not contain its issuer identifier as its sole audience value." A
                        //CARDINALITY rule, not only a membership rule, so an array naming the issuer
                        //twice is refused even though every element would otherwise match an accepted
                        //audience below.
                        if(!payload.TryGetValue(WellKnownJwtClaimNames.Aud, out object? issuerOnlyAudienceRaw)
                            || !IsIssuerIdentifierOnlyAudience(issuerOnlyAudienceRaw, issuerUri.OriginalString))
                        {
                            return false;
                        }
                    }
                    else
                    {
                        if(additionalAcceptedAudiences is not null)
                        {
                            acceptedAudiences.AddRange(additionalAcceptedAudiences);
                        }

                        //RFC 9126 Section 2: "the authorization server MUST accept its issuer identifier,
                        //token endpoint URL, or pushed authorization request endpoint URL as values
                        //that identify it as an intended audience" - a blanket MUST on the
                        //authorization server, not only at the PAR endpoint, so every caller of this
                        //validator accepts the same three identities without a second wiring
                        //parameter. The per-request EndpointChain already carries each active
                        //endpoint's resolved URL (the same one MetadataEndpoints publishes), so the
                        //token and PAR endpoint URLs are read from it rather than duplicated here. The
                        //accepted string is the PUBLISHED one: RFC 7519 Section 2's StringOrURI is "compared
                        //as case-sensitive strings with no transformations or canonicalizations
                        //applied", so an `aud` copied from `MetadataEndpoints`' own
                        //`ResolvedUri.ToString()` must be matched with the same call, never
                        //`OriginalString`.
                        if(context.EndpointChain is { } endpointChain)
                        {
                            foreach(ServerEndpoint chainEndpoint in endpointChain)
                            {
                                if(string.Equals(chainEndpoint.Name, WellKnownEndpointNames.AuthCodeToken, StringComparison.Ordinal)
                                    || string.Equals(chainEndpoint.Name, WellKnownEndpointNames.AuthCodePar, StringComparison.Ordinal))
                                {
                                    acceptedAudiences.Add(chainEndpoint.ResolvedUri.ToString());
                                }
                            }
                        }
                    }

                    DateTimeOffset now = server.TimeProvider.GetUtcNow();
                    PrivateKeyJwtClientAuthenticationResult result = Validate(
                        payload, registration.ClientId, acceptedAudiences, now, context.ClockSkewTolerance);

                    if(!result.IsValid)
                    {
                        return false;
                    }

                    if(checkJtiReplayAsync is not null)
                    {
                        //RFC 7523 §3 rule 7: the recorded jti is retained "for the length of time for
                        //which the JWT would be considered valid based on the applicable exp instant" —
                        //here that is exp plus the clock-skew tolerance Validate just accepted the
                        //assertion's timing under, not the bare exp, and the clock's last instant where
                        //that window reaches the clock's end.
                        JtiReplayOutcome outcome = await checkJtiReplayAsync(
                            server, context, registration.TenantId, result.ClientId!, result.Jti!,
                            ClientAssertionClaimRules.ReplayRecordKeptUntil(result.Expiration!, context.ClockSkewTolerance), cancellationToken).ConfigureAwait(false);

                        //Any outcome other than FirstUse refuses the assertion: Replayed is the
                        //defense doing its job, StoreUnavailable is a policy that cannot prove
                        //itself, and Unacceptable is an oversized jti the guard will not track —
                        //none of the three authenticates the client.
                        if(outcome != JtiReplayOutcome.FirstUse)
                        {
                            return false;
                        }
                    }

                    return true;
                }
            }
        };
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="audienceRaw"/> is exactly the issuer
    /// identifier, a bare string equal to <paramref name="issuerIdentifier"/>, or an array holding
    /// exactly that one string and nothing else. rfc7523bis-11
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">Section
    /// 4</see> item b: the <c>aud</c> claim value "MUST indicate only the issuer identifier of the
    /// intended authorization server as the audience of the JWT; this includes that the token endpoint
    /// URL of the authorization server MUST NOT be used as an audience value." A CARDINALITY rule, so an
    /// array of two or more elements is refused regardless of what it holds, including a duplicated
    /// issuer. An array is matched as <see cref="IEnumerable{T}"/> of <see cref="string"/> or of
    /// <see cref="object"/> and counted to exactly one element, the same shapes
    /// <see cref="ClientAssertionClaimRules.AudienceNamesOnly"/> matches, so a one-element array is judged the same way under
    /// both audience policies.
    /// </summary>
    /// <remarks>
    /// The comparison is ordinal (<see cref="StringComparison.Ordinal"/>), the Simple String Comparison
    /// method rfc7523bis-11
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">Section
    /// 4</see> requires: "In the absence of an application profile specifying otherwise, applications
    /// MUST compare the audience values using the Simple String Comparison method defined in Section
    /// 6.2.1 of RFC 3986" (<see href="https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.1">RFC
    /// 3986 Section 6.2.1</see>). An issuer identifier with an appended <c>/</c> or a differently cased
    /// scheme is a different value and is refused; a differently cased host follows from the same
    /// ordinal comparison, which sees only code units and folds no case.
    /// </remarks>
    private static bool IsIssuerIdentifierOnlyAudience(object audienceRaw, string issuerIdentifier)
    {
        return audienceRaw switch
        {
            string single => string.Equals(single, issuerIdentifier, StringComparison.Ordinal),
            IEnumerable<string> stringArray => stringArray.Take(2).ToList() is [string soleString]
                && string.Equals(soleString, issuerIdentifier, StringComparison.Ordinal),
            IEnumerable<object> mixedArray => mixedArray.Take(2).ToList() is [string soleValue]
                && string.Equals(soleValue, issuerIdentifier, StringComparison.Ordinal),
            _ => false
        };
    }


    /// <summary>
    /// Selects the verification key from a registered <c>ClientJwks</c> JWK Set document, eligible for
    /// signature verification and free of private or symmetric material. When the assertion header
    /// carried a <paramref name="kid"/>, selects by it through
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/> —
    /// which refuses rather than picks a winner when the identifier appears on more than one key,
    /// whatever each match's <c>use</c> is. Only when <paramref name="kid"/> is absent does this fall
    /// to <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>, since
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// <c>kid</c> optional for a legitimate single-key set; a kid-less assertion is refused UNLESS
    /// exactly one key of the set is eligible for signature verification — a set with no <c>use</c>
    /// member on any key is refused when it carries more than one key, but a set holding one
    /// <c>sig</c> key and one <c>enc</c> key authenticates against the <c>sig</c> key rather than
    /// being refused for carrying two keys. Either path refuses the whole set — this library's own
    /// policy for a JWK Set of verification keys, not a requirement of any RFC — when any key in it
    /// carries private or symmetric material; the caller's own refusal of a private or symmetric
    /// SELECTED key stays in force alongside this set-wide one.
    /// </summary>
    /// <param name="jwksJson">The registered JWK Set document.</param>
    /// <param name="kid">The assertion header's <c>kid</c>, or <see langword="null"/> when absent.</param>
    /// <param name="memoryPool">The pool the UTF-8 encoding of <paramref name="jwksJson"/> rents from.</param>
    /// <returns>The selected key's string-valued members, or <see langword="null"/> when no key was selected.</returns>
    private static IReadOnlyDictionary<string, string>? FindJwkMembers(string jwksJson, string? kid, BaseMemoryPool memoryPool)
    {
        int maxByteCount = Encoding.UTF8.GetMaxByteCount(jwksJson.Length);
        using IMemoryOwner<byte> owner = memoryPool.Rent(maxByteCount);
        int written = Encoding.UTF8.GetBytes(jwksJson, owner.Memory.Span);
        ReadOnlySpan<byte> json = owner.Memory.Span[..written];

        JwkSelectionResult result = string.IsNullOrEmpty(kid)
            ? JwkJsonReader.SelectSoleKey(json, WellKnownJwkValues.UseSigUtf8)
            : JwkJsonReader.SelectKeyByKeyId(json, kid, WellKnownJwkValues.UseSigUtf8);

        return result.IsSelected ? result.Members : null;
    }
}
