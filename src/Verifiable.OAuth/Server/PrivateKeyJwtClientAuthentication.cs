using System.Buffers;
using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.WellKnown;
using Verifiable.Server;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Consults a <c>jti</c> replay store for a client-authentication assertion, governed by the
/// same <see cref="JtiReplayPolicy"/>/<see cref="JtiReplayGuard"/> axis the JAR and DPoP paths
/// use. Its parameter shape matches <see cref="JtiReplayGuard.ConsultAsync"/> exactly, so a
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

    /// <summary>The assertion's expiry; <see langword="null"/> on failure.</summary>
    public DateTimeOffset? Expiration { get; init; }

    /// <summary>The reason validation failed; <see langword="null"/> on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary><see langword="true"/> when the client assertion validated.</summary>
    public bool IsValid => FailureReason is null;


    /// <summary>Builds a success result.</summary>
    public static PrivateKeyJwtClientAuthenticationResult Authenticated(
        string clientId, string jti, DateTimeOffset expiration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);

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
/// shape. <see cref="BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?)"/>
/// and its explicit-<see cref="VerificationDelegate"/> overload compose the signature step around
/// it: they parse the compact <c>client_assertion</c>, resolve the verification key from the
/// registration's <see cref="ClientRecord.ClientJwks"/> via <see cref="JwkJsonReader"/> and
/// <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/> (through
/// <see cref="DpopJwkUtilities.PublicKeyFromJwk"/>), verify with <see cref="Jws.VerifyAsync(string,DecodeDelegate,MemoryPool{byte},PublicKeyMemory,CancellationToken)"/>,
/// and only then apply <see cref="Validate"/>.
/// </para>
/// <para>
/// The claim rules enforced by <see cref="Validate"/>:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>iss</c> and <c>sub</c> both equal <c>client_id</c> — RFC 7523 §3 items 1 and 2.B: "For
///     client authentication, the subject MUST be the client_id of the OAuth client."
///   </description></item>
///   <item><description>
///     <c>aud</c> (string or array) contains only values the caller accepts as this authorization
///     server's identity — its issuer identifier or token endpoint URL (RFC 7523 §3 item 3) — and
///     at least one is present; an array carrying any other value is rejected outright, the same
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
[DebuggerDisplay("PrivateKeyJwtClientAuthentication")]
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
    /// used as a value for an aud element").
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

        //RFC 7523 §3 item 1 / item 2.B: iss and sub both identify the OAuth client for the
        //private_key_jwt shape — the assertion's issuer and subject are the client_id.
        if(!TryReadString(payload, WellKnownJwtClaimNames.Iss, out string? iss)
            || !string.Equals(iss, clientId, StringComparison.Ordinal))
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion iss must equal the client_id (RFC 7523 §3 item 1).");
        }

        if(!TryReadString(payload, WellKnownJwtClaimNames.Sub, out string? sub)
            || !string.Equals(sub, clientId, StringComparison.Ordinal))
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion sub must equal the client_id (RFC 7523 §3 item 2.B).");
        }

        //§3 item 3: aud MUST name this AS; every element present must be an accepted AS identity
        //and at least one must be present. Rejecting any non-AS element (rather than accepting on a
        //single match) prevents an assertion crafted to also be valid at another audience.
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Aud, out object? audienceRaw))
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion is missing the aud claim (RFC 7523 §3 item 3).");
        }

        if(!IsAudienceAccepted(audienceRaw, acceptedAudiences))
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion aud must name only this authorization server's issuer identifier "
                + "or token endpoint (RFC 7523 §3 item 3).");
        }

        //jti presence: draft-ietf-oauth-client-id-metadata-document-02's confidential-client model
        //needs a replayable identifier for every assertion, stricter than RFC 7523 §3 item 7's MAY.
        if(!TryReadString(payload, WellKnownJwtClaimNames.Jti, out string? jti))
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion is missing the jti claim.");
        }

        if(!TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Exp, out bool expPresent, out DateTimeOffset exp)
            || !expPresent)
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion is missing or has a malformed exp claim (RFC 7523 §3 item 4).");
        }

        if(!TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Iat, out bool iatPresent, out DateTimeOffset iat))
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion iat claim is malformed.");
        }

        if(iatPresent && exp <= iat)
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion exp is at or before iat (non-positive lifetime).");
        }

        //iat sanity: an assertion claiming to have been issued in the future is nonsensical
        //regardless of its exp.
        if(iatPresent && iat > now + clockSkew)
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion iat is in the future beyond the skew tolerance.");
        }

        if(!TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Nbf, out bool nbfPresent, out DateTimeOffset nbf))
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion nbf claim is malformed.");
        }

        if(nbfPresent)
        {
            if(exp <= nbf)
            {
                return PrivateKeyJwtClientAuthenticationResult.Rejected(
                    "The client assertion exp is at or before nbf (the validity window never opens).");
            }

            if(nbf > now + clockSkew)
            {
                return PrivateKeyJwtClientAuthenticationResult.Rejected(
                    "The client assertion is not yet valid (nbf is in the future beyond the skew tolerance).");
            }
        }

        if(exp + clockSkew <= now)
        {
            return PrivateKeyJwtClientAuthenticationResult.Rejected(
                "The client assertion has expired (RFC 7523 §3 item 4).");
        }

        return PrivateKeyJwtClientAuthenticationResult.Authenticated(clientId, jti!, exp);
    }


    /// <summary>
    /// Builds a <see cref="ValidateClientCredentialsDelegate"/> that parses the compact
    /// <c>client_assertion</c>, resolves the verification key from the registration's
    /// <see cref="ClientRecord.ClientJwks"/>, verifies the signature via
    /// <see cref="Jws.VerifyAsync(string,DecodeDelegate,MemoryPool{byte},PublicKeyMemory,CancellationToken)"/>'s
    /// registry-resolving overload, and applies <see cref="Validate"/>. Delegates the signature step
    /// to <see cref="BuildValidator(VerificationDelegate,System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?)"/>'s
    /// shared core once the key is resolved per request, so the verification logic is written once.
    /// </summary>
    /// <param name="additionalAcceptedAudiences">
    /// Extra values <c>aud</c> may name beyond the resolved issuer identifier — for example the
    /// token endpoint URL — or <see langword="null"/> to accept only the issuer.
    /// </param>
    /// <param name="checkJtiReplayAsync">
    /// Replay-defense hook consulted after the claim rules pass, or <see langword="null"/> to skip
    /// replay defense (the caller relies on a different mechanism). Pass
    /// <see cref="JtiReplayGuard.ConsultAsync"/> directly to reuse the library's <c>(issuer, jti)</c>
    /// store.
    /// </param>
    public static ValidateClientCredentialsDelegate BuildValidator(
        IReadOnlyCollection<string>? additionalAcceptedAudiences = null,
        CheckClientAssertionJtiReplayDelegate? checkJtiReplayAsync = null) =>
        BuildValidatorCore(additionalAcceptedAudiences, checkJtiReplayAsync, verificationDelegate: null);


    /// <summary>
    /// Builds a <see cref="ValidateClientCredentialsDelegate"/> using an explicit
    /// <see cref="VerificationDelegate"/> rather than resolving one from
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1,TDiscriminator2}"/>. The registry-resolving
    /// overload above shares this method's validation core, supplying a
    /// <see langword="null"/> function so the per-request signature step falls back to
    /// <see cref="Jws.VerifyAsync(string,DecodeDelegate,MemoryPool{byte},PublicKeyMemory,CancellationToken)"/>'s
    /// own registry resolution.
    /// </summary>
    /// <param name="verificationDelegate">The verification function to use.</param>
    /// <param name="additionalAcceptedAudiences">
    /// Extra values <c>aud</c> may name beyond the resolved issuer identifier — for example the
    /// token endpoint URL — or <see langword="null"/> to accept only the issuer.
    /// </param>
    /// <param name="checkJtiReplayAsync">
    /// Replay-defense hook consulted after the claim rules pass, or <see langword="null"/> to skip
    /// replay defense.
    /// </param>
    public static ValidateClientCredentialsDelegate BuildValidator(
        VerificationDelegate verificationDelegate,
        IReadOnlyCollection<string>? additionalAcceptedAudiences = null,
        CheckClientAssertionJtiReplayDelegate? checkJtiReplayAsync = null)
    {
        ArgumentNullException.ThrowIfNull(verificationDelegate);

        return BuildValidatorCore(additionalAcceptedAudiences, checkJtiReplayAsync, verificationDelegate);
    }


    private static ValidateClientCredentialsDelegate BuildValidatorCore(
        IReadOnlyCollection<string>? additionalAcceptedAudiences,
        CheckClientAssertionJtiReplayDelegate? checkJtiReplayAsync,
        VerificationDelegate? verificationDelegate)
    {
        return async (request, fields, registration, context, cancellationToken) =>
        {
            EndpointServer? server = context.Server;
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

            //draft-ietf-oauth-client-id-metadata-document-02 §8.2: no published key material means
            //the assertion cannot be verified. Fail closed rather than treat the client as
            //unauthenticated — the caller is responsible for populating ClientJwks (directly, or from
            //ClientJwksUri content it fetched through its own OutboundFetch-policed call) before this
            //validator runs.
            if(registration.ClientJwks is null)
            {
                return false;
            }

            UnverifiedJwsMessage unverified;
            try
            {
                unverified = JwsParsing.ParseCompact(
                    clientAssertion,
                    oauth.Codecs.Decoder,
                    bytes => oauth.Codecs.JwtHeaderDeserializer(bytes),
                    BaseMemoryPool.Shared);
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                return false;
            }

            using(unverified)
            {
                UnverifiedJwtHeader header = unverified.Signatures[0].ProtectedHeader;

                //RFC 8725 §3.1: alg=none is rejected unconditionally — an assertion with no
                //signature algorithm cannot authenticate a confidential client.
                if(!header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algObj)
                    || algObj is not string alg
                    || string.IsNullOrEmpty(alg)
                    || string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                string? kid = header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj)
                    && kidObj is string kidValue
                    ? kidValue
                    : null;

                Dictionary<string, string>? jwkMembers = FindJwkMembers(registration.ClientJwks, kid);

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
                        jwkMembers, alg, oauth.Codecs.Decoder, BaseMemoryPool.Shared);
                }
                catch(Exception ex) when(ex is FormatException or InvalidOperationException or ArgumentException or NotSupportedException)
                {
                    return false;
                }

                using(publicKey)
                {
                    bool signatureValid;
                    try
                    {
                        signatureValid = verificationDelegate is not null
                            ? await Jws.VerifyAsync(
                                clientAssertion, oauth.Codecs.Decoder, BaseMemoryPool.Shared,
                                publicKey, verificationDelegate, cancellationToken).ConfigureAwait(false)
                            : await Jws.VerifyAsync(
                                clientAssertion, oauth.Codecs.Decoder, BaseMemoryPool.Shared,
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

                    JwtPayload payload;
                    try
                    {
                        payload = new JwtPayload(oauth.Codecs.JwtPayloadDeserializer(unverified.Payload.Span));
                    }
                    catch(Exception ex) when(ex is FormatException or InvalidOperationException)
                    {
                        return false;
                    }

                    Uri issuerUri;
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

                    List<string> acceptedAudiences = [issuerUri.OriginalString];
                    if(additionalAcceptedAudiences is not null)
                    {
                        acceptedAudiences.AddRange(additionalAcceptedAudiences);
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
                        JtiReplayOutcome outcome = await checkJtiReplayAsync(
                            server, context, registration.TenantId, result.ClientId!, result.Jti!,
                            result.Expiration!.Value, cancellationToken).ConfigureAwait(false);

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
    /// Reads a non-empty string claim, or returns <see langword="false"/> when it is absent or not a
    /// non-empty string.
    /// </summary>
    private static bool TryReadString(JwtPayload payload, string claimName, out string? value)
    {
        if(payload.TryGetValue(claimName, out object? raw) && raw is string text && text.Length > 0)
        {
            value = text;

            return true;
        }

        value = null;

        return false;
    }


    /// <summary>
    /// Reads an epoch-seconds temporal claim. Returns <see langword="false"/> when the claim is
    /// present but not a numeric timestamp; sets <paramref name="present"/> to whether the claim was
    /// there at all.
    /// </summary>
    private static bool TryReadEpochSeconds(
        JwtPayload payload, string claimName, out bool present, out DateTimeOffset value)
    {
        value = default;
        if(!payload.TryGetValue(claimName, out object? raw))
        {
            present = false;

            return true;
        }

        present = true;
        long? seconds = raw switch
        {
            long l => l,
            int i => i,
            short s => s,
            byte b => b,
            ulong u when u <= long.MaxValue => (long)u,
            uint ui => ui,
            double d when d >= long.MinValue && d <= long.MaxValue && d == Math.Floor(d) => (long)d,
            float f when f >= long.MinValue && f <= long.MaxValue && f == Math.Floor(f) => (long)f,
            string text when long.TryParse(text, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out long parsed) => parsed,
            _ => null,
        };

        if(seconds is null)
        {
            return false;
        }

        value = DateTimeOffset.FromUnixTimeSeconds(seconds.Value);

        return true;
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="audienceRaw"/> (a string or an array of
    /// strings) contains at least one entry and every entry ordinal-equals one of
    /// <paramref name="acceptedAudiences"/> — RFC 7523 §3 item 3's "MUST reject any JWT that does not
    /// contain its own identity as the intended audience," hardened so a mixed-in foreign audience
    /// value rejects the whole assertion rather than being ignored.
    /// </summary>
    private static bool IsAudienceAccepted(object audienceRaw, IReadOnlyCollection<string> acceptedAudiences)
    {
        if(acceptedAudiences.Count == 0)
        {
            return false;
        }

        return audienceRaw switch
        {
            string single => single.Length > 0 && ContainsOrdinal(acceptedAudiences, single),
            IEnumerable<string> typed => AreAllAccepted(typed, acceptedAudiences),
            IEnumerable<object> mixed => AreAllAccepted(mixed, acceptedAudiences),
            _ => false
        };
    }


    private static bool AreAllAccepted(IEnumerable<string> values, IReadOnlyCollection<string> acceptedAudiences)
    {
        bool sawAny = false;
        foreach(string value in values)
        {
            if(value.Length == 0 || !ContainsOrdinal(acceptedAudiences, value))
            {
                return false;
            }

            sawAny = true;
        }

        return sawAny;
    }


    private static bool AreAllAccepted(IEnumerable<object> values, IReadOnlyCollection<string> acceptedAudiences)
    {
        bool sawAny = false;
        foreach(object value in values)
        {
            if(value is not string text || text.Length == 0 || !ContainsOrdinal(acceptedAudiences, text))
            {
                return false;
            }

            sawAny = true;
        }

        return sawAny;
    }


    private static bool ContainsOrdinal(IReadOnlyCollection<string> values, string candidate)
    {
        foreach(string value in values)
        {
            if(string.Equals(value, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Locates the JWK matching <paramref name="kid"/> (or the first key when <paramref name="kid"/>
    /// is <see langword="null"/>, mirroring <see cref="FederationKeyResolver"/>'s
    /// absent-kid convention) inside a JWKS JSON document's <c>keys</c> array, and extracts its
    /// string-valued members. Composes <see cref="JwkJsonReader"/> primitives the way
    /// <see cref="ClientIdMetadataDocumentReader"/> already walks a <c>keys</c> array —
    /// <see cref="JwkJsonReader"/> itself has no combinator for "the array element whose kid
    /// matches."
    /// </summary>
    private static Dictionary<string, string>? FindJwkMembers(string jwksJson, string? kid)
    {
        ReadOnlySpan<byte> json = Encoding.UTF8.GetBytes(jwksJson);

        int keysStart = JwkJsonReader.IndexOfKey(json, WellKnownJwkMemberNames.KeysUtf8);
        if(keysStart < 0)
        {
            return null;
        }

        int afterKeysKey = keysStart + WellKnownJwkMemberNames.KeysUtf8.Length + 1;
        afterKeysKey = JwkJsonReader.SkipWhitespaceAndColon(json, afterKeysKey);
        if(afterKeysKey < 0 || afterKeysKey >= json.Length || json[afterKeysKey] != (byte)'[')
        {
            return null;
        }

        int cursor = afterKeysKey + 1;
        while(cursor < json.Length)
        {
            while(cursor < json.Length && IsArraySeparator(json[cursor]))
            {
                cursor++;
            }

            if(cursor >= json.Length || json[cursor] == (byte)']')
            {
                return null;
            }

            if(json[cursor] != (byte)'{')
            {
                return null;
            }

            int objectStart = cursor;
            int objectEnd = FindObjectEnd(json, objectStart);
            if(objectEnd < 0)
            {
                return null;
            }

            ReadOnlySpan<byte> candidate = json[objectStart..objectEnd];
            string? candidateKid = JwkJsonReader.ExtractStringValue(candidate, WellKnownJwkMemberNames.KidUtf8);

            if(kid is null || string.Equals(candidateKid, kid, StringComparison.Ordinal))
            {
                return ExtractJwkStringMembers(candidate);
            }

            cursor = objectEnd;
        }

        return null;
    }


    //Returns the index one past the '}' that closes the object opening at objectStart, or -1 when
    //the braces never balance. String content is skipped so a brace inside a quoted value never
    //biases the depth counter. Mirrors ClientIdMetadataDocumentReader's identically-named helper.
    private static int FindObjectEnd(ReadOnlySpan<byte> json, int objectStart)
    {
        int depth = 1;
        int pos = objectStart + 1;

        while(pos < json.Length && depth > 0)
        {
            byte current = json[pos];
            if(current == (byte)'{')
            {
                depth++;
            }
            else if(current == (byte)'}')
            {
                depth--;
            }
            else if(current == (byte)'"')
            {
                pos++;
                while(pos < json.Length && json[pos] != (byte)'"')
                {
                    if(json[pos] == (byte)'\\')
                    {
                        pos++;
                    }

                    pos++;
                }
            }

            pos++;
        }

        return depth == 0 ? pos : -1;
    }


    private static bool IsArraySeparator(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or (byte)',';


    private static Dictionary<string, string> ExtractJwkStringMembers(ReadOnlySpan<byte> jwkObject)
    {
        List<string> names = JwkJsonReader.GetTopLevelKeyNames(jwkObject);
        Dictionary<string, string> members = new(names.Count, StringComparer.Ordinal);
        foreach(string name in names)
        {
            string? value = JwkJsonReader.ExtractStringValue(jwkObject, Encoding.UTF8.GetBytes(name));
            if(value is not null)
            {
                members[name] = value;
            }
        }

        return members;
    }
}
