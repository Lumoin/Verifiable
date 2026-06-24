using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// Factory methods for constructing <see cref="JwtPayload"/> instances populated
/// with well-known claim structures.
/// </summary>
/// <remarks>
/// <para>
/// Follows the same C# 14 extension syntax design as <see cref="JwtHeaderExtensions"/>.
/// Each factory produces a complete <see cref="JwtPayload"/> for a specific protocol
/// context, with all required and optional claims as named parameters.
/// </para>
/// <para>
/// Library users can define their own extension class and the methods appear alongside
/// these in IntelliSense:
/// </para>
/// <code>
/// public static class MyPayloadExtensions
/// {
///     extension(JwtPayload)
///     {
///         public static JwtPayload ForMyCredential(
///             string issuer,
///             DateTimeOffset issuedAt,
///             Dictionary&lt;string, object&gt; holderConfirmation,
///             string tenantId) => JwtPayload.ForSdJwtVcIssuance(
///                 issuer, "urn:my:credential:1", issuedAt, holderConfirmation,
///                 claims: new KeyValuePair&lt;string, object&gt;[]
///                 {
///                     new("tenant_id", tenantId)
///                 });
///     }
/// }
/// </code>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not yet up to date with extension syntax.")]
public static class JwtPayloadExtensions
{
    extension(JwtPayload)
    {
        /// <summary>
        /// Creates a payload for a general JWT issuance with standard
        /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1">RFC 7519 §4.1</see>
        /// registered claims and optional
        /// <see href="https://www.rfc-editor.org/rfc/rfc7800#section-3.1">RFC 7800 §3.1</see>
        /// holder key confirmation.
        /// </summary>
        /// <param name="issuer">
        /// The <c>iss</c> claim identifying the principal that issued the JWT.
        /// </param>
        /// <param name="issuedAt">
        /// The <c>iat</c> claim identifying the time at which the JWT was issued.
        /// Converted to Unix epoch seconds.
        /// </param>
        /// <param name="holderConfirmation">
        /// The holder's public key as a JWK dictionary for the <c>cnf</c> claim
        /// per RFC 7800. When provided, produces <c>{"cnf": {"jwk": ...}}</c>.
        /// Pass <see langword="null"/> for bearer tokens without holder binding.
        /// </param>
        /// <param name="subject">
        /// The <c>sub</c> claim identifying the principal that is the subject of the JWT.
        /// Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="expiresAt">
        /// The <c>exp</c> claim identifying the expiration time.
        /// Converted to Unix epoch seconds. Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="notBefore">
        /// The <c>nbf</c> claim identifying the time before which the JWT must not be accepted.
        /// Converted to Unix epoch seconds. Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="claims">
        /// Additional application-level claims to include in the payload.
        /// </param>
        /// <returns>A <see cref="JwtPayload"/> populated with the specified claims.</returns>
        public static JwtPayload ForIssuance(
            string issuer,
            DateTimeOffset issuedAt,
            Dictionary<string, object>? holderConfirmation = null,
            string? subject = null,
            DateTimeOffset? expiresAt = null,
            DateTimeOffset? notBefore = null,
            IEnumerable<KeyValuePair<string, object>>? claims = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(issuer);

            var payload = new JwtPayload
            {
                [WellKnownJwtClaimNames.Iss] = issuer,
                [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds()
            };

            if(subject is not null)
            {
                payload[WellKnownJwtClaimNames.Sub] = subject;
            }

            if(expiresAt.HasValue)
            {
                payload[WellKnownJwtClaimNames.Exp] = expiresAt.Value.ToUnixTimeSeconds();
            }

            if(notBefore.HasValue)
            {
                payload[WellKnownJwtClaimNames.Nbf] = notBefore.Value.ToUnixTimeSeconds();
            }

            if(holderConfirmation is not null)
            {
                payload[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>
                {
                    [WellKnownJoseHeaderNames.Jwk] = holderConfirmation
                };
            }

            if(claims is not null)
            {
                foreach(KeyValuePair<string, object> claim in claims)
                {
                    payload[claim.Key] = claim.Value;
                }
            }

            return payload;
        }


        /// <summary>
        /// Creates a payload for SD-JWT Verifiable Credential issuance per
        /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html">SD-JWT VC</see>,
        /// adding the required <c>vct</c> (Verifiable Credential Type) claim to the
        /// standard <see cref="ForIssuance"/> claims.
        /// </summary>
        /// <remarks>
        /// <para>
        /// SD-JWT VC requires both <c>iss</c> and <c>vct</c> as mandatory claims.
        /// Holder binding via <c>cnf</c> is required for credentials that will be
        /// presented with a Key Binding JWT.
        /// </para>
        /// </remarks>
        /// <param name="issuer">
        /// The <c>iss</c> claim identifying the credential issuer.
        /// </param>
        /// <param name="verifiableCredentialType">
        /// The <c>vct</c> claim identifying the credential type
        /// (e.g., <c>urn:eudi:pid:1</c>).
        /// </param>
        /// <param name="issuedAt">
        /// The <c>iat</c> claim. Converted to Unix epoch seconds.
        /// </param>
        /// <param name="holderConfirmation">
        /// The holder's public key as a JWK dictionary for the <c>cnf</c> claim.
        /// Required for credentials intended for OID4VP presentation with KB-JWT.
        /// </param>
        /// <param name="subject">
        /// The <c>sub</c> claim. Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="expiresAt">
        /// The <c>exp</c> claim. Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="notBefore">
        /// The <c>nbf</c> claim. Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="claims">
        /// Application-level claims (e.g., <c>given_name</c>, <c>family_name</c>).
        /// </param>
        /// <returns>A <see cref="JwtPayload"/> populated with all specified claims.</returns>
        public static JwtPayload ForSdJwtVcIssuance(
            string issuer,
            string verifiableCredentialType,
            DateTimeOffset issuedAt,
            Dictionary<string, object> holderConfirmation,
            string? subject = null,
            DateTimeOffset? expiresAt = null,
            DateTimeOffset? notBefore = null,
            IEnumerable<KeyValuePair<string, object>>? claims = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(verifiableCredentialType);
            ArgumentNullException.ThrowIfNull(holderConfirmation);

            JwtPayload payload = ForIssuance(
                issuer, issuedAt, holderConfirmation,
                subject, expiresAt, notBefore, claims);

            payload[WellKnownJwtClaimNames.Vct] = verifiableCredentialType;

            return payload;
        }


        /// <summary>
        /// Creates a payload for an OAuth 2.0 JWT access token per
        /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 §2.2</see>,
        /// populated with <c>sub</c>, <c>jti</c>, <c>scope</c>, <c>iat</c>, <c>exp</c>,
        /// and the optional <c>iss</c>, <c>aud</c>, and <c>client_id</c> claims.
        /// </summary>
        /// <remarks>
        /// <para>
        /// RFC 9068 §2.2 requires <c>iss</c>, <c>exp</c>, <c>aud</c>, <c>sub</c>,
        /// <c>client_id</c>, <c>iat</c>, and <c>jti</c>. The <c>iss</c>, <c>aud</c>, and
        /// <c>client_id</c> parameters are nullable here to support callers that construct
        /// tokens before the issuer or audience values are available; callers targeting
        /// strict RFC 9068 conformance must supply all three.
        /// </para>
        /// </remarks>
        /// <param name="subject">
        /// The <c>sub</c> claim identifying the principal that is the subject of the token.
        /// </param>
        /// <param name="jti">The <c>jti</c> claim — a unique identifier for this token.</param>
        /// <param name="scope">The <c>scope</c> claim carrying the granted scopes.</param>
        /// <param name="issuedAt">
        /// The <c>iat</c> claim. Converted to Unix epoch seconds.
        /// </param>
        /// <param name="expiresAt">
        /// The <c>exp</c> claim. Converted to Unix epoch seconds.
        /// </param>
        /// <param name="issuer">
        /// The <c>iss</c> claim identifying the authorization server. Required by RFC 9068.
        /// </param>
        /// <param name="audience">
        /// The <c>aud</c> claim identifying the intended resource server(s). Required
        /// by RFC 9068. The wire shape follows
        /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see>:
        /// <see langword="null"/> or empty omits the claim entirely; a single-element
        /// list is emitted as a JSON string; a multi-element list as a JSON array.
        /// </param>
        /// <param name="clientId">
        /// The <c>client_id</c> claim identifying the OAuth client that requested the token.
        /// Required by RFC 9068.
        /// </param>
        /// <param name="claims">
        /// Additional application-level claims (e.g., role claims, tenant identifier).
        /// </param>
        /// <returns>A <see cref="JwtPayload"/> populated with the specified claims.</returns>
        public static JwtPayload ForAccessToken(
            string subject,
            string jti,
            string scope,
            DateTimeOffset issuedAt,
            DateTimeOffset expiresAt,
            string? issuer = null,
            IReadOnlyList<string>? audience = null,
            string? clientId = null,
            IEnumerable<KeyValuePair<string, object>>? claims = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(subject);
            ArgumentException.ThrowIfNullOrWhiteSpace(jti);
            ArgumentNullException.ThrowIfNull(scope);

            var payload = new JwtPayload(capacity: 8)
            {
                [WellKnownJwtClaimNames.Sub] = subject,
                [WellKnownJwtClaimNames.Jti] = jti,
                [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
                [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds(),
                [WellKnownJwtClaimNames.Scope] = scope
            };

            if(issuer is not null)
            {
                payload[WellKnownJwtClaimNames.Iss] = issuer;
            }

            //RFC 7519 §4.1.3 permits aud as either a single string or an array of
            //strings. Emit single-element lists as a string for compatibility with
            //RPs that only handle the string form; multi-element lists go on the
            //wire as an array.
            if(audience is not null && audience.Count > 0)
            {
                payload[WellKnownJwtClaimNames.Aud] = audience.Count == 1
                    ? audience[0]
                    : audience;
            }

            if(clientId is not null)
            {
                payload[WellKnownJwtClaimNames.ClientId] = clientId;
            }

            if(claims is not null)
            {
                foreach(KeyValuePair<string, object> claim in claims)
                {
                    payload[claim.Key] = claim.Value;
                }
            }

            return payload;
        }


        /// <summary>
        /// Creates a payload for an OpenID Connect ID Token per
        /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>,
        /// populated with <c>iss</c>, <c>sub</c>, <c>aud</c>, <c>exp</c>, <c>iat</c>,
        /// and the optional <c>auth_time</c>, <c>nonce</c>, <c>acr</c>, <c>amr</c>,
        /// and <c>azp</c> claims.
        /// </summary>
        /// <remarks>
        /// <para>
        /// OIDC Core §2 requires <c>iss</c>, <c>sub</c>, <c>aud</c>, <c>exp</c>, and
        /// <c>iat</c>. The <c>auth_time</c> claim is required when a <c>max_age</c>
        /// request was made or when the <c>auth_time</c> claim was requested specifically.
        /// The <c>nonce</c> claim is required when a <c>nonce</c> value was sent in the
        /// authentication request and must equal the request value.
        /// The <c>azp</c> (authorized party) claim is required when the ID Token has a
        /// single audience value and that audience differs from the authorized party.
        /// </para>
        /// </remarks>
        /// <param name="issuer">
        /// The <c>iss</c> claim identifying the authorization server.
        /// </param>
        /// <param name="subject">
        /// The <c>sub</c> claim identifying the End-User.
        /// </param>
        /// <param name="audience">
        /// The <c>aud</c> claim. Typically the OAuth Client ID for whom the ID Token is intended.
        /// </param>
        /// <param name="issuedAt">
        /// The <c>iat</c> claim. Converted to Unix epoch seconds.
        /// </param>
        /// <param name="expiresAt">
        /// The <c>exp</c> claim. Converted to Unix epoch seconds.
        /// </param>
        /// <param name="authTime">
        /// The <c>auth_time</c> claim — the time when the End-User authentication occurred.
        /// Converted to Unix epoch seconds. Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="nonce">
        /// The <c>nonce</c> claim — must equal the value sent in the authentication request.
        /// Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="acr">
        /// The <c>acr</c> (Authentication Context Class Reference) claim.
        /// Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="amr">
        /// The <c>amr</c> (Authentication Methods References) claim.
        /// Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="azp">
        /// The <c>azp</c> (Authorized Party) claim — required when the ID Token has a single
        /// audience that differs from the authorized party.
        /// Omitted when <see langword="null"/>.
        /// </param>
        /// <param name="claims">
        /// Additional application-level claims (e.g., <c>name</c>, <c>email</c>, custom claims).
        /// </param>
        /// <returns>A <see cref="JwtPayload"/> populated with the specified claims.</returns>
        public static JwtPayload ForIdToken(
            string issuer,
            string subject,
            string audience,
            DateTimeOffset issuedAt,
            DateTimeOffset expiresAt,
            DateTimeOffset? authTime = null,
            string? nonce = null,
            string? acr = null,
            IReadOnlyList<string>? amr = null,
            string? azp = null,
            IEnumerable<KeyValuePair<string, object>>? claims = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
            ArgumentException.ThrowIfNullOrWhiteSpace(subject);
            ArgumentException.ThrowIfNullOrWhiteSpace(audience);

            var payload = new JwtPayload(capacity: 10)
            {
                [WellKnownJwtClaimNames.Iss] = issuer,
                [WellKnownJwtClaimNames.Sub] = subject,
                [WellKnownJwtClaimNames.Aud] = audience,
                [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
                [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds()
            };

            if(authTime.HasValue)
            {
                payload[WellKnownJwtClaimNames.AuthTime] = authTime.Value.ToUnixTimeSeconds();
            }

            if(nonce is not null)
            {
                payload[WellKnownJwtClaimNames.Nonce] = nonce;
            }

            if(acr is not null)
            {
                payload[WellKnownJwtClaimNames.Acr] = acr;
            }

            if(amr is not null)
            {
                payload[WellKnownJwtClaimNames.Amr] = amr;
            }

            if(azp is not null)
            {
                payload[WellKnownJwtClaimNames.Azp] = azp;
            }

            if(claims is not null)
            {
                foreach(KeyValuePair<string, object> claim in claims)
                {
                    payload[claim.Key] = claim.Value;
                }
            }

            return payload;
        }


        /// <summary>
        /// Creates a payload for an Identity Assertion JWT Authorization Grant (ID-JAG) per
        /// draft-ietf-oauth-identity-assertion-authz-grant §3.1, populated with the REQUIRED
        /// <c>iss</c>, <c>sub</c>, <c>aud</c>, <c>client_id</c>, <c>jti</c>, <c>iat</c>, and
        /// <c>exp</c> claims, plus the optional <c>scope</c> and any additional claims.
        /// </summary>
        /// <remarks>
        /// <para>
        /// §3.1: <c>iss</c> is the IdP Authorization Server issuer identifier; <c>aud</c> is the
        /// issuer identifier of the Resource Authorization Server the grant is intended for;
        /// <c>client_id</c> is the client identifier at the Resource Authorization Server that
        /// will act on behalf of the subject (it MAY differ from the client that requested the
        /// ID-JAG from the IdP). The grant is consumed by the Resource Authorization Server as a
        /// JWT bearer assertion (§4.4).
        /// </para>
        /// <para>
        /// Optional authorization (<c>resource</c>, <c>authorization_details</c>) and tenancy
        /// (<c>tenant</c>, <c>aud_tenant</c>, <c>aud_sub</c>), DPoP (<c>cnf</c>), and identity
        /// (<c>sub_id</c>, <c>auth_time</c>, <c>acr</c>, <c>amr</c>, <c>email</c>) claims are
        /// carried through <paramref name="claims"/>.
        /// </para>
        /// </remarks>
        /// <param name="issuer">The <c>iss</c> claim — the IdP Authorization Server issuer identifier.</param>
        /// <param name="subject">The <c>sub</c> claim — the End-User in the issuer's subject namespace.</param>
        /// <param name="audience">The <c>aud</c> claim — the Resource Authorization Server issuer identifier.</param>
        /// <param name="clientId">The <c>client_id</c> claim — the client at the Resource Authorization Server.</param>
        /// <param name="jti">The <c>jti</c> claim — a unique identifier for this grant.</param>
        /// <param name="issuedAt">The <c>iat</c> claim. Converted to Unix epoch seconds.</param>
        /// <param name="expiresAt">The <c>exp</c> claim. Converted to Unix epoch seconds.</param>
        /// <param name="scope">The optional <c>scope</c> claim — a space-separated scope list. Omitted when null or empty.</param>
        /// <param name="claims">Additional ID-JAG claims (e.g. <c>resource</c>, <c>authorization_details</c>, <c>tenant</c>, <c>cnf</c>).</param>
        /// <returns>A <see cref="JwtPayload"/> populated with the ID-JAG claims.</returns>
        public static JwtPayload ForIdJag(
            string issuer,
            string subject,
            string audience,
            string clientId,
            string jti,
            DateTimeOffset issuedAt,
            DateTimeOffset expiresAt,
            string? scope = null,
            IEnumerable<KeyValuePair<string, object>>? claims = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
            ArgumentException.ThrowIfNullOrWhiteSpace(subject);
            ArgumentException.ThrowIfNullOrWhiteSpace(audience);
            ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
            ArgumentException.ThrowIfNullOrWhiteSpace(jti);

            var payload = new JwtPayload(capacity: 8)
            {
                [WellKnownJwtClaimNames.Iss] = issuer,
                [WellKnownJwtClaimNames.Sub] = subject,
                [WellKnownJwtClaimNames.Aud] = audience,
                [WellKnownJwtClaimNames.ClientId] = clientId,
                [WellKnownJwtClaimNames.Jti] = jti,
                [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
                [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds()
            };

            if(!string.IsNullOrEmpty(scope))
            {
                payload[WellKnownJwtClaimNames.Scope] = scope;
            }

            if(claims is not null)
            {
                foreach(KeyValuePair<string, object> claim in claims)
                {
                    payload[claim.Key] = claim.Value;
                }
            }

            return payload;
        }
    }
}
