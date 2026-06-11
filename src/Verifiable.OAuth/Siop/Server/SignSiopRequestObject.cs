using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// The effectful action produced by the SIOPv2 request-object endpoint: sign the §9 Request Object
/// the Relying Party serves at its <c>request_uri</c>, the by-reference parallel of the OID4VP JAR.
/// Run by the registered handler on the <see cref="OAuthActionExecutor"/> — signing is an EFFECT, so
/// it lives in the action handler rather than in the pure PDA transition or the endpoint's
/// <c>BuildInputAsync</c>, the same discipline the OID4VP <c>SignJarAction</c> follows.
/// </summary>
/// <remarks>
/// Carries exactly the per-flow values the handler needs to compose and sign the Request Object.
/// Per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-9">SIOPv2 §9</see>
/// the request carries <c>response_type=id_token</c>, the RP's <c>client_id</c>, the transaction
/// <c>nonce</c>, the <c>redirect_uri</c> the Self-Issued OP returns the response to, and the
/// <c>state</c> handle the Wallet echoes. The <c>aud</c> is resolved per §9.1 — see
/// <paramref name="Audience"/>. The JWT timing claims (<c>iat</c>, <c>nbf</c>, <c>exp</c>) are
/// stamped by the handler from the active request instant and
/// <see cref="Verifiable.OAuth.Server.TimingPolicy.Oid4VpRequestObjectLifetime"/>.
/// </remarks>
/// <param name="RequestHandle">
/// The opaque per-flow token. The handler writes it as the Request Object's <c>state</c> claim per
/// RFC 6749 §4.1.1; the Wallet echoes the value as the <c>state</c> form field on its Self-Issued ID
/// Token response, and the application's
/// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration.ResolveCorrelationKeyAsync"/>
/// maps it back to the internal flow identifier.
/// </param>
/// <param name="ClientId">The RP's <c>client_id</c> the Request Object asserts (also the ID Token's required <c>aud</c>).</param>
/// <param name="Nonce">The transaction <c>nonce</c> the ID Token MUST echo (§9 REQUIRED).</param>
/// <param name="RedirectUri">The <c>redirect_uri</c> the Self-Issued OP delivers the Authorization Response to.</param>
/// <param name="Audience">
/// The §9.1 Request Object <c>aud</c>: <c>https://self-issued.me/v2</c> under Static Self-Issued OP
/// Discovery, else the dynamically discovered issuer. Decided by the endpoint from
/// <see cref="States.SiopRequestPreparedState.UseStaticDiscoveryAudience"/> and the resolved issuer.
/// </param>
/// <param name="SigningKeyId">
/// The identifier of the signing key. The handler resolves this to live key material via
/// <see cref="Verifiable.OAuth.Server.AuthorizationServerCryptography.SigningKeyResolver"/>.
/// </param>
/// <param name="IdTokenType">The requested <c>id_token_type</c> (§7), when constrained.</param>
/// <param name="AllowedAlgorithms">The signing algorithms the RP accepts for the Self-Issued ID Token, threaded onto the served state.</param>
/// <param name="AdditionalHeaderClaims">
/// Optional additional JOSE header claims the handler merges into the §9 Request Object's signed
/// header alongside <c>alg</c> and <c>typ</c>. Used to inject the client-id-prefix material the
/// wallet resolves the RP signing key from — the <c>x5c</c> certificate chain for
/// <c>x509_san_dns:</c>, the <c>trust_chain</c> array for <c>openid_federation:</c>, the
/// verifier-attestation <c>jwt</c>, or the <c>kid</c> verification-method DID URL for
/// <c>decentralized_identifier:</c>. The SIOPv2 §9 Request Object and the OID4VP JAR are the same
/// RFC 9101 <c>oauth-authz-req+jwt</c> artifact, so this mirrors the OID4VP
/// <see cref="Verifiable.OAuth.Oid4Vp.Server.SignJarAction.AdditionalHeaderClaims"/>. The handler
/// never lets these entries overwrite the library-owned <c>alg</c> or <c>typ</c>.
/// <see langword="null"/> on the bespoke direct-key path, which leaves the header at <c>alg</c>+<c>typ</c>.
/// </param>
public sealed record SignSiopRequestObject(
    string RequestHandle,
    string ClientId,
    string Nonce,
    Uri RedirectUri,
    string Audience,
    KeyId SigningKeyId,
    string? IdTokenType,
    IReadOnlyList<string> AllowedAlgorithms,
    JwtHeader? AdditionalHeaderClaims = null): OAuthAction;
