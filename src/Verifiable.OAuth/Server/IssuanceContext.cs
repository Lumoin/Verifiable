using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The immutable inputs available to a <see cref="TokenProducer"/> and to each
/// <see cref="ClaimContributor"/> at a token-endpoint request. Constructed once per
/// request from the loaded flow state and request context, then handed to every
/// producer and contributor.
/// </summary>
/// <remarks>
/// <para>
/// The context carries the spec-required inputs that every token type needs (subject,
/// issuer, client identifier, request times) plus the OIDC-specific signals (nonce,
/// auth_time) that producers consume conditionally. It does not carry resolved key
/// material or pre-resolved <c>KeyId</c>s — each producer performs its own two-step
/// key resolution inside its <see cref="TokenProducer.BuildAsync"/> body using the
/// <see cref="Verifiable.Cryptography.Context.KeyUsageContext"/> appropriate for the
/// token type it produces.
/// </para>
/// <para>
/// Time values use a single <see cref="IssuedAt"/> instant captured at the start of
/// the request so that <c>iat</c> and other timestamps remain consistent across the
/// access token, ID token, and any other tokens emitted by the same request.
/// </para>
/// <para>
/// Per-token expiry is derived inside each producer from
/// <see cref="ClientRegistration.GetTokenLifetime"/> using the producer's own token
/// type constant — different token types have different lifetimes.
/// </para>
/// </remarks>
[DebuggerDisplay("IssuanceContext Subject={Subject} Client={ClientId} Issuer={IssuerUri}")]
public sealed record IssuanceContext
{
    /// <summary>
    /// The client registration the request belongs to.
    /// </summary>
    public required ClientRegistration Registration { get; init; }

    /// <summary>
    /// The per-request context bag. Producers and contributors may read it for
    /// tenant identifiers, caller signals, or any other request-scoped state the
    /// ASP.NET skin surfaced.
    /// </summary>
    public required RequestContext Context { get; init; }

    /// <summary>
    /// The Authorization Server's resolved issuer URI for this request. Already
    /// flowed through <see cref="AuthorizationServerOptions.ResolveIssuerAsync"/>
    /// once before the producer walk begins; producers consume the resolved value.
    /// </summary>
    public required Uri IssuerUri { get; init; }

    /// <summary>
    /// The authenticated subject identifier. Becomes the <c>sub</c> claim on every
    /// token produced for the request.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The granted scope string. Producers may apply spec-specific scope semantics
    /// — for example, the OIDC ID Token producer's <see cref="TokenProducer.IsApplicable"/>
    /// checks whether <c>openid</c> is in this scope.
    /// </summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The OAuth client identifier. Becomes the <c>client_id</c> claim on access
    /// tokens and the <c>aud</c> claim on ID tokens.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The instant the request started processing. Used for <c>iat</c> claims on
    /// every token in this response and as the base for per-token <c>exp</c> values.
    /// </summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>
    /// The <c>nonce</c> value carried in the original authorization request, when
    /// present. Required on ID Tokens per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>
    /// when the request carried a <c>nonce</c>; ignored by access-token producers.
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// The instant at which the End-User authenticated. Bound into the ID Token's
    /// <c>auth_time</c> claim per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>
    /// when present.
    /// </summary>
    public DateTimeOffset? AuthTime { get; init; }
}
