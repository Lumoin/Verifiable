using System.Diagnostics;

using Verifiable.Core;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Per-token-endpoint-call refined view, constructed from
/// <see cref="ExchangeContext"/> + the loaded
/// <see cref="OAuthFlowState"/> + resolved values. Lives only during the
/// token producer / claim contributor walk.
/// </summary>
/// <remarks>
/// <para>
/// One of three stage-specific refined views in the pipeline. Each
/// per-request context shape's lifetime maps to a stage of request
/// processing: <see cref="ExchangeContext"/> covers the whole request and
/// holds the resolved policy via
/// <see cref="Server.PolicyExchangeContextExtensions"/>;
/// <see cref="IssuanceContext"/> exists only during the token producer /
/// claim contributor walk;
/// <see cref="Verifiable.OAuth.Validation.ValidationContext"/> exists only
/// during a validation-check run.
/// </para>
/// <para>
/// Each producer reads the inputs it needs and runs its own two-step key
/// resolution inside its <see cref="TokenProducer.BuildAsync"/> body using
/// the <see cref="Verifiable.Cryptography.Context.KeyUsageContext"/>
/// appropriate for the token type. The typed-record shape (required fields
/// where appropriate) is deliberate: <see cref="Subject"/> and
/// <see cref="ClientId"/> are guaranteed present at any token-issuance walk,
/// not just present "if populated".
/// </para>
/// <para>
/// The context carries the spec-required inputs every token type needs
/// (subject, issuer, client identifier, request times) plus the OIDC-specific
/// signals (nonce, auth_time) that producers consume conditionally. It does
/// not carry resolved key material or pre-resolved <c>KeyId</c>s.
/// </para>
/// <para>
/// Time values use a single <see cref="IssuedAt"/> instant captured at the start of
/// the request so that <c>iat</c> and other timestamps remain consistent across the
/// access token, ID token, and any other tokens emitted by the same request.
/// </para>
/// <para>
/// Per-token expiry is derived inside each producer from
/// <see cref="ClientRecord.GetTokenLifetime"/> using the producer's own token
/// type constant — different token types have different lifetimes.
/// </para>
/// </remarks>
[DebuggerDisplay("IssuanceContext Subject={Subject} Client={ClientId} Issuer={IssuerUri}")]
public sealed record IssuanceContext
{
    /// <summary>
    /// The client registration the request belongs to.
    /// </summary>
    public required ClientRecord Registration { get; init; }

    /// <summary>
    /// The per-request context bag. Producers and contributors may read it for
    /// tenant identifiers, caller signals, or any other request-scoped state the
    /// ASP.NET skin surfaced.
    /// </summary>
    public required ExchangeContext Context { get; init; }

    /// <summary>
    /// The Authorization Server's resolved issuer URI for this request. Already
    /// flowed through <see cref="AuthorizationServerIntegration.ResolveIssuerAsync"/>
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

    /// <summary>
    /// The Authentication Context Class Reference (<c>acr</c>) established for the
    /// End-User's authentication at authorize time and carried through the flow
    /// state. Emitted into the access token's <c>acr</c> claim per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2.1">RFC 9068 §2.2.1</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc9470#section-5">RFC 9470 §5</see>
    /// (step-up authentication) so the Resource Server can read the authentication
    /// strength actually achieved. <see langword="null"/> when the deployment stamps
    /// no <c>acr</c> (no step-up / authentication-context tracking for this request).
    /// </summary>
    public string? Acr { get; init; }

    /// <summary>
    /// The RFC 7800 confirmation method established at the token endpoint —
    /// for example the DPoP <c>jkt</c> thumbprint when the request carried a
    /// validated DPoP proof. Token producers consume the populated members to
    /// emit the <c>cnf</c> claim in their payload. <see langword="null"/> or
    /// an empty <see cref="ConfirmationMethod"/> means the token is not
    /// sender-constrained and no <c>cnf</c> claim is emitted.
    /// </summary>
    public ConfirmationMethod? Confirmation { get; init; }

    /// <summary>
    /// The End-User's authentication session identifier (<c>sid</c>) established at
    /// authorize time and carried through the flow state. Emitted as the ID Token's
    /// <c>sid</c> claim when present per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html">OIDC Core</see>;
    /// <see langword="null"/> for tokens not bound to a session-scoped identifier.
    /// </summary>
    public string? SessionId { get; init; }
}
