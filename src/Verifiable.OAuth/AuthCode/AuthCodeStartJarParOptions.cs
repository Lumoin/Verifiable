using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Per-call inputs for
/// <see cref="AuthCodeClient.StartJarParAsync(Verifiable.OAuth.Client.ClientRegistration, AuthCodeStartJarParOptions, System.Threading.CancellationToken)"/> — the JAR-bearing Pushed
/// Authorization Request flow per RFC 9101 §5 + RFC 9126 §3. The client signs a
/// JAR carrying the AuthCode-specific claims (PKCE challenge, redirect URI,
/// scope, state, nonce), POSTs it to the PAR endpoint with an outer
/// <c>client_id</c> + <c>request</c> body, and persists the PKCE verifier for
/// the eventual token exchange.
/// </summary>
public sealed record AuthCodeStartJarParOptions
{
    /// <summary>
    /// The space-separated scope string (RFC 6749 §3.3) carried into the JAR's <c>scope</c> claim. A
    /// blank string names no scope, and the request object then carries no <c>scope</c> claim
    /// (RFC 6749 §3.1: "Parameters sent without a value MUST be treated as if they were omitted from
    /// the request."). An OpenID Connect request names <c>openid</c> here itself (OpenID Connect Core
    /// 1.0 §3.1.2.1).
    /// </summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>
    /// <c>resource</c> indicators the request names, each one absolute URI given as its own entry, or
    /// <see langword="null"/> to name none. The request object carries them as its <c>resource</c>
    /// claim (RFC 8707 §2.1: "a single "resource" parameter value is represented as a JSON string
    /// while multiple values are represented as an array of strings"), and the flow state keeps them
    /// so that the code redemption names them as well (the MCP authorization specification: "MUST be
    /// included in both authorization requests and token requests"). The canonical form of each URI
    /// is the caller's to give; the entries travel as given. An entry holding any white-space
    /// character is refused with <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> and
    /// <c>invalid_request</c> before anything is signed, sent or stored.
    /// </summary>
    public IReadOnlyList<string>? Resource { get; init; }

    /// <summary>The client's JAR signing key. Tag determines the JWS <c>alg</c>.</summary>
    public required PrivateKeyMemory SigningKey { get; init; }

    /// <summary>The <c>kid</c> header parameter value identifying <see cref="SigningKey"/>.</summary>
    public required string SigningKeyId { get; init; }

    /// <summary>
    /// The redirect URI to put in the JAR's <c>redirect_uri</c> claim. Per
    /// RFC 6749 §3.1.2.3 the client picks one of the AS's allow-listed URIs
    /// at request time; the library does not validate against
    /// <see cref="ClientRegistration.RedirectUris"/> — that is the AS's
    /// responsibility.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>Serialises the JAR protected header to UTF-8 JSON bytes.</summary>
    public required JwtHeaderSerializer HeaderSerializer { get; init; }

    /// <summary>Serialises the JAR payload claims to UTF-8 JSON bytes.</summary>
    public required JwtPayloadSerializer PayloadSerializer { get; init; }

    /// <summary>Memory pool for transient signing buffers.</summary>
    public required BaseMemoryPool MemoryPool { get; init; }

    /// <summary>
    /// Open-ended additional outer body fields for the POST to the PAR endpoint
    /// (vendor extensions, profile-specific parameters). The outer
    /// <c>client_id</c> (RFC 9101 §5) and <c>request</c> field are added
    /// automatically; callers do not include them here. A field under a name the start composes
    /// (<c>client_id</c>, <c>response_type</c>, <c>redirect_uri</c>, <c>scope</c>, <c>state</c>,
    /// <c>code_challenge</c>, <c>code_challenge_method</c>, <c>resource</c>, <c>dpop_jkt</c>, <c>request_uri</c>,
    /// <c>request</c>) is dropped
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-3">RFC 9126 Section 3</see>: "All other request
    /// parameters, i.e., those pertaining to the authorization request itself, MUST appear as claims of the JWT
    /// representing the authorization request.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 Section 5</see>: "If this parameter is
    /// present in the authorization request, "request_uri" MUST NOT be present.").
    /// </summary>
    public OAuthFormEncodedFields AdditionalFields { get; init; } = OAuthFormEncodedFields.Empty;

    /// <summary>
    /// Optional <c>nonce</c> claim value. When <see langword="null"/>, the
    /// handler generates one.
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// The JAR's lifetime: the <c>exp</c> claim is the <c>iat</c> plus this value. Defaults to thirty seconds, the
    /// library's own value.
    /// </summary>
    /// <remarks>
    /// The library writes the request object's <c>iat</c> and <c>exp</c> as whole-second NumericDates, so the value
    /// is at least one and at most <see cref="int.MaxValue"/> whole seconds, the library's own rule: the <c>init</c>
    /// accessor refuses any other value with <see cref="ArgumentOutOfRangeException"/> and holds an issuable value as
    /// its whole seconds.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The value's whole seconds are under one or above <see cref="int.MaxValue"/>.
    /// </exception>
    public TimeSpan JarLifetime
    {
        get;
        init => field = TokenLifetimes.RequireIssuable(value, nameof(JarLifetime));
    } = TimeSpan.FromSeconds(30);
}
