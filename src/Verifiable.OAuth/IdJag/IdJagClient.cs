using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// Per-call inputs for <see cref="IdJagClient.MintAsync(ClientRegistration, IdJagMintOptions, CancellationToken)"/>
/// — the client side of the ID-JAG mint (a Token Exchange requesting <c>requested_token_type</c> id-jag,
/// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.3). The client authenticates as a confidential
/// client (§9.1) with a <c>private_key_jwt</c> assertion signed from <see cref="SigningKey"/>.
/// </summary>
[DebuggerDisplay("IdJagMintOptions Audience={Audience}, SubjectTokenType={SubjectTokenType}")]
public sealed record IdJagMintOptions
{
    /// <summary>The Resource Authorization Server identifier the ID-JAG is minted for (§4.3 <c>audience</c>, REQUIRED).</summary>
    public required string Audience { get; init; }

    /// <summary>The Identity Assertion or Refresh Token presented as the <c>subject_token</c> (§4.3, REQUIRED).</summary>
    public required string SubjectToken { get; init; }

    /// <summary>The type of <see cref="SubjectToken"/> (<c>subject_token_type</c>, §4.3) — for example <see cref="TokenType.IdToken"/>, <see cref="TokenType.Saml2"/>, or <see cref="TokenType.RefreshToken"/>.</summary>
    public required TokenType SubjectTokenType { get; init; }

    /// <summary>The client's signing key for the <c>private_key_jwt</c> client assertion. Its <see cref="Tag"/> determines the JWS <c>alg</c>.</summary>
    public required PrivateKeyMemory SigningKey { get; init; }

    /// <summary>The <c>kid</c> header value identifying <see cref="SigningKey"/> to the authorization server.</summary>
    public required string SigningKeyId { get; init; }

    /// <summary>Serialises the client-assertion protected header to UTF-8 JSON bytes.</summary>
    public required JwtHeaderSerializer HeaderSerializer { get; init; }

    /// <summary>Serialises the client-assertion payload claims to UTF-8 JSON bytes.</summary>
    public required JwtPayloadSerializer PayloadSerializer { get; init; }

    /// <summary>The requested Resource Identifier(s) (RFC 8707 / §4.3 <c>resource</c>). MAY be empty.</summary>
    public IReadOnlyList<string> Resource { get; init; } = [];

    /// <summary>The requested scope (§4.3 <c>scope</c>), or <see langword="null"/>.</summary>
    public string? Scope { get; init; }

    /// <summary>The requested RFC 9396 <c>authorization_details</c> as a JSON array string (§4.3.3), or <see langword="null"/>.</summary>
    public string? AuthorizationDetails { get; init; }

    /// <summary>The validity window of the signed client assertion (RFC 7523 §3). Defaults to one minute.</summary>
    public TimeSpan ClientAssertionLifetime { get; init; } = TimeSpan.FromMinutes(1);
}


/// <summary>
/// Per-call inputs for <see cref="IdJagClient.RedeemAsync(ClientRegistration, IdJagRedeemOptions, CancellationToken)"/>
/// — the client side of the ID-JAG redeem (a JWT Bearer grant presenting the ID-JAG as the assertion,
/// draft-ietf-oauth-identity-assertion-authz-grant-04 §4.4). The client authenticates as a confidential
/// client (§9.1) with a <c>private_key_jwt</c> assertion signed from <see cref="SigningKey"/>.
/// </summary>
[DebuggerDisplay("IdJagRedeemOptions")]
public sealed record IdJagRedeemOptions
{
    /// <summary>The ID-JAG obtained from the mint, presented as the §4.4 <c>assertion</c> (REQUIRED).</summary>
    public required string Assertion { get; init; }

    /// <summary>The client's signing key for the <c>private_key_jwt</c> client assertion. Its <see cref="Tag"/> determines the JWS <c>alg</c>.</summary>
    public required PrivateKeyMemory SigningKey { get; init; }

    /// <summary>The <c>kid</c> header value identifying <see cref="SigningKey"/> to the authorization server.</summary>
    public required string SigningKeyId { get; init; }

    /// <summary>Serialises the client-assertion protected header to UTF-8 JSON bytes.</summary>
    public required JwtHeaderSerializer HeaderSerializer { get; init; }

    /// <summary>Serialises the client-assertion payload claims to UTF-8 JSON bytes.</summary>
    public required JwtPayloadSerializer PayloadSerializer { get; init; }

    /// <summary>The validity window of the signed client assertion (RFC 7523 §3). Defaults to one minute.</summary>
    public TimeSpan ClientAssertionLifetime { get; init; } = TimeSpan.FromMinutes(1);
}


/// <summary>
/// The ID-JAG sub-client of <see cref="OAuthClient"/> — the client side of the Cross-App Access two-leg
/// profile (draft-ietf-oauth-identity-assertion-authz-grant-04): <see cref="MintAsync(ClientRegistration, IdJagMintOptions, CancellationToken)"/>
/// obtains an ID-JAG from the IdP via Token Exchange (§4.3); <see cref="RedeemAsync(ClientRegistration, IdJagRedeemOptions, CancellationToken)"/>
/// redeems it at the Resource Authorization Server via the JWT Bearer grant (§4.4). Both authenticate the
/// confidential client (§9.1) with a <c>private_key_jwt</c> assertion.
/// </summary>
/// <remarks>
/// Constructed via the <see cref="IdJagClientExtensions">OAuthClient.IdJag</see> extension property. The
/// struct is cheap (one reference field) and carries no per-AS state — each method takes a
/// <see cref="ClientRegistration"/> describing which authorization server the call targets.
/// </remarks>
[DebuggerDisplay("IdJagClient")]
[SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "IdJagClient is a service-shaped wrapper around a single reference; value equality would compare reference identity of the underlying infrastructure, which is not a meaningful operation for callers.")]
public readonly struct IdJagClient
{
    /// <summary>The long-lived infrastructure this client reads delegates from.</summary>
    public OAuthClientInfrastructure Infrastructure { get; }


    /// <summary>
    /// Creates a new ID-JAG client over the supplied infrastructure. Internal — use
    /// <see cref="IdJagClientExtensions">OAuthClient.IdJag</see> to access an instance.
    /// </summary>
    internal IdJagClient(OAuthClientInfrastructure infrastructure)
    {
        ArgumentNullException.ThrowIfNull(infrastructure);

        Infrastructure = infrastructure;
    }


    /// <summary>
    /// Mints an ID-JAG via Token Exchange at the IdP's token endpoint (§4.3). The returned token response
    /// carries the ID-JAG in its <see cref="TokenResponse.AccessToken"/> (<c>token_type</c> N_A, §4.3.4).
    /// </summary>
    /// <param name="registration">The registration identifying the IdP authorization server.</param>
    /// <param name="options">The mint inputs (subject token, audience, client signing material).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<Result<TokenResponse, OAuthParseError>> MintAsync(
        ClientRegistration registration,
        IdJagMintOptions options,
        CancellationToken cancellationToken) =>
        MintAsync(registration, options, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="MintAsync(ClientRegistration, IdJagMintOptions, CancellationToken)"/>
    /// <param name="context">The per-operation exchange context threaded into the transport delegates.</param>
    public ValueTask<Result<TokenResponse, OAuthParseError>> MintAsync(
        ClientRegistration registration,
        IdJagMintOptions options,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(context);

        return IdJagFlowHandlers.MintAsync(options, Infrastructure, registration, context, cancellationToken);
    }


    /// <summary>
    /// Redeems an ID-JAG via the JWT Bearer grant at the Resource Authorization Server's token endpoint
    /// (§4.4). The returned token response carries the issued access token.
    /// </summary>
    /// <param name="registration">The registration identifying the Resource Authorization Server.</param>
    /// <param name="options">The redeem inputs (the ID-JAG assertion, client signing material).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public ValueTask<Result<TokenResponse, OAuthParseError>> RedeemAsync(
        ClientRegistration registration,
        IdJagRedeemOptions options,
        CancellationToken cancellationToken) =>
        RedeemAsync(registration, options, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="RedeemAsync(ClientRegistration, IdJagRedeemOptions, CancellationToken)"/>
    /// <param name="context">The per-operation exchange context threaded into the transport delegates.</param>
    public ValueTask<Result<TokenResponse, OAuthParseError>> RedeemAsync(
        ClientRegistration registration,
        IdJagRedeemOptions options,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(context);

        return IdJagFlowHandlers.RedeemAsync(options, Infrastructure, registration, context, cancellationToken);
    }
}
