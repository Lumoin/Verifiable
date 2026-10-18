using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// Per-call inputs for <see cref="IdJagClient.MintAsync(ClientRegistration, IdJagMintOptions, CancellationToken)"/>
/// — the client side of the ID-JAG mint (a Token Exchange requesting <c>requested_token_type</c> id-jag,
/// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.3). The client authenticates as a confidential
/// client (§9.1) by the method its registration names: the client assertion of <c>private_key_jwt</c> or
/// <c>client_secret_jwt</c> (RFC 7523 §2.2), composed under the key or the secret the registration carries and the inputs
/// <see cref="ClientAssertion"/> names, or the client secret of <c>client_secret_basic</c> or <c>client_secret_post</c>
/// (RFC 6749 §2.3.1), which the registration the caller composes for the one call carries and the library reads for that
/// call alone.
/// </summary>
[DebuggerDisplay("IdJagMintOptions Audience={Audience}, SubjectTokenType={SubjectTokenType}")]
public sealed record IdJagMintOptions
{
    /// <summary>
    /// The Resource Authorization Server identifier the ID-JAG is minted for (§4.3 <c>audience</c>), or <see langword="null"/>
    /// to send no <c>audience</c>: RFC 8693 §2.1 makes the parameter OPTIONAL in a token exchange, and an identity provider
    /// that takes the audience from its own mapping of the requested <c>resource</c> is sent none. Draft-04 §4.3 marks it
    /// REQUIRED, so a caller omits it only toward such a provider and holds the grant it answers to the Resource
    /// Authorization Server's issuer all the same (<see cref="IdJagGrantHolding"/>).
    /// </summary>
    public required string? Audience { get; init; }

    /// <summary>The Identity Assertion or Refresh Token presented as the <c>subject_token</c> (§4.3, REQUIRED).</summary>
    public required string SubjectToken { get; init; }

    /// <summary>The type of <see cref="SubjectToken"/> (<c>subject_token_type</c>, §4.3) — for example <see cref="TokenType.IdToken"/>, <see cref="TokenType.Saml2"/>, or <see cref="TokenType.RefreshToken"/>.</summary>
    public required TokenType SubjectTokenType { get; init; }

    /// <summary>
    /// The client assertion's inputs (RFC 7523 §2.2) for a registration naming <c>private_key_jwt</c> or
    /// <c>client_secret_jwt</c>: the <c>kid</c> of a <c>private_key_jwt</c> key or the HMAC algorithm of a
    /// <c>client_secret_jwt</c> secret, the serialisers and the assertion's validity window. The key or the secret itself is
    /// the registration's <see cref="ClientRegistration.AuthenticationKeyMaterial"/>, under the method the registration names
    /// (<see cref="ClientAssertionCredential.Of"/>). <see langword="null"/> for a registration naming
    /// <c>client_secret_basic</c> or <c>client_secret_post</c>, which presents no assertion; an assertion method handed none
    /// is refused before anything is sent (<see cref="OAuthClientAuthenticationRefused"/>).
    /// </summary>
    public required ClientAssertionOptions? ClientAssertion { get; init; }

    /// <summary>The requested Resource Identifier(s) (RFC 8707 / §4.3 <c>resource</c>). MAY be empty. The entries are sent as given and unchecked; the application decides whether an entry is acceptable.</summary>
    public IReadOnlyList<string> Resource { get; init; } = [];

    /// <summary>
    /// The requested scope (section 4.3 <c>scope</c>), or <see langword="null"/>. An empty value, or
    /// a value of white space only, white space being every character
    /// <see cref="char.IsWhiteSpace(char)"/> reads as white space, is omitted: the request carries no
    /// <c>scope</c> parameter. Omitting a value of white space only is this library's normalization
    /// at the builder:
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 section 3.3</see>'s
    /// grammar, <c>scope-token = 1*( %x21 / %x23-5B / %x5D-7E )</c>, shows such a value holds no
    /// <c>scope-token</c>, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">section 3.2</see>'s "Parameters
    /// sent without a value MUST be treated as if they were omitted from the request." governs an
    /// empty value only. Any other value is sent as given, its <c>scope-token</c> syntax being the
    /// caller's.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>The requested RFC 9396 <c>authorization_details</c> as a JSON array string (§4.3.3), or <see langword="null"/>.</summary>
    public string? AuthorizationDetails { get; init; }

    /// <summary>
    /// The party acting for the subject (RFC 8693 §2.1 <c>actor_token</c> and <c>actor_token_type</c>, a delegation of §1.1), or
    /// <see langword="null"/> for an exchange naming none.
    /// </summary>
    public IdJagMintActor? Actor { get; init; }
}


/// <summary>
/// The actor a token exchange names (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see>):
/// <c>actor_token</c> "A security token that represents the identity of the acting party", and <c>actor_token_type</c>,
/// "REQUIRED when the actor_token parameter is present", so the two are carried as one.
/// </summary>
public sealed record IdJagMintActor
{
    /// <summary>The token representing the acting party, sent as <c>actor_token</c>.</summary>
    public required string Token { get; init; }

    /// <summary>The type of <see cref="Token"/>, sent as <c>actor_token_type</c> (RFC 8693 §3).</summary>
    public required TokenType Type { get; init; }


    /// <summary>Names the actor by its type alone, never its token.</summary>
    /// <returns>The text.</returns>
    public override string ToString() => $"{nameof(IdJagMintActor)} {{ {nameof(Type)} = {TokenTypeNames.GetName(Type)} }}";
}


/// <summary>
/// Per-call inputs for <see cref="IdJagClient.RedeemAsync(ClientRegistration, IdJagRedeemOptions, CancellationToken)"/>
/// — the client side of the ID-JAG redeem (a JWT Bearer grant presenting the ID-JAG as the assertion,
/// draft-ietf-oauth-identity-assertion-authz-grant-04 §4.4). The client authenticates as a confidential
/// client (§9.1) with the client assertion its registration's method names (RFC 7523 §2.2), composed under the key or the
/// secret the registration carries and the inputs <see cref="ClientAssertion"/> names.
/// </summary>
public sealed record IdJagRedeemOptions
{
    /// <summary>The ID-JAG obtained from the mint, presented as the §4.4 <c>assertion</c> (REQUIRED).</summary>
    public required string Assertion { get; init; }

    /// <summary>
    /// The client assertion's inputs (RFC 7523 §2.2): the <c>kid</c> of a <c>private_key_jwt</c> key or the HMAC algorithm
    /// of a <c>client_secret_jwt</c> secret, the serialisers and the assertion's validity window. The key or the secret
    /// itself is the registration's <see cref="ClientRegistration.AuthenticationKeyMaterial"/>, under the method the
    /// registration names (<see cref="ClientAssertionCredential.Of"/>).
    /// </summary>
    public required ClientAssertionOptions ClientAssertion { get; init; }
}


/// <summary>
/// The ID-JAG sub-client of <see cref="OAuthClient"/> — the client side of the Cross-App Access two-leg
/// profile (draft-ietf-oauth-identity-assertion-authz-grant-04): <see cref="MintAsync(ClientRegistration, IdJagMintOptions, CancellationToken)"/>
/// obtains an ID-JAG from the IdP via Token Exchange (§4.3); <see cref="RedeemAsync(ClientRegistration, IdJagRedeemOptions, CancellationToken)"/>
/// redeems it at the Resource Authorization Server via the JWT Bearer grant (§4.4). Both authenticate the
/// confidential client (§9.1) with the client assertion the registration's method names.
/// </summary>
/// <remarks>
/// Constructed via the <see cref="IdJagClientExtensions">OAuthClient.IdJag</see> extension property. The
/// struct is cheap (one reference field) and carries no per-AS state — each method takes a
/// <see cref="ClientRegistration"/> describing which authorization server the call targets.
/// </remarks>
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
        MintAsync(registration, options, [], cancellationToken);


    /// <inheritdoc cref="MintAsync(ClientRegistration, IdJagMintOptions, CancellationToken)"/>
    /// <param name="registration">The registration identifying the IdP authorization server.</param>
    /// <param name="options">The mint inputs (subject token, audience, client signing material).</param>
    /// <param name="context">The per-operation exchange context threaded into the transport delegates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
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
        RedeemAsync(registration, options, [], cancellationToken);


    /// <inheritdoc cref="RedeemAsync(ClientRegistration, IdJagRedeemOptions, CancellationToken)"/>
    /// <param name="registration">The registration identifying the Resource Authorization Server.</param>
    /// <param name="options">The redeem inputs (the ID-JAG assertion, client signing material).</param>
    /// <param name="context">The per-operation exchange context threaded into the transport delegates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
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
