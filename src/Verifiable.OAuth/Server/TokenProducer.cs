using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Emits one token type at a token endpoint. The Authorization Server's token
/// endpoint walks <see cref="AuthorizationServerOptions.TokenProducers"/>, filters
/// by <see cref="RequiredCapability"/> and <see cref="IsApplicable"/>, and for
/// each applicable producer runs the pipeline:
/// resolve key (via <see cref="KeyUsage"/>) → producer's <see cref="BuildAsync"/>
/// → claim contributors → request-claim filtering → sign.
/// </summary>
/// <remarks>
/// <para>
/// Producers are the extension point for new token types — RFC 9068 access tokens,
/// OIDC ID Tokens, refresh tokens issued as JWT, OIDC back-channel logout tokens,
/// JWT-Secured Authorization Response (JARM) tokens, OID4VCI credential tokens, and
/// any future shape that fits the "build header and payload, then sign" model.
/// </para>
/// <para>
/// The library ships <see cref="TokenProducer.Rfc9068AccessToken"/> and
/// <see cref="TokenProducer.Oidc10IdToken"/> via extension blocks on
/// <see cref="TokenProducer"/>. Applications add their own producers via their
/// own extension blocks following the same shape:
/// </para>
/// <code>
/// public static class MyTokenProducerExtensions
/// {
///     extension(TokenProducer)
///     {
///         public static TokenProducer MyLogoutToken => MyLogoutTokenProducer.Instance;
///     }
/// }
/// </code>
/// <para>
/// Producers do not resolve key material or sign — the endpoint handler resolves
/// the <see cref="KeyId"/> via <see cref="SigningKeySelection.ResolveSigningKeyIdAsync"/>
/// against the producer's declared <see cref="KeyUsage"/>, materialises the
/// <see cref="PrivateKeyMemory"/> via
/// <see cref="AuthorizationServerOptions.SigningKeyResolver"/>, derives the JWA
/// algorithm string from the key's <c>Tag</c>, and hands those values to the
/// producer's <see cref="BuildAsync"/>. The producer composes the JCose header
/// and payload with all values already known, returning a
/// <see cref="TokenProducerOutput"/>. The endpoint then signs via
/// <see cref="UnsignedJwt.SignAsync"/>.
/// </para>
/// <para>
/// This separation keeps key handling at one well-defined site and producers
/// concentrated on header and claim composition.
/// </para>
/// </remarks>
[DebuggerDisplay("TokenProducer {Name,nq} -> {ResponseField,nq}")]
public sealed record TokenProducer
{
    /// <summary>
    /// A diagnostic identifier for this producer used in logging and tracing.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// The response field name this producer's token appears under in the token
    /// endpoint response body. Typically a value from <see cref="WellKnownTokenTypes"/>
    /// — <c>access_token</c>, <c>id_token</c>, <c>refresh_token</c>, etc.
    /// </summary>
    public required string ResponseField { get; init; }

    /// <summary>
    /// The capability the registration must have for this producer to run. The
    /// endpoint handler skips producers whose <see cref="RequiredCapability"/> is
    /// not allowed by the active <see cref="ClientRegistration"/>.
    /// </summary>
    public required ServerCapabilityName RequiredCapability { get; init; }

    /// <summary>
    /// The protocol-level usage context this producer signs with. The endpoint
    /// handler resolves a <see cref="KeyId"/> for this usage via
    /// <see cref="SigningKeySelection.ResolveSigningKeyIdAsync"/> before invoking
    /// <see cref="BuildAsync"/>. Allows per-token-type key separation — access
    /// tokens, ID tokens, refresh tokens, and logout tokens may each use their
    /// own signing keys per registration.
    /// </summary>
    public required KeyUsageContext KeyUsage { get; init; }

    /// <summary>
    /// Whether this producer applies to the current request beyond the capability
    /// check. Used for fine-grained gating — for example, the OIDC ID Token producer
    /// returns <see langword="true"/> only when <c>openid</c> is in the granted scope.
    /// </summary>
    public required TokenProducerIsApplicableDelegate IsApplicable { get; init; }

    /// <summary>
    /// Builds the JWT header and base payload for this token type, given the
    /// signing <see cref="KeyId"/> and JWA algorithm string the endpoint resolved
    /// from <see cref="KeyUsage"/>. The endpoint signs the result and applies
    /// claim contributors before signing.
    /// </summary>
    public required TokenProducerBuildDelegate BuildAsync { get; init; }
}


/// <summary>
/// Determines whether a <see cref="TokenProducer"/> applies to the current request.
/// </summary>
/// <param name="context">The per-request issuance context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// <see langword="true"/> when the producer should emit a token for this request;
/// <see langword="false"/> to skip it.
/// </returns>
public delegate ValueTask<bool> TokenProducerIsApplicableDelegate(
    IssuanceContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Builds the JWT header and base payload for a token type.
/// </summary>
/// <remarks>
/// <para>
/// All key resolution has already happened by the time this delegate is invoked —
/// <paramref name="signingKeyId"/> is the identifier the endpoint resolved via
/// <see cref="SigningKeySelection.ResolveSigningKeyIdAsync"/> against the producer's
/// declared <see cref="TokenProducer.KeyUsage"/>, and <paramref name="algorithm"/>
/// is the JWA identifier derived from the resolved key's <c>Tag</c> via
/// <c>CryptoFormatConversions.DefaultTagToJwaConverter</c>.
/// </para>
/// <para>
/// Producers must populate only the spec-mandated claims for their token type.
/// Optional or extension claims are added by <see cref="ClaimContributor"/>
/// instances that run after the producer.
/// </para>
/// </remarks>
/// <param name="context">The per-request issuance context.</param>
/// <param name="options">The Authorization Server options for delegate access.</param>
/// <param name="signingKeyId">The signing <see cref="KeyId"/> resolved by the endpoint.</param>
/// <param name="algorithm">The JWA algorithm identifier derived from the resolved key.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The header and base payload for the token.</returns>
public delegate ValueTask<TokenProducerOutput> TokenProducerBuildDelegate(
    IssuanceContext context,
    AuthorizationServerOptions options,
    KeyId signingKeyId,
    string algorithm,
    CancellationToken cancellationToken);


/// <summary>
/// The output of a <see cref="TokenProducer.BuildAsync"/> invocation. Carries the
/// header and base payload the endpoint will sign.
/// </summary>
/// <param name="Header">
/// The JWT header carrying <c>alg</c>, <c>typ</c>, and <c>kid</c>, plus any
/// token-type-specific header parameters (for example <c>x5c</c>).
/// </param>
/// <param name="Payload">The base payload with the producer's spec-mandated claims.</param>
[DebuggerDisplay("TokenProducerOutput Header={Header.Count} Payload={Payload.Count}")]
public readonly record struct TokenProducerOutput(JwtHeader Header, JwtPayload Payload);
