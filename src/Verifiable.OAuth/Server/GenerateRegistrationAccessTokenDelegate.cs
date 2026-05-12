namespace Verifiable.OAuth.Server;

/// <summary>
/// Generates a fresh, high-entropy registration access token for a
/// newly-registered client per
/// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 §3.2.1</see>.
/// Returned as the plaintext bearer; the application's
/// <see cref="ClientRegistered"/> event observer stores it (preferably
/// hashed) for later validation against RFC 7592 management calls.
/// </summary>
/// <remarks>
/// The default implementation
/// (<see cref="Registration.RegistrationEndpoints.DefaultGenerateRegistrationAccessTokenAsync"/>)
/// emits <c>Guid.NewGuid().ToString("N")</c>. Applications wanting
/// higher-entropy bearers, prefix-tagged tokens, or JWT-shaped tokens
/// supply their own delegate.
/// </remarks>
/// <param name="context">The request context for the registration call.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The plaintext bearer token.</returns>
public delegate ValueTask<RegistrationAccessToken> GenerateRegistrationAccessTokenDelegate(
    RequestContext context,
    CancellationToken cancellationToken);
