namespace Verifiable.OAuth.Server;

/// <summary>
/// Generates a fresh, unguessable client identifier for a newly-registered
/// client per <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 §3.2.1</see>.
/// </summary>
/// <remarks>
/// The default implementation
/// (<see cref="Registration.RegistrationEndpoints.DefaultGenerateClientIdAsync"/>) emits
/// <c>Guid.NewGuid().ToString("N")</c> — 32 hex characters from .NET's
/// CSPRNG-backed GUID v4 generator. Applications wanting different shapes
/// (URL-safe base64 of higher-entropy bytes, prefix-tagged tokens, integer
/// counters from a managed sequence) supply their own delegate. The
/// returned value must satisfy RFC 6749 §10.10 entropy guidance (≥128 bits
/// of randomness when guessability matters; the default's 122 bits is the
/// floor).
/// </remarks>
/// <param name="context">The request context for the registration call.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The generated client identifier.</returns>
public delegate ValueTask<string> GenerateClientIdDelegate(
    RequestContext context,
    CancellationToken cancellationToken);
