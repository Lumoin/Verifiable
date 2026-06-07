using Verifiable.Core;
namespace Verifiable.OAuth.Server;

/// <summary>
/// Validates a bearer token presented at an RFC 7592 management endpoint.
/// The application compares the presented token against its persisted
/// value (typically a hash) and returns <see langword="true"/> on a match.
/// </summary>
/// <remarks>
/// <para>
/// The library never sees the stored form of the token. The application's
/// implementation decides the storage shape (plaintext, hash, hashed and
/// salted, separate vault) and answers the validation question.
/// </para>
/// <para>
/// Constant-time comparison is the application's responsibility. The
/// library calls this delegate exactly once per RFC 7592 request after
/// extracting the <c>Authorization: Bearer</c> header.
/// </para>
/// </remarks>
/// <param name="tenantId">The tenant the registration belongs to.</param>
/// <param name="clientId">The client identifier from the request path.</param>
/// <param name="presentedToken">The bearer token value from the <c>Authorization</c> header.</param>
/// <param name="context">The request context for the validation call.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns><see langword="true"/> on match, <see langword="false"/> otherwise.</returns>
public delegate ValueTask<bool> ValidateRegistrationAccessTokenDelegate(
    TenantId tenantId,
    string clientId,
    string presentedToken,
    ExchangeContext context,
    CancellationToken cancellationToken);
