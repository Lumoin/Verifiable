using System;
using System.Collections.Generic;
using Verifiable.JCose;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared OAuth 2.0 access-token JWT payload assembly, delegating to the production
/// <see cref="JwtPayloadExtensions.ForAccessToken"/> with a fresh <c>jti</c> per call.
/// </summary>
internal static class OAuthAccessTokenFixtures
{
    /// <summary>
    /// Builds an access-token <see cref="JwtPayload"/> via <see cref="JwtPayloadExtensions.ForAccessToken"/>,
    /// minting a fresh <c>jti</c> each call.
    /// </summary>
    /// <param name="subject">The <c>sub</c> claim.</param>
    /// <param name="scope">The <c>scope</c> claim.</param>
    /// <param name="clientId">The <c>client_id</c> claim.</param>
    /// <param name="issuedAt">The <c>iat</c> instant.</param>
    /// <param name="expiresAt">The <c>exp</c> instant.</param>
    /// <param name="issuer">The <c>iss</c> claim, or <see langword="null"/> to omit it.</param>
    /// <param name="audience">The <c>aud</c> claim values.</param>
    /// <returns>The assembled access-token payload.</returns>
    internal static JwtPayload BuildAccessTokenPayload(
        string subject,
        string scope,
        string clientId,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        string? issuer,
        IReadOnlyList<string> audience) =>
        JwtPayloadExtensions.ForAccessToken(
            subject: subject,
            jti: Guid.NewGuid().ToString("N"),
            scope: scope,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            issuer: issuer,
            audience: audience,
            clientId: clientId);
}
