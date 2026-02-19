using System;
using System.Diagnostics;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Represents a Status List Token containing status information for multiple Referenced Tokens.
/// </summary>
/// <remarks>
/// <para>
/// A Status List Token embeds a <see cref="StatusList"/> into a cryptographically signed
/// container (JWT or CWT) that protects the integrity of the status data. This allows
/// the token to be hosted by third parties or transferred for offline use.
/// </para>
/// <para>
/// Required claims:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="Subject"/> (sub/2): The URI of this Status List Token.</description></item>
///   <item><description><see cref="IssuedAt"/> (iat/6): The time at which this token was issued.</description></item>
///   <item><description><see cref="StatusList"/> (status_list/65533): The embedded Status List.</description></item>
/// </list>
/// <para>
/// Recommended claims:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="ExpirationTime"/> (exp/4): When this token expires.</description></item>
///   <item><description><see cref="TimeToLive"/> (ttl/65534): Maximum cache duration in seconds.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("StatusListToken[Subject={Subject}]")]
public sealed class StatusListToken
{
    /// <summary>
    /// Gets the subject URI of this Status List Token.
    /// This value must match the <c>uri</c> claim in Referenced Tokens.
    /// </summary>
    public string Subject { get; }

    /// <summary>
    /// Gets the time at which this Status List Token was issued.
    /// </summary>
    public DateTimeOffset IssuedAt { get; }

    /// <summary>
    /// Gets the expiration time after which this token should be considered invalid.
    /// </summary>
    public DateTimeOffset? ExpirationTime { get; init; }

    /// <summary>
    /// Gets the maximum time in seconds that this token may be cached before
    /// a fresh copy should be retrieved.
    /// </summary>
    public long? TimeToLive { get; init; }

    /// <summary>
    /// Gets the embedded Status List containing the actual status data.
    /// </summary>
    public StatusList StatusList { get; }

    /// <summary>
    /// Creates a new Status List Token.
    /// </summary>
    /// <param name="subject">
    /// The subject URI of the Status List Token. Must match the <c>uri</c> claim
    /// in corresponding Referenced Tokens.
    /// </param>
    /// <param name="issuedAt">The time at which this token was issued.</param>
    /// <param name="statusList">The Status List to embed in this token.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="subject"/> or <paramref name="statusList"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="subject"/> is empty or whitespace.</exception>
    public StatusListToken(string subject, DateTimeOffset issuedAt, StatusList statusList)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        ArgumentNullException.ThrowIfNull(statusList);

        Subject = subject;
        IssuedAt = issuedAt;
        StatusList = statusList;
    }
}