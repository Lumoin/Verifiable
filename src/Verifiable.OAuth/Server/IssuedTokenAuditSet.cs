using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The set of <see cref="IssuedTokenAudit"/> records for tokens emitted in one
/// token-endpoint response, keyed by the response field name the producing
/// <see cref="TokenProducer"/> declared. Persisted on
/// <see cref="ServerTokenIssuedState"/> as part of the post-issuance flow record.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the shape of <see cref="IssuedTokenSet"/> — both are dictionaries
/// keyed by the same response field names (members of
/// <see cref="WellKnownTokenTypes"/>) — but carries different content. The
/// transient <see cref="IssuedTokenSet"/> holds compact JWS strings during
/// response composition; the persisted <see cref="IssuedTokenAuditSet"/> holds
/// the audit records that survive the request.
/// </para>
/// </remarks>
[DebuggerDisplay("IssuedTokenAuditSet({Audits.Count} entries)")]
public sealed record IssuedTokenAuditSet
{
    /// <summary>
    /// The audits keyed by token-type response field name.
    /// </summary>
    public required IReadOnlyDictionary<string, IssuedTokenAudit> Audits { get; init; }


    /// <summary>
    /// Returns the audit for the given token type, or <see langword="null"/>
    /// when no token of that type was issued in the response this set describes.
    /// </summary>
    /// <param name="tokenType">A member of <see cref="WellKnownTokenTypes"/>.</param>
    public IssuedTokenAudit? Get(string tokenType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenType);
        return Audits.TryGetValue(tokenType, out IssuedTokenAudit? audit) ? audit : null;
    }


    /// <summary>
    /// Whether this set contains an audit for the given token type.
    /// </summary>
    /// <param name="tokenType">A member of <see cref="WellKnownTokenTypes"/>.</param>
    public bool Contains(string tokenType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenType);
        return Audits.ContainsKey(tokenType);
    }


    /// <summary>
    /// An empty <see cref="IssuedTokenAuditSet"/> singleton.
    /// </summary>
    public static IssuedTokenAuditSet Empty { get; } = new()
    {
        Audits = new Dictionary<string, IssuedTokenAudit>(0)
    };
}
