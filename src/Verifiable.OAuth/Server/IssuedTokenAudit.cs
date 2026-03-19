using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Per-token audit metadata persisted in flow state after a token response is
/// composed. Captures everything needed for replay detection, key-scoped
/// revocation, and post-hoc audit without retaining the token bytes themselves.
/// </summary>
/// <remarks>
/// <para>
/// One <see cref="IssuedTokenAudit"/> is recorded for every token emitted by a
/// successful token-endpoint request. The set of audits for a single response is
/// carried on <see cref="IssuedTokenAuditSet"/>, keyed by the same response field
/// name the corresponding <see cref="TokenProducer"/> declared.
/// </para>
/// <para>
/// The token's compact JWS string is never persisted — only the identifiers that
/// would be needed to recognise the token if it is presented later (the <c>jti</c>)
/// or to revoke a class of tokens by signing key (<see cref="SigningKeyId"/>).
/// </para>
/// </remarks>
[DebuggerDisplay("IssuedTokenAudit Jti={Jti,nq} Key={SigningKeyId,nq}")]
public sealed record IssuedTokenAudit
{
    /// <summary>
    /// The <c>jti</c> (JWT ID) claim of the issued token. Used for replay
    /// detection per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.2">RFC 9700 §2.2</see>.
    /// </summary>
    public required string Jti { get; init; }

    /// <summary>
    /// The identifier of the signing key used. Enables revocation of all tokens
    /// signed by a particular key.
    /// </summary>
    public required string SigningKeyId { get; init; }

    /// <summary>
    /// The instant the token was issued.
    /// </summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>
    /// The instant the token expires.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}
