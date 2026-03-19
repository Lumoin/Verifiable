using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// A nonce bound to a single authorization transaction.
/// </summary>
/// <remarks>
/// Used in KB-JWT holder binding and as an anti-replay anchor in OID4VP
/// direct_post.jwt responses. A nonce must not be reused across flows.
/// Each authorization transaction generates its own nonce independently.
/// </remarks>
/// <param name="Value">A cryptographically random string, Base64url-encoded without padding.</param>
[DebuggerDisplay("Value={Value}")]
public sealed record TransactionNonce(string Value);
