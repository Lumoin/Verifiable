using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The wire shape a deployment uses for the <c>aud</c> JWT claim per
/// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see>.
/// </summary>
/// <remarks>
/// RFC 7519 §4.1.3 permits either a single string or an array of strings. The
/// library validates both shapes on inbound tokens; on outbound tokens the
/// shape is a deployment choice. Some legacy parsers reject array form.
/// </remarks>
[DebuggerDisplay("AudClaimFormat={ToString(),nq}")]
public enum AudClaimFormat
{
    /// <summary>Single-string form.</summary>
    String,

    /// <summary>Array form (single-element array allowed).</summary>
    Array,

    /// <summary>
    /// The producer emits whichever form is conventional for the token type.
    /// Default for cross-token-type policy.
    /// </summary>
    Either
}
