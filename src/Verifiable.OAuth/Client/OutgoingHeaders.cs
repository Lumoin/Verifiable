using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Headers attached to an outbound HTTP request. The library composes
/// these (including <c>Authorization</c> with the right scheme) inside
/// the handler layer before calling the transport delegate, so the
/// transport stays auth-scheme-naive.
/// </summary>
/// <remarks>
/// Future binding schemes (RFC 9449 DPoP nonce, RFC 9421 HTTP signing)
/// add additional headers (<c>DPoP</c>, <c>Signature</c>, <c>Signature-Input</c>)
/// alongside <c>Authorization</c>. Because the transport delegate sees
/// only the composed header bag, those schemes plug in without changing
/// the delegate signature.
/// </remarks>
[DebuggerDisplay("OutgoingHeaders ({Values.Count} headers)")]
public sealed record OutgoingHeaders
{
    /// <summary>The composed header name-to-value map.</summary>
    public ImmutableDictionary<string, string> Values { get; init; } =
        ImmutableDictionary<string, string>.Empty;

    /// <summary>The empty header set.</summary>
    public static OutgoingHeaders Empty { get; } = new();

    /// <summary>
    /// Returns a new <see cref="OutgoingHeaders"/> with the <c>Authorization</c>
    /// header set to <paramref name="scheme"/> followed by a single space and
    /// <paramref name="parameter"/>. Composes per RFC 9110 §11.6.2.
    /// </summary>
    public OutgoingHeaders WithAuthorization(string scheme, string parameter) =>
        this with { Values = Values.SetItem("Authorization", $"{scheme} {parameter}") };

    /// <summary>
    /// Returns a new <see cref="OutgoingHeaders"/> with <paramref name="name"/>
    /// set to <paramref name="value"/>. Replaces any existing value for the
    /// same name.
    /// </summary>
    public OutgoingHeaders With(string name, string value) =>
        this with { Values = Values.SetItem(name, value) };
}
