using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// A §3.4.1 query entry whose <c>type</c> is well-formed (a non-empty string) but not one this
/// document defines. The §3.4.1 <c>query</c> array is an open extension point — a verifier MAY
/// introduce further query types — so such an entry parses into the model rather than failing the
/// request; <see cref="VprEvaluator"/> simply cannot satisfy it from held verifiable credentials.
/// </summary>
/// <remarks>
/// This is distinct from the §3.4.1 "each query MUST define a type" violation: a query entry with no
/// <c>type</c> (or a non-string <c>type</c>) is a parse failure, not an <see cref="UnknownQuery"/>.
/// The raw entry JSON is preserved so a downstream extension handler can interpret it.
/// </remarks>
[DebuggerDisplay("UnknownQuery Type={Type} Group={Group}")]
public sealed record UnknownQuery: VcalmPresentationQuery
{
    /// <summary>The verbatim JSON of the unrecognized query entry, for a downstream extension handler.</summary>
    public required string RawJson { get; init; }
}
