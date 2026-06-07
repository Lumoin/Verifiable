using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// A VP Token returned in an OID4VP authorization response, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#response-parameters">OID4VP 1.0 §8.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// When DCQL is used, a VP Token is a JSON object whose keys are the <c>id</c>
/// values from the <c>credentials</c> array of the DCQL query and whose values
/// are arrays of one or more Presentations matching the respective Credential
/// Query. When the Credential Query's <c>multiple</c> is omitted or
/// <see langword="false"/>, the array contains exactly one Presentation; the
/// array shape is preserved regardless of cardinality.
/// </para>
/// <para>
/// For SD-JWT VC the presentation value is the compact serialisation of the
/// SD-JWT with the selected disclosures appended, optionally followed by a KB-JWT.
/// </para>
/// </remarks>
[DebuggerDisplay("VpToken Count={Presentations.Count}")]
public sealed class VpToken
{
    /// <summary>
    /// The presentations keyed by DCQL credential query identifier. Each value
    /// is a one-or-more-element array of serialised presentations — for SD-JWT
    /// VC each element is the compact serialisation string with disclosures
    /// and optional KB-JWT.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Presentations { get; }


    /// <summary>
    /// Initialises a <see cref="VpToken"/> from an existing dictionary.
    /// </summary>
    public VpToken(IReadOnlyDictionary<string, IReadOnlyList<string>> presentations)
    {
        ArgumentNullException.ThrowIfNull(presentations);

        Presentations = presentations;
    }


    /// <summary>
    /// Initialises a <see cref="VpToken"/> from one or more query ID and
    /// presentation-array pairs.
    /// </summary>
    public VpToken(params (string QueryId, IReadOnlyList<string> Presentations)[] entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        ImmutableDictionary<string, IReadOnlyList<string>>.Builder builder =
            ImmutableDictionary.CreateBuilder<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach((string id, IReadOnlyList<string> presentations) in entries)
        {
            builder.Add(id, presentations);
        }

        Presentations = builder.ToImmutable();
    }


}
