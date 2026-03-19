using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// A VP Token returned in an OID4VP authorization response, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OID4VP 1.0 §8.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// When DCQL is used, a VP Token is a JSON object whose keys are the <c>id</c>
/// values from the <c>credentials</c> array of the DCQL query and whose values
/// are the Verifiable Presentations matching the respective Credential Query.
/// </para>
/// <para>
/// For SD-JWT VC the presentation value is the compact serialization of the
/// SD-JWT with the selected disclosures appended, optionally followed by a KB-JWT.
/// </para>
/// <para>
/// Serialization is handled by the JSON layer in <c>Verifiable.Json</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("VpToken Count={Presentations.Count}")]
public sealed class VpToken
{
    /// <summary>
    /// The presentations keyed by DCQL credential query identifier.
    /// Each value is the serialized presentation — for SD-JWT VC this is the
    /// compact serialization string with disclosures and optional KB-JWT.
    /// </summary>
    public IReadOnlyDictionary<string, string> Presentations { get; }


    /// <summary>
    /// Initializes a <see cref="VpToken"/> from an existing dictionary.
    /// </summary>
    public VpToken(IReadOnlyDictionary<string, string> presentations)
    {
        ArgumentNullException.ThrowIfNull(presentations);

        Presentations = presentations;
    }


    /// <summary>
    /// Initializes a <see cref="VpToken"/> from one or more query ID and
    /// serialized presentation pairs.
    /// </summary>
    public VpToken(params (string QueryId, string SerializedPresentation)[] entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var builder = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        foreach((string id, string presentation) in entries)
        {
            builder.Add(id, presentation);
        }

        Presentations = builder.ToImmutable();
    }


    /// <summary>
    /// Returns the serialized presentation for the given DCQL query identifier,
    /// or <see langword="null"/> when no matching presentation is present.
    /// </summary>
    public string? GetPresentation(string queryId)
    {
        ArgumentNullException.ThrowIfNull(queryId);

        return Presentations.TryGetValue(queryId, out string? value) ? value : null;
    }
}
