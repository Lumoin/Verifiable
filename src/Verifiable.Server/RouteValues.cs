using System.Diagnostics;

namespace Verifiable.Server;

/// <summary>
/// Framework-extracted route template parameters from the inbound request.
/// </summary>
/// <remarks>
/// <para>
/// Optional. Skins that do path-template parsing before handing off to the
/// library (the typical ASP.NET case, where attribute routing extracts
/// <c>{segment}</c> and similar) populate this with the extracted values.
/// Skins that hand the raw path through and let matchers do their own path
/// parsing pass <see cref="Empty"/>.
/// </para>
/// <para>
/// The library does not require route values; matchers can always read
/// <see cref="IncomingRequest.Path"/> directly. Route values are an
/// optimization for the common case where the framework has already done
/// the parsing — they let matchers ask <c>route.TryGetValue("segment", out
/// var segment)</c> instead of re-parsing the path.
/// </para>
/// <para>
/// Tenant resolution typically reads from this when tenant identity is
/// in a path segment, but other tenant-resolution strategies (subdomain,
/// header, mTLS subject) ignore it.
/// </para>
/// </remarks>
[DebuggerDisplay("RouteValues({Count} values)")]
public sealed class RouteValues
{
    private Dictionary<string, string> Values { get; }


    /// <summary>
    /// Creates a <see cref="RouteValues"/> from a name-to-value map.
    /// </summary>
    /// <param name="source">
    /// Route template parameter names mapped to their extracted values.
    /// </param>
    public RouteValues(IReadOnlyDictionary<string, string> source)
    {
        ArgumentNullException.ThrowIfNull(source);

        Values = new Dictionary<string, string>(source.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> entry in source)
        {
            Values[entry.Key] = entry.Value;
        }
    }


    /// <summary>
    /// An empty <see cref="RouteValues"/> instance for skins that do not
    /// surface route values.
    /// </summary>
    public static RouteValues Empty { get; } =
        new RouteValues(new Dictionary<string, string>(0));


    /// <summary>
    /// The number of route values present.
    /// </summary>
    public int Count => Values.Count;


    /// <summary>
    /// Tries to read the value for <paramref name="name"/>.
    /// </summary>
    /// <param name="name">Route parameter name (case-sensitive).</param>
    /// <param name="value">The value when found; otherwise <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> when the parameter is present; otherwise
    /// <see langword="false"/>.
    /// </returns>
    public bool TryGetValue(string name, out string? value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return Values.TryGetValue(name, out value);
    }


    /// <summary>
    /// Whether <paramref name="name"/> is present.
    /// </summary>
    /// <param name="name">Route parameter name (case-sensitive).</param>
    public bool Contains(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return Values.ContainsKey(name);
    }
}
