using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace Verifiable.OAuth;

/// <summary>
/// The set of form-encoded field occurrences to send in the body of an outgoing
/// HTTP POST via <see cref="SendFormPostDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// Symmetric outbound pair to <see cref="Verifiable.Server.RequestFields"/>:
/// <c>RequestFields</c> is the inbound side that the AS skin populates from
/// incoming request bodies, faithfully preserving every occurrence of a
/// repeated key; <see cref="OutgoingFormFields"/> is the outbound side the
/// client builds before posting, and mirrors that same multi-valued shape —
/// HTTP form parameters are inherently repeatable (RFC 8707 §2's
/// <c>resource</c> is the recurring example in this library), so a key CAN
/// carry more than one occurrence. The indexer keeps the common single-value
/// convention: setting <c>form[key]</c> replaces every occurrence already
/// present with exactly one, which is what every caller that treats a field
/// as single-valued naturally does. <see cref="Add"/> is the deliberate
/// opt-in for a genuinely repeated field: it appends a new occurrence without
/// disturbing any already present, so the wire form carries the key
/// several times rather than folding several values into one delimited
/// occurrence — the latter is a distinct, narrower value the receiving
/// parser must not confuse with "the parameter repeated."
/// </para>
/// <para>
/// Type identity prevents accidental argument swapping at compile time and
/// reads clearly at the call site.
/// </para>
/// <para>
/// Keys are OAuth or OID4VP parameter names (see
/// <see cref="OAuthRequestParameterNames"/>,
/// <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpAuthorizationRequestParameterNames"/>).
/// Values are the form-encoded value strings the caller wants sent on the wire.
/// </para>
/// </remarks>
[DebuggerDisplay("OutgoingFormFields({Count} entries)")]
[SuppressMessage("Design", "CA1710:Identifiers should have correct suffix", Justification = "OutgoingFormFields is the established, symmetric name for this type's inbound counterpart Verifiable.Server.RequestFields (which carries no collection-interface suffix either) — renaming to a Collection/Dictionary suffix would break that pairing and the many public delegate/API signatures already named around it across this library.")]
public sealed class OutgoingFormFields: IReadOnlyCollection<KeyValuePair<string, string>>, IEquatable<OutgoingFormFields>
{
    /// <summary>The backing store: an ordered list of key/value occurrences, preserving repeats.</summary>
    private readonly List<KeyValuePair<string, string>> entries;

    /// <summary>
    /// Creates an empty <see cref="OutgoingFormFields"/> instance.
    /// </summary>
    public OutgoingFormFields()
    {
        entries = [];
    }

    /// <summary>
    /// Creates an <see cref="OutgoingFormFields"/> instance with the specified
    /// initial capacity.
    /// </summary>
    /// <param name="capacity">The initial number of occurrences the collection can contain.</param>
    public OutgoingFormFields(int capacity)
    {
        entries = new List<KeyValuePair<string, string>>(capacity);
    }

    /// <summary>
    /// Creates an <see cref="OutgoingFormFields"/> instance populated from any
    /// key-value enumerable. Each pair is applied through the indexer's
    /// single-value convention (a repeated key in <paramref name="fields"/> leaves only
    /// its last occurrence); a caller that needs genuinely repeated occurrences from a
    /// source sequence should construct empty and call <see cref="Add"/> per entry instead.
    /// </summary>
    /// <param name="fields">Initial field entries to copy.</param>
    public OutgoingFormFields(IEnumerable<KeyValuePair<string, string>> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        entries = [];
        foreach((string key, string value) in fields)
        {
            this[key] = value;
        }
    }


    /// <summary>The number of key/value occurrences present, counting every repeat.</summary>
    public int Count => entries.Count;


    /// <summary>
    /// Gets the value of the first occurrence of <paramref name="key"/>, or sets
    /// <paramref name="key"/> to a single occurrence carrying <paramref name="value"/>,
    /// replacing every occurrence already present. This is the single-value convention every
    /// non-repeating field uses; see <see cref="Add"/> for the repeated-occurrence alternative.
    /// </summary>
    /// <param name="key">The parameter name.</param>
    /// <exception cref="KeyNotFoundException">No occurrence of <paramref name="key"/> is present.</exception>
    public string this[string key]
    {
        get
        {
            foreach(KeyValuePair<string, string> entry in entries)
            {
                if(string.Equals(entry.Key, key, StringComparison.Ordinal))
                {
                    return entry.Value;
                }
            }

            throw new KeyNotFoundException($"The key '{key}' was not present.");
        }
        set
        {
            entries.RemoveAll(entry => string.Equals(entry.Key, key, StringComparison.Ordinal));
            entries.Add(new KeyValuePair<string, string>(key, value));
        }
    }


    /// <summary>
    /// Appends a REPEATED occurrence of <paramref name="key"/> carrying <paramref name="value"/>,
    /// preserving every occurrence already present under the same key — unlike the indexer setter,
    /// which replaces. Used for the wire parameters a specification permits to repeat (for example
    /// RFC 8707 §2's <c>resource</c> indicator): each absolute-URI indicator becomes its own
    /// occurrence of <paramref name="key"/>, never several indicators packed into one delimited value.
    /// </summary>
    /// <param name="key">The parameter name.</param>
    /// <param name="value">The occurrence's value.</param>
    public void Add(string key, string value)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);

        entries.Add(new KeyValuePair<string, string>(key, value));
    }


    /// <summary>Whether at least one occurrence of <paramref name="key"/> is present.</summary>
    /// <param name="key">The parameter name.</param>
    public bool ContainsKey(string key)
    {
        foreach(KeyValuePair<string, string> entry in entries)
        {
            if(string.Equals(entry.Key, key, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Reads every occurrence's value for <paramref name="key"/>, in the order they were added.
    /// Returns an empty list when the key is absent. Used to inspect a genuinely repeated field
    /// (for example RFC 8707 §2's <c>resource</c>) rather than the indexer's single-value read.
    /// </summary>
    /// <param name="key">The parameter name.</param>
    public IReadOnlyList<string> GetValues(string key)
    {
        List<string> values = [];
        foreach(KeyValuePair<string, string> entry in entries)
        {
            if(string.Equals(entry.Key, key, StringComparison.Ordinal))
            {
                values.Add(entry.Value);
            }
        }

        return values;
    }


    /// <inheritdoc/>
    public IEnumerator<KeyValuePair<string, string>> GetEnumerator() => entries.GetEnumerator();


    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] OutgoingFormFields? other)
    {
        if(other is null || Count != other.Count)
        {
            return false;
        }

        //Order-independent multiset comparison: two field sets are equal when they carry the same
        //key/value occurrences the same number of times, regardless of the order Add/the indexer
        //appended them in.
        List<KeyValuePair<string, string>> ordered = [.. entries
            .OrderBy(static entry => entry.Key, StringComparer.Ordinal)
            .ThenBy(static entry => entry.Value, StringComparer.Ordinal)];
        List<KeyValuePair<string, string>> otherOrdered = [.. other.entries
            .OrderBy(static entry => entry.Key, StringComparer.Ordinal)
            .ThenBy(static entry => entry.Value, StringComparer.Ordinal)];

        for(int i = 0; i < ordered.Count; i++)
        {
            if(!string.Equals(ordered[i].Key, otherOrdered[i].Key, StringComparison.Ordinal)
                || !string.Equals(ordered[i].Value, otherOrdered[i].Value, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is OutgoingFormFields other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Count;


    /// <summary>Determines whether two <see cref="OutgoingFormFields"/> instances contain identical occurrences.</summary>
    public static bool operator ==(OutgoingFormFields? left, OutgoingFormFields? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="OutgoingFormFields"/> instances differ.</summary>
    public static bool operator !=(OutgoingFormFields? left, OutgoingFormFields? right) =>
        !(left == right);
}
