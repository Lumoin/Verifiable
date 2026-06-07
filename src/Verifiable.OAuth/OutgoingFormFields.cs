using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth;

/// <summary>
/// The set of form-encoded field values to send in the body of an outgoing
/// HTTP POST via <see cref="SendFormPostDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// Symmetric outbound pair to <see cref="Verifiable.OAuth.Server.RequestFields"/>:
/// <c>RequestFields</c> is the inbound side that the AS skin populates from
/// incoming request bodies; <see cref="OutgoingFormFields"/> is the outbound side
/// that the client builds before posting. Type identity prevents accidental
/// argument swapping at compile time and reads clearly at the call site.
/// </para>
/// <para>
/// Inheriting from <see cref="Dictionary{TKey, TValue}"/> follows the same pattern
/// as <see cref="Verifiable.OAuth.Server.RequestFields"/>,
/// <see cref="Verifiable.JCose.JwtHeader"/>, and
/// <see cref="Verifiable.JCose.JwtPayload"/>: full dictionary API surface with a
/// distinct nominal type. Ordinal comparison matches the OAuth parameter-name
/// convention.
/// </para>
/// <para>
/// Keys are OAuth or OID4VP parameter names (see
/// <see cref="OAuthRequestParameterNames"/>,
/// <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpAuthorizationRequestParameterNames"/>).
/// Values are the form-encoded value strings the caller wants sent on the wire.
/// </para>
/// </remarks>
[DebuggerDisplay("OutgoingFormFields({Count} entries)")]
public sealed class OutgoingFormFields: Dictionary<string, string>, IEquatable<OutgoingFormFields>
{
    /// <summary>
    /// Creates an empty <see cref="OutgoingFormFields"/> instance.
    /// </summary>
    public OutgoingFormFields(): base(StringComparer.Ordinal) { }

    /// <summary>
    /// Creates an <see cref="OutgoingFormFields"/> instance with the specified
    /// initial capacity.
    /// </summary>
    /// <param name="capacity">The initial number of entries the collection can contain.</param>
    public OutgoingFormFields(int capacity): base(capacity, StringComparer.Ordinal) { }

    /// <summary>
    /// Creates an <see cref="OutgoingFormFields"/> instance populated from any
    /// key-value enumerable.
    /// </summary>
    /// <param name="entries">Initial field entries to copy.</param>
    public OutgoingFormFields(IEnumerable<KeyValuePair<string, string>> entries)
        : base(StringComparer.Ordinal)
    {
        ArgumentNullException.ThrowIfNull(entries);

        foreach((string key, string value) in entries)
        {
            this[key] = value;
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] OutgoingFormFields? other)
    {
        if(other is null || Count != other.Count)
        {
            return false;
        }

        foreach((string key, string value) in this)
        {
            if(!other.TryGetValue(key, out string? otherValue)
                || !string.Equals(value, otherValue, StringComparison.Ordinal))
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


    /// <summary>Determines whether two <see cref="OutgoingFormFields"/> instances contain identical entries.</summary>
    public static bool operator ==(OutgoingFormFields? left, OutgoingFormFields? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="OutgoingFormFields"/> instances differ.</summary>
    public static bool operator !=(OutgoingFormFields? left, OutgoingFormFields? right) =>
        !(left == right);
}
