using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth;

/// <summary>
/// A typed wrapper around the form-encoded field dictionary OAuth requests
/// carry on the wire (PAR body, token request body, callback query string,
/// revocation body, etc.).
/// </summary>
/// <remarks>
/// <para>
/// OAuth requests serialise as <c>application/x-www-form-urlencoded</c>
/// key-value pairs per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-B">RFC 6749 Appendix B</see>.
/// The library represents these as <see cref="IReadOnlyDictionary{TKey, TValue}"/>
/// of <see cref="string"/> to <see cref="string"/> internally; the wrapper
/// gives that shape a name so call sites read as "OAuth form fields" rather
/// than as a generic dictionary.
/// </para>
/// <para>
/// Typed accessors for well-known OAuth parameter values
/// (<c>client_id</c>, <c>scope</c>, <c>state</c>, <c>code</c>, etc.) live in
/// <see cref="OAuthFormEncodedFieldsExtensions"/>. The accessor names mirror
/// the camelCased parameter constant names from
/// <see cref="OAuthRequestParameters"/> so the typed surface and the wire
/// surface stay aligned.
/// </para>
/// <para>
/// The wrapper exposes read-only access plus typed shorthand for well-known
/// parameter values. Composition of the underlying field set is the caller's
/// concern: callers build the dictionary in whatever shape suits the call
/// site (literal, builder, copy-and-mutate) and wrap it once at the API
/// boundary.
/// </para>
/// <para>
/// Equality is reference-equal on the underlying dictionary instance — the
/// wrapper does not deep-compare. Two <see cref="OAuthFormEncodedFields"/>
/// values are equal when they wrap the same dictionary reference (or are
/// both <see cref="Empty"/>).
/// </para>
/// </remarks>
[DebuggerDisplay("OAuthFormEncodedFields Count={Fields.Count}")]
public readonly struct OAuthFormEncodedFields: IEquatable<OAuthFormEncodedFields>
{
    private readonly IReadOnlyDictionary<string, string>? fields;


    /// <summary>
    /// Wraps the supplied dictionary of form-encoded field name-value pairs.
    /// </summary>
    /// <param name="fields">
    /// The underlying dictionary. The caller retains ownership; the wrapper
    /// stores the reference and exposes it via <see cref="Fields"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="fields"/> is <see langword="null"/>.
    /// </exception>
    public OAuthFormEncodedFields(IReadOnlyDictionary<string, string> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        this.fields = fields;
    }


    /// <summary>
    /// An empty <see cref="OAuthFormEncodedFields"/> instance — the conventional
    /// value for callers that have no fields to send.
    /// </summary>
    public static OAuthFormEncodedFields Empty { get; } =
        new(new Dictionary<string, string>(0));


    /// <summary>
    /// The underlying dictionary of form-encoded field name-value pairs. When
    /// the wrapper is the <see langword="default"/> struct value, this returns
    /// <see cref="Empty"/>'s underlying dictionary so callers do not need to
    /// guard against an unconstructed wrapper.
    /// </summary>
    public IReadOnlyDictionary<string, string> Fields => fields ?? Empty.Fields;


    /// <summary>
    /// Returns <see langword="true"/> when the wrapper holds the same
    /// underlying dictionary reference as <paramref name="other"/>.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(OAuthFormEncodedFields other) =>
        ReferenceEquals(Fields, other.Fields);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is OAuthFormEncodedFields other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() =>
        System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(Fields);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(OAuthFormEncodedFields left, OAuthFormEncodedFields right) =>
        left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(OAuthFormEncodedFields left, OAuthFormEncodedFields right) =>
        !left.Equals(right);
}
