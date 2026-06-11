using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// The neutral information model of one RFC 9396 authorization details object as parsed from an
/// entry of the <c>authorization_details</c> request parameter (a JSON array of objects). It
/// carries the §2 REQUIRED <c>type</c>, the §2.2 common data fields every authorization details
/// type may share, and the type-specific members preserved verbatim in
/// <see cref="ExtensionData"/> so the registered handler for the <see cref="Type"/> reads its
/// own fields losslessly.
/// </summary>
/// <remarks>
/// <para>
/// The wire shape is parsed by the application-wired
/// <see cref="Server.ParseAuthorizationDetailListDelegate"/> (default in <c>Verifiable.Json</c>),
/// which keeps <c>System.Text.Json</c> out of the library. The parser fills the common fields
/// from their well-known member names (<see cref="AuthorizationDetailsParameterNames"/>) and
/// places every remaining member, keyed by its JSON member name, into
/// <see cref="ExtensionData"/> as the raw JSON text of its value.
/// </para>
/// <para>
/// The value of the <see cref="Type"/> determines the allowable contents of the object
/// (RFC 9396 §2/§2.1); the per-type semantics are owned by the registered
/// <see cref="Server.AuthorizationDetailHandler"/> in the
/// <see cref="Server.AuthorizationDetailTypeRegistry"/>. A <see cref="Type"/> with no registered
/// handler is refused with <c>invalid_authorization_details</c> (RFC 9396 §5).
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationDetail Type={Type}")]
public sealed record AuthorizationDetail
{
    /// <summary>
    /// The RFC 9396 §2 <c>type</c> (REQUIRED): the identifier for the authorization details
    /// type, unique for the described API in the context of the AS. Its value determines the
    /// allowable contents of the object.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// The RFC 9396 §2.2 <c>locations</c> common field, or <see langword="null"/> when absent:
    /// an array of strings (typically URIs) naming the resource server(s) the authorization
    /// applies to.
    /// </summary>
    public IReadOnlyList<string>? Locations { get; init; }

    /// <summary>
    /// The RFC 9396 §2.2 <c>actions</c> common field, or <see langword="null"/> when absent: an
    /// array of strings naming the kinds of actions to be taken at the resource.
    /// </summary>
    public IReadOnlyList<string>? Actions { get; init; }

    /// <summary>
    /// The RFC 9396 §2.2 <c>datatypes</c> common field, or <see langword="null"/> when absent:
    /// an array of strings naming the kinds of data being requested from the resource.
    /// </summary>
    public IReadOnlyList<string>? DataTypes { get; init; }

    /// <summary>
    /// The RFC 9396 §2.2 <c>identifier</c> common field, or <see langword="null"/> when absent:
    /// a string identifying a specific resource available at the API.
    /// </summary>
    public string? Identifier { get; init; }

    /// <summary>
    /// The RFC 9396 §2.2 <c>privileges</c> common field, or <see langword="null"/> when absent:
    /// an array of strings naming the types or levels of privilege being requested at the
    /// resource.
    /// </summary>
    public IReadOnlyList<string>? Privileges { get; init; }

    /// <summary>
    /// The type-specific members not covered by <see cref="Type"/> or the §2.2 common fields,
    /// keyed by JSON member name, each value the raw JSON text of that member's value. Empty
    /// when the object carries only common fields. The registered handler for the
    /// <see cref="Type"/> reads its own fields from here.
    /// </summary>
    public IReadOnlyDictionary<string, string> ExtensionData { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// The names of the §2.2 common fields that were present on the wire but carried the wrong
    /// JSON type for the field (<c>locations</c>/<c>actions</c>/<c>datatypes</c>/<c>privileges</c>
    /// not an array of strings, or <c>identifier</c> not a string), so the parser could not
    /// promote them to their typed slots. Empty when every present common field had the correct
    /// type. A wrong-typed common field is an RFC 9396 §5 abort cause ("contains fields of the
    /// wrong type for the authorization details type") that a handler validating its type
    /// strictly refuses; the <c>openid_credential</c> profile is lenient and ignores it (the slot
    /// is simply left unset, as if the field were absent).
    /// </summary>
    public IReadOnlyList<string> MalformedCommonFields { get; init; } = [];
}
