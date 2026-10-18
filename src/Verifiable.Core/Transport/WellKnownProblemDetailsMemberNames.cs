using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Transport;

/// <summary>
/// The member NAMES of an RFC 9457 problem details object with UTF-8 twins.
/// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1">RFC 9457 §3.1</see> defines the members a problem
/// details object carries; the problem type VALUES live in <see cref="WellKnownProblemTypes"/>.
/// </summary>
/// <remarks>
/// Only the members the library reads are listed; another member enters here when a reader needs it.
/// </remarks>
public static class WellKnownProblemDetailsMemberNames
{
    /// <summary>The UTF-8 source literal of <see cref="Type"/>.</summary>
    public static ReadOnlySpan<byte> TypeUtf8 => "type"u8;

    /// <summary>
    /// The <c>type</c> member.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>: "The "type" member is a
    /// JSON string containing a URI reference that identifies the problem type."
    /// </summary>
    public static string Type { get; } = Utf8Constants.ToInternedString(TypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Detail"/>.</summary>
    public static ReadOnlySpan<byte> DetailUtf8 => "detail"u8;

    /// <summary>
    /// The <c>detail</c> member.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.4">RFC 9457 §3.1.4</see>: "The "detail" member is a
    /// JSON string containing a human-readable explanation specific to this occurrence of the problem."
    /// </summary>
    public static string Detail { get; } = Utf8Constants.ToInternedString(DetailUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Instance"/>.</summary>
    public static ReadOnlySpan<byte> InstanceUtf8 => "instance"u8;

    /// <summary>
    /// The <c>instance</c> member.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.5">RFC 9457 §3.1.5</see>: "The "instance" member is a
    /// JSON string containing a URI reference that identifies the specific occurrence of the problem."
    /// </summary>
    public static string Instance { get; } = Utf8Constants.ToInternedString(InstanceUtf8);
}
