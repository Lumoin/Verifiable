using System.Globalization;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Mcp;

/// <summary>
/// A protocol revision's text, compared ordinally by record equality.
/// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">Case Sensitivity</see>:
/// "Header values (such as method names) are case-sensitive."
/// </summary>
/// <remarks>
/// MCP 2026-07-28 is the current revision.
/// <see cref="Parse"/> accepts an invariant Gregorian date in exactly YYYY-MM-DD form as
/// a local syntax contract; success does not establish support for that revision.
/// The default value has a null <see cref="Text"/> and names no revision.
/// </remarks>
public readonly record struct McpProtocolRevision
{
    /// <summary>
    /// The validated spelling retained by <see cref="Parse"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#protocol-version-negotiation">Version negotiation</see>:
    /// "Every request declares the protocol version it is using in its _meta field."
    /// </summary>
    public string? Text { get; }


    /// <summary>
    /// Constructs a revision after <see cref="Parse"/> has checked its local date syntax.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#protocol-version-negotiation">Version negotiation</see>:
    /// "Every request declares the protocol version it is using in its _meta field."
    /// </summary>
    /// <param name="text">The validated revision spelling.</param>
    private McpProtocolRevision(string text)
    {
        Text = text;
    }


    /// <summary>
    /// The UTF-8 source of <see cref="Revision20260728Text"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#terminology">Terminology</see>:
    /// "revision 2026-07-28 and later".
    /// </summary>
    public static ReadOnlySpan<byte> Revision20260728TextUtf8 => "2026-07-28"u8;

    /// <summary>
    /// The interned spelling derived from <see cref="Revision20260728TextUtf8"/> and carried by <see cref="Revision20260728"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#terminology">Terminology</see>:
    /// "revision 2026-07-28 and later".
    /// </summary>
    public static string Revision20260728Text { get; } = Utf8Constants.ToInternedString(Revision20260728TextUtf8);


    /// <summary>
    /// The current revision, whose <see cref="Text"/> is interned from <see cref="Revision20260728TextUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#terminology">Terminology</see>:
    /// "revision 2026-07-28 and later".
    /// </summary>
    public static McpProtocolRevision Revision20260728 { get; } = new(Revision20260728Text);


    /// <summary>
    /// The UTF-8 source of <see cref="Revision20251125Text"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#terminology">Terminology</see>:
    /// "2025-11-25 and earlier".
    /// </summary>
    public static ReadOnlySpan<byte> Revision20251125TextUtf8 => "2025-11-25"u8;

    /// <summary>
    /// The interned spelling derived from <see cref="Revision20251125TextUtf8"/> and carried by <see cref="Revision20251125"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#terminology">Terminology</see>:
    /// "2025-11-25 and earlier".
    /// </summary>
    public static string Revision20251125Text { get; } = Utf8Constants.ToInternedString(Revision20251125TextUtf8);


    /// <summary>
    /// The initialization-based revision, with <see cref="Text"/> interned from <see cref="Revision20251125TextUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#terminology">Terminology</see>:
    /// "2025-11-25 and earlier".
    /// </summary>
    public static McpProtocolRevision Revision20251125 { get; } = new(Revision20251125Text);


    /// <summary>
    /// Parses exactly YYYY-MM-DD into a revision or <see cref="McpProtocolRevisionParseError.InvalidFormat"/>, without throwing for input.
    /// This local contract requires ASCII digits and a valid Gregorian date; an unknown date may succeed.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#protocol-version-negotiation">Version negotiation</see>:
    /// "Every request declares the protocol version it is using in its _meta field."
    /// </summary>
    /// <param name="text">The received revision spelling, including a possible null value.</param>
    /// <returns>A success containing the unchanged spelling or a typed syntax failure.</returns>
    public static Result<McpProtocolRevision, McpProtocolRevisionParseError> Parse(string? text)
    {
        if(!DateOnly.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
        {
            return Result.Failure<McpProtocolRevision, McpProtocolRevisionParseError>(McpProtocolRevisionParseError.InvalidFormat);
        }

        return Result.Success<McpProtocolRevision, McpProtocolRevisionParseError>(new(text));
    }
}


/// <summary>
/// A local syntax failure returned by <see cref="McpProtocolRevision.Parse"/>.
/// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#protocol-version-negotiation">Version negotiation</see>:
/// "Every request declares the protocol version it is using in its _meta field."
/// </summary>
public enum McpProtocolRevisionParseError
{
    /// <summary>
    /// The input does not satisfy the local YYYY-MM-DD Gregorian-date contract of <see cref="McpProtocolRevision.Parse"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#protocol-version-negotiation">Version negotiation</see>:
    /// "Every request declares the protocol version it is using in its _meta field."
    /// </summary>
    InvalidFormat
}
