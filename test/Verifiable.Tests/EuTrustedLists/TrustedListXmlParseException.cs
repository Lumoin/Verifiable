using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki.Xml;

/// <summary>
/// A Trusted List XML document could not be parsed into the <see cref="TrustedList"/> model: it was not
/// well-formed, was missing an element ETSI TS 119 612 V2.4.1 clause 5 requires, or a criteria-list tree
/// nested deeper than <see cref="TrustedListXmlParser"/> supports for untrusted input.
/// </summary>
/// <remarks>
/// <see cref="TrustedListXmlParser.ParseAsync"/> catches every instance of this type at its boundary and
/// converts it to a <see cref="TrustedListParseResult.Failed(TrustedListParseStatus, string)"/> result — this
/// type never escapes the parser as a thrown exception; it exists so the parser's many extraction helpers can
/// fail closed with a `throw` from deep inside a nested read rather than threading a status code back through
/// every call.
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code (layering-split-ledger.md): public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
public sealed class TrustedListXmlParseException: Exception
{
    /// <summary>
    /// The <see cref="TrustedListParseStatus"/> this failure maps to. Defaults to
    /// <see cref="TrustedListParseStatus.MissingRequiredElement"/> — the common case, a helper that
    /// constructs this exception via the parameterless or message-only constructors is reporting an absent
    /// required element unless it sets this explicitly (as the criteria-list depth guard does, for
    /// <see cref="TrustedListParseStatus.ExcessiveNesting"/>).
    /// </summary>
    public TrustedListParseStatus Status { get; init; } = TrustedListParseStatus.MissingRequiredElement;


    /// <summary>
    /// Initializes a new instance with no message.
    /// </summary>
    public TrustedListXmlParseException()
    {
    }


    /// <summary>
    /// Initializes a new instance with a message describing what the parser could not find or make sense of.
    /// </summary>
    /// <param name="message">A message describing the parse failure.</param>
    public TrustedListXmlParseException(string message): base(message)
    {
    }


    /// <summary>
    /// Initializes a new instance with a message and the specific <see cref="TrustedListParseStatus"/> it maps to.
    /// </summary>
    /// <param name="message">A message describing the parse failure.</param>
    /// <param name="status">The status this failure maps to.</param>
    public TrustedListXmlParseException(string message, TrustedListParseStatus status): base(message)
    {
        Status = status;
    }


    /// <summary>
    /// Initializes a new instance with a message and an inner exception describing the underlying failure.
    /// </summary>
    /// <param name="message">A message describing the parse failure.</param>
    /// <param name="innerException">The underlying XML or format failure, if any.</param>
    public TrustedListXmlParseException(string message, Exception innerException): base(message, innerException)
    {
    }
}
