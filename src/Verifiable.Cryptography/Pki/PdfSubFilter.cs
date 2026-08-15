using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The identity of the <c>SubFilter</c> entry of a PDF Signature Dictionary — the PDF Name that states which
/// signature-encoding convention the <c>Contents</c> hexadecimal string follows
/// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 5.3, PA-5.3-01).
/// </summary>
/// <remarks>
/// An open wire-value wrapper rather than an enumeration, mirroring <see cref="SignatureFormatIdentifier"/>:
/// ISO 32000-1 clause 12.8.1 lets a developer register further <c>SubFilter</c> values under its own annex E
/// prefix convention (the Document Time-stamp dictionary's own entry, PA-5.4.3's table, states this explicitly
/// for its <c>ETSI.RFC3161</c> value — "Other values may be defined by developers"), so the closed set this
/// library recognises grows without this type changing. <see cref="EtsiCAdESDetached"/> is the one value
/// currently named; further values join this set as the need arises.
/// </remarks>
/// <param name="Value">The <c>SubFilter</c> Name's identity, without the leading <c>/</c> delimiter.</param>
[DebuggerDisplay("PdfSubFilter: {Value}")]
public readonly record struct PdfSubFilter(string Value)
{
    /// <summary>
    /// The <c>ETSI.CAdES.detached</c> <c>SubFilter</c> value clause 6.3 requirement l) requires of every PAdES
    /// baseline signature: "The Signature Dictionary shall contain a value of ETSI.CAdES.detached for the key
    /// SubFilter" (PA-6.3-l) — the value that identifies the <c>Contents</c> hexadecimal string as a detached
    /// CAdES <c>SignedData</c> object (PA-4.1-01, PA-6.3-h).
    /// </summary>
    public static PdfSubFilter EtsiCAdESDetached { get; } = new("ETSI.CAdES.detached");

    /// <summary>
    /// The <c>ETSI.RFC3161</c> <c>SubFilter</c> value clause 5.4.3's own table states as the Document Time-stamp
    /// dictionary's recommended value (PA-5.4.3-03, "should be ETSI.RFC3161") and clause 6.3 requirement y) makes
    /// mandatory for every PAdES baseline document-time-stamp ("The value of SubFilter shall be ETSI.RFC3161",
    /// PA-6.3-y) — the value that identifies <c>Contents</c> as an RFC 3161 <c>TimeStampToken</c> (PA-5.4.3-05).
    /// </summary>
    public static PdfSubFilter EtsiRfc3161 { get; } = new("ETSI.RFC3161");
}
