using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Byte-assembles minimal PDF documents carrying one or more PAdES-shaped Signature Dictionaries, entirely
/// independently of <see cref="Verifiable.Cryptography.Pki.PdfByteSurfaceReader"/> (the independent-oracle
/// discipline this project's fixture builders follow throughout — see <c>AsicZipStructureOracle</c> and
/// <c>CmsStructureOracle</c> for the precedent). Every byte offset, every <c>ByteRange</c> number, and every
/// cross-reference entry this builder writes is computed here, from the bytes it itself wrote, never by asking
/// the reader anything.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The fixed-width placeholder trick.</strong> A signature's own <c>ByteRange</c> names byte offsets
/// that depend on the document's total length, which is not known until the whole document — including the
/// <c>ByteRange</c> array's own rendered text — has been written. This builder resolves the circularity the way
/// real PAdES signing tools do: every <c>ByteRange</c> number is rendered zero-padded to a fixed
/// <see cref="ByteRangeFieldWidth"/>-digit width up front (so its total rendered length never changes), and once
/// the document's true length is known the placeholder digits are overwritten in place with the correct values —
/// same byte count in, same byte count out, so no offset written afterward shifts.
/// </para>
/// <para>
/// <strong>Delimiter convention.</strong> ISO 32000-1 clause 12.8.1 defines the <c>ByteRange</c> gap as covering
/// the signature value itself, "excluding the signature value (the Contents entry)" — the gap excludes the
/// ENTIRE <c>Contents</c> string value, its own <c>&lt;</c>/<c>&gt;</c> delimiters included, not merely the
/// hexadecimal digits between them. This builder's own <c>ByteRange</c> arithmetic is derived from that spec
/// text directly, never from <see cref="Verifiable.Cryptography.Pki.PdfByteSurfaceReader"/>'s own reading of it
/// (the independent-oracle discipline this class's own remarks describe above).
/// </para>
/// </remarks>
internal static class PdfFixtureBuilder
{
    /// <summary>The zero-padded digit width every <c>ByteRange</c> number is rendered at.</summary>
    private const int ByteRangeFieldWidth = 10;


    /// <summary>Where one signature's placeholder <c>ByteRange</c> array and <c>Contents</c> hex digits landed while this builder assembled the document.</summary>
    /// <param name="ByteRangeArrayOffset">The byte offset at which the <c>ByteRange</c> array's rendered text (opening <c>[</c> included) begins.</param>
    /// <param name="ContentsHexStart">The byte offset of the first <c>Contents</c> hexadecimal digit (just after the opening <c>&lt;</c>).</param>
    /// <param name="ContentsHexEnd">The byte offset just past the last <c>Contents</c> hexadecimal digit (at the closing <c>&gt;</c>).</param>
    internal readonly record struct SignatureLocation(int ByteRangeArrayOffset, int ContentsHexStart, int ContentsHexEnd);


    /// <summary>A single-revision signed PDF this builder assembled.</summary>
    /// <param name="Bytes">The whole document's bytes, with its <c>ByteRange</c> already patched to the true values.</param>
    /// <param name="Signature">Where the signature's own fields landed.</param>
    /// <param name="XrefOffset">The byte offset of this revision's own <c>xref</c> keyword — the value an incremental update built on top of this revision states as its own trailer's <c>/Prev</c>.</param>
    internal sealed record SingleUpdateFixture(byte[] Bytes, SignatureLocation Signature, int XrefOffset);


    /// <summary>A two-revision signed PDF — a base revision plus one incremental update, each carrying its own signature.</summary>
    /// <param name="Bytes">The whole document's bytes, both signatures' <c>ByteRange</c>s already patched to their own revision's true values.</param>
    /// <param name="FirstSignature">The base revision's signature location; its <c>ByteRange</c> covers only the base revision's own (shorter) length.</param>
    /// <param name="SecondSignature">The incremental update's signature location; its <c>ByteRange</c> covers the whole final document.</param>
    internal sealed record IncrementalUpdateFixture(byte[] Bytes, SignatureLocation FirstSignature, SignatureLocation SecondSignature);


    /// <summary>
    /// Builds a minimal single-revision PDF carrying one PAdES-shaped signature dictionary as object 2 (object 1
    /// is a placeholder catalog the trailer's <c>/Root</c> names but this builder never resolves).
    /// </summary>
    public static SingleUpdateFixture BuildSingleUpdateSignedPdf(
        byte[] contentsPayload,
        string filter = "Adobe.PPKLite",
        string subFilter = "ETSI.CAdES.detached",
        string? signingTime = "D:20250314120000+02'00'",
        string? location = "Helsinki",
        string? reason = "Testing",
        string? contactInfo = "test@example.com",
        string? name = "Test Signer")
    {
        var writer = new List<byte>();
        AppendAscii(writer, "%PDF-1.7\n");

        int obj1Offset = writer.Count;
        AppendAscii(writer, "1 0 obj\n<< /Type /Catalog >>\nendobj\n");

        int obj2Offset = writer.Count;
        SignatureLocation placeholder = AppendSignatureObject(writer, 2, contentsPayload, filter, subFilter, signingTime, location, reason, contactInfo, name);

        int xrefOffset = writer.Count;
        AppendAscii(writer, "xref\n0 3\n");
        AppendAscii(writer, "0000000000 65535 f \n");
        AppendAscii(writer, $"{obj1Offset.ToString("D10", CultureInfo.InvariantCulture)} 00000 n \n");
        AppendAscii(writer, $"{obj2Offset.ToString("D10", CultureInfo.InvariantCulture)} 00000 n \n");
        AppendAscii(writer, "trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n");
        AppendAscii(writer, xrefOffset.ToString(CultureInfo.InvariantCulture));
        AppendAscii(writer, "\n%%EOF\n");

        byte[] bytes = [.. writer];
        SignatureLocation patched = PatchByteRange(bytes, placeholder, bytes.Length);

        return new SingleUpdateFixture(bytes, patched, xrefOffset);
    }


    /// <summary>
    /// Builds a two-revision PDF: <see cref="BuildSingleUpdateSignedPdf"/>'s own output as the base revision,
    /// plus one incremental update appending a second, independent signature (object 3) whose own
    /// cross-reference section names only the new object and whose trailer's <c>/Prev</c> chains back to the
    /// base revision's own <c>xref</c> — the shape PAdES signing tools produce when a second party countersigns
    /// (or the same signer re-applies) a document without disturbing the first signature's own covered bytes.
    /// </summary>
    public static IncrementalUpdateFixture BuildIncrementalUpdateSignedPdf(
        byte[] firstContentsPayload,
        byte[] secondContentsPayload,
        string filter = "Adobe.PPKLite",
        string subFilter = "ETSI.CAdES.detached")
    {
        SingleUpdateFixture revision1 = BuildSingleUpdateSignedPdf(
            firstContentsPayload, filter, subFilter, "D:20250314120000+02'00'", "Helsinki", "First signature", "first@example.com", "First Signer");

        var writer = new List<byte>(revision1.Bytes);

        int obj3Offset = writer.Count;
        SignatureLocation placeholder = AppendSignatureObject(
            writer, 3, secondContentsPayload, filter, subFilter, "D:20250401090000Z", "Espoo", "Second signature", "second@example.com", "Second Signer");

        int xref2Offset = writer.Count;
        AppendAscii(writer, "xref\n3 1\n");
        AppendAscii(writer, $"{obj3Offset.ToString("D10", CultureInfo.InvariantCulture)} 00000 n \n");
        AppendAscii(writer, $"trailer\n<< /Size 4 /Root 1 0 R /Prev {revision1.XrefOffset.ToString(CultureInfo.InvariantCulture)} >>\nstartxref\n");
        AppendAscii(writer, xref2Offset.ToString(CultureInfo.InvariantCulture));
        AppendAscii(writer, "\n%%EOF\n");

        byte[] bytes = [.. writer];
        SignatureLocation patchedSecond = PatchByteRange(bytes, placeholder, bytes.Length);

        //The first signature's own bytes -- including its own already-patched ByteRange -- are untouched by the
        //append, so revision1.Signature's offsets are still exactly correct against the longer, final buffer.
        return new IncrementalUpdateFixture(bytes, revision1.Signature, patchedSecond);
    }


    /// <summary>Overwrites a signature's placeholder <c>ByteRange</c> in place with the correct values for the two segments bracketing its <c>Contents</c> hex digits, given the document's final length.</summary>
    /// <param name="bytes">The whole document's bytes, mutated in place.</param>
    /// <param name="placeholder">Where the placeholder was written.</param>
    /// <param name="documentLength">The document's true final length.</param>
    /// <returns>The same location (offsets do not move; only the array's digits change).</returns>
    public static SignatureLocation PatchByteRange(byte[] bytes, SignatureLocation placeholder, int documentLength)
    {
        //ISO 32000-1 clause 12.8.1: the gap excludes the entire Contents string value, '<'/'>' delimiters
        //included (the class remarks above).
        int firstLength = placeholder.ContentsHexStart - 1;
        int secondOffset = placeholder.ContentsHexEnd + 1;
        int secondLength = documentLength - secondOffset;

        WriteByteRangeArray(bytes, placeholder.ByteRangeArrayOffset, 0, firstLength, secondOffset, secondLength);

        return placeholder;
    }


    /// <summary>Overwrites a signature's <c>ByteRange</c> with a deliberately overlapping pair of segments (the second starting before the first ends), for the reader's fail-closed negative.</summary>
    public static void CorruptByteRangeToOverlap(byte[] bytes, SignatureLocation location)
    {
        int firstLength = location.ContentsHexStart - 1;

        //The second segment starts one byte before the first one ends -- a one-byte overlap, deliberately small
        //so the corruption is unambiguous rather than accidentally landing on some other valid shape.
        WriteByteRangeArray(bytes, location.ByteRangeArrayOffset, 0, firstLength, firstLength - 1, 1);
    }


    /// <summary>Overwrites a signature's <c>ByteRange</c> so its gap no longer sits over the <c>Contents</c> string it actually names, for the reader's fail-closed negative.</summary>
    public static void CorruptByteRangeToMissTheContentsGap(byte[] bytes, SignatureLocation location, int documentLength)
    {
        //Shifts the second segment two bytes later than the true value: the gap now ends two bytes past the
        //actual closing '>', so Contents no longer sits exactly inside the declared gap, while the ByteRange
        //itself remains internally well-formed (non-overlapping, in-bounds, covering the whole document) -- the
        //corruption isolates the Contents-alignment check specifically.
        int firstLength = location.ContentsHexStart - 1;
        int secondOffset = location.ContentsHexEnd + 1 + 2;
        int secondLength = documentLength - secondOffset;

        WriteByteRangeArray(bytes, location.ByteRangeArrayOffset, 0, firstLength, secondOffset, secondLength);
    }


    /// <summary>
    /// Overwrites a signature's <c>ByteRange</c> using the OLD, WRONG gap convention -- the gap excludes only the
    /// <c>Contents</c> hexadecimal digits, leaving the opening <c>&lt;</c> inside the first signed segment and the
    /// closing <c>&gt;</c> inside the second -- pinning the fix in the rejecting direction:
    /// <see cref="Verifiable.Cryptography.Pki.PdfByteSurfaceReader"/> must reject this shape now that ISO 32000-1
    /// clause 12.8.1 requires the delimiters excluded too.
    /// </summary>
    public static void CorruptByteRangeToTheOldHexDigitsOnlyGapConvention(byte[] bytes, SignatureLocation location, int documentLength)
    {
        int firstLength = location.ContentsHexStart;
        int secondOffset = location.ContentsHexEnd;
        int secondLength = documentLength - secondOffset;

        WriteByteRangeArray(bytes, location.ByteRangeArrayOffset, 0, firstLength, secondOffset, secondLength);
    }


    /// <summary>
    /// Appends a further, unsigned incremental-update revision on top of an already-signed document: one benign
    /// object plus a new cross-reference section and trailer chaining <c>/Prev</c> back to the prior revision --
    /// content that lands after the newest signature's own <c>ByteRange</c> coverage without introducing any new
    /// Signature Dictionary, exactly the append (shadow) attack PA-6.3-k's coverage rule exists to catch.
    /// </summary>
    /// <param name="priorBytes">The whole bytes of the already-signed revision to append on top of.</param>
    /// <param name="priorXrefOffset">The byte offset of <paramref name="priorBytes"/>' own <c>xref</c> keyword, the new revision's own trailer <c>/Prev</c> value.</param>
    /// <param name="objectNumber">The appended object's own number — a fresh number by default (never before decided), or an existing one (e.g. <c>1</c>, the document catalog) to shape a redefinition attack instead.</param>
    /// <param name="objectBody">The appended object's own dictionary body, verbatim (e.g. <c>"&lt;&lt; /Type /Metadata &gt;&gt;"</c>).</param>
    public static byte[] AppendUnsignedIncrementalUpdate(
        byte[] priorBytes, int priorXrefOffset, int objectNumber = 1000, string objectBody = "<< /Type /Metadata >>")
    {
        var writer = new List<byte>(priorBytes);

        int objectOffset = writer.Count;
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"{objectNumber} 0 obj\n{objectBody}\nendobj\n"));

        int xrefOffset = writer.Count;
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"xref\n{objectNumber} 1\n"));
        AppendAscii(writer, $"{objectOffset.ToString("D10", CultureInfo.InvariantCulture)} 00000 n \n");
        AppendAscii(writer, string.Create(
            CultureInfo.InvariantCulture,
            $"trailer\n<< /Size {Math.Max(objectNumber + 1, 1001)} /Root 1 0 R /Prev {priorXrefOffset} >>\nstartxref\n"));
        AppendAscii(writer, xrefOffset.ToString(CultureInfo.InvariantCulture));
        AppendAscii(writer, "\n%%EOF\n");

        return [.. writer];
    }


    /// <summary>
    /// Appends a further incremental-update revision introducing a decoy object shaped like a Signature Dictionary
    /// (carrying both <c>ByteRange</c> and <c>Contents</c>) but structurally malformed (a five-element
    /// <c>ByteRange</c>) -- a candidate <see cref="Verifiable.Cryptography.Pki.PdfByteSurfaceReader"/> must skip
    /// rather than let sink a document's own genuinely valid signature(s).
    /// </summary>
    /// <param name="priorBytes">The whole bytes of the already-signed revision to append on top of.</param>
    /// <param name="priorXrefOffset">The byte offset of <paramref name="priorBytes"/>' own <c>xref</c> keyword, the new revision's own trailer <c>/Prev</c> value.</param>
    /// <param name="objectNumber">The decoy's own object number, chosen well above any object number a fixture built by this class ever uses.</param>
    public static byte[] AppendMalformedDecoySignatureObject(byte[] priorBytes, int priorXrefOffset, int objectNumber = 999)
    {
        var writer = new List<byte>(priorBytes);

        int objectOffset = writer.Count;
        AppendAscii(writer, string.Create(
            CultureInfo.InvariantCulture,
            $"{objectNumber} 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0 0 0 0 0] /Contents <00> >>\nendobj\n"));

        int xrefOffset = writer.Count;
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"xref\n{objectNumber} 1\n"));
        AppendAscii(writer, $"{objectOffset.ToString("D10", CultureInfo.InvariantCulture)} 00000 n \n");
        AppendAscii(writer, string.Create(
            CultureInfo.InvariantCulture,
            $"trailer\n<< /Size {objectNumber + 1} /Root 1 0 R /Prev {priorXrefOffset} >>\nstartxref\n"));
        AppendAscii(writer, xrefOffset.ToString(CultureInfo.InvariantCulture));
        AppendAscii(writer, "\n%%EOF\n");

        return [.. writer];
    }


    /// <summary>Overwrites the classic <c>xref</c> keyword at a known offset with bytes that are not a valid cross-reference section header, for the reader's fail-closed negative.</summary>
    public static void CorruptXrefKeyword(byte[] bytes, int xrefOffset)
    {
        byte[] garbage = "XREF"u8.ToArray();
        garbage.CopyTo(bytes, xrefOffset);
    }


    private static void WriteByteRangeArray(byte[] bytes, int offset, int first, int firstLength, int second, int secondLength)
    {
        string rendered = FormatByteRangeArray(first, firstLength, second, secondLength);
        byte[] renderedBytes = Encoding.ASCII.GetBytes(rendered);
        renderedBytes.CopyTo(bytes, offset);
    }


    private static string FormatByteRangeArray(int first, int firstLength, int second, int secondLength) =>
        $"[{Pad(first)} {Pad(firstLength)} {Pad(second)} {Pad(secondLength)}]";


    private static string Pad(int value) => value.ToString("D" + ByteRangeFieldWidth.ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);


    private static SignatureLocation AppendSignatureObject(
        List<byte> writer,
        int objectNumber,
        byte[] contentsPayload,
        string filter,
        string subFilter,
        string? signingTime,
        string? location,
        string? reason,
        string? contactInfo,
        string? name)
    {
        AppendAscii(writer, $"{objectNumber.ToString(CultureInfo.InvariantCulture)} 0 obj\n<< /Type /Sig /Filter /{filter} /SubFilter /{subFilter} /ByteRange ");

        int byteRangeArrayOffset = writer.Count;
        AppendAscii(writer, FormatByteRangeArray(0, 0, 0, 0));

        AppendAscii(writer, " /Contents <");
        int contentsHexStart = writer.Count;
        AppendAscii(writer, Convert.ToHexString(contentsPayload));
        int contentsHexEnd = writer.Count;
        AppendAscii(writer, ">");

        if(signingTime is not null)
        {
            AppendAscii(writer, $" /M ({EscapeLiteral(signingTime)})");
        }

        if(location is not null)
        {
            AppendAscii(writer, $" /Location ({EscapeLiteral(location)})");
        }

        if(reason is not null)
        {
            AppendAscii(writer, $" /Reason ({EscapeLiteral(reason)})");
        }

        if(contactInfo is not null)
        {
            AppendAscii(writer, $" /ContactInfo ({EscapeLiteral(contactInfo)})");
        }

        if(name is not null)
        {
            AppendAscii(writer, $" /Name ({EscapeLiteral(name)})");
        }

        AppendAscii(writer, " >>\nendobj\n");

        return new SignatureLocation(byteRangeArrayOffset, contentsHexStart, contentsHexEnd);
    }


    private static string EscapeLiteral(string text) => text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("(", "\\(", StringComparison.Ordinal).Replace(")", "\\)", StringComparison.Ordinal);


    private static void AppendAscii(List<byte> writer, string text) => writer.AddRange(Encoding.ASCII.GetBytes(text));
}
