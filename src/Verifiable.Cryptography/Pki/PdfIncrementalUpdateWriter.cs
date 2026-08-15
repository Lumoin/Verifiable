using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Where an existing PDF revision's own cross-reference chain and document catalog sit — everything
/// <see cref="PdfIncrementalUpdateWriter.AppendPlaceholderSignature"/> needs to append a new incremental-update
/// section on top of it without walking the document catalog itself (RP-1/RP-2: no general PDF object model).
/// </summary>
/// <remarks>
/// A caller producing the very first signature over a freshly built PDF already knows every value here, having
/// just written the document; a caller layering a further signature over one this writer already produced reads
/// them straight off <see cref="PdfSignaturePlaceholder.NextAnchor"/> rather than re-deriving anything.
/// </remarks>
public sealed record PdfIncrementalUpdateAnchor
{
    /// <summary>Gets the byte offset of the prior revision's own <c>startxref</c> target — the new revision's trailer <c>/Prev</c> value.</summary>
    public required int PriorXrefOffset { get; init; }

    /// <summary>Gets the prior revision's own trailer <c>/Size</c> — one past the highest object number already in use, and so the new signature object's own number.</summary>
    public required int PriorObjectCount { get; init; }

    /// <summary>Gets the document catalog's object number, named by the trailer <c>/Root</c> entry every revision restates.</summary>
    public required int RootObjectNumber { get; init; }

    /// <summary>Gets the document catalog's generation number. <c>0</c> for every catalog this writer's own callers produce.</summary>
    public int RootGeneration { get; init; }
}


/// <summary>
/// The Signature Dictionary field values <see cref="PdfIncrementalUpdateWriter.AppendPlaceholderSignature"/>
/// writes — the nine keys ETSI EN 319 142-1 clause 5.3 (PA-5.3-01) addresses, minus <c>Contents</c> and
/// <c>ByteRange</c> (which the placeholder trick computes) and <c>Filter</c>/<c>SubFilter</c> (which this
/// writer fixes to the values PA-6.3-l and this library's own normative scope require).
/// </summary>
public sealed record PdfSignatureFieldValues
{
    /// <summary>Gets the signature handler name written as the <c>Filter</c> key (PA-6.3-j: a verifier may substitute a different handler as long as it supports <c>SubFilter</c>).</summary>
    public string Filter { get; init; } = "Adobe.PPKLite";

    /// <summary>Gets the claimed UTC time written as the <c>M</c> key — PA-6.3-T12/g)'s mandatory carrier of the claimed signing time (never the CMS <c>signing-time</c> attribute, which PA-6.3-T13 forbids).</summary>
    public required DateTimeOffset SigningTime { get; init; }

    /// <summary>Gets the <c>Location</c> key's text, or <see langword="null"/> to omit it.</summary>
    public string? Location { get; init; }

    /// <summary>Gets the <c>Reason</c> key's text, or <see langword="null"/> to omit it. PA-6.3-m1/m2 forbid this alongside a <c>commitment-type-indication</c> or <c>signature-policy-identifier</c> signed attribute; <see cref="PAdESSignatureCreation"/> enforces that cross-field rule.</summary>
    public string? Reason { get; init; }

    /// <summary>Gets the <c>ContactInfo</c> key's text, or <see langword="null"/> to omit it.</summary>
    public string? ContactInfo { get; init; }

    /// <summary>Gets the <c>Name</c> key's text, or <see langword="null"/> to omit it.</summary>
    public string? Name { get; init; }
}


/// <summary>
/// The result of <see cref="PdfIncrementalUpdateWriter.AppendPlaceholderSignature"/>: a whole PDF document
/// carrying one Signature Dictionary whose <c>ByteRange</c> already names the true, final segment offsets and
/// whose <c>Contents</c> is a run of <c>'0'</c> hexadecimal digits reserving the capacity a real signature will
/// be written into by <see cref="PdfIncrementalUpdateWriter.CompleteSignature"/>.
/// </summary>
public sealed record PdfSignaturePlaceholder
{
    /// <summary>Gets the whole document's bytes, <c>ByteRange</c> already patched to its true values, <c>Contents</c> still all-zero placeholder digits.</summary>
    public required byte[] Document { get; init; }

    /// <summary>Gets the placeholder's own <c>ByteRange</c> — the two segments <see cref="CompleteSignature"/>'s embedded signature is computed to cover.</summary>
    public required PdfByteRange ByteRange { get; init; }

    /// <summary>Gets the byte offset of the first <c>Contents</c> hexadecimal digit.</summary>
    public required int ContentsHexStart { get; init; }

    /// <summary>Gets the byte offset just past the last <c>Contents</c> hexadecimal digit (at the closing <c>&gt;</c>).</summary>
    public required int ContentsHexEnd { get; init; }

    /// <summary>Gets the byte offset of this revision's own <c>xref</c> keyword, for chaining a further incremental update's own <c>/Prev</c>.</summary>
    public required int XrefOffset { get; init; }

    /// <summary>Gets the new Signature Dictionary's own object number.</summary>
    public required int SignatureObjectNumber { get; init; }

    /// <summary>Gets the anchor a further incremental update built on top of this one supplies to its own <see cref="PdfIncrementalUpdateWriter.AppendPlaceholderSignature"/> call.</summary>
    public PdfIncrementalUpdateAnchor NextAnchor(int rootObjectNumber, int rootGeneration = 0) => new()
    {
        PriorXrefOffset = XrefOffset,
        PriorObjectCount = SignatureObjectNumber + 1,
        RootObjectNumber = rootObjectNumber,
        RootGeneration = rootGeneration
    };
}


/// <summary>
/// The minimal PDF incremental-update writer: the production twin of <see cref="PdfByteSurfaceReader"/>, minting
/// exactly the byte-surface a PAdES Signature Dictionary needs (ETSI EN 319 142-1 clause 5.3, PA-5.3-01) rather
/// than a general PDF authoring surface (RP-1/RP-2). Every value this writer emits is one
/// <see cref="PdfByteSurfaceReader"/> locates and <see cref="PdfByteRange"/> validates unchanged — the same
/// fixed-width placeholder trick <c>PdfFixtureBuilder</c> uses for its own, deliberately independent test
/// fixtures (the arc's oracle-independence discipline: this writer and that builder are two separate
/// implementations of the same convention, never one calling the other).
/// </summary>
/// <remarks>
/// <para>
/// <strong>The fixed-width placeholder trick.</strong> A signature's own <c>ByteRange</c> names byte offsets
/// that depend on the document's total length, which is not settled until the Signature Dictionary — including
/// the <c>ByteRange</c> array's own rendered text — has been written. <see cref="AppendPlaceholderSignature"/>
/// resolves the circularity by rendering every <c>ByteRange</c> number zero-padded to a fixed
/// <see cref="ByteRangeFieldWidth"/>-digit width up front, so the array's total rendered length never changes,
/// then overwrites the placeholder digits in place with the true values once the document's final length is
/// known — same byte count in, same byte count out, so no later offset shifts.
/// </para>
/// <para>
/// <strong><c>Contents</c> capacity is reserved, not measured.</strong> The CMS <c>SignedData</c> a real
/// signing operation produces is not known until after the digest over the placeholder's own
/// <c>ByteRange</c>-gapped segments has been signed — and that digest itself depends on the placeholder's total
/// length, which depends on the <c>Contents</c> capacity chosen. <see cref="AppendPlaceholderSignature"/> breaks
/// this circularity the way every byte-range PDF signing tool does: the caller reserves a capacity generous
/// enough for the final signature (larger for CAdES-B-T, whose <c>signature-time-stamp</c> unsigned attribute
/// adds a whole time-stamp token), and <see cref="CompleteSignature"/> zero-pads whatever is left once the real
/// signature is written — trailing zero octets past the DER-encoded <c>SignedData</c> value. This is a producer
/// convention, not a guarantee ETSI EN 319 142-1 itself states anywhere (no clause of that document sanctions
/// trailing padding past <c>Contents</c>' own decoded value); what this library has traced is narrower and
/// concrete: all three of its own shipped CMS backends — Microsoft, BouncyCastle, and the fully managed
/// <see cref="ManagedCmsVerification"/> reader — decode <c>SignedData</c> correctly regardless of trailing zero
/// octets, since ASN.1 DER decoding is driven by the structure's own length prefixes, not by the buffer's length.
/// </para>
/// </remarks>
public static class PdfIncrementalUpdateWriter
{
    /// <summary>The zero-padded digit width every <c>ByteRange</c> number is rendered at, mirroring the reader's own tolerance for arbitrary-width integers and <c>PdfFixtureBuilder</c>'s independent choice of the same width.</summary>
    private const int ByteRangeFieldWidth = 10;


    /// <summary>
    /// Appends a placeholder Signature Dictionary as a new incremental-update revision on top of an existing
    /// PDF document, with its <c>ByteRange</c> already patched to the true final segment offsets and its
    /// <c>Contents</c> reserved as <paramref name="contentsCapacityBytes"/> bytes of all-zero hexadecimal
    /// digits.
    /// </summary>
    /// <param name="priorDocument">The whole bytes of the revision the new signature is layered on top of.</param>
    /// <param name="anchor">Where the prior revision's own cross-reference chain and catalog sit.</param>
    /// <param name="fields">The Signature Dictionary field values to write.</param>
    /// <param name="contentsCapacityBytes">The number of raw signature bytes to reserve room for; must be at least as large as the final signature <see cref="CompleteSignature"/> will embed.</param>
    /// <returns>The placeholder document and everything needed to locate and complete its signature.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="anchor"/> or <paramref name="fields"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="contentsCapacityBytes"/> is not positive.</exception>
    /// <exception cref="ArgumentException">When <paramref name="anchor"/> names a negative offset or a non-positive object number.</exception>
    public static PdfSignaturePlaceholder AppendPlaceholderSignature(
        ReadOnlyMemory<byte> priorDocument,
        PdfIncrementalUpdateAnchor anchor,
        PdfSignatureFieldValues fields,
        int contentsCapacityBytes)
    {
        ArgumentNullException.ThrowIfNull(anchor);
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(contentsCapacityBytes);
        if(anchor.PriorXrefOffset < 0 || anchor.PriorObjectCount <= 0 || anchor.RootObjectNumber <= 0 || anchor.RootGeneration < 0)
        {
            throw new ArgumentException(
                "An incremental-update anchor names a non-negative prior xref offset, a positive prior object count, and a positive root object number.",
                nameof(anchor));
        }

        var writer = new List<byte>(priorDocument.Length + 512 + (contentsCapacityBytes * 2));
        AppendBytes(writer, priorDocument.Span);

        int signatureObjectNumber = anchor.PriorObjectCount;
        int signatureObjectOffset = writer.Count;
        AppendAscii(writer, string.Create(
            CultureInfo.InvariantCulture,
            $"{signatureObjectNumber} 0 obj\n<< /Type /Sig /Filter /{fields.Filter} /SubFilter /{PdfSubFilter.EtsiCAdESDetached.Value} /ByteRange "));

        int byteRangeOffset = writer.Count;
        AppendAscii(writer, FormatByteRangeArray(0, 0, 0, 0));
        AppendAscii(writer, " /Contents <");
        int contentsHexStart = writer.Count;
        AppendAscii(writer, new string('0', contentsCapacityBytes * 2));
        int contentsHexEnd = writer.Count;
        AppendAscii(writer, ">");
        AppendAscii(writer, $" /M ({EscapeLiteral(FormatPdfDate(fields.SigningTime))})");
        if(fields.Location is not null)
        {
            AppendAscii(writer, $" /Location ({EscapeLiteral(fields.Location)})");
        }

        if(fields.Reason is not null)
        {
            AppendAscii(writer, $" /Reason ({EscapeLiteral(fields.Reason)})");
        }

        if(fields.ContactInfo is not null)
        {
            AppendAscii(writer, $" /ContactInfo ({EscapeLiteral(fields.ContactInfo)})");
        }

        if(fields.Name is not null)
        {
            AppendAscii(writer, $" /Name ({EscapeLiteral(fields.Name)})");
        }

        AppendAscii(writer, " >>\nendobj\n");

        int xrefOffset = writer.Count;
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"xref\n{signatureObjectNumber} 1\n"));
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"{signatureObjectOffset:D10} 00000 n \n"));
        AppendAscii(writer, string.Create(
            CultureInfo.InvariantCulture,
            $"trailer\n<< /Size {signatureObjectNumber + 1} /Root {anchor.RootObjectNumber} {anchor.RootGeneration} R /Prev {anchor.PriorXrefOffset} >>\nstartxref\n"));
        AppendAscii(writer, xrefOffset.ToString(CultureInfo.InvariantCulture));
        AppendAscii(writer, "\n%%EOF\n");

        byte[] document = [.. writer];
        int documentLength = document.Length;
        //ISO 32000-1 clause 12.8.1's ByteRange gap excludes the signature value itself -- the whole Contents
        //string, its '<'/'>' delimiters included, not merely the hexadecimal digits between them (matching
        //PdfByteSurfaceReader's own reading of the same convention).
        int firstLength = contentsHexStart - 1;
        int secondOffset = contentsHexEnd + 1;
        int secondLength = documentLength - secondOffset;
        WriteByteRangeArray(document, byteRangeOffset, 0, firstLength, secondOffset, secondLength);

        Span<long> numbers = [0, firstLength, secondOffset, secondLength];
        if(!PdfByteRange.TryCreate(numbers, documentLength, out PdfByteRange byteRange, out string? error))
        {
            throw new InvalidOperationException($"The incremental-update writer produced an invalid ByteRange: {error}");
        }

        return new PdfSignaturePlaceholder
        {
            Document = document,
            ByteRange = byteRange,
            ContentsHexStart = contentsHexStart,
            ContentsHexEnd = contentsHexEnd,
            XrefOffset = xrefOffset,
            SignatureObjectNumber = signatureObjectNumber
        };
    }


    /// <summary>
    /// Appends a placeholder Document Time-stamp dictionary (ETSI EN 319 142-1 clause 5.4.3) as a new
    /// incremental-update revision, with the same fixed-width <c>ByteRange</c> placeholder trick
    /// <see cref="AppendPlaceholderSignature"/> uses for an ordinary Signature Dictionary — clause 5.4.3's own
    /// <c>ByteRange</c> sentence (PA-5.4.3-07) states the identical single-gap coverage, "the entire document,
    /// including the Document Time-stamp dictionary but excluding the TimeStampToken itself". The dictionary
    /// carries exactly the keys table 14's own modifications name (PA-5.4.3-02/-03/-04/-05/-08): <c>Type</c>
    /// <c>DocTimeStamp</c>, <c>SubFilter</c> <see cref="PdfSubFilter.EtsiRfc3161"/> (PA-6.3-y), <c>V</c> <c>0</c> —
    /// and never the keys PA-5.4.3-09/-10 name (<c>Cert</c>, <c>Reference</c>, <c>Changes</c>, <c>R</c>,
    /// <c>Prop_AuthTime</c>, <c>Prop_AuthType</c>, <c>Name</c>, <c>M</c>, <c>Location</c>, <c>Reason</c>,
    /// <c>ContactInfo</c>) since this method never writes them.
    /// </summary>
    /// <param name="priorDocument">The whole bytes of the revision the document time-stamp is layered on top of.</param>
    /// <param name="anchor">Where the prior revision's own cross-reference chain and catalog sit.</param>
    /// <param name="contentsCapacityBytes">The number of raw <c>TimeStampToken</c> bytes to reserve room for; must be at least as large as the final token <see cref="CompleteSignature"/> will embed.</param>
    /// <param name="filter">The signature handler name written as the <c>Filter</c> key — still required of the base Signature Dictionary shape table 14 modifies (ISO 32000-1 clause 12.8.1), unlisted among table 14's own changes.</param>
    /// <returns>The placeholder document and everything needed to locate and complete the time-stamp, reusing <see cref="PdfSignaturePlaceholder"/>'s own generic shape.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="anchor"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="contentsCapacityBytes"/> is not positive.</exception>
    /// <exception cref="ArgumentException">When <paramref name="anchor"/> names a negative offset or a non-positive object number.</exception>
    public static PdfSignaturePlaceholder AppendPlaceholderDocTimeStamp(
        ReadOnlyMemory<byte> priorDocument,
        PdfIncrementalUpdateAnchor anchor,
        int contentsCapacityBytes,
        string filter = "Adobe.PPKLite")
    {
        ArgumentNullException.ThrowIfNull(anchor);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(contentsCapacityBytes);
        if(anchor.PriorXrefOffset < 0 || anchor.PriorObjectCount <= 0 || anchor.RootObjectNumber <= 0 || anchor.RootGeneration < 0)
        {
            throw new ArgumentException(
                "An incremental-update anchor names a non-negative prior xref offset, a positive prior object count, and a positive root object number.",
                nameof(anchor));
        }

        var writer = new List<byte>(priorDocument.Length + 256 + (contentsCapacityBytes * 2));
        AppendBytes(writer, priorDocument.Span);

        int dictionaryObjectNumber = anchor.PriorObjectCount;
        int dictionaryObjectOffset = writer.Count;
        AppendAscii(writer, string.Create(
            CultureInfo.InvariantCulture,
            $"{dictionaryObjectNumber} 0 obj\n<< /Type /DocTimeStamp /Filter /{filter} /SubFilter /{PdfSubFilter.EtsiRfc3161.Value} /V 0 /ByteRange "));

        int byteRangeOffset = writer.Count;
        AppendAscii(writer, FormatByteRangeArray(0, 0, 0, 0));
        AppendAscii(writer, " /Contents <");
        int contentsHexStart = writer.Count;
        AppendAscii(writer, new string('0', contentsCapacityBytes * 2));
        int contentsHexEnd = writer.Count;
        AppendAscii(writer, ">");
        AppendAscii(writer, " >>\nendobj\n");

        int xrefOffset = writer.Count;
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"xref\n{dictionaryObjectNumber} 1\n"));
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"{dictionaryObjectOffset:D10} 00000 n \n"));
        AppendAscii(writer, string.Create(
            CultureInfo.InvariantCulture,
            $"trailer\n<< /Size {dictionaryObjectNumber + 1} /Root {anchor.RootObjectNumber} {anchor.RootGeneration} R /Prev {anchor.PriorXrefOffset} >>\nstartxref\n"));
        AppendAscii(writer, xrefOffset.ToString(CultureInfo.InvariantCulture));
        AppendAscii(writer, "\n%%EOF\n");

        byte[] document = [.. writer];
        int documentLength = document.Length;
        //PA-5.4.3-07: the same single-gap ByteRange coverage AppendPlaceholderSignature computes, excluding the
        //whole Contents string value, its '<'/'>' delimiters included.
        int firstLength = contentsHexStart - 1;
        int secondOffset = contentsHexEnd + 1;
        int secondLength = documentLength - secondOffset;
        WriteByteRangeArray(document, byteRangeOffset, 0, firstLength, secondOffset, secondLength);

        Span<long> numbers = [0, firstLength, secondOffset, secondLength];
        if(!PdfByteRange.TryCreate(numbers, documentLength, out PdfByteRange byteRange, out string? error))
        {
            throw new InvalidOperationException($"The incremental-update writer produced an invalid ByteRange: {error}");
        }

        return new PdfSignaturePlaceholder
        {
            Document = document,
            ByteRange = byteRange,
            ContentsHexStart = contentsHexStart,
            ContentsHexEnd = contentsHexEnd,
            XrefOffset = xrefOffset,
            SignatureObjectNumber = dictionaryObjectNumber
        };
    }


    /// <summary>
    /// Writes a real signature value into a placeholder's reserved <c>Contents</c> capacity, hexadecimal digits
    /// left-justified and the remainder zero-padded — the placeholder's <c>ByteRange</c> is untouched, since its
    /// segment offsets never depend on what the reserved gap's own digits state.
    /// </summary>
    /// <param name="placeholder">The placeholder to complete. Not mutated; the result is a new array.</param>
    /// <param name="signatureValue">The DER-encoded CMS <c>SignedData</c> to embed (PA-4.1-01/PA-6.3-h).</param>
    /// <returns>The whole signed document's bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="placeholder"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="signatureValue"/> is empty or exceeds the placeholder's reserved <c>Contents</c> capacity.</exception>
    public static byte[] CompleteSignature(PdfSignaturePlaceholder placeholder, ReadOnlyMemory<byte> signatureValue)
    {
        ArgumentNullException.ThrowIfNull(placeholder);
        if(signatureValue.IsEmpty)
        {
            throw new ArgumentException("A completed PAdES signature embeds a non-empty CMS SignedData.", nameof(signatureValue));
        }

        int capacityBytes = (placeholder.ContentsHexEnd - placeholder.ContentsHexStart) / 2;
        if(signatureValue.Length > capacityBytes)
        {
            throw new ArgumentException(
                $"The signature ({signatureValue.Length} bytes) does not fit the placeholder's reserved Contents capacity ({capacityBytes} bytes); request a larger contentsCapacityBytes.",
                nameof(signatureValue));
        }

        byte[] document = (byte[])placeholder.Document.Clone();
        string hex = Convert.ToHexString(signatureValue.Span);
        for(int i = 0; i < hex.Length; ++i)
        {
            document[placeholder.ContentsHexStart + i] = (byte)hex[i];
        }

        int padStart = placeholder.ContentsHexStart + hex.Length;
        int padLength = placeholder.ContentsHexEnd - padStart;
        for(int i = 0; i < padLength; ++i)
        {
            document[padStart + i] = (byte)'0';
        }

        return document;
    }


    /// <summary>
    /// Appends a document's DSS dictionary (clause 5.4.2.2) and, optionally, its Signature VRI dictionaries
    /// (clause 5.4.2.3) as one new incremental-update revision: every certificate/CRL/OCSP-response supplied is
    /// written as its own stream object, each VRI entry references the subset it names by index into those same
    /// streams (making PA-5.4.2.3-17 true by construction), the DSS dictionary references every stream plus every
    /// VRI dictionary, and the document catalog is rewritten with a <c>DSS</c> entry appended (PA-5.4.2.1-T1) —
    /// its own existing entries copied byte-for-byte from <see cref="PdfDssPlacementRequest.Catalog"/>, never
    /// re-parsed or re-serialized.
    /// </summary>
    /// <param name="request">The prior document, where its catalog sits, and the validation material to place.</param>
    /// <returns>The new revision's bytes and the object numbers a further incremental update chains onto.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="request"/>, its <see cref="PdfDssPlacementRequest.Anchor"/>, or its <see cref="PdfDssPlacementRequest.Catalog"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <see cref="PdfCatalogLocation.HasDssEntry"/> is already <see langword="true"/> (this method mints a
    /// document's first DSS revision only; PA-5.4.1-01's incremental-update merge is not composed here), when
    /// <see cref="PdfDssPlacementRequest.Anchor"/> names a negative offset or a non-positive object number, when a
    /// VRI entry's own key is not a well-formed <see cref="PdfVriKey"/> (PA-5.4.2.2-T2), when a VRI entry names
    /// both <see cref="PdfVriEntryRequest.TimeUpdated"/> and <see cref="PdfVriEntryRequest.TimeStampToken"/>
    /// (PA-5.4.2.3-10/-13), or when a VRI entry's own index list names an index outside the enclosing request's
    /// corresponding array.
    /// </exception>
    public static PdfDssPlacementResult AppendValidationData(PdfDssPlacementRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Anchor);
        ArgumentNullException.ThrowIfNull(request.Catalog);
        if(request.Catalog.HasDssEntry)
        {
            throw new ArgumentException(
                "The catalog already carries a DSS entry; AppendValidationData mints a document's first DSS " +
                "revision only (PA-5.4.1-01's incremental-update merge — 'should contain the values from the " +
                "previous DSS Dictionary' — is not composed here).",
                nameof(request));
        }

        PdfIncrementalUpdateAnchor anchor = request.Anchor;
        if(anchor.PriorXrefOffset < 0 || anchor.PriorObjectCount <= 0 || anchor.RootObjectNumber <= 0 || anchor.RootGeneration < 0)
        {
            throw new ArgumentException(
                "An incremental-update anchor names a non-negative prior xref offset, a positive prior object count, and a positive root object number.",
                nameof(request));
        }

        var writer = new List<byte>(request.PriorDocument.Length + 4096);
        AppendBytes(writer, request.PriorDocument.Span);

        int nextObjectNumber = anchor.PriorObjectCount;
        var objectOffsets = new List<(int Number, int Offset)>();

        List<int> certNumbers = WriteStreamObjects(writer, ref nextObjectNumber, request.Certificates, objectOffsets);
        List<int> crlNumbers = WriteStreamObjects(writer, ref nextObjectNumber, request.CertificateRevocationLists, objectOffsets);
        List<int> ocspNumbers = WriteStreamObjects(writer, ref nextObjectNumber, request.OcspResponses, objectOffsets);

        var vriObjectNumbers = new Dictionary<string, int>(StringComparer.Ordinal);
        if(request.VriEntries is not null)
        {
            foreach((string key, PdfVriEntryRequest entry) in request.VriEntries)
            {
                if(!PdfVriKey.IsWellFormed(key))
                {
                    throw new ArgumentException($"VRI key '{key}' is not a well-formed 40-character uppercase hexadecimal SHA-1 digest (PA-5.4.2.2-T2).", nameof(request));
                }

                if(entry.TimeUpdated is not null && entry.TimeStampToken is not null)
                {
                    throw new ArgumentException($"VRI entry '{key}' names both TU and TS; exactly one claimed-time mechanism is permitted (PA-5.4.2.3-10/-13).", nameof(request));
                }

                int? tsObjectNumber = null;
                if(entry.TimeStampToken is { } timeStampToken)
                {
                    tsObjectNumber = nextObjectNumber++;
                    int tsOffset = writer.Count;
                    WriteDerStreamObject(writer, tsObjectNumber.Value, timeStampToken.AsReadOnlySpan());
                    objectOffsets.Add((tsObjectNumber.Value, tsOffset));
                }

                int vriObjectNumber = nextObjectNumber++;
                int vriOffset = writer.Count;
                WriteVriDictionaryObject(
                    writer, vriObjectNumber, entry,
                    SelectByIndex(certNumbers, entry.CertificateIndices, key, "Cert"),
                    SelectByIndex(crlNumbers, entry.CrlIndices, key, "CRL"),
                    SelectByIndex(ocspNumbers, entry.OcspIndices, key, "OCSP"),
                    tsObjectNumber);
                objectOffsets.Add((vriObjectNumber, vriOffset));
                vriObjectNumbers[key] = vriObjectNumber;
            }
        }

        int dssObjectNumber = nextObjectNumber++;
        int dssOffset = writer.Count;
        WriteDssDictionaryObject(writer, dssObjectNumber, certNumbers, crlNumbers, ocspNumbers, vriObjectNumbers);
        objectOffsets.Add((dssObjectNumber, dssOffset));

        int catalogOffset = writer.Count;
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"{request.Catalog.ObjectNumber} {request.Catalog.Generation} obj\n<<"));
        AppendBytes(writer, request.PriorDocument.Span.Slice(request.Catalog.EntriesStart, request.Catalog.EntriesEnd - request.Catalog.EntriesStart));
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $" /DSS {dssObjectNumber} 0 R >>\nendobj\n"));
        objectOffsets.Add((request.Catalog.ObjectNumber, catalogOffset));

        int xrefOffset = writer.Count;
        WriteXrefSections(writer, objectOffsets);
        AppendAscii(writer, string.Create(
            CultureInfo.InvariantCulture,
            $"trailer\n<< /Size {nextObjectNumber} /Root {request.Catalog.ObjectNumber} {request.Catalog.Generation} R /Prev {anchor.PriorXrefOffset} >>\nstartxref\n"));
        AppendAscii(writer, xrefOffset.ToString(CultureInfo.InvariantCulture));
        AppendAscii(writer, "\n%%EOF\n");

        return new PdfDssPlacementResult
        {
            Bytes = [.. writer],
            XrefOffset = xrefOffset,
            DssObjectNumber = dssObjectNumber,
            VriObjectNumbers = vriObjectNumbers,
            NextObjectNumber = nextObjectNumber
        };
    }


    /// <summary>Writes each item as its own DER stream object, in order, returning the object numbers minted.</summary>
    private static List<int> WriteStreamObjects(List<byte> writer, ref int nextObjectNumber, IReadOnlyList<PkiCertificateMemory> items, List<(int Number, int Offset)> objectOffsets)
    {
        var numbers = new List<int>(items.Count);
        for(int i = 0; i < items.Count; ++i)
        {
            int number = nextObjectNumber++;
            int offset = writer.Count;
            WriteDerStreamObject(writer, number, items[i].AsReadOnlySpan());
            objectOffsets.Add((number, offset));
            numbers.Add(number);
        }

        return numbers;
    }


    /// <summary>Writes one <c>N 0 obj &lt;&lt; /Length L &gt;&gt; stream ... endstream endobj</c> object carrying <paramref name="derBytes"/> verbatim.</summary>
    private static void WriteDerStreamObject(List<byte> writer, int objectNumber, ReadOnlySpan<byte> derBytes)
    {
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"{objectNumber} 0 obj\n<< /Length {derBytes.Length} >>\nstream\n"));
        AppendBytes(writer, derBytes);
        AppendAscii(writer, "\nendstream\nendobj\n");
    }


    /// <summary>Resolves a VRI entry's own index list against one of the enclosing request's arrays, fail-closed on an out-of-range index.</summary>
    private static List<int> SelectByIndex(List<int> objectNumbers, IReadOnlyList<int> indices, string vriKey, string arrayName)
    {
        var selected = new List<int>(indices.Count);
        for(int i = 0; i < indices.Count; ++i)
        {
            int index = indices[i];
            if(index < 0 || index >= objectNumbers.Count)
            {
                throw new ArgumentException($"VRI entry '{vriKey}' names {arrayName} index {index}, outside the enclosing request's own array of {objectNumbers.Count} item(s).", nameof(indices));
            }

            selected.Add(objectNumbers[index]);
        }

        return selected;
    }


    /// <summary>Writes one Signature VRI dictionary object (clause 5.4.2.3).</summary>
    private static void WriteVriDictionaryObject(
        List<byte> writer, int objectNumber, PdfVriEntryRequest entry,
        List<int> certNumbers, List<int> crlNumbers, List<int> ocspNumbers, int? tsObjectNumber)
    {
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"{objectNumber} 0 obj\n<< /Type /VRI"));
        AppendReferenceArray(writer, "/Cert", certNumbers);
        AppendReferenceArray(writer, "/CRL", crlNumbers);
        AppendReferenceArray(writer, "/OCSP", ocspNumbers);
        if(entry.TimeUpdated is { } timeUpdated)
        {
            AppendAscii(writer, $" /TU ({EscapeLiteral(FormatPdfDate(timeUpdated))})");
        }

        if(tsObjectNumber is { } ts)
        {
            AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $" /TS {ts} 0 R"));
        }

        AppendAscii(writer, " >>\nendobj\n");
    }


    /// <summary>Writes the DSS dictionary object (clause 5.4.2.2).</summary>
    private static void WriteDssDictionaryObject(
        List<byte> writer, int objectNumber, List<int> certNumbers, List<int> crlNumbers, List<int> ocspNumbers,
        Dictionary<string, int> vriObjectNumbers)
    {
        AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"{objectNumber} 0 obj\n<< /Type /DSS"));
        AppendReferenceArray(writer, "/Certs", certNumbers);
        AppendReferenceArray(writer, "/CRLs", crlNumbers);
        AppendReferenceArray(writer, "/OCSPs", ocspNumbers);
        if(vriObjectNumbers.Count > 0)
        {
            AppendAscii(writer, " /VRI <<");
            foreach((string key, int number) in vriObjectNumbers)
            {
                AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $" /{key} {number} 0 R"));
            }

            AppendAscii(writer, " >>");
        }

        AppendAscii(writer, " >>\nendobj\n");
    }


    /// <summary>Appends <c>key [N 0 R ...]</c> when <paramref name="objectNumbers"/> is non-empty; omitted entirely when empty (PA-5.4.2.3-03/-06/-08: "if present, it shall not be an empty array").</summary>
    private static void AppendReferenceArray(List<byte> writer, string key, List<int> objectNumbers)
    {
        if(objectNumbers.Count == 0)
        {
            return;
        }

        AppendAscii(writer, $" {key} [");
        for(int i = 0; i < objectNumbers.Count; ++i)
        {
            if(i > 0)
            {
                AppendAscii(writer, " ");
            }

            AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"{objectNumbers[i]} 0 R"));
        }

        AppendAscii(writer, "]");
    }


    /// <summary>Writes one or more classic cross-reference subsections covering every entry, grouped into contiguous object-number runs (ISO 32000-1 clause 7.5.4 permits any number of subsections per section).</summary>
    private static void WriteXrefSections(List<byte> writer, List<(int Number, int Offset)> entries)
    {
        entries.Sort((left, right) => left.Number.CompareTo(right.Number));
        AppendAscii(writer, "xref\n");

        int i = 0;
        while(i < entries.Count)
        {
            int start = entries[i].Number;
            int j = i;
            while(j + 1 < entries.Count && entries[j + 1].Number == entries[j].Number + 1)
            {
                j++;
            }

            int count = j - i + 1;
            AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"{start} {count}\n"));
            for(int k = i; k <= j; ++k)
            {
                AppendAscii(writer, string.Create(CultureInfo.InvariantCulture, $"{entries[k].Offset:D10} 00000 n \n"));
            }

            i = j + 1;
        }
    }


    /// <summary>Formats an ISO 32000-1 clause 7.9.4 date string (<c>D:YYYYMMDDHHmmSSOHH'mm'</c>), the inverse of <c>PdfByteSurfaceReader</c>'s own reading of the same syntax.</summary>
    private static string FormatPdfDate(DateTimeOffset value)
    {
        string stamp = value.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        if(value.Offset == TimeSpan.Zero)
        {
            return $"D:{stamp}Z";
        }

        TimeSpan offset = value.Offset;
        string sign = offset < TimeSpan.Zero ? "-" : "+";
        TimeSpan magnitude = offset.Duration();

        return $"D:{stamp}{sign}{magnitude.Hours:D2}'{magnitude.Minutes:D2}'";
    }


    /// <summary>Escapes a literal-string value's own delimiters and escape character (ISO 32000-1 clause 7.3.4.2).</summary>
    private static string EscapeLiteral(string text) =>
        text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("(", "\\(", StringComparison.Ordinal).Replace(")", "\\)", StringComparison.Ordinal);


    private static string FormatByteRangeArray(int first, int firstLength, int second, int secondLength) =>
        $"[{Pad(first)} {Pad(firstLength)} {Pad(second)} {Pad(secondLength)}]";


    private static string Pad(int value) => value.ToString("D" + ByteRangeFieldWidth.ToString(CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);


    private static void WriteByteRangeArray(byte[] document, int offset, int first, int firstLength, int second, int secondLength)
    {
        string rendered = FormatByteRangeArray(first, firstLength, second, secondLength);
        for(int i = 0; i < rendered.Length; ++i)
        {
            document[offset + i] = (byte)rendered[i];
        }
    }


    private static void AppendAscii(List<byte> writer, string text) => AppendBytes(writer, Encoding.ASCII.GetBytes(text));


    private static void AppendBytes(List<byte> writer, ReadOnlySpan<byte> bytes)
    {
        for(int i = 0; i < bytes.Length; ++i)
        {
            writer.Add(bytes[i]);
        }
    }
}
