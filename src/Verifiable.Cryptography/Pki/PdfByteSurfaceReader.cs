using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Where an existing PDF document's own document catalog sits, located by <see cref="PdfByteSurfaceReader.TryLocateCatalog"/>.
/// </summary>
public sealed record PdfCatalogLocation
{
    /// <summary>Gets the catalog's own indirect object number.</summary>
    public required int ObjectNumber { get; init; }

    /// <summary>Gets the catalog's own generation number.</summary>
    public required int Generation { get; init; }

    /// <summary>Gets the byte offset of the first byte of the catalog dictionary's own raw entries text (right after its opening <c>&lt;&lt;</c>).</summary>
    public required int EntriesStart { get; init; }

    /// <summary>Gets the byte offset of the catalog dictionary's own closing <c>&gt;&gt;</c> — <c>[EntriesStart, EntriesEnd)</c> is the raw entries text, copied byte-for-byte by <see cref="PdfIncrementalUpdateWriter.AppendValidationData"/> rather than reconstructed.</summary>
    public required int EntriesEnd { get; init; }

    /// <summary>Gets whether the catalog already carries a <c>DSS</c> entry (ISO 32000-1 table 28, PA-5.4.2.1-T1).</summary>
    public required bool HasDssEntry { get; init; }
}


/// <summary>
/// The targeted PDF byte-surface reader (RP-1/RP-2): locates every PDF Signature Dictionary a document carries
/// by walking its cross-reference/trailer structure across incremental-update sections, and extracts exactly the
/// entries
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 5.3 (PA-5.3-01) names — no general PDF object model, no content-stream
/// interpretation, no decompression beyond what locating requires.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The ManagedCertificate discipline.</strong> Mirrors <see cref="ManagedCertificate"/>: a synchronous,
/// span-first, fail-closed parse over attacker-reachable bytes, with every loop bounded and every structural
/// defect reported through <see cref="PdfByteSurfaceParseResult"/> rather than an exception.
/// </para>
/// <para>
/// <strong>How a signature dictionary is located.</strong> ISO 32000-1's own path to a signature dictionary runs
/// through the document catalog's <c>AcroForm</c>/<c>Fields</c> tree — a general object model this reader does
/// not build (RP-1). Instead, every object the merged cross-reference table resolves to is inspected for the one
/// shape clause 5.3 itself names: a dictionary carrying both a <c>ByteRange</c> and a <c>Contents</c> entry. This
/// is exactly the byte-surface the EN's own statements require, and it finds every signature a document carries
/// (including one applied in an earlier incremental-update section, whose own object entry survives untouched in
/// later sections precisely so that its bytes — and its own <c>ByteRange</c> — stay intact) without walking the
/// catalog at all.
/// </para>
/// <para>
/// <strong>Recorded boundary: cross-reference streams are not read.</strong> ISO 32000-1 clause 7.5.8 lets a
/// document store its cross-reference table compressed inside a stream object instead of the classic
/// <c>xref</c>/<c>trailer</c> text form this reader parses. No statement in EN 319 142-1's own clauses 1–5.3 (or
/// leg 2's clause 5.4/6) requires cross-reference streams — they are a storage optimisation ISO 32000-1 itself
/// makes optional, and RP-2 treats ISO 32000-1 internals as a cited boundary rather than a surface to transcribe
/// wholesale. A document whose current cross-reference section is a stream is reported as a located-but-failed
/// parse (<see cref="PdfByteSurfaceParseResult.IsSuccess"/> <see langword="false"/>) rather than silently
/// misread; support is added when a concrete signed-PDF scenario needs it.
/// </para>
/// <para>
/// <strong>Fail-closed per candidate, not per document.</strong> Once the cross-reference structure itself
/// resolves, a single object shaped like a Signature Dictionary (carrying both <c>ByteRange</c> and
/// <c>Contents</c>) that fails one of the byte-surface invariants — an out-of-shape <c>ByteRange</c>, a
/// <c>Contents</c> value that does not sit exactly inside its declared gap, a missing <c>Filter</c>/<c>SubFilter</c> —
/// is excluded from <see cref="PdfByteSurfaceParseResult.SignatureDictionaries"/> and recorded in
/// <see cref="PdfByteSurfaceParseResult.SkippedCandidateReasons"/>, never a whole-document
/// <see cref="PdfByteSurfaceParseResult.IsSuccess"/> <see langword="false"/>: a decoy object appended alongside a
/// genuinely valid signature must not make that signature unreachable.
/// </para>
/// </remarks>
public static class PdfByteSurfaceReader
{
    /// <summary>The most incremental-update sections (<c>/Prev</c> hops) this reader follows before failing closed.</summary>
    private const int MaxXrefSections = 256;

    /// <summary>The most entries one classic cross-reference subsection may declare before this reader fails closed.</summary>
    private const int MaxXrefEntriesPerSubsection = 1_048_576;

    /// <summary>The most distinct object numbers the merged cross-reference table may resolve to before this reader fails closed.</summary>
    private const int MaxTrackedObjects = 1_048_576;


    /// <summary>
    /// Locates every PDF Signature Dictionary a document carries.
    /// </summary>
    /// <param name="document">The whole PDF document's bytes. Borrowed: this method takes no ownership of it, and every <see cref="PdfSignatureDictionary"/> in the result holds the same borrowed view.</param>
    /// <param name="pool">The memory pool each located signature's <see cref="PdfSignatureDictionary.Contents"/> carrier rents its buffer from.</param>
    /// <returns>The Unverified parse carriage — every candidate that parsed cleanly, plus <see cref="PdfByteSurfaceParseResult.SkippedCandidateReasons"/> for every signature-dictionary-shaped candidate that did not. The caller owns and disposes the returned result.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each located signature transfers to the 'located' list on the very next line, owned onward by the returned PdfByteSurfaceParseResult.")]
    public static PdfByteSurfaceParseResult Locate(ReadOnlyMemory<byte> document, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> s = document.Span;
        if(s.IsEmpty)
        {
            return PdfByteSurfaceParseResult.Failure("The document is empty.");
        }

        if(!TryBuildObjectIndex(s, out Dictionary<long, long> objectOffsets, out _, out string? xrefError))
        {
            return PdfByteSurfaceParseResult.Failure(xrefError);
        }

        var sortedObjectNumbers = new List<long>(objectOffsets.Keys);
        sortedObjectNumbers.Sort();

        var located = new List<PdfSignatureDictionary>();
        var skippedCandidateReasons = new List<string>();
        var parsedOffsets = new HashSet<int>();
        for(int i = 0; i < sortedObjectNumbers.Count; ++i)
        {
            long objectOffset = objectOffsets[sortedObjectNumbers[i]];
            if(objectOffset < 0 || objectOffset >= s.Length)
            {
                //An offset that does not fit inside the document cannot be a signature dictionary; the
                //cross-reference table's own structure was already validated above, so this is a property of
                //this one entry, not the document as a whole, and is skipped rather than fatal.
                continue;
            }

            int pos = (int)objectOffset;
            if(!parsedOffsets.Add(pos))
            {
                //Two distinct object numbers naming the same physical offset name the same one object; the first
                //occurrence already parsed (or found unsuitable) it, so a repeat offset costs one hash lookup
                //rather than a second full parse.
                continue;
            }

            int objectOffsetInt = pos;
            if(!PdfValueParser.TryParseIndirectObjectHeader(s, ref pos, out _, out _))
            {
                continue;
            }

            if(!PdfValueParser.TryParseValue(s, ref pos, depth: 0, out PdfValue value, out _))
            {
                continue;
            }

            if(value.Kind != PdfValueKind.Dictionary || value.Entries is null)
            {
                continue;
            }

            if(!value.Entries.ContainsKey("ByteRange") || !value.Entries.ContainsKey("Contents"))
            {
                continue;
            }

            //A candidate shaped like a Signature Dictionary (ByteRange + Contents present) that fails one of the
            //byte-surface invariants is its own, per-signature failure -- skipped, never a whole-document abort,
            //so one decoy object never sinks a document's own genuinely valid signature(s).
            if(!TryBuildSignatureDictionary(document, s, value.Entries, pool, objectOffsetInt, out PdfSignatureDictionary? signature, out string? buildError))
            {
                skippedCandidateReasons.Add(buildError);

                continue;
            }

            located.Add(signature);
        }

        return PdfByteSurfaceParseResult.Success(located, skippedCandidateReasons);
    }


    /// <summary>Finds the last <c>startxref</c> keyword and reads the offset that follows it.</summary>
    internal static bool TryLocateStartXref(ReadOnlySpan<byte> s, out long offset)
    {
        int found = PdfValueParser.LastIndexOf(s, "startxref"u8);
        if(found < 0)
        {
            offset = 0;

            return false;
        }

        int pos = found + "startxref"u8.Length;
        PdfValueParser.SkipWhitespaceAndComments(s, ref pos);

        return PdfValueParser.TryReadUnsignedInteger(s, ref pos, out offset);
    }


    /// <summary>
    /// Walks the <c>/Prev</c>-linked chain of cross-reference sections, merging object offsets with newest-wins
    /// semantics: the first (most recent) section to mention an object number — whether as in-use (<c>n</c>) or
    /// freed (<c>f</c>) — is authoritative, and an older section's own entry for the same number is never allowed
    /// to override it. This is exactly the mechanism PAdES's own incremental-update signing relies on: an
    /// object's bytes, once covered by an earlier signature's <c>ByteRange</c>, are never rewritten in place.
    /// </summary>
    /// <param name="s">The whole document's bytes.</param>
    /// <param name="startOffset">The most recent cross-reference section's own offset (<see cref="TryLocateStartXref"/>).</param>
    /// <param name="objectOffsets">Every object number the chain resolves to, mapped to its most recent in-use offset.</param>
    /// <param name="rootReference">The document catalog's own indirect reference, read from the newest (first-walked) trailer's <c>/Root</c> entry — every revision restates it, so the newest one is authoritative.</param>
    /// <param name="error">The reason walking failed, when this method returns <see langword="false"/>.</param>
    internal static bool TryWalkXrefChain(
        ReadOnlySpan<byte> s, long startOffset, out Dictionary<long, long> objectOffsets,
        out (long ObjectNumber, long Generation)? rootReference, [NotNullWhen(false)] out string? error)
    {
        objectOffsets = new Dictionary<long, long>();
        var decidedObjectNumbers = new HashSet<long>();
        var visitedSectionOffsets = new HashSet<long>();
        long? next = startOffset;
        rootReference = null;
        error = null;

        while(next is long offset)
        {
            if(!visitedSectionOffsets.Add(offset))
            {
                error = "The cross-reference '/Prev' chain revisits an offset (a cycle).";

                return false;
            }

            if(visitedSectionOffsets.Count > MaxXrefSections)
            {
                error = "The cross-reference '/Prev' chain exceeds the supported number of incremental-update sections.";

                return false;
            }

            if(!TryLocateAndParseXrefSection(s, offset, objectOffsets, decidedObjectNumbers, rawSectionEntries: null, out long? prev, out (long, long)? sectionRoot, out error))
            {
                return false;
            }

            //The first (newest) trailer's own /Root is authoritative; every older revision restates the same
            //catalog object number, so only the first section's own reading is kept.
            rootReference ??= sectionRoot;

            if(objectOffsets.Count > MaxTrackedObjects)
            {
                error = "The document declares more objects than this reader supports.";

                return false;
            }

            next = prev;
        }

        return true;
    }


    /// <summary>One cross-reference section's own raw, unmerged declared object entries and trailer <c>/Root</c> — <see cref="TryWalkXrefChainSections"/>'s own per-revision detail.</summary>
    /// <param name="Offset">The byte offset of this section's own <c>xref</c> keyword.</param>
    /// <param name="DeclaredObjects">Every object number this ONE section itself declares, mapped to its own in-use offset, or <c>-1</c> for a freed (<c>f</c>) entry.</param>
    /// <param name="Root">This section's own trailer <c>/Root</c> reference, when its trailer states one.</param>
    internal sealed record PdfXrefSection(long Offset, IReadOnlyDictionary<long, long> DeclaredObjects, (long ObjectNumber, long Generation)? Root);


    /// <summary>
    /// Walks the <c>/Prev</c>-linked chain of cross-reference sections exactly as <see cref="TryWalkXrefChain"/>
    /// does, but returns each section's OWN raw declared entries individually, in walk order (newest first),
    /// instead of merging them with newest-wins semantics — the per-revision detail a shadow-attack check over a
    /// document's own discarded suffix needs (which incremental-update revision declared which object number),
    /// that a merged view discards.
    /// </summary>
    /// <param name="s">The whole document's bytes.</param>
    /// <param name="startOffset">The most recent cross-reference section's own offset (<see cref="TryLocateStartXref"/>).</param>
    /// <param name="sections">Every section the chain visits, newest first.</param>
    /// <param name="error">The reason walking failed, when this method returns <see langword="false"/>.</param>
    internal static bool TryWalkXrefChainSections(
        ReadOnlySpan<byte> s, long startOffset, out List<PdfXrefSection> sections, [NotNullWhen(false)] out string? error)
    {
        sections = [];
        var objectOffsets = new Dictionary<long, long>();
        var decidedObjectNumbers = new HashSet<long>();
        var visitedSectionOffsets = new HashSet<long>();
        long? next = startOffset;
        error = null;

        while(next is long offset)
        {
            if(!visitedSectionOffsets.Add(offset))
            {
                error = "The cross-reference '/Prev' chain revisits an offset (a cycle).";

                return false;
            }

            if(visitedSectionOffsets.Count > MaxXrefSections)
            {
                error = "The cross-reference '/Prev' chain exceeds the supported number of incremental-update sections.";

                return false;
            }

            var rawSectionEntries = new Dictionary<long, long>();
            if(!TryLocateAndParseXrefSection(s, offset, objectOffsets, decidedObjectNumbers, rawSectionEntries, out long? prev, out (long, long)? sectionRoot, out error))
            {
                return false;
            }

            sections.Add(new PdfXrefSection(offset, rawSectionEntries, sectionRoot));

            if(objectOffsets.Count > MaxTrackedObjects)
            {
                error = "The document declares more objects than this reader supports.";

                return false;
            }

            next = prev;
        }

        return true;
    }


    /// <summary>Validates one cross-reference section's own offset and <c>xref</c> keyword, then parses it — the shared per-hop step both <see cref="TryWalkXrefChain"/> and <see cref="TryWalkXrefChainSections"/> repeat.</summary>
    private static bool TryLocateAndParseXrefSection(
        ReadOnlySpan<byte> s, long offset, Dictionary<long, long> objectOffsets, HashSet<long> decidedObjectNumbers,
        Dictionary<long, long>? rawSectionEntries, out long? prev, out (long ObjectNumber, long Generation)? root,
        [NotNullWhen(false)] out string? error)
    {
        prev = null;
        root = null;
        if(offset < 0 || offset >= s.Length)
        {
            error = $"A cross-reference section offset ({offset}) lies outside the document.";

            return false;
        }

        int pos = (int)offset;
        PdfValueParser.SkipWhitespaceAndComments(s, ref pos);
        if(pos + 4 > s.Length || !s.Slice(pos, 4).SequenceEqual("xref"u8) || (pos + 4 < s.Length && !PdfValueParser.IsWhitespace(s[pos + 4])))
        {
            error = "No classic 'xref' table was found at the expected offset (a malformed cross-reference " +
                "section, or a cross-reference stream — ISO 32000-1 clause 7.5.8 — which this reader does not read).";

            return false;
        }

        pos += 4;

        return TryParseClassicXrefSection(s, ref pos, objectOffsets, decidedObjectNumbers, rawSectionEntries, out prev, out root, out error);
    }


    /// <summary>Composes <see cref="TryLocateStartXref"/> and <see cref="TryWalkXrefChain"/> — the one entry point every caller that needs a document's merged object index (locating signature dictionaries, the catalog, or DSS/VRI material) goes through.</summary>
    internal static bool TryBuildObjectIndex(
        ReadOnlySpan<byte> s, out Dictionary<long, long> objectOffsets,
        out (long ObjectNumber, long Generation)? rootReference, [NotNullWhen(false)] out string? error)
    {
        objectOffsets = [];
        rootReference = null;
        if(!TryLocateStartXref(s, out long startXrefOffset))
        {
            error = "No 'startxref' keyword was found.";

            return false;
        }

        return TryWalkXrefChain(s, startXrefOffset, out objectOffsets, out rootReference, out error);
    }


    /// <summary>Resolves an object number through an already-built object index to its parsed value — the shared primitive every indirect reference in DSS/VRI/catalog material is followed through.</summary>
    /// <param name="s">The whole document's bytes.</param>
    /// <param name="objectOffsets">The merged object index (<see cref="TryBuildObjectIndex"/>).</param>
    /// <param name="objectNumber">The object number to resolve.</param>
    /// <param name="value">The parsed value, when this method returns <see langword="true"/>.</param>
    /// <param name="error">The reason resolution failed, when this method returns <see langword="false"/>.</param>
    internal static bool TryResolveObject(
        ReadOnlySpan<byte> s, IReadOnlyDictionary<long, long> objectOffsets, long objectNumber,
        out PdfValue value, [NotNullWhen(false)] out string? error)
    {
        value = default;
        if(!objectOffsets.TryGetValue(objectNumber, out long offset) || offset < 0 || offset >= s.Length)
        {
            error = $"Object {objectNumber} could not be located.";

            return false;
        }

        int pos = (int)offset;
        if(!PdfValueParser.TryParseIndirectObjectHeader(s, ref pos, out _, out _))
        {
            error = $"Object {objectNumber}'s own indirect-object header is malformed.";

            return false;
        }

        return PdfValueParser.TryParseValue(s, ref pos, depth: 0, out value, out error);
    }


    /// <summary>
    /// Locates the document catalog through the trailer's own <c>/Root</c> reference — everything
    /// <see cref="PdfIncrementalUpdateWriter.AppendValidationData"/> needs to append a new incremental-update
    /// revision that adds (or extends) the catalog's own <c>DSS</c> entry (ISO 32000-1 table 28, PA-5.4.2.1-T1)
    /// without re-parsing or re-serializing whatever else the catalog already carries — <see cref="PdfCatalogLocation.EntriesStart"/>/
    /// <see cref="PdfCatalogLocation.EntriesEnd"/> bracket the catalog's own raw entries text, copied byte-for-byte
    /// rather than reconstructed from the parsed <see cref="PdfValue"/> tree.
    /// </summary>
    /// <param name="document">The whole PDF document's bytes.</param>
    /// <param name="location">Where the catalog sits, when this method returns <see langword="true"/>.</param>
    /// <param name="error">The reason locating failed, when this method returns <see langword="false"/>.</param>
    public static bool TryLocateCatalog(ReadOnlyMemory<byte> document, [NotNullWhen(true)] out PdfCatalogLocation? location, [NotNullWhen(false)] out string? error)
    {
        location = null;
        ReadOnlySpan<byte> s = document.Span;
        if(s.IsEmpty)
        {
            error = "The document is empty.";

            return false;
        }

        if(!TryBuildObjectIndex(s, out Dictionary<long, long> objectOffsets, out (long ObjectNumber, long Generation)? rootReference, out error))
        {
            return false;
        }

        if(rootReference is not { } root)
        {
            error = "No trailer '/Root' entry was found.";

            return false;
        }

        if(!TryResolveObject(s, objectOffsets, root.ObjectNumber, out PdfValue value, out error))
        {
            return false;
        }

        if(value.Kind != PdfValueKind.Dictionary || value.Entries is null)
        {
            error = "The document catalog is not a dictionary.";

            return false;
        }

        location = new PdfCatalogLocation
        {
            ObjectNumber = (int)root.ObjectNumber,
            Generation = (int)root.Generation,
            EntriesStart = value.DictionaryContentStart,
            EntriesEnd = value.DictionaryContentEnd,
            HasDssEntry = value.Entries.ContainsKey("DSS")
        };

        return true;
    }


    /// <summary>
    /// Parses one classic cross-reference table section (its subsections and the trailer dictionary that follows),
    /// and reads the trailer's own <c>/Prev</c> link and <c>/Root</c> reference.
    /// </summary>
    /// <param name="rawSectionEntries">
    /// When supplied, populated with EVERY object number this one section itself declares, unmerged against any
    /// other section (an in-use entry's own offset, or <c>-1</c> for a freed <c>'f'</c> entry) — the per-revision
    /// detail <paramref name="objectOffsets"/>'s own newest-wins merge discards, needed to tell which
    /// incremental-update revision declared which object number (<see cref="TryWalkXrefChainSections"/>).
    /// </param>
    private static bool TryParseClassicXrefSection(
        ReadOnlySpan<byte> s,
        ref int pos,
        Dictionary<long, long> objectOffsets,
        HashSet<long> decidedObjectNumbers,
        Dictionary<long, long>? rawSectionEntries,
        out long? prev,
        out (long ObjectNumber, long Generation)? root,
        [NotNullWhen(false)] out string? error)
    {
        prev = null;
        root = null;
        error = null;

        while(true)
        {
            PdfValueParser.SkipWhitespaceAndComments(s, ref pos);
            if(pos + 7 <= s.Length && s.Slice(pos, 7).SequenceEqual("trailer"u8))
            {
                pos += 7;
                break;
            }

            if(pos >= s.Length || s[pos] is < (byte)'0' or > (byte)'9')
            {
                error = "A cross-reference subsection header (two integers) or the 'trailer' keyword was expected.";

                return false;
            }

            if(!PdfValueParser.TryReadUnsignedInteger(s, ref pos, out long subsectionStart) ||
                !PdfValueParser.SkipWhitespaceThenReadUnsignedInteger(s, ref pos, out long subsectionCount))
            {
                error = "A malformed cross-reference subsection header.";

                return false;
            }

            if(subsectionCount < 0 || subsectionCount > MaxXrefEntriesPerSubsection)
            {
                error = "A cross-reference subsection declares an unsupported number of entries.";

                return false;
            }

            for(long i = 0; i < subsectionCount; ++i)
            {
                PdfValueParser.SkipWhitespaceAndComments(s, ref pos);
                if(!PdfValueParser.TryReadUnsignedInteger(s, ref pos, out long entryOffset) ||
                    !PdfValueParser.SkipWhitespaceThenReadUnsignedInteger(s, ref pos, out _))
                {
                    error = "A malformed cross-reference entry.";

                    return false;
                }

                PdfValueParser.SkipWhitespaceAndComments(s, ref pos);
                if(pos >= s.Length || (s[pos] != (byte)'n' && s[pos] != (byte)'f'))
                {
                    error = "A cross-reference entry's type flag must be 'n' or 'f'.";

                    return false;
                }

                bool isInUse = s[pos] == (byte)'n';
                pos++;

                long objectNumber = subsectionStart + i;
                if(rawSectionEntries is not null)
                {
                    //A malformed document can redeclare the same object number twice within one section; the
                    //last declaration within THIS section wins for the raw, per-section view (harmless -- this is
                    //diagnostic detail for the suffix walk, never the merged objectOffsets table below).
                    rawSectionEntries[objectNumber] = isInUse ? entryOffset : -1;
                }

                if(decidedObjectNumbers.Add(objectNumber) && isInUse)
                {
                    objectOffsets[objectNumber] = entryOffset;
                }
            }
        }

        PdfValueParser.SkipWhitespaceAndComments(s, ref pos);
        if(!PdfValueParser.TryParseValue(s, ref pos, depth: 0, out PdfValue trailerDictionary, out error) || trailerDictionary.Kind != PdfValueKind.Dictionary)
        {
            error ??= "The 'trailer' keyword was not followed by a dictionary.";

            return false;
        }

        if(trailerDictionary.Entries!.TryGetValue("Prev", out PdfValue prevValue) && prevValue.Kind == PdfValueKind.Integer)
        {
            prev = prevValue.Number;
        }

        if(trailerDictionary.Entries!.TryGetValue("Root", out PdfValue rootValue) && rootValue.Kind == PdfValueKind.Reference)
        {
            root = (rootValue.Number, rootValue.Generation);
        }

        return true;
    }


    /// <summary>Builds and byte-range-validates one <see cref="PdfSignatureDictionary"/> from a candidate dictionary's already-parsed entries.</summary>
    private static bool TryBuildSignatureDictionary(
        ReadOnlyMemory<byte> document,
        ReadOnlySpan<byte> s,
        IReadOnlyDictionary<string, PdfValue> entries,
        BaseMemoryPool pool,
        int objectOffset,
        [NotNullWhen(true)] out PdfSignatureDictionary? signature,
        [NotNullWhen(false)] out string? error)
    {
        signature = null;

        if(!entries.TryGetValue("Filter", out PdfValue filterValue) || filterValue.Kind != PdfValueKind.Name)
        {
            error = "A signature dictionary's 'Filter' entry is missing or is not a Name.";

            return false;
        }

        if(!entries.TryGetValue("SubFilter", out PdfValue subFilterValue) || subFilterValue.Kind != PdfValueKind.Name)
        {
            error = "A signature dictionary's 'SubFilter' entry is missing or is not a Name.";

            return false;
        }

        if(!entries.TryGetValue("ByteRange", out PdfValue byteRangeValue) || byteRangeValue.Kind != PdfValueKind.Array || byteRangeValue.Items is null)
        {
            error = "A signature dictionary's 'ByteRange' entry is missing or is not an Array.";

            return false;
        }

        if(byteRangeValue.Items.Count != 4)
        {
            error = $"A PAdES ByteRange names exactly two segments (four integers, PA-6.3-k); found {byteRangeValue.Items.Count}.";

            return false;
        }

        Span<long> numbers = stackalloc long[4];
        for(int i = 0; i < byteRangeValue.Items.Count; ++i)
        {
            if(byteRangeValue.Items[i].Kind != PdfValueKind.Integer)
            {
                error = "A 'ByteRange' element is not an Integer.";

                return false;
            }

            numbers[i] = byteRangeValue.Items[i].Number;
        }

        if(!PdfByteRange.TryCreate(numbers, s.Length, out PdfByteRange byteRange, out error))
        {
            return false;
        }

        if(!entries.TryGetValue("Contents", out PdfValue contentsValue) || contentsValue.Kind != PdfValueKind.HexString || contentsValue.StringBytes is not byte[] contentsBytes)
        {
            error = "A signature dictionary's 'Contents' entry is missing or is not a hexadecimal string.";

            return false;
        }

        //ISO 32000-1 clause 12.8.1 defines the gap ByteRange excludes as covering the signature value itself --
        //the whole Contents string, its '<'/'>' delimiters included, not merely the hexadecimal digits between
        //them (the universal producer convention; see PdfIncrementalUpdateWriter's own matching computation).
        if(contentsValue.HexContentStart - 1 != byteRange.GapStart || contentsValue.HexContentEnd + 1 != byteRange.SecondOffset)
        {
            error = "The 'ByteRange' gap must exclude the entire 'Contents' string value, its '<'/'>' delimiters included (ISO 32000-1 clause 12.8.1, PA-6.3-k).";

            return false;
        }

        if(!TryDecodeOptionalTextEntry(entries, "M", out string? signingTimeText, out error))
        {
            return false;
        }

        DateTimeOffset? signingTime = null;
        if(signingTimeText is not null)
        {
            if(!TryParsePdfDate(signingTimeText, out DateTimeOffset parsedSigningTime))
            {
                error = "A signature dictionary's 'M' entry is not a well-formed ISO 32000-1 date string.";

                return false;
            }

            signingTime = parsedSigningTime;
        }

        if(!TryDecodeOptionalTextEntry(entries, "Location", out string? location, out error) ||
            !TryDecodeOptionalTextEntry(entries, "Reason", out string? reason, out error) ||
            !TryDecodeOptionalTextEntry(entries, "ContactInfo", out string? contactInfo, out error) ||
            !TryDecodeOptionalTextEntry(entries, "Name", out string? name, out error))
        {
            return false;
        }

        string? type = entries.TryGetValue("Type", out PdfValue typeValue) && typeValue.Kind == PdfValueKind.Name ? typeValue.Text : null;

        CmsSignedData contents = CmsSignedData.FromBytes(contentsBytes, pool);
        signature = new PdfSignatureDictionary(
            document, filterValue.Text!, new PdfSubFilter(subFilterValue.Text!), byteRange, contents, signingTime, location, reason, contactInfo, name,
            objectOffset, type);

        return true;
    }


    /// <summary>Reads an optional string-typed dictionary entry, decoding it as PDF text (PDFDocEncoding or UTF-16BE), fail-closed when present under a non-string kind.</summary>
    internal static bool TryDecodeOptionalTextEntry(IReadOnlyDictionary<string, PdfValue> entries, string key, out string? decoded, [NotNullWhen(false)] out string? error)
    {
        decoded = null;
        error = null;
        if(!entries.TryGetValue(key, out PdfValue value))
        {
            return true;
        }

        if((value.Kind != PdfValueKind.LiteralString && value.Kind != PdfValueKind.HexString) || value.StringBytes is not byte[] stringBytes)
        {
            error = $"A signature dictionary's '{key}' entry is present but is not a string.";

            return false;
        }

        decoded = DecodeTextString(stringBytes);

        return true;
    }


    /// <summary>
    /// Decodes a PDF text string (ISO 32000-1 clause 7.9.2): UTF-16BE when a byte-order mark opens it, otherwise
    /// PDFDocEncoding. PDFDocEncoding's own mapping table (ISO 32000-1 annex D) is ISO 32000-1 internals this
    /// reader does not transcribe (RP-2); its ASCII-range subset — every value this reader's own fixtures and
    /// ordinary Location/Reason/ContactInfo/Name text use — is decoded via the Latin-1-compatible fallback below.
    /// </summary>
    internal static string DecodeTextString(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF
            ? Encoding.BigEndianUnicode.GetString(bytes[2..])
            : Encoding.Latin1.GetString(bytes);


    /// <summary>Parses an ISO 32000-1 clause 7.9.4 date string (<c>D:YYYYMMDDHHmmSSOHH'mm'</c>), with every part after the four-digit year optional.</summary>
    internal static bool TryParsePdfDate(string text, out DateTimeOffset value)
    {
        value = default;
        ReadOnlySpan<char> chars = text;
        int i = 0;
        if(chars.Length >= 2 && chars[0] == 'D' && chars[1] == ':')
        {
            i = 2;
        }

        if(!TryReadFixedDigits(chars, ref i, 4, out int year))
        {
            return false;
        }

        int month = 1;
        int day = 1;
        int hour = 0;
        int minute = 0;
        int second = 0;
        if(i < chars.Length && char.IsAsciiDigit(chars[i]) && !TryReadFixedDigits(chars, ref i, 2, out month))
        {
            return false;
        }

        if(i < chars.Length && char.IsAsciiDigit(chars[i]) && !TryReadFixedDigits(chars, ref i, 2, out day))
        {
            return false;
        }

        if(i < chars.Length && char.IsAsciiDigit(chars[i]) && !TryReadFixedDigits(chars, ref i, 2, out hour))
        {
            return false;
        }

        if(i < chars.Length && char.IsAsciiDigit(chars[i]) && !TryReadFixedDigits(chars, ref i, 2, out minute))
        {
            return false;
        }

        if(i < chars.Length && char.IsAsciiDigit(chars[i]) && !TryReadFixedDigits(chars, ref i, 2, out second))
        {
            return false;
        }

        TimeSpan offset = TimeSpan.Zero;
        if(i < chars.Length && (chars[i] == '+' || chars[i] == '-'))
        {
            bool negative = chars[i] == '-';
            i++;
            if(!TryReadFixedDigits(chars, ref i, 2, out int offsetHours))
            {
                return false;
            }

            int offsetMinutes = 0;
            if(i < chars.Length && chars[i] == '\'')
            {
                i++;
                if(!TryReadFixedDigits(chars, ref i, 2, out offsetMinutes))
                {
                    return false;
                }

                if(i < chars.Length && chars[i] == '\'')
                {
                    i++;
                }
            }

            offset = new TimeSpan(offsetHours, offsetMinutes, 0);
            if(negative)
            {
                offset = -offset;
            }
        }
        else if(i < chars.Length && chars[i] == 'Z')
        {
            i++;
        }

        try
        {
            value = new DateTimeOffset(year, month, day, hour, minute, second, offset);

            return true;
        }
        catch(ArgumentOutOfRangeException)
        {
            return false;
        }
    }


    /// <summary>Reads exactly <paramref name="digitCount"/> ASCII digits as an unsigned integer.</summary>
    private static bool TryReadFixedDigits(ReadOnlySpan<char> chars, ref int i, int digitCount, out int value)
    {
        value = 0;
        if(i + digitCount > chars.Length)
        {
            return false;
        }

        for(int k = 0; k < digitCount; ++k)
        {
            char c = chars[i + k];
            if(!char.IsAsciiDigit(c))
            {
                return false;
            }

            value = (value * 10) + (c - '0');
        }

        i += digitCount;

        return true;
    }
}
