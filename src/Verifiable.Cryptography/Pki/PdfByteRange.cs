using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>ByteRange</c> entry of a PDF Signature Dictionary
/// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 5.3, PA-5.3-01) as PAdES uses it: two segments of digest-covered bytes
/// bracketing exactly one excluded gap — the hexadecimal <c>Contents</c> string itself. Clause 6.3 requirement
/// k) states the shape this type enforces: "The ByteRange shall cover the entire file, including the Signature
/// Dictionary but excluding the PDF Signature itself (the entry with key <c>Contents</c>)" (PA-6.3-k); the
/// Document Time-stamp dictionary's own ByteRange sentence (PA-5.4.3-07) describes the identical single-gap
/// shape. ISO 32000-1 clause 12.8.1 itself allows a <c>ByteRange</c> array of more than two segments in the
/// general case; PAdES never produces more than the one gap these two segments bracket, so a four-integer array
/// is the only shape this reader accepts — a wider array is rejected fail-closed rather than silently narrowed.
/// </summary>
/// <remarks>
/// The first segment always starts at byte 0 — clause 6.3 requirement k)'s "entire file" — so only its length is
/// carried; the first segment's own offset is not a separate field.
/// </remarks>
[DebuggerDisplay("PdfByteRange: [0,{FirstLength}) + [{SecondOffset},{SecondOffset + SecondLength})")]
public readonly record struct PdfByteRange
{
    /// <summary>Gets the length in bytes of the first signed segment, which starts at byte 0.</summary>
    public required int FirstLength { get; init; }

    /// <summary>Gets the byte offset at which the second signed segment starts — the byte immediately after the excluded gap.</summary>
    public required int SecondOffset { get; init; }

    /// <summary>Gets the length in bytes of the second signed segment.</summary>
    public required int SecondLength { get; init; }

    /// <summary>Gets the offset at which the excluded gap (the <c>Contents</c> hexadecimal string) begins — equal to <see cref="FirstLength"/>, since the first segment starts at byte 0.</summary>
    public int GapStart => FirstLength;

    /// <summary>Gets the length in bytes of the excluded gap.</summary>
    public int GapLength => SecondOffset - GapStart;

    /// <summary>Gets the file length this <c>ByteRange</c> states it was computed against — the offset just past the second segment.</summary>
    public int DocumentLength => SecondOffset + SecondLength;

    /// <summary>
    /// Reports whether this <c>ByteRange</c> states that its two segments cover the entire supplied document —
    /// clause 6.3 requirement k)'s "entire file" reading for the document's <em>current</em> length, which is
    /// true of the most recently applied signature in a file carrying several incremental-update signatures and
    /// false of an earlier one (whose own <c>ByteRange</c> correctly stops at that earlier revision's shorter
    /// length). Left to the caller rather than enforced at parse time, since the byte-surface reader locates
    /// every signature dictionary a document carries without judging which one is the newest.
    /// </summary>
    /// <param name="documentLength">The length in bytes of the document to compare against.</param>
    /// <returns><see langword="true"/> when <see cref="DocumentLength"/> equals <paramref name="documentLength"/>.</returns>
    public bool CoversEntireDocument(int documentLength) => DocumentLength == documentLength;


    /// <summary>
    /// Parses and validates a <c>ByteRange</c> array's four integers into a <see cref="PdfByteRange"/>,
    /// fail-closed on every shape the PAdES single-gap reading does not admit.
    /// </summary>
    /// <param name="numbers">The <c>ByteRange</c> array's elements, in wire order.</param>
    /// <param name="documentLength">The length in bytes of the document the array was read from, so a range reaching past the end of the actual bytes is rejected.</param>
    /// <param name="range">The parsed range, when this method returns <see langword="true"/>.</param>
    /// <param name="error">The reason parsing failed, when this method returns <see langword="false"/>.</param>
    /// <returns><see langword="true"/> when the array is a well-formed, non-overlapping, in-bounds PAdES <c>ByteRange</c>.</returns>
    public static bool TryCreate(ReadOnlySpan<long> numbers, int documentLength, out PdfByteRange range, [NotNullWhen(false)] out string? error)
    {
        range = default;

        if(numbers.Length != 4)
        {
            error = $"A PAdES ByteRange names exactly two segments (four integers, PA-6.3-k); found {numbers.Length}.";

            return false;
        }

        long firstOffset = numbers[0];
        long firstLength = numbers[1];
        long secondOffset = numbers[2];
        long secondLength = numbers[3];

        if(firstOffset != 0)
        {
            error = "The first ByteRange segment shall start at byte 0 (PA-6.3-k: the ByteRange covers the entire file).";

            return false;
        }

        if(firstLength < 0 || secondOffset < 0 || secondLength < 0)
        {
            error = "A ByteRange segment declares a negative offset or length.";

            return false;
        }

        if(firstLength > documentLength || secondOffset > documentLength || secondLength > documentLength - secondOffset)
        {
            error = "The ByteRange declares an offset or length reaching past the end of the document.";

            return false;
        }

        long gapStart = firstOffset + firstLength;
        if(secondOffset < gapStart)
        {
            error = "The two ByteRange segments overlap: the second segment starts before the first one ends.";

            return false;
        }

        range = new PdfByteRange
        {
            FirstLength = (int)firstLength,
            SecondOffset = (int)secondOffset,
            SecondLength = (int)secondLength
        };
        error = null;

        return true;
    }
}
