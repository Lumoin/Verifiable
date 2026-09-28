using System.Text;

namespace Verifiable.Core.Text;

/// <summary>
/// One occurrence of a <see cref="TextHygieneClass"/> selected by a <see cref="TextHygieneRule"/>: where it is,
/// how many input units it spans, and which code point it holds. An occurrence is the answer of an inspection, not
/// an error of it, and <see cref="CodePoint"/> is derived from <see cref="Class"/>, so it is null exactly when
/// <see cref="Class"/> is <see cref="TextHygieneClass.IllFormedEncoding"/> for every value of the type. This is a
/// value type, so its default value exists, with <see cref="Offset"/> and <see cref="Length"/> both zero; no
/// inspection ever produces that value, because every occurrence <see cref="TextHygiene"/> reports has a
/// <see cref="Length"/> of at least one. <see cref="ForCodePoint"/> and <see cref="ForIllFormedEncoding"/> are the
/// only way <see cref="TextHygiene"/> builds an occurrence with a positive length.
/// </summary>
public readonly record struct TextHygieneFinding
{
    /// <summary>
    /// Stores the members of one occurrence; <see cref="ForCodePoint"/> and <see cref="ForIllFormedEncoding"/> pair
    /// them consistently.
    /// </summary>
    /// <param name="offset">The index of the first input unit of the occurrence.</param>
    /// <param name="length">The number of input units the occurrence spans.</param>
    /// <param name="storedCodePoint">The scalar or lone code unit; zero for an ill-formed sequence, where it is never read.</param>
    /// <param name="class">The class the rule selected.</param>
    private TextHygieneFinding(int offset, int length, int storedCodePoint, TextHygieneClass @class)
    {
        Offset = offset;
        Length = length;
        StoredCodePoint = storedCodePoint;
        Class = @class;
    }

    /// <summary>
    /// Gets the index of the occurrence's first input unit: a UTF-16 code-unit index when the input was
    /// <see cref="ReadOnlySpan{T}"/> of <see cref="char"/>, a byte offset when it was UTF-8 bytes.
    /// </summary>
    public int Offset { get; }

    /// <summary>
    /// Gets how many input units the occurrence spans, in the unit of <see cref="Offset"/>: one or two UTF-16
    /// code units, one to four UTF-8 bytes, or the length of an ill-formed UTF-8 maximal subpart. A caller cuts
    /// the occurrence out of its input with <see cref="Offset"/> and this length, without decoding again.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the code point the occurrence holds: a Unicode scalar value, or for
    /// <see cref="TextHygieneClass.UnpairedSurrogate"/> the lone code unit, which is a surrogate code point and not
    /// a scalar value. Null for <see cref="TextHygieneClass.IllFormedEncoding"/>, whose bytes decode to no code point.
    /// A caller that turns the value into a character reads <see cref="Scalar"/>, which is null in both of those cases.
    /// </summary>
    public int? CodePoint => Class == TextHygieneClass.IllFormedEncoding ? null : StoredCodePoint;

    /// <summary>
    /// Gets <see cref="CodePoint"/> as a <see cref="Rune"/> when it is a Unicode scalar value, and null for a lone
    /// surrogate or an ill-formed sequence, so a caller never constructs a <see cref="Rune"/> from a value that has none.
    /// </summary>
    public Rune? Scalar => CodePoint is { } value && Rune.IsValid(value) ? new Rune(value) : null;

    /// <summary>
    /// Gets the class the <see cref="TextHygieneRule"/> selected for this occurrence.
    /// </summary>
    public TextHygieneClass Class { get; }

    /// <summary>
    /// Gets the stored scalar or lone code unit that <see cref="CodePoint"/> exposes unless the occurrence is an
    /// ill-formed sequence.
    /// </summary>
    private int StoredCodePoint { get; }

    /// <summary>
    /// Creates the occurrence of a decoded scalar or a lone UTF-16 code unit.
    /// </summary>
    /// <param name="offset">The index of the first input unit.</param>
    /// <param name="length">The input units the scalar or code unit spans.</param>
    /// <param name="codePoint">The scalar value or lone code unit.</param>
    /// <param name="class">A class other than <see cref="TextHygieneClass.IllFormedEncoding"/>.</param>
    /// <returns>The occurrence carrying its code point.</returns>
    internal static TextHygieneFinding ForCodePoint(int offset, int length, int codePoint, TextHygieneClass @class)
    {
        return new TextHygieneFinding(offset, length, codePoint, @class);
    }

    /// <summary>
    /// Creates the occurrence of an ill-formed UTF-8 maximal subpart, which has no code point.
    /// </summary>
    /// <param name="offset">The byte offset of the subpart.</param>
    /// <param name="length">The bytes the subpart spans.</param>
    /// <returns>The occurrence with a null <see cref="CodePoint"/>.</returns>
    internal static TextHygieneFinding ForIllFormedEncoding(int offset, int length)
    {
        return new TextHygieneFinding(offset, length, 0, TextHygieneClass.IllFormedEncoding);
    }
}
