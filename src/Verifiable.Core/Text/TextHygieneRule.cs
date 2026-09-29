using System.Collections.Frozen;

namespace Verifiable.Core.Text;

/// <summary>
/// An immutable selection of <see cref="TextHygieneClass"/> values that <see cref="TextHygiene"/> reports or escapes,
/// with code points exempt from that selection. Which classes a reader must not be shown is the caller's policy;
/// <see cref="Default"/>, <see cref="DisplayText"/> and <see cref="Strict"/> are the presets, and the
/// <see cref="TextHygieneRule(IEnumerable{TextHygieneClass}, IEnumerable{int})"/> constructor builds any other rule
/// and throws for one that could never select anything it names.
/// A rule selects only what its classes cover: the remarks of <see cref="TextHygieneClass"/> list the code points
/// that act when shown and that no class covers, so no rule is a complete display sanitizer.
/// </summary>
public sealed class TextHygieneRule
{
    /// <summary>
    /// Stores the snapshots of a rule whose values are already known to be usable.
    /// </summary>
    /// <param name="classes">The classes to report or escape.</param>
    /// <param name="allowedCodePoints">The exempt code points.</param>
    private TextHygieneRule(FrozenSet<TextHygieneClass> classes, FrozenSet<int> allowedCodePoints)
    {
        Classes = classes;
        AllowedCodePoints = allowedCodePoints;
    }

    /// <summary>
    /// Gets the classes <see cref="TextHygiene"/> reports or escapes. The set is an immutable snapshot.
    /// </summary>
    public IReadOnlySet<TextHygieneClass> Classes { get; }

    /// <summary>
    /// Gets the code points exempt from <see cref="Classes"/>. An exception overrides every class, including
    /// <see cref="TextHygieneClass.Format"/>, <see cref="TextHygieneClass.Tag"/> and
    /// <see cref="TextHygieneClass.UnpairedSurrogate"/> (a value in D800..DFFF exempts that lone UTF-16 code unit),
    /// and exempting U+2028 or U+2029 exempts a whole class; these are the caller's choice, so a caller that exempts
    /// U+202E shows the reader a real override. A caller that exempts an opener (U+202A, U+202B, U+202D, U+202E,
    /// U+2066 to U+2068) exempts its terminator (U+202C, U+2069) with it, because the library pairs nothing: UAX #9,
    /// <see href="https://www.unicode.org/reports/tr9/#Terminating_Explicit_Directional_Embeddings_and_Overrides">Section 2.3</see>,
    /// states "The following character terminates the scope of the last LRE, RLE, LRO, or RLO whose scope has not
    /// yet been terminated.", so a rule that exempts U+202E but not U+202C (and, for the isolates, U+2069 in
    /// <see href="https://www.unicode.org/reports/tr9/#Terminating_Explicit_Directional_Isolates">Section 2.5</see>)
    /// reports the terminator and passes the opener, which leaves the directional scope open. Exempting the pair
    /// leaves an opener that the input never terminates open all the same, so a reader is safe from an open scope
    /// only when the opener is not exempted. The scope reaches the end of the paragraph: UAX #9,
    /// <see href="https://www.unicode.org/reports/tr9/#X8">rule X8</see>, states "All explicit directional
    /// embeddings, overrides and isolates are completely terminated at the end of each paragraph.", and the paragraph
    /// includes any text the application renders after the output in it.
    /// A carriage return directly followed by a line feed is one line break and is exempt whenever the line feed is.
    /// An ill-formed UTF-8 subpart has no code point, so no exception reaches
    /// <see cref="TextHygieneClass.IllFormedEncoding"/>. The set is an immutable snapshot.
    /// </summary>
    public IReadOnlySet<int> AllowedCodePoints { get; }

    /// <summary>
    /// Gets the rule for text a reader must not be misled by: controls, format characters, line and paragraph
    /// separators, the Tags block, unpaired surrogates and ill-formed UTF-8. It passes the variation selectors, the
    /// assigned default-ignorable code points outside Cf, combining marks, whitespace look-alikes, U+2800 and
    /// confusable characters, which no class covers (see <see cref="TextHygieneClass"/>), and a code point assigned
    /// after the running runtime's Unicode version, which reads as Cn. The reserved default-ignorable code points
    /// outside the Tags block (the ranges <see cref="TextHygieneClass"/> names) are
    /// <see cref="TextHygieneClass.Unassigned"/> while the running runtime has not assigned them, a class
    /// <see cref="Default"/> does not select, so they pass; those inside the Tags block (U+E0000, U+E0002 to
    /// U+E001F) are <see cref="TextHygieneClass.Tag"/>, which <see cref="Default"/> reports.
    /// </summary>
    public static TextHygieneRule Default { get; } = new(
        new[]
        {
            TextHygieneClass.Control, TextHygieneClass.Format, TextHygieneClass.LineSeparator,
            TextHygieneClass.ParagraphSeparator, TextHygieneClass.Tag, TextHygieneClass.UnpairedSurrogate,
            TextHygieneClass.IllFormedEncoding
        }.ToFrozenSet(),
        FrozenSet<int>.Empty);

    /// <summary>
    /// Gets <see cref="Default"/> with tab and line feed allowed for display layout, and a carriage return allowed
    /// only as the first half of a CRLF line break. A lone carriage return stays a
    /// <see cref="TextHygieneClass.Control"/> finding: shown on a terminal or any line-oriented display it returns to
    /// the start of the line, and the text after it overwrites what the reader saw. A line feed starts a new line, so a
    /// partner's text can begin a line that reads as a separate record; a caller that frames records by line uses
    /// <see cref="Default"/>.
    /// </summary>
    public static TextHygieneRule DisplayText { get; } = new(Default.Classes.ToFrozenSet(), new[] { 0x0009, 0x000A }.ToFrozenSet());

    /// <summary>
    /// Gets <see cref="Default"/> plus <see cref="TextHygieneClass.PrivateUse"/> and
    /// <see cref="TextHygieneClass.Unassigned"/>, so a code point assigned after the running runtime's Unicode version,
    /// a reserved default-ignorable code point outside the Tags block and a noncharacter are reported as Cn; a
    /// reserved default-ignorable code point inside the Tags block is still <see cref="TextHygieneClass.Tag"/>. It
    /// still passes the variation selectors, the assigned default-ignorable code points outside Cf, combining marks,
    /// whitespace look-alikes, U+2800 and confusable characters: no class covers them (see <see cref="TextHygieneClass"/>).
    /// </summary>
    public static TextHygieneRule Strict { get; } = new(
        Default.Classes.Concat([TextHygieneClass.PrivateUse, TextHygieneClass.Unassigned]).ToFrozenSet(),
        FrozenSet<int>.Empty);

    /// <summary>
    /// Builds a rule from the caller's classes and exceptions, or throws for one that could never select anything it
    /// names: an empty class set, a value that is not a defined <see cref="TextHygieneClass"/>, or an exception outside
    /// the Unicode codespace 0..10FFFF. The classes are checked before the exceptions, and the first offending value in
    /// input order is named in the exception. Exceptions that exempt a selected code point, or a whole class, are the
    /// caller's choice and are kept (see <see cref="AllowedCodePoints"/>). Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G22696">D9</see> defines the
    /// codespace as "A range of integers from 0 to" 10FFFF (hexadecimal).
    /// </summary>
    /// <param name="classes">The classes to report or escape.</param>
    /// <param name="allowedCodePoints">Exempt scalar values, or lone UTF-16 code units in D800..DFFF.</param>
    /// <exception cref="ArgumentNullException"><paramref name="classes"/> or <paramref name="allowedCodePoints"/>
    /// is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="classes"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="classes"/> holds a value that is not a defined
    /// <see cref="TextHygieneClass"/>, or <paramref name="allowedCodePoints"/> holds a value outside 0..10FFFF.</exception>
    public TextHygieneRule(IEnumerable<TextHygieneClass> classes, IEnumerable<int> allowedCodePoints)
        : this(ValidateClasses(classes), ValidateAllowedCodePoints(allowedCodePoints))
    {
    }

    /// <summary>
    /// Snapshots <paramref name="classes"/> after guarding it against null, emptiness and an undefined value: a
    /// rule with no class would pass every input, and a value that is not a defined <see cref="TextHygieneClass"/>
    /// can never be an occurrence's class.
    /// </summary>
    /// <param name="classes">The classes to report or escape.</param>
    /// <returns>The snapshot the constructor stores as <see cref="Classes"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="classes"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="classes"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="classes"/> holds a value that is not a defined
    /// <see cref="TextHygieneClass"/>.</exception>
    private static FrozenSet<TextHygieneClass> ValidateClasses(IEnumerable<TextHygieneClass> classes)
    {
        ArgumentNullException.ThrowIfNull(classes);
        TextHygieneClass[] classList = [.. classes];
        if(classList.Length == 0)
        {
            throw new ArgumentException("A rule with no class would pass every input.", nameof(classes));
        }

        foreach(TextHygieneClass selected in classList)
        {
            if(!Enum.IsDefined(selected))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(classes), (int)selected, "A rule's class must be a defined TextHygieneClass; an undefined value can never be an occurrence's class.");
            }
        }

        return classList.ToFrozenSet();
    }

    /// <summary>
    /// Snapshots <paramref name="allowedCodePoints"/> after guarding it against null and a value outside the
    /// Unicode codespace 0..10FFFF, which Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G22696">D9</see> defines as
    /// "A range of integers from 0 to" 10FFFF (hexadecimal): such a value can never match an input.
    /// </summary>
    /// <param name="allowedCodePoints">Exempt scalar values, or lone UTF-16 code units in D800..DFFF.</param>
    /// <returns>The snapshot the constructor stores as <see cref="AllowedCodePoints"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="allowedCodePoints"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="allowedCodePoints"/> holds a value outside
    /// 0..10FFFF.</exception>
    private static FrozenSet<int> ValidateAllowedCodePoints(IEnumerable<int> allowedCodePoints)
    {
        ArgumentNullException.ThrowIfNull(allowedCodePoints);
        int[] allowedList = [.. allowedCodePoints];
        foreach(int allowed in allowedList)
        {
            if(allowed < 0 || allowed > MaximumCodePoint)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(allowedCodePoints), allowed, "An exception outside the Unicode codespace 0..10FFFF can never match an input.");
            }
        }

        return allowedList.ToFrozenSet();
    }

    /// <summary>
    /// The largest value in the Unicode codespace. Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G22696">D9</see> defines the
    /// codespace as "A range of integers from 0 to" 10FFFF (hexadecimal), and an exception outside it can match nothing.
    /// </summary>
    private static int MaximumCodePoint { get; } = 0x10FFFF;
}
