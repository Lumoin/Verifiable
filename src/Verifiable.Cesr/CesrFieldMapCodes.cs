using System.Collections.Frozen;

namespace Verifiable.Cesr;

/// <summary>
/// The well-known CESR primitive codes a native field-map body uses to encode field labels and typed field
/// values: the fixed markers for the null, boolean, escape, and empty values; the variable decimal-number
/// codes; and the label/text codes (compact tags, Base64 strings, and raw-byte strings). Naming these codes
/// here keeps the bare wire strings out of the field-map codec and gives it <c>Is*</c> classification helpers,
/// the same way <see cref="CesrDigestCodes"/> names the digest codes.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// Master code table</see>: a native field map is a sequence of (label, value) primitive pairs, where a label
/// is a compact tag or Base64-string primitive and a value is either one of the fixed marker primitives, a
/// decimal-number primitive, a text primitive, or any other fully qualified primitive carried through verbatim.
/// The fixed markers and the family groupings mirror the specification's escape, decimal, tag, and label codes.
/// </para>
/// </remarks>
public static class CesrFieldMapCodes
{
    /// <summary>The fixed marker code whose value is null (<c>1AAK</c>).</summary>
    public static string Null { get; } = "1AAK";

    /// <summary>The fixed marker code whose value is boolean false (<c>1AAL</c>).</summary>
    public static string No { get; } = "1AAL";

    /// <summary>The fixed marker code whose value is boolean true (<c>1AAM</c>).</summary>
    public static string Yes { get; } = "1AAM";

    /// <summary>
    /// The escape marker code (<c>1AAO</c>): the primitive that follows it is a verbatim value that would
    /// otherwise be mistaken for a typed marker, so its neutral value is that following primitive's own text.
    /// </summary>
    public static string Escape { get; } = "1AAO";

    /// <summary>The fixed marker code whose value is the empty text/nonce value (<c>1AAP</c>).</summary>
    public static string Empty { get; } = "1AAP";


    /// <summary>
    /// The variable decimal-number codes (<c>4H</c>/<c>5H</c>/<c>6H</c> and their big <c>7AAH</c>/<c>8AAH</c>/
    /// <c>9AAH</c> variants), whose value is a signed integer or float carried as a compact Base64 number string.
    /// </summary>
    private static FrozenSet<string> DecimalCodes { get; } = new[]
    {
        "4H", "5H", "6H", "7AAH", "8AAH", "9AAH"
    }.ToFrozenSet();

    /// <summary>
    /// The compact tag codes (<c>0J</c>/<c>0K</c>/<c>X</c>/<c>1AAF</c>/<c>0L</c>/<c>0M</c>/<c>Y</c>/<c>1AAN</c>/
    /// <c>0N</c>/<c>0O</c>/<c>Z</c>), whose one-to-eleven Base64 characters are carried in the code's soft part.
    /// A short label or short Base64 text value auto-sizes to one of these.
    /// </summary>
    private static FrozenSet<string> TagCodes { get; } = new[]
    {
        "0J", "0K", "X", "1AAF", "0L", "0M", "Y", "1AAN", "0N", "0O", "Z"
    }.ToFrozenSet();

    /// <summary>
    /// The Base64-string codes (<c>4A</c>/<c>5A</c>/<c>6A</c> and their big <c>7AAA</c>/<c>8AAA</c>/<c>9AAA</c>
    /// variants), whose value is a Base64-only string longer than a compact tag can carry, packed with mid-pad bits.
    /// </summary>
    private static FrozenSet<string> Base64TextCodes { get; } = new[]
    {
        "4A", "5A", "6A", "7AAA", "8AAA", "9AAA"
    }.ToFrozenSet();

    /// <summary>
    /// The raw-byte text codes (<c>V</c>/<c>W</c> one- and two-byte labels and the <c>4B</c>/<c>5B</c>/<c>6B</c>
    /// and big <c>7AAB</c>/<c>8AAB</c>/<c>9AAB</c> byte strings), whose value is arbitrary text carried as raw bytes.
    /// </summary>
    private static FrozenSet<string> RawTextCodes { get; } = new[]
    {
        "V", "W", "4B", "5B", "6B", "7AAB", "8AAB", "9AAB"
    }.ToFrozenSet();


    /// <summary>
    /// Whether the given stable code is a decimal-number code whose value is a signed integer or float.
    /// </summary>
    /// <param name="code">The stable (hard) code.</param>
    /// <returns><see langword="true"/> when the code is a decimal-number code.</returns>
    public static bool IsDecimalCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        return DecimalCodes.Contains(code);
    }


    /// <summary>
    /// Whether the given stable code is a compact tag code that carries its text in the code's soft part.
    /// </summary>
    /// <param name="code">The stable (hard) code.</param>
    /// <returns><see langword="true"/> when the code is a compact tag code.</returns>
    public static bool IsTagCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        return TagCodes.Contains(code);
    }


    /// <summary>
    /// Whether the given stable code is a Base64-string code whose value is a Base64-only string packed with
    /// mid-pad bits (the encoding a label or text value longer than a compact tag uses).
    /// </summary>
    /// <param name="code">The stable (hard) code.</param>
    /// <returns><see langword="true"/> when the code is a Base64-string code.</returns>
    public static bool IsBase64TextCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        return Base64TextCodes.Contains(code);
    }


    /// <summary>
    /// Whether the given stable code is a raw-byte text code whose value is arbitrary text carried as raw bytes.
    /// </summary>
    /// <param name="code">The stable (hard) code.</param>
    /// <returns><see langword="true"/> when the code is a raw-byte text code.</returns>
    public static bool IsRawTextCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        return RawTextCodes.Contains(code);
    }


    /// <summary>
    /// Whether a value that is itself a complete primitive under the given code would be mistaken for a typed
    /// field-map value (a fixed marker, a number, or a label/text primitive) and so must be escaped to be carried
    /// verbatim. This is every code the field-map encoding treats specially rather than as an opaque qualified value.
    /// </summary>
    /// <param name="code">The stable (hard) code.</param>
    /// <returns><see langword="true"/> when a verbatim value under the code must be escaped.</returns>
    public static bool IsEscapableValueCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        return code == Null
            || code == No
            || code == Yes
            || code == Escape
            || code == Empty
            || DecimalCodes.Contains(code)
            || TagCodes.Contains(code)
            || Base64TextCodes.Contains(code)
            || RawTextCodes.Contains(code);
    }
}
