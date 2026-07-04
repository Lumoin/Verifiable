namespace Verifiable.Keri;

/// <summary>
/// The KERI / ACDC protocol genus and its well-known genus/version codes. A CESR stream selects the genus of
/// the count codes that follow with a protocol genus/version code; the KERI / ACDC stack is genus <c>AAA</c>.
/// The genus is what makes the count codes after it mean what <see cref="KeriCountCodeSemantics"/> says they mean.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#keriacdc-protocol-genus-version-table">
/// KERI/ACDC protocol genus version table</see>: the stable genus code is <c>-_AAA</c>, and the published
/// genus/version codes are <c>-_AAABAA</c> (genus <c>AAA</c>, version 1.00) and <c>-_AAACAA</c> (genus
/// <c>AAA</c>, version 2.00).
/// </para>
/// </remarks>
public static class KeriGenus
{
    /// <summary>
    /// The five-character stable genus code of the KERI / ACDC protocol stack (<c>-_AAA</c>).
    /// </summary>
    public const string GenusCode = "-_AAA";

    /// <summary>
    /// The three-character genus identifier of the KERI / ACDC protocol stack (<c>AAA</c>), the hard characters
    /// of <see cref="GenusCode"/> after the <c>-_</c> prefix.
    /// </summary>
    public const string Genus = "AAA";

    /// <summary>
    /// The full genus/version code for the KERI / ACDC stack at version 1.00 (<c>-_AAABAA</c>).
    /// </summary>
    public const string Version1Code = "-_AAABAA";

    /// <summary>
    /// The full genus/version code for the KERI / ACDC stack at version 2.00 (<c>-_AAACAA</c>).
    /// </summary>
    public const string Version2Code = "-_AAACAA";


    /// <summary>
    /// Whether a stable genus code is the KERI / ACDC genus.
    /// </summary>
    /// <param name="genusCode">The stable (hard) genus code, for example a stream's genus/version token code.</param>
    /// <returns><see langword="true"/> when the code is <see cref="GenusCode"/>.</returns>
    public static bool IsKeriGenus(string genusCode)
    {
        ArgumentNullException.ThrowIfNull(genusCode);

        return string.Equals(genusCode, GenusCode, StringComparison.Ordinal);
    }
}
