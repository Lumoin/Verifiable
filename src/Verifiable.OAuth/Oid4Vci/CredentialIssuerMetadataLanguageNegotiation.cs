using System.Globalization;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// OID4VCI 1.0 §12.2.2 <c>Accept-Language</c> / <c>Content-Language</c> negotiation for the
/// human-readable <c>display</c> values of the Credential Issuer Metadata document.
/// </summary>
/// <remarks>
/// <para>
/// §12.2.2: "The Wallet is RECOMMENDED to send an Accept-Language header in the HTTP GET request
/// to indicate the language(s) preferred for display." A Credential Issuer that honours it may
/// "send a subset the metadata containing internationalized display data for one or all of the
/// requested languages and indicate returned languages using the HTTP Content-Language Header".
/// "The language(s) in HTTP Accept-Language and Content-Language Headers MUST use the values
/// defined in [RFC3066]."
/// </para>
/// <para>
/// This helper implements RFC 9110 §12.5.4 best-match over the RFC 3066 language tags: it parses
/// the <c>Accept-Language</c> field (quality weights, ordering, the <c>*</c> wildcard), inspects
/// the <c>locale</c> tags actually present in a <c>display</c> array, and selects the single
/// highest-ranked language for which the array carries an entry — prefix-folding a range such as
/// <c>de</c> onto a <c>de-DE</c> entry. The endpoint then filters every <c>display</c> array to
/// that language and sets <c>Content-Language</c> to the served tag. With no <c>Accept-Language</c>,
/// or no requested language present in the data, the endpoint keeps the current behaviour and
/// serves all languages (the §12.2.2 "ignore the Accept-Language Header" option).
/// </para>
/// </remarks>
public static class CredentialIssuerMetadataLanguageNegotiation
{
    /// <summary>
    /// Selects the best-matching served language for <paramref name="acceptLanguage"/> over the
    /// <c>locale</c> tags present in <paramref name="displayArrays"/>, per RFC 9110 §12.5.4.
    /// Returns <see langword="null"/> when no negotiation applies (absent/empty header, no
    /// candidate locales, or no acceptable match) — in which case the caller serves all languages.
    /// </summary>
    /// <param name="acceptLanguage">The raw <c>Accept-Language</c> field value, or <see langword="null"/>.</param>
    /// <param name="displayArrays">The <c>display</c> arrays whose entries' <c>locale</c> tags are the negotiation candidates.</param>
    /// <returns>The chosen RFC 3066 language tag to serve and set as <c>Content-Language</c>, or <see langword="null"/>.</returns>
    public static string? SelectServedLanguage(
        string? acceptLanguage,
        IEnumerable<IReadOnlyList<object>?> displayArrays)
    {
        ArgumentNullException.ThrowIfNull(displayArrays);

        if(string.IsNullOrWhiteSpace(acceptLanguage))
        {
            return null;
        }

        List<AcceptLanguageRange> ranges = ParseAcceptLanguage(acceptLanguage);
        if(ranges.Count == 0)
        {
            return null;
        }

        List<string> candidateLocales = CollectLocales(displayArrays);
        if(candidateLocales.Count == 0)
        {
            return null;
        }

        string? bestLocale = null;
        double bestQuality = 0.0;
        int bestSpecificity = -1;
        int bestCandidateOrder = int.MaxValue;
        for(int candidateOrder = 0; candidateOrder < candidateLocales.Count; candidateOrder++)
        {
            string locale = candidateLocales[candidateOrder];
            (double quality, int specificity) = ScoreLocale(locale, ranges);

            //A zero weight (q=0) explicitly refuses a language; it never wins.
            if(quality <= 0.0)
            {
                continue;
            }

            //Higher weight wins; ties go to the more specific range match (a "de-DE" range outranks
            //"de" outranks "*"), then to the candidate the issuer listed first for stability.
            bool isBetter = quality > bestQuality
                || (quality == bestQuality && specificity > bestSpecificity)
                || (quality == bestQuality && specificity == bestSpecificity && candidateOrder < bestCandidateOrder);
            if(isBetter)
            {
                bestLocale = locale;
                bestQuality = quality;
                bestSpecificity = specificity;
                bestCandidateOrder = candidateOrder;
            }
        }

        return bestLocale;
    }


    /// <summary>
    /// Returns a copy of <paramref name="display"/> keeping only entries whose <c>locale</c> matches
    /// <paramref name="servedLanguage"/> by RFC 3066 prefix-fold (a <c>de</c> served language keeps a
    /// <c>de</c> or <c>de-DE</c> entry). Entries carrying no <c>locale</c> are language-neutral and
    /// are kept. Returns <paramref name="display"/> unchanged when <paramref name="servedLanguage"/>
    /// is <see langword="null"/>.
    /// </summary>
    /// <param name="display">The <c>display</c> array to filter.</param>
    /// <param name="servedLanguage">The negotiated language tag, or <see langword="null"/> to keep all.</param>
    /// <returns>The filtered (or unchanged) <c>display</c> array.</returns>
    public static IReadOnlyList<object> FilterDisplay(IReadOnlyList<object> display, string? servedLanguage)
    {
        ArgumentNullException.ThrowIfNull(display);

        if(servedLanguage is null)
        {
            return display;
        }

        List<object> filtered = new(display.Count);
        foreach(object entry in display)
        {
            if(entry is not IReadOnlyDictionary<string, object> displayEntry)
            {
                //A non-object entry carries no locale to filter on; keep it verbatim so the
                //§12.2.4 shape validation (not this language filter) owns the malformed-entry verdict.
                filtered.Add(entry);

                continue;
            }

            string? locale = ReadLocale(displayEntry);
            if(locale is null || RangeMatchesTag(servedLanguage, locale))
            {
                filtered.Add(entry);
            }
        }

        return filtered;
    }


    /// <summary>Reads an entry's <c>locale</c> tag, or <see langword="null"/> when absent or not a string.</summary>
    private static string? ReadLocale(IReadOnlyDictionary<string, object> displayEntry) =>
        displayEntry.TryGetValue(CredentialIssuerMetadataParameterNames.Locale, out object? value)
            && value is string locale
            && !string.IsNullOrWhiteSpace(locale)
                ? locale
                : null;


    /// <summary>Collects the distinct <c>locale</c> tags across all display arrays, in first-seen order.</summary>
    private static List<string> CollectLocales(IEnumerable<IReadOnlyList<object>?> displayArrays)
    {
        List<string> locales = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        foreach(IReadOnlyList<object>? display in displayArrays)
        {
            if(display is null)
            {
                continue;
            }

            foreach(object entry in display)
            {
                if(entry is IReadOnlyDictionary<string, object> displayEntry
                    && ReadLocale(displayEntry) is string locale
                    && seen.Add(locale))
                {
                    locales.Add(locale);
                }
            }
        }

        return locales;
    }


    /// <summary>
    /// Scores a candidate <paramref name="locale"/> against the parsed ranges: the quality weight of
    /// the most specific range that matches it (by RFC 3066 prefix-fold), with the matched range's
    /// subtag count as the specificity tie-breaker.
    /// </summary>
    private static (double Quality, int Specificity) ScoreLocale(string locale, List<AcceptLanguageRange> ranges)
    {
        double bestQuality = 0.0;
        int bestSpecificity = -1;
        foreach(AcceptLanguageRange range in ranges)
        {
            if(!RangeMatchesTag(range.Tag, locale))
            {
                continue;
            }

            if(range.Specificity > bestSpecificity
                || (range.Specificity == bestSpecificity && range.Quality > bestQuality))
            {
                bestQuality = range.Quality;
                bestSpecificity = range.Specificity;
            }
        }

        return (bestQuality, bestSpecificity);
    }


    /// <summary>
    /// Whether the RFC 9110 §12.5.4 language range <paramref name="range"/> matches the RFC 3066
    /// language tag <paramref name="tag"/> — the wildcard <c>*</c> matches anything, an exact tag
    /// matches case-insensitively, and a shorter range matches a longer tag on a subtag boundary
    /// (<c>de</c> matches <c>de-DE</c>, but not <c>de-DE</c> against <c>de</c>).
    /// </summary>
    private static bool RangeMatchesTag(string range, string tag)
    {
        if(range == "*")
        {
            return true;
        }

        if(string.Equals(range, tag, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return tag.Length > range.Length
            && tag.StartsWith(range, StringComparison.OrdinalIgnoreCase)
            && tag[range.Length] == '-';
    }


    /// <summary>
    /// Parses an <c>Accept-Language</c> field into ranges with their quality weights (RFC 9110
    /// §12.5.4). A range with no explicit <c>q</c> defaults to <c>1.0</c>; a malformed weight is
    /// treated as <c>1.0</c>; <c>*</c> carries specificity 0 so a named range outranks it.
    /// </summary>
    private static List<AcceptLanguageRange> ParseAcceptLanguage(string acceptLanguage)
    {
        List<AcceptLanguageRange> ranges = [];
        foreach(string rawElement in acceptLanguage.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string[] parts = rawElement.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if(parts.Length == 0)
            {
                continue;
            }

            string tag = parts[0];
            if(tag.Length == 0)
            {
                continue;
            }

            double quality = ReadQuality(parts);
            int specificity = tag == "*" ? 0 : CountSubtags(tag);
            ranges.Add(new AcceptLanguageRange(tag, quality, specificity));
        }

        return ranges;
    }


    /// <summary>Reads the <c>q=</c> weight from an element's parameters, defaulting to <c>1.0</c>.</summary>
    private static double ReadQuality(string[] parts)
    {
        for(int i = 1; i < parts.Length; i++)
        {
            string parameter = parts[i];
            if(!parameter.StartsWith("q=", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string weight = parameter[2..];

            return double.TryParse(weight, NumberStyles.Float, CultureInfo.InvariantCulture, out double parsed)
                ? Math.Clamp(parsed, 0.0, 1.0)
                : 1.0;
        }

        return 1.0;
    }


    /// <summary>Counts the subtags in a language tag (the number of <c>-</c>-separated parts).</summary>
    private static int CountSubtags(string tag)
    {
        int count = 1;
        foreach(char c in tag)
        {
            if(c == '-')
            {
                count++;
            }
        }

        return count;
    }


    /// <summary>A parsed <c>Accept-Language</c> range: the tag, its quality weight, and its subtag specificity.</summary>
    private readonly record struct AcceptLanguageRange(string Tag, double Quality, int Specificity);
}
