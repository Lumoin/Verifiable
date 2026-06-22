using System;
using System.Collections.Generic;
using System.Globalization;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// A minimal RFC 9110 <c>Accept</c> header parser for the test-only DID Resolution HTTP binding: it parses the
/// comma-separated media ranges and their <c>q</c> weights, and selects the best-matching offered representation
/// by descending quality (specificity breaks ties), or reports that none is acceptable so the binding can answer
/// 406 Not Acceptable.
/// </summary>
/// <remarks>
/// This replaces substring matching with the header's defined semantics: a <c>q=0</c> media range excludes a
/// representation, a wildcard (<c>*/*</c> or <c>type/*</c>) matches by range, and the highest-quality matching
/// offer wins. An absent or empty <c>Accept</c> is treated as <c>*/*</c> (every representation acceptable).
/// </remarks>
internal sealed class HttpAcceptHeader
{
    private readonly IReadOnlyList<MediaRange> ranges;

    private HttpAcceptHeader(IReadOnlyList<MediaRange> ranges)
    {
        this.ranges = ranges;
    }


    /// <summary>Parses an <c>Accept</c> header value. An absent or empty value matches every representation.</summary>
    public static HttpAcceptHeader Parse(string? accept)
    {
        var parsed = new List<MediaRange>();
        if(!string.IsNullOrWhiteSpace(accept))
        {
            foreach(string element in accept.Split(','))
            {
                if(TryParseRange(element, out MediaRange range))
                {
                    parsed.Add(range);
                }
            }
        }

        //An absent or unparseable Accept is */* with quality 1: every representation is acceptable.
        if(parsed.Count == 0)
        {
            parsed.Add(new MediaRange("*", "*", 1.0));
        }

        return new HttpAcceptHeader(parsed);
    }


    /// <summary>
    /// Selects the offered media type with the highest acceptable quality, or <see langword="null"/> when no
    /// offer is acceptable (every match has <c>q=0</c> or no range matches), so the caller can answer 406.
    /// </summary>
    /// <param name="offers">The representations the resource can serve, in the server's preference order.</param>
    public string? SelectBest(IReadOnlyList<string> offers)
    {
        ArgumentNullException.ThrowIfNull(offers);

        string? best = null;
        double bestQuality = 0.0;
        int bestSpecificity = -1;

        foreach(string offer in offers)
        {
            (double quality, int specificity) = Match(offer);

            //A zero quality excludes the offer; among acceptable offers the highest quality wins, with a more
            //specific matching range breaking ties so a concrete media range outranks a wildcard.
            if(quality > 0.0 && (quality > bestQuality || (quality == bestQuality && specificity > bestSpecificity)))
            {
                best = offer;
                bestQuality = quality;
                bestSpecificity = specificity;
            }
        }

        return best;
    }


    //The quality and match specificity of the best media range matching an offered media type. Specificity is 2
    //for an exact type/subtype match, 1 for a type/* match, 0 for */*, and -1 for no match.
    private (double Quality, int Specificity) Match(string offer)
    {
        int slashIndex = offer.IndexOf('/', StringComparison.Ordinal);
        string offerType = slashIndex >= 0 ? offer[..slashIndex] : offer;
        string offerSubtype = slashIndex >= 0 ? offer[(slashIndex + 1)..] : "*";

        double quality = 0.0;
        int specificity = -1;
        foreach(MediaRange range in ranges)
        {
            int rangeSpecificity = range.Specificity(offerType, offerSubtype);
            if(rangeSpecificity > specificity)
            {
                specificity = rangeSpecificity;
                quality = range.Quality;
            }
        }

        return (quality, specificity);
    }


    private static bool TryParseRange(string element, out MediaRange range)
    {
        range = default!;

        string[] parts = element.Split(';');
        string mediaType = parts[0].Trim();
        if(mediaType.Length == 0)
        {
            return false;
        }

        int slashIndex = mediaType.IndexOf('/', StringComparison.Ordinal);
        string type = slashIndex >= 0 ? mediaType[..slashIndex] : mediaType;
        string subtype = slashIndex >= 0 ? mediaType[(slashIndex + 1)..] : "*";

        double quality = 1.0;
        for(int i = 1; i < parts.Length; i++)
        {
            string parameter = parts[i].Trim();
            if(parameter.StartsWith("q=", StringComparison.OrdinalIgnoreCase)
                && double.TryParse(parameter.AsSpan(2), NumberStyles.Float, CultureInfo.InvariantCulture, out double parsedQuality))
            {
                quality = parsedQuality;
            }
        }

        range = new MediaRange(type, subtype, quality);

        return true;
    }


    private readonly record struct MediaRange(string Type, string Subtype, double Quality)
    {
        //The match specificity against an offered type/subtype: 2 for an exact match, 1 for type/*, 0 for */*,
        //and -1 when the range does not match the offer.
        public int Specificity(string offerType, string offerSubtype)
        {
            bool isTypeWildcard = string.Equals(Type, "*", StringComparison.Ordinal);
            bool isSubtypeWildcard = string.Equals(Subtype, "*", StringComparison.Ordinal);

            if(isTypeWildcard)
            {
                return 0;
            }

            if(!string.Equals(Type, offerType, StringComparison.OrdinalIgnoreCase))
            {
                return -1;
            }

            if(isSubtypeWildcard)
            {
                return 1;
            }

            return string.Equals(Subtype, offerSubtype, StringComparison.OrdinalIgnoreCase) ? 2 : -1;
        }
    }
}
