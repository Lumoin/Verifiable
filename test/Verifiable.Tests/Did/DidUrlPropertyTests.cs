using CsCheck;
using System.Text;
using Verifiable.Core.Did;
using Verifiable.Core.Model.Did;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Property-based tests for <see cref="DidUrl"/> using CsCheck.
    /// These tests generate thousands of random test cases to ensure comprehensive coverage
    /// and catch edge cases that might not be covered by traditional unit tests.
    /// </summary>
    [TestClass]
    internal sealed class DidUrlPropertyTests
    {
        /// <summary>
        /// Generates valid DID method names according to the ABNF specification.
        /// Method names must be lowercase letters and digits only.
        /// </summary>
        private static Gen<string> GenMethodName { get; } =
            Gen.OneOf(Gen.Char['a', 'z'], Gen.Char['0', '9'])
            .Array[1, 10]
            .Select(chars => new string(chars));

        /// <summary>
        /// Generates valid characters for method-specific identifiers.
        /// According to ABNF: ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
        /// </summary>
        private static Gen<char> GenIdChar { get; } =
            Gen.OneOf(Gen.Char['a', 'z'],
            Gen.Char['A', 'Z'],
            Gen.Char['0', '9'],
            Gen.Const(() => '.'),
            Gen.Const(() => '-'),
            Gen.Const(() => '_'));

        /// <summary>
        /// Generates percent-encoded characters in the format %XX where XX is hexadecimal.
        /// </summary>
        private static Gen<string> GenPercentEncoded { get; } =
            from hex1 in Gen.OneOf(Gen.Char['0', '9'], Gen.Char['A', 'F'])
            from hex2 in Gen.OneOf(Gen.Char['0', '9'], Gen.Char['A', 'F'])
            select $"%{hex1}{hex2}";

        /// <summary>
        /// Generates method-specific identifier segments that can be separated by colons.
        /// Each segment contains valid idchars and optional percent-encoded characters.
        /// </summary>
        private static readonly Gen<string> GenMethodSpecificIdSegment =
            Gen.OneOf(
                GenIdChar.Select(c => c.ToString()),
                GenPercentEncoded
            ).Array[1, 20].Select(parts => string.Concat(parts));

        /// <summary>
        /// Generates complete method-specific identifiers that may contain multiple colon-separated segments.
        /// This handles cases like did:web:example.com:path where "example.com:path" is the method-specific-id.
        /// </summary>
        private static readonly Gen<string> GenMethodSpecificId =
            GenMethodSpecificIdSegment.Array[1, 5]
                .Select(segments => string.Join(":", segments));

        /// <summary>
        /// Generates valid path components that start with "/" and contain valid path characters.
        /// </summary>
        private static readonly Gen<string> GenPath =
            Gen.Char.Where(c => c != '?' && c != '#' && c > 32 && c < 127)
               .Array[0, 30]
               .Select(chars => "/" + new string(chars));

        /// <summary>
        /// Generates valid query parameter names using alphanumeric characters.
        /// </summary>
        private static Gen<string> GenParamName { get; } =
            Gen.OneOf(Gen.Char['a', 'z'], Gen.Char['A', 'Z'], Gen.Char['0', '9'])
            .Array[1, 15]
            .Select(chars => new string(chars));

        /// <summary>
        /// Generates valid query parameter values using URL-safe characters.
        /// </summary>
        private static Gen<string> GenParamValue { get; } =
            Gen.Char.Where(c => c != '&' && c != '#' && c > 32 && c < 127)
            .Array[0, 20]
            .Select(chars => new string(chars));

        /// <summary>
        /// Generates a single query parameter in the format "name=value".
        /// </summary>
        private static Gen<string> GenQueryParam { get; } =
            from name in GenParamName
            from value in GenParamValue
            select $"{name}={value}";

        /// <summary>
        /// Generates complete query strings with multiple parameters separated by "&".
        /// </summary>
        private static Gen<string> GenQuery { get; } = GenQueryParam.Array[1, 5].Select(params_ => string.Join("&", params_));

        /// <summary>
        /// Generates valid fragment identifiers using URL-safe characters.
        /// </summary>
        private static Gen<string> GenFragment { get; } =
            Gen.Char.Where(c => c > 32 && c < 127)
            .Array[1, 20]
            .Select(chars => new string(chars));

        /// <summary>
        /// Generates optional components (either null or a generated value).
        /// </summary>
        private static Gen<T?> GenOption<T>(Gen<T> gen) where T: class => Gen.OneOf(Gen.Const(default(T)), gen.Select(x => (T?)x));


        /// <summary>
        /// Generates complete absolute DID URLs with all optional components.
        /// </summary>
        private static Gen<string> GenAbsoluteDidUrl { get; } =
            from method in GenMethodName
            from methodId in GenMethodSpecificId
            from path in GenOption(GenPath)
            from query in GenOption(GenQuery)
            from fragment in GenOption(GenFragment)
            select BuildDidUrl(method, methodId, path, query, fragment);

        /// <summary>
        /// Generates fragment-only references starting with "#".
        /// </summary>
        private static Gen<string> GenFragmentReference { get; } = GenFragment.Select(frag => $"#{frag}");

        /// <summary>
        /// Generates any valid DID URL (either absolute or fragment-only).
        /// </summary>
        private static Gen<string> GenAnyDidUrl { get; } = Gen.OneOf(GenAbsoluteDidUrl, GenFragmentReference);

        /// <summary>
        /// Generates known valid DID method names for realistic testing.
        /// </summary>
        private static Gen<string> GenKnownMethodName { get; } =
            Gen.OneOf
            (
                Gen.Const("example"),
                Gen.Const("web"),
                Gen.Const("key"),
                Gen.Const("ethr"),
                Gen.Const("ion"),
                Gen.Const("sov"),
                Gen.Const("peer")
            );

        /// <summary>
        /// Generates realistic DID URLs using known method names.
        /// </summary>
        private static Gen<string> GenRealisticDidUrl { get; } =
            from method in GenKnownMethodName
            from methodId in GenMethodSpecificId
            from path in GenOption(GenPath)
            from query in GenOption(GenQuery)
            from fragment in GenOption(GenFragment)
            select BuildDidUrl(method, methodId, path, query, fragment);

        /// <summary>
        /// Builds a complete DID URL string from its components.
        /// </summary>
        /// <param name="method">The DID method name.</param>
        /// <param name="methodId">The method-specific identifier.</param>
        /// <param name="path">Optional path component.</param>
        /// <param name="query">Optional query component.</param>
        /// <param name="fragment">Optional fragment component.</param>
        /// <returns>A complete DID URL string.</returns>
        private static string BuildDidUrl(string method, string methodId, string? path, string? query, string? fragment)
        {
            var builder = new StringBuilder();
            builder.Append("did:");
            builder.Append(method);
            builder.Append(':');
            builder.Append(methodId);

            if(path != null)
            {
                builder.Append(path);
            }

            if(query != null)
            {
                builder.Append('?');
                builder.Append(query);
            }

            if(fragment != null)
            {
                builder.Append('#');
                builder.Append(fragment);
            }

            return builder.ToString();
        }


        /// <summary>
        /// Property: All generated absolute DID URLs should be parseable and maintain their structure.
        /// </summary>
        [TestMethod]
        public void GeneratedAbsoluteDidUrlsAreParseable()
        {
            GenAbsoluteDidUrl.ForAll(didUrlString =>
            {
                //Generated DID URL should be parseable as absolute.
                var parseResult = DidUrl.TryParseAbsolute(didUrlString, out var parsed);

                if(!parseResult)
                {
                    return false;
                }

                //Parsed DID should have method and method-specific-id.
                return !string.IsNullOrEmpty(parsed!.Method)
                    && !string.IsNullOrEmpty(parsed.MethodSpecificId)
                    && parsed.IsAbsolute
                    && !parsed.IsRelative;
            });
        }


        /// <summary>
        /// Property: All generated fragment references should be parseable as fragments.
        /// </summary>
        [TestMethod]
        public void GeneratedFragmentReferencesAreParseable()
        {
            GenFragmentReference.ForAll(fragmentString =>
            {
                //Generated fragment should be parseable as fragment.
                var parseResult = DidUrl.TryParseFragment(fragmentString, out var parsed);

                if(!parseResult)
                {
                    return false;
                }

                //Parsed fragment should have fragment content and be relative.
                return !string.IsNullOrEmpty(parsed!.Fragment)
                    && parsed.IsRelative
                    && !parsed.IsAbsolute
                    && parsed.Method == null
                    && parsed.MethodSpecificId == null;
            });
        }


        /// <summary>
        /// Property: Roundtrip consistency - Parse(url.ToString()) should equal the original.
        /// </summary>
        [TestMethod]
        public void ParsedDidUrlRoundtripConsistency()
        {
            GenAnyDidUrl.ForAll(originalString =>
            {
                if(!DidUrl.TryParse(originalString, out var parsed))
                {
                    //If it doesn't parse, that's a generator issue, not a parser issue.
                    return true;
                }

                var roundtripString = parsed.ToString();
                var reparsed = DidUrl.Parse(roundtripString);

                //Original parsed DID should equal reparsed DID.
                return parsed.Equals(reparsed);
            });
        }


        /// <summary>
        /// Property: Regex and parser should always agree on validity.
        /// </summary>
        [TestMethod]
        public void RegexAndParserAlwaysAgreeOnValidAbsoluteDids()
        {
            GenAbsoluteDidUrl.ForAll(didUrlString =>
            {
                var regexResult = DidUrlRegex.AbsoluteDidUrl().IsMatch(didUrlString);
                var parserResult = DidUrl.TryParseAbsolute(didUrlString, out _);

                return regexResult == parserResult;
            });
        }


        /// <summary>
        /// Property: Regex and parser should always agree on fragment references.
        /// </summary>
        [TestMethod]
        public void RegexAndParserAlwaysAgreeOnValidFragments()
        {
            GenFragmentReference.ForAll(fragmentString =>
            {
                var regexResult = DidUrlRegex.FragmentReference().IsMatch(fragmentString);
                var parserResult = DidUrl.TryParseFragment(fragmentString, out _);

                return regexResult == parserResult;
            });
        }


        /// <summary>
        /// Property: Fragment resolution should work correctly.
        /// </summary>
        [TestMethod]
        public void FragmentResolutionWorksCorrectly()
        {
            var genTuple = from baseDid in GenAbsoluteDidUrl
                           from fragment in GenFragmentReference
                           select (baseDid, fragment);

            genTuple.ForAll(tuple =>
            {
                var (baseDidString, fragmentString) = tuple;
                if(!DidUrl.TryParseAbsolute(baseDidString, out var baseDid)
                    || !DidUrl.TryParseFragment(fragmentString, out var fragment))
                {
                    return true; //Skip invalid generated data.
                }

                var resolved = fragment.Resolve(baseDid);

                //Resolved DID should have the same method and method-specific-id as base.
                //And should have the fragment from the fragment reference.
                return resolved.Method == baseDid.Method &&
                       resolved.MethodSpecificId == baseDid.MethodSpecificId &&
                       resolved.Fragment == fragment.Fragment &&
                       resolved.IsAbsolute &&
                       !resolved.IsRelative;
            });
        }


        /// <summary>
        /// Property: Parameter parsing should be consistent.
        /// </summary>
        [TestMethod]
        public void ParameterParsingConsistency()
        {
            GenRealisticDidUrl.ForAll(didUrlString =>
            {
                if(!DidUrl.TryParseAbsolute(didUrlString, out var parsed))
                {
                    return true; //Skip unparseable URLs.
                }

                var parameters = parsed.GetParameters();

                //If there's no query, parameters should be empty.
                if(string.IsNullOrEmpty(parsed.Query))
                {
                    return parameters.Count == 0;
                }

                //If there is a query, we should have at least some parameters.
                //Each parameter should be retrievable individually.
                foreach(var param in parameters)
                {
                    var individualValue = parsed.GetParameter(param.Key);
                    if(individualValue != param.Value)
                    {
                        return false;
                    }
                }

                return true;
            });
        }


        /// <summary>
        /// Property: Equality and hash code consistency.
        /// </summary>
        [TestMethod]
        public void EqualityAndHashCodeConsistency()
        {
            var genTuple = from url1 in GenAnyDidUrl
                           from url2 in GenAnyDidUrl
                           select (url1, url2);

            genTuple.ForAll(tuple =>
            {
                var (url1String, url2String) = tuple;

                if(!DidUrl.TryParse(url1String, out var url1) ||
                    !DidUrl.TryParse(url2String, out var url2))
                {
                    //Skip unparseable URLs.
                    return true;
                }

                //Equal objects should have equal hash codes.
                if(url1.Equals(url2))
                {
                    return url1.GetHashCode() == url2.GetHashCode();
                }

                //Reflexivity: object should equal itself.
                return url1.Equals(url1) && url2.Equals(url2);
            });
        }


        /// <summary>
        /// Property: Invalid characters should be rejected.
        /// </summary>
        [TestMethod]
        public void InvalidCharactersAreRejected()
        {
            // Replace the incorrect usage of Gen.String() with the correct property access Gen.String
            var genInvalidDid = Gen.String.Where(static s =>
                !string.IsNullOrEmpty(s) &&
                (s.Contains(' ', StringComparison.Ordinal) ||
                 s.Contains('\t', StringComparison.Ordinal) ||
                 s.Contains('\n', StringComparison.Ordinal) ||
                 !s.StartsWith("did:", StringComparison.Ordinal)));

            genInvalidDid.ForAll(static invalidString =>
            {
                var absoluteResult = DidUrl.TryParseAbsolute(invalidString, out _);

                // Invalid strings should not parse successfully (unless they happen to be valid fragments).
                if(invalidString.StartsWith('#') && invalidString.Length > 1)
                {
                    // This might be a valid fragment, so we can't assert it fails.
                    return true;
                }

                // Non-DID strings should not parse as absolute DIDs.
                return !absoluteResult;
            });
        }


        /// <summary>
        /// Property: Method names must be lowercase letters and digits only.
        /// </summary>
        [TestMethod]
        public void MethodNamesMustBeLowercaseLettersAndDigitsOnly()
        {
            //Generate method names from printable ASCII characters, excluding colon to avoid parsing confusion.
            var genPrintableMethodName =
                Gen.Char[(char)32, (char)126]
                   .Where(c => c != ':') //Exclude colon to avoid confusion with DID syntax.
                   .Array[1, 10]
                   .Select(chars => new string(chars))
                   .Where(s => !string.IsNullOrEmpty(s) && s != "did"); //Avoid the "did" keyword itself.

            var genDidWithAnyMethod =
                from method in genPrintableMethodName
                from methodId in GenMethodSpecificId
                select (method, $"did:{method}:{methodId}");

            genDidWithAnyMethod.ForAll(tuple =>
            {
                var (method, didString) = tuple;
                var parseResult = DidUrl.TryParseAbsolute(didString, out _);

                //Check if method contains only lowercase letters and digits.
                bool isValidMethod = method.All(c => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'));

                //Parser result should match method validity.
                return parseResult == isValidMethod;
            });
        }
    }
}