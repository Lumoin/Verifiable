using Verifiable.Core.Did;
using Verifiable.Core.Model.Did;


namespace Verifiable.Tests
{
    /// <summary>
    /// Tests for <see cref="DidUrlRegex"/> patterns and their integration with <see cref="DidUrl"/> parsing.
    /// These tests ensure that the regex patterns and the DidUrl parser remain synchronized.
    /// </summary>
    [TestClass]
    internal sealed class DidUrlParsingTests
    {
        /// <summary>
        /// Test cases for absolute DID URL validation, including expected results.
        /// </summary>
        private static (string Input, bool ExpectedValid)[] AbsoluteDidUrlTestCases { get; } =
        [
            ("did:example:123", true),
            ("did:example:123#key-1", true),
            ("did:example:123/path", true),
            ("did:example:123?service=files", true),
            ("did:example:123/path?service=files#key-1", true),
            ("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", true),
            ("did:web:example.com", true),
            ("did:web:example.com:path", true),
            ("#key-1", false),
            ("invalid", false),
            ("", false),
            ("did:", false),
            ("did:example:", false),
            ("http://example.com", false),
            ("did:EXAMPLE:123", false), //Method names must be lowercase
            ("did:example:123 invalid", false)
        ];


        /// <summary>
        /// Test cases for fragment-only reference validation, including expected results.
        /// </summary>
        private static (string Input, bool ExpectedValid)[] FragmentReferenceTestCases { get; } =
        [
            ("#key-1", true),
            ("#agent", true),
            ("#service-endpoint", true),
            ("#verificationMethod/0", true),
            ("#", false), //Empty fragment
            ("did:example:123", false),
            ("did:example:123#key-1", false),
            ("invalid", false),
            ("", false),
            ("key-1", false) //Missing hash
        ];


        /// <summary>
        /// Test cases for unified DID URL validation (both absolute and fragment), including expected results.
        /// </summary>
        private static (string Input, bool ExpectedValid)[] UnifiedDidUrlTestCases { get; } =
        [
            ("did:example:123", true),
            ("did:example:123#key-1", true),
            ("did:example:123/path?service=files#key-1", true),
            ("#key-1", true),
            ("#agent", true),
            ("invalid", false),
            ("", false),
            ("#", false), //Empty fragment.
            ("did:", false),
            ("did:example:", false)
        ];


        [TestMethod]
        public void FragmentReferenceRegexAndParserShouldAgree()
        {
            foreach(var (input, expectedValid) in FragmentReferenceTestCases)
            {
                //Test regex directly.
                bool regexResult = DidUrlRegex.FragmentReference().IsMatch(input);

                //Test DidUrl parser.
                bool parserResult = DidUrl.TryParseFragment(input, out _);

                //Both should agree with expected result.
                Assert.AreEqual(expectedValid, regexResult, $"Regex disagreed with expected result for: '{input}'.");
                Assert.AreEqual(expectedValid, parserResult, $"Parser disagreed with expected result for: '{input}'.");
                Assert.AreEqual(regexResult, parserResult, $"Regex and parser disagreed for: '{input}'.");
            }
        }


        [TestMethod]
        public void UnifiedDidUrlRegexAndParserShouldAgree()
        {
            foreach(var (input, expectedValid) in UnifiedDidUrlTestCases)
            {
                //Test regex directly.
                bool regexResult = DidUrlRegex.AnyDidUrl().IsMatch(input);

                //Test DidUrl parser.
                bool parserResult = DidUrl.TryParse(input, out _);

                //Both should agree with expected result.
                Assert.AreEqual(expectedValid, regexResult, $"Regex disagreed with expected result for: '{input}'.");
                Assert.AreEqual(expectedValid, parserResult, $"Parser disagreed with expected result for: '{input}'.");
                Assert.AreEqual(regexResult, parserResult, $"Regex and parser disagreed for: '{input}'.");
            }
        }


        [TestMethod]
        public void ParsedComponentsMatchRegexGroups()
        {
            var testCases = new[]
            {
                "did:example:123",
                "did:example:123#key-1",
                "did:example:123/path",
                "did:example:123?service=files",
                "did:example:123/path?service=files#key-1",
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1"
            };

            foreach(var input in testCases)
            {
                var regexMatch = DidUrlRegex.AbsoluteDidUrl().Match(input);
                var didUrl = DidUrl.ParseAbsolute(input);

                Assert.IsTrue(regexMatch.Success, $"Regex should match: '{input}'.");

                //Verify components match regex groups.
                Assert.AreEqual(regexMatch.Groups[1].Value, didUrl.Method, $"Method mismatch for: '{input}'.");
                Assert.AreEqual(regexMatch.Groups[2].Value, didUrl.MethodSpecificId, $"MethodSpecificId mismatch for: '{input}'.");

                string? expectedPath = regexMatch.Groups[3].Success ? regexMatch.Groups[3].Value : null;
                Assert.AreEqual(expectedPath, didUrl.Path, $"Path mismatch for: '{input}'.");

                string? expectedQuery = regexMatch.Groups[4].Success ? regexMatch.Groups[4].Value[1..] : null; //Remove leading '?'.
                Assert.AreEqual(expectedQuery, didUrl.Query, $"Query mismatch for: '{input}'.");

                string? expectedFragment = regexMatch.Groups[5].Success ? regexMatch.Groups[5].Value[1..] : null; //Remove leading '#'.
                Assert.AreEqual(expectedFragment, didUrl.Fragment, $"Fragment mismatch for: '{input}'.");
            }
        }


        [TestMethod]
        public void FragmentComponentsMatchRegexGroups()
        {
            var testCases = new[] { "#key-1", "#agent", "#service-endpoint" };

            foreach(var input in testCases)
            {
                var regexMatch = DidUrlRegex.FragmentReference().Match(input);
                var didUrl = DidUrl.ParseFragment(input);

                Assert.IsTrue(regexMatch.Success, $"Regex should match: '{input}'.");
                Assert.AreEqual(regexMatch.Groups[1].Value, didUrl.Fragment, $"Fragment mismatch for: '{input}'.");
                Assert.IsTrue(didUrl.IsRelative, $"Should be relative for: '{input}'.");
            }
        }


        [TestMethod]
        public void AbsoluteDidUrlRegexAndParserShouldAgree()
        {
            foreach(var (input, expectedValid) in AbsoluteDidUrlTestCases)
            {
                //Test regex directly.
                bool regexResult = DidUrlRegex.AbsoluteDidUrl().IsMatch(input);

                //Test DidUrl parser.
                bool parserResult = DidUrl.TryParseAbsolute(input, out _);

                //Both should agree with expected result.
                Assert.AreEqual(expectedValid, regexResult, $"Regex disagreed with expected result for: '{input}'.");
                Assert.AreEqual(expectedValid, parserResult, $"Parser disagreed with expected result for: '{input}'.");
                Assert.AreEqual(regexResult, parserResult, $"Regex and parser disagreed for: '{input}'.");
            }
        }

        [TestMethod]
        public void ParseAbsoluteValidInputReturnsCorrectComponents()
        {
            var didUrl = DidUrl.ParseAbsolute("did:example:123/path?service=files&relativeRef=/resume.pdf#key-1");

            Assert.AreEqual("example", didUrl.Method);
            Assert.AreEqual("123", didUrl.MethodSpecificId);
            Assert.AreEqual("/path", didUrl.Path);
            Assert.AreEqual("service=files&relativeRef=/resume.pdf", didUrl.Query);
            Assert.AreEqual("key-1", didUrl.Fragment);
            Assert.IsTrue(didUrl.IsAbsolute);
            Assert.IsFalse(didUrl.IsRelative);
            Assert.AreEqual("did:example:123", didUrl.BaseDid);
        }


        [TestMethod]
        public void ParseFragmentValidInputReturnsCorrectComponents()
        {
            var didUrl = DidUrl.ParseFragment("#key-1");

            Assert.IsNull(didUrl.Method);
            Assert.IsNull(didUrl.MethodSpecificId);
            Assert.IsNull(didUrl.Path);
            Assert.IsNull(didUrl.Query);
            Assert.AreEqual("key-1", didUrl.Fragment);
            Assert.IsFalse(didUrl.IsAbsolute);
            Assert.IsTrue(didUrl.IsRelative);
            Assert.IsNull(didUrl.BaseDid);
        }


        [TestMethod]
        public void ParseHandlesAbsoluteAndFragment()
        {
            var absoluteUrl = DidUrl.Parse("did:example:123#key-1");
            var fragmentUrl = DidUrl.Parse("#key-1");

            Assert.IsTrue(absoluteUrl.IsAbsolute);
            Assert.IsTrue(fragmentUrl.IsRelative);
        }


        [TestMethod]
        public void ParseAbsoluteInvalidInputThrowsException()
        {
            Assert.ThrowsExactly<ArgumentException>(() => DidUrl.ParseAbsolute("#key-1"));
        }


        [TestMethod]
        public void ParseFragmentInvalidInputThrowsException()
        {
            Assert.ThrowsExactly<ArgumentException>(() => DidUrl.ParseFragment("did:example:123"));
        }


        [TestMethod]
        public void ParseNullInputThrowsException()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => DidUrl.Parse(null!));
        }


        [TestMethod]
        public void ToStringReturnsOriginalInput()
        {
            var testCases = new[]
            {
                "did:example:123",
                "did:example:123#key-1",
                "did:example:123/path?service=files#key-1",
                "#key-1"
            };

            foreach(var input in testCases)
            {
                var didUrl = DidUrl.Parse(input);
                Assert.AreEqual(input, didUrl.ToString());
            }
        }


        [TestMethod]
        public void ImplicitStringOperatorWorksCorrectly()
        {
            var didUrl = DidUrl.Parse("did:example:123#key-1");
            string? result = didUrl;
            Assert.AreEqual("did:example:123#key-1", result);
        }


        [TestMethod]
        public void ExplicitDidUrlOperatorWorksCorrectly()
        {
            var didUrl = (DidUrl)"did:example:123#key-1";
            Assert.AreEqual("example", didUrl.Method);
            Assert.AreEqual("123", didUrl.MethodSpecificId);
            Assert.AreEqual("key-1", didUrl.Fragment);
        }


        [TestMethod]
        public void ResolveFragmentAgainstBaseDidWorksCorrectly()
        {
            var baseDid = DidUrl.ParseAbsolute("did:example:123");
            var fragment = DidUrl.ParseFragment("#key-1");

            var resolved = fragment.Resolve(baseDid);

            Assert.AreEqual("did:example:123#key-1", resolved.ToString());
            Assert.AreEqual("example", resolved.Method);
            Assert.AreEqual("123", resolved.MethodSpecificId);
            Assert.AreEqual("key-1", resolved.Fragment);
            Assert.IsTrue(resolved.IsAbsolute);
        }


        [TestMethod]
        public void ResolveAbsoluteDidUrlThrowsException()
        {
            var absoluteDidUrl = DidUrl.ParseAbsolute("did:example:123#key-1");
            var baseDid = DidUrl.ParseAbsolute("did:example:456");

            Assert.ThrowsExactly<InvalidOperationException>(() => absoluteDidUrl.Resolve(baseDid));
        }


        [TestMethod]
        public void GetParametersParsesQueryCorrectly()
        {
            var didUrl = DidUrl.ParseAbsolute("did:example:123?service=files&relativeRef=%2Fresume.pdf&versionId=1");
            var parameters = didUrl.GetParameters();

            Assert.HasCount(3, parameters);
            Assert.AreEqual("files", parameters["service"]);
            Assert.AreEqual("/resume.pdf", parameters["relativeRef"]); //URL decoded
            Assert.AreEqual("1", parameters["versionId"]);
        }


        [TestMethod]
        public void GetParameterReturnsCorrectValue()
        {
            var didUrl = DidUrl.ParseAbsolute("did:example:123?service=files&relativeRef=/resume.pdf");

            Assert.AreEqual("files", didUrl.GetParameter("service"));
            Assert.AreEqual("/resume.pdf", didUrl.GetParameter("relativeRef"));
            Assert.IsNull(didUrl.GetParameter("nonexistent"));
        }


        [TestMethod]
        public void GetParametersEmptyQueryReturnsEmptyDictionary()
        {
            var didUrl = DidUrl.ParseAbsolute("did:example:123");
            var parameters = didUrl.GetParameters();

            Assert.IsEmpty(parameters);
        }
    }
}
