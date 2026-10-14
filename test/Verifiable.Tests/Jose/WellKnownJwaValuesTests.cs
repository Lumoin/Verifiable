using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose
{
    /// <summary>
    /// Tests that canonicalization of JWA algorithms works correctly.
    /// </summary>
    [TestClass]
    internal sealed class WellKnownJwaValuesTests
    {
        /// <summary>
        /// The rows of <see cref="JwaAlgorithmComparesCorrectly"/>: every well-known JWA algorithm of
        /// <see cref="WellKnownJwaValues"/> the rows cover, each with its predicate.
        /// </summary>
        /// <returns>
        /// The catalogue's instance of the algorithm name and the predicate of <see cref="WellKnownJwaValues"/>
        /// that recognizes that name.
        /// </returns>
        public static IEnumerable<object[]> GetJwaAlgorithms()
        {
            yield return new object[] { WellKnownJwaValues.None, new Func<string, bool>(WellKnownJwaValues.IsNone) };
            yield return new object[] { WellKnownJwaValues.Hs256, new Func<string, bool>(WellKnownJwaValues.IsHs256) };
            yield return new object[] { WellKnownJwaValues.Hs384, new Func<string, bool>(WellKnownJwaValues.IsHs384) };
            yield return new object[] { WellKnownJwaValues.Hs512, new Func<string, bool>(WellKnownJwaValues.IsHs512) };
            yield return new object[] { WellKnownJwaValues.Es256, new Func<string, bool>(WellKnownJwaValues.IsEs256) };
            yield return new object[] { WellKnownJwaValues.Es384, new Func<string, bool>(WellKnownJwaValues.IsEs384) };
            yield return new object[] { WellKnownJwaValues.Es512, new Func<string, bool>(WellKnownJwaValues.IsEs512) };
            yield return new object[] { WellKnownJwaValues.Es256K, new Func<string, bool>(WellKnownJwaValues.IsEs256K) };
            yield return new object[] { WellKnownJwaValues.Ps256, new Func<string, bool>(WellKnownJwaValues.IsPs256) };
            yield return new object[] { WellKnownJwaValues.Ps384, new Func<string, bool>(WellKnownJwaValues.IsPs384) };
            yield return new object[] { WellKnownJwaValues.Ps512, new Func<string, bool>(WellKnownJwaValues.IsPs512) };
            yield return new object[] { WellKnownJwaValues.Rs256, new Func<string, bool>(WellKnownJwaValues.IsRs256) };
            yield return new object[] { WellKnownJwaValues.Rs384, new Func<string, bool>(WellKnownJwaValues.IsRs384) };
            yield return new object[] { WellKnownJwaValues.Rs512, new Func<string, bool>(WellKnownJwaValues.IsRs512) };
            yield return new object[] { WellKnownJwaValues.EdDsa, new Func<string, bool>(WellKnownJwaValues.IsEdDsa) };
            yield return new object[] { WellKnownJwaValues.Ed25519, new Func<string, bool>(WellKnownJwaValues.IsEd25519) };
        }


        /// <summary>
        /// Tests that all well-known JWA algorithms are recognized: a copy of the name that is not the
        /// catalogue's instance satisfies its predicate and canonicalizes to the catalogue's instance, and the
        /// name with the case of one letter toggled does not satisfy it, since
        /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see> says:
        /// "The "alg" value is a case-sensitive ASCII string containing a StringOrURI value."
        /// </summary>
        /// <param name="correctAlgorithm">The algorithm to test.</param>
        /// <param name="isCorrectAlgorithm">The function that checks if the algorithm is recognized.</param>
        [TestMethod]
        [DynamicData(nameof(GetJwaAlgorithms))]
        public void JwaAlgorithmComparesCorrectly(string correctAlgorithm, Func<string, bool> isCorrectAlgorithm)
        {
            //A newly created instance should not reference the canonicalized version.
            //This means a different version even with the same case will not reference
            //the same object. This is a a premise check for the implementation of the
            //WellKnownJwaValues.GetCanonicalizedValue that relies on this optimization
            //to avoid comparing the actual strings if the references are the same.
            string instanceAlgorithm = new(correctAlgorithm);
            Assert.IsFalse(object.ReferenceEquals(correctAlgorithm, instanceAlgorithm), "Instance created from canonical should not reference equal to it.");

            //The correct algorithm should be correctly identified even if it's not the canonicalized version.
            //This is a premise check for the WellKnownJweAlgorithms.GetCanonicalizedValue, now the
            //comparison is done with the actual strings.
            Assert.IsTrue(isCorrectAlgorithm(instanceAlgorithm), "Is<SomeAlgorithm> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownJwaValues.GetCanonicalizedValue(instanceAlgorithm);
            Assert.IsTrue(object.ReferenceEquals(correctAlgorithm, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should not be the same since it's both a different string
            //and a different reference.
            string incorrectAlgorithm = instanceAlgorithm.ToggleCaseForLetterAt(0);
            Assert.IsFalse(isCorrectAlgorithm(incorrectAlgorithm), "Comparison should fail when casing is changed.");
        }


        /// <summary>
        /// RFC 7515 &#167;4.1.1 and RFC 7518 &#167;3.1 specify "alg" values as case-sensitive strings
        /// compared for exact match. A soft hyphen (U+00AD, a Unicode default-ignorable code point)
        /// inserted into the value produces a byte-different string that a culture-aware comparison
        /// could still treat as equal; <see cref="WellKnownJwaValues.Equals(string, string)"/> must
        /// reject it.
        /// </summary>
        [TestMethod]
        public void JwaAlgorithmWithIgnorableCodePointIsNotEqualToCanonicalValue()
        {
            string tamperedAlgorithm = WellKnownJwaValues.Es256.InsertIgnorableCodePointAt(2);

            Assert.IsFalse(WellKnownJwaValues.Equals(WellKnownJwaValues.Es256, tamperedAlgorithm));
            Assert.IsFalse(WellKnownJwaValues.IsEs256(tamperedAlgorithm));
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, of a DPoP proof's
        /// <c>alg</c>: "An identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]. It MUST NOT
        /// be none or an identifier for a symmetric algorithm (Message Authentication Code (MAC)).", each identifier
        /// compared exactly (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section
        /// 4.1.1</see>: "The "alg" value is a case-sensitive ASCII string containing a StringOrURI value.").
        /// <see cref="WellKnownJwaValues.IsAsymmetricSignatureAlgorithm(string)"/> names the catalogue's asymmetric JWS
        /// signature identifiers <c>ES256</c>, <c>ES256K</c>, <c>RS256</c>, <c>PS256</c>, <c>EdDSA</c>, <c>Ed25519</c>,
        /// <c>ESB256</c> and <c>ML-DSA-44</c>, and names neither the MAC identifier <c>HS256</c>, <c>none</c>, the JWE
        /// key agreement identifier <c>ECDH-ES</c>, <c>es256</c>, <c>ES256</c> with a leading space, nor the empty string.
        /// </summary>
        /// <param name="alg">The identifier asked about.</param>
        /// <param name="isAsymmetricSignatureAlgorithm">Whether the predicate names it.</param>
        [TestMethod]
        [DataRow("ES256", true)]
        [DataRow("ES256K", true)]
        [DataRow("RS256", true)]
        [DataRow("PS256", true)]
        [DataRow("EdDSA", true)]
        [DataRow("Ed25519", true)]
        [DataRow("ESB256", true)]
        [DataRow("ML-DSA-44", true)]
        [DataRow("HS256", false)]
        [DataRow("none", false)]
        [DataRow("ECDH-ES", false)]
        [DataRow("es256", false)]
        [DataRow(" ES256", false, DisplayName = "ES256 with a leading space")]
        [DataRow("", false, DisplayName = "the empty string")]
        public void IsAsymmetricSignatureAlgorithmNamesTheCataloguesAsymmetricSignatureIdentifiers(string alg, bool isAsymmetricSignatureAlgorithm)
        {
            Assert.AreEqual(isAsymmetricSignatureAlgorithm, WellKnownJwaValues.IsAsymmetricSignatureAlgorithm(alg));
        }
    }
}
