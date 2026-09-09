using System.Globalization;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose
{
    /// <summary>
    /// Tests for <see cref="DictionaryEquality"/>, the shared dictionary equality and hash code
    /// computation backing <see cref="JsonWebKey"/>, <see cref="JwtHeader"/>,
    /// <see cref="JwtPayload"/>, <see cref="JoseDictionary"/>, <see cref="UnverifiedJwtHeader"/>, and
    /// <see cref="UnverifiedJwtPayload"/>.
    /// </summary>
    [TestClass]
    internal sealed class DictionaryEqualityTests
    {
        /// <summary>
        /// RFC 7517 &#167;4 JWK members (and the other JOSE dictionary-backed types built on this
        /// utility) compare as exact JSON member names.
        /// <see cref="DictionaryEquality.GetDictionaryHashCode"/> combines entries in key order, so
        /// the hash must be a pure function of content: the iteration order must not depend on the
        /// current culture's string collation. The same dictionary must hash to the same value under
        /// two cultures whose default string ordering differs (Danish collates the digraph
        /// <c>"aa"</c> as the letter <c>&#229;</c>, sorting it after <c>"z"</c>, unlike English).
        /// </summary>
        [TestMethod]
        public void GetDictionaryHashCodeIsCultureIndependent()
        {
            var dictionary = new Dictionary<string, object>
            {
                ["aa"] = "1",
                ["z"] = "2",
                ["b"] = "3"
            };

            CultureInfo originalCulture = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = new CultureInfo("en-US");
                int hashUnderEnUs = DictionaryEquality.GetDictionaryHashCode(dictionary);

                CultureInfo.CurrentCulture = new CultureInfo("da-DK");
                int hashUnderDaDk = DictionaryEquality.GetDictionaryHashCode(dictionary);

                Assert.AreEqual(hashUnderEnUs, hashUnderDaDk);
            }
            finally
            {
                CultureInfo.CurrentCulture = originalCulture;
            }
        }
    }
}
