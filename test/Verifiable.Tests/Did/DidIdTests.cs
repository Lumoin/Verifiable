using Verifiable.Core.Assessment;
using Verifiable.Core.Did;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Ebsi;
using Verifiable.Core.Did.Methods.Keri;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Json.Converters;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Did
{
    [TestClass]
    internal sealed class DidIdTests
    {
        /// <summary>
        /// All the known DID methods.
        /// </summary>
        private static DidMethodFactoryDelegate DidFactoryDelegate { get; } = did =>
        {
            return did switch
            {
                "did:key:" => new KeyDidMethod(did),
                "did:web:" => new WebDidMethod(did),
                "did:ebsi:" => new EbsiDidMethod(did),
                "did:keri:" => new KeriDidMethod(did),
                "did:plc:" => new PlaceholderDidMethod(did),
                _ => new GenericDidMethod(did)
            };
        };


        [TestMethod]
        public void DidIdTest()
        {
            const string DidUrl = "did:example:123456/path?versionId=1#public-key-0";
            var didDocument = new DidDocument { Id = new GenericDidMethod(DidUrl) };

            var resultClaims = DidDocumentValidationRules.ValidatePrefix(didDocument);
            Assert.IsTrue(resultClaims.All(c => c.Outcome == ClaimOutcome.Success));
        }


        /// <summary>
        /// The required prefix for each known DID method's constructor, paired with a factory that
        /// invokes that constructor.
        /// </summary>
        public static IEnumerable<object[]> GetDidMethodConstructorsWithRequiredPrefix()
        {
            yield return new object[] { "did:web:", new Func<string, GenericDidMethod>(didString => new WebDidMethod(didString)) };
            yield return new object[] { "did:keri:", new Func<string, GenericDidMethod>(didString => new KeriDidMethod(didString)) };
            yield return new object[] { "did:ebsi:", new Func<string, GenericDidMethod>(didString => new EbsiDidMethod(didString)) };
            yield return new object[] { "did:peer:", new Func<string, GenericDidMethod>(didString => new PeerDidMethod(didString)) };
            yield return new object[] { "did:key:", new Func<string, GenericDidMethod>(didString => new KeyDidMethod(didString)) };
            yield return new object[] { "did:plc:", new Func<string, GenericDidMethod>(didString => new PlaceholderDidMethod(didString)) };
        }


        /// <summary>
        /// DID Core 1.0 &#167;3.1 defines the DID method-name production as <c>1*method-char</c> of
        /// lowercase ASCII and requires DIDs to be compared by exact string match. A soft hyphen
        /// (U+00AD, a Unicode default-ignorable code point) inserted into the method prefix produces
        /// a byte-different string that a culture-aware comparison could still accept as the
        /// well-known prefix; each DID method's constructor must reject it.
        /// </summary>
        /// <param name="requiredPrefix">The exact prefix the constructor under test requires.</param>
        /// <param name="construct">A factory that invokes the constructor under test.</param>
        [TestMethod]
        [DynamicData(nameof(GetDidMethodConstructorsWithRequiredPrefix))]
        public void DidMethodConstructorRejectsPrefixWithIgnorableCodePoint(string requiredPrefix, Func<string, GenericDidMethod> construct)
        {
            string tamperedDid = requiredPrefix.InsertIgnorableCodePointAt(4) + "abc";

            Assert.ThrowsExactly<ArgumentException>(() => construct(tamperedDid));
        }


        /// <summary>
        /// DID Core 1.0 &#167;3.1 requires DIDs to be compared by exact string match. A soft hyphen
        /// (U+00AD, a Unicode default-ignorable code point) inserted into a well-known DID method
        /// prefix produces a byte-different string that a culture-aware comparison could still treat
        /// as equal to the prefix; <see cref="WellKnownDidMethodPrefixes.Equals(string, string)"/> and
        /// its <c>Is*DidPrefix</c> predicates must reject it.
        /// </summary>
        [TestMethod]
        public void WellKnownDidMethodPrefixRejectsIgnorableCodePointVariant()
        {
            string tamperedPrefix = WellKnownDidMethodPrefixes.WebDidMethodPrefix.InsertIgnorableCodePointAt(4);

            Assert.IsFalse(WellKnownDidMethodPrefixes.Equals(WellKnownDidMethodPrefixes.WebDidMethodPrefix, tamperedPrefix));
            Assert.IsFalse(WellKnownDidMethodPrefixes.IsWebDidPrefix(tamperedPrefix));
        }


        /// <summary>
        /// DID Core 1.0 &#167;3.1 delimits the DID method name by the colon that follows it, so
        /// <c>did:web</c>, <c>did:webvh</c>, and <c>did:webplus</c> are distinct method names rather
        /// than a shared prefix family. <see cref="WebDidMethod"/> must reject an identifier using
        /// either of the other two method names.
        /// </summary>
        [TestMethod]
        public void WebDidMethodConstructorRejectsDistinctWebRelatedMethodNames()
        {
            Assert.ThrowsExactly<ArgumentException>(() => new WebDidMethod("did:webvh:example.com:abc"));
            Assert.ThrowsExactly<ArgumentException>(() => new WebDidMethod("did:webplus:example.com"));
        }
    }
}
