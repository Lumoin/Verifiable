using Verifiable.Jose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jwt
{
    /// <summary>
    /// Tests that canonicalization of media type values works correctly.
    /// </summary>
    [TestClass]
    public sealed class WellKnownMediaTypesTests
    {
        /// <summary>
        /// All of the well-known Application media type values and their comparison functions.
        /// </summary>
        public static IEnumerable<object[]> GetApplicationMediaTypeValues()
        {
            yield return new object[] { WellKnownMediaTypes.Application.VcLdJwt, new Func<string, bool>(WellKnownMediaTypes.Application.IsVcLdJwt) };
            yield return new object[] { WellKnownMediaTypes.Application.VpLdJwt, new Func<string, bool>(WellKnownMediaTypes.Application.IsVpLdJwt) };
            yield return new object[] { WellKnownMediaTypes.Application.VcJwt, new Func<string, bool>(WellKnownMediaTypes.Application.IsVcJwt) };
            yield return new object[] { WellKnownMediaTypes.Application.VpJwt, new Func<string, bool>(WellKnownMediaTypes.Application.IsVpJwt) };
            yield return new object[] { WellKnownMediaTypes.Application.VcLdCose, new Func<string, bool>(WellKnownMediaTypes.Application.IsVcLdCose) };
            yield return new object[] { WellKnownMediaTypes.Application.VpLdCose, new Func<string, bool>(WellKnownMediaTypes.Application.IsVpLdCose) };
            yield return new object[] { WellKnownMediaTypes.Application.VcCose, new Func<string, bool>(WellKnownMediaTypes.Application.IsVcCose) };
            yield return new object[] { WellKnownMediaTypes.Application.VpCose, new Func<string, bool>(WellKnownMediaTypes.Application.IsVpCose) };
        }


        /// <summary>
        /// All of the well-known JWT typ header values and their comparison functions.
        /// </summary>
        public static IEnumerable<object[]> GetJwtTypValues()
        {
            yield return new object[] { WellKnownMediaTypes.Jwt.VcLdJwt, new Func<string, bool>(WellKnownMediaTypes.Jwt.IsVcLdJwt) };
            yield return new object[] { WellKnownMediaTypes.Jwt.VpLdJwt, new Func<string, bool>(WellKnownMediaTypes.Jwt.IsVpLdJwt) };
            yield return new object[] { WellKnownMediaTypes.Jwt.VcJwt, new Func<string, bool>(WellKnownMediaTypes.Jwt.IsVcJwt) };
            yield return new object[] { WellKnownMediaTypes.Jwt.VpJwt, new Func<string, bool>(WellKnownMediaTypes.Jwt.IsVpJwt) };
        }


        /// <summary>
        /// Tests that all well-known Application media type values are recognized correctly.
        /// </summary>
        /// <param name="mediaType">The media type to test.</param>
        /// <param name="isCorrectMediaType">The function that checks if the media type is recognized.</param>
        [TestMethod]
        [DynamicData(nameof(GetApplicationMediaTypeValues))]
        public void ApplicationMediaTypeValuesCompareCorrectly(string mediaType, Func<string, bool> isCorrectMediaType)
        {
            //A newly created instance should not reference the canonicalized version.
            //This means a different version even with the same case will not reference
            //the same object. This is a premise check for the implementation of the
            //GetCanonicalizedValue that relies on this optimization to avoid comparing
            //the actual strings if the references are the same.
            string instanceMediaType = new(mediaType);
            Assert.IsFalse(object.ReferenceEquals(mediaType, instanceMediaType), "Instance created from canonical should not reference equal to it.");

            //The correct media type should be correctly identified even if it's not the canonicalized version.
            //This is a premise check for the GetCanonicalizedValue, now the comparison is done with the actual strings.
            Assert.IsTrue(isCorrectMediaType(instanceMediaType), "Is<SomeMediaType> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownMediaTypes.Application.GetCanonicalizedValue(instanceMediaType);
            Assert.IsTrue(object.ReferenceEquals(mediaType, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should still match since media types are case-insensitive per RFC 2045.
            string differentCaseMediaType = instanceMediaType.ToggleCaseForLetterAt(0);
            Assert.IsTrue(isCorrectMediaType(differentCaseMediaType), "Media type comparison should be case-insensitive per RFC 2045.");
        }


        /// <summary>
        /// Tests that all well-known JWT typ header values are recognized correctly.
        /// </summary>
        /// <param name="typ">The typ value to test.</param>
        /// <param name="isCorrectTyp">The function that checks if the typ is recognized.</param>
        [TestMethod]
        [DynamicData(nameof(GetJwtTypValues))]
        public void JwtTypValuesCompareCorrectly(string typ, Func<string, bool> isCorrectTyp)
        {
            //A newly created instance should not reference the canonicalized version.
            string instanceTyp = new(typ);
            Assert.IsFalse(object.ReferenceEquals(typ, instanceTyp), "Instance created from canonical should not reference equal to it.");

            //The correct typ should be correctly identified even if it's not the canonicalized version.
            Assert.IsTrue(isCorrectTyp(instanceTyp), "Is<SomeTyp> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownMediaTypes.Jwt.GetCanonicalizedValue(instanceTyp);
            Assert.IsTrue(object.ReferenceEquals(typ, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should still match since typ comparison is case-insensitive per RFC 7515.
            string differentCaseTyp = instanceTyp.ToggleCaseForLetterAt(0);
            Assert.IsTrue(isCorrectTyp(differentCaseTyp), "Typ comparison should be case-insensitive per RFC 7515.");
        }


        /// <summary>
        /// Tests that the Application.Equals method correctly compares media types case-insensitively.
        /// </summary>
        [TestMethod]
        public void ApplicationEqualsComparesCaseInsensitively()
        {
            Assert.IsTrue(WellKnownMediaTypes.Application.Equals("application/vc+ld+jwt", "APPLICATION/VC+LD+JWT"), "Equals should be case-insensitive.");
            Assert.IsTrue(WellKnownMediaTypes.Application.Equals("application/vc+jwt", "Application/Vc+Jwt"), "Equals should be case-insensitive.");
            Assert.IsFalse(WellKnownMediaTypes.Application.Equals("application/vc+ld+jwt", "application/vp+ld+jwt"), "Different media types should not be equal.");
        }


        /// <summary>
        /// Tests that the Jwt.Equals method correctly compares typ values case-insensitively.
        /// </summary>
        [TestMethod]
        public void JwtEqualsComparesCaseInsensitively()
        {
            Assert.IsTrue(WellKnownMediaTypes.Jwt.Equals("vc+ld+jwt", "VC+LD+JWT"), "Equals should be case-insensitive.");
            Assert.IsTrue(WellKnownMediaTypes.Jwt.Equals("vc+jwt", "Vc+Jwt"), "Equals should be case-insensitive.");
            Assert.IsFalse(WellKnownMediaTypes.Jwt.Equals("vc+ld+jwt", "vp+ld+jwt"), "Different typ values should not be equal.");
        }


        /// <summary>
        /// Tests that unknown media types are not recognized and returned as-is.
        /// </summary>
        [TestMethod]
        public void UnknownMediaTypeIsNotRecognizedAndReturnedAsIs()
        {
            Assert.IsFalse(WellKnownMediaTypes.Application.IsVcLdJwt("application/json"), "Unknown media type should not be recognized as VcLdJwt.");
            Assert.IsFalse(WellKnownMediaTypes.Application.IsVpLdJwt("text/plain"), "Unknown media type should not be recognized as VpLdJwt.");

            string unknownCanonical = WellKnownMediaTypes.Application.GetCanonicalizedValue("application/unknown");
            Assert.AreEqual("application/unknown", unknownCanonical, "Unknown media type should be returned as-is.");
        }


        /// <summary>
        /// Tests that unknown JWT typ values are not recognized and returned as-is.
        /// </summary>
        [TestMethod]
        public void UnknownJwtTypIsNotRecognizedAndReturnedAsIs()
        {
            Assert.IsFalse(WellKnownMediaTypes.Jwt.IsVcLdJwt("unknown"), "Unknown typ should not be recognized as VcLdJwt.");
            Assert.IsFalse(WellKnownMediaTypes.Jwt.IsVpLdJwt("jwt"), "Unknown typ should not be recognized as VpLdJwt.");

            string unknownCanonical = WellKnownMediaTypes.Jwt.GetCanonicalizedValue("unknown");
            Assert.AreEqual("unknown", unknownCanonical, "Unknown typ should be returned as-is.");
        }


        /// <summary>
        /// Tests that Application and Jwt values correspond where applicable.
        /// </summary>
        [TestMethod]
        public void ApplicationAndJwtValuesCorrespond()
        {
            //The Application values should have the "application/" prefix over the Jwt values.
            Assert.AreEqual("application/" + WellKnownMediaTypes.Jwt.VcLdJwt, WellKnownMediaTypes.Application.VcLdJwt, "Application.VcLdJwt should be 'application/' + Jwt.VcLdJwt.");
            Assert.AreEqual("application/" + WellKnownMediaTypes.Jwt.VpLdJwt, WellKnownMediaTypes.Application.VpLdJwt, "Application.VpLdJwt should be 'application/' + Jwt.VpLdJwt.");
            Assert.AreEqual("application/" + WellKnownMediaTypes.Jwt.VcJwt, WellKnownMediaTypes.Application.VcJwt, "Application.VcJwt should be 'application/' + Jwt.VcJwt.");
            Assert.AreEqual("application/" + WellKnownMediaTypes.Jwt.VpJwt, WellKnownMediaTypes.Application.VpJwt, "Application.VpJwt should be 'application/' + Jwt.VpJwt.");
        }
    }
}