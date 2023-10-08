using System;
using System.Collections.Generic;
using Verifiable.Jwt;
using Verifiable.Tests.TestInfrastructure;
using Xunit;

namespace Verifiable.Tests.Jwt
{
    /// <summary>
    /// Tests that canonicalization of kty values works correctly.
    /// </summary>
    public class WellKnownKeyTypeTests
    {
        /// <summary>
        /// All of the well-known key type values and their comparison functions..
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<object[]> GetKeyTypeValues()
        {
            yield return new object[] { WellKnownKeyTypeValues.Ec, new Func<string, bool>(WellKnownKeyTypeValues.IsEc) };
            yield return new object[] { WellKnownKeyTypeValues.Oct, new Func<string, bool>(WellKnownKeyTypeValues.IsOct) };
            yield return new object[] { WellKnownKeyTypeValues.Okp, new Func<string, bool>(WellKnownKeyTypeValues.IsOkp) };
            yield return new object[] { WellKnownKeyTypeValues.Rsa, new Func<string, bool>(WellKnownKeyTypeValues.IsRsa) };            
        }


        [Theory]
        [MemberData(nameof(GetKeyTypeValues))]
        public void KeyTypesComparesCorrectly(string correctAlgorithm, Func<string, bool> isCorrectAlgorithm)
        {
            //A newly created instance should not reference the canonicalized version.
            //This means a different version even with the same case will not reference
            //the same object. This is a a premise check for the implementation of the
            //WellKnownKtyValues.GetCanonicalizedValue that relies on this optimization
            //to avoid comparing the actual strings if the references are the same.
            string instanceAlgorithm = new(correctAlgorithm);
            Assert.False(object.ReferenceEquals(correctAlgorithm, instanceAlgorithm), "Instance created from canonical should not reference equal to it.");

            //The correct algorithm should be correctly identified even if it's not the canonicalized version.
            //This is a premise check for the WellKnownKtyValues.GetCanonicalizedValue, now the
            //comparison is done with the actual strings.
            Assert.True(isCorrectAlgorithm(instanceAlgorithm), "Is<SomeAlgorithm> should compare correctly to canonicalized version even if instance.");

            //The canonicalized version should be the same as the original.
            string canonicalizedVersion = WellKnownKeyTypeValues.GetCanonicalizedValue(instanceAlgorithm);
            Assert.True(object.ReferenceEquals(correctAlgorithm, canonicalizedVersion), "Canonicalized version should be the same as original.");

            //A case with a toggled letter should not be the same since it's both a different string
            //and a different reference.
            string incorrectAlgorithm = instanceAlgorithm.ToggleCaseForLetterAt(0);
            Assert.False(isCorrectAlgorithm(incorrectAlgorithm), "Comparison should fail when casing is changed.");
        }
    }
}
