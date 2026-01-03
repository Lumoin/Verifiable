using Verifiable.Core.Model.Did;
using Verifiable.Jose;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Tests for <see cref="PublicKeyJwk" /> <see cref="System.IEquatable{T}" /> implementation.
    /// </summary>
    [TestClass]
    public sealed class PublicKeyJwkEquatableTests
    {
        /// <summary>
        /// A first instance for testing comparisons.
        /// </summary>
        private static PublicKeyJwk Jwk1 { get; } = new PublicKeyJwk
        {
            Header = new Dictionary<string, object>
            {
                [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec,
                [JwkProperties.Crv] = WellKnownCurveValues.P256,
                [JwkProperties.X] = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                [JwkProperties.Y] = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                [JwkProperties.Alg] = WellKnownJwaValues.Es256
            },
            Payload = new Dictionary<string, object>
            {
                [JwkProperties.Use] = "sig",
                [JwkProperties.Kid] = "test-key-1"
            }
        };

        /// <summary>
        /// A second instance with different properties for testing comparisons.
        /// </summary>
        private static PublicKeyJwk Jwk2 { get; } = new PublicKeyJwk
        {
            Header = new Dictionary<string, object>
            {
                [JwkProperties.Kty] = WellKnownKeyTypeValues.Rsa,
                [JwkProperties.N] = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISO",
                [JwkProperties.E] = "AQAB",
                [JwkProperties.Alg] = WellKnownJwaValues.Rs256
            }
        };

        /// <summary>
        /// A third instance with the same properties as the first for testing equality.
        /// </summary>
        private static PublicKeyJwk Jwk3 { get; } = new PublicKeyJwk
        {
            Header = new Dictionary<string, object>
            {
                [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec,
                [JwkProperties.Crv] = WellKnownCurveValues.P256,
                [JwkProperties.X] = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                [JwkProperties.Y] = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                [JwkProperties.Alg] = WellKnownJwaValues.Es256
            },
            Payload = new Dictionary<string, object>
            {
                [JwkProperties.Use] = "sig",
                [JwkProperties.Kid] = "test-key-1"
            }
        };


        [TestMethod]
        public void InstancesWithDifferentPropertiesAreNotEqual()
        {
            Assert.IsFalse(Jwk1.Equals(Jwk2));
            Assert.IsFalse(Jwk1 == Jwk2);
            Assert.IsTrue(Jwk1 != Jwk2);
        }


        [TestMethod]
        public void InstancesWithSamePropertiesAreEqual()
        {
            Assert.IsTrue(Jwk1.Equals(Jwk3));
            Assert.IsTrue(Jwk1 == Jwk3);
            Assert.IsFalse(Jwk1 != Jwk3);
        }


        [TestMethod]
        public void SameInstanceIsEqualToItself()
        {
            Assert.IsTrue(Jwk1.Equals(Jwk1));
            Assert.IsTrue(Jwk1 == Jwk1);
            Assert.IsFalse(Jwk1 != Jwk1);
        }


        [TestMethod]
        public void ComparisonWithTypeAndObjectSucceeds()
        {
            object jwkAsObject = Jwk1;
            Assert.IsTrue(Jwk1.Equals(jwkAsObject));
        }


        [TestMethod]
        public void JwkAndObjectEqualityComparisonSucceeds()
        {
            object jwkAsObject = Jwk1;
            bool result1 = Jwk1 == jwkAsObject;
            Assert.IsTrue(result1);

            bool result2 = jwkAsObject == Jwk1;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void JwkAndObjectInequalityComparisonSucceeds()
        {
            object jwkAsObject = Jwk1;
            bool result1 = Jwk1 != jwkAsObject;
            Assert.IsFalse(result1);

            bool result2 = jwkAsObject != Jwk1;
            Assert.IsFalse(result2);
        }


        [TestMethod]
        public void JwkAndObjectEqualityComparisonWithDifferentValuesSucceeds()
        {
            object jwkAsObject = Jwk2;
            bool result1 = Jwk1 == jwkAsObject;
            Assert.IsFalse(result1);

            bool result2 = Jwk1 != jwkAsObject;
            Assert.IsTrue(result2);
        }


        [TestMethod]
        public void EqualsWithDifferentTypesReturnsFalse()
        {
            object differentType = new();
            Assert.IsFalse(Jwk1.Equals(differentType));
        }


        [TestMethod]
        public void EqualsWithNullObjectReturnsFalse()
        {
            object? nullObject = null;
            Assert.IsFalse(Jwk1.Equals(nullObject));
        }


        [TestMethod]
        public void EqualsWithNullKeyFormatReturnsFalse()
        {
            KeyFormat? nullKeyFormat = null;
            Assert.IsFalse(Jwk1.Equals(nullKeyFormat));
        }


        [TestMethod]
        public void NullKeyFormatsAreEqual()
        {
            PublicKeyJwk? jwk1 = null;
            PublicKeyJwk? jwk2 = null;
            Assert.IsTrue(jwk1 == jwk2);
            Assert.IsFalse(jwk1 != jwk2);
        }


        [TestMethod]
        public void NullAndNonNullKeyFormatsAreNotEqual()
        {
            PublicKeyJwk? nullJwk = null;
            Assert.IsFalse(nullJwk == Jwk1);
            Assert.IsFalse(Jwk1 == nullJwk);
            Assert.IsTrue(nullJwk != Jwk1);
            Assert.IsTrue(Jwk1 != nullJwk);
        }


        [TestMethod]
        public void JwksWithDifferentHeadersAreNotEqual()
        {
            var jwk1 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec,
                    [JwkProperties.Crv] = WellKnownCurveValues.P256
                }
            };

            var jwk2 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [JwkProperties.Kty] = WellKnownKeyTypeValues.Rsa,
                    [JwkProperties.N] = "abc123"
                }
            };

            Assert.IsFalse(jwk1.Equals(jwk2));
            Assert.IsFalse(jwk1 == jwk2);
            Assert.IsTrue(jwk1 != jwk2);
        }


        [TestMethod]
        public void JwksWithDifferentPayloadsAreNotEqual()
        {
            var jwk1 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object> { [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec },
                Payload = new Dictionary<string, object> { [JwkProperties.Use] = "sig" }
            };

            var jwk2 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object> { [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec },
                Payload = new Dictionary<string, object> { [JwkProperties.Use] = "enc" }
            };

            Assert.IsFalse(jwk1.Equals(jwk2));
            Assert.IsFalse(jwk1 == jwk2);
            Assert.IsTrue(jwk1 != jwk2);
        }


        [TestMethod]
        public void JwksWithNullPayloadsCanBeEqual()
        {
            var jwk1 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object> { [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec },
                Payload = null
            };

            var jwk2 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object> { [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec },
                Payload = null
            };

            Assert.IsTrue(jwk1.Equals(jwk2));
            Assert.IsTrue(jwk1 == jwk2);
            Assert.IsFalse(jwk1 != jwk2);
        }


        [TestMethod]
        public void JwksWithNullAndNonNullPayloadsAreNotEqual()
        {
            var jwk1 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object> { [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec },
                Payload = null
            };

            var jwk2 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object> { [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec },
                Payload = new Dictionary<string, object> { [JwkProperties.Use] = "sig" }
            };

            Assert.IsFalse(jwk1.Equals(jwk2));
            Assert.IsFalse(jwk1 == jwk2);
            Assert.IsTrue(jwk1 != jwk2);
        }


        [TestMethod]
        public void HashCodeIsConsistentForEqualInstances()
        {
            Assert.AreEqual(Jwk1.GetHashCode(), Jwk3.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsDifferentForDifferentInstances()
        {
            //Note: This test may occasionally fail due to hash collisions, but should generally pass.
            Assert.AreNotEqual(Jwk1.GetHashCode(), Jwk2.GetHashCode());
        }


        [TestMethod]
        public void HashCodeIsConsistentAcrossMultipleCalls()
        {
            int hash1 = Jwk1.GetHashCode();
            int hash2 = Jwk1.GetHashCode();
            Assert.AreEqual(hash1, hash2);
        }


        [TestMethod]
        public void JwkWithDifferentKeyOrdersAreEqual()
        {
            var jwk1 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec,
                    [JwkProperties.Crv] = WellKnownCurveValues.P256,
                    [JwkProperties.X] = "abc"
                }
            };

            var jwk2 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [JwkProperties.Crv] = WellKnownCurveValues.P256,
                    [JwkProperties.X] = "abc",
                    [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec
                }
            };

            Assert.IsTrue(jwk1.Equals(jwk2));
            Assert.IsTrue(jwk1 == jwk2);
            Assert.IsFalse(jwk1 != jwk2);
        }


        [TestMethod]
        public void Ed25519JwkEqualityWorksCorrectly()
        {
            var jwk1 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [JwkProperties.Kty] = WellKnownKeyTypeValues.Okp,
                    [JwkProperties.Crv] = WellKnownCurveValues.Ed25519,
                    [JwkProperties.X] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                    [JwkProperties.Alg] = WellKnownJwaValues.EdDsa
                }
            };

            var jwk2 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [JwkProperties.Kty] = WellKnownKeyTypeValues.Okp,
                    [JwkProperties.Crv] = WellKnownCurveValues.Ed25519,
                    [JwkProperties.X] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                    [JwkProperties.Alg] = WellKnownJwaValues.EdDsa
                }
            };

            Assert.IsTrue(jwk1.Equals(jwk2));
            Assert.IsTrue(jwk1 == jwk2);
            Assert.IsFalse(jwk1 != jwk2);
        }


        [TestMethod]
        public void Secp256k1JwkEqualityWorksCorrectly()
        {
            var jwk1 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec,
                    [JwkProperties.Crv] = WellKnownCurveValues.Secp256k1,
                    [JwkProperties.X] = "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXQ",
                    [JwkProperties.Y] = "y77As5vbZx_ErFOfGmHV-DIjkA0vyNNw-sDslUt6ld0",
                    [JwkProperties.Alg] = WellKnownJwaValues.Es256k1
                }
            };

            var jwk2 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec,
                    [JwkProperties.Crv] = WellKnownCurveValues.Secp256k1,
                    [JwkProperties.X] = "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXQ",
                    [JwkProperties.Y] = "y77As5vbZx_ErFOfGmHV-DIjkA0vyNNw-sDslUt6ld0",
                    [JwkProperties.Alg] = WellKnownJwaValues.Es256k1
                }
            };

            Assert.IsTrue(jwk1.Equals(jwk2));
            Assert.IsTrue(jwk1 == jwk2);
            Assert.IsFalse(jwk1 != jwk2);
        }


        [TestMethod]
        public void X25519JwkEqualityWorksCorrectly()
        {
            var jwk1 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [JwkProperties.Kty] = WellKnownKeyTypeValues.Okp,
                    [JwkProperties.Crv] = WellKnownCurveValues.X25519,
                    [JwkProperties.X] = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
                    [JwkProperties.Alg] = WellKnownJwaValues.Ecdha
                }
            };

            var jwk2 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    [JwkProperties.Kty] = WellKnownKeyTypeValues.Okp,
                    [JwkProperties.Crv] = WellKnownCurveValues.X25519,
                    [JwkProperties.X] = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
                    [JwkProperties.Alg] = WellKnownJwaValues.Ecdha
                }
            };

            Assert.IsTrue(jwk1.Equals(jwk2));
            Assert.IsTrue(jwk1 == jwk2);
            Assert.IsFalse(jwk1 != jwk2);
        }


        [TestMethod]
        public void JwkWithComplexPayloadEqualityWorksCorrectly()
        {
            var complexPayload = new Dictionary<string, object>
            {
                [JwkProperties.Use] = "sig",
                [JwkProperties.Kid] = "test-key-1",
                ["custom_claim"] = "custom_value",
                ["nested"] = new Dictionary<string, object>
                {
                    ["inner"] = "value"
                }
            };

            var jwk1 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object> { [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec },
                Payload = complexPayload
            };

            var jwk2 = new PublicKeyJwk
            {
                Header = new Dictionary<string, object> { [JwkProperties.Kty] = WellKnownKeyTypeValues.Ec },
                Payload = new Dictionary<string, object>(complexPayload)
            };

            Assert.IsTrue(jwk1.Equals(jwk2));
            Assert.IsTrue(jwk1 == jwk2);
            Assert.IsFalse(jwk1 != jwk2);
        }
    }
}