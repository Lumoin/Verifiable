using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Tests for <see cref="VerificationMethodResolutionExtensions"/>.
    /// These tests verify that the extension methods can properly resolve verification methods
    /// from DID documents and handle both local and external resolution scenarios.
    /// </summary>
    [TestClass]
    internal sealed class VerificationMethodResolutionExtensionsTests
    {
        private static VerificationMethod TestVerificationMethod1 { get; } = new()
        {
            Id = "#key-1",
            Type = "JsonWebKey2020",
            Controller = "did:example:123",
            KeyFormat = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["alg"] = "ES256",
                    ["x"] = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    ["y"] = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
                }
            }
        };

        private static VerificationMethod TestVerificationMethod2 { get; } = new()
        {
            Id = "#key-2",
            Type = "JsonWebKey2020",
            Controller = "did:example:123",
            KeyFormat = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    ["kty"] = "OKP",
                    ["crv"] = "Ed25519VerificationKey2020",
                    ["alg"] = "EdDSA",
                    ["x"] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
                }
            }
        };

        private static VerificationMethod TestEmbeddedMethod { get; } = new()
        {
            Id = "#embedded-key",
            Type = "JsonWebKey2020",
            Controller = "did:example:123",
            KeyFormat = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-384",
                    ["alg"] = "ES384",
                    ["x"] = "fY7ROTrP1Z_R7T_DaWA_DaEwbJNfGKEUK3QK5cN_-TkA",
                    ["y"] = "HhLlBOECz7L8SqI7k_pA_hOkQlF5K_8Mm_tG_G7fD8A"
                }
            }
        };

        private static VerificationMethod ExternalVerificationMethod { get; } = new()
        {
            Id = "#key-1",
            Type = "JsonWebKey2020",
            Controller = "did:example:external",
            KeyFormat = new PublicKeyJwk
            {
                Header = new Dictionary<string, object>
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["alg"] = "ES256",
                    ["x"] = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    ["y"] = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
                }
            }
        };


        /// <summary>
        /// Creates a comprehensive test DID document with multiple verification methods and relationships.
        /// This includes both referenced and embedded verification methods to test array handling.
        /// </summary>
        /// <returns>A DID document with multiple verification methods in all relationships.</returns>
        private static DidDocument CreateTestDidDocument()
        {
            return new DidDocument
            {
                Id = new GenericDidMethod("did:example:123"),
                VerificationMethod = [TestVerificationMethod1, TestVerificationMethod2],
                Authentication =
                [
                    new AuthenticationMethod("#key-1"),
                    new AuthenticationMethod(TestEmbeddedMethod)
                ],
                AssertionMethod =
                [
                    new AssertionMethod("#key-1"),
                    new AssertionMethod("#key-2")
                ],
                KeyAgreement = [new KeyAgreementMethod("#key-2")],
                CapabilityInvocation = [new CapabilityInvocationMethod("#key-1")],
                CapabilityDelegation =
                [
                    new CapabilityDelegationMethod("#key-1"),
                    new CapabilityDelegationMethod("#key-2")
                ]
            };
        }


        /// <summary>
        /// Creates a test external resolver that simulates retrieving DID documents.
        /// This avoids mocking by using real document structures and uses proper DID URL parsing.
        /// </summary>
        /// <param name="availableDocuments">Dictionary of DID IDs to their documents.</param>
        /// <returns>A resolver function that can resolve external references.</returns>
        private static ExternalVerificationMethodResolver CreateTestResolver(Dictionary<string, DidDocument> availableDocuments)
        {
            return (didReference) =>
            {
                //Parse the DID reference using the proper DID URL parser.
                if(!DidUrl.TryParseAbsolute(didReference, out var didUrl))
                {
                    return ValueTask.FromResult<VerificationMethod?>(null);
                }

                //Extract base DID and fragment.
                var baseDid = didUrl.BaseDid;
                var fragment = didUrl.Fragment;

                if(baseDid == null || fragment == null)
                {
                    return ValueTask.FromResult<VerificationMethod?>(null);
                }

                if(availableDocuments.TryGetValue(baseDid, out var document))
                {
                    //Look for the verification method in the external document.
                    var method = document.ResolveVerificationMethodReference($"#{fragment}");

                    return ValueTask.FromResult(method);
                }

                return ValueTask.FromResult<VerificationMethod?>(null);
            };
        }


        [TestMethod]
        public async Task SelectFromAuthenticationAsyncWithLocalResolutionReturnsResolvedResults()
        {
            var didDocument = CreateTestDidDocument();

            var results = await didDocument.SelectFromAuthenticationAsync().ConfigureAwait(false);
            var resultsList = results.ToList();

            Assert.HasCount(2, resultsList, "Should have exactly two authentication methods.");
            Assert.IsTrue(resultsList.All(r => r.IsResolved), "All authentication methods should be resolved.");
            Assert.IsTrue(resultsList.All(r => r.IsLocal), "All authentication methods should be resolved locally.");
            Assert.IsTrue(resultsList.All(r => r.Method != null), "All resolved methods should not be null.");

            var referencedMethod = resultsList.FirstOrDefault(r => r.Method!.Id == "#key-1");
            Assert.IsNotNull(referencedMethod.Method, "Referenced method should be resolved.");
            Assert.AreEqual("JsonWebKey2020", referencedMethod.Method!.Type, "Method type should match.");
            Assert.IsInstanceOfType<PublicKeyJwk>(referencedMethod.Method.KeyFormat, "Key format should be PublicKeyJwk.");

            var embeddedMethod = resultsList.FirstOrDefault(r => r.Method!.Id == "#embedded-key");
            Assert.IsNotNull(embeddedMethod.Method, "Embedded method should be resolved.");
        }


        [TestMethod]
        public async Task SelectFromAssertionMethodAsyncReturnsResolvedResults()
        {
            var didDocument = CreateTestDidDocument();

            var results = await didDocument.SelectFromAssertionMethodAsync().ConfigureAwait(false);
            var resultsList = results.ToList();

            Assert.HasCount(2, resultsList, "Should have exactly two assertion methods.");
            Assert.IsTrue(resultsList.All(r => r.IsResolved), "All assertion methods should be resolved.");
        }


        [TestMethod]
        public async Task SelectFromKeyAgreementAsyncReturnsResolvedResults()
        {
            var didDocument = CreateTestDidDocument();

            var results = await didDocument.SelectFromKeyAgreementAsync().ConfigureAwait(false);
            var resultsList = results.ToList();

            Assert.HasCount(1, resultsList, "Should have exactly one key agreement method.");
            Assert.IsTrue(resultsList[0].IsResolved, "Key agreement method should be resolved.");
            Assert.AreEqual("#key-2", resultsList[0].Method!.Id, "Key agreement method ID should match.");
        }


        [TestMethod]
        public async Task SelectFromCapabilityInvocationAsyncReturnsResolvedResults()
        {
            var didDocument = CreateTestDidDocument();

            var results = await didDocument.SelectFromCapabilityInvocationAsync().ConfigureAwait(false);
            var resultsList = results.ToList();

            Assert.HasCount(1, resultsList, "Should have exactly one capability invocation method.");
            Assert.IsTrue(resultsList[0].IsResolved, "Capability invocation method should be resolved.");
        }


        [TestMethod]
        public async Task SelectFromCapabilityDelegationAsyncReturnsResolvedResults()
        {
            var didDocument = CreateTestDidDocument();

            var results = await didDocument.SelectFromCapabilityDelegationAsync().ConfigureAwait(false);
            var resultsList = results.ToList();

            Assert.HasCount(2, resultsList, "Should have exactly two capability delegation methods.");
            Assert.IsTrue(resultsList.All(r => r.IsResolved), "All capability delegation methods should be resolved.");
        }


        [TestMethod]
        public async Task SelectFromAllVerificationRelationshipsAsyncReturnsAllResults()
        {
            var didDocument = CreateTestDidDocument();

            var results = await didDocument.SelectFromAllVerificationRelationshipsAsync().ConfigureAwait(false);
            var resultsList = results.ToList();

            Assert.HasCount(8, resultsList, "Should have eight total verification relationship methods.");
            Assert.IsTrue(resultsList.All(r => r.IsResolved), "All methods should be resolved.");
        }


        [TestMethod]
        public async Task SelectFromAuthenticationAsyncWithExternalResolverResolvesExternalReferences()
        {
            var externalDocument = new DidDocument
            {
                Id = new GenericDidMethod("did:example:external"),
                VerificationMethod = [ExternalVerificationMethod]
            };

            var resolver = CreateTestResolver(new Dictionary<string, DidDocument>
            {
                ["did:example:external"] = externalDocument
            });

            var didDocument = new DidDocument
            {
                Id = new GenericDidMethod("did:example:123"),
                Authentication =
                [
                    new AuthenticationMethod("did:example:external#key-1")
                ]
            };

            var results = await didDocument.SelectFromAuthenticationAsync(resolver).ConfigureAwait(false);
            var resultsList = results.ToList();

            Assert.HasCount(1, resultsList, "Should have one authentication method.");
            Assert.IsTrue(resultsList[0].IsResolved, "Method should be resolved.");
            Assert.IsFalse(resultsList[0].IsLocal, "Method should be resolved externally.");
            Assert.IsNotNull(resultsList[0].Method, "Resolved method should not be null.");
            Assert.AreEqual("#key-1", resultsList[0].Method!.Id, "Method ID should match.");
        }


        [TestMethod]
        public async Task SelectFromAuthenticationAsyncWithUnresolvableReferenceReturnsUnresolvedResult()
        {
            var resolver = CreateTestResolver(new Dictionary<string, DidDocument>());

            var didDocument = new DidDocument
            {
                Id = new GenericDidMethod("did:example:123"),
                Authentication =
                [
                    new AuthenticationMethod("did:example:unknown#key-1")
                ]
            };

            var results = await didDocument.SelectFromAuthenticationAsync(resolver).ConfigureAwait(false);
            var resultsList = results.ToList();

            Assert.HasCount(1, resultsList, "Should have one authentication method.");
            Assert.IsFalse(resultsList[0].IsResolved, "Method should not be resolved.");
            Assert.IsFalse(resultsList[0].IsLocal, "Unresolved method is not local.");
            Assert.IsNull(resultsList[0].Method, "Unresolved result should not have a method.");
            Assert.AreEqual("did:example:unknown#key-1", resultsList[0].Reference, "Reference should be preserved.");
        }


        [TestMethod]
        public void ExtractKeyMaterialFromVerificationMethodReturnsValidData()
        {
            var didDocument = CreateTestDidDocument();

            var method = didDocument.VerificationMethod![0];

            var keyMaterial = method.ExtractKeyMaterial(SensitiveMemoryPool<byte>.Shared);

            using(keyMaterial.keyMaterial)
            {
                Assert.IsGreaterThan(0, keyMaterial.keyMaterial.Memory.Length, "Key material should not be empty.");
            }
        }


        [TestMethod]
        public void ToPublicKeyMemoryFromVerificationMethodCreatesValidInstance()
        {
            var didDocument = CreateTestDidDocument();

            var method = didDocument.VerificationMethod![0];

            using var publicKeyMemory = method.ToPublicKeyMemory(SensitiveMemoryPool<byte>.Shared);

            Assert.IsGreaterThan(0, publicKeyMemory.AsReadOnlyMemory().Length, "Public key memory should not be empty.");
            Assert.IsNotNull(publicKeyMemory.Tag, "Tag should be set.");
        }


        [TestMethod]
        public async Task EmptyVerificationRelationshipsReturnEmptyResults()
        {
            var didDocument = new DidDocument
            {
                Id = new GenericDidMethod("did:example:empty"),
                Authentication = null,
                AssertionMethod = null,
                KeyAgreement = null,
                CapabilityInvocation = null,
                CapabilityDelegation = null
            };

            var authResults = await didDocument.SelectFromAuthenticationAsync().ConfigureAwait(false);
            var assertionResults = await didDocument.SelectFromAssertionMethodAsync().ConfigureAwait(false);
            var keyAgreementResults = await didDocument.SelectFromKeyAgreementAsync().ConfigureAwait(false);
            var capInvocationResults = await didDocument.SelectFromCapabilityInvocationAsync().ConfigureAwait(false);
            var capDelegationResults = await didDocument.SelectFromCapabilityDelegationAsync().ConfigureAwait(false);
            var allResults = await didDocument.SelectFromAllVerificationRelationshipsAsync().ConfigureAwait(false);

            Assert.IsEmpty(authResults, "Authentication should return empty.");
            Assert.IsEmpty(assertionResults, "AssertionMethod should return empty.");
            Assert.IsEmpty(keyAgreementResults, "KeyAgreement should return empty.");
            Assert.IsEmpty(capInvocationResults, "CapabilityInvocation should return empty.");
            Assert.IsEmpty(capDelegationResults, "CapabilityDelegation should return empty.");
            Assert.IsEmpty(allResults, "All relationships should return empty.");
        }


        [TestMethod]
        public async Task EmptyVerificationRelationshipArraysReturnEmptyResults()
        {
            var didDocument = new DidDocument
            {
                Id = new GenericDidMethod("did:example:empty"),
                Authentication = [],
                AssertionMethod = [],
                KeyAgreement = [],
                CapabilityInvocation = [],
                CapabilityDelegation = []
            };

            var authResults = await didDocument.SelectFromAuthenticationAsync().ConfigureAwait(false);
            var assertionResults = await didDocument.SelectFromAssertionMethodAsync().ConfigureAwait(false);
            var keyAgreementResults = await didDocument.SelectFromKeyAgreementAsync().ConfigureAwait(false);
            var capInvocationResults = await didDocument.SelectFromCapabilityInvocationAsync().ConfigureAwait(false);
            var capDelegationResults = await didDocument.SelectFromCapabilityDelegationAsync().ConfigureAwait(false);
            var allResults = await didDocument.SelectFromAllVerificationRelationshipsAsync().ConfigureAwait(false);

            Assert.IsEmpty(authResults, "Authentication should return empty for empty array.");
            Assert.IsEmpty(assertionResults, "AssertionMethod should return empty for empty array.");
            Assert.IsEmpty(keyAgreementResults, "KeyAgreement should return empty for empty array.");
            Assert.IsEmpty(capInvocationResults, "CapabilityInvocation should return empty for empty array.");
            Assert.IsEmpty(capDelegationResults, "CapabilityDelegation should return empty for empty array.");
            Assert.IsEmpty(allResults, "All relationships should return empty for empty arrays.");
        }


        [TestMethod]
        public async Task ResolveVerificationMethodReferenceWithLocalReferenceReturnsMethod()
        {
            var didDocument = CreateTestDidDocument();

            var resolved = didDocument.ResolveVerificationMethodReference("#key-1");

            Assert.IsNotNull(resolved, "Reference should be resolved.");
            Assert.AreEqual("#key-1", resolved.Id, "Resolved method ID should match.");

            var results = await didDocument.SelectFromAuthenticationAsync().ConfigureAwait(false);
            var result = results.FirstOrDefault(r => r.Method?.Id == "#key-1");

            Assert.IsTrue(result.IsResolved, "Selection should resolve the reference.");
            Assert.IsTrue(result.IsLocal, "Selection should be local.");
            Assert.AreEqual(resolved, result.Method, "Selected method should match the resolved method.");
        }


        [TestMethod]
        public async Task EmbeddedVerificationMethodResolvedDirectly()
        {
            var embeddedMethod = new VerificationMethod
            {
                Id = "#embedded-key",
                Type = "JsonWebKey2020",
                Controller = "did:example:123",
                KeyFormat = new PublicKeyJwk
                {
                    Header = new Dictionary<string, object>
                    {
                        ["kty"] = "EC",
                        ["crv"] = "P-256",
                        ["alg"] = "ES256"
                    }
                }
            };

            var didDocument = new DidDocument
            {
                Id = new GenericDidMethod("did:example:123"),
                Authentication = [new AuthenticationMethod(embeddedMethod)]
            };

            var results = await didDocument.SelectFromAuthenticationAsync().ConfigureAwait(false);
            var result = results.First();

            Assert.IsTrue(result.IsResolved, "Embedded method should be resolved.");
            Assert.IsTrue(result.IsLocal, "Embedded method should be local.");
            Assert.AreEqual(embeddedMethod, result.Method, "Should return the embedded method directly.");
            Assert.IsNull(result.Reference, "Embedded method should not have a reference.");
        }
    }
}