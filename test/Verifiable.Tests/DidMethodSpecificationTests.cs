using Verifiable.Core.Builders;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests
{
    /// <summary>
    /// Tests for DID method cycles.
    /// </summary>
    [TestClass]
    public sealed class DidMethodSpecificationTests
    {
        private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();
        // Future: private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder();


        [TestMethod]
        [DynamicData(nameof(DidKeyTheoryData.GetDidTheoryTestData), typeof(DidKeyTheoryData))]
        public void KeyDidVerificationMethodFunctionalCycle(DidKeyTestData testData)
        {
            var didDocument = KeyDidBuilder.Build(testData.KeyPair.PublicKey, testData.VerificationMethodTypeInfo);

            // Test DID Key specific functionality:
            // - Single verification method
            // - All verification relationships point to same method
            // - Ed25519 key derivation to X25519 for key agreement
            // - Offline resolution (no network needed)
        }
    }
}
