namespace Verifiable.Tests.Resolver
{
    [TestClass]
    public sealed class ResolverTests
    {
        //TODO: These test vectors are taken from https://w3c-ccg.github.io/did-method-web/#did-method-operations.
        [TestMethod]
        public void CanResolveDidWebWithDomainOnly()
        {
            var didWebIdentifier = "did:web:w3c-ccg.github.io";
            var didDocument = WebDidResolver.Resolve(didWebIdentifier);
            Assert.AreEqual("https://w3c-ccg.github.io/.well-known/did.json", didDocument);
        }


        [TestMethod]
        public void CanResolveDidWebWithDomainAndPath()
        {
            var didWebIdentifier = "did:web:w3c-ccg.github.io:user:alice";
            var didDocument = WebDidResolver.Resolve(didWebIdentifier);
            Assert.AreEqual("https://w3c-ccg.github.io/user/alice/did.json", didDocument);
        }


        [TestMethod]
        public void CanResolveDidWebWithDomainAndPortAndPath()
        {
            var didWebIdentifier = "did:web:example.com%3A3000:user:alice";
            var didDocument = WebDidResolver.Resolve(didWebIdentifier);
            Assert.AreEqual("https://example.com:3000/user/alice/did.json", didDocument);
        }
    }
}
