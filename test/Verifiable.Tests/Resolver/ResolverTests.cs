using Xunit;

namespace Verifiable.Tests.Resolver
{
    public class ResolverTests
    {
        //TODO: These test vectors are taken from https://w3c-ccg.github.io/did-method-web/#did-method-operations.
        [Fact]
        public void CanResolveDidWebWithDomainOnly()
        {
            var didWebIdentifier = "did:web:w3c-ccg.github.io";
            var didDocument = WebDidResolver.Resolve(didWebIdentifier);
            Assert.Equal("https://w3c-ccg.github.io/.well-known/did.json", didDocument);
        }


        [Fact]
        public void CanResolveDidWebWithDomainAndPath()
        {
            var didWebIdentifier = "did:web:w3c-ccg.github.io:user:alice";
            var didDocument = WebDidResolver.Resolve(didWebIdentifier);
            Assert.Equal("https://w3c-ccg.github.io/user/alice/did.json", didDocument);
        }


        [Fact]
        public void CanResolveDidWebWithDomainAndPortAndPath()
        {
            var didWebIdentifier = "did:web:example.com%3A3000:user:alice";
            var didDocument = WebDidResolver.Resolve(didWebIdentifier);
            Assert.Equal("https://example.com:3000/user/alice/did.json", didDocument);
        }
    }
}
