using System.IO;
using Verifiable.Core;
using Xunit;

namespace Verifiable.Tests
{
    /// <summary>
    /// General DID tests.
    /// </summary>
    public class VcDocumentTests
    {
        /// <summary>
        /// Getting a hash of an empty document. This should not throw.
        /// </summary>
        [Fact]
        public void EmptyDocumentHash()
        {
            _ = new VerifiableCredential().GetHashCode();
        }


        /// <summary>
        /// The reader should be able to deserialize all these test files correctly. These are files
        /// that are either from DID related specification examples or from real production systems.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        /// <remarks>Compared to <see cref="CanRoundtripDidDocumentWithoutStronglyTypedService(string, string)"/>
        /// this tests provides strong type to see if <see cref="VerifiableCredentialService"/> in particular is serialized.</remarks>
        [Theory]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToCurrentVc, ".json", SearchOption.AllDirectories)]
        public void CanRoundtripDidDocumentWithStronglyTypedService(string didDocumentFilename, string didDocumentFileContents)
        {
            TestInfrastructureConstants.ThrowIfPreconditionFails(didDocumentFilename, didDocumentFileContents);
        }
    }
}
