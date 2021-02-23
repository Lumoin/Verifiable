using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotDecentralized.Tests
{
    /// <summary>
    /// Some constants and utilities used in tests.
    /// </summary>
    public static class TestInfrastructureConstants
    {
        /// <summary>
        /// Path to current tests.
        /// </summary>
        public const string RelativeTestPathToCurrent = @"..\..\..\TestDIDDocuments\current\";

        /// <summary>
        /// Path to deprecated documents according to tests.
        /// </summary>
        public const string RelativeTestPathToDeprecated = @"..\..\..\TestDIDDocuments\deprecated\";

        /// <summary>
        /// Path to extended documents according to tests.
        /// </summary>
        public const string RelativeTestPathToExtended = @"..\..\..\TestDIDDocuments\extended\";

        /// <summary>
        /// Path to Sidetree documents.
        /// </summary>
        public const string RelativeTestPathToSidetree = @"..\..\..\TestDIDDocuments\Sidetree\";

        /// <summary>
        /// Test material is loaded from external files. This check preconditions assumed on them hold.
        /// </summary>
        /// <param name="didDocumentFilename">The filename under test.</param>
        /// <param name="didDocumentFileContents">The contents of the file being tested.</param>
        public static void ThrowIfPreconditionFails(string didDocumentFilename, string didDocumentFileContents)
        {
            if(didDocumentFilename is null)
            {
                throw new ArgumentNullException(nameof(didDocumentFilename));
            }

            if(string.IsNullOrWhiteSpace(didDocumentFileContents))
            {
                throw new ArgumentException($"The test file {didDocumentFilename} must not be empty or null.", nameof(didDocumentFileContents));
            }
        }
    }
}
