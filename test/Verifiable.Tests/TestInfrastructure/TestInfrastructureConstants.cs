namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Some constants and utilities used in tests.
    /// </summary>
    public static class TestInfrastructureConstants
    {
        /// <summary>
        /// Path to test DID files.
        /// </summary>
        public const string RelativeTestPathToCurrent = "..//..//../TestDocuments//Did//";

        /// <summary>
        /// Path to test DID files that contain DID documents that contain extensions to the W3C specification.
        /// </summary>
        public const string RelativeTestPathToExtended = "..//..//../TestDocuments//Extended//";

        /// <summary>
        /// Path to deprecated documents according to tests.
        /// </summary>
        public const string RelativeTestPathToDeprecated = "..//..//..//TestDocuments//Deprecated//";

        /// <summary>
        /// Path to Sidetree documents.
        /// </summary>
        public const string RelativeTestPathToSidetree = "..//..//../TestDocuments//Sidetree//";

        /// <summary>
        /// Test material is loaded from external files. This check preconditions assumed on them hold.
        /// </summary>
        /// <param name="didDocumentFilename">The filename under test.</param>
        /// <param name="didDocumentFileContents">The contents of the file being tested.</param>
        public static void ThrowIfPreconditionFails(string didDocumentFilename, string didDocumentFileContents)
        {
            ArgumentNullException.ThrowIfNull(didDocumentFilename);

            if(string.IsNullOrWhiteSpace(didDocumentFileContents))
            {
                throw new ArgumentException($"The test file {didDocumentFilename} must not be empty or null.", nameof(didDocumentFileContents));
            }
        }
    }
}
