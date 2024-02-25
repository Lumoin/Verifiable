namespace Verifiable.Core
{
    /// <summary>
    /// Deprecation information for the Verifiable library.
    /// </summary>
    internal static class DeprecationInfo
    {
        /// <summary>
        /// The base URL for deprecation information.
        /// </summary>
        internal const string DeprecationUrlBase = "https://putsomethinghere/deprecations/{0}";

        /// <summary>
        /// Ed25519VerificationKey2020 deprecation information.
        /// </summary>
        internal const string Ed25519VerificationKey2020Message = "This crypto suite is deprecated. Consider using the another suite instead.";
        
        /// <summary>
        /// Ed25519VerificationKey2020 deprecation diagnostic code.
        /// </summary>
        internal const string Ed25519VerificationKey2020DiagId = "VF0001";        
    }
}
