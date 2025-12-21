namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// This class holds some general constants as specified by DID Core specification.
    /// </summary>
    public static class DidCoreConstants
    {
        /// <summary>
        /// The DID documents must have a @context part in which the first URI is this.
        /// </summary>
        public const string JsonLdContextFirstUri = "https://www.w3.org/ns/did/v1";
    }
}
