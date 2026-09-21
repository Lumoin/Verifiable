using System.Collections.ObjectModel;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    /// <summary>
    /// The fallback verification method type used when a <c>type</c> value in a DID document does not match any
    /// registered <see cref="VerificationMethodTypeInfo"/>, so key material can still be carried without the
    /// resolver refusing the document outright.
    /// </summary>
    public sealed class UndefinedMethodTypeInfo: VerificationMethodTypeInfo
    {
        private static string[] ContextsArray { get; } = ["Undefined"];


        /// <summary>The shared <see cref="UndefinedMethodTypeInfo"/> instance.</summary>
        public static UndefinedMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "UndefinedVerificationMethod",
            DefaultKeyFormatType = typeof(KeyFormat),
            Contexts = new ReadOnlyCollection<string>(ContextsArray)
        };
    }
}
