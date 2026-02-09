using System.Collections.ObjectModel;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    public sealed class UndefinedMethodTypeInfo: VerificationMethodTypeInfo
    {
        private static readonly string[] ContextsArray = ["Undefined"];


        public static UndefinedMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "UndefinedVerificationMethod",
            DefaultKeyFormatType = typeof(KeyFormat),
            Contexts = new ReadOnlyCollection<string>(ContextsArray)
        };
    }
}