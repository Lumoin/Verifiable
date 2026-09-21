using System.Collections.ObjectModel;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    /// <summary>
    /// Verification method type descriptor for the <c>JsonWebKey2020</c> suite, whose default key
    /// material format is a <see cref="PublicKeyJwk"/> and whose context carries the
    /// <c>jws-2020</c> security suite IRI.
    /// </summary>
    public sealed class JsonWebKey2020VerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
        private static ReadOnlyCollection<string> ContextsArray { get; } = new(["https://w3id.org/security/suites/jws-2020/v1"]);

        /// <summary>Gets the shared, immutable descriptor instance for <c>JsonWebKey2020</c>.</summary>
        public static JsonWebKey2020VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "JsonWebKey2020",
            DefaultKeyFormatType = typeof(PublicKeyJwk),
            Contexts = ContextsArray
        };
    }
}
