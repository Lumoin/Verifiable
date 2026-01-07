using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Model
{
    public class DidResolutionDocument
    {
        /// <summary>
        /// https://w3c.github.io/did-core/#json-ld
        /// </summary>
        public Context? Context { get; set; }

        public DidDocument? DidDocument { get; set; }

        //https://w3c-ccg.github.io/did-resolution/#example
        public object? DidResolutionMetadata { get; set; }

        public object? DidDocumentMetadata { get; set; }
    }
}
