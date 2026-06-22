using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Provides extension methods for appending structural members — verification methods and
    /// services — to a <see cref="DidDocument"/> during building. These complement the
    /// verification-relationship extensions in <see cref="DidDocumentVerificationExtensions"/>
    /// so a document can be assembled member by member with a uniform fluent API.
    /// </summary>
    /// <remarks>
    /// Each append reallocates the target array with the new element appended, matching the
    /// growth strategy used by the verification-relationship extensions. This favours a simple,
    /// allocation-transparent API over in-place mutation; DID documents carry a small, bounded
    /// number of verification methods and services, so the per-append copy is inconsequential.
    /// </remarks>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with the latest syntax.")]
    public static class DidDocumentBuildingExtensions
    {
        extension(DidDocument document)
        {
            /// <summary>
            /// Appends a verification method to the document's <see cref="DidDocument.VerificationMethod"/> array.
            /// </summary>
            /// <param name="verificationMethod">The verification method to append.</param>
            /// <returns>The same DID document instance with the verification method appended.</returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="document"/> or <paramref name="verificationMethod"/> is null.
            /// </exception>
            /// <example>
            /// <code>
            /// var document = new DidDocument();
            /// document.WithVerificationMethod(verificationMethod)
            ///         .WithAuthentication(verificationMethod.Id);
            /// </code>
            /// </example>
            public DidDocument WithVerificationMethod(VerificationMethod verificationMethod)
            {
                ArgumentNullException.ThrowIfNull(document);
                ArgumentNullException.ThrowIfNull(verificationMethod);

                document.VerificationMethod = document.VerificationMethod is null
                    ? [verificationMethod]
                    : [.. document.VerificationMethod, verificationMethod];

                return document;
            }


            /// <summary>
            /// Appends a service to the document's <see cref="DidDocument.Service"/> array.
            /// </summary>
            /// <param name="service">The service to append.</param>
            /// <returns>The same DID document instance with the service appended.</returns>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="document"/> or <paramref name="service"/> is null.
            /// </exception>
            /// <example>
            /// <code>
            /// var document = new DidDocument();
            /// document.WithService(service);
            /// </code>
            /// </example>
            public DidDocument WithService(Service service)
            {
                ArgumentNullException.ThrowIfNull(document);
                ArgumentNullException.ThrowIfNull(service);

                document.Service = document.Service is null
                    ? [service]
                    : [.. document.Service, service];

                return document;
            }
        }
    }
}
