using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Builds <c>did:ebsi</c> DID documents for EBSI (European Blockchain Services Infrastructure) using
    /// a fold/aggregate pattern with sensible defaults.
    /// </summary>
    /// <remarks>
    /// <para>
    /// According to the EBSI DID Method specification
    /// (https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method),
    /// the following fields are required for Legal Entities EBSI DID documents:
    /// </para>
    /// <list type="bullet">
    /// <item><description>verificationMethod.</description></item>
    /// <item><description>verificationMethod[].publicKeyJwk.</description></item>
    /// <item><description>assertionMethod.</description></item>
    /// </list>
    /// <para>
    /// <strong>Relationship to Delegate-Based Patterns</strong>
    /// </para>
    /// <para>
    /// This builder is a convenience layer over the library's delegate-based primitives. For maximum
    /// control over document construction or custom EBSI-specific requirements, use the underlying
    /// APIs directly.
    /// </para>
    /// <para>
    /// The EBSI DID Document is compliant with the W3C DID Document specification but defines
    /// additional constraints specific to the EBSI ecosystem.
    /// </para>
    /// <para>
    /// All transformations are asynchronous, returning <see cref="System.Threading.Tasks.ValueTask{TResult}"/>.
    /// This enables transformations that require I/O operations such as cryptographic signing,
    /// key resolution, or external service calls while maintaining efficient execution for
    /// synchronous operations.
    /// </para>
    /// </remarks>
    public class EbsiDidBuilder: Builder<DidDocument, object, EbsiDidBuilder>
    {
    }
}