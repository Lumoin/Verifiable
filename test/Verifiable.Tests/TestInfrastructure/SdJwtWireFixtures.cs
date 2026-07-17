using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Json.Sd;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared SD-JWT disclosure encoding for the DCQL presentation-flow and claim-redaction test corpus,
/// delegating to the production <see cref="SdJwtSerializer.SerializeDisclosure"/>.
/// </summary>
internal static class SdJwtWireFixtures
{
    /// <summary>Encodes <paramref name="disclosure"/> via <see cref="SdJwtSerializer.SerializeDisclosure"/>.</summary>
    /// <param name="disclosure">The disclosure to encode.</param>
    /// <param name="encoder">The base64url encoder.</param>
    /// <returns>The base64url-encoded disclosure string.</returns>
    internal static string SerializeDisclosure(SdDisclosure disclosure, EncodeDelegate encoder)
    {
        return SdJwtSerializer.SerializeDisclosure(disclosure, encoder);
    }
}
