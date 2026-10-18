using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The serializer and parser bundles the DPoP primitive tests construct and validate proofs with: the library's own
/// System.Text.Json serializer and the library's own reading of a proof's segments, so every test validates a proof as a
/// receiver of the library does.
/// </summary>
internal static class DpopTestSupport
{
    /// <summary>The library's serializer of a proof's header and claims.</summary>
    public static DpopJwsPartSerializer Serializer { get; } = DpopJwsPartSerializerJson.Default;


    /// <summary>
    /// The ES256 verification over P-256 keys the DPoP and resource-server tests verify proofs and access tokens under, the
    /// function bound to the one algorithm it performs.
    /// </summary>
    public static JwsAlgorithmVerification Es256Verification { get; } =
        new(WellKnownJwaValues.Es256, MicrosoftCryptographicFunctionsAdapter.VerifyP256Async);


    /// <summary>The library's reading of a proof's header and claims (<see cref="DpopJwsPartParser.Default"/>).</summary>
    public static DpopJwsPartParser Parser { get; } = DpopJwsPartParser.Default;
}
