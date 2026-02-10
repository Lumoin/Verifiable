using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// End-to-end flow tests for JWS-secured Verifiable Presentations.
/// </summary>
/// <remarks>
/// <para>
/// These tests will demonstrate the holder constructing a <see cref="Verifiable.Core.Credentials.VerifiablePresentation"/>
/// containing one or more JWS-secured Verifiable Credentials, signing the VP envelope
/// to prove holder binding, and verifier validation of both the VP signature and the
/// embedded VC signatures.
/// </para>
/// <para>
/// Placeholder for:
/// </para>
/// <list type="bullet">
/// <item><description>VP wrapping a single JWS-secured VC with holder signature.</description></item>
/// <item><description>VP wrapping multiple JWS-secured VCs from different issuers.</description></item>
/// <item><description>Verifier validates VP holder binding and all embedded VC issuer signatures.</description></item>
/// <item><description>Challenge/nonce replay protection in the VP proof.</description></item>
/// </list>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-jose-cose/">VC-JOSE-COSE</see> and
/// <see href="https://www.w3.org/TR/vc-data-model-2.0/#presentations">VC Data Model 2.0 §3.3</see>.
/// </para>
/// </remarks>
/*[TestClass]

internal sealed class JwsPresentationFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    //TODO: Implement VP construction, signing, and verification for JWS envelopes.
}*/