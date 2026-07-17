using Verifiable.Cbor.Ctap;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Builds complete CTAP2 request envelopes (command byte plus CBOR-encoded parameter map) for
/// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> tests that drive
/// <see cref="Verifiable.Fido2.Ctap.Authenticator.Automata.CtapAuthenticatorSimulator.TransceiveAsync"/>
/// directly, so every CTAP wave-2 test category shares one envelope-building seam instead of
/// reimplementing the command-byte-plus-CBOR-body assembly per test file.
/// </summary>
internal static class CtapWave2RequestEnvelopes
{
    /// <summary>
    /// Builds the complete <c>authenticatorMakeCredential</c> request envelope for <paramref name="request"/>.
    /// </summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The command byte followed by the CTAP2-canonical CBOR parameter map.</returns>
    public static byte[] BuildMakeCredentialEnvelope(CtapMakeCredentialRequest request)
    {
        TaggedMemory<byte> parameters = CtapMakeCredentialRequestCborWriter.Write(request);
        byte[] envelope = new byte[parameters.Length + 1];
        envelope[0] = WellKnownCtapCommands.MakeCredential;
        parameters.Span.CopyTo(envelope.AsSpan(1));

        return envelope;
    }


    /// <summary>
    /// Builds the complete <c>authenticatorGetAssertion</c> request envelope for <paramref name="request"/>.
    /// </summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The command byte followed by the CTAP2-canonical CBOR parameter map.</returns>
    public static byte[] BuildGetAssertionEnvelope(CtapGetAssertionRequest request)
    {
        TaggedMemory<byte> parameters = CtapGetAssertionRequestCborWriter.Write(request);
        byte[] envelope = new byte[parameters.Length + 1];
        envelope[0] = WellKnownCtapCommands.GetAssertion;
        parameters.Span.CopyTo(envelope.AsSpan(1));

        return envelope;
    }


    /// <summary>
    /// Builds the complete <c>authenticatorGetNextAssertion</c> request envelope: the command byte alone,
    /// since the command takes no parameters.
    /// </summary>
    /// <returns>The one-byte request envelope.</returns>
    public static byte[] BuildGetNextAssertionEnvelope() => [WellKnownCtapCommands.GetNextAssertion];
}
