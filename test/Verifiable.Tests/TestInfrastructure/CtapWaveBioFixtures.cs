using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared fixtures for the CTAP <c>authenticatorBioEnrollment</c> (<c>0x09</c>) test suite: request-
/// envelope assembly and the platform-side <c>pinUvAuthParam</c> verify message (bio scout Finding C:
/// <c>uint8(modality) || uint8(subCommand) [|| subCommandParams]</c> — the FOURTH message shape, a
/// TWO-byte leading prefix). PIN establishment and token issuance are generic across every token-gated
/// command, so this fixture reuses <see cref="CtapWaveConfigFixtures.EstablishPinAsync"/>/
/// <see cref="CtapWaveConfigFixtures.IssueTokenAsync"/>/<see cref="CtapWaveConfigFixtures.ComputeSignatureAsync"/>
/// unchanged, mirroring <see cref="CtapWaveCmFixtures"/>'s identical role for
/// <c>authenticatorCredentialManagement</c>.
/// </summary>
internal static class CtapWaveBioFixtures
{
    /// <summary>Encodes, sends, and returns the raw response envelope for an <c>authenticatorBioEnrollment</c> request.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="request">The request to send.</param>
    /// <param name="pool">The memory pool for the request and response buffers.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The raw response envelope. The caller owns it and must dispose it.</returns>
    public static async Task<PooledMemory> SendBioEnrollmentAsync(
        CtapAuthenticatorSimulator simulator, CtapBioEnrollmentRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = BuildBioEnrollmentEnvelope(request);

        return await simulator.TransceiveAsync(envelope, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Builds the complete <c>authenticatorBioEnrollment</c> request envelope for <paramref name="request"/>.</summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The command byte followed by the CTAP2-canonical CBOR parameter map.</returns>
    public static byte[] BuildBioEnrollmentEnvelope(CtapBioEnrollmentRequest request)
    {
        TaggedMemory<byte> parameters = CtapBioEnrollmentRequestCborWriter.Write(request);
        byte[] envelope = new byte[parameters.Length + 1];
        envelope[0] = WellKnownCtapCommands.BioEnrollment;
        parameters.Span.CopyTo(envelope.AsSpan(1));

        return envelope;
    }


    /// <summary>
    /// Builds a gated subcommand's own <c>subCommandParams</c> bytes, EXACTLY the bytes
    /// <see cref="CtapBioEnrollmentRequestCborWriter.WriteSubCommandParams"/> would embed for the same
    /// fields — the caller's own <see cref="BuildMessage"/> call must cover these same bytes for the
    /// platform's computed <c>pinUvAuthParam</c> to verify.
    /// </summary>
    /// <param name="templateId">The <c>templateId</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="templateFriendlyName">The <c>templateFriendlyName</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="timeoutMilliseconds">The <c>timeoutMilliseconds</c> member, or <see langword="null"/> to omit it.</param>
    /// <returns>The encoded <c>subCommandParams</c> map bytes.</returns>
    public static byte[] BuildSubCommandParams(ReadOnlyMemory<byte>? templateId = null, string? templateFriendlyName = null, int? timeoutMilliseconds = null) =>
        CtapBioEnrollmentRequestCborWriter.WriteSubCommandParams(templateId, templateFriendlyName, timeoutMilliseconds).Span.ToArray();


    /// <summary>
    /// Assembles <c>authenticatorBioEnrollment</c>'s verify message (bio scout Finding C):
    /// <c>uint8(modality) || uint8(subCommand) [|| subCommandParams]</c>. <paramref name="subCommandParams"/>
    /// is empty for <c>enumerateEnrollments</c>, which structurally never carries one — the message then
    /// elides that segment entirely (no CBOR map at all), mirroring
    /// <see cref="CtapWaveCmFixtures.BuildMessage"/>'s own elision convention but with a two-byte prefix.
    /// </summary>
    /// <param name="modality">The <c>modality</c> value.</param>
    /// <param name="subCommand">The <c>subCommand</c> value.</param>
    /// <param name="subCommandParams">The (possibly empty) raw <c>subCommandParams</c> bytes.</param>
    /// <returns>The assembled verify message.</returns>
    public static byte[] BuildMessage(int modality, int subCommand, ReadOnlyMemory<byte> subCommandParams)
    {
        byte[] message = new byte[2 + subCommandParams.Length];
        message[0] = (byte)modality;
        message[1] = (byte)subCommand;
        subCommandParams.Span.CopyTo(message.AsSpan(2));

        return message;
    }
}
