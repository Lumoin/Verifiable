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
/// Shared fixtures for the CTAP <c>authenticatorCredentialManagement</c> (<c>0x0A</c>) test suite:
/// request-envelope assembly and the platform-side <c>pinUvAuthParam</c> verify message (CTAP 2.3
/// §6.5.8, line 6309-6315: <c>uint8(subCommand) [|| subCommandParams]</c> — the THIRD message shape, NO
/// 32-byte <c>0xff</c> prefix, NO command byte). PIN establishment and token issuance are generic across
/// every token-gated command, so this fixture reuses <see cref="CtapWaveConfigFixtures.EstablishPinAsync"/>/
/// <see cref="CtapWaveConfigFixtures.IssueTokenAsync"/>/<see cref="CtapWaveConfigFixtures.GetInfoAsync"/>/
/// <see cref="CtapWaveConfigFixtures.ComputeSignatureAsync"/> unchanged — all four are already
/// command-agnostic (real crypto through <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/>, never a
/// test-only reimplementation) — rather than duplicating them, mirroring
/// <see cref="CtapWave2AuthenticatorFixtures"/>'s envelope-building role for the mc/ga surface.
/// </summary>
internal static class CtapWaveCmFixtures
{
    /// <summary>Encodes, sends, and returns the raw response envelope for an <c>authenticatorCredentialManagement</c> request.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="request">The request to send.</param>
    /// <param name="pool">The memory pool for the request and response buffers.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The raw response envelope. The caller owns it and must dispose it.</returns>
    public static async Task<PooledMemory> SendCredentialManagementAsync(
        CtapAuthenticatorSimulator simulator, CtapCredentialManagementRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = BuildCredentialManagementEnvelope(request);

        return await simulator.TransceiveAsync(envelope, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Builds the complete <c>authenticatorCredentialManagement</c> request envelope for <paramref name="request"/>.</summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The command byte followed by the CTAP2-canonical CBOR parameter map.</returns>
    public static byte[] BuildCredentialManagementEnvelope(CtapCredentialManagementRequest request)
    {
        TaggedMemory<byte> parameters = CtapCredentialManagementRequestCborWriter.Write(request);
        byte[] envelope = new byte[parameters.Length + 1];
        envelope[0] = WellKnownCtapCommands.CredentialManagement;
        parameters.Span.CopyTo(envelope.AsSpan(1));

        return envelope;
    }


    /// <summary>
    /// Builds a gated subcommand's own <c>subCommandParams</c> bytes, EXACTLY the bytes
    /// <see cref="CtapCredentialManagementRequestCborWriter.Write"/> would embed for the same fields —
    /// the caller's own <see cref="BuildMessage"/> call must cover these same bytes for the platform's
    /// computed <c>pinUvAuthParam</c> to verify.
    /// </summary>
    /// <param name="rpIdHash">The <c>rpIDHash</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="credentialId">The <c>credentialID</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="user">The <c>user</c> member, or <see langword="null"/> to omit it.</param>
    /// <returns>The encoded <c>subCommandParams</c> map bytes.</returns>
    public static byte[] BuildSubCommandParams(
        ReadOnlyMemory<byte>? rpIdHash = null, PublicKeyCredentialDescriptor? credentialId = null, CtapPublicKeyCredentialUserEntity? user = null) =>
        CtapCredentialManagementRequestCborWriter.WriteSubCommandParams(rpIdHash, credentialId, user).Span.ToArray();


    /// <summary>
    /// Assembles <c>authenticatorCredentialManagement</c>'s verify message (CTAP 2.3 §6.5.8, line
    /// 6309-6315): <c>uint8(subCommand) [|| subCommandParams]</c>. <paramref name="subCommandParams"/> is
    /// empty for <c>getCredsMetadata</c>/<c>enumerateRPsBegin</c>, which structurally never carry one —
    /// the message then elides that segment entirely (no 32-byte prefix, no command byte, unlike
    /// <see cref="CtapWaveConfigFixtures.BuildMessage"/>'s own compound shape).
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value.</param>
    /// <param name="subCommandParams">The (possibly empty) raw <c>subCommandParams</c> bytes.</param>
    /// <returns>The assembled verify message.</returns>
    public static byte[] BuildMessage(int subCommand, ReadOnlyMemory<byte> subCommandParams)
    {
        byte[] message = new byte[1 + subCommandParams.Length];
        message[0] = (byte)subCommand;
        subCommandParams.Span.CopyTo(message.AsSpan(1));

        return message;
    }
}
