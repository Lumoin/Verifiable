using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared fixtures for the CTAP <c>authenticatorConfig</c> (<c>0x0D</c>) test suite: request-envelope
/// assembly and the platform-side <c>pinUvAuthParam</c> verify message (CTAP 2.3, line 7947:
/// <c>32×0xff || 0x0d || uint8(subCommand) || subCommandParams</c>), computed the same way the
/// wave-5c fixtures compute mc/ga's own <c>pinUvAuthParam</c> — through
/// <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/> over the actual token bytes, never a test-only
/// crypto reimplementation. Mirrors <see cref="CtapWave2AuthenticatorFixtures"/>'s envelope-building
/// role for the mc/ga surface.
/// </summary>
internal static class CtapWaveConfigFixtures
{
    /// <summary>The fixed 32-byte <c>0xff</c> prefix every <c>authenticatorConfig</c> verify message shares (CTAP 2.3, line 7947).</summary>
    private const int MessagePrefixLength = 32;


    /// <summary>Sends an <c>authenticatorGetInfo</c> request and decodes its response.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool for the request and response buffers.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The decoded <c>authenticatorGetInfo</c> response.</returns>
    public static async Task<CtapGetInfoResponse> GetInfoAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await simulator.TransceiveAsync(request, pool, cancellationToken).ConfigureAwait(false);

        return CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
    }


    /// <summary>Establishes <paramref name="pin"/> as the authenticator's PIN via <c>setPIN</c>.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="protocolId">Which PIN/UV auth protocol to establish the PIN under.</param>
    /// <param name="pin">The plaintext PIN to set.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    public static async Task EstablishPinAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, cancellationToken).ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>Issues a permissions-scoped <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c> (<c>0x09</c>).</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="protocolId">Which PIN/UV auth protocol to issue the token under.</param>
    /// <param name="pin">The plaintext PIN proving knowledge of it.</param>
    /// <param name="permissions">The requested permissions bitfield.</param>
    /// <param name="rpId">The permissions RP ID to bind the token to, or <see langword="null"/> for none.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The decrypted, plaintext token bytes.</returns>
    public static async Task<byte[]> IssueTokenAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, int permissions, string? rpId,
        CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, cancellationToken).ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a permissions-scoped <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingUvWithPermissions</c>
    /// (<c>0x06</c>) — the built-in-UV sibling of <see cref="IssueTokenAsync"/>: establishes a
    /// key-agreement session exactly the same way, but sends NO <c>pinHashEnc</c> (0x06's request has
    /// none), letting the injected <see cref="SimulateBuiltInUvDelegate"/> personalization decide the
    /// simulated gesture's outcome instead.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="protocolId">Which PIN/UV auth protocol to issue the token under.</param>
    /// <param name="permissions">The requested permissions bitfield.</param>
    /// <param name="rpId">The permissions RP ID to bind the token to, or <see langword="null"/> for none.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The decrypted, plaintext token bytes.</returns>
    public static async Task<byte[]> IssueUvTokenAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, int permissions, string? rpId,
        CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingUvWithPermissions,
            PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
            Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends an <c>authenticatorClientPIN</c> request expecting it to fail and returns the exact status
    /// code — a fixture-level sibling of the per-test-class private helper every clientPIN test file
    /// otherwise reimplements, usable directly for <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s (and
    /// any other subcommand's) negative paths.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="request">The request expected to fail.</param>
    /// <param name="pool">The memory pool every allocation uses.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The CTAP2 status byte.</returns>
    public static async Task<byte> SendClientPinExpectingErrorAsync(
        CtapAuthenticatorSimulator simulator, CtapClientPinRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(async () =>
            await CtapAuthenticatorClientPinClient.ClientPinAsync(
                simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
                .ConfigureAwait(false));

        return exception.StatusCode;
    }


    /// <summary>Encodes, sends, and returns the raw response envelope for an <c>authenticatorConfig</c> request.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="request">The request to send.</param>
    /// <param name="pool">The memory pool for the request and response buffers.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The raw response envelope. The caller owns it and must dispose it.</returns>
    public static async Task<PooledMemory> SendAuthenticatorConfigAsync(
        CtapAuthenticatorSimulator simulator, CtapAuthenticatorConfigRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = BuildAuthenticatorConfigEnvelope(request);

        return await simulator.TransceiveAsync(envelope, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Builds the complete <c>authenticatorConfig</c> request envelope for <paramref name="request"/>.</summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The command byte followed by the CTAP2-canonical CBOR parameter map.</returns>
    public static byte[] BuildAuthenticatorConfigEnvelope(CtapAuthenticatorConfigRequest request)
    {
        TaggedMemory<byte> parameters = CtapAuthenticatorConfigRequestCborWriter.Write(request);
        byte[] envelope = new byte[parameters.Length + 1];
        envelope[0] = WellKnownCtapCommands.AuthenticatorConfig;
        parameters.Span.CopyTo(envelope.AsSpan(1));

        return envelope;
    }


    /// <summary>
    /// Builds <c>setMinPINLength</c>'s own <c>subCommandParams</c> bytes, EXACTLY the bytes
    /// <see cref="CtapAuthenticatorConfigRequestCborWriter.Write"/> would embed for the same fields —
    /// the caller's own <see cref="BuildMessage"/> call must cover these same bytes for the platform's
    /// computed <c>pinUvAuthParam</c> to verify.
    /// </summary>
    /// <param name="newMinPinLength">The <c>newMinPINLength</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="minPinLengthRpIds">The <c>minPinLengthRPIDs</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="forceChangePin">The <c>forceChangePin</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="pinComplexityPolicy">The <c>pinComplexityPolicy</c> member, or <see langword="null"/> to omit it.</param>
    /// <returns>The encoded <c>subCommandParams</c> map bytes.</returns>
    public static byte[] BuildSubCommandParams(
        int? newMinPinLength = null, IReadOnlyList<string>? minPinLengthRpIds = null, bool? forceChangePin = null, bool? pinComplexityPolicy = null) =>
        CtapAuthenticatorConfigRequestCborWriter.WriteSubCommandParams(newMinPinLength, minPinLengthRpIds, forceChangePin, pinComplexityPolicy).Span.ToArray();


    /// <summary>
    /// Assembles <c>authenticatorConfig</c>'s verify message (CTAP 2.3, line 7947): <c>32×0xff || 0x0d
    /// || uint8(subCommand) || subCommandParams</c>. <paramref name="subCommandParams"/> is empty when
    /// the platform sends none, eliding that segment entirely (the R5 ruling) rather than encoding an
    /// empty CBOR map.
    /// </summary>
    /// <param name="subCommand">The <c>subCommand</c> value.</param>
    /// <param name="subCommandParams">The (possibly empty) raw <c>subCommandParams</c> bytes.</param>
    /// <returns>The assembled verify message.</returns>
    public static byte[] BuildMessage(int subCommand, ReadOnlyMemory<byte> subCommandParams)
    {
        byte[] message = new byte[MessagePrefixLength + 2 + subCommandParams.Length];
        message.AsSpan(0, MessagePrefixLength).Fill(0xff);
        message[MessagePrefixLength] = WellKnownCtapCommands.AuthenticatorConfig;
        message[MessagePrefixLength + 1] = (byte)subCommand;
        subCommandParams.Span.CopyTo(message.AsSpan(MessagePrefixLength + 2));

        return message;
    }


    /// <summary>
    /// Computes <c>authenticate(token, message)</c> under <paramref name="protocolId"/>'s own truncation
    /// rule — the exact platform-side computation <c>verify</c> checks a presented
    /// <c>pinUvAuthParam</c> against, mirroring the wave-5c binding tests' own helper for mc/ga.
    /// </summary>
    /// <param name="token">The platform's decrypted copy of the <c>pinUvAuthToken</c>.</param>
    /// <param name="protocolId">Which PIN/UV auth protocol authenticated the token.</param>
    /// <param name="message">The message to sign, typically built by <see cref="BuildMessage"/>.</param>
    /// <param name="pool">The memory pool the signature computation allocates from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The computed <c>pinUvAuthParam</c> bytes.</returns>
    public static async Task<byte[]> ComputeSignatureAsync(
        byte[] token, CtapPinUvAuthProtocolId protocolId, byte[] message, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(protocolId);
        using IMemoryOwner<byte> signature = await protocol.AuthenticateAsync(token, message, pool, cancellationToken).ConfigureAwait(false);

        return signature.Memory.Span.ToArray();
    }
}
