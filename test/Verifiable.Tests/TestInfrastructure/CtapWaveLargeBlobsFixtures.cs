using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared fixtures for the <c>authenticatorLargeBlobs</c> (<c>0x0C</c>) write-machine test suite (PKG-B):
/// request-envelope assembly, the per-fragment <c>pinUvAuthParam</c> verify message (CTAP 2.3 §6.10.2,
/// lines 7578/7646: <c>32×0xff || h'0c00' || uint32LittleEndian(offset) || SHA-256(fragment)</c>) computed
/// the same way <see cref="CtapWaveConfigFixtures"/> computes <c>authenticatorConfig</c>'s own verify
/// message — through the registered SHA-256 primitive and <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/>
/// over the actual token bytes, never a test-only crypto reimplementation — and the multi-command
/// bootstrap sequences (setPIN, fingerprint enrollment completion, <c>toggleAlwaysUv</c>) the R5 gate's
/// three arming triggers each need.
/// </summary>
internal static class CtapWaveLargeBlobsFixtures
{
    /// <summary>The PIN every bootstrap helper below establishes, unless a test needs a different one.</summary>
    public const string DefaultPin = "1234";

    /// <summary>The fixed 32-byte <c>0xff</c> prefix every <c>authenticatorLargeBlobs</c> verify message shares (CTAP 2.3, line 7578).</summary>
    private const int MessagePrefixLength = 32;

    /// <summary>The verify message's fixed two-byte command segment: <c>authenticatorLargeBlobs</c> (<c>0x0C</c>) followed by a literal <c>0x00</c> (CTAP 2.3, line 7578's <c>h'0c00'</c>).</summary>
    private const int CommandSegmentLength = 2;

    /// <summary>The verify message's 32-bit <c>offset</c> segment length in bytes.</summary>
    private const int OffsetSegmentLength = 4;

    /// <summary>The SHA-256 digest length in bytes.</summary>
    private const int Sha256Length = 32;


    /// <summary>Builds the complete <c>authenticatorLargeBlobs</c> request envelope for <paramref name="request"/>.</summary>
    /// <param name="request">The request model to encode.</param>
    /// <returns>The command byte followed by the CTAP2-canonical CBOR parameter map.</returns>
    public static byte[] BuildEnvelope(CtapLargeBlobsRequest request)
    {
        TaggedMemory<byte> parameters = CtapLargeBlobsRequestCborWriter.Write(request);
        byte[] envelope = new byte[parameters.Length + 1];
        envelope[0] = WellKnownCtapCommands.LargeBlobs;
        parameters.Span.CopyTo(envelope.AsSpan(1));

        return envelope;
    }


    /// <summary>Encodes and sends an <c>authenticatorLargeBlobs</c> request, returning the raw response envelope. The caller owns it and must dispose it.</summary>
    public static async Task<PooledMemory> SendAsync(
        CtapAuthenticatorSimulator simulator, CtapLargeBlobsRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = BuildEnvelope(request);

        return await simulator.TransceiveAsync(envelope, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Encodes, sends, and returns ONLY the CTAP2 status byte of an <c>authenticatorLargeBlobs</c> request.</summary>
    public static async Task<byte> SendExpectingStatusAsync(
        CtapAuthenticatorSimulator simulator, CtapLargeBlobsRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using PooledMemory response = await SendAsync(simulator, request, pool, cancellationToken).ConfigureAwait(false);

        return response.AsReadOnlySpan()[0];
    }


    /// <summary>
    /// Assembles <c>authenticatorLargeBlobs</c>' per-fragment verify message (CTAP 2.3 §6.10.2, lines
    /// 7578/7646): <c>32×0xff || h'0c00' || uint32(offset) || SHA-256(fragment)</c>.
    /// <paramref name="littleEndian"/> selects the offset's byte order — <see langword="true"/> for the
    /// spec-correct construction, <see langword="false"/> to build a deliberately WRONG message for the
    /// endianness-differential KAT (seams trap 2).
    /// </summary>
    /// <param name="offset">The fragment's <c>offset</c> value.</param>
    /// <param name="fragment">The fragment's contents, hashed via the registered SHA-256 primitive.</param>
    /// <param name="pool">The memory pool the digest computation allocates from.</param>
    /// <param name="littleEndian">Whether the offset is written little-endian (spec-correct) or big-endian (deliberately wrong).</param>
    /// <returns>The assembled 70-byte verify message.</returns>
    public static byte[] BuildVerifyMessage(int offset, ReadOnlySpan<byte> fragment, MemoryPool<byte> pool, bool littleEndian = true)
    {
        using DigestValue fragmentDigest = CryptographicKeyEvents.ComputeDigest(fragment, Sha256Length, CryptoTags.Sha256Digest, pool);

        byte[] message = new byte[MessagePrefixLength + CommandSegmentLength + OffsetSegmentLength + Sha256Length];
        message.AsSpan(0, MessagePrefixLength).Fill(0xff);
        message[MessagePrefixLength] = WellKnownCtapCommands.LargeBlobs;
        message[MessagePrefixLength + 1] = 0x00;

        Span<byte> offsetSpan = message.AsSpan(MessagePrefixLength + CommandSegmentLength, OffsetSegmentLength);
        if(littleEndian)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(offsetSpan, (uint)offset);
        }
        else
        {
            BinaryPrimitives.WriteUInt32BigEndian(offsetSpan, (uint)offset);
        }

        fragmentDigest.AsReadOnlySpan().CopyTo(message.AsSpan(MessagePrefixLength + CommandSegmentLength + OffsetSegmentLength));

        return message;
    }


    /// <summary>
    /// Computes a <c>set</c> fragment's <c>pinUvAuthParam</c>: <c>authenticate(token,
    /// BuildVerifyMessage(offset, fragment))</c> — the exact platform-side computation <c>verify</c>
    /// checks a presented value against.
    /// </summary>
    public static async Task<byte[]> ComputeSetSignatureAsync(
        byte[] token, CtapPinUvAuthProtocolId protocolId, int offset, ReadOnlyMemory<byte> fragment, MemoryPool<byte> pool, CancellationToken cancellationToken,
        bool littleEndian = true)
    {
        byte[] message = BuildVerifyMessage(offset, fragment.Span, pool, littleEndian);

        return await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Establishes <see cref="DefaultPin"/> and issues a <paramref name="permissions"/>-scoped
    /// <c>pinUvAuthToken</c> via the PIN path. <paramref name="rpId"/> is REQUIRED whenever
    /// <paramref name="permissions"/> includes <c>mc</c>/<c>ga</c> (CTAP 2.3 §6.5.5.7.2's own "RP ID
    /// Required" column) — <c>lbw</c> alone needs none, its own RP ID column is "Ignored".
    /// </summary>
    public static async Task<byte[]> EstablishPinAndIssueTokenAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, int permissions, CancellationToken cancellationToken,
        string? rpId = null)
    {
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, cancellationToken).ConfigureAwait(false);

        return await CtapWaveConfigFixtures.IssueTokenAsync(simulator, pool, protocolId, DefaultPin, permissions, rpId, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Bootstraps <see cref="DefaultPin"/>, issues an unbound <c>be</c>-only token via the PIN path (the
    /// ONLY way this profile can ever mint a <c>be</c>-scoped token, since <c>authenticatorBioEnrollment</c>'s
    /// own token gate is UNCONDITIONAL — bio scout Finding F — and <c>getPinUvAuthTokenUsingUvWithPermissions</c>
    /// itself requires an enrollment to already exist), and drives one full enrollment lifecycle
    /// (<c>enrollBegin</c> plus enough <c>enrollCaptureNextSample</c> calls for the default always-GOOD
    /// simulated sensor to complete it) so <see cref="CtapAuthenticatorState.HasProvisionedBioEnrollments"/>
    /// becomes <see langword="true"/>. Documented structural note: in this profile a PIN MUST already be
    /// set before any enrollment can exist at all, so this bootstrap cannot isolate "armed by enrollment
    /// alone, no PIN ever set" — the R5 gate's own <c>IsProtectedByUserVerification</c> predicate is
    /// consumed AS-IS (zero edits) and is a plain OR of the same two facts regardless of which one a test
    /// can reach in isolation.
    /// </summary>
    public static async Task CompleteBootstrapEnrollmentAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, CancellationToken cancellationToken)
    {
        byte[] beToken = await EstablishPinAndIssueTokenAsync(
            simulator, pool, protocolId, WellKnownCtapPinUvAuthTokenPermissions.Be, cancellationToken).ConfigureAwait(false);

        byte[] enrollBeginParam = await ComputeBioMessageSignatureAsync(
            beToken, protocolId, WellKnownCtapBioEnrollmentSubCommands.EnrollBegin, ReadOnlyMemory<byte>.Empty, pool, cancellationToken).ConfigureAwait(false);
        var enrollBeginRequest = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: enrollBeginParam);
        using PooledMemory beginResponse = await SendBioEnrollmentAsync(simulator, enrollBeginRequest, pool, cancellationToken).ConfigureAwait(false);
        if(!WellKnownCtapStatusCodes.IsOk(beginResponse.AsReadOnlySpan()[0]))
        {
            throw new Fido2FormatException($"Fixture enrollBegin failed with CTAP2 status 0x{beginResponse.AsReadOnlySpan()[0]:X2}.");
        }

        byte[] templateId = CtapBioEnrollmentResponseCborReader.Read(beginResponse.AsReadOnlyMemory()[1..]).TemplateId!.Value.ToArray();

        for(int sample = 1; sample < CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll; sample++)
        {
            ReadOnlyMemory<byte> subCommandParams = CtapBioEnrollmentRequestCborWriter.WriteSubCommandParams(templateId, null, null).Memory;
            byte[] captureParam = await ComputeBioMessageSignatureAsync(
                beToken, protocolId, WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample, subCommandParams, pool, cancellationToken).ConfigureAwait(false);
            var captureRequest = new CtapBioEnrollmentRequest(
                Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample,
                TemplateId: templateId, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: captureParam);
            using PooledMemory captureResponse = await SendBioEnrollmentAsync(simulator, captureRequest, pool, cancellationToken).ConfigureAwait(false);
            if(!WellKnownCtapStatusCodes.IsOk(captureResponse.AsReadOnlySpan()[0]))
            {
                throw new Fido2FormatException($"Fixture enrollCaptureNextSample failed with CTAP2 status 0x{captureResponse.AsReadOnlySpan()[0]:X2}.");
            }
        }
    }


    /// <summary>Computes a gated <c>authenticatorBioEnrollment</c> subcommand's own <c>pinUvAuthParam</c> (bio scout Finding C: <c>uint8(modality) || uint8(subCommand) || subCommandParams</c>).</summary>
    private static async Task<byte[]> ComputeBioMessageSignatureAsync(
        byte[] token, CtapPinUvAuthProtocolId protocolId, int subCommand, ReadOnlyMemory<byte> subCommandParams, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] message = new byte[2 + subCommandParams.Length];
        message[0] = (byte)WellKnownCtapBioEnrollmentModalities.Fingerprint;
        message[1] = (byte)subCommand;
        subCommandParams.Span.CopyTo(message.AsSpan(2));

        return await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Encodes and sends an <c>authenticatorBioEnrollment</c> request, returning the raw response envelope. The caller owns it and must dispose it.</summary>
    private static async Task<PooledMemory> SendBioEnrollmentAsync(
        CtapAuthenticatorSimulator simulator, CtapBioEnrollmentRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        TaggedMemory<byte> parameters = CtapBioEnrollmentRequestCborWriter.Write(request);
        int envelopeLength = parameters.Length + 1;
        using IMemoryOwner<byte> envelopeOwner = pool.Rent(envelopeLength);
        Memory<byte> envelope = envelopeOwner.Memory[..envelopeLength];
        envelope.Span[0] = WellKnownCtapCommands.BioEnrollment;
        parameters.Span.CopyTo(envelope.Span[1..]);

        return await simulator.TransceiveAsync(envelope, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends <c>toggleAlwaysUv</c> (CTAP 2.3 §6.11.2), tokenless when both <paramref name="pinUvAuthParam"/>
    /// and <paramref name="pinUvAuthProtocol"/> are omitted — legal on a fresh, unprotected device with
    /// <c>alwaysUv</c> still <see langword="false"/> (§6.11's own step-4 gate: neither protected-by-UV nor
    /// already-enabled, so the gate does not apply at all).
    /// </summary>
    public static async Task<byte> ToggleAlwaysUvAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CancellationToken cancellationToken,
        ReadOnlyMemory<byte>? pinUvAuthParam = null, int? pinUvAuthProtocol = null)
    {
        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: pinUvAuthProtocol, PinUvAuthParam: pinUvAuthParam);
        using PooledMemory response = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, request, pool, cancellationToken).ConfigureAwait(false);

        return response.AsReadOnlySpan()[0];
    }
}
