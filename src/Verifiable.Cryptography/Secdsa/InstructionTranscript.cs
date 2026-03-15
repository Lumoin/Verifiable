using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Represents the signed instruction transcript produced by the WSCA after
/// successful instruction execution (Algorithm 37 of the SECDSA specification at
/// https://wellet.nl/SECDSA-EUDI-wallet-latest.pdf).
/// </summary>
/// <remarks>
/// <para>
/// The transcript provides publicly verifiable evidence that the wallet provider
/// correctly followed a user instruction. It contains:
/// </para>
/// <list type="bullet">
///   <item><description>The inner transcript TI: instruction payload, nonce point R, scaled verification points G'' and Y'', ZKP, Schnorr challenge Chal(SN), response hash H1, and execution result Res.</description></item>
///   <item><description>The WSCA signature Sig over TI using the transcript signing key s.</description></item>
/// </list>
/// <para>
/// Any third party can verify the transcript using Algorithm 38 with only the Internal
/// Certificate and the transcript verification public key S.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class InstructionTranscript: IDisposable
{
    private bool Disposed { get; set; }

    private IMemoryOwner<byte> InnerTranscriptOwner { get; }

    private IMemoryOwner<byte> WscaSignatureOwner { get; }

    private IMemoryOwner<byte> ExecutionResultOwner { get; }

    /// <summary>
    /// Gets the inner transcript bytes TI.
    /// </summary>
    public ReadOnlyMemory<byte> InnerTranscript { get; }

    /// <summary>
    /// Gets the WSCA signature Sig over <see cref="InnerTranscript"/>.
    /// </summary>
    public ReadOnlyMemory<byte> WscaSignature { get; }

    /// <summary>
    /// Gets the instruction execution result bytes returned by the HSM.
    /// </summary>
    public ReadOnlyMemory<byte> ExecutionResult { get; }

    /// <summary>
    /// Gets the sequence number from the instruction that produced this transcript.
    /// </summary>
    public ulong SequenceNumber { get; }

    /// <summary>
    /// Creates an <see cref="InstructionTranscript"/> from its component parts.
    /// </summary>
    /// <param name="sequenceNumber">The sequence number of the originating instruction.</param>
    /// <param name="innerTranscriptBytes">The serialized inner transcript TI.</param>
    /// <param name="wscaSignatureBytes">The WSCA signature over TI.</param>
    /// <param name="executionResultBytes">The HSM execution result bytes.</param>
    /// <param name="pool">The memory pool for buffer allocation.</param>
    /// <returns>A new <see cref="InstructionTranscript"/>.</returns>
    public static InstructionTranscript Create(
        ulong sequenceNumber,
        ReadOnlySpan<byte> innerTranscriptBytes,
        ReadOnlySpan<byte> wscaSignatureBytes,
        ReadOnlySpan<byte> executionResultBytes,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> tiOwner = pool.Rent(innerTranscriptBytes.Length);
        innerTranscriptBytes.CopyTo(tiOwner.Memory.Span);

        IMemoryOwner<byte> sigOwner = pool.Rent(wscaSignatureBytes.Length);
        wscaSignatureBytes.CopyTo(sigOwner.Memory.Span);

        IMemoryOwner<byte> resOwner = pool.Rent(executionResultBytes.Length);
        executionResultBytes.CopyTo(resOwner.Memory.Span);

        return new InstructionTranscript(
            sequenceNumber,
            tiOwner,
            tiOwner.Memory.Slice(0, innerTranscriptBytes.Length),
            sigOwner,
            sigOwner.Memory.Slice(0, wscaSignatureBytes.Length),
            resOwner,
            resOwner.Memory.Slice(0, executionResultBytes.Length));
    }

    private InstructionTranscript(
        ulong sequenceNumber,
        IMemoryOwner<byte> innerTranscriptOwner,
        ReadOnlyMemory<byte> innerTranscript,
        IMemoryOwner<byte> wscaSignatureOwner,
        ReadOnlyMemory<byte> wscaSignature,
        IMemoryOwner<byte> executionResultOwner,
        ReadOnlyMemory<byte> executionResult)
    {
        SequenceNumber = sequenceNumber;
        InnerTranscriptOwner = innerTranscriptOwner;
        InnerTranscript = innerTranscript;
        WscaSignatureOwner = wscaSignatureOwner;
        WscaSignature = wscaSignature;
        ExecutionResultOwner = executionResultOwner;
        ExecutionResult = executionResult;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            InnerTranscriptOwner.Dispose();
            WscaSignatureOwner.Dispose();
            ExecutionResultOwner.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"InstructionTranscript(SN={SequenceNumber}, TI={InnerTranscript.Length} bytes, Sig={WscaSignature.Length} bytes, Result={ExecutionResult.Length} bytes)";
}