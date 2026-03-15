using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Represents the signed instruction transcript produced by the Wallet Secure
/// Cryptographic Application (WSCA) after successful instruction execution.
/// </summary>
/// <remarks>
/// <para>
/// The Wallet Secure Cryptographic Application (WSCA) is the wallet provider's
/// trusted application that interfaces with the Hardware Security Module (HSM).
/// It authenticates and executes wallet instructions on behalf of the user.
/// This transcript corresponds to the output of Algorithm 37 of the SECDSA specification.
/// </para>
/// <para>
/// The transcript provides publicly verifiable evidence that the wallet provider
/// correctly followed a user instruction. Its structure is:
/// </para>
/// <list type="bullet">
///   <item><description>The inner transcript TI: instruction payload, nonce point R, scaled verification points G'' and Y'', zero-knowledge proof (ZKP), Schnorr challenge Chal(SN), response hash H1, and execution result Res. This content is specific to the SECDSA EUDI Wallet protocol.</description></item>
///   <item><description>The WSCA signature Sig over TI using the transcript signing key s. Any third party can verify Sig using the public transcript verification key S without access to the HSM.</description></item>
/// </list>
/// <para>
/// The outer envelope -- signed opaque payload, signature, and sequence number -- is
/// a general pattern shared with cryptographic event logs and append-only audit logs.
/// The EUDI Wallet-specific content is entirely inside <see cref="InnerTranscript"/>.
/// </para>
/// <para>
/// Chain-forward extension: the sequence number provides ordering but does not
/// cryptographically bind each transcript to its predecessor. A hash of the
/// previous transcript's canonical bytes can be added as a chain link, making
/// the log tamper-evident without relying on sequence number integrity alone.
/// This is the same pattern used in append-only cryptographic audit logs where
/// each entry commits to its predecessor via a hash chain.
/// </para>
/// <para>
/// Specification reference: SECDSA specification, Algorithms 37 and 38.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class InstructionTranscript: IDisposable
{
    /// <summary>Tracks whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <summary>Owns the memory backing <see cref="InnerTranscript"/>.</summary>
    private IMemoryOwner<byte> InnerTranscriptOwner { get; }

    /// <summary>Owns the memory backing <see cref="WscaSignature"/>.</summary>
    private IMemoryOwner<byte> WscaSignatureOwner { get; }

    /// <summary>Owns the memory backing <see cref="ExecutionResult"/>.</summary>
    private IMemoryOwner<byte> ExecutionResultOwner { get; }

    /// <summary>
    /// Gets the inner transcript bytes TI.
    /// </summary>
    public ReadOnlyMemory<byte> InnerTranscript { get; }

    /// <summary>
    /// Gets the Wallet Secure Cryptographic Application (WSCA) signature Sig over
    /// <see cref="InnerTranscript"/>.
    /// </summary>
    public ReadOnlyMemory<byte> WscaSignature { get; }

    /// <summary>
    /// Gets the instruction execution result bytes returned by the Wallet Secure
    /// Cryptographic Device (WSCD).
    /// </summary>
    public ReadOnlyMemory<byte> ExecutionResult { get; }

    /// <summary>
    /// Gets the sequence number from the instruction that produced this transcript.
    /// </summary>
    public ulong SequenceNumber { get; }

    //TODO: Add PreviousTranscriptHash: a SHA-256 hash of the canonical bytes of the
    //preceding InstructionTranscript, making the log tamper-evident. Each entry would
    //then commit to its predecessor, forming a hash chain where altering any entry
    //invalidates all subsequent entries. The Create method and the private constructor
    //would need a corresponding ReadOnlySpan<byte> previousTranscriptHash parameter.


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
