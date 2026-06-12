using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu;

/// <summary>
/// Typed command extensions over <see cref="ApduDevice"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each method is a thin layer over the raw <see cref="ApduExecutor.ExecuteAsync"/> primitive:
/// it builds a command APDU, runs it through the executor (which handles <c>61xx</c> response
/// chaining and <c>6Cxx</c> Le correction transparently), maps the final status word to a result,
/// and parses the response data into a typed value.
/// </para>
/// <para>
/// <strong>Growth pattern — adding a command:</strong> define a response type implementing
/// <see cref="IApduWireType"/> with a static <c>Parse(ref ApduReader, MemoryPool&lt;byte&gt;)</c>
/// method, then add an <c>extension(ApduDevice)</c> method here that builds the command bytes
/// with <see cref="CommandApdu"/> and delegates to <see cref="ExecuteAndParseAsync"/> with the
/// parser. No registry or command-object ceremony is required.
/// </para>
/// <para>
/// <strong>Status-word mapping:</strong> the raw executor is transport-level and reports any
/// terminal (non-chaining) status word as a successful transceive. This typed layer reinterprets
/// it: only <c>9000</c> yields a parsed value; any other status word becomes a card error carrying
/// the status word for classification.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class ApduCommandExtensions
{
    extension(ApduDevice device)
    {
        /// <summary>
        /// Issues a SELECT by application identifier (AID), requesting the File Control Information.
        /// </summary>
        /// <param name="aid">The application identifier to select.</param>
        /// <param name="pool">The memory pool for command and response buffers.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The parsed SELECT response, a card error, or a transport error.</returns>
        public ValueTask<ApduResult<SelectResponse>> SelectAsync(
            ReadOnlySpan<byte> aid,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(pool);

            //SELECT by DF name (P1=04), return FCI / first or only occurrence (P2=00), Le=0 (max).
            IMemoryOwner<byte> command = CommandApdu.BuildCase4(
                0x00, InstructionCode.Select.Code, 0x04, 0x00, aid, 0, pool);

            return ExecuteAndParseAsync(device, command, SelectResponse.Parse, pool, cancellationToken);
        }

        /// <summary>
        /// Issues a READ BINARY to read a region of a transparent file at the given offset.
        /// </summary>
        /// <param name="offset">The byte offset within the file. Encoded in P1-P2 as a 15-bit value, so it must be in <c>[0, 0x7FFF]</c>.</param>
        /// <param name="length">The number of bytes to read, in <c>[1, 256]</c>. A length of 256 is requested as Le <c>0x00</c>.</param>
        /// <param name="pool">The memory pool for command and response buffers.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The parsed READ BINARY response, a card error, or a transport error.</returns>
        public ValueTask<ApduResult<ReadBinaryResponse>> ReadBinaryAsync(
            int offset,
            int length,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, 0x7FFF);
            ArgumentOutOfRangeException.ThrowIfLessThan(length, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, ApduConstants.MaxShortResponseData);

            //READ BINARY with a 15-bit offset in P1-P2 (high bit of P1 cleared so it is not a short-EF reference).
            byte p1 = (byte)((offset >> 8) & 0x7F);
            byte p2 = (byte)(offset & 0xFF);
            IMemoryOwner<byte> command = CommandApdu.BuildCase2(
                0x00, InstructionCode.ReadBinary.Code, p1, p2, length, useExtended: false, pool);

            return ExecuteAndParseAsync(device, command, ReadBinaryResponse.Parse, pool, cancellationToken);
        }

        /// <summary>
        /// Issues a GET CHALLENGE to obtain fresh random bytes from the card.
        /// </summary>
        /// <param name="length">The number of challenge bytes to request, in <c>[1, 256]</c>. The eMRTD Basic Access Control protocol uses 8.</param>
        /// <param name="pool">The memory pool for command and response buffers.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The parsed GET CHALLENGE response, a card error, or a transport error.</returns>
        public ValueTask<ApduResult<GetChallengeResponse>> GetChallengeAsync(
            int length,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentOutOfRangeException.ThrowIfLessThan(length, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, ApduConstants.MaxShortResponseData);

            //GET CHALLENGE: P1=P2=00, Case 2 short asking the card for Le challenge bytes.
            IMemoryOwner<byte> command = CommandApdu.BuildCase2(
                0x00, InstructionCode.GetChallenge.Code, 0x00, 0x00, length, useExtended: false, pool);

            return ExecuteAndParseAsync(device, command, GetChallengeResponse.Parse, pool, cancellationToken);
        }
    }

    /// <summary>
    /// Runs a pre-built command through the executor and parses its response data on success.
    /// Owns <paramref name="command"/> and disposes it once the exchange completes.
    /// </summary>
    private static async ValueTask<ApduResult<TResponse>> ExecuteAndParseAsync<TResponse>(
        ApduDevice device,
        IMemoryOwner<byte> command,
        ApduResponseParser<TResponse> parser,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken) where TResponse : IApduWireType
    {
        using(command)
        {
            ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
                device, command.Memory, pool, cancellationToken).ConfigureAwait(false);

            if(result.IsTransportError)
            {
                return ApduResult<TResponse>.TransportError(result.TransportErrorCode);
            }

            using ApduResponse response = result.Value;
            StatusWord sw = response.StatusWord;

            if(!sw.IsSuccess)
            {
                return ApduResult<TResponse>.CardError(sw);
            }

            var reader = new ApduReader(response.Data);
            TResponse parsed = parser(ref reader, pool);

            return ApduResult<TResponse>.Success(parsed, sw);
        }
    }
}
