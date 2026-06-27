using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu.SecureMessaging;

/// <summary>
/// Reads elementary files from a contactless IC over an established
/// <see cref="SecureMessagingSession"/>: it protects each SELECT and READ BINARY, transceives it,
/// and unprotects the response, so callers work with plaintext file bytes.
/// </summary>
/// <remarks>
/// <para>
/// A transparent elementary file (EF.COM, EF.SOD, a data group) is read by selecting it, reading its
/// BER-TLV header to learn the total length, then reading the remaining bytes in chunks. Every APDU
/// passes through the <see cref="SecureMessagingSession"/>, which keeps the send-sequence counter in
/// step and verifies each response MAC before any data is decrypted.
/// </para>
/// </remarks>
public sealed class SecureMessagingChannel
{
    /// <summary>The number of bytes read first to determine a file's total length from its BER-TLV header.</summary>
    private const int FileHeaderLength = 4;

    /// <summary>The maximum number of data bytes a short READ BINARY can request (Le 0x00 means 256).</summary>
    private const int MaxReadLength = 256;

    /// <summary>The card device. Borrowed, not disposed.</summary>
    private ApduDevice Device { get; }

    /// <summary>The established Secure Messaging session. Borrowed, not disposed.</summary>
    private SecureMessagingSession Session { get; }


    /// <summary>
    /// Initialises a channel over a device and an established Secure Messaging session.
    /// </summary>
    /// <param name="device">The card device. Borrowed, not disposed.</param>
    /// <param name="session">The established Secure Messaging session. Borrowed, not disposed.</param>
    public SecureMessagingChannel(ApduDevice device, SecureMessagingSession session)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(session);

        Device = device;
        Session = session;
    }


    /// <summary>
    /// Selects and reads a transparent elementary file by its file identifier.
    /// </summary>
    /// <param name="fileId">The two-byte elementary file identifier (for example <c>0x011E</c> for EF.COM).</param>
    /// <param name="pool">The sensitive-memory pool for the file contents.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The read <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    public async ValueTask<ElementaryFile> ReadElementaryFileAsync(
        ushort fileId,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        await SelectElementaryFileAsync(fileId, pool, cancellationToken).ConfigureAwait(false);

        //The file content (DG1 holds the MRZ, DG2 biometrics) is sensitive, so it lives in pinned memory.
        using SecureMessagingResponse header = await ReadBinaryAsync(0, FileHeaderLength, pool, cancellationToken).ConfigureAwait(false);
        ThrowIfRejected(header.StatusWord, "READ BINARY header", fileId);

        int totalLength = DetermineFileLength(header.Data);
        IMemoryOwner<byte> file = pool.Rent(totalLength, AllocationKind.Pinned);
        try
        {
            int prefixLength = Math.Min(header.Data.Length, totalLength);
            header.Data[..prefixLength].CopyTo(file.Memory.Span);

            int offset = prefixLength;
            while(offset < totalLength)
            {
                int requested = Math.Min(MaxReadLength, totalLength - offset);
                using SecureMessagingResponse chunk = await ReadBinaryAsync(offset, requested, pool, cancellationToken).ConfigureAwait(false);
                ThrowIfRejected(chunk.StatusWord, "READ BINARY", fileId);
                if(chunk.Data.Length == 0)
                {
                    throw new InvalidOperationException($"READ BINARY returned no data at offset {offset} while reading file 0x{fileId:X4}.");
                }

                int copy = Math.Min(chunk.Data.Length, totalLength - offset);
                chunk.Data[..copy].CopyTo(file.Memory.Span[offset..]);
                offset += copy;
            }

            return new ElementaryFile(file, fileId);
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Issues a Secure Messaging SELECT of an elementary file by file identifier (P1=02, P2=0C).
    /// </summary>
    private async ValueTask SelectElementaryFileAsync(ushort fileId, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> identifier = pool.Rent(2);
        identifier.Memory.Span[0] = (byte)(fileId >> 8);
        identifier.Memory.Span[1] = (byte)fileId;

        using SecureMessagingResponse response = await SecureTransceiveAsync(
            0x00, InstructionCode.Select.Code, 0x02, 0x0C, identifier.Memory, expectedResponseLength: null, pool, cancellationToken).ConfigureAwait(false);

        ThrowIfRejected(response.StatusWord, "SELECT", fileId);
    }


    /// <summary>
    /// Issues a Secure Messaging READ BINARY for <paramref name="length"/> bytes at <paramref name="offset"/>.
    /// </summary>
    private async ValueTask<SecureMessagingResponse> ReadBinaryAsync(int offset, int length, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        //READ BINARY with a 15-bit offset in P1-P2 (the high bit of P1 is clear so it is not a short-EF reference).
        byte p1 = (byte)((offset >> 8) & 0x7F);
        byte p2 = (byte)(offset & 0xFF);

        return await SecureTransceiveAsync(
            0x00, InstructionCode.ReadBinary.Code, p1, p2, ReadOnlyMemory<byte>.Empty, length, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Throws when a Secure Messaging response carried an unsuccessful status word.
    /// </summary>
    private static void ThrowIfRejected(StatusWord statusWord, string operation, ushort fileId)
    {
        if(!statusWord.IsSuccess)
        {
            throw new InvalidOperationException($"Secure Messaging {operation} of file 0x{fileId:X4} was rejected: {statusWord}.");
        }
    }


    /// <summary>
    /// Protects a command, transceives it, and unprotects the response.
    /// </summary>
    private async ValueTask<SecureMessagingResponse> SecureTransceiveAsync(
        byte cla, byte ins, byte p1, byte p2, ReadOnlyMemory<byte> commandData, int? expectedResponseLength, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using ProtectedCommandApdu protectedCommand = await Session.ProtectCommandAsync(
            cla, ins, p1, p2, commandData, expectedResponseLength, pool, cancellationToken).ConfigureAwait(false);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(Device, protectedCommand.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            throw new InvalidOperationException($"Secure Messaging transceive failed with a transport error 0x{result.TransportErrorCode:X8}.");
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess)
        {
            throw new InvalidOperationException($"Secure Messaging response carried a transport error: {response.StatusWord}.");
        }

        return await Session.UnprotectResponseAsync(response.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Reads a file's total byte length from the start of its BER-TLV header (tag then definite length).
    /// </summary>
    private static int DetermineFileLength(ReadOnlySpan<byte> header)
    {
        int offset = 0;

        //A BER-TLV tag is two bytes when the low five bits of the first byte are all set.
        byte firstTagByte = header[offset++];
        if((firstTagByte & 0x1F) == 0x1F)
        {
            offset++;
        }

        byte lengthByte = header[offset++];
        int contentLength;
        if(lengthByte < 0x80)
        {
            contentLength = lengthByte;
        }
        else if(lengthByte == 0x81)
        {
            contentLength = header[offset++];
        }
        else if(lengthByte == 0x82)
        {
            contentLength = (header[offset] << 8) | header[offset + 1];
            offset += 2;
        }
        else
        {
            throw new InvalidOperationException($"Unsupported BER-TLV length encoding 0x{lengthByte:X2} in the file header.");
        }

        return offset + contentLength;
    }
}
