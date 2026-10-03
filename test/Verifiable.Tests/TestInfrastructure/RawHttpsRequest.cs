using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Sends one HTTP/1.1 request whose head is written field line by field line, exactly as the caller
/// lists it, and whose body is the caller's bytes, over a TLS connection pinned to a test host's own
/// certificate, to that host's loopback listener, and returns the status, every received field line and
/// the body. <see cref="HttpClient"/> joins two values of one request field into one field line, so a
/// request that carries a field on two lines reaches the wire only through this sender. The connection
/// opens through <see cref="LoopbackConnect"/>, the TLS handshake pins the certificate through
/// <see cref="WebSocketCertificatePinning"/>, as the stalled-handshake row of
/// <see cref="LoopbackKestrelTests"/> does, and the request asks the listener to close the connection
/// after the response, so the response is read to the end of the stream. The request goes to the connection in
/// one write of one buffer: the listener closes the connection after its response, and a byte the client sends
/// after the listener has read the whole request reaches a closed socket, whose reset discards the response the
/// client has not read; on Windows an empty write over <see cref="SslStream"/> is itself such bytes, a
/// zero-length TLS record, so the request carries nothing after its last byte.
/// </summary>
internal static class RawHttpsRequest
{
    /// <summary>The line terminator of an HTTP/1.1 head.</summary>
    private static string LineEnd { get; } = "\r\n";

    /// <summary>The separator between the head and the body of an HTTP/1.1 message.</summary>
    private static byte[] HeadEnd { get; } = "\r\n\r\n"u8.ToArray();

    /// <summary>The CRLF that ends a chunk's size line and a chunk's data in the chunked transfer coding.</summary>
    private static byte[] ChunkLineEnd { get; } = "\r\n"u8.ToArray();

    /// <summary>The size of each read from the connection into the response buffer.</summary>
    private static int ReceiveBufferSize { get; } = 4096;


    /// <summary>
    /// Sends <paramref name="method"/> to <paramref name="target"/> on <paramref name="host"/>'s
    /// listener with <c>Host</c>, then each of <paramref name="fieldLines"/> as its own field line in the
    /// order given, then <c>Content-Length</c> and <c>Connection: close</c>, and
    /// <paramref name="body"/>.
    /// </summary>
    /// <param name="host">The fixture whose listener serves <paramref name="target"/> and whose certificate the connection pins.</param>
    /// <param name="method">The request method.</param>
    /// <param name="target">The absolute URI of the request, on the host's loopback listener.</param>
    /// <param name="fieldLines">The request's field lines besides <c>Host</c>, <c>Content-Length</c> and <c>Connection</c>, each sent on its own line.</param>
    /// <param name="body">The body bytes, sent as given.</param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>The status, every received field line and the body.</returns>
    internal static async Task<HttpResponseData> SendAsync(
        TestHostShell host,
        string method,
        Uri target,
        IReadOnlyList<KeyValuePair<string, string>> fieldLines,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(fieldLines);

        StringBuilder head = new();
        _ = head.Append(method).Append(' ').Append(target.PathAndQuery).Append(" HTTP/1.1").Append(LineEnd);
        _ = head.Append("Host: ").Append(target.Authority).Append(LineEnd);
        foreach(KeyValuePair<string, string> fieldLine in fieldLines)
        {
            _ = head.Append(fieldLine.Key).Append(": ").Append(fieldLine.Value).Append(LineEnd);
        }

        _ = head.Append("Content-Length: ").Append(body.Length.ToString(CultureInfo.InvariantCulture)).Append(LineEnd);
        _ = head.Append("Connection: close").Append(LineEnd).Append(LineEnd);

        using Socket socket = await LoopbackConnect.ConnectAsync(
            new IPEndPoint(IPAddress.Loopback, target.Port), cancellationToken).ConfigureAwait(false);
        WebSocketCertificatePinning pinning = new(host.ServerCertificate);
        await using NetworkStream socketStream = new(socket, ownsSocket: false);
        await using SslStream tlsStream = new(socketStream, leaveInnerStreamOpen: true, pinning.Create());
        await tlsStream.AuthenticateAsClientAsync(
            new SslClientAuthenticationOptions { TargetHost = target.Host }, cancellationToken).ConfigureAwait(false);

        //The listener closes the connection after its response, and a byte the client sends after the listener has
        //read the whole request reaches a closed socket, whose reset discards the response the client has not read.
        //On Windows an empty write over SslStream is itself such bytes, a zero-length TLS record, so the head and the
        //body are composed into one buffer and written with one write, and nothing follows the request's last byte.
        string headText = head.ToString();
        ArrayBufferWriter<byte> request = new(headText.Length + body.Length);
        int headLength = Encoding.ASCII.GetBytes(headText, request.GetSpan(headText.Length));
        request.Advance(headLength);
        request.Write(body.Span);
        await tlsStream.WriteAsync(request.WrittenMemory, cancellationToken).ConfigureAwait(false);
        await tlsStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        ArrayBufferWriter<byte> received = new(ReceiveBufferSize);
        while(true)
        {
            int read = await tlsStream.ReadAsync(received.GetMemory(ReceiveBufferSize), cancellationToken).ConfigureAwait(false);
            if(read == 0)
            {
                break;
            }

            received.Advance(read);
        }

        return Parse(received.WrittenSpan);
    }


    /// <summary>
    /// Reads an HTTP/1.1 response: the status code of its status line, each field line as received, and
    /// its body, decoded from the chunked transfer coding when the response names it and otherwise read
    /// as the bytes after the head.
    /// </summary>
    /// <param name="response">The response bytes, read to the end of the stream.</param>
    /// <returns>The status, the field lines and the body text.</returns>
    private static HttpResponseData Parse(ReadOnlySpan<byte> response)
    {
        int headEnd = response.IndexOf(HeadEnd);
        if(headEnd < 0)
        {
            throw new InvalidOperationException("The response carries no complete head.");
        }

        string[] headLines = Encoding.ASCII.GetString(response[..headEnd]).Split(LineEnd);
        string[] statusParts = headLines[0].Split(' ', 3);
        int statusCode = int.Parse(statusParts[1], NumberStyles.None, CultureInfo.InvariantCulture);

        List<(string Name, string Value)> received = [];
        bool isChunked = false;
        foreach(string line in headLines.Skip(1))
        {
            int colon = line.IndexOf(':', StringComparison.Ordinal);
            if(colon < 0)
            {
                throw new InvalidOperationException($"The response head carries a field line without a colon: '{line}'.");
            }

            string name = line[..colon];
            string value = line[(colon + 1)..].Trim(' ', '\t');
            received.Add((name, value));
            isChunked |= string.Equals(name, "Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
                && value.Contains("chunked", StringComparison.OrdinalIgnoreCase);
        }

        ReadOnlySpan<byte> rest = response[(headEnd + HeadEnd.Length)..];
        string body = isChunked ? Dechunk(rest) : Encoding.UTF8.GetString(rest);

        return new HttpResponseData
        {
            StatusCode = statusCode,
            Body = body,
            Headers = new ResponseHeaders { Headers = HttpHeaderSet.FromReceived(received) }
        };
    }


    /// <summary>
    /// Decodes a body sent in the chunked transfer coding
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9112#section-7.1">RFC 9112 Section 7.1</see>): each chunk's
    /// hexadecimal size line, then that many bytes and the CRLF that ends the chunk's data, until the chunk of
    /// size zero. The chunks are written into one <see cref="ArrayBufferWriter{T}"/> over spans of the received
    /// bytes. A size line without its CRLF, a size that is not hexadecimal or exceeds 64 bits, a chunk larger than
    /// the bytes that remain (the size read unsigned and bounded before it is used) and a chunk's data not followed by
    /// CRLF are each answered with an <see cref="InvalidOperationException"/> that names the defect.
    /// </summary>
    /// <param name="chunked">The bytes after the head.</param>
    /// <returns>The body text.</returns>
    private static string Dechunk(ReadOnlySpan<byte> chunked)
    {
        ArrayBufferWriter<byte> body = new(chunked.Length);
        int position = 0;
        while(true)
        {
            int sizeLineEnd = chunked[position..].IndexOf(ChunkLineEnd);
            if(sizeLineEnd < 0)
            {
                throw new InvalidOperationException($"The chunk size line at byte {position} has no CRLF.");
            }

            ReadOnlySpan<byte> sizeLine = chunked.Slice(position, sizeLineEnd);
            int extension = sizeLine.IndexOf((byte)';');
            ReadOnlySpan<byte> sizeText = (extension < 0 ? sizeLine : sizeLine[..extension]).Trim((byte)' ');
            if(!ulong.TryParse(sizeText, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ulong declaredSize))
            {
                throw new InvalidOperationException(
                    $"The chunk size line at byte {position} is not a hexadecimal size that fits 64 bits: '{Encoding.ASCII.GetString(sizeText)}'.");
            }

            position += sizeLineEnd + ChunkLineEnd.Length;
            if(declaredSize == 0)
            {
                return Encoding.UTF8.GetString(body.WrittenSpan);
            }

            //The declared size is unsigned and bounded against the bytes that remain before it is used, so a size
            //above the 32-bit signed range, 80000000 among them, is answered as an oversized chunk.
            int remaining = chunked.Length - position;
            if(declaredSize > (ulong)remaining)
            {
                throw new InvalidOperationException(
                    $"The chunk at byte {position} declares {declaredSize} bytes, more than the {remaining} that remain.");
            }

            int size = (int)declaredSize;
            body.Write(chunked.Slice(position, size));
            position += size;
            if(!chunked[position..].StartsWith(ChunkLineEnd))
            {
                throw new InvalidOperationException($"The chunk data ending at byte {position} is not followed by CRLF.");
            }

            position += ChunkLineEnd.Length;
        }
    }
}
