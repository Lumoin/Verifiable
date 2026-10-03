using System.Globalization;
using System.Net;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.JCose;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Exercises both a host returning an early reader refusal and the shared HttpClient streaming adapter.
/// Neither transport compares a length to a limit. The tracked stream exposes only asynchronous,
/// short reads and records how much the library read before the transport disposed it.
/// </summary>
internal sealed class StreamingOutboundTransport: IDisposable
{
    /// <summary>The response facts handed to the library reader.</summary>
    private HttpHeaderSet Headers { get; }

    /// <summary>The stream handed to the reader, directly or through HttpClient.</summary>
    private TrackedBody Body { get; }

    /// <summary>The in-memory response source behind <see cref="Client"/>; this transport owns and disposes it.</summary>
    private ResponseHandler Handler { get; }

    /// <summary>The in-memory HTTP adapter; it never opens a socket.</summary>
    private HttpClient Client { get; }

    /// <summary>The transport selected by the test row.</summary>
    public OutboundTransportDelegate Delegate { get; }

    /// <summary>The reader result the direct transport returned, including an early refusal.</summary>
    public OutboundTransportResult? Returned { get; private set; }

    /// <summary>The number of bytes actually read from the response.</summary>
    public int BytesRead => Body.BytesRead;

    /// <summary>Whether the response stream was disposed by the transport.</summary>
    public bool IsDisposed => Body.IsDisposed;

    /// <summary>Creates a short-reading response, with an independently supplied declared length.</summary>
    public StreamingOutboundTransport(byte[] bytes, long? declaredLength, bool useHttpClient)
    {
        HttpHeaderSet.Builder headers = new();
        _ = headers.Add(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json);
        if(declaredLength is long length)
        {
            _ = headers.Add(WellKnownHttpHeaderNames.ContentLength, length.ToString(CultureInfo.InvariantCulture));
        }

        Headers = headers.Build();
        Body = new TrackedBody(bytes);
        Handler = new ResponseHandler(Body, declaredLength);
        Client = new HttpClient(Handler, disposeHandler: false);
        Delegate = useHttpClient ? GuardedHttpClientTransport.BuildSingleHopTransport(Client) : SendAsync;
    }


    /// <summary>Returns the reader's typed outcome and closes the stream even when reading stops early.</summary>
    private async ValueTask<OutboundTransportResult> SendAsync(
        OutboundRequest request, ExchangeContext context, OutboundResponseReaderDelegate readResponse,
        CancellationToken cancellationToken)
    {
        using(Body)
        {
            Returned = await readResponse(200, Headers, Body, cancellationToken).ConfigureAwait(false);
            return Returned;
        }
    }


    /// <inheritdoc />
    public void Dispose()
    {
        Client.Dispose();
        Handler.Dispose();
        Body.Dispose();
    }


    /// <summary>An HTTP response source with no network and no response buffering.</summary>
    private sealed class ResponseHandler(TrackedBody body, long? declaredLength): HttpMessageHandler
    {
        /// <inheritdoc />
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            HttpResponseMessage response = new(HttpStatusCode.OK) { Content = new StreamContent(body) };
            response.Content.Headers.ContentType = new(WellKnownMediaTypes.Application.Json);
            response.Content.Headers.ContentLength = declaredLength;
            return Task.FromResult(response);
        }
    }


    /// <summary>A non-seekable body whose short reads cannot be replaced by a synchronous copy.</summary>
    private sealed class TrackedBody(byte[] bytes): Stream
    {
        /// <summary>The in-memory source, isolated from this non-seekable stream wrapper.</summary>
        private MemoryStream Content { get; } = new(bytes, writable: false);

        /// <summary>The bytes received by the guarded reader.</summary>
        public int BytesRead { get; private set; }

        /// <summary>Whether the response owner closed the stream.</summary>
        public bool IsDisposed { get; private set; }

        /// <inheritdoc />
        public override bool CanSeek => false;

        /// <inheritdoc />
        public override bool CanRead => !IsDisposed;

        /// <inheritdoc />
        public override bool CanWrite => false;

        /// <inheritdoc />
        public override long Length => throw new NotSupportedException();

        /// <inheritdoc />
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override void Flush() => throw new NotSupportedException();

        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        /// <inheritdoc />
        public override void SetLength(long value) => throw new NotSupportedException();

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count) =>
            throw new InvalidOperationException("The response must be read asynchronously.");

        /// <inheritdoc />
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int count = Content.Read(buffer.Span[..Math.Min(7, buffer.Length)]);
            BytesRead += count;
            return ValueTask.FromResult(count);
        }

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            if(disposing)
            {
                Content.Dispose();
            }

            IsDisposed = true;
            base.Dispose(disposing);
        }
    }
}
