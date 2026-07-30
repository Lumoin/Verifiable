using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The per-call context a <see cref="FetchTimestampResponseAsyncDelegate"/> implementation receives — the
/// Time-Stamping Authority location and the request bytes to send — so the delegate carries no caller data
/// through a lambda closure (the codebase's context-object convention for callback seams, mirroring
/// <see cref="OcspFetchContext"/>).
/// </summary>
public sealed record TimestampFetchContext
{
    /// <summary>
    /// The Time-Stamping Authority URI to contact
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-3.4">RFC 3161 §3.4</see>'s HTTP binding
    /// names it only as "the address of the TSA"; the caller supplies it, this seam carries no default).
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "A TSA address is caller-supplied configuration, not a wire value this library parses; the transport delegate owns URI parsing and scheme policy, matching OcspFetchContext.ResponderUri's own reasoning.")]
    public required string TsaUri { get; init; }

    /// <summary>
    /// The DER-encoded <c>TimeStampReq</c> to send, tagged <see cref="PkiCertificateTags.TimestampRequest"/>.
    /// Owned by the caller of the delegate; the delegate implementation must not dispose it.
    /// </summary>
    public required PkiCertificateMemory Request { get; init; }
}


/// <summary>
/// Sends an RFC 3161 <c>TimeStampReq</c> to a Time-Stamping Authority and returns the raw <c>TimeStampResp</c>
/// bytes. This is the network seam a caller configures to make time-stamping requests — the library ships the
/// request/response format and the fail-closed verify-before-attach policy
/// (<see cref="TimestampAcquisition"/>), not an HTTP client.
/// </summary>
/// <param name="context">The Time-Stamping Authority location and request bytes.</param>
/// <param name="pool">The memory pool the returned response's buffer is rented from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The raw DER-encoded <c>TimeStampResp</c> bytes, tagged <see cref="PkiCertificateTags.TimestampResponse"/>, or
/// <see langword="null"/> when the authority could not be reached (connection failure, timeout, non-success
/// transport status). The caller owns and disposes the returned carrier.
/// </returns>
/// <remarks>
/// The delegate maps a <em>transport</em> failure to <see langword="null"/>, mirroring
/// <see cref="FetchOcspResponseAsyncDelegate"/>'s own contract: a response that DID arrive — including one
/// carrying a rejected <c>PKIStatus</c> or garbage bytes — is returned as bytes for
/// <see cref="TimestampAcquisition.VerifyResponseAsync"/> to parse and reject; the delegate itself makes no
/// protocol judgement. A typical implementation is an HTTP POST of <see cref="TimestampFetchContext.Request"/>'s
/// bytes to <see cref="TimestampFetchContext.TsaUri"/> with content type <c>application/timestamp-query</c>,
/// reading the response body as <c>application/timestamp-reply</c>, per
/// <see href="https://www.rfc-editor.org/rfc/rfc3161#section-3.4">RFC 3161 §3.4</see>.
/// </remarks>
public delegate ValueTask<PkiCertificateMemory?> FetchTimestampResponseAsyncDelegate(
    TimestampFetchContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
