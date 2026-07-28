using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The per-call context an <see cref="FetchOcspResponseAsyncDelegate"/> implementation receives — the
/// responder location and the request bytes to send — so the delegate carries no caller data through a
/// lambda closure (the codebase's context-object convention for callback seams).
/// </summary>
public sealed record OcspFetchContext
{
    /// <summary>
    /// The OCSP responder URI to contact, one of the <c>id-ad-ocsp</c> access locations
    /// <see cref="RevocationSourceFactsExtractor"/> reads from the target certificate's Authority Information
    /// Access extension.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "An id-ad-ocsp accessLocation is a verbatim GeneralName IA5String read off the certificate (RFC 5280 §4.2.2.1); the transport delegate owns URI parsing and scheme policy, and promoting to System.Uri here would impose platform URI semantics on a wire value before that policy runs.")]
    public required string ResponderUri { get; init; }

    /// <summary>
    /// The DER-encoded <c>OCSPRequest</c> to send, tagged <see cref="PkiCertificateTags.OcspRequest"/>. Owned by
    /// the caller of the delegate; the delegate implementation must not dispose it.
    /// </summary>
    public required PkiCertificateMemory Request { get; init; }
}


/// <summary>
/// Sends an OCSP request to a responder and returns the raw response bytes. This is the network seam a
/// caller configures to make revocation checking online — the library ships the request/response format and
/// the fail-closed verification policy, not an HTTP client.
/// </summary>
/// <param name="context">The responder location and request bytes.</param>
/// <param name="pool">The memory pool the returned response's buffer is rented from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The raw DER-encoded <c>OCSPResponse</c> bytes, tagged <see cref="PkiCertificateTags.OcspResponse"/>, or
/// <see langword="null"/> when the responder could not be reached (connection failure, timeout, non-success
/// transport status). The caller owns and disposes the returned carrier.
/// </returns>
/// <remarks>
/// The delegate maps a <em>transport</em> failure to <see langword="null"/> so a caller trying several
/// responder URIs (see <see cref="RevocationSourceFacts.OcspResponderUris"/>) can move to the next one without
/// interpreting a network error as a revocation-status determination. A response that DID arrive — including
/// one carrying protocol-level garbage or an unsuccessful <c>OCSPResponseStatus</c> — is returned as bytes for
/// <see cref="OcspResponseVerification.VerifyAsync"/> to parse and reject; the delegate itself makes no
/// protocol judgement. A typical implementation is an HTTP POST of <see cref="OcspFetchContext.Request"/>'s
/// bytes to <see cref="OcspFetchContext.ResponderUri"/> with content type <c>application/ocsp-request</c>,
/// reading the response body as <c>application/ocsp-response</c>, per
/// <see href="https://www.rfc-editor.org/rfc/rfc6960#appendix-A.1">RFC 6960 Appendix A.1</see>.
/// </remarks>
public delegate ValueTask<PkiCertificateMemory?> FetchOcspResponseAsyncDelegate(
    OcspFetchContext context,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
