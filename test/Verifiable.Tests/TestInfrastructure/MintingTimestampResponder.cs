using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A <see cref="FetchTimestampResponseAsyncDelegate"/> test double that answers like a Time-Stamping Authority:
/// it decodes the <c>TimeStampReq</c> it is handed, mints a genuine token over the message imprint the request
/// states through the independent time-stamp protocol oracle
/// (<see cref="X509ChainTestRingTimestamping.MintTimestampTokenOverImprint"/>), and wraps it in the
/// <c>TimeStampResp</c> envelope of
/// <see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2">RFC 3161 §2.4.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// The decode is written here from the request syntax rather than taken from the library's own writer, so what
/// this responder answers is a fact about the octets that crossed the seam, not about the object the library
/// built. The envelope is likewise assembled with its own writer.
/// </para>
/// <para>
/// The authority, the certificates the token carries, and the generation time are supplied at construction —
/// this is a configured object, not a closure over test state — so a call sees exactly what it was given.
/// </para>
/// </remarks>
internal sealed class MintingTimestampResponder
{
    /// <summary><c>PKIStatus</c> value <c>granted</c> (RFC 3161 §2.4.2).</summary>
    private const int PkiStatusGranted = 0;

    /// <summary>The authority whose key signs every token this responder answers with.</summary>
    private X509ChainTestRingNode Authority { get; }

    /// <summary>The certificates every minted token carries in its own <c>certificates</c> field.</summary>
    private IReadOnlyList<X509ChainTestRingNode> EmbeddedCertificates { get; }

    /// <summary>The <c>genTime</c> every minted token states.</summary>
    private DateTimeOffset GenerationTime { get; }


    /// <summary>
    /// Initializes a new <see cref="MintingTimestampResponder"/>.
    /// </summary>
    /// <param name="authority">The Time-Stamping Authority node whose key signs the tokens.</param>
    /// <param name="embeddedCertificates">The certificates the tokens carry.</param>
    /// <param name="generationTime">The <c>genTime</c> the tokens state.</param>
    internal MintingTimestampResponder(
        X509ChainTestRingNode authority,
        IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
        DateTimeOffset generationTime)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(embeddedCertificates);

        Authority = authority;
        EmbeddedCertificates = embeddedCertificates;
        GenerationTime = generationTime;
    }


    /// <summary>
    /// Implements <see cref="FetchTimestampResponseAsyncDelegate"/>: mints a token over the request's message
    /// imprint and returns it inside a granted <c>TimeStampResp</c>.
    /// </summary>
    /// <param name="context">The authority address and the request octets.</param>
    /// <param name="pool">The memory pool the returned response is rented from.</param>
    /// <param name="cancellationToken">A cancellation token; unused, as this double performs no input or output.</param>
    /// <returns>The response. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the response carrier transfers to the caller via the returned ValueTask.")]
    internal ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);

        (byte[] messageImprint, string algorithmOid, byte[] nonce) = ReadRequest(context.Request.AsReadOnlyMemory());
        PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(algorithmOid);
        if(algorithm is null)
        {
            throw new ArgumentException($"The request states a message imprint algorithm this responder does not mint under: {algorithmOid}.", nameof(context));
        }

        using PkiCertificateMemory token = X509ChainTestRingTimestamping.MintTimestampTokenOverImprint(
            Authority, EmbeddedCertificates, messageImprint, GenerationTime, nonce, messageImprintAlgorithm: algorithm.Value);

        return ValueTask.FromResult<PkiCertificateMemory?>(BuildResponse(token.AsReadOnlySpan(), pool));
    }


    /// <summary>
    /// Decodes the fields of a <c>TimeStampReq</c> this responder answers from (RFC 3161 §2.4.1).
    /// </summary>
    /// <param name="request">The DER-encoded request.</param>
    /// <returns>The message imprint's hashed message, the algorithm it names, and the nonce when the request carried one.</returns>
    /// <remarks>
    /// The algorithm is read rather than assumed, because an authority answers under the algorithm the request
    /// states: a caller renewing an archive under a new hash algorithm asks this responder for a token under
    /// that algorithm, and a responder that always answered under one would make the renewal untestable.
    /// </remarks>
    private static (byte[] MessageImprint, string AlgorithmOid, byte[] Nonce) ReadRequest(ReadOnlyMemory<byte> request)
    {
        var outer = new AsnReader(request, AsnEncodingRules.DER);
        AsnReader timeStampReq = outer.ReadSequence();
        outer.ThrowIfNotEmpty();

        _ = timeStampReq.ReadInteger();                                     //version.
        AsnReader messageImprint = timeStampReq.ReadSequence();
        AsnReader hashAlgorithm = messageImprint.ReadSequence();
        string algorithmOid = hashAlgorithm.ReadObjectIdentifier();
        byte[] hashedMessage = messageImprint.ReadOctetString();
        messageImprint.ThrowIfNotEmpty();

        if(timeStampReq.HasData && timeStampReq.PeekTag() == Asn1Tag.ObjectIdentifier)
        {
            _ = timeStampReq.ReadObjectIdentifier();                        //reqPolicy.
        }

        byte[] nonce = [];
        if(timeStampReq.HasData && timeStampReq.PeekTag() == Asn1Tag.Integer)
        {
            nonce = timeStampReq.ReadIntegerBytes().ToArray();
        }

        return (hashedMessage, algorithmOid, nonce);
    }


    /// <summary>
    /// Wraps a token in a granted <c>TimeStampResp</c> (RFC 3161 §2.4.2).
    /// </summary>
    /// <param name="token">The DER-encoded token.</param>
    /// <param name="pool">The memory pool the response is rented from.</param>
    /// <returns>The response carrier. The caller disposes it.</returns>
    private static PkiCertificateMemory BuildResponse(ReadOnlySpan<byte> token, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence())                                    //PKIStatusInfo — status alone.
            {
                writer.WriteInteger(PkiStatusGranted);
            }

            writer.WriteEncodedValue(token);
        }

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out _);

            return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampResponse);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }
}
