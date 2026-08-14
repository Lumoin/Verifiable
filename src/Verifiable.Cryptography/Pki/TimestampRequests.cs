using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A time-stamp request built by <see cref="TimestampRequests.CreateAsync"/>: the DER-encoded
/// <c>TimeStampReq</c> bytes and, when the request carries one, the nonce
/// (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1">RFC 3161 §2.4.1</see>) it must be
/// matched against the response.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TimestampRequestContent: IDisposable
{
    /// <summary>Gets the DER-encoded <c>TimeStampReq</c>, tagged <see cref="PkiCertificateTags.TimestampRequest"/>. Owned by this instance.</summary>
    public PkiCertificateMemory Request { get; }

    /// <summary>
    /// Gets the nonce this request carries, or <see langword="null"/> when
    /// <see cref="TimestampRequests.CreateAsync"/> was called with <c>includeNonce: false</c>. Owned by this
    /// instance; its bytes were already consumed (<see cref="Nonce.UseNonce"/>) to embed them in
    /// <see cref="Request"/>, so a later comparison against a response reads
    /// <see cref="Nonce.AsReadOnlySpan"/> directly rather than calling <see cref="Nonce.UseNonce"/> a second
    /// time.
    /// </summary>
    public Nonce? RequestNonce { get; }

    /// <summary>
    /// Gets the TSA policy object identifier this request asked the authority to issue under
    /// (<c>reqPolicy</c>, <see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1">RFC 3161 §2.4.1</see>),
    /// or <see langword="null"/> when the request stated none. Retained so
    /// <see cref="TimestampAcquisition.VerifyResponseAsync"/> can hold the returned token's <c>policy</c> to what
    /// was asked for (RFC 3161 §2.4.2); a request that named no policy imposes no policy check on the response.
    /// </summary>
    public string? RequestedPolicyOid { get; }


    /// <summary>
    /// Initializes a new <see cref="TimestampRequestContent"/>, taking ownership of both carriers.
    /// </summary>
    /// <param name="request">The DER-encoded TimeStampReq. Ownership transfers to this instance.</param>
    /// <param name="requestNonce">The request's nonce, or <see langword="null"/>. Ownership transfers to this instance.</param>
    /// <param name="requestedPolicyOid">The TSA policy the request asked for (<c>reqPolicy</c>), or <see langword="null"/>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="request"/> is <see langword="null"/>.</exception>
    public TimestampRequestContent(PkiCertificateMemory request, Nonce? requestNonce, string? requestedPolicyOid = null)
    {
        ArgumentNullException.ThrowIfNull(request);

        Request = request;
        RequestNonce = requestNonce;
        RequestedPolicyOid = requestedPolicyOid;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        Request.Dispose();
        RequestNonce?.Dispose();
    }


    private string DebuggerDisplay => $"TimestampRequestContent({Request.Length} bytes, nonce={(RequestNonce is null ? "none" : $"{RequestNonce.Length} bytes")})";
}


/// <summary>
/// Builds an RFC 3161 <c>TimeStampReq</c> with <see cref="AsnWriter"/>. No certificate library and no HTTP
/// client: the library ships the request format, the caller (via <see cref="FetchTimestampResponseAsyncDelegate"/>)
/// ships the transport, and <see cref="TimestampAcquisition"/> verifies the response before any token is
/// attached to a signature.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="OcspRequests"/>'s shape exactly: <see cref="AsnWriter"/> over pooled memory, a nonce drawn
/// through the entropy provider seam, and an async surface even though today's composition needs no
/// <c>await</c> — the message-imprint digest arrives pre-computed (see the <paramref name="messageImprintAlgorithm"/>
/// remarks below), and the registered <see cref="GenerateNonceDelegate"/> happens to complete synchronously.
/// Composability, not I/O, motivates keeping this <see cref="ValueTask{TResult}"/>-returning: a caller that
/// composes a time-stamp request into a larger async pipeline (signature creation, archive-time-stamp
/// augmentation) never has to special-case a sync call in the middle of it, and a future async entropy
/// backend (a TPM/HSM-backed CSPRNG) composes here with no signature change — the same rationale
/// <see cref="OcspRequests"/> states for its own digest calls.
/// </para>
/// <para>
/// <strong>Why the message imprint arrives pre-computed.</strong> Unlike an OCSP request's <c>issuerNameHash</c>/
/// <c>issuerKeyHash</c> (always the issuer certificate's own fields), what a time-stamp request's
/// <c>messageImprint</c> is a digest of is level-dependent: a signature-time-stamp hashes the raw signature
/// value (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.3</see>), an archive-time-stamp-v3 hashes the <c>ats-hash-index-v3</c>-driven
/// concatenation (clause 5.5.3). That decision belongs to the creation surface composing this builder, so the
/// caller computes the digest through the registered <see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, CancellationToken)"/>
/// seam over whatever octets its level requires, then hands the resulting bytes and their
/// <see cref="PkiDigestAlgorithm"/> here.
/// </para>
/// </remarks>
public static class TimestampRequests
{
    /// <summary>The RFC 3161 <c>TimeStampReq.version</c> value this builder writes (v1).</summary>
    private const int RequestVersion = 1;

    /// <summary>
    /// The smallest nonce length this builder accepts. RFC 3161 places no <c>SIZE</c> constraint on
    /// <c>nonce</c> (an unbounded <c>INTEGER</c>); this floor rejects a caller-supplied length that could
    /// not carry meaningful anti-replay entropy.
    /// </summary>
    private const int MinimumNonceByteLength = 1;

    /// <summary>
    /// The largest nonce length this builder accepts. Not an RFC ceiling — none exists for an <c>INTEGER</c>
    /// nonce — but an engineering bound so a caller cannot accidentally request unbounded entropy; 128
    /// matches the ceiling RFC 9654 §2.1 places on an OCSP nonce, ample margin beyond any anti-replay need.
    /// </summary>
    private const int MaximumNonceByteLength = 128;

    /// <summary>The nonce tag for a time-stamp request's <c>nonce</c> field.</summary>
    private static Tag TimestampRequestNonceTag { get; } = Tag.Create(Purpose.Nonce).With(EntropySource.Csprng);


    /// <summary>
    /// Builds a <c>TimeStampReq</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1">RFC 3161 §2.4.1</see>): version 1, the
    /// message imprint from the computed digest carrier — the octets and their algorithm both come from the
    /// one carrier the registered digest seam produced and tagged, so the pair cannot disagree the way
    /// separately passed octets and an algorithm could — an optional <c>reqPolicy</c>, a nonce drawn from the
    /// entropy provider unless suppressed, and <c>certReq</c> always <see langword="true"/> — a creation-side
    /// request always asks for the Time-Stamping Authority's certificate, since the token has to be verified
    /// (<see cref="TimestampAcquisition"/>) and later embedded. A caller holding wire-sourced digest octets
    /// wraps them in a <see cref="DigestValue"/> under the algorithm's own digest tag first; the octets never
    /// cross this surface bare.
    /// </summary>
    /// <param name="messageImprint">The computed digest of the data being time-stamped, carrying its own algorithm in its tag.</param>
    /// <param name="pool">The memory pool for every allocation this call performs.</param>
    /// <param name="reqPolicyOid">The TSA policy the request asks for, or <see langword="null"/> to state none.</param>
    /// <param name="nonceByteLength">The nonce length in octets; 32 is a sound default (matching <see cref="OcspRequests.CreateAsync"/>'s own), not an RFC-mandated one — RFC 3161 places no <c>SIZE</c> bound on the <c>nonce</c> field.</param>
    /// <param name="includeNonce">Whether to include a <c>nonce</c> field. Defaults to <see langword="true"/>: a request with no nonce cannot itself detect a replayed response.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The built request and, when requested, the nonce it carries. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="messageImprint"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the carrier's tag names no digest algorithm this library states in PKI structures, or its length is not that algorithm's <see cref="PkiDigestAlgorithm.OutputByteLength"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="nonceByteLength"/> is outside this builder's accepted range.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the built request (and, when drawn, the nonce) transfers to the returned carrier, which the caller disposes; the nested catch blocks dispose them on a partial failure. The ValueTask.FromResult wrapper this method returns through is what defeats the analyzer's own escape analysis here.")]
    public static ValueTask<TimestampRequestContent> CreateAsync(
        DigestValue messageImprint,
        BaseMemoryPool pool,
        string? reqPolicyOid = null,
        int nonceByteLength = 32,
        bool includeNonce = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(messageImprint);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        PkiDigestAlgorithm algorithm = PkiDigestAlgorithm.FromDigest(messageImprint)
            ?? throw new ArgumentException("The digest carrier's tag names no digest algorithm this library states in PKI structures.", nameof(messageImprint));
        if(messageImprint.Length != algorithm.OutputByteLength)
        {
            throw new ArgumentException(
                $"The message imprint digest must be exactly {algorithm.OutputByteLength} bytes for '{algorithm.Identifier.Oid}'.",
                nameof(messageImprint));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(nonceByteLength, MinimumNonceByteLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(nonceByteLength, MaximumNonceByteLength);

        Nonce? nonce = includeNonce
            ? CryptographicKeyEvents.GenerateNonce(nonceByteLength, TimestampRequestNonceTag, pool)
            : null;
        try
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            WriteTimeStampReq(writer, algorithm.Identifier.Oid, messageImprint.AsReadOnlySpan(), reqPolicyOid, nonce);

            int encodedLength = writer.GetEncodedLength();
            IMemoryOwner<byte> requestOwner = pool.Rent(encodedLength);
            try
            {
                _ = writer.TryEncode(requestOwner.Memory.Span, out _);
                var request = new PkiCertificateMemory(requestOwner, PkiCertificateTags.TimestampRequest);

                return ValueTask.FromResult(new TimestampRequestContent(request, nonce, reqPolicyOid));
            }
            catch
            {
                requestOwner.Dispose();
                throw;
            }
        }
        catch
        {
            nonce?.Dispose();
            throw;
        }


        //Writes TimeStampReq ::= SEQUENCE { version INTEGER {v1(1)}, messageImprint MessageImprint,
        //reqPolicy TSAPolicyId OPTIONAL, nonce INTEGER OPTIONAL, certReq BOOLEAN DEFAULT FALSE,
        //extensions [0] IMPLICIT Extensions OPTIONAL } (RFC 3161 §2.4.1). No extensions.
        static void WriteTimeStampReq(
            AsnWriter writer,
            string hashAlgorithmOid,
            ReadOnlySpan<byte> messageImprintDigest,
            string? reqPolicyOid,
            Nonce? nonce)
        {
            using(writer.PushSequence())
            {
                writer.WriteInteger(RequestVersion);

                //MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }.
                using(writer.PushSequence())
                {
                    using(writer.PushSequence()) //hashAlgorithm AlgorithmIdentifier
                    {
                        writer.WriteObjectIdentifier(hashAlgorithmOid);

                        //SHA-2 family AlgorithmIdentifier parameters are absent (RFC 5754 §2); PkiDigestAlgorithm
                        //resolves only SHA-256/384/512 (see its remarks), so no NULL-parameters branch applies.
                    }

                    writer.WriteOctetString(messageImprintDigest);
                }

                if(reqPolicyOid is not null)
                {
                    writer.WriteObjectIdentifier(reqPolicyOid);
                }

                if(nonce is not null)
                {
                    //nonce INTEGER OPTIONAL: written from the CSPRNG bytes as an unsigned magnitude, so a
                    //positive INTEGER results (with a leading 0x00 sign-pad octet when the high bit is set,
                    //X.690 clause 8.3) regardless of the drawn bytes' own high bit.
                    writer.WriteInteger(new BigInteger(nonce.UseNonce(), isUnsigned: true, isBigEndian: true));
                }

                //certReq BOOLEAN DEFAULT FALSE — always written true (see the method's own remarks); DER
                //requires an explicit encoding whenever a value differs from its DEFAULT.
                writer.WriteBoolean(true);
            }
        }
    }
}
