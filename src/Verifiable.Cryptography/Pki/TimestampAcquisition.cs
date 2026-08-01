using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Why an attempt to acquire a verified time-stamp token failed — the discriminator carried by
/// <see cref="TimestampAcquisitionException.FailureKind"/>.
/// </summary>
public enum TimestampAcquisitionFailureKind
{
    /// <summary>
    /// The transport delegate reported it could not reach the Time-Stamping Authority
    /// (<see cref="FetchTimestampResponseAsyncDelegate"/> returned <see langword="null"/>).
    /// </summary>
    TransportFailure,

    /// <summary>
    /// The <c>TimeStampResp</c> bytes were not well-formed DER, or a granted response carried no
    /// <c>timeStampToken</c> (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2">RFC 3161 §2.4.2</see>).
    /// </summary>
    ResponseMalformed,

    /// <summary>
    /// The Time-Stamping Authority's <c>PKIStatus</c> was neither <c>granted</c> (0) nor <c>grantedWithMods</c>
    /// (1) — see <see cref="TimestampAcquisitionException.PkiStatus"/> for the value it returned.
    /// </summary>
    ResponseRejected,

    /// <summary>
    /// The token's own CMS signature did not verify, or its <c>TSTInfo</c> could not be read — see
    /// <see cref="TimestampTokenInfo.ReadFromTokenAsync"/>, the choke point this composition opens the token
    /// through.
    /// </summary>
    TokenNotVerified,

    /// <summary>The request carried a nonce the token does not carry, or a different one.</summary>
    NonceMismatch,

    /// <summary>The token's message imprint does not match the digest the request carried.</summary>
    MessageImprintMismatch,

    /// <summary>
    /// The request asked for a specific TSA policy (<c>reqPolicy</c>) but the token was issued under a different
    /// one. <see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2">RFC 3161 §2.4.2</see> requires
    /// <c>TSTInfo.policy</c> to equal the request's <c>reqPolicy</c> when one was present (or the authority to
    /// return <c>unacceptedPolicy</c>); a TSA that silently issues under another policy is refused rather than
    /// accepted — the fail-open EN 319 422 clause 4.1.2 / Annex A defect this closes.
    /// </summary>
    PolicyMismatch
}


/// <summary>
/// The exception <see cref="TimestampAcquisition"/> throws when a time-stamp token cannot be trusted enough to
/// attach to a signature — the fail-closed shape of the creation-side seams (mirroring the JCose/COSE creation
/// precedent: a typed exception, not the validation-side conclusion model of
/// <see cref="SignatureValidationConclusion"/>, which is purpose-built for evaluating already-attached material
/// against ETSI EN 319 102-1 clause 5 rather than for gating what gets attached in the first place).
/// </summary>
public sealed class TimestampAcquisitionException: Exception
{
    /// <summary>Gets the classification of why acquisition failed.</summary>
    public TimestampAcquisitionFailureKind FailureKind { get; }

    /// <summary>
    /// Gets the <c>PKIStatus</c> value the Time-Stamping Authority returned, when
    /// <see cref="FailureKind"/> is <see cref="TimestampAcquisitionFailureKind.ResponseRejected"/>; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public int? PkiStatus { get; }


    /// <summary>
    /// Initializes a new instance, classified <see cref="TimestampAcquisitionFailureKind.ResponseMalformed"/>
    /// (the standard parameterless exception constructor .NET convention expects; every throw site in this
    /// library uses one of the classified overloads below instead).
    /// </summary>
    public TimestampAcquisitionException(): this(TimestampAcquisitionFailureKind.ResponseMalformed, "Time-stamp token acquisition failed.")
    {
    }


    /// <summary>
    /// Initializes a new instance with a message, classified <see cref="TimestampAcquisitionFailureKind.ResponseMalformed"/>.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public TimestampAcquisitionException(string message): this(TimestampAcquisitionFailureKind.ResponseMalformed, message)
    {
    }


    /// <summary>
    /// Initializes a new instance with a message and an inner exception, classified
    /// <see cref="TimestampAcquisitionFailureKind.ResponseMalformed"/>.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of this exception.</param>
    public TimestampAcquisitionException(string message, Exception innerException): this(TimestampAcquisitionFailureKind.ResponseMalformed, message, innerException)
    {
    }


    /// <summary>
    /// Initializes a new instance with a message.
    /// </summary>
    /// <param name="failureKind">The failure classification.</param>
    /// <param name="message">The message that describes the error.</param>
    public TimestampAcquisitionException(TimestampAcquisitionFailureKind failureKind, string message)
        : base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>
    /// Initializes a new instance for a <see cref="TimestampAcquisitionFailureKind.ResponseRejected"/> failure,
    /// carrying the rejected <c>PKIStatus</c> value.
    /// </summary>
    /// <param name="failureKind">The failure classification.</param>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="pkiStatus">The <c>PKIStatus</c> value the authority returned.</param>
    public TimestampAcquisitionException(TimestampAcquisitionFailureKind failureKind, string message, int pkiStatus)
        : base(message)
    {
        FailureKind = failureKind;
        PkiStatus = pkiStatus;
    }


    /// <summary>
    /// Initializes a new instance with a message and an inner exception.
    /// </summary>
    /// <param name="failureKind">The failure classification.</param>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that is the cause of this exception.</param>
    public TimestampAcquisitionException(TimestampAcquisitionFailureKind failureKind, string message, Exception innerException)
        : base(message, innerException)
    {
        FailureKind = failureKind;
    }
}


/// <summary>
/// A time-stamp token that <see cref="TimestampAcquisition.VerifyResponseAsync"/> has already verified: its
/// CMS signature checked (<see cref="TimestampTokenInfo.ReadFromTokenAsync"/>), its message imprint matched
/// against the digest the request carried, and its nonce matched when the request sent one. Ready to attach as
/// an unsigned attribute (<see cref="CmsAttribute"/> plus <see cref="CmsSignedDataAugmentation.AppendUnsignedAttributes"/>);
/// nothing in this type re-parses the token.
/// </summary>
public sealed class AcquiredTimestampToken: IDisposable
{
    private bool disposed;

    /// <summary>Gets the DER-encoded time-stamp token, tagged <see cref="PkiCertificateTags.TimestampToken"/>. Owned by this instance.</summary>
    public PkiCertificateMemory Token { get; }

    /// <summary>Gets the already-parsed, already-verified <c>TSTInfo</c> facts. Owned by this instance.</summary>
    public TimestampTokenInfo Info { get; }


    /// <summary>
    /// Initializes a new <see cref="AcquiredTimestampToken"/>, taking ownership of both carriers.
    /// </summary>
    /// <param name="token">The verified token bytes. Ownership transfers to this instance.</param>
    /// <param name="info">The already-read <c>TSTInfo</c> facts. Ownership transfers to this instance.</param>
    /// <exception cref="ArgumentNullException">When either argument is <see langword="null"/>.</exception>
    public AcquiredTimestampToken(PkiCertificateMemory token, TimestampTokenInfo info)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(info);

        Token = token;
        Info = info;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Token.Dispose();
            Info.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// Verifies an RFC 3161 <c>TimeStampResp</c> before any token it carries is trusted enough to attach to a
/// signature, and composes the whole request/transport/verify round trip as a convenience.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Verify before attach.</strong> A time-stamp token reaches a signature as the value of an unsigned
/// attribute (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1</see> clause 5.3's <c>signature-time-stamp</c>, clause 5.5.3's
/// <c>archive-time-stamp-v3</c>), so nothing about the CMS encoding stops a Time-Stamping Authority's response
/// from being malformed, rejected, replayed, or bound to the wrong data. <see cref="VerifyResponseAsync"/> is
/// the single gate every acquired token passes through before a caller may embed it: any check that fails
/// throws a typed <see cref="TimestampAcquisitionException"/> and returns nothing — there is no partially
/// verified result a caller could accidentally attach.
/// </para>
/// <para>
/// <strong>One parse path.</strong> Once a <c>TimeStampResp</c>'s embedded <c>timeStampToken</c> octets are
/// located, they are handed to <see cref="TimestampTokenInfo.ReadFromTokenAsync"/> — the same choke point
/// every other reader of a time-stamp token in this library uses — rather than re-parsed here. That call opens
/// the token's own CMS layer through the registered <see cref="VerifyCmsSignedDataDelegate"/>, which is where
/// "verify the token signature via the CMS seam" happens.
/// </para>
/// <para>
/// <strong>Message imprint comparison, not re-hashing.</strong> The caller already computed the digest it
/// asked the request to carry (<see cref="TimestampRequests"/>'s own remarks explain why); verifying a
/// response therefore compares the token's <c>messageImprint</c> against that same already-computed digest
/// byte for byte, rather than re-deriving it from original data this composition never sees.
/// </para>
/// </remarks>
public static class TimestampAcquisition
{
    /// <summary>
    /// The largest number of <c>PKIFreeText</c> entries read from a <c>PKIStatusInfo.statusString</c>. The
    /// syntax leaves the sequence unbounded; this bounds the walk a hostile response can provoke.
    /// </summary>
    private const int MaximumStatusStrings = 16;

    /// <summary><c>PKIStatus</c> value <c>granted</c> (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2">RFC 3161 §2.4.2</see>).</summary>
    private const int PkiStatusGranted = 0;

    /// <summary><c>PKIStatus</c> value <c>grantedWithMods</c> (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2">RFC 3161 §2.4.2</see>).</summary>
    private const int PkiStatusGrantedWithMods = 1;


    /// <summary>
    /// Verifies a <c>TimeStampResp</c> a Time-Stamping Authority returned: its <c>PKIStatus</c>, its embedded
    /// token's own CMS signature, the token's message imprint against the digest the request carried, and the
    /// token's nonce against the request's when one was sent. The message-imprint octets and their algorithm
    /// both come from the one carrier the registered digest seam produced and tagged, so the pair cannot
    /// disagree the way separately passed octets and an algorithm could; a caller holding wire-sourced digest
    /// octets wraps them in a <see cref="DigestValue"/> under the algorithm's own digest tag first.
    /// </summary>
    /// <param name="response">The DER-encoded <c>TimeStampResp</c>, tagged <see cref="PkiCertificateTags.TimestampResponse"/>.</param>
    /// <param name="messageImprint">The computed digest the originating request carried, carrying its own algorithm in its tag.</param>
    /// <param name="requestNonce">The originating request's nonce, or <see langword="null"/> when the request sent none.</param>
    /// <param name="requestedPolicyOid">The TSA policy the originating request asked for (<c>reqPolicy</c>), or <see langword="null"/> when it named none. When non-<see langword="null"/>, the token's <c>policy</c> MUST equal it (RFC 3161 §2.4.2) or acquisition fails <see cref="TimestampAcquisitionFailureKind.PolicyMismatch"/>.</param>
    /// <param name="pool">The memory pool for every allocation this call performs.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verified token, ready to attach. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="response"/>, <paramref name="messageImprint"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="response"/> does not carry a <c>TimeStampResp</c>, the carrier's tag names no digest algorithm this library states in PKI structures, or its length is not that algorithm's <see cref="PkiDigestAlgorithm.OutputByteLength"/>.</exception>
    /// <exception cref="TimestampAcquisitionException">
    /// When the response is malformed, was not granted, or the token it carries does not verify, does not
    /// match the message imprint, does not match the nonce, or was issued under a different policy than the
    /// request asked for.
    /// </exception>
    public static async ValueTask<AcquiredTimestampToken> VerifyResponseAsync(
        PkiCertificateMemory response,
        DigestValue messageImprint,
        Nonce? requestNonce,
        string? requestedPolicyOid,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(messageImprint);
        ArgumentNullException.ThrowIfNull(pool);
        if(!response.IsTimestampResponse)
        {
            throw new ArgumentException("The carrier must hold a DER-encoded TimeStampResp.", nameof(response));
        }

        PkiDigestAlgorithm messageImprintAlgorithm = PkiDigestAlgorithm.FromDigest(messageImprint)
            ?? throw new ArgumentException("The digest carrier's tag names no digest algorithm this library states in PKI structures.", nameof(messageImprint));
        if(messageImprint.Length != messageImprintAlgorithm.OutputByteLength)
        {
            throw new ArgumentException(
                $"The message imprint digest must be exactly {messageImprintAlgorithm.OutputByteLength} bytes for '{messageImprintAlgorithm.Identifier.Oid}'.",
                nameof(messageImprint));
        }

        (int status, ReadOnlyMemory<byte>? tokenDer, bool failInfoHasSetBits) parsed;
        try
        {
            parsed = ReadTimeStampResp(response.AsReadOnlyMemory());
        }
        catch(AsnContentException exception)
        {
            throw new TimestampAcquisitionException(
                TimestampAcquisitionFailureKind.ResponseMalformed,
                "The TimeStampResp is not well-formed DER (RFC 3161 §2.4.2).",
                exception);
        }

        if(parsed.status != PkiStatusGranted && parsed.status != PkiStatusGrantedWithMods)
        {
            throw new TimestampAcquisitionException(
                TimestampAcquisitionFailureKind.ResponseRejected,
                $"The Time-Stamping Authority did not grant the request (PKIStatus {parsed.status}, RFC 3161 §2.4.2).",
                parsed.status);
        }

        //RFC 3161 §2.4.2: failInfo carries a failure indication and belongs to a rejection. A granted or
        //grantedWithMods response carrying a PKIFailureInfo with any set bit is self-contradictory — a
        //compliant client (RFC 3161 §2.4.2) must not silently accept a failure bit it did not otherwise act on.
        if(parsed.failInfoHasSetBits)
        {
            throw new TimestampAcquisitionException(
                TimestampAcquisitionFailureKind.ResponseMalformed,
                "A granted TimeStampResp carried a PKIFailureInfo with set bits, which contradicts the granted status (RFC 3161 §2.4.2).");
        }

        if(parsed.tokenDer is not { } tokenDer)
        {
            throw new TimestampAcquisitionException(
                TimestampAcquisitionFailureKind.ResponseMalformed,
                "A granted TimeStampResp must carry a timeStampToken (RFC 3161 §2.4.2).");
        }

        PkiCertificateMemory tokenCarrier = ToTimestampTokenCarrier(tokenDer.Span, pool);
        TimestampTokenInfo? info = null;
        try
        {
            info = await TimestampTokenInfo.ReadFromTokenAsync(tokenCarrier, pool, cancellationToken).ConfigureAwait(false);
            if(!info.IsRead || info.MessageImprint is not { } tokenImprint)
            {
                throw new TimestampAcquisitionException(
                    TimestampAcquisitionFailureKind.TokenNotVerified,
                    $"The time-stamp token could not be verified ({info.Status}).");
            }

            if(!string.Equals(info.MessageImprintAlgorithm.Oid, messageImprintAlgorithm.Identifier.Oid, StringComparison.Ordinal)
                || !tokenImprint.AsReadOnlySpan().SequenceEqual(messageImprint.AsReadOnlySpan()))
            {
                throw new TimestampAcquisitionException(
                    TimestampAcquisitionFailureKind.MessageImprintMismatch,
                    "The token's message imprint does not match the digest the request carried (RFC 3161 §2.4.2).");
            }

            if(requestNonce is not null && !NonceMatches(requestNonce, info.Nonce))
            {
                throw new TimestampAcquisitionException(
                    TimestampAcquisitionFailureKind.NonceMismatch,
                    "The token's nonce does not match the request's nonce (RFC 3161 §2.4.2).");
            }

            //RFC 3161 §2.4.2: when the request named a reqPolicy, TSTInfo.policy MUST equal it (otherwise the
            //authority is required to return unacceptedPolicy). A request that named no policy imposes no check.
            //Without this the client is fail-open: a TSA that silently issues under a different policy — an
            //EN 319 422 clause 4.1.2 / Annex A concern — is accepted. Fail closed instead.
            if(requestedPolicyOid is not null
                && !string.Equals(info.PolicyOid, requestedPolicyOid, StringComparison.Ordinal))
            {
                throw new TimestampAcquisitionException(
                    TimestampAcquisitionFailureKind.PolicyMismatch,
                    $"The token was issued under policy '{info.PolicyOid}' but the request asked for '{requestedPolicyOid}' (RFC 3161 §2.4.2).");
            }

            return new AcquiredTimestampToken(tokenCarrier, info);
        }
        catch
        {
            tokenCarrier.Dispose();
            info?.Dispose();
            throw;
        }


        //Reads TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL },
        //PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText OPTIONAL,
        //failInfo PKIFailureInfo OPTIONAL } (RFC 3161 §2.4.2). statusString is consumed so the closing emptiness
        //check is exact; failInfo is interpreted for set bits (see the caller) rather than discarded —
        //ResponseRejected already carries PKIStatus itself.
        static (int Status, ReadOnlyMemory<byte>? TimeStampToken, bool FailInfoHasSetBits) ReadTimeStampResp(ReadOnlyMemory<byte> responseDer)
        {
            var reader = new AsnReader(responseDer, AsnEncodingRules.DER);
            AsnReader response = reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            AsnReader statusInfo = response.ReadSequence();
            if(!statusInfo.TryReadInt32(out int status))
            {
                throw new AsnContentException("A TimeStampResp PKIStatusInfo.status must fit a 32-bit integer (RFC 3161 §2.4.2).");
            }

            if(statusInfo.HasData && statusInfo.PeekTag() == Asn1Tag.Sequence)
            {
                AsnReader freeText = statusInfo.ReadSequence();
                int freeTextCount = 0;
                while(freeText.HasData)
                {
                    if(++freeTextCount > MaximumStatusStrings)
                    {
                        throw new AsnContentException("A TimeStampResp PKIFreeText carries more entries than this reader accepts.");
                    }

                    _ = freeText.ReadCharacterString(UniversalTagNumber.UTF8String);
                }

                freeText.ThrowIfNotEmpty();
            }

            bool failInfoHasSetBits = false;
            if(statusInfo.HasData && statusInfo.PeekTag() == Asn1Tag.PrimitiveBitString)
            {
                if(!statusInfo.TryReadPrimitiveBitString(out _, out ReadOnlyMemory<byte> failInfo))
                {
                    throw new AsnContentException("A TimeStampResp PKIFailureInfo must be a primitive BIT STRING in DER.");
                }

                //Any non-zero octet means at least one PKIFailureInfo bit is set.
                failInfoHasSetBits = failInfo.Span.IndexOfAnyExcept((byte)0) >= 0;
            }

            statusInfo.ThrowIfNotEmpty();

            //TimeStampToken ::= ContentInfo — read whole, unparsed; TimestampTokenInfo.ReadFromTokenAsync is
            //the single choke point that opens it. Deliberately not a `response.HasData ? ... : null`
            //conditional expression: the compiler resolves that shape's type as the non-nullable
            //ReadOnlyMemory<byte> of the true branch and converts the null branch to ITS default (an empty
            //ReadOnlyMemory<byte>) before the whole expression converts to the declared nullable type — so
            //the "no token" case silently becomes a present-but-empty value instead of true absence.
            ReadOnlyMemory<byte>? timeStampToken;
            if(response.HasData)
            {
                timeStampToken = response.ReadEncodedValue();
            }
            else
            {
                timeStampToken = null;
            }

            response.ThrowIfNotEmpty();

            return (status, timeStampToken, failInfoHasSetBits);
        }


        //Copies a TimeStampToken's octets into a pooled carrier tagged for TimestampTokenInfo.ReadFromTokenAsync.
        static PkiCertificateMemory ToTimestampTokenCarrier(ReadOnlySpan<byte> tokenDer, MemoryPool<byte> pool)
        {
            IMemoryOwner<byte> owner = pool.Rent(tokenDer.Length);
            try
            {
                tokenDer.CopyTo(owner.Memory.Span);

                return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }


        //Compares a request nonce against a token's read-back hexadecimal nonce as arbitrary-precision
        //non-negative integers, so a leading 0x00 sign-pad octet on either side (X.690 clause 8.3, the same
        //padding TimestampRequests.CreateAsync applies when the CSPRNG draw's high bit is set) never causes a
        //false mismatch.
        static bool NonceMatches(Nonce requestNonce, string? tokenNonceHex)
        {
            if(tokenNonceHex is null)
            {
                return false;
            }

            var requestValue = new BigInteger(requestNonce.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
            var tokenValue = new BigInteger(Convert.FromHexString(tokenNonceHex), isUnsigned: true, isBigEndian: true);

            return requestValue == tokenValue;
        }
    }


    /// <summary>
    /// Builds a request (<see cref="TimestampRequests.CreateAsync"/>), sends it through
    /// <paramref name="fetchResponse"/>, and verifies the response (<see cref="VerifyResponseAsync"/>) before
    /// returning — the convenience compose of this file's two other deliverables, for a caller that has no
    /// reason to keep the request/response steps separate. The message-imprint octets and their algorithm both
    /// come from the one carrier the registered digest seam produced and tagged; a caller holding wire-sourced
    /// digest octets wraps them in a <see cref="DigestValue"/> under the algorithm's own digest tag first.
    /// </summary>
    /// <param name="messageImprint">The computed digest of the data being time-stamped, carrying its own algorithm in its tag.</param>
    /// <param name="tsaUri">The Time-Stamping Authority to contact.</param>
    /// <param name="fetchResponse">The transport delegate.</param>
    /// <param name="pool">The memory pool for every allocation this call performs.</param>
    /// <param name="reqPolicyOid">The TSA policy the request asks for, or <see langword="null"/> to state none.</param>
    /// <param name="nonceByteLength">The nonce length in octets; see <see cref="TimestampRequests.CreateAsync"/>.</param>
    /// <param name="includeNonce">Whether the request carries a nonce; see <see cref="TimestampRequests.CreateAsync"/>.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The verified token, ready to attach. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">When <paramref name="tsaUri"/> is null or empty, or the carrier's tag names no digest algorithm this library states in PKI structures.</exception>
    /// <exception cref="ArgumentNullException">When <paramref name="messageImprint"/>, <paramref name="fetchResponse"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="TimestampAcquisitionException">
    /// When the authority could not be reached, or the response fails any check <see cref="VerifyResponseAsync"/> performs.
    /// </exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the same reason that property gives (the transport delegate owns URI parsing and scheme policy); promoting to System.Uri here would impose platform URI semantics before that policy runs.")]
    public static async ValueTask<AcquiredTimestampToken> AcquireAsync(
        DigestValue messageImprint,
        string tsaUri,
        FetchTimestampResponseAsyncDelegate fetchResponse,
        MemoryPool<byte> pool,
        string? reqPolicyOid = null,
        int nonceByteLength = 32,
        bool includeNonce = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(messageImprint);
        ArgumentException.ThrowIfNullOrEmpty(tsaUri);
        ArgumentNullException.ThrowIfNull(fetchResponse);
        ArgumentNullException.ThrowIfNull(pool);

        using TimestampRequestContent request = await TimestampRequests.CreateAsync(
            messageImprint, pool, reqPolicyOid, nonceByteLength, includeNonce, cancellationToken).ConfigureAwait(false);

        var fetchContext = new TimestampFetchContext { TsaUri = tsaUri, Request = request.Request };
        PkiCertificateMemory? response = await fetchResponse(fetchContext, pool, cancellationToken).ConfigureAwait(false);
        if(response is null)
        {
            throw new TimestampAcquisitionException(
                TimestampAcquisitionFailureKind.TransportFailure,
                $"The Time-Stamping Authority at '{tsaUri}' could not be reached.");
        }

        using(response)
        {
            return await VerifyResponseAsync(
                response, messageImprint, request.RequestNonce,
                request.RequestedPolicyOid, pool, cancellationToken).ConfigureAwait(false);
        }
    }
}
