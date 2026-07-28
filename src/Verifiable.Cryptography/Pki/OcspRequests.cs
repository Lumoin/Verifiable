using System;
using System.Buffers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>CertID</c> hash algorithm an OCSP request's <c>issuerNameHash</c>/<c>issuerKeyHash</c> are computed
/// with (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1">RFC 6960 §4.1.1</see>).
/// </summary>
public enum OcspCertIdDigestAlgorithm
{
    /// <summary>
    /// SHA-256 (<see href="https://www.rfc-editor.org/rfc/rfc5754#section-2">RFC 5754 §2</see>). The default
    /// and sound choice: SHA-1 is collision-broken and retained on this enum only for responder interop.
    /// </summary>
    Sha256 = 0,

    /// <summary>
    /// SHA-1 (<see href="https://www.rfc-editor.org/rfc/rfc3279">RFC 3279</see>).
    /// <see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.3">RFC 6960 §4.3</see> requires an OCSP
    /// client to support SHA-1 for <c>CertID</c> hash-algorithm agility with responders that have not moved
    /// to SHA-2; this is an identification use of the hash (matching an issuer's name and key to a request a
    /// responder already indexes), not a collision-sensitive one.
    /// </summary>
    Sha1
}


/// <summary>
/// An OCSP request built by <see cref="OcspRequests.CreateAsync"/>: the DER-encoded request bytes and, when the
/// request carries one, the nonce (RFC 9654 §2.1) it must be matched against on the response.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class OcspRequestContent: IDisposable
{
    /// <summary>Gets the DER-encoded <c>OCSPRequest</c>, tagged <see cref="PkiCertificateTags.OcspRequest"/>. Owned by this instance.</summary>
    public PkiCertificateMemory Request { get; }

    /// <summary>
    /// Gets the nonce this request carries in its <c>requestExtensions</c>, or <see langword="null"/> when
    /// <see cref="OcspRequests.CreateAsync"/> was called with <c>includeNonce: false</c>. Owned by this instance;
    /// its bytes were already consumed (<see cref="Nonce.UseNonce"/>) to embed them in <see cref="Request"/>,
    /// so a later comparison against a response reads <see cref="Nonce.AsReadOnlySpan"/> directly rather than
    /// calling <see cref="Nonce.UseNonce"/> a second time.
    /// </summary>
    public Nonce? RequestNonce { get; }


    /// <summary>
    /// Initializes a new <see cref="OcspRequestContent"/>, taking ownership of both carriers.
    /// </summary>
    /// <param name="request">The DER-encoded OCSPRequest. Ownership transfers to this instance.</param>
    /// <param name="requestNonce">The request's nonce, or <see langword="null"/>. Ownership transfers to this instance.</param>
    public OcspRequestContent(PkiCertificateMemory request, Nonce? requestNonce)
    {
        ArgumentNullException.ThrowIfNull(request);

        Request = request;
        RequestNonce = requestNonce;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        Request.Dispose();
        RequestNonce?.Dispose();
    }


    private string DebuggerDisplay => $"OcspRequestContent({Request.Length} bytes, nonce={(RequestNonce is null ? "none" : $"{RequestNonce.Length} bytes")})";
}


/// <summary>
/// Builds an unsigned, single-certificate RFC 6960 <c>OCSPRequest</c> with <see cref="AsnWriter"/>. No
/// certificate library and no HTTP client: the library ships the request format, the caller (via
/// <see cref="FetchOcspResponseAsyncDelegate"/>) ships the transport.
/// </summary>
/// <remarks>
/// The <c>issuerNameHash</c>/<c>issuerKeyHash</c> digests are computed through <see cref="CryptographicKeyEvents"/>'s
/// async digest seam (<c>ComputeDigestAsync</c>) rather than the synchronous one: composability, not I/O,
/// motivates the choice — a caller that composes an OCSP request into a larger async pipeline (chain building,
/// revocation checking) never has to special-case a sync call in the middle of it. A backend that completes
/// synchronously (as the registered Microsoft SHA backend does) makes the returned <see cref="ValueTask{TResult}"/>
/// nearly free; a future hardware- or service-backed digest composes here with no signature change.
/// </remarks>
public static class OcspRequests
{
    /// <summary>The RFC 9654 §2.1 <c>Nonce ::= OCTET STRING (SIZE(1..128))</c> lower bound.</summary>
    private const int MinimumNonceByteLength = 1;

    /// <summary>The RFC 9654 §2.1 <c>Nonce ::= OCTET STRING (SIZE(1..128))</c> upper bound.</summary>
    private const int MaximumNonceByteLength = 128;

    /// <summary>The SHA-1 digest output length in bytes (FIPS 180-4).</summary>
    private const int Sha1DigestByteLength = 20;

    /// <summary>The SHA-256 digest output length in bytes (FIPS 180-4).</summary>
    private const int Sha256DigestByteLength = 32;

    /// <summary>
    /// The SHA-1 digest tag — composed inline because <see cref="CryptoTags"/> omits SHA-1 by design. Carries
    /// no qualifier: the registered <see cref="ComputeDigestDelegate"/> default (<c>MicrosoftCryptographicFunctions.ComputeDigestAsync</c>)
    /// dispatches the algorithm from the <see cref="HashAlgorithmName"/> this tag carries, mirroring the eMRTD
    /// BAC idiom (<c>BasicAccessControl.ComputeSha1Async</c>).
    /// </summary>
    private static Tag Sha1DigestTag { get; } = Tag.Create(HashAlgorithmName.SHA1).With(Purpose.Digest).With(EncodingScheme.Raw);

    /// <summary>The nonce tag for an OCSP request's <c>id-pkix-ocsp-nonce</c> extension value.</summary>
    private static Tag OcspRequestNonceTag { get; } = Tag.Create(Purpose.Nonce).With(EntropySource.Csprng);


    /// <summary>
    /// Builds an unsigned <c>OCSPRequest</c> for exactly one target certificate
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1">RFC 6960 §4.1.1</see>): no
    /// <c>requestorName</c>, a single <c>Request</c> with no <c>singleRequestExtensions</c>, and no
    /// <c>optionalSignature</c>.
    /// </summary>
    /// <param name="certificate">The certificate whose revocation status is being requested.</param>
    /// <param name="issuerCertificate">The certificate's issuer, from which <c>issuerNameHash</c>/<c>issuerKeyHash</c> are computed.</param>
    /// <param name="certIdDigestAlgorithm">The <c>CertID</c> hash algorithm.</param>
    /// <param name="pool">The memory pool for every allocation this call performs.</param>
    /// <param name="nonceByteLength">The nonce length in octets (RFC 9654 §2.1: <c>SIZE(1..128)</c>; 32 is the RFC's suggested length and this parameter's default).</param>
    /// <param name="includeNonce">
    /// Whether to include an <c>id-pkix-ocsp-nonce</c> <c>requestExtensions</c> entry (RFC 9654 §2.1).
    /// Defaults to <see langword="true"/>: accepting a pre-produced, nonce-less (RFC 5019-profile) response is
    /// a caller opt-out via <see langword="false"/>, not the default — a request without a nonce cannot
    /// itself detect a replayed response.
    /// </param>
    /// <param name="cancellationToken">A cancellation token observed by the <c>issuerNameHash</c>/<c>issuerKeyHash</c> digest computations.</param>
    /// <returns>The built request and, when requested, the nonce it carries. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">When <paramref name="certificate"/> or <paramref name="issuerCertificate"/> does not carry an X.509 certificate.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="nonceByteLength"/> is outside RFC 9654 §2.1's <c>SIZE(1..128)</c>.</exception>
    /// <exception cref="AsnContentException">When either certificate is not a well-formed DER-encoded RFC 5280 certificate.</exception>
    public static async ValueTask<OcspRequestContent> CreateAsync(
        PkiCertificateMemory certificate,
        PkiCertificateMemory issuerCertificate,
        OcspCertIdDigestAlgorithm certIdDigestAlgorithm,
        MemoryPool<byte> pool,
        int nonceByteLength = 32,
        bool includeNonce = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(pool);
        if(!certificate.IsX509Certificate)
        {
            throw new ArgumentException("The carrier must hold an X.509 certificate.", nameof(certificate));
        }

        if(!issuerCertificate.IsX509Certificate)
        {
            throw new ArgumentException("The carrier must hold an X.509 certificate.", nameof(issuerCertificate));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(nonceByteLength, MinimumNonceByteLength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(nonceByteLength, MaximumNonceByteLength);

        (ReadOnlyMemory<byte> issuerSubjectNameDer, ReadOnlyMemory<byte> issuerPublicKeyBits) = ReadIssuerCertIdInputs(issuerCertificate);
        ReadOnlyMemory<byte> serialNumber = ReadSerialNumber(certificate);
        (Tag digestTag, int digestLength, string hashAlgorithmOid, bool writeNullParameters) = ResolveDigest(certIdDigestAlgorithm);

        using DigestValue issuerNameHash = await CryptographicKeyEvents.ComputeDigestAsync(
            issuerSubjectNameDer, digestLength, digestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        using DigestValue issuerKeyHash = await CryptographicKeyEvents.ComputeDigestAsync(
            issuerPublicKeyBits, digestLength, digestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        Nonce? nonce = includeNonce
            ? CryptographicKeyEvents.GenerateNonce(nonceByteLength, OcspRequestNonceTag, pool)
            : null;
        try
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            WriteOcspRequest(writer, hashAlgorithmOid, writeNullParameters, issuerNameHash.AsReadOnlySpan(), issuerKeyHash.AsReadOnlySpan(), serialNumber.Span, nonce);

            int encodedLength = writer.GetEncodedLength();
            IMemoryOwner<byte> requestOwner = pool.Rent(encodedLength);
            try
            {
                _ = writer.TryEncode(requestOwner.Memory.Span, out _);
                var request = new PkiCertificateMemory(requestOwner, PkiCertificateTags.OcspRequest);

                return new OcspRequestContent(request, nonce);
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


        //Writes the OCSPRequest structure (RFC 6960 §4.1.1) for exactly one certificate, with an optional
        //id-pkix-ocsp-nonce requestExtensions entry (RFC 9654 §2.1). A single-caller helper kept local to the
        //call it serves.
        static void WriteOcspRequest(
            AsnWriter writer,
            string hashAlgorithmOid,
            bool writeNullParameters,
            ReadOnlySpan<byte> issuerNameHash,
            ReadOnlySpan<byte> issuerKeyHash,
            ReadOnlySpan<byte> serialNumber,
            Nonce? nonce)
        {
            //OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, optionalSignature [0] EXPLICIT Signature OPTIONAL }; no optionalSignature.
            using(writer.PushSequence())
            {
                //TBSRequest ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1, requestorName [1] EXPLICIT GeneralName OPTIONAL,
                //requestList SEQUENCE OF Request, requestExtensions [2] EXPLICIT Extensions OPTIONAL }.
                //version DEFAULT v1 is omitted per DER; no requestorName.
                using(writer.PushSequence())
                {
                    using(writer.PushSequence()) //requestList
                    {
                        //Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }; no singleRequestExtensions.
                        using(writer.PushSequence())
                        {
                            //CertID ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, issuerNameHash OCTET STRING, issuerKeyHash OCTET STRING, serialNumber CertificateSerialNumber }.
                            using(writer.PushSequence())
                            {
                                using(writer.PushSequence()) //hashAlgorithm AlgorithmIdentifier
                                {
                                    writer.WriteObjectIdentifier(hashAlgorithmOid);
                                    if(writeNullParameters)
                                    {
                                        //SHA-1's AlgorithmIdentifier carries explicit NULL parameters (RFC 3279); SHA-2 omits parameters entirely (RFC 5754 §2).
                                        writer.WriteNull();
                                    }
                                }

                                writer.WriteOctetString(issuerNameHash);
                                writer.WriteOctetString(issuerKeyHash);
                                writer.WriteInteger(serialNumber);
                            }
                        }
                    }

                    if(nonce is not null)
                    {
                        //requestExtensions [2] EXPLICIT Extensions OPTIONAL, carrying the id-pkix-ocsp-nonce entry (RFC 9654 §2.1).
                        using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2)))
                        {
                            using(writer.PushSequence()) //Extensions ::= SEQUENCE OF Extension
                            {
                                using(writer.PushSequence()) //Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
                                {
                                    writer.WriteObjectIdentifier(WellKnownOids.OcspNonce);

                                    //extnValue wraps the DER encoding of Nonce ::= OCTET STRING (RFC 9654 §2.1); encode it
                                    //into a fixed scratch buffer sized for the RFC's SIZE(1..128) bound plus TLV overhead.
                                    Span<byte> nonceValueBuffer = stackalloc byte[MaximumNonceByteLength + 8];
                                    var nonceValueWriter = new AsnWriter(AsnEncodingRules.DER);
                                    nonceValueWriter.WriteOctetString(nonce.UseNonce());
                                    _ = nonceValueWriter.TryEncode(nonceValueBuffer, out int nonceValueWritten);
                                    writer.WriteOctetString(nonceValueBuffer[..nonceValueWritten]);
                                }
                            }
                        }
                    }
                }
            }
        }
    }


    /// <summary>
    /// Reads the target certificate's <c>serialNumber</c> INTEGER content bytes, verbatim, for the
    /// <c>CertID.serialNumber</c> field.
    /// </summary>
    private static ReadOnlyMemory<byte> ReadSerialNumber(PkiCertificateMemory certificate)
    {
        var reader = new AsnReader(certificate.AsReadOnlyMemory(), AsnEncodingRules.DER);
        AsnReader certificateSequence = reader.ReadSequence();
        AsnReader tbs = certificateSequence.ReadSequence();

        //version [0] EXPLICIT INTEGER DEFAULT v1 (RFC 5280 §4.1.2.1), present in practically every certificate.
        if(tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            _ = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        return tbs.ReadIntegerBytes();
    }


    /// <summary>
    /// Reads the issuer certificate's <c>subject</c> Name (full encoded value, tag and length included — the
    /// <c>issuerNameHash</c> input) and its <c>subjectPublicKey</c> BIT STRING content bytes, excluding the
    /// tag, length, and unused-bits count octet (the <c>issuerKeyHash</c> input), per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1">RFC 6960 §4.1.1</see>.
    /// </summary>
    private static (ReadOnlyMemory<byte> SubjectNameDer, ReadOnlyMemory<byte> PublicKeyBitStringContent) ReadIssuerCertIdInputs(PkiCertificateMemory issuerCertificate)
    {
        var reader = new AsnReader(issuerCertificate.AsReadOnlyMemory(), AsnEncodingRules.DER);
        AsnReader certificateSequence = reader.ReadSequence();
        AsnReader tbs = certificateSequence.ReadSequence();

        if(tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            _ = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        _ = tbs.ReadIntegerBytes();                                     //serialNumber.
        _ = tbs.ReadSequence();                                         //signature AlgorithmIdentifier.
        _ = tbs.ReadEncodedValue();                                     //issuer Name.
        _ = tbs.ReadSequence();                                         //validity.
        ReadOnlyMemory<byte> subjectNameDer = tbs.ReadEncodedValue();   //subject Name — full TLV.

        AsnReader subjectPublicKeyInfo = tbs.ReadSequence();
        _ = subjectPublicKeyInfo.ReadSequence();                        //algorithm AlgorithmIdentifier.
        if(!subjectPublicKeyInfo.TryReadPrimitiveBitString(out _, out ReadOnlyMemory<byte> publicKeyBitStringContent))
        {
            throw new AsnContentException("A SubjectPublicKeyInfo must carry its subjectPublicKey as a primitive BIT STRING in DER (RFC 5280 §4.1.2.7).");
        }

        return (subjectNameDer, publicKeyBitStringContent);
    }


    /// <summary>
    /// Resolves the <see cref="Tag"/>, output length, <c>AlgorithmIdentifier</c> OID, and NULL-parameters
    /// convention for a <see cref="OcspCertIdDigestAlgorithm"/>. No qualifier: the async digest seam dispatches
    /// the algorithm from the <see cref="Tag"/> itself (see <see cref="Sha1DigestTag"/>'s remarks).
    /// </summary>
    private static (Tag Tag, int Length, string HashAlgorithmOid, bool WriteNullParameters) ResolveDigest(OcspCertIdDigestAlgorithm algorithm) => algorithm switch
    {
        OcspCertIdDigestAlgorithm.Sha256 => (CryptoTags.Sha256Digest, Sha256DigestByteLength, WellKnownOids.Sha256, false),
        OcspCertIdDigestAlgorithm.Sha1 => (Sha1DigestTag, Sha1DigestByteLength, WellKnownOids.Sha1, true),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported OCSP CertID digest algorithm.")
    };
}
