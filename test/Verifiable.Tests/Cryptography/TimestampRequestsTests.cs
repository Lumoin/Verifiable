using System;
using System.Buffers;
using System.Formats.Asn1;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="TimestampRequests"/>: the RFC 3161 <c>TimeStampReq</c> writer
/// (<see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1">RFC 3161 §2.4.1</see>). Every request is
/// decoded back through an independent <see cref="AsnReader"/> walk written in this file, never by re-reading
/// with the library's own writer, so the assertions are checks of the bytes this writer actually produced.
/// </summary>
[TestClass]
internal sealed class TimestampRequestsTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>Every field of a default request decodes exactly as RFC 3161 §2.4.1 prescribes.</summary>
    [TestMethod]
    public async Task BuildsAWellFormedRequestTheIndependentReaderDecodesFieldByField()
    {
        using DigestValue digest = await ComputeMessageImprintAsync(
            "timestamp requests stage 2 fixture", TestContext.CancellationToken).ConfigureAwait(false);

        using TimestampRequestContent request = await TimestampRequests.CreateAsync(
            digest, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(request.Request.IsTimestampRequest, "The built request must carry the TimestampRequest tag.");
        Assert.IsNotNull(request.RequestNonce, "A nonce must be present by default.");
        Assert.AreEqual(32, request.RequestNonce.Length, "The default nonce length must be 32 bytes.");

        var reader = new AsnReader(request.Request.AsReadOnlyMemory(), AsnEncodingRules.DER);
        AsnReader timeStampReq = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        Assert.IsTrue(timeStampReq.TryReadInt32(out int version));
        Assert.AreEqual(1, version, "RFC 3161 §2.4.1: version must be v1 (1).");

        AsnReader messageImprint = timeStampReq.ReadSequence();
        AsnReader hashAlgorithm = messageImprint.ReadSequence();
        Assert.AreEqual(WellKnownOids.Sha256, hashAlgorithm.ReadObjectIdentifier(), "The messageImprint.hashAlgorithm must name SHA-256.");
        Assert.IsFalse(hashAlgorithm.HasData, "RFC 5754 §2: SHA-2 AlgorithmIdentifier parameters must be absent.");
        ReadOnlyMemory<byte> hashedMessage = messageImprint.ReadOctetString();
        messageImprint.ThrowIfNotEmpty();
        Assert.IsTrue(hashedMessage.Span.SequenceEqual(digest.AsReadOnlySpan()), "hashedMessage must equal the caller-supplied digest exactly.");

        //No reqPolicy was supplied: the next field is the nonce INTEGER.
        Assert.AreEqual(new Asn1Tag(UniversalTagNumber.Integer), timeStampReq.PeekTag(), "The nonce INTEGER must follow messageImprint when no reqPolicy is supplied.");
        BigInteger nonceValue = timeStampReq.ReadInteger();
        BigInteger expectedNonce = new(request.RequestNonce.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        Assert.AreEqual(expectedNonce, nonceValue, "The written nonce INTEGER must equal the nonce the caller reads back.");

        Assert.IsTrue(timeStampReq.ReadBoolean(), "RFC 3161 §2.4.1: certReq must always be written true.");
        timeStampReq.ThrowIfNotEmpty();
    }


    /// <summary>A supplied <c>reqPolicy</c> is written as its own OID, between <c>messageImprint</c> and the nonce.</summary>
    [TestMethod]
    public async Task WritesTheSuppliedReqPolicyBetweenMessageImprintAndNonce()
    {
        using DigestValue digest = await ComputeMessageImprintAsync(
            "timestamp requests reqPolicy fixture", TestContext.CancellationToken).ConfigureAwait(false);
        const string policyOid = "1.2.3.4.5.6";

        using TimestampRequestContent request = await TimestampRequests.CreateAsync(
            digest, BaseMemoryPool.Shared, reqPolicyOid: policyOid, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var reader = new AsnReader(request.Request.AsReadOnlyMemory(), AsnEncodingRules.DER);
        AsnReader timeStampReq = reader.ReadSequence();
        _ = timeStampReq.ReadInteger();          //version.
        _ = timeStampReq.ReadSequence();          //messageImprint — read whole to advance past it.

        Assert.AreEqual(new Asn1Tag(UniversalTagNumber.ObjectIdentifier), timeStampReq.PeekTag(), "reqPolicy must be the next field.");
        Assert.AreEqual(policyOid, timeStampReq.ReadObjectIdentifier());
        _ = timeStampReq.ReadInteger();           //nonce.
        Assert.IsTrue(timeStampReq.ReadBoolean());
        timeStampReq.ThrowIfNotEmpty();
    }


    /// <summary><c>includeNonce: false</c> omits the nonce field entirely — the next field after messageImprint is certReq.</summary>
    [TestMethod]
    public async Task OmittingTheNonceOmitsTheNonceFieldEntirely()
    {
        using DigestValue digest = await ComputeMessageImprintAsync(
            "timestamp requests no-nonce fixture", TestContext.CancellationToken).ConfigureAwait(false);

        using TimestampRequestContent request = await TimestampRequests.CreateAsync(
            digest, BaseMemoryPool.Shared, includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(request.RequestNonce, "No nonce carrier is produced when includeNonce is false.");

        var reader = new AsnReader(request.Request.AsReadOnlyMemory(), AsnEncodingRules.DER);
        AsnReader timeStampReq = reader.ReadSequence();
        _ = timeStampReq.ReadInteger();
        _ = timeStampReq.ReadSequence();

        Assert.AreEqual(new Asn1Tag(UniversalTagNumber.Boolean), timeStampReq.PeekTag(), "certReq must follow directly when neither reqPolicy nor nonce is present.");
        Assert.IsTrue(timeStampReq.ReadBoolean());
        timeStampReq.ThrowIfNotEmpty();
    }


    /// <summary>A SHA-384 message imprint is written under its own OID and length, exercising algorithm agility beyond the SHA-256 default.</summary>
    [TestMethod]
    public async Task BuildsARequestUnderASha384MessageImprint()
    {
        byte[] content = Encoding.UTF8.GetBytes("timestamp requests sha384 fixture");
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            content, PkiDigestAlgorithm.Sha384.OutputByteLength, CryptoTags.Sha384Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using TimestampRequestContent request = await TimestampRequests.CreateAsync(
            digest, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var reader = new AsnReader(request.Request.AsReadOnlyMemory(), AsnEncodingRules.DER);
        AsnReader timeStampReq = reader.ReadSequence();
        _ = timeStampReq.ReadInteger();
        AsnReader messageImprint = timeStampReq.ReadSequence();
        AsnReader hashAlgorithm = messageImprint.ReadSequence();
        Assert.AreEqual(WellKnownOids.Sha384, hashAlgorithm.ReadObjectIdentifier());
        ReadOnlyMemory<byte> hashedMessage = messageImprint.ReadOctetString();
        Assert.HasCount(48, hashedMessage.ToArray(), "A SHA-384 hashedMessage must be 48 bytes.");
        Assert.IsTrue(hashedMessage.Span.SequenceEqual(digest.AsReadOnlySpan()));
    }


    /// <summary>The nonce length bound is enforced regardless of whether a nonce is actually requested, mirroring <see cref="OcspRequests"/>'s own contract.</summary>
    [TestMethod]
    public async Task EnforcesTheNonceLengthBoundUnconditionally()
    {
        using DigestValue digest = await ComputeMessageImprintAsync(
            "timestamp requests bounds fixture", TestContext.CancellationToken).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            async () => await TimestampRequests.CreateAsync(digest, BaseMemoryPool.Shared, nonceByteLength: 0, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false),
            "A zero-length nonce is below this builder's lower bound.").ConfigureAwait(false);
        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            async () => await TimestampRequests.CreateAsync(digest, BaseMemoryPool.Shared, nonceByteLength: 129, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false),
            "A 129-byte nonce is above this builder's upper bound.").ConfigureAwait(false);
        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            async () => await TimestampRequests.CreateAsync(digest, BaseMemoryPool.Shared, nonceByteLength: 0, includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false),
            "The nonce length is validated unconditionally, even when includeNonce is false.").ConfigureAwait(false);
    }


    /// <summary>A carrier whose length does not match its own tag's algorithm output length is rejected fail-closed — a hand-built carrier cannot smuggle a truncated imprint past the writer.</summary>
    [TestMethod]
    public async Task RejectsAMessageImprintDigestOfTheWrongLength()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(16);
        using var shortDigest = new DigestValue(owner, CryptoTags.Sha256Digest);

        await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await TimestampRequests.CreateAsync(shortDigest, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false),
            "A 16-byte digest cannot be a SHA-256 (32-byte) message imprint.").ConfigureAwait(false);
    }


    /// <summary>Computes a SHA-256 digest through the registered seam, returned as the tagged carrier the request writer consumes, standing in for the level-specific data a real caller would hash.</summary>
    private static ValueTask<DigestValue> ComputeMessageImprintAsync(string content, System.Threading.CancellationToken cancellationToken)
    {
        byte[] data = Encoding.UTF8.GetBytes(content);

        return CryptographicKeyEvents.ComputeDigestAsync(
            data, PkiDigestAlgorithm.Sha256.OutputByteLength, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: cancellationToken);
    }
}
