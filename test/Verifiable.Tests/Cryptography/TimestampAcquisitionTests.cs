using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="TimestampAcquisition"/>: the RFC 3161 <c>TimeStampResp</c> verify-before-
/// attach composition. Every genuine token is minted through the independent BouncyCastle time-stamp protocol
/// oracle (<see cref="X509ChainTestRingTimestamping.MintTimestampTokenAsync"/>); the <c>TimeStampResp</c>
/// envelope wrapping a token — PKIStatus plus the token octets — is assembled by an <see cref="AsnWriter"/> in
/// this file, independent of the reader under test.
/// </summary>
[TestClass]
internal sealed class TimestampAcquisitionTests
{
    /// <summary>PKIStatus <c>granted</c> (RFC 3161 §2.4.2).</summary>
    private const int PkiStatusGranted = 0;

    /// <summary>PKIStatus <c>rejection</c> (RFC 3161 §2.4.2).</summary>
    private const int PkiStatusRejection = 2;


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A granted response carrying a genuinely minted token, whose message imprint matches the digest the
    /// request carried, verifies: the returned <see cref="AcquiredTimestampToken"/> exposes the already-read
    /// facts without a second parse.
    /// </summary>
    [TestMethod]
    public async Task VerifiesAGrantedResponseCarryingAMatchingToken()
    {
        using TsaScenario scenario = BuildScenario();
        byte[] timestampedOctets = Encoding.UTF8.GetBytes("timestamp acquisition happy path fixture");
        using DigestValue digest = await ComputeSha256Async(timestampedOctets, TestContext.CancellationToken).ConfigureAwait(false);

        using TimestampRequestContent request = await TimestampRequests.CreateAsync(
            digest, BaseMemoryPool.Shared, includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            scenario.Authority, [scenario.Authority], timestampedOctets, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = WriteTimeStampResp(PkiStatusGranted, token.AsReadOnlySpan());

        using AcquiredTimestampToken acquired = await TimestampAcquisition.VerifyResponseAsync(
            response, digest,request.RequestNonce, request.RequestedPolicyOid, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(acquired.Token.IsTimestampToken, "The acquired token must carry the TimestampToken tag.");
        Assert.IsTrue(acquired.Info.IsRead, "The already-read TSTInfo facts must report Read.");
        Assert.AreEqual(TestClock.CanonicalEpoch, acquired.Info.GenerationTime, "The token's genTime must be the authority's stated generation time.");
        Assert.IsTrue(acquired.Info.MessageImprint!.AsReadOnlySpan().SequenceEqual(digest.AsReadOnlySpan()), "The acquired token's message imprint must equal the request's digest.");
    }


    /// <summary>
    /// ETSI EN 319 422 clauses 4.2.3 and 4.2.4 through ETSI TS 119 312 V1.4.3: a token requester supports RSA
    /// with SHA-512 (clause A.9 Table A.8) and post-2025 key lengths of at least 3&#160;000 bits (Tables 9-10).
    /// A granted response whose token is signed by a 3072-bit RSA authority under
    /// <c>sha512WithRSAEncryption</c> verifies through the shipped acquisition path, and the same token's CMS
    /// layer verifies through the managed backend — the zero-registration fallback — so such an authority is
    /// inside every shipped backend's profile.
    /// </summary>
    [TestMethod]
    public async Task VerifiesAGrantedResponseFromA3072BitRsaAuthoritySigningSha512()
    {
        using RSA authorityKey = RSA.Create(3072);
        using X509Certificate2 authority = CmsSignedDataTestFactory.MintSelfSignedTimeStampingCertificate(
            authorityKey, TestClock.CanonicalEpoch.AddDays(-1), TestClock.CanonicalEpoch.AddYears(1));
        byte[] timestampedOctets = Encoding.UTF8.GetBytes("timestamp acquisition rsa 3072 sha-512 fixture");
        using DigestValue digest = await ComputeSha256Async(timestampedOctets, TestContext.CancellationToken).ConfigureAwait(false);

        using TimestampRequestContent request = await TimestampRequests.CreateAsync(
            digest, BaseMemoryPool.Shared, includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenWithRsaAuthorityAsync(
            authority, authorityKey, timestampedOctets, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = WriteTimeStampResp(PkiStatusGranted, token.AsReadOnlySpan());

        using AcquiredTimestampToken acquired = await TimestampAcquisition.VerifyResponseAsync(
            response, digest,request.RequestNonce, request.RequestedPolicyOid, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(acquired.Info.IsRead, "The RSA-3072/SHA-512 authority's token must read through the shipped acquisition path.");
        Assert.AreEqual(TestClock.CanonicalEpoch, acquired.Info.GenerationTime, "The token's genTime must be the authority's stated generation time.");
        Assert.IsTrue(acquired.Info.MessageImprint!.AsReadOnlySpan().SequenceEqual(digest.AsReadOnlySpan()), "The acquired token's message imprint must equal the request's digest.");

        //The managed CMS backend — what the detached seam resolves to when a host registers nothing, and the
        //registrable fallback of the encapsulated one — accepts the same token's combined
        //sha512WithRSAEncryption signer with the 3072-bit modulus.
        using CmsSignedData tokenCms = CmsSignedData.FromBytes(token.AsReadOnlySpan(), BaseMemoryPool.Shared);
        using CmsVerifiedContent managedVerified = await ManagedCmsVerification.VerifyCmsSignedDataAsync(
            tokenCms, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsGreaterThan(0, managedVerified.Content.Length, "The managed backend surfaces the TSTInfo the token encapsulates.");
    }


    /// <summary>A request that sent a nonce, answered by a token carrying none, is a nonce mismatch — fail-closed, never silently accepted.</summary>
    [TestMethod]
    public async Task RejectsANonceMismatchWhenTheTokenDoesNotEchoTheRequestsNonce()
    {
        using TsaScenario scenario = BuildScenario();
        byte[] timestampedOctets = Encoding.UTF8.GetBytes("timestamp acquisition nonce mismatch fixture");
        using DigestValue digest = await ComputeSha256Async(timestampedOctets, TestContext.CancellationToken).ConfigureAwait(false);

        using TimestampRequestContent request = await TimestampRequests.CreateAsync(
            digest, BaseMemoryPool.Shared, includeNonce: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            scenario.Authority, [scenario.Authority], timestampedOctets, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = WriteTimeStampResp(PkiStatusGranted, token.AsReadOnlySpan());

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await TimestampAcquisition.VerifyResponseAsync(
                response, digest,request.RequestNonce, request.RequestedPolicyOid, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A request nonce with no matching token nonce must fail closed.").ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.NonceMismatch, exception.FailureKind);
    }


    /// <summary>A token minted over different octets than the ones the request's digest names is a message-imprint mismatch.</summary>
    [TestMethod]
    public async Task RejectsAMessageImprintMismatch()
    {
        using TsaScenario scenario = BuildScenario();
        byte[] mintedOver = Encoding.UTF8.GetBytes("timestamp acquisition imprint fixture — actually minted");
        byte[] requestedOver = Encoding.UTF8.GetBytes("timestamp acquisition imprint fixture — actually requested");
        using DigestValue requestDigest = await ComputeSha256Async(requestedOver, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            scenario.Authority, [scenario.Authority], mintedOver, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = WriteTimeStampResp(PkiStatusGranted, token.AsReadOnlySpan());

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await TimestampAcquisition.VerifyResponseAsync(
                response, requestDigest,requestNonce: null, requestedPolicyOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A token minted over different octets than the request's digest names must fail closed.").ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.MessageImprintMismatch, exception.FailureKind);
    }


    /// <summary>A rejected <c>PKIStatus</c> is reported with the exact status value the authority returned, never silently retried as if granted.</summary>
    [TestMethod]
    public async Task RejectsAResponseThatWasNotGranted()
    {
        using DigestValue digest = await ComputeSha256Async(
            Encoding.UTF8.GetBytes("timestamp acquisition rejected fixture"), TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = WriteTimeStampResp(PkiStatusRejection, tokenDer: default, includeToken: false);

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await TimestampAcquisition.VerifyResponseAsync(
                response, digest,requestNonce: null, requestedPolicyOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A rejection status must fail closed.").ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.ResponseRejected, exception.FailureKind);
        Assert.AreEqual(PkiStatusRejection, exception.PkiStatus);
    }


    /// <summary>A granted status with no <c>timeStampToken</c> field is malformed — RFC 3161 §2.4.2 requires the token whenever status is granted or grantedWithMods.</summary>
    [TestMethod]
    public async Task RejectsAGrantedResponseCarryingNoToken()
    {
        using DigestValue digest = await ComputeSha256Async(
            Encoding.UTF8.GetBytes("timestamp acquisition tokenless fixture"), TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = WriteTimeStampResp(PkiStatusGranted, tokenDer: default, includeToken: false);

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await TimestampAcquisition.VerifyResponseAsync(
                response, digest,requestNonce: null, requestedPolicyOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.ResponseMalformed, exception.FailureKind);
    }


    /// <summary>Garbage bytes that are not a well-formed <c>TimeStampResp</c> are rejected, never an unhandled parse exception.</summary>
    [TestMethod]
    public async Task RejectsMalformedResponseBytes()
    {
        using DigestValue digest = await ComputeSha256Async(
            Encoding.UTF8.GetBytes("timestamp acquisition malformed fixture"), TestContext.CancellationToken).ConfigureAwait(false);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(5);
        owner.Memory.Span[..5].Fill(0xFF);
        using var response = new PkiCertificateMemory(owner, PkiCertificateTags.TimestampResponse);

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await TimestampAcquisition.VerifyResponseAsync(
                response, digest,requestNonce: null, requestedPolicyOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.ResponseMalformed, exception.FailureKind);
    }


    /// <summary>A token whose signature was tampered after minting fails the CMS verification the choke point performs, never silently accepted.</summary>
    [TestMethod]
    public async Task RejectsATokenWhoseCmsSignatureDoesNotVerify()
    {
        using TsaScenario scenario = BuildScenario();
        byte[] timestampedOctets = Encoding.UTF8.GetBytes("timestamp acquisition tampered fixture");
        using DigestValue digest = await ComputeSha256Async(timestampedOctets, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            scenario.Authority, [scenario.Authority], timestampedOctets, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tampered = token.AsReadOnlySpan().ToArray();
        tampered[^1] ^= 0xFF;
        using PkiCertificateMemory response = WriteTimeStampResp(PkiStatusGranted, tampered);

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await TimestampAcquisition.VerifyResponseAsync(
                response, digest,requestNonce: null, requestedPolicyOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A tampered signature must not verify.").ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.TokenNotVerified, exception.FailureKind);
    }


    /// <summary><see cref="TimestampAcquisition.AcquireAsync"/> composes request, transport and verify into one successful round trip.</summary>
    [TestMethod]
    public async Task AcquireAsyncRunsTheFullRequestTransportVerifyRoundTrip()
    {
        using TsaScenario scenario = BuildScenario();
        byte[] timestampedOctets = Encoding.UTF8.GetBytes("timestamp acquisition compose fixture");
        using DigestValue digest = await ComputeSha256Async(timestampedOctets, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            scenario.Authority, [scenario.Authority], timestampedOctets, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var transport = new FixedTimestampResponder(WriteTimeStampResp(PkiStatusGranted, token.AsReadOnlySpan()));

        using AcquiredTimestampToken acquired = await TimestampAcquisition.AcquireAsync(
            digest, "https://tsa.example.test/", transport.FetchAsync, BaseMemoryPool.Shared,
            includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(acquired.Info.IsRead);
        Assert.IsTrue(acquired.Info.MessageImprint!.AsReadOnlySpan().SequenceEqual(digest.AsReadOnlySpan()));
    }


    /// <summary>An unreachable Time-Stamping Authority (the transport delegate returning <see langword="null"/>) is a typed <see cref="TimestampAcquisitionFailureKind.TransportFailure"/>.</summary>
    [TestMethod]
    public async Task AcquireAsyncReportsATransportFailureWhenTheAuthorityCannotBeReached()
    {
        using DigestValue digest = await ComputeSha256Async(
            Encoding.UTF8.GetBytes("timestamp acquisition unreachable fixture"), TestContext.CancellationToken).ConfigureAwait(false);
        using var transport = new FixedTimestampResponder(response: null);

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await TimestampAcquisition.AcquireAsync(
                digest, "https://tsa.example.test/unreachable", transport.FetchAsync, BaseMemoryPool.Shared,
                includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.TransportFailure, exception.FailureKind);
    }


    /// <summary>An arbitrary TSA policy object identifier the D2 policy-binding tests ask a request for.</summary>
    private const string RequestedPolicyOid = "1.3.6.1.4.1.99999.7.1";

    /// <summary>The id-data content type (RFC 5652 §4), used as a stand-in for a NON-<c>id-ct-TSTInfo</c> eContentType.</summary>
    private const string IdDataContentTypeOid = "1.2.840.113549.1.7.1";


    /// <summary>
    /// D3 (RFC 3161 §2.4.2): a CMS <c>SignedData</c> whose signature verifies but whose <c>eContentType</c> is
    /// not <c>id-ct-TSTInfo</c> is not a time-stamp token. Reading its encapsulated content as a <c>TSTInfo</c>
    /// because the signature verified would trust arbitrary bytes; the reader refuses (not <c>Read</c>).
    /// </summary>
    [TestMethod]
    public async Task RejectsATokenWhoseEContentTypeIsNotTstInfo()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 signer = CmsSignedDataTestFactory.MintSelfSignedCertificate(
            key, TestClock.CanonicalEpoch, TestClock.CanonicalEpoch.AddYears(1));

        //A genuinely-signed SignedData whose encapsulated content type is id-data, not id-ct-TSTInfo, with the
        //signer certificate embedded so the default CMS backend verifies its signature.
        var contentInfo = new ContentInfo(new Oid(IdDataContentTypeOid), Encoding.UTF8.GetBytes("not a TSTInfo"));
        var signedCms = new SignedCms(contentInfo, detached: false);
        signedCms.ComputeSignature(new CmsSigner(signer) { IncludeOption = X509IncludeOption.EndCertOnly });
        byte[] der = signedCms.Encode();

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);
        using var carrier = new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(info.IsRead,
            "A SignedData whose eContentType is not id-ct-TSTInfo must not read as a TSTInfo.");
        Assert.AreEqual(TimestampTokenInfoStatus.TokenNotVerified, info.Status,
            "A non-TSTInfo eContentType must yield TokenNotVerified, not a parsed TSTInfo.");
    }


    /// <summary>
    /// D2 (RFC 3161 §2.4.2 / EN 319 422 clause 4.1.2): a request that names a <c>reqPolicy</c>, answered by a
    /// conforming authority that issues under it, is accepted — and the acquired token states that same policy.
    /// Proves both halves: the responder honours the requested policy, and the client binds the response to it.
    /// </summary>
    [TestMethod]
    public async Task AcquireAsyncAcceptsATokenWhosePolicyMatchesTheRequestedPolicy()
    {
        using TsaScenario scenario = BuildScenario();
        byte[] timestampedOctets = Encoding.UTF8.GetBytes("timestamp acquisition policy match fixture");
        using DigestValue digest = await ComputeSha256Async(timestampedOctets, TestContext.CancellationToken).ConfigureAwait(false);

        //A responder with no override honours the request's reqPolicy.
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], TestClock.CanonicalEpoch);

        using AcquiredTimestampToken acquired = await TimestampAcquisition.AcquireAsync(
            digest, "https://tsa.example.test/", responder.FetchAsync, BaseMemoryPool.Shared,
            reqPolicyOid: RequestedPolicyOid, includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(RequestedPolicyOid, acquired.Info.PolicyOid,
            "The acquired token must state the policy the request asked for.");
    }


    /// <summary>
    /// D2 exploit regression (RFC 3161 §2.4.2 / EN 319 422 clause 4.1.2): a Time-Stamping Authority that issues
    /// under a policy other than the one the request asked for must be refused, not accepted. Before the fix the
    /// requested policy was written to the request but never checked against the token's <c>policy</c>, so a
    /// mismatched policy passed silently (fail-open).
    /// </summary>
    [TestMethod]
    public async Task AcquireAsyncRefusesATokenWhosePolicyDiffersFromTheRequestedPolicy()
    {
        using TsaScenario scenario = BuildScenario();
        byte[] timestampedOctets = Encoding.UTF8.GetBytes("timestamp acquisition policy mismatch fixture");
        using DigestValue digest = await ComputeSha256Async(timestampedOctets, TestContext.CancellationToken).ConfigureAwait(false);

        //A non-conforming responder that ignores reqPolicy and issues under a different policy.
        var responder = new MintingTimestampResponder(
            scenario.Authority, [scenario.Authority], TestClock.CanonicalEpoch, policyOverride: "1.3.6.1.4.1.99999.7.2");

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await TimestampAcquisition.AcquireAsync(
                digest, "https://tsa.example.test/", responder.FetchAsync, BaseMemoryPool.Shared,
                reqPolicyOid: RequestedPolicyOid, includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false),
            "A token issued under a policy other than the requested one must fail closed.").ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.PolicyMismatch, exception.FailureKind);
    }


    /// <summary>
    /// D5 (RFC 3161 §2.4.2): a granted response that nonetheless carries a <c>PKIFailureInfo</c> with a set bit
    /// is self-contradictory and must be refused, not silently accepted with the failure bit discarded.
    /// </summary>
    [TestMethod]
    public async Task RejectsAGrantedResponseCarryingAFailInfoWithSetBits()
    {
        using TsaScenario scenario = BuildScenario();
        byte[] timestampedOctets = Encoding.UTF8.GetBytes("timestamp acquisition failinfo fixture");
        using DigestValue digest = await ComputeSha256Async(timestampedOctets, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            scenario.Authority, [scenario.Authority], timestampedOctets, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = WriteTimeStampRespWithFailInfo(PkiStatusGranted, token.AsReadOnlySpan());

        TimestampAcquisitionException exception = await Assert.ThrowsExactlyAsync<TimestampAcquisitionException>(
            async () => await TimestampAcquisition.VerifyResponseAsync(
                response, digest,requestNonce: null, requestedPolicyOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A granted response carrying a set PKIFailureInfo bit must fail closed.").ConfigureAwait(false);

        Assert.AreEqual(TimestampAcquisitionFailureKind.ResponseMalformed, exception.FailureKind);
    }


    /// <summary>
    /// Assembles a granted <c>TimeStampResp</c> whose <c>PKIStatusInfo</c> carries a <c>failInfo</c> BIT STRING
    /// with the <c>badAlg</c> bit (bit 0) set — a contradictory response an independent writer produces so the
    /// reader's failInfo interpretation is exercised against real octets.
    /// </summary>
    private static PkiCertificateMemory WriteTimeStampRespWithFailInfo(int pkiStatus, ReadOnlySpan<byte> tokenDer)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence()) //PKIStatusInfo — status plus a failInfo BIT STRING (statusString omitted).
            {
                writer.WriteInteger(pkiStatus);
                writer.WriteBitString([0x80], unusedBitCount: 7); //bit 0 set (badAlg).
            }

            writer.WriteEncodedValue(tokenDer);
        }

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(encodedLength);
        _ = writer.TryEncode(owner.Memory.Span, out _);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampResponse);
    }


    /// <summary>Computes a SHA-256 digest through the registered seam over caller-supplied octets, returned as the tagged carrier the acquisition surfaces consume directly — never flattened to naked bytes.</summary>
    private static ValueTask<DigestValue> ComputeSha256Async(ReadOnlyMemory<byte> content, CancellationToken cancellationToken) =>
        CryptographicKeyEvents.ComputeDigestAsync(
            content, PkiDigestAlgorithm.Sha256.OutputByteLength, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: cancellationToken);


    /// <summary>
    /// Assembles a <c>TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }</c>
    /// (RFC 3161 §2.4.2) around a minted token — an independent writer from the reader
    /// <see cref="TimestampAcquisition"/> exercises, so a wrapping bug here could not mask a defect in that reader.
    /// </summary>
    private static PkiCertificateMemory WriteTimeStampResp(int pkiStatus, ReadOnlySpan<byte> tokenDer, bool includeToken = true)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence()) //PKIStatusInfo — status only; statusString/failInfo omitted.
            {
                writer.WriteInteger(pkiStatus);
            }

            if(includeToken)
            {
                writer.WriteEncodedValue(tokenDer);
            }
        }

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(encodedLength);
        _ = writer.TryEncode(owner.Memory.Span, out _);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampResponse);
    }


    /// <summary>Builds a Root CA and a Time-Stamping Authority certificate anchored to <see cref="TestClock.CanonicalEpoch"/>.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of both nodes transfers to the returned TsaScenario, which the caller disposes; the catch disposes the root on a partial failure.")]
    private static TsaScenario BuildScenario()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
        try
        {
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider);

            return new TsaScenario(root, authority);
        }
        catch
        {
            root.Dispose();
            throw;
        }
    }


    /// <summary>The minted Root CA and Time-Stamping Authority nodes for a scenario, disposed together.</summary>
    private sealed record TsaScenario(X509ChainTestRingNode Root, X509ChainTestRingNode Authority): IDisposable
    {
        /// <inheritdoc/>
        public void Dispose()
        {
            Authority.Dispose();
            Root.Dispose();
        }
    }
}


/// <summary>
/// A <see cref="FetchTimestampResponseAsyncDelegate"/> test double returning one fixed, pre-built response
/// regardless of the request — a configured object holding its data explicitly, rather than a lambda capturing
/// per-test state, per the codebase's no-closure-capture convention for callback seams (mirroring
/// <c>MapBackedOcspResponder</c>). A <see langword="null"/> response simulates an unreachable authority.
/// </summary>
internal sealed class FixedTimestampResponder: IDisposable
{
    /// <summary>The prepared response, or <see langword="null"/> to simulate an unreachable authority.</summary>
    private PkiCertificateMemory? Response { get; }


    /// <summary>Initializes a new <see cref="FixedTimestampResponder"/>. Ownership of a non-<see langword="null"/> response transfers to this instance.</summary>
    /// <param name="response">The response every call returns a fresh pooled clone of, or <see langword="null"/>.</param>
    internal FixedTimestampResponder(PkiCertificateMemory? response)
    {
        Response = response;
    }


    /// <summary>Implements <see cref="FetchTimestampResponseAsyncDelegate"/>: returns a fresh pooled clone of the configured response, or <see langword="null"/>.</summary>
    /// <param name="context">The fetch context; unused, as this test double answers regardless of the request.</param>
    /// <param name="pool">The memory pool the returned clone is rented from.</param>
    /// <param name="cancellationToken">A cancellation token; unused, as this test double performs no I/O.</param>
    /// <returns>The cloned response, or <see langword="null"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the cloned carrier transfers to the caller via the returned ValueTask.")]
    internal ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        if(Response is null)
        {
            return ValueTask.FromResult<PkiCertificateMemory?>(null);
        }

        IMemoryOwner<byte> owner = pool.Rent(Response.Length);
        Response.AsReadOnlySpan().CopyTo(owner.Memory.Span);

        return ValueTask.FromResult<PkiCertificateMemory?>(new PkiCertificateMemory(owner, PkiCertificateTags.TimestampResponse));
    }


    /// <inheritdoc/>
    public void Dispose() => Response?.Dispose();
}
