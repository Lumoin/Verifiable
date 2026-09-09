using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
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
/// Conformance tests for <see cref="PAdESDocTimeStampCreation"/> and <see
/// cref="PAdESDocTimeStampValidation"/>: the Document Time-stamp of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 5.4.3, composing the SHIPPED RFC 3161 acquisition client — an
/// in-process genuine-token round trip, a REAL loopback-HTTP wire round trip, the shared shadow-attack coverage
/// gate, tamper negatives, and metered custody.
/// </summary>
[TestClass]
internal sealed class PAdESDocTimeStampTests
{
    /// <summary>The address handed to the in-process TSA transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.doctimestamp.example.test/";

    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampReq</c>.</summary>
    private const string TimestampQueryContentType = "application/timestamp-query";

    /// <summary>The <c>Content-Type</c> RFC 3161 §3.4 gives a <c>TimeStampResp</c>.</summary>
    private const string TimestampReplyContentType = "application/timestamp-reply";

    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    private static DateTimeOffset GenerationTime { get; } = TestClock.CanonicalEpoch.AddHours(1);


    public required TestContext TestContext { get; set; }


    /// <summary>PA-5.4.3-01/-02/-03/-04/-05/-06/-07/-08/-09: creates a Document Time-stamp over an in-process, genuine RFC 3161 token, and validates it back.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-5.4.3-M1, PA-5.4.3-10, PA-5.4.3-11, PA-6.3-T25, PA-6.3-n, PA-6.3-y.
    /// </remarks>
    [TestMethod]
    public async Task CreatesAndValidatesARoundTripDocTimeStamp()
    {
        using DocTimeStampScenario scenario = DocTimeStampScenario.Create();
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority, scenario.Root], GenerationTime);

        PAdESDocTimeStampResult result = await PAdESDocTimeStampCreation.CreateAsync(
            scenario.BuildRequest(responder.FetchAsync), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PAdESDocTimeStampCollectionResult validation = await PAdESDocTimeStampValidation.ValidateAsync(
            result.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.HasCount(1, validation.DocTimeStamps!);
        PAdESDocTimeStampValidationResult docTimeStamp = validation.DocTimeStamps![0];
        Assert.IsTrue(docTimeStamp.IsValid, $"Expected Valid, was {docTimeStamp.Status}.");
        Assert.AreEqual(GenerationTime, docTimeStamp.GenerationTime);
        Assert.IsTrue(docTimeStamp.CoversDocumentEnd);
    }


    /// <summary>
    /// The real-wire leg: the DocTimeStamp's own <c>TimeStampReq</c>/<c>TimeStampResp</c> cross a genuine loopback
    /// HTTPS socket to an independent BouncyCastle-backed TSP oracle (<see cref="MintingTimestampResponder"/>),
    /// mirroring <c>CAdESMultiServerWireFlowTests</c>'s own Host A pattern.
    /// </summary>
    [TestMethod]
    public async Task RealLoopbackHttpTsaRoundTripProducesAValidDocTimeStamp()
    {
        using DocTimeStampScenario scenario = DocTimeStampScenario.Create();
        var tsaResponder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority, scenario.Root], GenerationTime);

        await using BinaryHttpHost tsaHost = await BinaryHttpHost.StartAsync(
            new BinaryTsaHostAdapter(tsaResponder.FetchAsync).HandleAsync, TestContext.CancellationToken).ConfigureAwait(false);
        string tsaUri = new Uri(tsaHost.BaseAddress, "/tsa").AbsoluteUri;
        using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(tsaHost.Certificate);
        var wireTsa = new WireTimestampTransport(httpClient);

        PAdESDocTimeStampResult result = await PAdESDocTimeStampCreation.CreateAsync(
            scenario.BuildRequest(wireTsa.FetchAsync) with { TsaUri = tsaUri },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PAdESDocTimeStampCollectionResult validation = await PAdESDocTimeStampValidation.ValidateAsync(
            result.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        PAdESDocTimeStampValidationResult docTimeStamp = validation.DocTimeStamps![0];
        Assert.IsTrue(docTimeStamp.IsValid, $"Expected Valid over a real loopback-HTTP TSA round trip, was {docTimeStamp.Status}.");
        Assert.AreEqual(GenerationTime, docTimeStamp.GenerationTime,
            "The token's own genTime, read back after crossing a real socket, must equal what the independent TSP oracle minted.");
    }


    /// <summary>
    /// PA-5.4.3-07, the same shadow-attack coverage gate PA-6.3-k states for an ordinary signature: content
    /// appended after the newest Document Time-stamp's own <c>ByteRange</c> coverage is rejected, never silently
    /// accepted as a benign trailing update.
    /// </summary>
    [TestMethod]
    public async Task ContentAppendedAfterTheDocTimeStampsByteRangeCoverageIsRejected()
    {
        using DocTimeStampScenario scenario = DocTimeStampScenario.Create();
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority, scenario.Root], GenerationTime);

        PAdESDocTimeStampResult result = await PAdESDocTimeStampCreation.CreateAsync(
            scenario.BuildRequest(responder.FetchAsync), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] shadowed = PdfFixtureBuilder.AppendUnsignedIncrementalUpdate(result.Bytes, result.XrefOffset);

        using PAdESDocTimeStampCollectionResult validation = await PAdESDocTimeStampValidation.ValidateAsync(
            shadowed, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.AreEqual(PAdESDocTimeStampStatus.IncompleteByteRangeCoverage, validation.DocTimeStamps![0].Status);
        Assert.IsFalse(validation.DocTimeStamps[0].CoversDocumentEnd);
    }


    /// <summary>A single flipped hex digit inside the real <c>TimeStampToken</c> bytes must not still validate.</summary>
    [TestMethod]
    public async Task TamperingWithTheTimeStampTokenContentsIsDetected()
    {
        using DocTimeStampScenario scenario = DocTimeStampScenario.Create();
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority, scenario.Root], GenerationTime);

        PAdESDocTimeStampResult result = await PAdESDocTimeStampCreation.CreateAsync(
            scenario.BuildRequest(responder.FetchAsync), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tampered = (byte[])result.Bytes.Clone();
        string text = Encoding.ASCII.GetString(tampered);
        int contentsStart = text.IndexOf("/Contents <", StringComparison.Ordinal) + "/Contents <".Length;
        tampered[contentsStart + 20] = tampered[contentsStart + 20] == (byte)'0' ? (byte)'1' : (byte)'0';

        using PAdESDocTimeStampCollectionResult validation = await PAdESDocTimeStampValidation.ValidateAsync(
            tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.IsFalse(validation.DocTimeStamps![0].IsValid, "A single flipped Contents hex digit must not still validate.");
    }


    /// <summary>
    /// A document that carries no {<c>ByteRange</c>, <c>Contents</c>}-shaped object at all is a well-formed,
    /// successful "no Document Time-stamp" outcome — an empty collection, not a failure.
    /// </summary>
    [TestMethod]
    public async Task ADocumentWithNoDocTimeStampIsALegitimateEmptySuccess()
    {
        (byte[] document, _) = DocTimeStampScenario.BuildUnsignedBasePdf();

        using PAdESDocTimeStampCollectionResult validation = await PAdESDocTimeStampValidation.ValidateAsync(
            document, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        Assert.IsEmpty(validation.DocTimeStamps!);
    }


    [TestMethod]
    public async Task CreationAndValidationAreMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();
        using DocTimeStampScenario scenario = DocTimeStampScenario.Create();
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority, scenario.Root], GenerationTime);

        PAdESDocTimeStampResult result = await PAdESDocTimeStampCreation.CreateAsync(
            scenario.BuildRequest(responder.FetchAsync), metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(PAdESDocTimeStampCollectionResult validation = await PAdESDocTimeStampValidation.ValidateAsync(
            result.Bytes, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
            Assert.IsTrue(validation.DocTimeStamps![0].IsValid);
        }

        Assert.AreEqual(metered.RentedCount, metered.ReturnedCount, "Every carrier rented across creation and validation must be returned once every owning result is disposed.");
        Assert.AreEqual(0, metered.OutstandingCount);
    }


    /// <summary>Bridges a <see cref="BinaryHttpHost"/> to a <see cref="FetchTimestampResponseAsyncDelegate"/>-shaped responder — the server side of the real-wire leg.</summary>
    private sealed class BinaryTsaHostAdapter
    {
        private FetchTimestampResponseAsyncDelegate Responder { get; }


        internal BinaryTsaHostAdapter(FetchTimestampResponseAsyncDelegate responder)
        {
            this.Responder = responder;
        }


        internal async Task<BinaryHttpResponse> HandleAsync(BinaryHttpRequest request, CancellationToken cancellationToken)
        {
            using PkiCertificateMemory requestCarrier = ToCarrier(request.Body, PkiCertificateTags.TimestampRequest);
            PkiCertificateMemory? response = await Responder(
                new TimestampFetchContext { TsaUri = request.Path, Request = requestCarrier },
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            if(response is null)
            {
                return new BinaryHttpResponse { StatusCode = 502 };
            }

            using(response)
            {
                return new BinaryHttpResponse
                {
                    StatusCode = 200,
                    ContentType = TimestampReplyContentType,
                    Body = response.AsReadOnlySpan().ToArray()
                };
            }
        }
    }


    /// <summary>The client-side RFC 3161 §3.4 HTTP binding over a real <see cref="HttpClient"/> POST — the client side of the real-wire leg.</summary>
    private sealed class WireTimestampTransport
    {
        private HttpClient WireClient { get; }


        internal WireTimestampTransport(HttpClient httpClient)
        {
            this.WireClient = httpClient;
        }


        internal async ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            using var content = new ByteArrayContent(context.Request.AsReadOnlySpan().ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(TimestampQueryContentType);

            HttpResponseMessage httpResponse;
            try
            {
                httpResponse = await WireClient.PostAsync(new Uri(context.TsaUri), content, cancellationToken).ConfigureAwait(false);
            }
            catch(HttpRequestException)
            {
                return null;
            }

            using(httpResponse)
            {
                if(!httpResponse.IsSuccessStatusCode)
                {
                    return null;
                }

                byte[] bytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
                bytes.CopyTo(owner.Memory.Span);

                return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampResponse);
            }
        }
    }


    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>Mints the Time-Stamping Authority identity and the unsigned base PDF one <see cref="PAdESDocTimeStampRequest"/> is built against.</summary>
    private sealed class DocTimeStampScenario: IDisposable
    {
        internal required X509ChainTestRingNode Root { get; init; }

        internal required X509ChainTestRingNode Authority { get; init; }

        internal required byte[] UnsignedDocument { get; init; }

        internal required PdfIncrementalUpdateAnchor Anchor { get; init; }


        internal static DocTimeStampScenario Create()
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            (byte[] document, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();

            return new DocTimeStampScenario
            {
                Root = root,
                Authority = authority,
                UnsignedDocument = document,
                Anchor = anchor
            };
        }


        internal PAdESDocTimeStampRequest BuildRequest(FetchTimestampResponseAsyncDelegate fetchResponse) => new()
        {
            PriorDocument = UnsignedDocument,
            Anchor = Anchor,
            ContentsCapacityBytes = 8192,
            MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
            TsaUri = TsaUri,
            FetchResponse = fetchResponse
        };


        internal static (byte[] Bytes, PdfIncrementalUpdateAnchor Anchor) BuildUnsignedBasePdf()
        {
            var writer = new List<byte>();
            void Ascii(string s) => writer.AddRange(Encoding.ASCII.GetBytes(s));

            Ascii("%PDF-1.7\n");
            int obj1Offset = writer.Count;
            Ascii("1 0 obj\n<< /Type /Catalog >>\nendobj\n");
            int xrefOffset = writer.Count;
            Ascii("xref\n0 2\n");
            Ascii("0000000000 65535 f \n");
            Ascii($"{obj1Offset:D10} 00000 n \n");
            Ascii("trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n");
            Ascii(xrefOffset.ToString(CultureInfo.InvariantCulture));
            Ascii("\n%%EOF\n");

            byte[] bytes = [.. writer];
            var anchor = new PdfIncrementalUpdateAnchor
            {
                PriorXrefOffset = xrefOffset,
                PriorObjectCount = 2,
                RootObjectNumber = 1,
                RootGeneration = 0
            };

            return (bytes, anchor);
        }


        public void Dispose()
        {
            Authority.Dispose();
            Root.Dispose();
        }
    }
}
