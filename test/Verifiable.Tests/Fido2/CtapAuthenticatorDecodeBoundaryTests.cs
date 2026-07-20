using System;
using System.Buffers;
using System.Formats.Cbor;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Contract R7's decode-boundary precision matrix: every one of the seven body-carrying CTAP2 command
/// boundaries (<c>authenticatorMakeCredential</c>, <c>authenticatorGetAssertion</c>,
/// <c>authenticatorClientPIN</c>, <c>authenticatorBioEnrollment</c>, <c>authenticatorLargeBlobs</c>,
/// <c>authenticatorConfig</c>, <c>authenticatorCredentialManagement</c>) maps a decode failure to the
/// classified status byte — <see cref="WellKnownCtapStatusCodes.InvalidCbor"/> for genuinely
/// non-conformant CBOR, <see cref="WellKnownCtapStatusCodes.CborUnexpectedType"/> for a well-formed
/// request whose nested structure is wrong, and <see cref="WellKnownCtapStatusCodes.MissingParameter"/>
/// for a Required top-level member's absence — rather than letting a <see cref="Fido2FormatException"/>
/// escape <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> as an unhandled .NET exception (trap
/// 11). Also closes TORN rows 8750 (tagged CBOR rejection) and 8760 (a ≥1024-byte CTAP message over the
/// real wire).
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorDecodeBoundaryTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A CBOR map header declaring 2 entries followed by only one key byte and no value at all —
    /// truncated mid-structure, so the buffer runs out before the declared shape can be satisfied. The
    /// BCL's <see cref="System.Formats.Cbor.CborReader"/> raises <see cref="CborContentException"/> for
    /// this shape (verified directly against the shipped <c>System.Formats.Cbor</c> package: "Declared
    /// definite length of CBOR data item exceeds available buffer size"), the exact failure class R7
    /// classifies <see cref="Fido2FormatFailureKind.MalformedCbor"/> — reused verbatim from
    /// <see cref="CtapLargeBlobsRequestCborReaderTests.ThrowsOnMalformedCbor"/>'s own vector, since every
    /// command reader's decode boundary shares this exact syntax-level failure mode.
    /// </summary>
    private static byte[] TruncatedMapBytes => [0xA2, 0x03];


    /// <summary>Builds a complete CTAP2 request envelope: <paramref name="command"/> followed by <paramref name="parametersCbor"/>.</summary>
    private static byte[] BuildEnvelope(byte command, ReadOnlySpan<byte> parametersCbor)
    {
        byte[] envelope = new byte[parametersCbor.Length + 1];
        envelope[0] = command;
        parametersCbor.CopyTo(envelope.AsSpan(1));

        return envelope;
    }


    /// <summary>Builds a genuinely empty CBOR map (<c>{}</c>) — the shared "subCommand absent" shape the config/credMgmt fence tests also use.</summary>
    private static byte[] BuildEmptyMap()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(0);
        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>Malformed CBOR at the <c>authenticatorMakeCredential</c> boundary returns <c>InvalidCbor</c> (0x12), never an uncaught exception.</summary>
    [TestMethod]
    public async Task MakeCredentialMalformedCborReturnsInvalidCbor()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-mc-malformed");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.MakeCredential, TruncatedMapBytes), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCbor, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Malformed CBOR at the <c>authenticatorGetAssertion</c> boundary returns <c>InvalidCbor</c> (0x12), never an uncaught exception.</summary>
    [TestMethod]
    public async Task GetAssertionMalformedCborReturnsInvalidCbor()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-ga-malformed");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.GetAssertion, TruncatedMapBytes), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCbor, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Malformed CBOR at the <c>authenticatorClientPIN</c> boundary returns <c>InvalidCbor</c> (0x12) — the "uncaught twin" session-17's queue note named (this command had no try/catch at all before this wave).</summary>
    [TestMethod]
    public async Task ClientPinMalformedCborReturnsInvalidCbor()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-clientpin-malformed");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.ClientPin, TruncatedMapBytes), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCbor, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Malformed CBOR at the <c>authenticatorBioEnrollment</c> boundary returns <c>InvalidCbor</c> (0x12), never an uncaught exception.</summary>
    [TestMethod]
    public async Task BioEnrollmentMalformedCborReturnsInvalidCbor()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-bio-malformed");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.BioEnrollment, TruncatedMapBytes), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCbor, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Malformed CBOR at the <c>authenticatorLargeBlobs</c> boundary returns <c>InvalidCbor</c> (0x12), never an uncaught exception.</summary>
    [TestMethod]
    public async Task LargeBlobsMalformedCborReturnsInvalidCbor()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-lb-malformed");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.LargeBlobs, TruncatedMapBytes), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCbor, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// Malformed CBOR at the <c>authenticatorConfig</c> boundary returns <c>InvalidCbor</c> (0x12), no
    /// longer the imprecise <c>MissingParameter</c> a single undiscriminating catch used to return for
    /// every decode failure — <see cref="CtapAuthenticatorConfigTests.SubCommandAbsentReturnsMissingParameter"/>
    /// (the genuinely empty-map sub-case, snapshot line 7953's own MUST) is unaffected and stays
    /// byte-unchanged.
    /// </summary>
    [TestMethod]
    public async Task AuthenticatorConfigMalformedCborReturnsInvalidCbor()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-config-malformed");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.AuthenticatorConfig, TruncatedMapBytes), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCbor, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// Malformed CBOR at the <c>authenticatorCredentialManagement</c> boundary returns <c>InvalidCbor</c>
    /// (0x12) — <see cref="CtapAuthenticatorCredentialManagementTests.SubCommandAbsentReturnsMissingParameter"/>
    /// (the genuinely empty-map sub-case) is unaffected and stays byte-unchanged.
    /// </summary>
    [TestMethod]
    public async Task CredentialManagementMalformedCborReturnsInvalidCbor()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-credmgmt-malformed");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.CredentialManagement, TruncatedMapBytes), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCbor, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A well-formed request map omitting the Required top-level <c>clientDataHash</c> (0x01) member returns <c>MissingParameter</c> (0x14).</summary>
    [TestMethod]
    public async Task MakeCredentialClientDataHashAbsentReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-mc-clientdatahash-absent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.Rp);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        writer.WriteTextString("rp.co");
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.User);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        writer.WriteByteString([0x01]);
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.MakeCredential, writer.Encode()), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A well-formed request map omitting the Required top-level <c>rpId</c> (0x01) member returns <c>MissingParameter</c> (0x14).</summary>
    [TestMethod]
    public async Task GetAssertionRpIdAbsentReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-ga-rpid-absent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapGetAssertionRequestKeys.ClientDataHash);
        writer.WriteByteString(CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x30));
        writer.WriteEndMap();

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.GetAssertion, writer.Encode()), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A genuinely empty <c>authenticatorClientPIN</c> request map omits the Required top-level
    /// <c>subCommand</c> (0x02) member and returns <c>MissingParameter</c> (0x14) — the "uncaught twin"
    /// session-17's queue note named: this command had no try/catch around its decode call at all
    /// before this wave, so this exact shape previously escaped <c>TransceiveAsync</c> as an unhandled
    /// <see cref="Fido2FormatException"/>.
    /// </summary>
    [TestMethod]
    public async Task ClientPinSubCommandAbsentReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-clientpin-subcommand-absent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.ClientPin, BuildEmptyMap()), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A well-formed <c>authenticatorMakeCredential</c> request whose <c>rp</c> entity omits its own
    /// required <c>id</c> member returns <c>CborUnexpectedType</c> (0x11) — the nested-structure half of
    /// R7's classification (8777-8783), distinct from a top-level Required member's own absence (0x14)
    /// and from a genuinely non-conformant encoding (0x12).
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialRpEntityWithoutIdReturnsCborUnexpectedType()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-mc-rp-without-id");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(4);
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.ClientDataHash);
        writer.WriteByteString(CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x31));
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.Rp);
        writer.WriteStartMap(1);
        writer.WriteTextString("name");
        writer.WriteTextString("Example RP with no id");
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.User);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        writer.WriteByteString([0x02]);
        writer.WriteEndMap();
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.MakeCredential, writer.Encode()), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.CborUnexpectedType, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// TORN row 8750: a tagged CBOR item (RFC 8949 §3.4, tag 0 — an <c>0xC0</c> prefix) inside an
    /// <c>authenticatorMakeCredential</c> parameter map is rejected by the reader as a typed
    /// <see cref="Fido2FormatException"/> (the write-side half is already structurally proven — no CTAP
    /// writer ever calls a tag-writing API), and, via R7, the SAME bytes driven through
    /// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> return <c>InvalidCbor</c> (0x12) — tags
    /// are forbidden by CTAP 2.3 snapshot line 8750, and <see cref="CborConformanceMode.Ctap2Canonical"/>
    /// surfaces that as a <see cref="CborContentException"/>, R7's <see cref="Fido2FormatFailureKind.MalformedCbor"/>
    /// bucket.
    /// </summary>
    [TestMethod]
    public async Task TaggedCborIsRejectedByTheReaderAndAsInvalidCborAtTheBoundary()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapMakeCredentialRequestKeys.ClientDataHash);
        writer.WriteTag((CborTag)0);
        writer.WriteTextString("2013-03-21T20:04:00Z");
        writer.WriteEndMap();
        byte[] taggedParametersCbor = writer.Encode();

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapMakeCredentialRequestCborReader.Read(taggedParametersCbor, BaseMemoryPool.Shared));

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-mc-tagged");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await simulator.TransceiveAsync(
            BuildEnvelope(WellKnownCtapCommands.MakeCredential, taggedParametersCbor), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCbor, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// At least one malformed-CBOR case driven over the REAL APDU wire (not merely in-process): the same
    /// truncated-map bytes an in-process boundary test uses, carried by
    /// <c>authenticatorGetAssertion</c>'s command byte over <see cref="CtapWave2TransportHarness"/>,
    /// still returns <c>InvalidCbor</c> (0x12) after a genuine <c>SELECT</c> and NFC/APDU round trip.
    /// </summary>
    [TestMethod]
    public async Task MalformedCborOverRealApduTransportReturnsInvalidCbor()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-realwire-malformed");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken);

        using PooledMemory response = await harness.Transceive(
            BuildEnvelope(WellKnownCtapCommands.GetAssertion, TruncatedMapBytes), pool, cancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCbor, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// TORN row 8760: "By default, authenticators MUST support messages of at least 1024 bytes"
    /// (snapshot line 8760). A single <c>authenticatorMakeCredential</c> request whose <c>excludeList</c>
    /// carries exactly 8 credential descriptors — <see cref="CtapAuthenticatorState.MaxCredentialCountInListCapacity"/>,
    /// never above it (R5's <c>LimitExceeded</c> enforcement caps <c>excludeList</c> at that count) —
    /// each with a 128-byte credential ID (legal: <c>AuthenticatorDataWriter</c>'s own credential-ID
    /// ceiling is 1023 bytes) pushes the TOTAL encoded CTAP message (command byte + CBOR parameters,
    /// measured directly from the writer's own output, not a per-fragment size) past 1024 bytes; driven
    /// end to end over <see cref="CtapWave2TransportHarness"/>'s real, unmodified APDU transport, the
    /// request succeeds (a fresh, non-excluded credential mints normally).
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialWithAtLeast1024ByteTotalMessageSucceedsOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("waveclose-boundary-1024-realwire");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken);

        var excludeList = new System.Collections.Generic.List<PublicKeyCredentialDescriptor>();
        for(int i = 0; i < CtapAuthenticatorState.MaxCredentialCountInListCapacity; i++)
        {
            excludeList.Add(new PublicKeyCredentialDescriptor
            {
                Type = WellKnownPublicKeyCredentialTypes.PublicKey,
                Id = CredentialId.Create(CtapWave2AuthenticatorFixtures.BuildFixedBytes(128, (byte)i), pool)
            });
        }

        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, excludeList: excludeList);

        TaggedMemory<byte> encodedParameters = CtapMakeCredentialRequestCborWriter.Write(request);
        Assert.IsGreaterThanOrEqualTo(1024, encodedParameters.Length + 1, "the TOTAL CTAP message (command byte + parameters) must reach the 1024-byte floor, not merely a fragment.");

        byte[] envelope = BuildEnvelope(WellKnownCtapCommands.MakeCredential, encodedParameters.Span);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);

        using PooledMemory response = await harness.Transceive(envelope, pool, cancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }
}
