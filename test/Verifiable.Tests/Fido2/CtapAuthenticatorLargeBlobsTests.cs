using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wave unit-test matrix for <c>authenticatorLargeBlobs</c> (<c>0x0C</c>): the three shared shape
/// checks and their spec-mandated order (R6), the <c>get</c> algorithm's complete behavior including the
/// zero-length-substring success boundary (PKG-A), and the complete <c>set</c> write machine — the R5
/// conditional token gate, every R6 error path in spec order, the volatile state machine's three discard
/// disciplines, the lbw carve-out E2E proof, and the per-fragment verify-message byte-exact KAT (PKG-B).
/// Driven in-process through <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/> (real-wire
/// capstones are a later package).
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorLargeBlobsTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A fresh authenticator's <c>get</c> at <c>offset</c> 0 requesting the full 17 bytes returns the
    /// byte-exact initial serialized large-blob array (trap 9): the state seed already carries it, so
    /// <c>get</c> is genuinely served with no write ever having occurred.
    /// </summary>
    [TestMethod]
    public async Task FreshStateGetReturnsInitialSeventeenByteConstant()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-fresh-get");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: 17, Offset: 0);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapLargeBlobsResponse decoded = CtapLargeBlobsResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        CollectionAssert.AreEqual(CtapAuthenticatorState.InitialSerializedLargeBlobArray.ToArray(), decoded.Config.ToArray());
    }


    /// <summary>
    /// Requesting MORE bytes than are stored returns the maximum number available — a SHORT READ, not an
    /// error (line 7607's SHOULD): a fresh device's 17-byte array satisfies a <c>get</c> of 960 with only
    /// 17 bytes.
    /// </summary>
    [TestMethod]
    public async Task GetRequestingMoreThanStoredReturnsShortRead()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-short-read");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: CtapAuthenticatorState.MaxFragmentLength, Offset: 0);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapLargeBlobsResponse decoded = CtapLargeBlobsResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(CtapAuthenticatorState.InitialSerializedLargeBlobArray.Length, decoded.Config.Length);
    }


    /// <summary>
    /// <c>get</c> with <c>Get</c> value zero is a legal request for zero bytes — distinct from an ABSENT
    /// <c>get</c> member — and succeeds with an empty <c>config</c>.
    /// </summary>
    [TestMethod]
    public async Task GetZeroBytesReturnsEmptySuccess()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-get-zero");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: 0, Offset: 0);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapLargeBlobsResponse decoded = CtapLargeBlobsResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(0, decoded.Config.Length);
    }


    /// <summary>
    /// <c>offset</c> EQUAL to the stored array's length succeeds with a ZERO-LENGTH substring (line
    /// 7607's explicit note, trap 8) — the off-by-one boundary a naive "offset &gt;= length" check would
    /// miss.
    /// </summary>
    [TestMethod]
    public async Task GetAtOffsetEqualToStoredLengthReturnsEmptySuccess()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-offset-equals-length");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: 10, Offset: CtapAuthenticatorState.InitialSerializedLargeBlobArray.Length);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapLargeBlobsResponse decoded = CtapLargeBlobsResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(0, decoded.Config.Length);
    }


    /// <summary><c>offset</c> STRICTLY GREATER than the stored array's length is the only <c>get</c>-side offset error (line 7605).</summary>
    [TestMethod]
    public async Task GetOffsetPastStoredLengthReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-offset-past-length");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: 10, Offset: CtapAuthenticatorState.InitialSerializedLargeBlobArray.Length + 1);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>get</c>'s value exceeding <see cref="CtapAuthenticatorState.MaxFragmentLength"/> (960) returns <c>InvalidLength</c> (line 7603).</summary>
    [TestMethod]
    public async Task GetExceedingMaxFragmentLengthReturnsInvalidLength()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-get-exceeds-fragment");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: CtapAuthenticatorState.MaxFragmentLength + 1, Offset: 0);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidLength, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>get</c> with <c>length</c> also present is rejected (line 7599) — the two are mutually exclusive per the parameter table's own "MUST NOT be present" pair.</summary>
    [TestMethod]
    public async Task GetWithLengthPresentReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-get-with-length");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: 10, Offset: 0, Length: 17);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>get</c> with <c>pinUvAuthParam</c> present is rejected (line 7601, trap 5): reads are
    /// deliberately public, and supplying auth material on a read is an ERROR, not a tolerated no-op.
    /// </summary>
    [TestMethod]
    public async Task GetWithPinUvAuthParamPresentReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-get-with-param");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(2);
        pinUvAuthParamOwner.Memory.Span[0] = 0x01;
        pinUvAuthParamOwner.Memory.Span[1] = 0x02;
        var request = new CtapLargeBlobsRequest(Get: 10, Offset: 0, PinUvAuthParam: pinUvAuthParamOwner.Memory[..2]);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>get</c> with <c>pinUvAuthProtocol</c> present alone (no param) is rejected identically (line 7601's "either of").</summary>
    [TestMethod]
    public async Task GetWithPinUvAuthProtocolPresentReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-get-with-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: 10, Offset: 0, PinUvAuthProtocol: 2);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>offset</c> absent is rejected (line 7590) regardless of which other members are present.</summary>
    [TestMethod]
    public async Task OffsetAbsentReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-offset-absent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: 10);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Neither <c>get</c> nor <c>set</c> present is rejected (line 7592) even with a well-formed <c>offset</c>.</summary>
    [TestMethod]
    public async Task NeitherGetNorSetReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-neither");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Offset: 0);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Both <c>get</c> and <c>set</c> present is rejected (line 7594) even with a well-formed <c>offset</c>.</summary>
    [TestMethod]
    public async Task BothGetAndSetReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-both");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x01;
        var request = new CtapLargeBlobsRequest(Get: 10, Set: setOwner.Memory[..1], Offset: 0);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// R6/trap 6: <c>offset</c>'s absence (line 7590) is checked BEFORE the <c>get</c> branch even
    /// begins — a request with an excessive <c>get</c> value (which would otherwise trigger
    /// <c>InvalidLength</c>) and no <c>offset</c> still returns <c>InvalidParameter</c>, proving the
    /// shared shape check runs first, not the fragment-length check.
    /// </summary>
    [TestMethod]
    public async Task OffsetAbsentCheckFiresBeforeGetBranchChecks()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-order-offset-first");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: CtapAuthenticatorState.MaxFragmentLength + 1);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// R6/trap 7: the "both present" shape check (line 7594) is checked BEFORE the <c>get</c> branch's
    /// own fragment-length check — a request satisfying both an excessive <c>get</c> value AND a
    /// non-null <c>set</c> still returns <c>InvalidParameter</c> (the shared shape check's own code),
    /// never <c>InvalidLength</c> (which would mean the implementation entered the <c>get</c> branch
    /// first).
    /// </summary>
    [TestMethod]
    public async Task BothPresentCheckFiresBeforeGetBranchChecks()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-order-both-first");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x01;
        var request = new CtapLargeBlobsRequest(Get: CtapAuthenticatorState.MaxFragmentLength + 1, Set: setOwner.Memory[..1], Offset: 0);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// R6: within the <c>get</c> branch, the <c>length</c>-present check (line 7599) precedes the
    /// fragment-length check (line 7603) — a request satisfying both returns <c>InvalidParameter</c>,
    /// never <c>InvalidLength</c>.
    /// </summary>
    [TestMethod]
    public async Task GetLengthPresentCheckFiresBeforeFragmentLengthCheck()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-order-length-first");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(Get: CtapAuthenticatorState.MaxFragmentLength + 1, Offset: 0, Length: 17);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// R6: within the <c>get</c> branch, the auth-material-present check (line 7601) precedes the
    /// fragment-length check (line 7603) — a request satisfying both returns <c>InvalidParameter</c>,
    /// never <c>InvalidLength</c>.
    /// </summary>
    [TestMethod]
    public async Task GetAuthMaterialCheckFiresBeforeFragmentLengthCheck()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-order-auth-first");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(1);
        pinUvAuthParamOwner.Memory.Span[0] = 0x01;
        var request = new CtapLargeBlobsRequest(
            Get: CtapAuthenticatorState.MaxFragmentLength + 1, Offset: 0, PinUvAuthParam: pinUvAuthParamOwner.Memory[..1]);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// R6: the fragment-length check (line 7603) precedes the offset-past-stored-length check (line
    /// 7605) — a request satisfying both returns <c>InvalidLength</c>, never <c>InvalidParameter</c>.
    /// </summary>
    [TestMethod]
    public async Task FragmentLengthCheckFiresBeforeOffsetPastLengthCheck()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-order-fragment-first");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapLargeBlobsRequest(
            Get: CtapAuthenticatorState.MaxFragmentLength + 1, Offset: CtapAuthenticatorState.InitialSerializedLargeBlobArray.Length + 100);
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidLength, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>set</c>'s fragment-length check (line 7613) fires before either offset sub-branch: a fragment
    /// longer than <see cref="CtapAuthenticatorState.MaxFragmentLength"/> returns <c>InvalidLength</c>
    /// regardless of <c>offset</c>.
    /// </summary>
    [TestMethod]
    public async Task SetFragmentExceedingMaxFragmentLengthReturnsInvalidLength()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-set-fragment-too-long");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        int oversizedFragmentLength = CtapAuthenticatorState.MaxFragmentLength + 1;
        using IMemoryOwner<byte> setOwner = pool.Rent(oversizedFragmentLength);
        setOwner.Memory.Span[..oversizedFragmentLength].Clear();
        var request = new CtapLargeBlobsRequest(
            Set: setOwner.Memory[..oversizedFragmentLength], Offset: 0, Length: 20);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidLength, status);
    }


    /// <summary><c>offset</c> zero without <c>length</c> is rejected (line 7618) — <c>length</c> is Required precisely when a new sequence starts.</summary>
    [TestMethod]
    public async Task SetOffsetZeroMissingLengthReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-set-offset-zero-no-length");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 0);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, status);
    }


    /// <summary><c>length</c> greater than 1024 AND exceeding <see cref="CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity"/> returns <c>LargeBlobStorageFull</c> (line 7620).</summary>
    [TestMethod]
    public async Task SetOffsetZeroLengthExceedingCapacityReturnsLargeBlobStorageFull()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-set-length-exceeds-capacity");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(
            Set: setOwner.Memory[..1], Offset: 0, Length: CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity + 1);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.LargeBlobStorageFull, status);
    }


    /// <summary><c>length</c> below 17 — the minimum a serialized large-blob array can ever be (trap 9) — is rejected (line 7622).</summary>
    [TestMethod]
    public async Task SetOffsetZeroLengthBelowSeventeenReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-set-length-too-short");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 0, Length: 16);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, status);
    }


    /// <summary>A non-zero <c>offset</c> carrying <c>length</c> is rejected (line 7632) — <c>length</c> is legal ONLY on the sequence-initiating fragment.</summary>
    [TestMethod]
    public async Task SetOffsetNonZeroWithLengthReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-set-offset-nonzero-with-length");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 1, Length: 17);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, status);
    }


    /// <summary>A continuation fragment whose <c>offset</c> does not match <c>expectedNextOffset</c> — here, no sequence was ever started — is rejected with <c>InvalidSeq</c> (line 7635), never <c>InvalidParameter</c>.</summary>
    [TestMethod]
    public async Task SetOffsetMismatchWithNoPriorSequenceReturnsInvalidSeq()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-set-offset-mismatch-no-sequence");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 5);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSeq, status);
    }


    /// <summary>
    /// A continuation fragment whose <c>offset</c> does not match a LIVE, already-installed sequence's
    /// own <c>expectedNextOffset</c> is rejected with <c>InvalidSeq</c> — the genuinely-wrong-offset
    /// shape of line 7635, distinct from <see cref="SetOffsetMismatchWithNoPriorSequenceReturnsInvalidSeq"/>'s
    /// no-sequence-at-all shape.
    /// </summary>
    [TestMethod]
    public async Task SetOffsetMismatchAgainstLiveSequenceReturnsInvalidSeq()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-set-offset-mismatch-live-sequence");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> firstFragmentOwner = pool.Rent(1);
        firstFragmentOwner.Memory.Span[0] = 0x80;
        var firstFragment = new CtapLargeBlobsRequest(Set: firstFragmentOwner.Memory[..1], Offset: 0, Length: 17);
        byte firstStatus = await SendLargeBlobsExpectingStatusAsync(simulator, firstFragment, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstStatus, "the sequence-initiating fragment must itself succeed on a fresh, unprotected device.");

        using IMemoryOwner<byte> wrongOffsetFragmentOwner = pool.Rent(1);
        wrongOffsetFragmentOwner.Memory.Span[0] = 0x76;
        var wrongOffsetFragment = new CtapLargeBlobsRequest(Set: wrongOffsetFragmentOwner.Memory[..1], Offset: 7);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, wrongOffsetFragment, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSeq, status);
    }


    /// <summary>
    /// R6/trap 6: when the authenticator is protected (a PIN is set, arming the R5 gate), the pre-auth
    /// content checks (here, <c>length</c> &lt; 17) STILL fire before <c>PuatRequired</c> — an
    /// unauthenticated caller learns the length is invalid without ever presenting a token.
    /// </summary>
    [TestMethod]
    public async Task SetLengthCheckFiresBeforePuatRequiredWhenGateArmed()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-order-length-before-puat");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, CtapWaveLargeBlobsFixtures.DefaultPin, TestContext.CancellationToken);

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 0, Length: 5);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, status, "the length<17 check must fire before PuatRequired, even on a protected device.");
    }


    /// <summary>R6/trap 6: the sequencing check (<c>InvalidSeq</c>) also fires before <c>PuatRequired</c> on a protected device — no token is ever consulted for a mismatched offset.</summary>
    [TestMethod]
    public async Task SetOffsetMismatchFiresBeforePuatRequiredWhenGateArmed()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-order-seq-before-puat");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, CtapWaveLargeBlobsFixtures.DefaultPin, TestContext.CancellationToken);

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 5);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSeq, status);
    }


    /// <summary>
    /// R6/trap 6-7: the sum check (line 7655, <c>offset + |fragment| &gt; expectedLength</c>) runs AFTER
    /// token verification — a continuation fragment that would BOTH overflow <c>expectedLength</c> AND
    /// carry a bad signature returns <c>PinAuthInvalid</c>, never <c>InvalidParameter</c>.
    /// </summary>
    [TestMethod]
    public async Task SumCheckRunsAfterVerificationFailure()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-order-sum-after-verify");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await CtapWaveLargeBlobsFixtures.EstablishPinAndIssueTokenAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Lbw, TestContext.CancellationToken);

        using IMemoryOwner<byte> firstFragmentOwner = pool.Rent(1);
        firstFragmentOwner.Memory.Span[0] = 0x01;
        Memory<byte> firstFragment = firstFragmentOwner.Memory[..1];
        byte[] firstParam = await CtapWaveLargeBlobsFixtures.ComputeSetSignatureAsync(
            token, CtapPinUvAuthProtocolId.Two, 0, firstFragment, pool, TestContext.CancellationToken);
        var firstRequest = new CtapLargeBlobsRequest(
            Set: firstFragment, Offset: 0, Length: 17, PinUvAuthParam: firstParam, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        byte firstStatus = await SendLargeBlobsExpectingStatusAsync(simulator, firstRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstStatus);

        using IMemoryOwner<byte> overflowingFragmentOwner = pool.Rent(30);
        overflowingFragmentOwner.Memory.Span[..30].Clear();
        using IMemoryOwner<byte> badParamOwner = pool.Rent(32);
        badParamOwner.Memory.Span[..32].Clear();
        var secondRequest = new CtapLargeBlobsRequest(
            Set: overflowingFragmentOwner.Memory[..30], Offset: 1, PinUvAuthParam: badParamOwner.Memory[..32], PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, secondRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, status, "verification must run, and fail, before the sum check ever gets a chance to report InvalidParameter.");
    }


    /// <summary>Armed gate, <c>pinUvAuthParam</c> absent → <c>PuatRequired</c> (line 7640).</summary>
    [TestMethod]
    public async Task SetGateArmedParamAbsentReturnsPuatRequired()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-armed-param-absent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, CtapWaveLargeBlobsFixtures.DefaultPin, TestContext.CancellationToken);

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 0, Length: 17);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, status);
    }


    /// <summary>Armed gate, <c>pinUvAuthParam</c> present but <c>pinUvAuthProtocol</c> absent → <c>MissingParameter</c> (line 7642).</summary>
    [TestMethod]
    public async Task SetGateArmedProtocolAbsentReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-armed-protocol-absent");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, CtapWaveLargeBlobsFixtures.DefaultPin, TestContext.CancellationToken);

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(32);
        pinUvAuthParamOwner.Memory.Span[..32].Clear();
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 0, Length: 17, PinUvAuthParam: pinUvAuthParamOwner.Memory[..32]);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, status);
    }


    /// <summary>Armed gate, an unsupported <c>pinUvAuthProtocol</c> value → <c>InvalidParameter</c> (line 7644).</summary>
    [TestMethod]
    public async Task SetGateArmedUnsupportedProtocolReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-armed-unsupported-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, CtapWaveLargeBlobsFixtures.DefaultPin, TestContext.CancellationToken);

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(32);
        pinUvAuthParamOwner.Memory.Span[..32].Clear();
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 0, Length: 17, PinUvAuthParam: pinUvAuthParamOwner.Memory[..32], PinUvAuthProtocol: 99);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, status);
    }


    /// <summary>Armed gate, a syntactically well-formed but WRONG <c>pinUvAuthParam</c> → <c>PinAuthInvalid</c> (lines 7646-7650).</summary>
    [TestMethod]
    public async Task SetGateArmedBadSignatureReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-armed-bad-signature");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        _ = await CtapWaveLargeBlobsFixtures.EstablishPinAndIssueTokenAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Lbw, TestContext.CancellationToken);

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(32);
        pinUvAuthParamOwner.Memory.Span[..32].Clear();
        var request = new CtapLargeBlobsRequest(
            Set: setOwner.Memory[..1], Offset: 0, Length: 17, PinUvAuthParam: pinUvAuthParamOwner.Memory[..32], PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, status);
    }


    /// <summary>
    /// A token that verifies correctly but lacks <c>lbw</c> is rejected with <c>PinAuthInvalid</c> (line
    /// 7652), NOT <c>UnauthorizedPermission</c> (trap 4) — the shipped <c>acfg</c>-check precedent's
    /// identical shape.
    /// </summary>
    [TestMethod]
    public async Task SetTokenLackingLbwReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-no-lbw-permission");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] mcOnlyToken = await CtapWaveLargeBlobsFixtures.EstablishPinAndIssueTokenAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Mc, TestContext.CancellationToken, rpId: DefaultRpId);

        using IMemoryOwner<byte> fragmentOwner = pool.Rent(1);
        fragmentOwner.Memory.Span[0] = 0x80;
        Memory<byte> fragment = fragmentOwner.Memory[..1];
        byte[] param = await CtapWaveLargeBlobsFixtures.ComputeSetSignatureAsync(
            mcOnlyToken, CtapPinUvAuthProtocolId.Two, 0, fragment, pool, TestContext.CancellationToken);
        var request = new CtapLargeBlobsRequest(
            Set: fragment, Offset: 0, Length: 17, PinUvAuthParam: param, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, status);
    }


    /// <summary>
    /// A fresh, wholly unprotected device (no PIN, no enrollment, <c>alwaysUv</c> off) accepts a complete
    /// multi-fragment <c>set</c> with NO token at all (line 7682) — the tokenless-write requirement.
    /// Read back afterward confirms the committed bytes match exactly what was written.
    /// </summary>
    [TestMethod]
    public async Task TokenlessWriteSucceedsOnFreshUnprotectedDevice()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-tokenless-multi-fragment");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] fullArray = BuildValidSerializedLargeBlobArray(pool, payloadLength: 20);
        byte[] firstFragment = fullArray[..10];
        byte[] secondFragment = fullArray[10..];

        var firstRequest = new CtapLargeBlobsRequest(Set: firstFragment, Offset: 0, Length: fullArray.Length);
        byte firstStatus = await SendLargeBlobsExpectingStatusAsync(simulator, firstRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstStatus);

        var secondRequest = new CtapLargeBlobsRequest(Set: secondFragment, Offset: firstFragment.Length);
        byte secondStatus = await SendLargeBlobsExpectingStatusAsync(simulator, secondRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, secondStatus);

        var getRequest = new CtapLargeBlobsRequest(Get: fullArray.Length, Offset: 0);
        using PooledMemory getResponse = await SendLargeBlobsAsync(simulator, getRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, getResponse.AsReadOnlySpan()[0]);
        CtapLargeBlobsResponse decoded = CtapLargeBlobsResponseCborReader.Read(getResponse.AsReadOnlyMemory()[1..]);
        CollectionAssert.AreEqual(fullArray, decoded.Config.ToArray());
    }


    /// <summary>An integrity-INVALID completed write returns <c>IntegrityFailure</c> (line 7666) and leaves the previously stored array byte-exact UNCHANGED.</summary>
    [TestMethod]
    public async Task IntegrityFailureLeavesStoredArrayUnchanged()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-integrity-failure");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] corrupted = BuildValidSerializedLargeBlobArray(pool, payloadLength: 20);
        corrupted[^1] ^= 0xFF;

        var request = new CtapLargeBlobsRequest(Set: corrupted, Offset: 0, Length: corrupted.Length);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.IntegrityFailure, status);

        var getRequest = new CtapLargeBlobsRequest(Get: 17, Offset: 0);
        using PooledMemory getResponse = await SendLargeBlobsAsync(simulator, getRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, getResponse.AsReadOnlySpan()[0]);
        CtapLargeBlobsResponse decoded = CtapLargeBlobsResponseCborReader.Read(getResponse.AsReadOnlyMemory()[1..]);
        CollectionAssert.AreEqual(CtapAuthenticatorState.InitialSerializedLargeBlobArray.ToArray(), decoded.Config.ToArray());
    }


    /// <summary>
    /// R7/trap 15: <c>authenticatorReset</c> discards a pending write exactly like every other
    /// intervening command (disposed by <see cref="CtapAuthenticatorState.FactoryReset"/> directly) — a
    /// subsequent continuation attempt at the old offset fails <c>InvalidSeq</c>, and a <c>get</c>
    /// afterward shows the reset's own restored 17-byte initial constant, never the abandoned pending
    /// content.
    /// </summary>
    [TestMethod]
    public async Task FactoryResetDiscardsPendingWrite()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-factory-reset-discards-pending");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> pendingFragmentOwner = pool.Rent(1);
        pendingFragmentOwner.Memory.Span[0] = 0x80;
        var pendingFragment = new CtapLargeBlobsRequest(Set: pendingFragmentOwner.Memory[..1], Offset: 0, Length: 17);
        byte pendingStatus = await SendLargeBlobsExpectingStatusAsync(simulator, pendingFragment, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, pendingStatus);

        using IMemoryOwner<byte> resetRequest = RentSingleByteCommandEnvelope(WellKnownCtapCommands.Reset, pool);
        using(PooledMemory resetResponse = await simulator.TransceiveAsync(resetRequest.Memory[..1], pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        using IMemoryOwner<byte> continuationAfterResetOwner = pool.Rent(1);
        continuationAfterResetOwner.Memory.Span[0] = 0x76;
        var continuationAfterReset = new CtapLargeBlobsRequest(Set: continuationAfterResetOwner.Memory[..1], Offset: 1);
        byte continuationStatus = await SendLargeBlobsExpectingStatusAsync(simulator, continuationAfterReset, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSeq, continuationStatus, "the reset must have discarded the pending sequence.");

        var getRequest = new CtapLargeBlobsRequest(Get: 17, Offset: 0);
        using PooledMemory getResponse = await SendLargeBlobsAsync(simulator, getRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, getResponse.AsReadOnlySpan()[0]);
        CtapLargeBlobsResponse decoded = CtapLargeBlobsResponseCborReader.Read(getResponse.AsReadOnlyMemory()[1..]);
        CollectionAssert.AreEqual(CtapAuthenticatorState.InitialSerializedLargeBlobArray.ToArray(), decoded.Config.ToArray());
    }


    /// <summary>
    /// R7 seams §4: an intervening <c>authenticatorGetInfo</c> between two <c>set</c> fragments discards
    /// the pending sequence (the GLOBAL discipline) — the next fragment, still addressed at its old
    /// continuation offset, now mismatches a freshly zeroed <c>expectedNextOffset</c> and reports
    /// <c>InvalidSeq</c>.
    /// </summary>
    [TestMethod]
    public async Task InterleavedGetInfoBetweenFragmentsCausesNextFragmentInvalidSeq()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-interleaved-getinfo");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> firstFragmentOwner = pool.Rent(1);
        firstFragmentOwner.Memory.Span[0] = 0x80;
        var firstFragment = new CtapLargeBlobsRequest(Set: firstFragmentOwner.Memory[..1], Offset: 0, Length: 17);
        byte firstStatus = await SendLargeBlobsExpectingStatusAsync(simulator, firstFragment, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstStatus);

        using IMemoryOwner<byte> getInfoRequest = RentSingleByteCommandEnvelope(WellKnownCtapCommands.GetInfo, pool);
        using(PooledMemory getInfoResponse = await simulator.TransceiveAsync(getInfoRequest.Memory[..1], pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, getInfoResponse.AsReadOnlySpan()[0]);
        }

        using IMemoryOwner<byte> secondFragmentOwner = pool.Rent(1);
        secondFragmentOwner.Memory.Span[0] = 0x76;
        var secondFragment = new CtapLargeBlobsRequest(Set: secondFragmentOwner.Memory[..1], Offset: 1);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, secondFragment, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSeq, status);
    }


    /// <summary>
    /// R7 (line 2869): a power cycle discards the pending write (a fresh continuation attempt at the old
    /// offset fails <c>InvalidSeq</c>) but PRESERVES whatever was already committed to
    /// <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> before the cycle.
    /// </summary>
    [TestMethod]
    public async Task PowerCycleDiscardsPendingWriteButPreservesCommittedArray()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-power-cycle");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] committed = BuildValidSerializedLargeBlobArray(pool, payloadLength: 20);
        var commitRequest = new CtapLargeBlobsRequest(Set: committed, Offset: 0, Length: committed.Length);
        byte commitStatus = await SendLargeBlobsExpectingStatusAsync(simulator, commitRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, commitStatus);

        using IMemoryOwner<byte> pendingFragmentOwner = pool.Rent(1);
        pendingFragmentOwner.Memory.Span[0] = 0x80;
        var pendingFragment = new CtapLargeBlobsRequest(Set: pendingFragmentOwner.Memory[..1], Offset: 0, Length: 17);
        byte pendingStatus = await SendLargeBlobsExpectingStatusAsync(simulator, pendingFragment, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, pendingStatus);

        simulator.PowerCycle();

        using IMemoryOwner<byte> continuationAfterCycleOwner = pool.Rent(1);
        continuationAfterCycleOwner.Memory.Span[0] = 0x76;
        var continuationAfterCycle = new CtapLargeBlobsRequest(Set: continuationAfterCycleOwner.Memory[..1], Offset: 1);
        byte continuationStatus = await SendLargeBlobsExpectingStatusAsync(simulator, continuationAfterCycle, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSeq, continuationStatus, "the power cycle must have discarded the pending sequence.");

        var getRequest = new CtapLargeBlobsRequest(Get: committed.Length, Offset: 0);
        using PooledMemory getResponse = await SendLargeBlobsAsync(simulator, getRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, getResponse.AsReadOnlySpan()[0]);
        CtapLargeBlobsResponse decoded = CtapLargeBlobsResponseCborReader.Read(getResponse.AsReadOnlyMemory()[1..]);
        CollectionAssert.AreEqual(committed, decoded.Config.ToArray(), "the previously committed array must survive the power cycle untouched.");
    }


    /// <summary>
    /// R7 (line 2873): once the pending sequence's authenticating <c>pinUvAuthToken</c> expires, the next
    /// continuation fragment finds the sequence discarded — the same <c>InvalidSeq</c> an interleaved
    /// command produces. A tokenless sequence has no such antecedent (documented at
    /// <see cref="CtapRememberedLargeBlobWriteState.AuthenticatingPinUvAuthProtocol"/>), so this test is
    /// meaningful only for a gate-armed sequence.
    /// </summary>
    [TestMethod]
    public async Task TokenExpiryDiscardsArmedPendingWrite()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-token-expiry-discard", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await CtapWaveLargeBlobsFixtures.EstablishPinAndIssueTokenAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Lbw, TestContext.CancellationToken);

        using IMemoryOwner<byte> firstFragmentOwner = pool.Rent(1);
        firstFragmentOwner.Memory.Span[0] = 0x01;
        Memory<byte> firstFragment = firstFragmentOwner.Memory[..1];
        byte[] firstParam = await CtapWaveLargeBlobsFixtures.ComputeSetSignatureAsync(
            token, CtapPinUvAuthProtocolId.Two, 0, firstFragment, pool, TestContext.CancellationToken);
        var firstRequest = new CtapLargeBlobsRequest(
            Set: firstFragment, Offset: 0, Length: 17, PinUvAuthParam: firstParam, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        byte firstStatus = await SendLargeBlobsExpectingStatusAsync(simulator, firstRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstStatus);

        timeProvider.Advance(CtapPinUvAuthTokenState.MaxUsageTimePeriod);

        using IMemoryOwner<byte> continuationOwner = pool.Rent(1);
        continuationOwner.Memory.Span[0] = 0x76;
        var continuation = new CtapLargeBlobsRequest(Set: continuationOwner.Memory[..1], Offset: 1);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, continuation, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSeq, status, "the expired authenticating token must discard the pending sequence.");
    }


    /// <summary>R5 arming trigger 1: <c>setPIN</c> arms the gate — a subsequent tokenless <c>set</c> now fails <c>PuatRequired</c>.</summary>
    [TestMethod]
    public async Task GateArmsViaSetPin()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-arms-via-setpin");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, CtapWaveLargeBlobsFixtures.DefaultPin, TestContext.CancellationToken);

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 0, Length: 17);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, status);
    }


    /// <summary>
    /// R5 arming trigger 2: completing a fingerprint enrollment arms the gate. Documented structural
    /// note (mirrors <see cref="CtapWaveLargeBlobsFixtures.CompleteBootstrapEnrollmentAsync"/>'s own
    /// remark): in this profile a PIN MUST already be set to bootstrap the <c>be</c>-scoped token any
    /// enrollment needs, so this test cannot isolate "armed by enrollment alone, no PIN ever set" — it
    /// demonstrates that <see cref="CtapAuthenticatorState.HasProvisionedBioEnrollments"/> contributes to
    /// the SAME <c>IsProtectedByUserVerification</c> OR <see cref="GateArmsViaSetPin"/> already exercises
    /// for its other operand, consumed AS-IS by the R5 gate (zero edits).
    /// </summary>
    [TestMethod]
    public async Task GateArmsViaBioEnrollmentCompletion()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-arms-via-enrollment");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapWaveLargeBlobsFixtures.CompleteBootstrapEnrollmentAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, TestContext.CancellationToken);

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 0, Length: 17);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, status);
    }


    /// <summary>
    /// R5 arming trigger 3, and the alwaysUv-armed-but-unmintable corner (documented at §6.11's own
    /// 7992 cross-reference): on a FRESH device, <c>toggleAlwaysUv</c> itself runs TOKENLESS (its own
    /// step-3 bypass: unprotected AND not-yet-enabled means the gate does not apply at all) and succeeds,
    /// arming <c>alwaysUv</c>. A subsequent <c>set</c> now requires a token — but NO token can ever be
    /// minted on this device (no PIN, no enrollment, and this profile's <c>getPinUvAuthTokenUsingUvWithPermissions</c>
    /// itself requires an enrollment to already exist) — so the device is durably stuck at
    /// <c>PuatRequired</c>, exactly as the spec's own organizations-preconfigure-before-distribution
    /// posture anticipates.
    /// </summary>
    [TestMethod]
    public async Task GateArmsViaToggleAlwaysUvWithNoMintPathAvailable()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-arms-via-alwaysuv-corner");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte toggleStatus = await CtapWaveLargeBlobsFixtures.ToggleAlwaysUvAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, toggleStatus, "toggleAlwaysUv on a fresh device must succeed tokenless.");

        using IMemoryOwner<byte> setOwner = pool.Rent(1);
        setOwner.Memory.Span[0] = 0x80;
        var request = new CtapLargeBlobsRequest(Set: setOwner.Memory[..1], Offset: 0, Length: 17);
        byte status = await SendLargeBlobsExpectingStatusAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, status, "no lbw token can ever be minted on this device, so the gate stays durably armed and unsatisfiable.");
    }


    /// <summary>
    /// The lbw carve-out's own E2E proof (seams Finding C): a token minted with <c>lbw|mc</c> completes
    /// an <c>authenticatorMakeCredential</c> (which strips every permission except <c>lbw</c>, line 5828)
    /// and the SAME token — now carrying only <c>lbw</c> — still drives a full <c>set</c> to completion.
    /// </summary>
    [TestMethod]
    public async Task LbwCarveOutSurvivesMakeCredentialAndDrivesSet()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-lbw-carveout");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        int lbwAndMc = WellKnownCtapPinUvAuthTokenPermissions.Lbw | WellKnownCtapPinUvAuthTokenPermissions.Mc;
        byte[] token = await CtapWaveLargeBlobsFixtures.EstablishPinAndIssueTokenAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, lbwAndMc, TestContext.CancellationToken, rpId: DefaultRpId);

        byte[] mcClientDataHash = BuildFixedBytes(32, 0x10);
        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, mcClientDataHash, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest mcRequest = BuildMakeCredentialRequest(
            pool, pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using(PooledMemory mcResponse = await SendMakeCredentialAsync(simulator, mcRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, mcResponse.AsReadOnlySpan()[0], "the mc call itself, authorized by mc, must succeed.");
        }

        using IMemoryOwner<byte> fragmentOwner = pool.Rent(1);
        fragmentOwner.Memory.Span[0] = 0x80;
        Memory<byte> fragment = fragmentOwner.Memory[..1];
        byte[] setParam = await CtapWaveLargeBlobsFixtures.ComputeSetSignatureAsync(
            token, CtapPinUvAuthProtocolId.Two, 0, fragment, pool, TestContext.CancellationToken);
        var setRequest = new CtapLargeBlobsRequest(
            Set: fragment, Offset: 0, Length: 17, PinUvAuthParam: setParam, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        byte setStatus = await SendLargeBlobsExpectingStatusAsync(simulator, setRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.Ok, setStatus,
            "the SAME token, stripped of mc but still carrying lbw (the line 5828 carve-out), must still drive set.");
    }


    /// <summary>
    /// The verify-message KAT (seams trap 2): the spec-correct LITTLE-endian <c>offset</c> encoding
    /// verifies successfully; a deliberately WRONG big-endian encoding of the SAME offset, fragment, and
    /// token fails <c>PinAuthInvalid</c> — pinning the ONLY little-endian integer on this whole surface.
    /// <c>offset</c> is chosen non-zero (1) so the two encodings are byte-distinguishable (an offset of
    /// zero is endian-invariant).
    /// </summary>
    [TestMethod]
    public async Task VerifyMessageOffsetIsLittleEndianNotBigEndian()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] fragment = System.Text.Encoding.ASCII.GetBytes("abc");
        byte[] expectedSha256OfAbc =
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        ];
        using(DigestValue actualDigest = CryptographicKeyEvents.ComputeDigest(fragment, 32, CryptoTags.Sha256Digest, pool))
        {
            CollectionAssert.AreEqual(expectedSha256OfAbc, actualDigest.AsReadOnlySpan().ToArray(), "SHA-256(\"abc\") must match the well-known NIST test vector, hand-verified independently of this KAT's own offset encoding.");
        }

        using CtapAuthenticatorSimulator correctSimulator = CreateSimulator("largeblobs-kat-correct");
        byte[] correctToken = await CtapWaveLargeBlobsFixtures.EstablishPinAndIssueTokenAsync(
            correctSimulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Lbw, TestContext.CancellationToken);
        using IMemoryOwner<byte> firstFragmentCorrectOwner = pool.Rent(1);
        firstFragmentCorrectOwner.Memory.Span[0] = 0x01;
        Memory<byte> firstFragmentCorrect = firstFragmentCorrectOwner.Memory[..1];
        byte[] firstParamCorrect = await CtapWaveLargeBlobsFixtures.ComputeSetSignatureAsync(
            correctToken, CtapPinUvAuthProtocolId.Two, 0, firstFragmentCorrect, pool, TestContext.CancellationToken);
        var firstRequestCorrect = new CtapLargeBlobsRequest(
            Set: firstFragmentCorrect, Offset: 0, Length: 17, PinUvAuthParam: firstParamCorrect, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.Ok,
            await SendLargeBlobsExpectingStatusAsync(correctSimulator, firstRequestCorrect, pool, TestContext.CancellationToken));

        byte[] correctSecondParam = await CtapWaveLargeBlobsFixtures.ComputeSetSignatureAsync(
            correctToken, CtapPinUvAuthProtocolId.Two, 1, fragment, pool, TestContext.CancellationToken, littleEndian: true);
        var correctSecondRequest = new CtapLargeBlobsRequest(
            Set: fragment, Offset: 1, PinUvAuthParam: correctSecondParam, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        byte correctStatus = await SendLargeBlobsExpectingStatusAsync(correctSimulator, correctSecondRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, correctStatus, "the spec-correct LITTLE-endian offset encoding must verify.");

        using CtapAuthenticatorSimulator wrongSimulator = CreateSimulator("largeblobs-kat-wrong");
        byte[] wrongToken = await CtapWaveLargeBlobsFixtures.EstablishPinAndIssueTokenAsync(
            wrongSimulator, pool, CtapPinUvAuthProtocolId.Two, WellKnownCtapPinUvAuthTokenPermissions.Lbw, TestContext.CancellationToken);
        using IMemoryOwner<byte> firstFragmentWrongOwner = pool.Rent(1);
        firstFragmentWrongOwner.Memory.Span[0] = 0x01;
        Memory<byte> firstFragmentWrong = firstFragmentWrongOwner.Memory[..1];
        byte[] firstParamWrong = await CtapWaveLargeBlobsFixtures.ComputeSetSignatureAsync(
            wrongToken, CtapPinUvAuthProtocolId.Two, 0, firstFragmentWrong, pool, TestContext.CancellationToken);
        var firstRequestWrong = new CtapLargeBlobsRequest(
            Set: firstFragmentWrong, Offset: 0, Length: 17, PinUvAuthParam: firstParamWrong, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.Ok,
            await SendLargeBlobsExpectingStatusAsync(wrongSimulator, firstRequestWrong, pool, TestContext.CancellationToken));

        byte[] wrongSecondParam = await CtapWaveLargeBlobsFixtures.ComputeSetSignatureAsync(
            wrongToken, CtapPinUvAuthProtocolId.Two, 1, fragment, pool, TestContext.CancellationToken, littleEndian: false);
        var wrongSecondRequest = new CtapLargeBlobsRequest(
            Set: fragment, Offset: 1, PinUvAuthParam: wrongSecondParam, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        byte wrongStatus = await SendLargeBlobsExpectingStatusAsync(wrongSimulator, wrongSecondRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, wrongStatus, "a BIG-endian offset encoding of the identical offset/fragment/token must fail verification.");
    }


    /// <summary>
    /// Builds a well-formed, integrity-VALID serialized large-blob array of a chosen total length: an
    /// empty CBOR array (<c>0x80</c>) padded with <paramref name="payloadLength"/> minus 17 filler bytes,
    /// followed by the correct trailing <c>LEFT(SHA-256(preceding bytes), 16)</c> — a test-side mirror of
    /// the authenticator's own commit-time check (CTAP 2.3 §6.10, line 7540's construction, generalized
    /// to an arbitrary total length above the 17-byte minimum).
    /// </summary>
    /// <param name="pool">The memory pool the array and its digest computation rent from.</param>
    /// <param name="payloadLength">The total serialized array length, at least 17.</param>
    /// <returns>The byte-exact, integrity-valid array.</returns>
    private static byte[] BuildValidSerializedLargeBlobArray(MemoryPool<byte> pool, int payloadLength)
    {
        using IMemoryOwner<byte> owner = pool.Rent(payloadLength);
        Span<byte> array = owner.Memory.Span[..payloadLength];
        array[0] = 0x80;
        for(int i = 1; i < payloadLength - 16; i++)
        {
            array[i] = (byte)(0x41 + i);
        }

        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(array[..(payloadLength - 16)], 32, CryptoTags.Sha256Digest, pool);
        digest.AsReadOnlySpan()[..16].CopyTo(array[(payloadLength - 16)..]);

        return array.ToArray();
    }


    /// <summary>
    /// <c>authenticatorGetInfo</c> advertises <c>largeBlobs:true</c> (BINARY, R2), the
    /// <c>maxSerializedLargeBlobArray</c> member equal to the single-sourced capacity constant, and the
    /// <c>largeBlobKey</c> extension identifier in the <c>extensions</c> array (R2's joint feature
    /// detection requirement, lines 12832-12834).
    /// </summary>
    [TestMethod]
    public async Task GetInfoAdvertisesLargeBlobsSupport()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("largeblobs-getinfo");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> request = RentSingleByteCommandEnvelope(WellKnownCtapCommands.GetInfo, pool);
        using PooledMemory response = await simulator.TransceiveAsync(request.Memory[..1], pool, TestContext.CancellationToken);
        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);

        Assert.IsTrue(decoded.Options!.LargeBlobs!.Value);
        Assert.AreEqual(CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity, decoded.MaxSerializedLargeBlobArray);
        Assert.Contains(WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey, decoded.Extensions!);
    }


    /// <summary>Rents a pooled one-byte CTAP2 request envelope carrying only <paramref name="command"/> — the shape a sub-command-less request like <c>authenticatorGetInfo</c> or <c>authenticatorReset</c> needs.</summary>
    /// <param name="command">The CTAP2 command byte.</param>
    /// <param name="pool">The memory pool the envelope is rented from.</param>
    /// <returns>A one-byte pooled owner holding <paramref name="command"/>; the caller owns it and must dispose it.</returns>
    private static IMemoryOwner<byte> RentSingleByteCommandEnvelope(byte command, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> envelope = pool.Rent(1);
        envelope.Memory.Span[0] = command;

        return envelope;
    }


    /// <summary>Builds the complete <c>authenticatorLargeBlobs</c> request envelope for <paramref name="request"/>, rented from <paramref name="pool"/>.</summary>
    /// <param name="request">The request model to encode.</param>
    /// <param name="pool">The memory pool the envelope is rented from.</param>
    /// <param name="length">The envelope's valid length: the command byte plus the CBOR parameter map.</param>
    /// <returns>A pooled owner holding the command byte followed by the CTAP2-canonical CBOR parameter map; the caller owns it and must dispose it.</returns>
    private static IMemoryOwner<byte> BuildLargeBlobsEnvelope(CtapLargeBlobsRequest request, MemoryPool<byte> pool, out int length)
    {
        TaggedMemory<byte> parameters = CtapLargeBlobsRequestCborWriter.Write(request);
        length = parameters.Length + 1;
        IMemoryOwner<byte> envelope = pool.Rent(length);
        envelope.Memory.Span[0] = WellKnownCtapCommands.LargeBlobs;
        parameters.Span.CopyTo(envelope.Memory.Span[1..length]);

        return envelope;
    }


    /// <summary>Encodes and sends an <c>authenticatorLargeBlobs</c> request, returning the raw response envelope.</summary>
    private static async Task<PooledMemory> SendLargeBlobsAsync(
        CtapAuthenticatorSimulator simulator, CtapLargeBlobsRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> envelope = BuildLargeBlobsEnvelope(request, pool, out int length);

        return await simulator.TransceiveAsync(envelope.Memory[..length], pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Encodes, sends, and returns ONLY the CTAP2 status byte of an <c>authenticatorLargeBlobs</c> request — the PKG-B set-matrix tests' own terse assertion shape.</summary>
    private static async Task<byte> SendLargeBlobsExpectingStatusAsync(
        CtapAuthenticatorSimulator simulator, CtapLargeBlobsRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using PooledMemory response = await SendLargeBlobsAsync(simulator, request, pool, cancellationToken).ConfigureAwait(false);

        return response.AsReadOnlySpan()[0];
    }
}
