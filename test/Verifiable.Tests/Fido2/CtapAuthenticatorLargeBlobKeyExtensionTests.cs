using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wavelb PKG-C unit-test matrix for the <c>largeBlobKey</c> extension (CTAP 2.3 §12.3) end to end:
/// <c>authenticatorMakeCredential</c>'s fresh-key minting and TOP-LEVEL <c>0x05</c> emission,
/// <c>authenticatorGetAssertion</c>'s TOP-LEVEL <c>0x07</c> emission gated on both the request AND the
/// resolved credential, and both operations' <c>CTAP2_ERR_INVALID_OPTION</c> negatives (R8). Driven
/// in-process through <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>, mirroring
/// <see cref="CtapAuthenticatorExtensionsTests"/>'s shape (real-wire capstones are a later package).
/// Every assertion decodes REAL wire bytes (the response's own top-level <c>largeBlobKey</c> member),
/// never back-channel simulator state.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorLargeBlobKeyExtensionTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A discoverable (<c>rk:true</c>) mc request carrying a solicited, legal <c>largeBlobKey:true</c>
    /// extension mints a fresh 32-byte key and emits it as the response's TOP-LEVEL <c>largeBlobKey</c>
    /// (<c>0x05</c>) member — CTAP 2.3 §12.3, lines 12851/12853.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialWithLargeBlobKeyAndResidentKeyEmitsFreshThirtyTwoByteKeyAtTopLevel()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("lbk-mc-fresh-key");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(largeBlobKey: true);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, options: new CtapCommandOptions(ResidentKey: true), extensions: extensions);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);

        Assert.IsNotNull(decoded.LargeBlobKey);
        Assert.AreEqual(32, decoded.LargeBlobKey!.Value.Length);
    }


    /// <summary>Two independent mc calls each requesting <c>largeBlobKey</c> mint DIFFERENT keys — the entropy provider is genuinely consulted per credential, not a fixed constant.</summary>
    [TestMethod]
    public async Task MakeCredentialWithLargeBlobKeyMintsADifferentKeyPerCredential()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("lbk-mc-distinct-keys");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(largeBlobKey: true);
        CtapMakeCredentialRequest first = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0xE0), options: new CtapCommandOptions(ResidentKey: true), extensions: extensions);
        using PooledMemory firstResponse = await SendMakeCredentialAsync(simulator, first, pool, TestContext.CancellationToken);
        CtapMakeCredentialResponse firstDecoded = CtapMakeCredentialResponseCborReader.Read(firstResponse.AsReadOnlyMemory()[1..]);

        CtapMakeCredentialRequest second = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0xE1), options: new CtapCommandOptions(ResidentKey: true), extensions: extensions);
        using PooledMemory secondResponse = await SendMakeCredentialAsync(simulator, second, pool, TestContext.CancellationToken);
        CtapMakeCredentialResponse secondDecoded = CtapMakeCredentialResponseCborReader.Read(secondResponse.AsReadOnlyMemory()[1..]);

        Assert.IsFalse(firstDecoded.LargeBlobKey!.Value.Span.SequenceEqual(secondDecoded.LargeBlobKey!.Value.Span));
    }


    /// <summary>A <c>largeBlobKey</c> value present but not exactly <c>true</c> rejects with <c>CTAP2_ERR_INVALID_OPTION</c> (line 12847: "the extension should be omitted rather than asserted to be false").</summary>
    [TestMethod]
    public async Task MakeCredentialWithLargeBlobKeyValueFalseReturnsInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("lbk-mc-value-false");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(largeBlobKey: false);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, options: new CtapCommandOptions(ResidentKey: true), extensions: extensions);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A <c>largeBlobKey:true</c> request whose <c>options.rk</c> is absent (non-discoverable) rejects with <c>CTAP2_ERR_INVALID_OPTION</c> (line 12849).</summary>
    [TestMethod]
    public async Task MakeCredentialWithLargeBlobKeyWithoutResidentKeyReturnsInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("lbk-mc-no-rk");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(largeBlobKey: true);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, extensions: extensions);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An mc request that never mentions <c>largeBlobKey</c> never carries the response member, even when discoverable — line 12828's MUST NOT (no unsolicited output), proven on a real decoded response.</summary>
    [TestMethod]
    public async Task MakeCredentialWithoutLargeBlobKeyExtensionNeverEmitsLargeBlobKeyMember()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("lbk-mc-unsolicited");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool, options: new CtapCommandOptions(ResidentKey: true));
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);

        Assert.IsNull(decoded.LargeBlobKey);
    }


    /// <summary>
    /// An <c>authenticatorGetAssertion</c> requesting <c>largeBlobKey:true</c> against the SAME
    /// credential an earlier mc minted a key for emits that IDENTICAL key as the response's TOP-LEVEL
    /// <c>largeBlobKey</c> (<c>0x07</c>) member — CTAP 2.3 §12.3, line 12867.
    /// </summary>
    [TestMethod]
    public async Task GetAssertionWithLargeBlobKeyOnKeyedCredentialEmitsTheSameKeyMcMinted()
    {
        const string rpId = "lbk-ga-keyed.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("lbk-ga-keyed");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        (byte[] credentialIdBytes, ReadOnlyMemory<byte> mintedKey) = await RegisterWithLargeBlobKeyAsync(simulator, pool, BuildFixedBytes(16, 0xE2), rpId, TestContext.CancellationToken);

        ReadOnlyMemory<byte> gaExtensions = BuildGetAssertionExtensionsInput(largeBlobKey: true);
        using PooledMemory gaResponse = await SendGetAssertionAsync(simulator, BuildGetAssertionRequest(pool, rpId: rpId, extensions: gaExtensions), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, gaResponse.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(gaResponse.AsReadOnlyMemory()[1..], pool);
        decoded.Credential.Id.Dispose();

        Assert.IsNotNull(decoded.LargeBlobKey);
        Assert.IsTrue(decoded.LargeBlobKey!.Value.Span.SequenceEqual(mintedKey.Span));

        using CredentialId disposeId = CredentialId.Create(credentialIdBytes, pool);
    }


    /// <summary>A ga request that never mentions <c>largeBlobKey</c> never carries the response member, even against a keyed credential — line 12828's MUST NOT, proven on a real decoded response.</summary>
    [TestMethod]
    public async Task GetAssertionWithoutLargeBlobKeyExtensionNeverEmitsLargeBlobKeyEvenOnKeyedCredential()
    {
        const string rpId = "lbk-ga-unsolicited.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("lbk-ga-unsolicited");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        (byte[] credentialIdBytes, _) = await RegisterWithLargeBlobKeyAsync(simulator, pool, BuildFixedBytes(16, 0xE3), rpId, TestContext.CancellationToken);

        using PooledMemory gaResponse = await SendGetAssertionAsync(simulator, BuildGetAssertionRequest(pool, rpId: rpId), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, gaResponse.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(gaResponse.AsReadOnlyMemory()[1..], pool);
        decoded.Credential.Id.Dispose();

        Assert.IsNull(decoded.LargeBlobKey);

        using CredentialId disposeId = CredentialId.Create(credentialIdBytes, pool);
    }


    /// <summary>A ga request naming <c>largeBlobKey:true</c> against a credential minted WITHOUT the extension succeeds (CTAP2_OK) but never carries the response member — the extension is present-but-key-less, not an error (line 12867's conjunctive "and the credential has an associated largeBlobKey").</summary>
    [TestMethod]
    public async Task GetAssertionWithLargeBlobKeyOnKeylessCredentialSucceedsWithNoLargeBlobKeyMember()
    {
        const string rpId = "lbk-ga-keyless.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("lbk-ga-keyless");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xE4), TestContext.CancellationToken, rpId: rpId);

        ReadOnlyMemory<byte> gaExtensions = BuildGetAssertionExtensionsInput(largeBlobKey: true);
        using PooledMemory gaResponse = await SendGetAssertionAsync(simulator, BuildGetAssertionRequest(pool, rpId: rpId, extensions: gaExtensions), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, gaResponse.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(gaResponse.AsReadOnlyMemory()[1..], pool);
        decoded.Credential.Id.Dispose();

        Assert.IsNull(decoded.LargeBlobKey);
    }


    /// <summary>A ga <c>largeBlobKey</c> value present but not exactly <c>true</c> rejects with <c>CTAP2_ERR_INVALID_OPTION</c> (line 12865).</summary>
    [TestMethod]
    public async Task GetAssertionWithLargeBlobKeyValueFalseReturnsInvalidOption()
    {
        const string rpId = "lbk-ga-value-false.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("lbk-ga-value-false");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xE5), TestContext.CancellationToken, rpId: rpId);

        ReadOnlyMemory<byte> gaExtensions = BuildGetAssertionExtensionsInput(largeBlobKey: false);
        using PooledMemory gaResponse = await SendGetAssertionAsync(simulator, BuildGetAssertionRequest(pool, rpId: rpId, extensions: gaExtensions), pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, gaResponse.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A multi-account <c>authenticatorGetAssertion</c> requesting <c>largeBlobKey</c> resolves the
    /// extension against EACH credential in the sequence independently: the initial response (most
    /// recently created, keyed) carries the minted key; the following <c>authenticatorGetNextAssertion</c>
    /// response (older, key-less) carries NO <c>largeBlobKey</c> member at all — proving
    /// <see cref="CtapRememberedGetAssertionState.LargeBlobKeyRequested"/> threads the ORIGINAL request's
    /// extension resolution across commands while <see cref="CtapAuthenticatorTransitions"/>'s
    /// <c>DeclareSignAssertion</c> still re-resolves the output per credential, never reusing the first
    /// response's value.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionResolvesLargeBlobKeyAgainstItsOwnCredentialNotTheFirstResponse()
    {
        const string rpId = "lbk-ga-continuation.example";
        using CtapAuthenticatorSimulator simulator = CreateSimulator("lbk-ga-continuation");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] olderKeylessCredentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xE6), TestContext.CancellationToken, rpId: rpId);
        (byte[] newerKeyedCredentialId, ReadOnlyMemory<byte> mintedKey) = await RegisterWithLargeBlobKeyAsync(simulator, pool, BuildFixedBytes(16, 0xE7), rpId, TestContext.CancellationToken);

        ReadOnlyMemory<byte> gaExtensions = BuildGetAssertionExtensionsInput(largeBlobKey: true);
        using(PooledMemory firstResponse = await SendGetAssertionAsync(simulator, BuildGetAssertionRequest(pool, rpId: rpId, extensions: gaExtensions), pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstResponse.AsReadOnlySpan()[0]);
            CtapGetAssertionResponse firstDecoded = CtapGetAssertionResponseCborReader.Read(firstResponse.AsReadOnlyMemory()[1..], pool);
            firstDecoded.Credential.Id.Dispose();
            firstDecoded.User?.Id.Dispose();

            Assert.AreEqual(2, firstDecoded.NumberOfCredentials);
            Assert.IsNotNull(firstDecoded.LargeBlobKey);
            Assert.IsTrue(firstDecoded.LargeBlobKey!.Value.Span.SequenceEqual(mintedKey.Span));
        }

        using PooledMemory nextResponse = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, nextResponse.AsReadOnlySpan()[0]);
        CtapGetAssertionResponse nextDecoded = CtapGetAssertionResponseCborReader.Read(nextResponse.AsReadOnlyMemory()[1..], pool);
        nextDecoded.Credential.Id.Dispose();
        nextDecoded.User?.Id.Dispose();

        Assert.IsNull(nextDecoded.NumberOfCredentials);
        Assert.IsNull(nextDecoded.LargeBlobKey);

        using CredentialId disposeOlder = CredentialId.Create(olderKeylessCredentialId, pool);
        using CredentialId disposeNewer = CredentialId.Create(newerKeyedCredentialId, pool);
    }


    /// <summary>
    /// Registers a discoverable credential minted WITH a requested <c>largeBlobKey</c>, returning its
    /// minted credential ID bytes and the mc response's freshly minted key bytes (copied into a
    /// plain array so both the response envelope and the request can be disposed before returning).
    /// </summary>
    private static async Task<(byte[] CredentialIdBytes, ReadOnlyMemory<byte> LargeBlobKey)> RegisterWithLargeBlobKeyAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, byte[] userId, string rpId, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> extensions = BuildMakeCredentialExtensionsInput(largeBlobKey: true);
        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, rpId: rpId, userId: userId, options: new CtapCommandOptions(ResidentKey: true), extensions: extensions);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, cancellationToken).ConfigureAwait(false);
        if(!WellKnownCtapStatusCodes.IsOk(response.AsReadOnlySpan()[0]))
        {
            throw new Fido2FormatException($"Fixture registration with largeBlobKey failed with CTAP2 status 0x{response.AsReadOnlySpan()[0]:X2}.");
        }

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        byte[] credentialIdBytes = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();

        return (credentialIdBytes, decoded.LargeBlobKey!.Value.ToArray());
    }
}
