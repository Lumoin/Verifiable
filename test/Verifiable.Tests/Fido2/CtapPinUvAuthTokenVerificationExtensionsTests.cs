using System;
using System.Buffers;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/>: the
/// state-aware <c>verify</c> composition that enforces CTAP 2.3's "key parameter value is the current
/// pinUvAuthToken and it is not in use" precondition (§6.5.6 line 6210-6214/§6.5.7 line 6270-6274) before
/// delegating to <see cref="CtapPinUvAuthProtocol.VerifyAsync"/>.
/// </summary>
[TestClass]
internal sealed class CtapPinUvAuthTokenVerificationExtensionsTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fixed message every authenticate/verify call in this file signs and checks.</summary>
    private static ReadOnlyMemory<byte> Message => Encoding.ASCII.GetBytes("ctap-pinuv-token-verify-message");


    /// <summary>
    /// When the presented key equals the current token and that token is NOT in use, verification
    /// fails — even though the signature itself is a perfectly correct HMAC over that key.
    /// </summary>
    [TestMethod]
    [DataRow(CtapPinUvAuthProtocolId.One)]
    [DataRow(CtapPinUvAuthProtocolId.Two)]
    public async Task NotInUseCurrentTokenAsKeyFailsEvenWithACorrectSignature(CtapPinUvAuthProtocolId id)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(id);
        using CtapPinUvAuthTokenState tokenState = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);

        using IMemoryOwner<byte> signature = await protocol.AuthenticateAsync(
            tokenState.Token.AsReadOnlyMemory(), Message, BaseMemoryPool.Shared, TestContext.CancellationToken);

        bool isValid = await protocol.VerifyPinUvAuthTokenAsync(
            tokenState, tokenState.Token.AsReadOnlyMemory(), Message, signature.Memory, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsFalse(isValid, "Line 6210-6214/6270-6274: a not-in-use token used as its own verify key must fail.");
    }


    /// <summary>The same current token, once in use, verifies successfully against a correct signature.</summary>
    [TestMethod]
    [DataRow(CtapPinUvAuthProtocolId.One)]
    [DataRow(CtapPinUvAuthProtocolId.Two)]
    public async Task InUseCurrentTokenAsKeySucceedsWithACorrectSignature(CtapPinUvAuthProtocolId id)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(id);
        using CtapPinUvAuthTokenState notInUse = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = notInUse.BeginUsing(userIsPresent: false, TestClock.CanonicalEpoch);

        using IMemoryOwner<byte> signature = await protocol.AuthenticateAsync(
            inUse.Token.AsReadOnlyMemory(), Message, BaseMemoryPool.Shared, TestContext.CancellationToken);

        bool isValid = await protocol.VerifyPinUvAuthTokenAsync(
            inUse, inUse.Token.AsReadOnlyMemory(), Message, signature.Memory, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(isValid, "An in-use token must verify normally against a correct signature.");
    }


    /// <summary>
    /// An in-use current token still fails verification against a WRONG signature — the composition
    /// seam only adds a precondition, it never weakens the underlying HMAC check.
    /// </summary>
    [TestMethod]
    public async Task InUseCurrentTokenAsKeyStillFailsWithAWrongSignature()
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(CtapPinUvAuthProtocolId.One);
        using CtapPinUvAuthTokenState notInUse = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = notInUse.BeginUsing(userIsPresent: false, TestClock.CanonicalEpoch);

        using IMemoryOwner<byte> wrongSignatureOwner = BaseMemoryPool.Shared.Rent(16);
        wrongSignatureOwner.Memory.Span[..16].Fill(0xAB);

        bool isValid = await protocol.VerifyPinUvAuthTokenAsync(
            inUse, inUse.Token.AsReadOnlyMemory(), Message, wrongSignatureOwner.Memory[..16], BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsFalse(isValid);
    }


    /// <summary>
    /// A key that is NOT the current token bypasses the in-use gate entirely: verification against a
    /// different, correctly-signed key succeeds even while the token itself is not in use — the check
    /// only ever fires when the presented key equals the current token's own bytes.
    /// </summary>
    [TestMethod]
    public async Task ADifferentKeyThanTheCurrentTokenBypassesTheInUseGate()
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(CtapPinUvAuthProtocolId.One);
        using CtapPinUvAuthTokenState notInUse = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        using CtapPinUvAuthTokenState differentToken = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);

        using IMemoryOwner<byte> signature = await protocol.AuthenticateAsync(
            differentToken.Token.AsReadOnlyMemory(), Message, BaseMemoryPool.Shared, TestContext.CancellationToken);

        bool isValid = await protocol.VerifyPinUvAuthTokenAsync(
            notInUse, differentToken.Token.AsReadOnlyMemory(), Message, signature.Memory, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(isValid, "The in-use gate only applies when the presented key equals notInUse's OWN current token.");
    }
}
