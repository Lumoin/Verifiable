using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorGetNextAssertionClient"/> against a scripted
/// <see cref="Ctap2TransceiveDelegate"/> — no APDU transport or simulator involved, isolating the
/// RP-side request-build/response-decode logic. Mirrors <see cref="CtapAuthenticatorGetInfoClientTests"/>'s
/// bare-command-byte shape.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorGetNextAssertionClientTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The request envelope is exactly the one-byte authenticatorGetNextAssertion command code (0x08),
    /// with no CBOR body, and a success envelope decodes into the same response model
    /// authenticatorGetAssertion uses.
    /// </summary>
    [TestMethod]
    public async Task SendsSingleByteRequestAndDecodesSuccessResponse()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[]? capturedRequest = null;

        CredentialId credentialId = CredentialId.Create([0x11, 0x22, 0x33, 0x44], pool);
        var scriptedResponse = new CtapGetAssertionResponse(
            new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId },
            new byte[] { 0x01, 0x02 }, new byte[] { 0x03, 0x04 });

        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> transceivePool, CancellationToken cancellationToken)
        {
            capturedRequest = request.ToArray();
            TaggedMemory<byte> payload = CtapGetAssertionResponseCborWriter.Write(scriptedResponse);
            byte[] envelope = new byte[payload.Length + 1];
            envelope[0] = WellKnownCtapStatusCodes.Ok;
            payload.Span.CopyTo(envelope.AsSpan(1));

            return ValueTask.FromResult(PooledMemory.FromBytes(envelope, transceivePool, Fido2BufferTags.CtapResponseEnvelope));
        }

        CtapGetAssertionResponse decoded = await CtapAuthenticatorGetNextAssertionClient.GetNextAssertionAsync(
            Transceive, CtapGetAssertionResponseCborReader.Read, pool, TestContext.CancellationToken);

        CollectionAssert.AreEqual(new byte[] { WellKnownCtapCommands.GetNextAssertion }, capturedRequest);
        CollectionAssert.AreEqual(scriptedResponse.AuthData.ToArray(), decoded.AuthData.ToArray());
        CollectionAssert.AreEqual(scriptedResponse.Signature.ToArray(), decoded.Signature.ToArray());

        credentialId.Dispose();
        decoded.Credential.Id.Dispose();
    }


    /// <summary>A non-success status byte raises <see cref="CtapCommandException"/> carrying that status code.</summary>
    [TestMethod]
    public async Task ThrowsCtapCommandExceptionOnNonSuccessStatus()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes([WellKnownCtapStatusCodes.NotAllowed], pool, Fido2BufferTags.CtapResponseEnvelope));

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorGetNextAssertionClient.GetNextAssertionAsync(
                Transceive, CtapGetAssertionResponseCborReader.Read, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, exception.StatusCode);
    }


    /// <summary>An empty response envelope is rejected before any decode is attempted.</summary>
    [TestMethod]
    public async Task ThrowsFido2FormatExceptionOnEmptyResponse()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, Fido2BufferTags.CtapResponseEnvelope));

        await Assert.ThrowsExactlyAsync<Fido2FormatException>(
            () => CtapAuthenticatorGetNextAssertionClient.GetNextAssertionAsync(
                Transceive, CtapGetAssertionResponseCborReader.Read, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }
}
