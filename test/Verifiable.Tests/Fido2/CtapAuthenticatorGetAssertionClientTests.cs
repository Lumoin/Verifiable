using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorGetAssertionClient"/> against a scripted
/// <see cref="Ctap2TransceiveDelegate"/> — no APDU transport or simulator involved, isolating the
/// RP-side request-build/response-decode logic. Mirrors <see cref="CtapAuthenticatorGetInfoClientTests"/>'s shape.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorGetAssertionClientTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The request envelope is exactly the <c>authenticatorGetAssertion</c> command byte followed by the
    /// request's CBOR-encoded parameter map, and a success envelope decodes correctly.
    /// </summary>
    [TestMethod]
    public async Task SendsCommandBytePlusParametersAndDecodesSuccessResponse()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapGetAssertionRequest request = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(pool);
        byte[] expectedRequestBytes = CtapWave2RequestEnvelopes.BuildGetAssertionEnvelope(request);

        CredentialId credentialId = CredentialId.Create([0x01, 0x02, 0x03, 0x04], pool);
        var scriptedResponse = new CtapGetAssertionResponse(
            new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId },
            new byte[] { 0x0A, 0x0B }, new byte[] { 0x0C, 0x0D });

        byte[]? capturedRequest = null;
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> transceiveRequest, MemoryPool<byte> transceivePool, CancellationToken cancellationToken)
        {
            capturedRequest = transceiveRequest.ToArray();
            TaggedMemory<byte> payload = CtapGetAssertionResponseCborWriter.Write(scriptedResponse);
            byte[] envelope = new byte[payload.Length + 1];
            envelope[0] = WellKnownCtapStatusCodes.Ok;
            payload.Span.CopyTo(envelope.AsSpan(1));

            return ValueTask.FromResult(PooledMemory.FromBytes(envelope, transceivePool, Fido2BufferTags.CtapResponseEnvelope));
        }

        CtapGetAssertionResponse decoded = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, TestContext.CancellationToken);

        Assert.AreSequenceEqual(expectedRequestBytes, capturedRequest);
        Assert.AreSequenceEqual(scriptedResponse.AuthData.ToArray(), decoded.AuthData.ToArray());
        Assert.AreSequenceEqual(scriptedResponse.Signature.ToArray(), decoded.Signature.ToArray());

        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(request);
        credentialId.Dispose();
        decoded.Credential.Id.Dispose();
    }


    /// <summary>A non-success status byte raises <see cref="CtapCommandException"/> carrying that status code.</summary>
    [TestMethod]
    public async Task ThrowsCtapCommandExceptionOnNonSuccessStatus()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapGetAssertionRequest request = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(pool);

        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> transceiveRequest, MemoryPool<byte> transceivePool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes([WellKnownCtapStatusCodes.NoCredentials], transceivePool, Fido2BufferTags.CtapResponseEnvelope));

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, TestContext.CancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, exception.StatusCode);

        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(request);
    }


    /// <summary>An empty response envelope is rejected before any decode is attempted.</summary>
    [TestMethod]
    public async Task ThrowsFido2FormatExceptionOnEmptyResponse()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapGetAssertionRequest request = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(pool);

        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> transceiveRequest, MemoryPool<byte> transceivePool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, transceivePool, Fido2BufferTags.CtapResponseEnvelope));

        await Assert.ThrowsExactlyAsync<Fido2FormatException>(
            () => CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, TestContext.CancellationToken).AsTask());

        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(request);
    }
}
