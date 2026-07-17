using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorMakeCredentialClient"/> against a scripted
/// <see cref="Ctap2TransceiveDelegate"/> — no APDU transport or simulator involved, isolating the
/// RP-side request-build/response-decode/attestation-object-translation logic. Mirrors
/// <see cref="CtapAuthenticatorGetInfoClientTests"/>'s shape.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorMakeCredentialClientTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The request envelope is exactly the <c>authenticatorMakeCredential</c> command byte followed by
    /// the request's CBOR-encoded parameter map, and a success envelope decodes correctly.
    /// </summary>
    [TestMethod]
    public async Task SendsCommandBytePlusParametersAndDecodesSuccessResponse()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool);
        byte[] expectedRequestBytes = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);

        var scriptedResponse = new CtapMakeCredentialResponse(
            WellKnownWebAuthnAttestationFormats.None, new byte[] { 0x01, 0x02, 0x03 }, new byte[] { NoneAttestation.CanonicalEmptyMap });

        byte[]? capturedRequest = null;
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> transceiveRequest, MemoryPool<byte> transceivePool, CancellationToken cancellationToken)
        {
            capturedRequest = transceiveRequest.ToArray();
            TaggedMemory<byte> payload = CtapMakeCredentialResponseCborWriter.Write(scriptedResponse);
            byte[] envelope = new byte[payload.Length + 1];
            envelope[0] = WellKnownCtapStatusCodes.Ok;
            payload.Span.CopyTo(envelope.AsSpan(1));

            return ValueTask.FromResult(PooledMemory.FromBytes(envelope, transceivePool, Fido2BufferTags.CtapResponseEnvelope));
        }

        CtapMakeCredentialResponse decoded = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, TestContext.CancellationToken);

        CollectionAssert.AreEqual(expectedRequestBytes, capturedRequest);
        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.None, decoded.Fmt);
        CollectionAssert.AreEqual(scriptedResponse.AuthData.ToArray(), decoded.AuthData.ToArray());

        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);
    }


    /// <summary>A non-success status byte raises <see cref="CtapCommandException"/> carrying that status code.</summary>
    [TestMethod]
    public async Task ThrowsCtapCommandExceptionOnNonSuccessStatus()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool);

        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> transceiveRequest, MemoryPool<byte> transceivePool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes([WellKnownCtapStatusCodes.UnsupportedAlgorithm], transceivePool, Fido2BufferTags.CtapResponseEnvelope));

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, TestContext.CancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.UnsupportedAlgorithm, exception.StatusCode);

        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);
    }


    /// <summary>An empty response envelope is rejected before any decode is attempted.</summary>
    [TestMethod]
    public async Task ThrowsFido2FormatExceptionOnEmptyResponse()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool);

        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> transceiveRequest, MemoryPool<byte> transceivePool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, transceivePool, Fido2BufferTags.CtapResponseEnvelope));

        await Assert.ThrowsExactlyAsync<Fido2FormatException>(
            () => CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, TestContext.CancellationToken).AsTask());

        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);
    }


    /// <summary>
    /// <see cref="CtapAuthenticatorMakeCredentialClient.BuildAttestationObject"/> translates a decoded
    /// <c>authenticatorMakeCredential</c> response into an <c>attestationObject</c> that round-trips
    /// through the shipped <see cref="AttestationObjectCborReader"/> with the same three parts.
    /// </summary>
    [TestMethod]
    public void BuildAttestationObjectRoundTripsThroughTheShippedReader()
    {
        byte[] authData = [0x0A, 0x0B, 0x0C];
        var response = new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.None, authData, new byte[] { NoneAttestation.CanonicalEmptyMap });

        TaggedMemory<byte> attestationObject = CtapAuthenticatorMakeCredentialClient.BuildAttestationObject(response, AttestationObjectCborWriter.Write);

        AttestationObjectParts parts = AttestationObjectCborReader.Parse(attestationObject.Memory);

        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.None, parts.Format);
        CollectionAssert.AreEqual(authData, parts.AuthenticatorData.ToArray());
        Assert.AreEqual(1, parts.AttestationStatement.Length);
        Assert.AreEqual(NoneAttestation.CanonicalEmptyMap, parts.AttestationStatement.Span[0]);
    }


    /// <summary>
    /// A response with no attestation statement (<c>attStmt</c> omitted, per CTAP 2.3 section 6.1.2 step
    /// 17's <c>attestationFormatsPreference</c> "omit attestation from the output" instruction) still
    /// translates: the client supplies WebAuthn section 8.7's <c>attStmt: emptyMap</c> in its place, so
    /// the encoded <c>attestationObject</c> round-trips through the shipped
    /// <see cref="AttestationObjectCborReader"/> with the standard <c>none</c>-format shape.
    /// </summary>
    [TestMethod]
    public void BuildAttestationObjectSuppliesEmptyMapAttStmtWhenAttestationStatementIsAbsent()
    {
        byte[] authData = [0x01];
        var response = new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.None, authData, AttStmt: null);

        TaggedMemory<byte> attestationObject = CtapAuthenticatorMakeCredentialClient.BuildAttestationObject(response, AttestationObjectCborWriter.Write);

        AttestationObjectParts parts = AttestationObjectCborReader.Parse(attestationObject.Memory);

        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.None, parts.Format);
        CollectionAssert.AreEqual(authData, parts.AuthenticatorData.ToArray());
        Assert.AreEqual(1, parts.AttestationStatement.Length);
        Assert.AreEqual(NoneAttestation.CanonicalEmptyMap, parts.AttestationStatement.Span[0]);
    }
}
