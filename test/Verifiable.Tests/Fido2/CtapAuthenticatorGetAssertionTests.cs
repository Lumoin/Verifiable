using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorSimulator"/>'s <c>authenticatorGetAssertion</c> handler, driven
/// over <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>: the full wave-2 error matrix, the
/// <c>allowList</c>/resident credential-location asymmetry, the <c>up</c> pre-flight, and per-credential
/// signature-counter progression verified against an independent <see cref="ECDsa"/> oracle.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorGetAssertionTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clientDataHash bytes <see cref="CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest"/> always embeds — reproduced here for the independent signature oracle.</summary>
    private static byte[] ExpectedClientDataHash => BuildFixedBytes(32, 0x20);


    /// <summary>
    /// An <c>allowList</c> entry matching a registered (non-resident) credential succeeds: the response
    /// carries no <c>user</c> member (CTAP 2.3 section 6.2's response table only updates it on the
    /// resident-lookup branch), and the signed <c>authData</c> is UP-set, AT-clear.
    /// </summary>
    [TestMethod]
    public async Task AllowListMatchSucceedsWithoutUserMember()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-allowlist-match");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] credentialId = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x11), TestContext.CancellationToken, resident: false);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(
            pool, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(credentialId, pool) }]);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        try
        {
            Assert.IsNull(decoded.User);

            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            Assert.IsTrue(authenticatorData.Flags.UserPresent);
            Assert.IsFalse(authenticatorData.Flags.AttestedCredentialDataIncluded);
            Assert.IsNull(authenticatorData.AttestedCredentialData);
            Assert.AreEqual(1u, authenticatorData.SignCount);
        }
        finally
        {
            decoded.Credential.Id.Dispose();
        }
    }


    /// <summary>
    /// An <c>allowList</c>-absent request against a resident credential succeeds via the resident lookup,
    /// and the response's <c>user</c> member carries only <c>id</c> — no <c>name</c>/<c>displayName</c>,
    /// since this simulator never performs user verification.
    /// </summary>
    [TestMethod]
    public async Task ResidentLookupSucceedsWithUserIdOnlyInResponse()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-resident-lookup");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] userId = BuildFixedBytes(16, 0x12);

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, userId, TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        try
        {
            Assert.IsNotNull(decoded.User);
            CollectionAssert.AreEqual(userId, decoded.User!.Id.AsReadOnlySpan().ToArray());
            Assert.IsNull(decoded.User.Name);
            Assert.IsNull(decoded.User.DisplayName);
        }
        finally
        {
            decoded.Credential.Id.Dispose();
            decoded.User?.Id.Dispose();
        }
    }


    /// <summary>
    /// A non-zero-length <c>pinUvAuthParam</c> accompanied by a SUPPORTED <c>pinUvAuthProtocol</c>
    /// passes the CTAP 2.3 §6.2.2 step 2 guard; since no PIN is set on this authenticator, it is NOT
    /// protected by some form of user verification, so the junk param is ignored per step 6's own
    /// structure (line 4025) and the assertion succeeds with the response authData's <c>uv</c> bit
    /// clear.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthParamWithSupportedProtocolAndNoPinSetSucceedsWithUvClear()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-pinuv-with-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x15), TestContext.CancellationToken);

        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(16);
        pinUvAuthParamOwner.Memory.Span[..16].Clear();

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, pinUvAuthParam: pinUvAuthParamOwner.Memory[..16], pinUvAuthProtocol: 1);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        try
        {
            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            Assert.IsFalse(authenticatorData.Flags.UserVerified, "an ignored pinUvAuthParam must never set the uv bit.");
        }
        finally
        {
            decoded.Credential.Id.Dispose();
            decoded.User?.Id.Dispose();
        }
    }


    /// <summary>A non-zero-length <c>pinUvAuthParam</c> accompanied by an UNSUPPORTED <c>pinUvAuthProtocol</c> is rejected with <c>CTAP1_ERR_INVALID_PARAMETER</c> (step 2's reject half).</summary>
    [TestMethod]
    public async Task PinUvAuthParamWithUnsupportedProtocolReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-pinuv-unsupported-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(16);
        pinUvAuthParamOwner.Memory.Span[..16].Clear();

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, pinUvAuthParam: pinUvAuthParamOwner.Memory[..16], pinUvAuthProtocol: 3);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A <c>pinUvAuthParam</c> without an accompanying <c>pinUvAuthProtocol</c> is rejected with <c>CTAP2_ERR_MISSING_PARAMETER</c>.</summary>
    [TestMethod]
    public async Task PinUvAuthParamWithoutProtocolReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-pinuv-without-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> pinUvAuthParamOwner = pool.Rent(16);
        pinUvAuthParamOwner.Memory.Span[..16].Clear();

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, pinUvAuthParam: pinUvAuthParamOwner.Memory[..16]);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>options.uv = true</c> is rejected with <c>CTAP2_ERR_INVALID_OPTION</c> on a fresh simulator
    /// with zero fingerprint enrollments — the built-in UV method is not yet configured
    /// (<see cref="CtapAuthenticatorBuiltInUvTests.GetAssertionLevelThreeCredProtectInvisibleWithoutUvVisibleThroughBuiltInUv"/>
    /// proves the same cluster live, once configured).
    /// </summary>
    [TestMethod]
    public async Task UserVerificationTrueReturnsInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-uv-true");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserVerification: true));
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An <c>rk</c> option key present with value <see langword="true"/> is rejected unconditionally with <c>CTAP2_ERR_UNSUPPORTED_OPTION</c>.</summary>
    [TestMethod]
    public async Task ResidentKeyOptionTrueReturnsUnsupportedOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-rk-true");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(ResidentKey: true));
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.UnsupportedOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An <c>rk</c> option key present with value <see langword="false"/> is ALSO rejected — the spec's rejection is unconditional on presence, not on the value.</summary>
    [TestMethod]
    public async Task ResidentKeyOptionFalseAlsoReturnsUnsupportedOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-rk-false");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(ResidentKey: false));
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.UnsupportedOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An <c>allowList</c>-absent request with no resident credential stored for the rp.id is rejected with <c>CTAP2_ERR_NO_CREDENTIALS</c>.</summary>
    [TestMethod]
    public async Task NoResidentCredentialReturnsNoCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-no-credentials-resident");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An <c>allowList</c> naming a credential ID this authenticator never minted is rejected with <c>CTAP2_ERR_NO_CREDENTIALS</c>.</summary>
    [TestMethod]
    public async Task AllowListWithUnknownCredentialIdReturnsNoCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-no-credentials-allowlist");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] unknownCredentialId = BuildFixedBytes(32, 0x99);
        CtapGetAssertionRequest request = BuildGetAssertionRequest(
            pool, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(unknownCredentialId, pool) }]);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>options.up = false</c> is a legitimate silent pre-flight: no error, and the signed <c>authData</c>'s UP bit is clear.</summary>
    [TestMethod]
    public async Task UserPresenceFalsePreflightSucceedsWithUpClear()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-up-false");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x13), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserPresence: false));
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        try
        {
            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            Assert.IsFalse(authenticatorData.Flags.UserPresent);
        }
        finally
        {
            decoded.Credential.Id.Dispose();
            decoded.User?.Id.Dispose();
        }
    }


    /// <summary>
    /// The signature counter starts at zero at registration, increments by one on every successful
    /// assertion (WebAuthn L3, section 6.1.1), and each returned signature independently verifies with
    /// <see cref="ECDsa"/> against the credential's own public key — never through this library's own
    /// signing/verification seam.
    /// </summary>
    [TestMethod]
    public async Task SignCountIncrementsAndEachSignatureVerifiesIndependently()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("ga-signcount");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] userId = BuildFixedBytes(16, 0x14);

        CtapWave2RegisteredCredential registered = await RegisterCredentialAsync(simulator, pool, userId, TestContext.CancellationToken);
        registered.CredentialId.Dispose();

        byte[] x = registered.PublicKey.X!.Value.ToArray();
        byte[] y = registered.PublicKey.Y!.Value.ToArray();

        //Independent oracle: reconstructs the public key from the wire-exported credential coordinates and
        //verifies the library-produced signature against it, outside the library's own signing/verification seam.
        using ECDsa oracleKey = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });

        for(uint expectedSignCount = 1; expectedSignCount <= 3; expectedSignCount++)
        {
            CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
            using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

            CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
            try
            {
                using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
                Assert.AreEqual(expectedSignCount, authenticatorData.SignCount);

                byte[] message = new byte[decoded.AuthData.Length + ExpectedClientDataHash.Length];
                decoded.AuthData.Span.CopyTo(message);
                ExpectedClientDataHash.CopyTo(message, decoded.AuthData.Length);

                bool verified = oracleKey.VerifyData(message, decoded.Signature.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
                Assert.IsTrue(verified, $"Assertion #{expectedSignCount} did not verify independently.");
            }
            finally
            {
                decoded.Credential.Id.Dispose();
                decoded.User?.Id.Dispose();
            }
        }
    }
}
