using Microsoft.Extensions.Time.Testing;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the authorization server's check of a <c>client_secret_jwt</c> assertion's MAC
/// (<see cref="ClientSecretAssertionVerification"/>) against the client's one composition
/// (<see cref="ClientAssertionCredential.OfClientSecret"/> through <see cref="ClientAssertionSigning"/>): an assertion the
/// composition MACed verifies under the same secret and algorithm, and every other assertion is refused typed - another
/// secret's, one whose payload or MAC changed, one under an algorithm that is no HMAC algorithm, one checked under a secret
/// shorter than the hash output, and one that is no compact JWS.
/// </summary>
[TestClass]
internal sealed class ClientSecretAssertionVerificationTests
{
    /// <summary>The test context, carrying the cancellation token every call observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the assertions' claims are computed from.</summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>The pool every buffer is rented from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The client identifier the assertions name.</summary>
    private const string ClientId = "https://client.example.com";

    /// <summary>The token endpoint the assertions are audienced at.</summary>
    private const string TokenEndpoint = "https://as.example.com/token";

    /// <summary>A secret of 64 octets, long enough for every HMAC algorithm of RFC 7518 Section 3.2.</summary>
    private const string LongClientSecret = "client-secret-the-authorization-server-issued-0123456789abcdefgh";

    /// <summary>Another secret of 64 octets, the one an assertion is checked under when it was MACed under the first.</summary>
    private const string AnotherClientSecret = "another-secret-the-authorization-server-issued-0123456789abcdefg";

    /// <summary>Serializes a protected header.</summary>
    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    /// <summary>Serializes a claims set.</summary>
    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// The round trip: an assertion the client's composition MACed under a secret verifies under that secret and algorithm,
    /// for each of RFC 7518 Section 3.2's three algorithms, and the verdict names the algorithm.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm.</param>
    [TestMethod]
    [DataRow("HS256")]
    [DataRow("HS384")]
    [DataRow("HS512")]
    public async Task AnAssertionTheCompositionMacedVerifiesUnderItsSecret(string algorithm)
    {
        using var secret = SecretOf(LongClientSecret);
        var assertion = await ComposeAsync(secret, algorithm).ConfigureAwait(false);

        var verdict = await VerifyAsync(assertion, secret, algorithm).ConfigureAwait(false);

        Assert.IsTrue(verdict.IsSuccess, "The composition's own MAC verifies under its secret.");
        Assert.AreEqual(algorithm, verdict.Value);
    }


    /// <summary>
    /// RFC 7523 Section 3 item 9: an assertion MACed under one secret is refused under another of the same length, typed
    /// <see cref="ClientAssertionCredentialRefusalReason.MacDoesNotVerify"/> naming the algorithm.
    /// </summary>
    [TestMethod]
    public async Task AnAssertionUnderAnotherSecretIsRefused()
    {
        using var secret = SecretOf(LongClientSecret);
        using var another = SecretOf(AnotherClientSecret);
        var assertion = await ComposeAsync(secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);

        var verdict = await VerifyAsync(assertion, another, WellKnownJwaValues.Hs256).ConfigureAwait(false);

        Assert.IsFalse(verdict.IsSuccess, "Another secret verifies no MAC of this one.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.MacDoesNotVerify, verdict.Error.Reason);
        Assert.AreEqual(WellKnownJwaValues.Hs256, verdict.Error.Algorithm);
    }


    /// <summary>
    /// The MAC covers the signing input: an assertion whose payload segment is another one's, or whose MAC lost an octet or
    /// carries an extra one, is refused <see cref="ClientAssertionCredentialRefusalReason.MacDoesNotVerify"/>, while the
    /// assertion itself still verifies, so each refusal is the change's.
    /// </summary>
    [TestMethod]
    public async Task AnAssertionWhosePayloadOrMacChangedIsRefused()
    {
        using var secret = SecretOf(LongClientSecret);
        var assertion = await ComposeAsync(secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);
        var other = await ComposeAsync(secret, WellKnownJwaValues.Hs256, "another-jti").ConfigureAwait(false);
        var parts = assertion.Split('.');
        var otherParts = other.Split('.');
        var macOctets = TestSetup.Base64UrlDecoder(parts[2], Pool);
        var mac = macOctets.Memory.Span[..32].ToArray();
        macOctets.Dispose();

        string[] changed =
        [
            $"{parts[0]}.{otherParts[1]}.{parts[2]}",
            $"{parts[0]}.{parts[1]}.{TestSetup.Base64UrlEncoder(mac.AsSpan(0, 31))}",
            $"{parts[0]}.{parts[1]}.{TestSetup.Base64UrlEncoder([.. mac, 0])}"
        ];

        Assert.IsTrue((await VerifyAsync(assertion, secret, WellKnownJwaValues.Hs256).ConfigureAwait(false)).IsSuccess);

        foreach(var candidate in changed)
        {
            var verdict = await VerifyAsync(candidate, secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);

            Assert.IsFalse(verdict.IsSuccess, $"The changed assertion '{candidate}' carries no MAC of its signing input.");
            Assert.AreEqual(ClientAssertionCredentialRefusalReason.MacDoesNotVerify, verdict.Error.Reason);
        }
    }


    /// <summary>
    /// A value that is no compact JWS of three base64url segments carries no MAC: two segments, four, an empty header, a
    /// segment outside the alphabet, padding, an empty signature and a value past <see cref="Jws.DefaultMaxJwsLength"/> are
    /// each refused <see cref="ClientAssertionCredentialRefusalReason.MacDoesNotVerify"/> and none throws.
    /// </summary>
    [TestMethod]
    public async Task AValueThatIsNoCompactJwsIsRefusedWithoutThrowing()
    {
        using var secret = SecretOf(LongClientSecret);
        var assertion = await ComposeAsync(secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);
        var parts = assertion.Split('.');

        string[] malformed =
        [
            $"{parts[0]}.{parts[1]}",
            $"{parts[0]}.{parts[1]}.{parts[2]}.{parts[2]}",
            $".{parts[1]}.{parts[2]}",
            $"{parts[0]}.{parts[1]}.",
            $"{parts[0]}é.{parts[1]}.{parts[2]}",
            $"{parts[0]}.{parts[1]}.{parts[2]}=",
            $"{parts[0]}.{parts[1]}.{parts[2]}+",
            $"{parts[0]}.{new string('A', Jws.DefaultMaxJwsLength)}.{parts[2]}"
        ];

        foreach(var candidate in malformed)
        {
            var verdict = await VerifyAsync(candidate, secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);

            Assert.IsFalse(verdict.IsSuccess, "A value that is no compact JWS verifies nothing.");
            Assert.AreEqual(ClientAssertionCredentialRefusalReason.MacDoesNotVerify, verdict.Error.Reason);
        }
    }


    /// <summary>
    /// RFC 7518 Section 3.2: the check refuses a secret shorter than the algorithm's hash output before any MAC is computed,
    /// typed <see cref="ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput"/> carrying the octets the
    /// secret carries and the octets the algorithm needs; a secret of exactly the hash output's length is checked.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <param name="hashOutputLength">Its hash output's length in octets.</param>
    [TestMethod]
    [DataRow("HS256", 32)]
    [DataRow("HS384", 48)]
    [DataRow("HS512", 64)]
    public async Task ASecretShorterThanTheHashOutputIsRefusedBeforeAnyMac(string algorithm, int hashOutputLength)
    {
        using var sufficient = SecretOf(new string('s', hashOutputLength));
        using var shortSecret = SecretOf(new string('s', hashOutputLength - 1));
        var assertion = await ComposeAsync(sufficient, algorithm).ConfigureAwait(false);

        var refused = await VerifyAsync(assertion, shortSecret, algorithm).ConfigureAwait(false);

        Assert.IsFalse(refused.IsSuccess, "A secret shorter than the hash output keys no MAC.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput, refused.Error.Reason);
        Assert.AreEqual(hashOutputLength - 1, refused.Error.SecretOctets);
        Assert.AreEqual(hashOutputLength, refused.Error.RequiredOctets);

        Assert.IsTrue((await VerifyAsync(assertion, sufficient, algorithm).ConfigureAwait(false)).IsSuccess);
    }


    /// <summary>
    /// The check MACs under an HMAC algorithm of RFC 7518 Section 3.2 alone: a signature algorithm and <c>none</c> are refused
    /// <see cref="ClientAssertionCredentialRefusalReason.AlgorithmIsNotAnHmac"/>, naming the algorithm, whatever the
    /// assertion carries; and an assertion MACed under one HMAC algorithm does not verify under another.
    /// </summary>
    /// <param name="algorithm">An algorithm none of the HMAC algorithms names.</param>
    [TestMethod]
    [DataRow("RS256")]
    [DataRow("ES256")]
    [DataRow("none")]
    public async Task AnAlgorithmThatIsNoHmacIsRefused(string algorithm)
    {
        using var secret = SecretOf(LongClientSecret);
        var assertion = await ComposeAsync(secret, WellKnownJwaValues.Hs256).ConfigureAwait(false);

        var refused = await VerifyAsync(assertion, secret, algorithm).ConfigureAwait(false);

        Assert.IsFalse(refused.IsSuccess, "Only an HMAC algorithm verifies a client secret assertion.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.AlgorithmIsNotAnHmac, refused.Error.Reason);
        Assert.AreEqual(algorithm, refused.Error.Algorithm);

        var otherHmac = await VerifyAsync(assertion, secret, WellKnownJwaValues.Hs512).ConfigureAwait(false);
        Assert.IsFalse(otherHmac.IsSuccess, "An HS256 MAC is no HS512 MAC.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.MacDoesNotVerify, otherHmac.Error.Reason);
    }


    /// <summary>Composes an assertion through the client's one composition under a secret and an algorithm.</summary>
    /// <param name="secret">The secret.</param>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <returns>The compact assertion.</returns>
    private ValueTask<string> ComposeAsync(PrivateKeyMemory secret, string algorithm) =>
        ComposeAsync(secret, algorithm, "secret-assertion-jti");


    /// <summary>Composes an assertion through the client's one composition under a secret, an algorithm and an identifier.</summary>
    /// <param name="secret">The secret.</param>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <param name="jti">The assertion's identifier.</param>
    /// <returns>The compact assertion.</returns>
    private async ValueTask<string> ComposeAsync(PrivateKeyMemory secret, string algorithm, string jti)
    {
        var key = ClientAssertionCredential.OfClientSecret(secret, algorithm);
        Assert.IsTrue(key.IsSuccess, "The secret keys the algorithm.");

        var now = TimeProvider.GetUtcNow();

        return await ClientAssertionSigning.SignAsync(
            ClientId,
            TokenEndpoint,
            jti,
            now,
            now.AddMinutes(1),
            key.Value,
            WellKnownJwkValues.TypeJwt,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Checks an assertion's MAC under a secret and an algorithm.</summary>
    /// <param name="assertion">The assertion.</param>
    /// <param name="secret">The secret.</param>
    /// <param name="algorithm">The algorithm judged.</param>
    /// <returns>The verdict.</returns>
    private ValueTask<Result<string, ClientAssertionCredentialRefusal>> VerifyAsync(string assertion, PrivateKeyMemory secret, string algorithm) =>
        ClientSecretAssertionVerification.VerifyAsync(
            assertion, secret, algorithm, TestSetup.Base64UrlDecoder, Pool, context: null, TestContext.CancellationToken);


    /// <summary>A client secret's UTF-8 octets as the library carries one, untagged, in pooled memory the caller disposes.</summary>
    /// <param name="secret">The secret.</param>
    /// <returns>The key holding the octets.</returns>
    private static PrivateKeyMemory SecretOf(string secret)
    {
        var octets = Encoding.UTF8.GetBytes(secret);
        var owner = Pool.Rent(octets.Length);
        octets.CopyTo(owner.Memory.Span);

        return new PrivateKeyMemory(owner, Tag.Empty);
    }
}
