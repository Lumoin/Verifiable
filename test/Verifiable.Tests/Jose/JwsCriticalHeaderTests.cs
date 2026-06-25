using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests that the JWS verify path enforces the <c>crit</c> (critical header) rule of
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11">RFC 7515 §4.1.11</see> via
/// <see cref="JoseCriticalHeaderValidation"/>: a JWS whose protected header declares a critical
/// extension the consumer does not understand MUST NOT verify, even when its signature is valid. The
/// rule set itself is covered by the JWE header-processing tests (both paths share the validator); this
/// proves the wiring on the JWS side that the consumer-feedback audit found missing.
/// </summary>
[TestClass]
internal sealed class JwsCriticalHeaderTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>Serialises a protected header to UTF-8 JSON bytes.</summary>
    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    /// <summary>Serialises a payload to UTF-8 JSON bytes.</summary>
    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// A validly-signed JWS whose protected header names an unrecognized critical extension does not
    /// verify (RFC 7515 §4.1.11); the otherwise-identical crit-free JWS does verify — so the rejection
    /// is the <c>crit</c> rule, not the signature.
    /// </summary>
    [TestMethod]
    public async Task VerifyRejectsUnrecognizedCriticalExtension()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);
        JwtPayload payload = new() { ["sub"] = "alice" };

        //A JWS whose protected header declares a critical extension this consumer does not understand.
        JwtHeader crittedHeader = JwtHeader.ForSigning(algorithm, WellKnownJwkValues.TypeJwt, "k1");
        crittedHeader["crit"] = new[] { "urn:example:my-extension" };
        crittedHeader["urn:example:my-extension"] = "present";
        string crittedJws = await SignCompactAsync(crittedHeader, payload, privateKey).ConfigureAwait(false);

        bool crittedVerifies = await Jws.VerifyAsync(
            crittedJws, TestSetup.Base64UrlDecoder, Pool, publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(crittedVerifies, "a JWS naming an unrecognized critical extension must not verify (RFC 7515 §4.1.11).");

        //Control: the same payload and key without crit verifies, so the rejection above is the crit
        //rule and not a signing or key-resolution failure.
        JwtHeader plainHeader = JwtHeader.ForSigning(algorithm, WellKnownJwkValues.TypeJwt, "k1");
        string plainJws = await SignCompactAsync(plainHeader, payload, privateKey).ConfigureAwait(false);

        bool plainVerifies = await Jws.VerifyAsync(
            plainJws, TestSetup.Base64UrlDecoder, Pool, publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(plainVerifies, "a crit-free JWS with a valid signature verifies.");
    }


    /// <summary>Signs <paramref name="header"/>/<paramref name="payload"/> into a compact JWS.</summary>
    private async Task<string> SignCompactAsync(JwtHeader header, JwtPayload payload, PrivateKeyMemory privateKey)
    {
        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            privateKey, HeaderSerializer, PayloadSerializer, TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }
}
