using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Jose;
using Verifiable.Jose.SdJwt;
using Verifiable.Json;
using Verifiable.Json.Converters;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SdJwt;

/// <summary>
/// Tests for <see cref="KeyBindingJwt"/> based on RFC 9901 Section 4.3 and 5.2.
/// </summary>
[TestClass]
public sealed class KeyBindingJwtTests
{
    //RFC 9901 Section 5.2 KB-JWT payload.
    private const string Rfc9901Nonce = "1234567890";
    private const string Rfc9901Audience = "https://verifier.example.org";
    private const long Rfc9901Iat = 1748537244;
    private const string Rfc9901SdHash = "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY";

    //RFC 9901 Section 5.2 - Complete KB-JWT.
    private const string Rfc9901KeyBindingJwtString =
        "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9." +
        "eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3Jn" +
        "IiwgImlhdCI6IDE3NDg1MzcyNDQsICJzZF9oYXNoIjogIjBfQWYtMkItRWhMV1g1eWRoX3cyeHp3bU82" +
        "aU02NkJfMlFDRWFuSTRmVVkifQ." +
        "T3SIus2OidNl41nmVkTZVCKKhOAX97aOldMyHFiYjHm261eLiJ1YiuONFiMN8QlCmYzDlBLAdPvrXh52" +
        "KaLgUQ";

    //Issuer-signed JWT from RFC 9901 Section 5.1.
    private const string Rfc9901IssuerSignedJwt =
        "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0." +
        "eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ" +
        "akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUph" +
        "Z3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1" +
        "cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JN" +
        "TSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVk" +
        "cTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6" +
        "TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29t" +
        "IiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAi" +
        "bmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5" +
        "RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtC" +
        "SnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIs" +
        "ICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2" +
        "Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9" +
        "fX0.MczwjBFGtzf-6WMT-hIvYbkb11NrV1WMO-jTijpMPNbswNzZ87wY2uHz-CXo6R04b7jYrpj9mNRA" +
        "vVssXou1iw";

    //Disclosures from RFC 9901 Section 5.2 presentation.
    private const string DisclosureFamilyName = "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd";
    private const string DisclosureAddress = "WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0";
    private const string DisclosureGivenName = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";
    private const string DisclosureNationalityUs = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0";

    private static MemoryPool<byte> MemoryPool => SensitiveMemoryPool<byte>.Shared;
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;


    private static Disclosure ParseDisclosure(string encoded)
    {
        var converter = new DisclosureJsonConverter(Encoder, Decoder, MemoryPool);
        var reader = new System.Text.Json.Utf8JsonReader(Encoding.UTF8.GetBytes($"\"{encoded}\""));
        reader.Read();
        return converter.Read(ref reader, typeof(Disclosure), null!)!;
    }


    [TestMethod]
    public void ParseKeyBindingJwtFromRfc9901Succeeds()
    {
        (Dictionary<string, object> header, Dictionary<string, object> payload) =
            KeyBindingJwtJsonExtensions.ParseToDictionary(Rfc9901KeyBindingJwtString, Decoder, MemoryPool);

        //Verify header.
        Assert.AreEqual("ES256", header[JwkProperties.Alg]);
        Assert.AreEqual("kb+jwt", header[JwkProperties.Typ]);

        //Verify payload.
        Assert.AreEqual(Rfc9901Nonce, payload[SdJwtConstants.NonceClaim]);
        Assert.AreEqual(Rfc9901Audience, payload[WellKnownJwtClaims.Aud]);
        Assert.AreEqual(Rfc9901Iat, payload[WellKnownJwtClaims.Iat]);
        Assert.AreEqual(Rfc9901SdHash, payload[SdJwtConstants.SdHashClaimName]);
    }


    [TestMethod]
    public void CreateHeaderProducesCorrectFormat()
    {
        Dictionary<string, object> header = KeyBindingJwt.CreateHeader("ES256");

        Assert.AreEqual("ES256", header[JwkProperties.Alg]);
        Assert.AreEqual("kb+jwt", header[JwkProperties.Typ]);
    }


    [TestMethod]
    public void CreatePayloadProducesCorrectFormat()
    {
        Disclosure d1 = ParseDisclosure(DisclosureFamilyName);
        Disclosure d2 = ParseDisclosure(DisclosureAddress);
        Disclosure d3 = ParseDisclosure(DisclosureGivenName);
        Disclosure d4 = ParseDisclosure(DisclosureNationalityUs);

        var sdJwtToken = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1, d2, d3, d4]);

        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(Rfc9901Iat);

        Dictionary<string, object> payload = KeyBindingJwt.CreatePayload(
            sdJwtToken,
            Rfc9901Audience,
            Rfc9901Nonce,
            issuedAt,
            SdJwtConstants.DefaultHashAlgorithm,
            Encoder);

        Assert.AreEqual(Rfc9901Iat, payload[WellKnownJwtClaims.Iat]);
        Assert.AreEqual(Rfc9901Audience, payload[WellKnownJwtClaims.Aud]);
        Assert.AreEqual(Rfc9901Nonce, payload[SdJwtConstants.NonceClaim]);
        Assert.IsTrue(payload.ContainsKey(SdJwtConstants.SdHashClaimName));
    }


    [TestMethod]
    public void ComputeSdHashMatchesRfc9901()
    {
        //The RFC 9901 Section 5.2 example uses these 4 disclosures.
        Disclosure d1 = ParseDisclosure(DisclosureFamilyName);
        Disclosure d2 = ParseDisclosure(DisclosureAddress);
        Disclosure d3 = ParseDisclosure(DisclosureGivenName);
        Disclosure d4 = ParseDisclosure(DisclosureNationalityUs);

        var sdJwtToken = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1, d2, d3, d4]);

        string sdHash = sdJwtToken.ComputeSdHash(SdJwtConstants.DefaultHashAlgorithm, Encoder);

        Assert.AreEqual(Rfc9901SdHash, sdHash);
    }


    [TestMethod]
    public void ValidateSdHashReturnsTrueForMatchingHash()
    {
        Disclosure d1 = ParseDisclosure(DisclosureFamilyName);
        Disclosure d2 = ParseDisclosure(DisclosureAddress);
        Disclosure d3 = ParseDisclosure(DisclosureGivenName);
        Disclosure d4 = ParseDisclosure(DisclosureNationalityUs);

        var sdJwtToken = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1, d2, d3, d4]);

        (_, Dictionary<string, object> payload) =
            KeyBindingJwtJsonExtensions.ParseToDictionary(Rfc9901KeyBindingJwtString, Decoder, MemoryPool);

        bool isValid = KeyBindingJwt.ValidateSdHash(
            payload,
            sdJwtToken,
            SdJwtConstants.DefaultHashAlgorithm,
            Encoder);

        Assert.IsTrue(isValid);
    }


    [TestMethod]
    public void ValidateSdHashReturnsFalseForMismatchedHash()
    {
        //Use different disclosures than what was used to create the KB-JWT.
        Disclosure d1 = ParseDisclosure(DisclosureFamilyName);

        var sdJwtToken = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1]);

        (_, Dictionary<string, object> payload) =
            KeyBindingJwtJsonExtensions.ParseToDictionary(Rfc9901KeyBindingJwtString, Decoder, MemoryPool);

        bool isValid = KeyBindingJwt.ValidateSdHash(
            payload,
            sdJwtToken,
            SdJwtConstants.DefaultHashAlgorithm,
            Encoder);

        Assert.IsFalse(isValid);
    }


    [TestMethod]
    public void ValidateClaimsReturnsValidForCorrectPayload()
    {
        (_, Dictionary<string, object> payload) =
            KeyBindingJwtJsonExtensions.ParseToDictionary(Rfc9901KeyBindingJwtString, Decoder, MemoryPool);

        //Use a time provider that returns a time after the iat.
        var timeProvider = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(Rfc9901Iat + 60));

        KeyBindingValidationResult result = KeyBindingJwt.ValidateClaims(
            payload,
            Rfc9901Audience,
            Rfc9901Nonce,
            timeProvider,
            TimeSpan.FromMinutes(5));

        Assert.AreEqual(KeyBindingValidationResult.Valid, result);
    }


    [TestMethod]
    public void ValidateClaimsReturnsAudienceMismatchForWrongAudience()
    {
        (_, Dictionary<string, object> payload) =
            KeyBindingJwtJsonExtensions.ParseToDictionary(Rfc9901KeyBindingJwtString, Decoder, MemoryPool);

        var timeProvider = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(Rfc9901Iat + 60));

        KeyBindingValidationResult result = KeyBindingJwt.ValidateClaims(
            payload,
            "https://wrong-verifier.example.org",
            Rfc9901Nonce,
            timeProvider,
            TimeSpan.FromMinutes(5));

        Assert.AreEqual(KeyBindingValidationResult.AudienceMismatch, result);
    }


    [TestMethod]
    public void ValidateClaimsReturnsNonceMismatchForWrongNonce()
    {
        (_, Dictionary<string, object> payload) =
            KeyBindingJwtJsonExtensions.ParseToDictionary(Rfc9901KeyBindingJwtString, Decoder, MemoryPool);

        var timeProvider = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(Rfc9901Iat + 60));

        KeyBindingValidationResult result = KeyBindingJwt.ValidateClaims(
            payload,
            Rfc9901Audience,
            "wrong-nonce",
            timeProvider,
            TimeSpan.FromMinutes(5));

        Assert.AreEqual(KeyBindingValidationResult.NonceMismatch, result);
    }


    [TestMethod]
    public void ValidateClaimsReturnsIatInFutureForFutureTimestamp()
    {
        (_, Dictionary<string, object> payload) =
            KeyBindingJwtJsonExtensions.ParseToDictionary(Rfc9901KeyBindingJwtString, Decoder, MemoryPool);

        //Use a time provider that returns a time before the iat (past the allowed skew).
        var timeProvider = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(Rfc9901Iat - 600));

        KeyBindingValidationResult result = KeyBindingJwt.ValidateClaims(
            payload,
            Rfc9901Audience,
            Rfc9901Nonce,
            timeProvider,
            TimeSpan.FromMinutes(5));

        Assert.AreEqual(KeyBindingValidationResult.IatInFuture, result);
    }


    [TestMethod]
    public void ValidateClaimsSkipsAudienceCheckWhenNull()
    {
        (_, Dictionary<string, object> payload) =
            KeyBindingJwtJsonExtensions.ParseToDictionary(Rfc9901KeyBindingJwtString, Decoder, MemoryPool);

        var timeProvider = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(Rfc9901Iat + 60));

        KeyBindingValidationResult result = KeyBindingJwt.ValidateClaims(
            payload,
            expectedAudience: null,
            Rfc9901Nonce,
            timeProvider,
            TimeSpan.FromMinutes(5));

        Assert.AreEqual(KeyBindingValidationResult.Valid, result);
    }


    [TestMethod]
    public void ValidateClaimsSkipsNonceCheckWhenNull()
    {
        (_, Dictionary<string, object> payload) =
            KeyBindingJwtJsonExtensions.ParseToDictionary(Rfc9901KeyBindingJwtString, Decoder, MemoryPool);

        var timeProvider = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(Rfc9901Iat + 60));

        KeyBindingValidationResult result = KeyBindingJwt.ValidateClaims(
            payload,
            Rfc9901Audience,
            expectedNonce: null,
            timeProvider,
            TimeSpan.FromMinutes(5));

        Assert.AreEqual(KeyBindingValidationResult.Valid, result);
    }


    [TestMethod]
    public void ParseThrowsForInvalidTypHeader()
    {
        string invalidKbJwt = CreateJwtWithTyp("wrong+typ");

        Assert.Throws<ArgumentException>(() =>
            KeyBindingJwtJsonExtensions.ParseToDictionary(invalidKbJwt, Decoder, MemoryPool));
    }


    [TestMethod]
    public void IsValidJwtStructureReturnsTrueForValidJwt()
    {
        Assert.IsTrue(KeyBindingJwt.IsValidJwtStructure(Rfc9901KeyBindingJwtString));
    }


    [TestMethod]
    public void IsValidJwtStructureReturnsFalseForInvalidJwt()
    {
        Assert.IsFalse(KeyBindingJwt.IsValidJwtStructure("not-a-jwt"));
        Assert.IsFalse(KeyBindingJwt.IsValidJwtStructure("a.b"));
        Assert.IsFalse(KeyBindingJwt.IsValidJwtStructure("a.b.c.d"));
        Assert.IsFalse(KeyBindingJwt.IsValidJwtStructure(""));
    }


    private static string CreateJwtWithTyp(string typ)
    {
        string header = Encoder(Encoding.UTF8.GetBytes(/*lang=json,strict*/ $"{{\"alg\":\"ES256\",\"typ\":\"{typ}\"}}"));
        string payload = Encoder(Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"iat\":12345}"));
        string signature = Encoder(new byte[64]);

        return $"{header}.{payload}.{signature}";
    }


    /// <summary>
    /// A fake time provider for testing time-dependent validation.
    /// </summary>
    private sealed class FakeTimeProvider: TimeProvider
    {
        private readonly DateTimeOffset utcNow;

        public FakeTimeProvider(DateTimeOffset utcNow)
        {
            this.utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}