using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Jose.SdJwt;
using Verifiable.Json.Converters;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SdJwt;

/// <summary>
/// Tests for <see cref="SdJwtToken"/> parsing and serialization based on RFC 9901.
/// </summary>
[TestClass]
public sealed class SdJwtTokenTests
{
    //RFC 9901 Section 5.1 - Full SD-JWT with all disclosures.
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

    //Individual disclosures from RFC 9901.
    private const string DisclosureGivenName = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";
    private const string DisclosureFamilyName = "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd";
    private const string DisclosureEmail = "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ";
    private const string DisclosureNationalityUs = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0";
    private const string DisclosureNationalityDe = "WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0";

    //RFC 9901 Section 5.2 - KB-JWT.
    private const string Rfc9901KeyBindingJwt =
        "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9." +
        "eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3Jn" +
        "IiwgImlhdCI6IDE3NDg1MzcyNDQsICJzZF9oYXNoIjogIjBfQWYtMkItRWhMV1g1eWRoX3cyeHp3bU82" +
        "aU02NkJfMlFDRWFuSTRmVVkifQ." +
        "T3SIus2OidNl41nmVkTZVCKKhOAX97aOldMyHFiYjHm261eLiJ1YiuONFiMN8QlCmYzDlBLAdPvrXh52" +
        "KaLgUQ";

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
    public void ParseSdJwtWithoutDisclosuresSucceeds()
    {
        string sdJwt = $"{Rfc9901IssuerSignedJwt}~";

        SdJwtToken token = SdJwtTokenJsonConverter.Parse(sdJwt, Decoder, MemoryPool);

        Assert.AreEqual(Rfc9901IssuerSignedJwt, token.IssuerSignedJwt);
        Assert.IsEmpty(token.Disclosures);
        Assert.IsFalse(token.HasKeyBinding);
        Assert.IsNull(token.KeyBindingJwt);
    }


    [TestMethod]
    public void ParseSdJwtWithDisclosuresSucceeds()
    {
        string sdJwt = $"{Rfc9901IssuerSignedJwt}~{DisclosureGivenName}~{DisclosureFamilyName}~";

        SdJwtToken token = SdJwtTokenJsonConverter.Parse(sdJwt, Decoder, MemoryPool);

        Assert.AreEqual(Rfc9901IssuerSignedJwt, token.IssuerSignedJwt);
        Assert.HasCount(2, token.Disclosures);
        Assert.IsFalse(token.HasKeyBinding);

        Assert.AreEqual("given_name", token.Disclosures[0].ClaimName);
        Assert.AreEqual("family_name", token.Disclosures[1].ClaimName);
    }


    [TestMethod]
    public void ParseSdJwtWithManyDisclosuresSucceeds()
    {
        string sdJwt = $"{Rfc9901IssuerSignedJwt}~" +
            $"{DisclosureGivenName}~{DisclosureFamilyName}~{DisclosureEmail}~" +
            $"{DisclosureNationalityUs}~{DisclosureNationalityDe}~";

        SdJwtToken token = SdJwtTokenJsonConverter.Parse(sdJwt, Decoder, MemoryPool);

        Assert.HasCount(5, token.Disclosures);
        Assert.IsFalse(token.HasKeyBinding);
    }


    [TestMethod]
    public void ParseSdJwtWithKeyBindingSucceeds()
    {
        string sdJwtKb = $"{Rfc9901IssuerSignedJwt}~" +
            $"{DisclosureGivenName}~{DisclosureFamilyName}~" +
            $"{Rfc9901KeyBindingJwt}";

        SdJwtToken token = SdJwtTokenJsonConverter.Parse(sdJwtKb, Decoder, MemoryPool);

        Assert.AreEqual(Rfc9901IssuerSignedJwt, token.IssuerSignedJwt);
        Assert.HasCount(2, token.Disclosures);
        Assert.IsTrue(token.HasKeyBinding);
        Assert.AreEqual(Rfc9901KeyBindingJwt, token.KeyBindingJwt);
    }


    [TestMethod]
    public void ParseSdJwtWithKeyBindingNoDisclosuresSucceeds()
    {
        string sdJwtKb = $"{Rfc9901IssuerSignedJwt}~{Rfc9901KeyBindingJwt}";

        SdJwtToken token = SdJwtTokenJsonConverter.Parse(sdJwtKb, Decoder, MemoryPool);

        Assert.IsEmpty(token.Disclosures);
        Assert.IsTrue(token.HasKeyBinding);
        Assert.AreEqual(Rfc9901KeyBindingJwt, token.KeyBindingJwt);
    }


    [TestMethod]
    public void SerializeSdJwtWithoutDisclosuresProducesValidFormat()
    {
        var token = new SdJwtToken(Rfc9901IssuerSignedJwt, []);

        string serialized = token.Serialize();

        Assert.AreEqual($"{Rfc9901IssuerSignedJwt}~", serialized);
        Assert.EndsWith("~", serialized);
    }


    [TestMethod]
    public void SerializeSdJwtWithDisclosuresProducesValidFormat()
    {
        Disclosure d1 = ParseDisclosure(DisclosureGivenName);
        Disclosure d2 = ParseDisclosure(DisclosureFamilyName);

        var token = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1, d2]);

        string serialized = token.Serialize();

        Assert.AreEqual($"{Rfc9901IssuerSignedJwt}~{DisclosureGivenName}~{DisclosureFamilyName}~", serialized);
        Assert.EndsWith("~", serialized);
    }


    [TestMethod]
    public void SerializeSdJwtWithKeyBindingProducesValidFormat()
    {
        Disclosure d1 = ParseDisclosure(DisclosureGivenName);

        var token = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1], Rfc9901KeyBindingJwt);

        string serialized = token.Serialize();

        Assert.AreEqual($"{Rfc9901IssuerSignedJwt}~{DisclosureGivenName}~{Rfc9901KeyBindingJwt}", serialized);
        Assert.DoesNotEndWith("~", serialized);
    }


    [TestMethod]
    public void RoundTripSdJwtPreservesAllData()
    {
        Disclosure d1 = ParseDisclosure(DisclosureGivenName);
        Disclosure d2 = ParseDisclosure(DisclosureFamilyName);

        var original = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1, d2]);
        string serialized = original.Serialize();

        SdJwtToken parsed = SdJwtTokenJsonConverter.Parse(serialized, Decoder, MemoryPool);

        Assert.AreEqual(original.IssuerSignedJwt, parsed.IssuerSignedJwt);
        Assert.HasCount(original.Disclosures.Count, parsed.Disclosures);
        Assert.AreEqual(original.HasKeyBinding, parsed.HasKeyBinding);

        for(int i = 0; i < original.Disclosures.Count; i++)
        {
            Assert.AreEqual(original.Disclosures[i].EncodedValue, parsed.Disclosures[i].EncodedValue);
        }
    }


    [TestMethod]
    public void RoundTripSdJwtKbPreservesAllData()
    {
        Disclosure d1 = ParseDisclosure(DisclosureGivenName);

        var original = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1], Rfc9901KeyBindingJwt);
        string serialized = original.Serialize();

        SdJwtToken parsed = SdJwtTokenJsonConverter.Parse(serialized, Decoder, MemoryPool);

        Assert.AreEqual(original.IssuerSignedJwt, parsed.IssuerSignedJwt);
        Assert.HasCount(original.Disclosures.Count, parsed.Disclosures);
        Assert.AreEqual(original.KeyBindingJwt, parsed.KeyBindingJwt);
    }


    [TestMethod]
    public void SelectDisclosuresCreatesNewTokenWithSubset()
    {
        Disclosure d1 = ParseDisclosure(DisclosureGivenName);
        Disclosure d2 = ParseDisclosure(DisclosureFamilyName);
        Disclosure d3 = ParseDisclosure(DisclosureEmail);

        var original = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1, d2, d3]);

        SdJwtToken selected = original.SelectDisclosures([d1, d3]);

        Assert.HasCount(2, selected.Disclosures);
        Assert.IsTrue(selected.Disclosures.Contains(d1));
        Assert.IsTrue(selected.Disclosures.Contains(d3));
        Assert.IsFalse(selected.Disclosures.Contains(d2));
        Assert.IsFalse(selected.HasKeyBinding);
    }


    [TestMethod]
    public void SelectDisclosuresThrowsForUnknownDisclosure()
    {
        Disclosure d1 = ParseDisclosure(DisclosureGivenName);
        Disclosure d2 = ParseDisclosure(DisclosureFamilyName);

        var token = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1]);

        Assert.Throws<ArgumentException>(() => token.SelectDisclosures([d2]));
    }


    [TestMethod]
    public void WithKeyBindingAddsKbJwt()
    {
        Disclosure d1 = ParseDisclosure(DisclosureGivenName);

        var original = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1]);
        Assert.IsFalse(original.HasKeyBinding);

        SdJwtToken withKb = original.WithKeyBinding(Rfc9901KeyBindingJwt);

        Assert.IsTrue(withKb.HasKeyBinding);
        Assert.AreEqual(Rfc9901KeyBindingJwt, withKb.KeyBindingJwt);
        Assert.HasCount(original.Disclosures.Count, withKb.Disclosures);
    }


    [TestMethod]
    public void WithKeyBindingThrowsForInvalidJwt()
    {
        var token = new SdJwtToken(Rfc9901IssuerSignedJwt, []);

        Assert.Throws<ArgumentException>(() => token.WithKeyBinding("not-a-jwt"));
    }


    [TestMethod]
    public void GetSdJwtForHashingReturnsCorrectFormat()
    {
        Disclosure d1 = ParseDisclosure(DisclosureGivenName);
        Disclosure d2 = ParseDisclosure(DisclosureFamilyName);

        var token = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1, d2]);

        string forHashing = token.GetSdJwtForHashing();

        //Should end with tilde and not include any KB-JWT.
        Assert.EndsWith("~", forHashing);
        Assert.AreEqual($"{Rfc9901IssuerSignedJwt}~{DisclosureGivenName}~{DisclosureFamilyName}~", forHashing);
    }


    [TestMethod]
    public void GetSdJwtForHashingExcludesKbJwt()
    {
        Disclosure d1 = ParseDisclosure(DisclosureGivenName);

        var tokenWithKb = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1], Rfc9901KeyBindingJwt);

        string forHashing = tokenWithKb.GetSdJwtForHashing();

        Assert.DoesNotContain(Rfc9901KeyBindingJwt, forHashing);
        Assert.EndsWith("~", forHashing);
    }


    [TestMethod]
    public void ParseInvalidJwtThrows()
    {
        Assert.Throws<ArgumentException>(() =>
            SdJwtTokenJsonConverter.Parse("not-a-jwt~", Decoder, MemoryPool));
    }


    [TestMethod]
    public void ParseMissingSeparatorThrows()
    {
        Assert.Throws<ArgumentException>(() =>
            SdJwtTokenJsonConverter.Parse(Rfc9901IssuerSignedJwt, Decoder, MemoryPool));
    }


    [TestMethod]
    public void TryParseReturnsFalseForInvalidInput()
    {
        bool result = SdJwtTokenJsonConverter.TryParse("invalid", Decoder, MemoryPool, out SdJwtToken? token);

        Assert.IsFalse(result);
        Assert.IsNull(token);
    }


    [TestMethod]
    public void TryParseReturnsTrueForValidInput()
    {
        string sdJwt = $"{Rfc9901IssuerSignedJwt}~";

        bool result = SdJwtTokenJsonConverter.TryParse(sdJwt, Decoder, MemoryPool, out SdJwtToken? token);

        Assert.IsTrue(result);
        Assert.IsNotNull(token);
    }


    [TestMethod]
    public void SdJwtTokenEqualityWorksCorrectly()
    {
        Disclosure d1 = ParseDisclosure(DisclosureGivenName);

        var token1 = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1]);
        var token2 = new SdJwtToken(Rfc9901IssuerSignedJwt, [d1]);
        var token3 = new SdJwtToken(Rfc9901IssuerSignedJwt, []);

        Assert.AreEqual(token1, token2);
        Assert.AreNotEqual(token1, token3);
        Assert.IsTrue(token1 == token2);
        Assert.IsTrue(token1 != token3);
    }
}