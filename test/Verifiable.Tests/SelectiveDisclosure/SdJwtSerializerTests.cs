using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose.Sd;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for <see cref="SdJwtSerializer"/> based on RFC 9901.
/// </summary>
[TestClass]
internal sealed class SdJwtSerializerTests
{
    private static MemoryPool<byte> MemoryPool => SensitiveMemoryPool<byte>.Shared;
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;

    /// <summary>
    /// RFC 9901 Section 5.1 - Issuer-signed JWT.
    /// </summary>
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

    /// <summary>
    /// RFC 9901 disclosures - Base64Url encoded.
    /// </summary>
    private const string DisclosureGivenName = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";
    private const string DisclosureFamilyName = "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd";
    private const string DisclosureEmail = "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ";
    private const string DisclosureNationalityUs = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0";
    private const string DisclosureNationalityDe = "WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0";

    /// <summary>
    /// RFC 9901 Section 5.2 - KB-JWT.
    /// </summary>
    private const string Rfc9901KeyBindingJwt =
        "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9." +
        "eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3Jn" +
        "IiwgImlhdCI6IDE3NDg1MzcyNDQsICJzZF9oYXNoIjogIjBfQWYtMkItRWhMV1g1eWRoX3cyeHp3bU82" +
        "aU02NkJfMlFDRWFuSTRmVVkifQ." +
        "T3SIus2OidNl41nmVkTZVCKKhOAX97aOldMyHFiYjHm261eLiJ1YiuONFiMN8QlCmYzDlBLAdPvrXh52" +
        "KaLgUQ";


    [TestMethod]
    public void ParseSdJwtWithoutDisclosuresSucceeds()
    {
        string sdJwt = $"{Rfc9901IssuerSignedJwt}~";

        SdToken<string> token = SdJwtSerializer.ParseToken(sdJwt, Decoder, MemoryPool);

        Assert.AreEqual(Rfc9901IssuerSignedJwt, token.IssuerSigned);
        Assert.IsEmpty(token.Disclosures);
        Assert.IsFalse(token.HasKeyBinding);
        Assert.IsNull(token.KeyBinding);
    }


    [TestMethod]
    public void ParseSdJwtWithDisclosuresSucceeds()
    {
        string sdJwt = $"{Rfc9901IssuerSignedJwt}~{DisclosureGivenName}~{DisclosureFamilyName}~";

        SdToken<string> token = SdJwtSerializer.ParseToken(sdJwt, Decoder, MemoryPool);

        Assert.AreEqual(Rfc9901IssuerSignedJwt, token.IssuerSigned);
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

        SdToken<string> token = SdJwtSerializer.ParseToken(sdJwt, Decoder, MemoryPool);

        Assert.HasCount(5, token.Disclosures);
        Assert.IsFalse(token.HasKeyBinding);
    }


    [TestMethod]
    public void ParseSdJwtWithKeyBindingSucceeds()
    {
        string sdJwtKb = $"{Rfc9901IssuerSignedJwt}~" +
            $"{DisclosureGivenName}~{DisclosureFamilyName}~" +
            $"{Rfc9901KeyBindingJwt}";

        SdToken<string> token = SdJwtSerializer.ParseToken(sdJwtKb, Decoder, MemoryPool);

        Assert.AreEqual(Rfc9901IssuerSignedJwt, token.IssuerSigned);
        Assert.HasCount(2, token.Disclosures);
        Assert.IsTrue(token.HasKeyBinding);
        Assert.AreEqual(Rfc9901KeyBindingJwt, token.KeyBinding);
    }


    [TestMethod]
    public void ParseSdJwtWithKeyBindingNoDisclosuresSucceeds()
    {
        string sdJwtKb = $"{Rfc9901IssuerSignedJwt}~{Rfc9901KeyBindingJwt}";

        SdToken<string> token = SdJwtSerializer.ParseToken(sdJwtKb, Decoder, MemoryPool);

        Assert.IsEmpty(token.Disclosures);
        Assert.IsTrue(token.HasKeyBinding);
        Assert.AreEqual(Rfc9901KeyBindingJwt, token.KeyBinding);
    }


    [TestMethod]
    public void SerializeSdJwtWithoutDisclosuresProducesValidFormat()
    {
        var token = new SdToken<string>(Rfc9901IssuerSignedJwt, []);

        string serialized = SdJwtSerializer.SerializeToken(token, Encoder);

        Assert.AreEqual($"{Rfc9901IssuerSignedJwt}~", serialized);
        Assert.EndsWith("~", serialized);
    }


    [TestMethod]
    public void SerializeSdJwtWithDisclosuresProducesValidFormat()
    {
        SdDisclosure d1 = SdJwtSerializer.ParseDisclosure(DisclosureGivenName, Decoder, MemoryPool);
        SdDisclosure d2 = SdJwtSerializer.ParseDisclosure(DisclosureFamilyName, Decoder, MemoryPool);

        var token = new SdToken<string>(Rfc9901IssuerSignedJwt, [d1, d2]);

        string serialized = SdJwtSerializer.SerializeToken(token, Encoder);

        Assert.EndsWith("~", serialized);
        Assert.Contains(Rfc9901IssuerSignedJwt, serialized);
    }


    [TestMethod]
    public void SerializeSdJwtWithKeyBindingProducesValidFormat()
    {
        SdDisclosure d1 = SdJwtSerializer.ParseDisclosure(DisclosureGivenName, Decoder, MemoryPool);

        var token = new SdToken<string>(Rfc9901IssuerSignedJwt, [d1], Rfc9901KeyBindingJwt);

        string serialized = SdJwtSerializer.SerializeToken(token, Encoder);

        Assert.EndsWith(Rfc9901KeyBindingJwt, serialized);
        Assert.DoesNotEndWith("~", serialized);
    }


    [TestMethod]
    public void RoundTripSdJwtPreservesAllData()
    {
        SdDisclosure d1 = SdJwtSerializer.ParseDisclosure(DisclosureGivenName, Decoder, MemoryPool);
        SdDisclosure d2 = SdJwtSerializer.ParseDisclosure(DisclosureFamilyName, Decoder, MemoryPool);

        var original = new SdToken<string>(Rfc9901IssuerSignedJwt, [d1, d2]);
        string serialized = SdJwtSerializer.SerializeToken(original, Encoder);

        SdToken<string> parsed = SdJwtSerializer.ParseToken(serialized, Decoder, MemoryPool);

        Assert.AreEqual(original.IssuerSigned, parsed.IssuerSigned);
        Assert.HasCount(original.Disclosures.Count, parsed.Disclosures);
        Assert.AreEqual(original.HasKeyBinding, parsed.HasKeyBinding);

        for(int i = 0; i < original.Disclosures.Count; i++)
        {
            Assert.AreEqual(original.Disclosures[i].ClaimName, parsed.Disclosures[i].ClaimName);
        }
    }


    [TestMethod]
    public void RoundTripSdJwtKbPreservesAllData()
    {
        SdDisclosure d1 = SdJwtSerializer.ParseDisclosure(DisclosureGivenName, Decoder, MemoryPool);

        var original = new SdToken<string>(Rfc9901IssuerSignedJwt, [d1], Rfc9901KeyBindingJwt);
        string serialized = SdJwtSerializer.SerializeToken(original, Encoder);

        SdToken<string> parsed = SdJwtSerializer.ParseToken(serialized, Decoder, MemoryPool);

        Assert.AreEqual(original.IssuerSigned, parsed.IssuerSigned);
        Assert.HasCount(original.Disclosures.Count, parsed.Disclosures);
        Assert.AreEqual(original.KeyBinding, parsed.KeyBinding);
    }


    [TestMethod]
    public void ParseDisclosureExtractsClaimNameAndValue()
    {
        SdDisclosure disclosure = SdJwtSerializer.ParseDisclosure(DisclosureGivenName, Decoder, MemoryPool);

        Assert.AreEqual("given_name", disclosure.ClaimName);
        Assert.AreEqual("John", disclosure.ClaimValue);
    }


    [TestMethod]
    public void ParseArrayElementDisclosureHasNullClaimName()
    {
        SdDisclosure disclosure = SdJwtSerializer.ParseDisclosure(DisclosureNationalityUs, Decoder, MemoryPool);

        Assert.IsNull(disclosure.ClaimName);
        Assert.AreEqual("US", disclosure.ClaimValue);
    }


    [TestMethod]
    public void GetSdJwtForHashingExcludesKbJwt()
    {
        SdDisclosure d1 = SdJwtSerializer.ParseDisclosure(DisclosureGivenName, Decoder, MemoryPool);

        var tokenWithKb = new SdToken<string>(Rfc9901IssuerSignedJwt, [d1], Rfc9901KeyBindingJwt);

        string forHashing = SdJwtSerializer.GetSdJwtForHashing(tokenWithKb, Encoder);

        Assert.DoesNotContain(Rfc9901KeyBindingJwt, forHashing);
        Assert.EndsWith("~", forHashing);
    }


    [TestMethod]
    public void ParseInvalidJwtThrows()
    {
        Assert.Throws<FormatException>(() =>
            SdJwtSerializer.ParseToken("not-a-jwt~", Decoder, MemoryPool));
    }


    [TestMethod]
    public void ParseMissingSeparatorThrows()
    {
        Assert.Throws<FormatException>(() =>
            SdJwtSerializer.ParseToken(Rfc9901IssuerSignedJwt, Decoder, MemoryPool));
    }


    [TestMethod]
    public void TryParseReturnsFalseForInvalidInput()
    {
        bool result = SdJwtSerializer.TryParseToken("invalid", Decoder, MemoryPool, out SdToken<string>? token);

        Assert.IsFalse(result);
        Assert.IsNull(token);
    }


    [TestMethod]
    public void TryParseReturnsTrueForValidInput()
    {
        string sdJwt = $"{Rfc9901IssuerSignedJwt}~";

        bool result = SdJwtSerializer.TryParseToken(sdJwt, Decoder, MemoryPool, out SdToken<string>? token);

        Assert.IsTrue(result);
        Assert.IsNotNull(token);
    }


    [TestMethod]
    public void IsValidJwtStructureReturnsTrueForValidJwt()
    {
        Assert.IsTrue(SdJwtSerializer.IsCompactJws(Rfc9901IssuerSignedJwt));
        Assert.IsTrue(SdJwtSerializer.IsCompactJws(Rfc9901KeyBindingJwt));
    }


    [TestMethod]
    public void IsValidJwtStructureReturnsFalseForInvalidJwt()
    {
        Assert.IsFalse(SdJwtSerializer.IsCompactJws("not-a-jwt"));
        Assert.IsFalse(SdJwtSerializer.IsCompactJws("a.b"));
        Assert.IsFalse(SdJwtSerializer.IsCompactJws("a.b.c.d"));
        Assert.IsFalse(SdJwtSerializer.IsCompactJws(""));
        Assert.IsFalse(SdJwtSerializer.IsCompactJws("a..c"));
    }


    [TestMethod]
    public void ComputeDisclosureDigestProducesNonEmptyResult()
    {
        string digest = ComputeDisclosureDigest(DisclosureGivenName, "sha-256");

        Assert.IsNotNull(digest);
        Assert.IsGreaterThan(0, digest.Length);
    }


    [TestMethod]
    public void ComputeSdHashProducesNonEmptyResult()
    {
        SdDisclosure d1 = SdJwtSerializer.ParseDisclosure(DisclosureGivenName, Decoder, MemoryPool);
        var token = new SdToken<string>(Rfc9901IssuerSignedJwt, [d1]);

        string sdHash = ComputeSdHash(token, "sha-256");

        Assert.IsNotNull(sdHash);
        Assert.IsGreaterThan(0, sdHash.Length);
    }


    //Real programs use these to get the final, specified form for digest computation.

    private static string ComputeDisclosureDigest(string encodedDisclosure, string algorithm)
    {
        byte[] disclosureBytes = Encoding.ASCII.GetBytes(encodedDisclosure);
        byte[] hashBytes = ComputeHash(disclosureBytes, algorithm);
        return Encoder(hashBytes);
    }


    private static string ComputeSdHash(SdToken<string> token, string algorithm)
    {
        string sdJwtForHashing = SdJwtSerializer.GetSdJwtForHashing(token, Encoder);
        byte[] sdJwtBytes = Encoding.ASCII.GetBytes(sdJwtForHashing);
        byte[] hashBytes = ComputeHash(sdJwtBytes, algorithm);
        return Encoder(hashBytes);
    }


    private static byte[] ComputeHash(byte[] data, string algorithmName)
    {
        HashAlgorithmName algorithm = WellKnownHashAlgorithms.ToHashAlgorithmName(algorithmName);
        return algorithm.Name switch
        {
            WellKnownHashAlgorithms.Sha256 => SHA256.HashData(data),
            WellKnownHashAlgorithms.Sha384 => SHA384.HashData(data),
            WellKnownHashAlgorithms.Sha512 => SHA512.HashData(data),
            _ => throw new ArgumentException($"Unsupported hash algorithm: '{algorithmName}'.", nameof(algorithmName))
        };
    }
}