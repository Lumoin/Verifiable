using System.Text;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the library's one reading of a DPoP proof's protected header and claims set (RFC 9449 section 4.2):
/// <see cref="DpopProofHeader.Read"/> and <see cref="DpopProofClaims.Read"/>, read through the JSON reader's members, each
/// answering the part or a typed refusal. The rows are the inputs a receiver's three readings of a proof meet: the header's
/// <c>alg</c> and the <c>kty</c> and <c>crv</c> of its <c>jwk</c> a verification is chosen by, the header the validator judges,
/// and the claims it judges.
/// </summary>
[TestClass]
internal sealed class DpopProofPartReadingTests
{
    /// <summary>The test context, carrying the cancellation token every call observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The instant the proofs are issued at.</summary>
    private static DateTimeOffset IssuedAt { get; } = TestClock.CanonicalEpoch;

    /// <summary>An embedded key every refusal row of the header carries where its own defect is elsewhere.</summary>
    private const string EmbeddedKey = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";


    /// <summary>
    /// A proof the library composed reads back as it was composed: its header's <c>alg</c>, <c>typ</c> and every string member
    /// of its <c>jwk</c>, the <c>kty</c> and <c>crv</c> a verification is chosen by among them, and its claims, the <c>iat</c> as
    /// written; <see cref="DpopJwsPartParser.Default"/> answers the same readings.
    /// </summary>
    /// <returns>A task completing once the proof is read.</returns>
    [TestMethod]
    public async Task AProofTheLibraryComposedReadsBackAsComposed()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var key = new DpopKey(keys, WellKnownJwaValues.Es256);
        var claims = new DpopProofClaims
        {
            Htm = WellKnownHttpMethods.Post,
            Htu = "https://as.example.com/token",
            Iat = IssuedAt,
            Jti = "proof-jti",
            Nonce = "server-nonce",
            Ath = "access-token-hash"
        };

        var proof = await DpopProofConstruction.BuildAsync(
            claims,
            key,
            TestSetup.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        var parts = proof.Split('.');
        using var headerBytes = TestSetup.Base64UrlDecoder(parts[0], BaseMemoryPool.Shared);
        using var claimsBytes = TestSetup.Base64UrlDecoder(parts[1], BaseMemoryPool.Shared);

        var header = DpopProofHeader.Read(headerBytes.Memory.Span) as DpopProofPartRead<DpopProofHeader>;
        var read = DpopProofClaims.Read(claimsBytes.Memory.Span) as DpopProofPartRead<DpopProofClaims>;

        Assert.IsNotNull(header, "The composed header reads.");
        Assert.IsNotNull(read, "The composed claims read.");
        Assert.AreEqual(WellKnownJwaValues.Es256, header.Part.Alg);
        Assert.AreEqual(WellKnownDpopValues.ProofTypeHeader, header.Part.Typ);
        Assert.AreEqual(WellKnownKeyTypeValues.Ec, header.Part.Jwk[WellKnownJwkMemberNames.Kty]);
        Assert.AreEqual(WellKnownCurveValues.P256, header.Part.Jwk[WellKnownJwkMemberNames.Crv]);
        Assert.HasCount(4, header.Part.Jwk);
        Assert.AreEqual(claims.Htm, read.Part.Htm);
        Assert.AreEqual(claims.Htu, read.Part.Htu);
        Assert.AreEqual(claims.Jti, read.Part.Jti);
        Assert.AreEqual(claims.Nonce, read.Part.Nonce);
        Assert.AreEqual(claims.Ath, read.Part.Ath);
        Assert.AreEqual(0, read.Part.Iat.CompareTo(IssuedAt), "The iat reads as written.");
        Assert.IsTrue(DpopJwsPartParser.Default.ParseHeader(headerBytes.Memory) is DpopProofPartRead<DpopProofHeader>, "The default parser reads the header.");
        Assert.IsTrue(DpopJwsPartParser.Default.ParseClaims(claimsBytes.Memory) is DpopProofPartRead<DpopProofClaims>, "The default parser reads the claims.");
    }


    /// <summary>
    /// A claims set carrying an <c>iat</c> with a fraction a tick cannot hold reads it as written, every digit kept, and one
    /// omitting <c>nonce</c> and <c>ath</c> reads neither.
    /// </summary>
    [TestMethod]
    public void AClaimsSetReadsItsIatAsWrittenAndItsOptionalClaimsOnlyWhereCarried()
    {
        var read = ReadClaims("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\",\"iat\":1700000000.00000000001}") as DpopProofPartRead<DpopProofClaims>;

        Assert.IsNotNull(read);
        Assert.AreEqual("1700000000.00000000001", read.Part.Iat.ToString(), "The iat keeps every digit written.");
        Assert.IsFalse(read.Part.Iat.FallsOnTick, "A part of a tick is kept.");
        Assert.IsNull(read.Part.Nonce);
        Assert.IsNull(read.Part.Ath);
    }


    /// <summary>
    /// RFC 9449 section 4.2: the header MUST carry <c>typ</c>, <c>alg</c> and <c>jwk</c>. A header omitting one, carrying
    /// <c>alg</c> or <c>typ</c> as no string, <c>jwk</c> as no object, or a <c>jwk</c> member that is no string is refused for that
    /// member by name, the place it is in and the defect, the member carried as the reader answered it.
    /// </summary>
    /// <param name="header">The header's JSON text.</param>
    /// <param name="place">The object the refusal names.</param>
    /// <param name="memberName">The member it names.</param>
    /// <param name="defect">The defect.</param>
    [TestMethod]
    [DataRow("{\"typ\":\"dpop+jwt\",\"jwk\":" + EmbeddedKey + "}", DpopProofPartPlace.ProtectedHeader, "alg", DpopProofMemberDefect.Absent)]
    [DataRow("{\"alg\":7,\"typ\":\"dpop+jwt\",\"jwk\":" + EmbeddedKey + "}", DpopProofPartPlace.ProtectedHeader, "alg", DpopProofMemberDefect.NotAString)]
    [DataRow("{\"alg\":\"ES256\",\"jwk\":" + EmbeddedKey + "}", DpopProofPartPlace.ProtectedHeader, "typ", DpopProofMemberDefect.Absent)]
    [DataRow("{\"alg\":\"ES256\",\"typ\":true,\"jwk\":" + EmbeddedKey + "}", DpopProofPartPlace.ProtectedHeader, "typ", DpopProofMemberDefect.NotAString)]
    [DataRow("{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\"}", DpopProofPartPlace.ProtectedHeader, "jwk", DpopProofMemberDefect.Absent)]
    [DataRow("{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":\"EC\"}", DpopProofPartPlace.ProtectedHeader, "jwk", DpopProofMemberDefect.NotAnObject)]
    [DataRow("{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"ext\":true}}", DpopProofPartPlace.EmbeddedJwk, "ext", DpopProofMemberDefect.NotAString)]
    [DataRow("{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":{\"kty\":\"EC\",\"d\":7}}", DpopProofPartPlace.EmbeddedJwk, "d", DpopProofMemberDefect.NotAString)]
    public void AHeaderIsRefusedForTheMemberItLacksOrCarriesAsAnotherKind(string header, DpopProofPartPlace place, string memberName, DpopProofMemberDefect defect)
    {
        var refused = DpopProofHeader.Read(Encoding.UTF8.GetBytes(header)) as DpopProofPartMemberRefused<DpopProofHeader>;

        Assert.IsNotNull(refused, header);
        Assert.AreEqual(place, refused.Place, header);
        Assert.AreEqual(memberName, refused.MemberName, header);
        Assert.AreEqual(defect, refused.Defect, header);
        Assert.AreEqual(defect is DpopProofMemberDefect.Absent, refused.Carried is JsonMemberAbsent, header);
    }


    /// <summary>
    /// RFC 9449 section 4.2 for the claims: <c>jti</c>, <c>htm</c>, <c>htu</c> and <c>iat</c> are REQUIRED, the first three
    /// strings and <c>iat</c> a NumericDate, and a carried <c>nonce</c> or <c>ath</c> is a string. A claims set omitting one,
    /// carrying one as another kind, or carrying an <c>iat</c> of digits in a string, past the clock or a literal is refused for
    /// that claim, the claim carried as the reader answered it.
    /// </summary>
    /// <param name="claims">The claims set's JSON text.</param>
    /// <param name="memberName">The claim the refusal names.</param>
    /// <param name="defect">The defect.</param>
    [TestMethod]
    [DataRow("{\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\",\"iat\":1700000000}", "jti", DpopProofMemberDefect.Absent)]
    [DataRow("{\"jti\":7,\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\",\"iat\":1700000000}", "jti", DpopProofMemberDefect.NotAString)]
    [DataRow("{\"jti\":\"j\",\"htu\":\"https://as.example.com/token\",\"iat\":1700000000}", "htm", DpopProofMemberDefect.Absent)]
    [DataRow("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":[\"https://as.example.com/token\"],\"iat\":1700000000}", "htu", DpopProofMemberDefect.NotAString)]
    [DataRow("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\"}", "iat", DpopProofMemberDefect.Absent)]
    [DataRow("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\",\"iat\":\"1700000000\"}", "iat", DpopProofMemberDefect.NotANumericDate)]
    [DataRow("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\",\"iat\":1e400}", "iat", DpopProofMemberDefect.NotANumericDate)]
    [DataRow("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\",\"iat\":true}", "iat", DpopProofMemberDefect.NotANumericDate)]
    [DataRow("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\",\"iat\":1700000000,\"nonce\":null}", "nonce", DpopProofMemberDefect.NotAString)]
    [DataRow("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\",\"iat\":1700000000,\"ath\":7}", "ath", DpopProofMemberDefect.NotAString)]
    public void AClaimsSetIsRefusedForTheClaimItLacksOrCarriesAsAnotherKind(string claims, string memberName, DpopProofMemberDefect defect)
    {
        var refused = ReadClaims(claims) as DpopProofPartMemberRefused<DpopProofClaims>;

        Assert.IsNotNull(refused, claims);
        Assert.AreEqual(DpopProofPartPlace.Claims, refused.Place, claims);
        Assert.AreEqual(memberName, refused.MemberName, claims);
        Assert.AreEqual(defect, refused.Defect, claims);
    }


    /// <summary>
    /// The carried claim of an <c>iat</c> refusal is the member as the reader answered it: a string with its text, a number with
    /// its spelling.
    /// </summary>
    [TestMethod]
    public void AnIatRefusalCarriesTheMemberAsTheReaderAnsweredIt()
    {
        var asString = ReadClaims("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\",\"iat\":\"1700000000\"}") as DpopProofPartMemberRefused<DpopProofClaims>;
        var pastTheClock = ReadClaims("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://as.example.com/token\",\"iat\":1e400}") as DpopProofPartMemberRefused<DpopProofClaims>;

        Assert.AreEqual(new JsonMemberString("1700000000"), asString?.Carried);
        Assert.AreEqual(new JsonMemberNumber("1e400"), pastTheClock?.Carried);
    }


    /// <summary>
    /// A part the JSON reader refuses is refused with the reader's own refusal and the object it concerns: a header naming
    /// <c>alg</c> twice, a <c>jwk</c> naming <c>kty</c> twice (the header's object nested one level), a claims set naming
    /// <c>htu</c> twice, a member naming no Unicode text, an array and an object never closed.
    /// </summary>
    [TestMethod]
    public void APartTheReaderRefusesIsRefusedWithTheReadersRefusal()
    {
        var repeatedAlg = DpopProofHeader.Read("{\"alg\":\"ES256\",\"alg\":\"none\",\"typ\":\"dpop+jwt\",\"jwk\":{\"kty\":\"EC\"}}"u8) as DpopProofPartDocumentRefused<DpopProofHeader>;
        var repeatedKty = DpopProofHeader.Read("{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":{\"kty\":\"EC\",\"kty\":\"RSA\"}}"u8) as DpopProofPartDocumentRefused<DpopProofHeader>;
        var repeatedHtu = DpopProofClaims.Read("{\"jti\":\"j\",\"htm\":\"POST\",\"htu\":\"https://a.example\",\"htu\":\"https://b.example\",\"iat\":1}"u8) as DpopProofPartDocumentRefused<DpopProofClaims>;
        var undecodable = DpopProofClaims.Read("{\"jti\":\"\\uD800\",\"htm\":\"POST\",\"htu\":\"https://a.example\",\"iat\":1}"u8) as DpopProofPartDocumentRefused<DpopProofClaims>;
        var array = DpopProofHeader.Read("[1]"u8) as DpopProofPartDocumentRefused<DpopProofHeader>;
        var unclosed = DpopProofClaims.Read("{\"jti\":"u8) as DpopProofPartDocumentRefused<DpopProofClaims>;

        var repeatedAlgName = repeatedAlg?.Refusal as JsonRepeatedMemberName;
        var repeatedKtyName = repeatedKty?.Refusal as JsonRepeatedMemberName;
        var undecodableMember = undecodable?.Refusal as JsonUndecodableMember;

        Assert.IsNotNull(repeatedAlgName, "A header naming alg twice is refused by the reader.");
        Assert.AreEqual(DpopProofPartPlace.ProtectedHeader, repeatedAlg?.Place);
        Assert.AreEqual("alg", repeatedAlgName.Name);
        Assert.AreEqual(1, repeatedAlgName.ObjectDepth);
        Assert.IsNotNull(repeatedKtyName, "A jwk naming kty twice is refused by the reader.");
        Assert.AreEqual("kty", repeatedKtyName.Name);
        Assert.AreEqual(2, repeatedKtyName.ObjectDepth);
        Assert.IsTrue(repeatedHtu is { Place: DpopProofPartPlace.Claims, Refusal: JsonRepeatedMemberName { Name: "htu" } }, "A claims set naming htu twice is refused by the reader.");
        Assert.IsNotNull(undecodableMember, "A claim naming no Unicode text is refused by the reader.");
        Assert.AreEqual("jti", undecodableMember.Name);
        Assert.IsTrue(array is { Refusal: JsonNotOneObject }, "An array is no header.");
        Assert.IsTrue(unclosed is { Refusal: JsonNotOneObject }, "An object never closed is no claims set.");
    }


    /// <summary>Reads a claims set given as JSON text.</summary>
    /// <param name="claims">The claims set's JSON text.</param>
    /// <returns>The reading.</returns>
    private static DpopProofPartReading<DpopProofClaims> ReadClaims(string claims) => DpopProofClaims.Read(Encoding.UTF8.GetBytes(claims));
}
