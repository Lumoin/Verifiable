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
/// and the claims it judges; the embedded key's members are judged each by its own rule (RFC 7517 section 4).
/// </summary>
[TestClass]
internal sealed class DpopProofPartReadingTests
{
    /// <summary>The test context, carrying the cancellation token every call observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The instant the proofs are issued at.</summary>
    private static DateTimeOffset IssuedAt { get; } = TestClock.CanonicalEpoch;

    /// <summary>The x coordinate of the embedded key the rows carry.</summary>
    private const string KeyX = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";

    /// <summary>The y coordinate of the embedded key the rows carry.</summary>
    private const string KeyY = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    /// <summary>The target URI the claims sets name.</summary>
    private const string Target = "https://as.example.com/token";

    /// <summary>An embedded key every refusal row of the header carries where its own defect is elsewhere.</summary>
    private static string EmbeddedKey { get; } = Key();

    /// <summary>
    /// The header refusal rows: the header's JSON text, the member the refusal names, its name and the defect - RFC 9449 section
    /// 4.2 for the header's members, RFC 7517 section 4 and RFC 7518 section 6 for the embedded key's.
    /// </summary>
    public static IEnumerable<object[]> HeaderRefusalRows { get; } =
    [
        [Header(TypMember(), JwkMember(EmbeddedKey)), DpopProofMember.Alg, WellKnownJoseHeaderNames.Alg, DpopProofMemberDefect.Absent],
        [Header(Member(WellKnownJoseHeaderNames.Alg, "7"), TypMember(), JwkMember(EmbeddedKey)), DpopProofMember.Alg, WellKnownJoseHeaderNames.Alg, DpopProofMemberDefect.NotAString],
        [Header(AlgMember(), JwkMember(EmbeddedKey)), DpopProofMember.Typ, WellKnownJoseHeaderNames.Typ, DpopProofMemberDefect.Absent],
        [Header(AlgMember(), Member(WellKnownJoseHeaderNames.Typ, "true"), JwkMember(EmbeddedKey)), DpopProofMember.Typ, WellKnownJoseHeaderNames.Typ, DpopProofMemberDefect.NotAString],
        [Header(AlgMember(), Member(WellKnownJoseHeaderNames.Typ, "null"), JwkMember(EmbeddedKey)), DpopProofMember.Typ, WellKnownJoseHeaderNames.Typ, DpopProofMemberDefect.NotAString],
        [Header(AlgMember(), TypMember()), DpopProofMember.Jwk, WellKnownJoseHeaderNames.Jwk, DpopProofMemberDefect.Absent],
        [Header(AlgMember(), TypMember(), Member(WellKnownJoseHeaderNames.Jwk, Quoted(WellKnownKeyTypeValues.Ec))), DpopProofMember.Jwk, WellKnownJoseHeaderNames.Jwk, DpopProofMemberDefect.NotAnObject],
        [Header(AlgMember(), TypMember(), JwkMember(KeyWith(WellKnownJwkMemberNames.Kty, "true"))), DpopProofMember.JwkMember, WellKnownJwkMemberNames.Kty, DpopProofMemberDefect.NotAString],
        [Header(AlgMember(), TypMember(), JwkMember(KeyWith(WellKnownJwkMemberNames.Crv, "null"))), DpopProofMember.JwkMember, WellKnownJwkMemberNames.Crv, DpopProofMemberDefect.NotAString],
        [Header(AlgMember(), TypMember(), JwkMember(Key(Member(WellKnownJwkMemberNames.D, "[\"cHJpdmF0ZQ\"]")))), DpopProofMember.JwkMember, WellKnownJwkMemberNames.D, DpopProofMemberDefect.PrivateKeyMaterial],
        [Header(AlgMember(), TypMember(), JwkMember(Key(Member(WellKnownJwkMemberNames.D, "7")))), DpopProofMember.JwkMember, WellKnownJwkMemberNames.D, DpopProofMemberDefect.PrivateKeyMaterial],
        [Header(AlgMember(), TypMember(), JwkMember(Key(Member(WellKnownJwkMemberNames.KeyOps, "\"verify\"")))), DpopProofMember.JwkMember, WellKnownJwkMemberNames.KeyOps, DpopProofMemberDefect.NotAnArrayOfStrings],
        [Header(AlgMember(), TypMember(), JwkMember(Key(Member(WellKnownJwkMemberNames.KeyOps, "[\"verify\",7]")))), DpopProofMember.JwkMember, WellKnownJwkMemberNames.KeyOps, DpopProofMemberDefect.NotAnArrayOfStrings],
        [Header(AlgMember(), TypMember(), JwkMember(Key(Member(WellKnownJwkMemberNames.X5c, "[]")))), DpopProofMember.JwkMember, WellKnownJwkMemberNames.X5c, DpopProofMemberDefect.NotACertificateChain],
        [Header(AlgMember(), TypMember(), JwkMember(Key(Member(WellKnownJwkMemberNames.X5c, "[\"_-_-\"]")))), DpopProofMember.JwkMember, WellKnownJwkMemberNames.X5c, DpopProofMemberDefect.NotACertificateChain],
        [Header(AlgMember(), TypMember(), JwkMember(Key(Member(WellKnownJwkMemberNames.Ext, "\"true\"")))), DpopProofMember.JwkMember, WellKnownJwkMemberNames.Ext, DpopProofMemberDefect.NotABoolean]
    ];


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
            Htu = Target,
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
    /// RFC 7517 section 4 and the Web Cryptography API's <c>JsonWebKey</c> dictionary: a key carrying <c>key_ops</c> as an array
    /// of strings, <c>x5c</c> as an array of base64-encoded certificates, <c>ext</c> as a Boolean and a member no rule names reads,
    /// each judged by its own rule; the key's members defined as strings are the ones it is read as, and the member no rule names
    /// is ignored.
    /// </summary>
    [TestMethod]
    public void AKeyCarryingKeyOperationsACertificateChainAnExtractableFlagAndAnUnknownMemberReads()
    {
        var key = Key(
            Member(WellKnownJwkMemberNames.KeyOps, $"[{Quoted("verify")}]"),
            Member(WellKnownJwkMemberNames.X5c, $"[{Quoted("MIIBkTCB+wIJAOfv")}]"),
            Member(WellKnownJwkMemberNames.Ext, "true"),
            Member(WellKnownJwkMemberNames.Kid, Quoted("proof-key")),
            Member("x-deployment", /*lang=json,strict*/ "{\"region\":[1,null]}"));

        var read = DpopProofHeader.Read(Encoding.UTF8.GetBytes(Header(AlgMember(), TypMember(), JwkMember(key)))) as DpopProofPartRead<DpopProofHeader>;

        Assert.IsNotNull(read, "A key whose members keep their rules reads.");
        Assert.AreEqual(WellKnownKeyTypeValues.Ec, read.Part.Jwk[WellKnownJwkMemberNames.Kty]);
        Assert.AreEqual("proof-key", read.Part.Jwk[WellKnownJwkMemberNames.Kid]);
        Assert.HasCount(5, read.Part.Jwk, "The key holds its string members: kty, crv, x, y and kid.");
        Assert.IsFalse(read.Part.Jwk.ContainsKey("x-deployment"), "A member no rule names is ignored.");
    }


    /// <summary>
    /// A claims set carrying an <c>iat</c> with a fraction a tick cannot hold reads it as written, every digit kept, and one
    /// omitting <c>nonce</c> and <c>ath</c> reads neither.
    /// </summary>
    [TestMethod]
    public void AClaimsSetReadsItsIatAsWrittenAndItsOptionalClaimsOnlyWhereCarried()
    {
        var read = ReadClaims(Claims(JtiClaim(), HtmClaim(), HtuClaim(), Member(WellKnownJwtClaimNames.Iat, "1700000000.00000000001"))) as DpopProofPartRead<DpopProofClaims>;

        Assert.IsNotNull(read);
        Assert.AreEqual("1700000000.00000000001", read.Part.Iat.ToString(), "The iat keeps every digit written.");
        Assert.IsFalse(read.Part.Iat.FallsOnTick, "A part of a tick is kept.");
        Assert.IsNull(read.Part.Nonce);
        Assert.IsNull(read.Part.Ath);
    }


    /// <summary>
    /// RFC 9449 section 4.2: the header MUST carry <c>typ</c>, <c>alg</c> and <c>jwk</c>, and RFC 7517 section 4 has each member
    /// of the key a kind of its own. A header omitting one, carrying <c>alg</c> or <c>typ</c> as no string - <c>null</c> among
    /// them - <c>jwk</c> as no object, or a key member of another kind than its rule names is refused for that member, identified
    /// and named, the place it is in, the segment and the defect, the member carried as the reader answered it; a key carrying
    /// private material is refused whatever the kind of its value.
    /// </summary>
    /// <param name="header">The header's JSON text.</param>
    /// <param name="member">The member the refusal identifies.</param>
    /// <param name="memberName">The member's name.</param>
    /// <param name="defect">The defect.</param>
    [TestMethod]
    [DynamicData(nameof(HeaderRefusalRows))]
    public void AHeaderIsRefusedForTheMemberItLacksOrCarriesAsAnotherKind(string header, DpopProofMember member, string memberName, DpopProofMemberDefect defect)
    {
        var refused = DpopProofHeader.Read(Encoding.UTF8.GetBytes(header)) as DpopProofPartRefused<DpopProofHeader>;
        var refusal = refused?.Refusal as DpopProofMemberRefusal;

        Assert.IsNotNull(refusal, header);
        Assert.AreEqual(member, refusal.Member, header);
        Assert.AreEqual(memberName, refusal.MemberName, header);
        Assert.AreEqual(defect, refusal.Defect, header);
        Assert.AreEqual(JwsPart.ProtectedHeader, refusal.Part, header);
        Assert.AreEqual(member is DpopProofMember.JwkMember ? DpopProofPartPlace.EmbeddedJwk : DpopProofPartPlace.ProtectedHeader, refusal.Place, header);
        Assert.AreEqual(defect is DpopProofMemberDefect.Absent, refusal.Carried is JsonMemberAbsent, header);
    }


    /// <summary>
    /// RFC 9449 section 4.2 for the claims: <c>jti</c>, <c>htm</c>, <c>htu</c> and <c>iat</c> are REQUIRED, the first three
    /// strings and <c>iat</c> a NumericDate, and a carried <c>nonce</c> or <c>ath</c> is a string. A claims set omitting one,
    /// carrying one as another kind, or carrying an <c>iat</c> of digits in a string, past the clock or a literal is refused for
    /// that claim, the claim carried as the reader answered it.
    /// </summary>
    /// <param name="claimsCase">The name of the claims set the row reads.</param>
    /// <param name="member">The claim the refusal identifies.</param>
    /// <param name="defect">The defect.</param>
    [TestMethod]
    [DataRow("jti-absent", DpopProofMember.Jti, DpopProofMemberDefect.Absent)]
    [DataRow("jti-number", DpopProofMember.Jti, DpopProofMemberDefect.NotAString)]
    [DataRow("htm-absent", DpopProofMember.Htm, DpopProofMemberDefect.Absent)]
    [DataRow("htu-array", DpopProofMember.Htu, DpopProofMemberDefect.NotAString)]
    [DataRow("iat-absent", DpopProofMember.Iat, DpopProofMemberDefect.Absent)]
    [DataRow("iat-digits", DpopProofMember.Iat, DpopProofMemberDefect.NotANumericDate)]
    [DataRow("iat-past-the-clock", DpopProofMember.Iat, DpopProofMemberDefect.NotANumericDate)]
    [DataRow("iat-literal", DpopProofMember.Iat, DpopProofMemberDefect.NotANumericDate)]
    [DataRow("nonce-null", DpopProofMember.Nonce, DpopProofMemberDefect.NotAString)]
    [DataRow("ath-number", DpopProofMember.Ath, DpopProofMemberDefect.NotAString)]
    public void AClaimsSetIsRefusedForTheClaimItLacksOrCarriesAsAnotherKind(string claimsCase, DpopProofMember member, DpopProofMemberDefect defect)
    {
        var iat = Member(WellKnownJwtClaimNames.Iat, "1700000000");
        var claims = claimsCase switch
        {
            "jti-absent" => Claims(HtmClaim(), HtuClaim(), iat),
            "jti-number" => Claims(Member(WellKnownJwtClaimNames.Jti, "7"), HtmClaim(), HtuClaim(), iat),
            "htm-absent" => Claims(JtiClaim(), HtuClaim(), iat),
            "htu-array" => Claims(JtiClaim(), HtmClaim(), Member(WellKnownJwtClaimNames.Htu, $"[{Quoted(Target)}]"), iat),
            "iat-absent" => Claims(JtiClaim(), HtmClaim(), HtuClaim()),
            "iat-digits" => Claims(JtiClaim(), HtmClaim(), HtuClaim(), Member(WellKnownJwtClaimNames.Iat, Quoted("1700000000"))),
            "iat-past-the-clock" => Claims(JtiClaim(), HtmClaim(), HtuClaim(), Member(WellKnownJwtClaimNames.Iat, "1e400")),
            "iat-literal" => Claims(JtiClaim(), HtmClaim(), HtuClaim(), Member(WellKnownJwtClaimNames.Iat, "true")),
            "nonce-null" => Claims(JtiClaim(), HtmClaim(), HtuClaim(), iat, Member(WellKnownJwtClaimNames.Nonce, "null")),
            "ath-number" => Claims(JtiClaim(), HtmClaim(), HtuClaim(), iat, Member(WellKnownJwtClaimNames.Ath, "7")),
            _ => throw new ArgumentOutOfRangeException(nameof(claimsCase), claimsCase, "No claims set is named so.")
        };

        var refusal = (ReadClaims(claims) as DpopProofPartRefused<DpopProofClaims>)?.Refusal as DpopProofMemberRefusal;

        Assert.IsNotNull(refusal, claims);
        Assert.AreEqual(DpopProofPartPlace.Claims, refusal.Place, claims);
        Assert.AreEqual(JwsPart.Payload, refusal.Part, claims);
        Assert.AreEqual(member, refusal.Member, claims);
        Assert.AreEqual(defect, refusal.Defect, claims);
    }


    /// <summary>
    /// The carried claim of an <c>iat</c> refusal is the member as the reader answered it: a string with its text, a number with
    /// its spelling.
    /// </summary>
    [TestMethod]
    public void AnIatRefusalCarriesTheMemberAsTheReaderAnsweredIt()
    {
        var asString = ReadClaims(Claims(JtiClaim(), HtmClaim(), HtuClaim(), Member(WellKnownJwtClaimNames.Iat, Quoted("1700000000")))) as DpopProofPartRefused<DpopProofClaims>;
        var pastTheClock = ReadClaims(Claims(JtiClaim(), HtmClaim(), HtuClaim(), Member(WellKnownJwtClaimNames.Iat, "1e400"))) as DpopProofPartRefused<DpopProofClaims>;

        Assert.AreEqual(new JsonMemberString("1700000000"), (asString?.Refusal as DpopProofMemberRefusal)?.Carried);
        Assert.AreEqual(new JsonMemberNumber("1e400"), (pastTheClock?.Refusal as DpopProofMemberRefusal)?.Carried);
    }


    /// <summary>
    /// A part the JSON reader refuses is refused with the reader's own refusal and the segment it concerns: a header naming
    /// <c>alg</c> twice, a <c>jwk</c> naming <c>kty</c> twice (the header's object nested one level), a claims set naming
    /// <c>htu</c> twice, a member naming no Unicode text, an array and an object never closed.
    /// </summary>
    [TestMethod]
    public void APartTheReaderRefusesIsRefusedWithTheReadersRefusal()
    {
        var repeatedAlg = HeaderDocumentRefusal(Header(AlgMember(), Member(WellKnownJoseHeaderNames.Alg, Quoted(WellKnownJwaValues.None)), TypMember(), JwkMember(EmbeddedKey)));
        var repeatedKty = HeaderDocumentRefusal(Header(AlgMember(), TypMember(), JwkMember(Key(Member(WellKnownJwkMemberNames.Kty, Quoted(WellKnownKeyTypeValues.Rsa))))));
        var repeatedHtu = ClaimsDocumentRefusal(Claims(JtiClaim(), HtmClaim(), HtuClaim(), Member(WellKnownJwtClaimNames.Htu, Quoted("https://b.example")), Member(WellKnownJwtClaimNames.Iat, "1")));
        var undecodable = ClaimsDocumentRefusal(Claims(Member(WellKnownJwtClaimNames.Jti, "\"\\uD800\""), HtmClaim(), HtuClaim(), Member(WellKnownJwtClaimNames.Iat, "1")));
        var array = HeaderDocumentRefusal("[1]");
        var unclosed = ClaimsDocumentRefusal($"{{{Quoted(WellKnownJwtClaimNames.Jti)}:");

        var repeatedAlgName = repeatedAlg?.Refusal as JsonRepeatedMemberName;
        var repeatedKtyName = repeatedKty?.Refusal as JsonRepeatedMemberName;
        var undecodableMember = undecodable?.Refusal as JsonUndecodableMember;

        Assert.IsNotNull(repeatedAlgName, "A header naming alg twice is refused by the reader.");
        Assert.AreEqual(JwsPart.ProtectedHeader, repeatedAlg?.Part);
        Assert.AreEqual(WellKnownJoseHeaderNames.Alg, repeatedAlgName.Name);
        Assert.AreEqual(1, repeatedAlgName.ObjectDepth);
        Assert.IsNotNull(repeatedKtyName, "A jwk naming kty twice is refused by the reader.");
        Assert.AreEqual(WellKnownJwkMemberNames.Kty, repeatedKtyName.Name);
        Assert.AreEqual(2, repeatedKtyName.ObjectDepth);
        Assert.AreEqual(JwsPart.Payload, repeatedHtu?.Part, "A claims set naming htu twice is refused by the reader.");
        Assert.AreEqual(WellKnownJwtClaimNames.Htu, (repeatedHtu?.Refusal as JsonRepeatedMemberName)?.Name);
        Assert.IsNotNull(undecodableMember, "A claim naming no Unicode text is refused by the reader.");
        Assert.AreEqual(WellKnownJwtClaimNames.Jti, undecodableMember.Name);
        Assert.IsTrue(array is { Refusal: JsonNotOneObject }, "An array is no header.");
        Assert.IsTrue(unclosed is { Refusal: JsonNotOneObject }, "An object never closed is no claims set.");
    }


    /// <summary>The header refusal of the JSON reader for a header given as JSON text, or none.</summary>
    /// <param name="header">The header's JSON text.</param>
    /// <returns>The reader's refusal with its segment, or <see langword="null"/>.</returns>
    private static JwsPartDocumentRefusal? HeaderDocumentRefusal(string header) =>
        (DpopProofHeader.Read(Encoding.UTF8.GetBytes(header)) as DpopProofPartRefused<DpopProofHeader>)?.Refusal as JwsPartDocumentRefusal;


    /// <summary>The claims refusal of the JSON reader for a claims set given as JSON text, or none.</summary>
    /// <param name="claims">The claims set's JSON text.</param>
    /// <returns>The reader's refusal with its segment, or <see langword="null"/>.</returns>
    private static JwsPartDocumentRefusal? ClaimsDocumentRefusal(string claims) =>
        (ReadClaims(claims) as DpopProofPartRefused<DpopProofClaims>)?.Refusal as JwsPartDocumentRefusal;


    /// <summary>Reads a claims set given as JSON text.</summary>
    /// <param name="claims">The claims set's JSON text.</param>
    /// <returns>The reading.</returns>
    private static DpopProofPartReading<DpopProofClaims> ReadClaims(string claims) => DpopProofClaims.Read(Encoding.UTF8.GetBytes(claims));


    /// <summary>A JSON string of a text needing no escape.</summary>
    /// <param name="text">The text.</param>
    /// <returns>The JSON string.</returns>
    private static string Quoted(string text) => $"\"{text}\"";


    /// <summary>One member of a JSON object, its name and its value's JSON text.</summary>
    /// <param name="name">The member's name.</param>
    /// <param name="valueJson">The value's JSON text.</param>
    /// <returns>The member's JSON text.</returns>
    private static string Member(string name, string valueJson) => $"{Quoted(name)}:{valueJson}";


    /// <summary>A header of the members given.</summary>
    /// <param name="members">The members' JSON text.</param>
    /// <returns>The header's JSON text.</returns>
    private static string Header(params string[] members) => $"{{{string.Join(',', members)}}}";


    /// <summary>A claims set of the members given.</summary>
    /// <param name="members">The members' JSON text.</param>
    /// <returns>The claims set's JSON text.</returns>
    private static string Claims(params string[] members) => $"{{{string.Join(',', members)}}}";


    /// <summary>The embedded EC key every row carries, its members followed by the members given.</summary>
    /// <param name="members">The further members' JSON text.</param>
    /// <returns>The key's JSON text.</returns>
    private static string Key(params string[] members) => Header(
        [
            Member(WellKnownJwkMemberNames.Kty, Quoted(WellKnownKeyTypeValues.Ec)),
            Member(WellKnownJwkMemberNames.Crv, Quoted(WellKnownCurveValues.P256)),
            Member(WellKnownJwkMemberNames.X, Quoted(KeyX)),
            Member(WellKnownJwkMemberNames.Y, Quoted(KeyY)),
            .. members
        ]);


    /// <summary>The embedded EC key every row carries, the member of the name given carrying the value given in place of its own.</summary>
    /// <param name="name">The member's name: <c>kty</c>, <c>crv</c>, <c>x</c> or <c>y</c>.</param>
    /// <param name="valueJson">The value's JSON text.</param>
    /// <returns>The key's JSON text.</returns>
    private static string KeyWith(string name, string valueJson) => Header(
        Member(WellKnownJwkMemberNames.Kty, WellKnownJwkMemberNames.IsKty(name) ? valueJson : Quoted(WellKnownKeyTypeValues.Ec)),
        Member(WellKnownJwkMemberNames.Crv, WellKnownJwkMemberNames.IsCrv(name) ? valueJson : Quoted(WellKnownCurveValues.P256)),
        Member(WellKnownJwkMemberNames.X, WellKnownJwkMemberNames.IsX(name) ? valueJson : Quoted(KeyX)),
        Member(WellKnownJwkMemberNames.Y, WellKnownJwkMemberNames.IsY(name) ? valueJson : Quoted(KeyY)));


    /// <summary>The header's <c>alg</c>, ES256.</summary>
    /// <returns>The member's JSON text.</returns>
    private static string AlgMember() => Member(WellKnownJoseHeaderNames.Alg, Quoted(WellKnownJwaValues.Es256));


    /// <summary>The header's <c>typ</c>, the DPoP proof type.</summary>
    /// <returns>The member's JSON text.</returns>
    private static string TypMember() => Member(WellKnownJoseHeaderNames.Typ, Quoted(WellKnownDpopValues.ProofTypeHeader));


    /// <summary>The header's <c>jwk</c>, the key given.</summary>
    /// <param name="key">The key's JSON text.</param>
    /// <returns>The member's JSON text.</returns>
    private static string JwkMember(string key) => Member(WellKnownJoseHeaderNames.Jwk, key);


    /// <summary>The claims set's <c>jti</c>.</summary>
    /// <returns>The member's JSON text.</returns>
    private static string JtiClaim() => Member(WellKnownJwtClaimNames.Jti, Quoted("j"));


    /// <summary>The claims set's <c>htm</c>, POST.</summary>
    /// <returns>The member's JSON text.</returns>
    private static string HtmClaim() => Member(WellKnownJwtClaimNames.Htm, Quoted(WellKnownHttpMethods.Post));


    /// <summary>The claims set's <c>htu</c>, the token endpoint.</summary>
    /// <returns>The member's JSON text.</returns>
    private static string HtuClaim() => Member(WellKnownJwtClaimNames.Htu, Quoted(Target));
}
