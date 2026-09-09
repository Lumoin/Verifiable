using System.Linq;
using System.Security;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the JOSE header parameter name table <see cref="WellKnownJoseHeaderNames"/> — the
/// <c>alg</c> entry required by
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</see>,
/// the table's case-sensitive comparison rule, its canonicalization rows, its separation from the
/// RFC 7517 Section 4.4 JWK member of the same spelling, and the three library parsing paths that
/// read a protected header's <c>alg</c> through it.
/// </summary>
[TestClass]
internal sealed class WellKnownJoseHeaderNamesTests
{
    public TestContext TestContext { get; set; } = null!;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>Serializes a JOSE header the way the library's own JSON leaf does.</summary>
    private static JwtHeaderSerializer JwtHeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    /// <summary>Serializes a JWT payload the way the library's own JSON leaf does.</summary>
    private static JwtPayloadSerializer JwtPayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    /// <summary>One canonicalized JOSE header parameter name under test.</summary>
    /// <param name="FieldName">The <see cref="WellKnownJoseHeaderNames"/> field that declares it, for messages only.</param>
    /// <param name="TabledValue">The table's own interned constant for this field, read directly rather than by name.</param>
    /// <param name="WireValue">The exact JSON member name as it appears in a JOSE header.</param>
    /// <param name="Predicate">The table's own <c>Is*</c> predicate for this name.</param>
    private sealed record TabledName(string FieldName, string TabledValue, string WireValue, Func<string, bool> Predicate);


    /// <summary>
    /// The names <see cref="WellKnownJoseHeaderNames"/> both predicates on and canonicalizes, each
    /// row's wire value transcribed from the defining specification rather than from the table.
    /// </summary>
    /// <returns>The tabled names in declaration order.</returns>
    private static TabledName[] AllCanonicalizedNames() =>
    [
        new(nameof(WellKnownJoseHeaderNames.Alg), WellKnownJoseHeaderNames.Alg, "alg", WellKnownJoseHeaderNames.IsAlg),
        new(nameof(WellKnownJoseHeaderNames.B64), WellKnownJoseHeaderNames.B64, "b64", WellKnownJoseHeaderNames.IsB64),
        new(nameof(WellKnownJoseHeaderNames.Typ), WellKnownJoseHeaderNames.Typ, "typ", WellKnownJoseHeaderNames.IsTyp),
        new(nameof(WellKnownJoseHeaderNames.Cty), WellKnownJoseHeaderNames.Cty, "cty", WellKnownJoseHeaderNames.IsCty),
        new(nameof(WellKnownJoseHeaderNames.Enc), WellKnownJoseHeaderNames.Enc, "enc", WellKnownJoseHeaderNames.IsEnc),
        new(nameof(WellKnownJoseHeaderNames.Epk), WellKnownJoseHeaderNames.Epk, "epk", WellKnownJoseHeaderNames.IsEpk),
        new(nameof(WellKnownJoseHeaderNames.Apu), WellKnownJoseHeaderNames.Apu, "apu", WellKnownJoseHeaderNames.IsApu),
        new(nameof(WellKnownJoseHeaderNames.Apv), WellKnownJoseHeaderNames.Apv, "apv", WellKnownJoseHeaderNames.IsApv),
        new(nameof(WellKnownJoseHeaderNames.Skid), WellKnownJoseHeaderNames.Skid, "skid", WellKnownJoseHeaderNames.IsSkid),
        new(nameof(WellKnownJoseHeaderNames.Jwk), WellKnownJoseHeaderNames.Jwk, "jwk", WellKnownJoseHeaderNames.IsJwk),
        new(nameof(WellKnownJoseHeaderNames.Jwt), WellKnownJoseHeaderNames.Jwt, "jwt", WellKnownJoseHeaderNames.IsJwt)
    ];


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</see>:
    /// "The 'alg' (algorithm) Header Parameter identifies the cryptographic algorithm used to secure
    /// the JWS. … This Header Parameter MUST be present and MUST be understood and processed by
    /// implementations." The name the library reads that parameter under is the three ASCII characters
    /// the section registers, and its UTF-8 twin is the same three bytes.
    /// </summary>
    [TestMethod]
    public void AlgIsTheRegisteredHeaderParameterNameAndItsUtf8Twin()
    {
        Assert.AreEqual("alg", WellKnownJoseHeaderNames.Alg,
            "RFC 7515 Section 4.1.1 registers the Header Parameter name as the three characters \"alg\".");

        Assert.AreEqual(WellKnownJoseHeaderNames.Alg, Encoding.UTF8.GetString(WellKnownJoseHeaderNames.AlgUtf8),
            "AlgUtf8 must be the UTF-8 encoding of Alg -- the span readers and the dictionary readers must agree on one name.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</see>
    /// names the parameter <c>alg</c>, and the registration template of Section 9.1.1 states of a Header
    /// Parameter Name: "This name is case sensitive. Names may not match other registered names in a
    /// case-insensitive manner unless the Designated Experts state that there is a compelling reason to
    /// allow an exception." The table's comparison rule is therefore case-SENSITIVE: only the exact
    /// registered spelling is <c>alg</c>.
    /// </summary>
    /// <param name="name">A candidate header parameter name.</param>
    /// <param name="isExpectedToBeAlg">Whether the registered case-sensitive name recognizes it.</param>
    [TestMethod]
    [DataRow("alg", true)]
    [DataRow("ALG", false)]
    [DataRow("Alg", false)]
    [DataRow("aLg", false)]
    [DataRow("alg ", false)]
    public void IsAlgIsCaseSensitivePerTheRegisteredName(string name, bool isExpectedToBeAlg)
    {
        Assert.AreEqual(isExpectedToBeAlg, WellKnownJoseHeaderNames.IsAlg(name),
            $"JOSE Header Parameter names are case sensitive (RFC 7515 Section 9.1.1), so IsAlg(\"{name}\") must be {isExpectedToBeAlg}.");
    }


    /// <summary>
    /// The case-sensitive comparison rule the registry of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</see>
    /// belongs to ("This name is case sensitive") is the whole table's rule, not just <c>alg</c>'s:
    /// <see cref="WellKnownJoseHeaderNames.Equals"/> matches the exact registered spelling and nothing else.
    /// </summary>
    [TestMethod]
    public void EqualsIsCaseSensitiveForEveryTabledName()
    {
        foreach(TabledName entry in AllCanonicalizedNames())
        {
            Assert.IsTrue(WellKnownJoseHeaderNames.Equals(entry.WireValue, entry.TabledValue),
                $"{entry.FieldName} must compare equal to its own registered spelling \"{entry.WireValue}\".");

            Assert.IsFalse(WellKnownJoseHeaderNames.Equals(entry.WireValue.ToUpperInvariant(), entry.TabledValue),
                $"JOSE Header Parameter names are case sensitive, so \"{entry.WireValue.ToUpperInvariant()}\" must not equal {entry.FieldName}.");
        }
    }


    /// <summary>
    /// Each tabled name's own <c>Is*</c> predicate recognizes its registered spelling and rejects every
    /// other registered spelling — the entries this table names are pairwise distinguishable, so a parser
    /// keying off one of them can never act on another
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</see>'s
    /// parameter is one entry of the shared JWS/JWE Header Parameter registry, not the registry itself).
    /// </summary>
    [TestMethod]
    public void EachPredicateRecognizesItsOwnNameAndRejectsTheOthers()
    {
        TabledName[] entries = AllCanonicalizedNames();
        for(int i = 0; i < entries.Length; ++i)
        {
            Assert.IsTrue(entries[i].Predicate(entries[i].WireValue),
                $"The predicate for {entries[i].FieldName} must recognize its registered name \"{entries[i].WireValue}\".");

            for(int j = 0; j < entries.Length; ++j)
            {
                if(i == j)
                {
                    continue;
                }

                Assert.IsFalse(entries[i].Predicate(entries[j].WireValue),
                    $"The predicate for {entries[i].FieldName} must reject \"{entries[j].WireValue}\" ({entries[j].FieldName}).");
            }
        }
    }


    /// <summary>
    /// <see cref="WellKnownJoseHeaderNames.GetCanonicalizedValue"/> hands back the table's own interned
    /// instance — by reference — for every tabled name, so a name read off the wire as a freshly
    /// allocated string becomes the one shared constant the library compares and stores; an unrecognized
    /// name passes through unchanged, because the registry
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</see>
    /// registers into is open to Public and Private Header Parameter names as well.
    /// </summary>
    [TestMethod]
    public void GetCanonicalizedValueReturnsTheInternedInstanceForEveryTabledNameAndPassesOthersThrough()
    {
        foreach(TabledName entry in AllCanonicalizedNames())
        {
            string equalButDistinctInstance = new(entry.WireValue.ToCharArray());
            string canonicalized = WellKnownJoseHeaderNames.GetCanonicalizedValue(equalButDistinctInstance);

            Assert.AreSame(entry.TabledValue, canonicalized,
                $"GetCanonicalizedValue(\"{entry.WireValue}\") must return the interned {entry.FieldName} constant, not the caller's instance.");
        }

        string unknown = new("x-private-parameter".ToCharArray());

        Assert.AreSame(unknown, WellKnownJoseHeaderNames.GetCanonicalizedValue(unknown),
            "An unregistered Private Header Parameter name must pass through GetCanonicalizedValue unchanged.");
    }


    /// <summary>
    /// The JWS/JWE <c>alg</c> Header Parameter of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</see>
    /// ("identifies the cryptographic algorithm used to secure the JWS") and the JWK <c>alg</c> member of
    /// RFC 7517 Section 4.4 (the algorithm intended for use with a key) are two different parameters that
    /// happen to share a spelling: each table declares its own entry and canonicalizes through its own
    /// rows, and the two read the same three characters. Interning makes the two constants one instance —
    /// a storage consequence, not a merge of the two registries.
    /// </summary>
    [TestMethod]
    public void TheJoseAlgHeaderAndTheJwkAlgMemberAreSeparatelyTabledNamesSharingASpelling()
    {
        Assert.AreEqual(WellKnownJoseHeaderNames.Alg, WellKnownJwkMemberNames.Alg,
            "Both registries spell their parameter \"alg\"; the tables differ in what the name means, not in how it reads.");

        Assert.AreSame(WellKnownJoseHeaderNames.Alg, WellKnownJoseHeaderNames.GetCanonicalizedValue(new string("alg".ToCharArray())),
            "The JOSE header table must canonicalize \"alg\" onto its own entry.");

        Assert.AreSame(WellKnownJwkMemberNames.Alg, WellKnownJwkMemberNames.GetCanonicalizedValue(new string("alg".ToCharArray())),
            "The JWK member table must canonicalize \"alg\" onto its own entry.");
    }


    /// <summary>
    /// The compact JWE parsing path reads the protected header's <c>alg</c> through the table: a compact
    /// JWE produced with <c>ECDH-ES</c> reparses to a header whose algorithm entry is keyed by the
    /// interned <see cref="WellKnownJoseHeaderNames.Alg"/> instance and carries the declared value —
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</see>:
    /// "This Header Parameter MUST be present and MUST be understood and processed by implementations."
    /// </summary>
    [TestMethod]
    public async Task CompactJweProtectedHeaderAlgIsReadThroughTheTable()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using JweMessage encrypted = await UnencryptedJwe.ForEcdhEs(
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"vp_token\":\"test\"}").AsMemory()).EncryptAsync(
                publicKey,
                JwtHeaderSerializer,
                TestSetup.Base64UrlEncoder,
                CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

        using AeadMessage parsed = JweParsing.ParseCompact(
            encrypted.ToCompactJwe(TestSetup.Base64UrlEncoder),
            WellKnownJweAlgorithms.EcdhEs,
            WellKnownJweEncryptionAlgorithms.A128Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        AssertAlgIsReadThroughTheTable(parsed.Header, WellKnownJweAlgorithms.EcdhEs);
    }


    /// <summary>
    /// The General JSON Serialization parsing path reads the protected header's <c>alg</c> through the
    /// same table: an anoncrypt message produced with <c>ECDH-ES+A256KW</c> reparses to a header whose
    /// algorithm entry is keyed by the interned <see cref="WellKnownJoseHeaderNames.Alg"/> instance and
    /// carries the declared value —
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</see>:
    /// "This Header Parameter MUST be present and MUST be understood and processed by implementations."
    /// </summary>
    [TestMethod]
    public async Task GeneralJsonJweProtectedHeaderAlgIsReadThroughTheTable()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral =
            BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient =
            BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        string generalJson;
        using(GeneralJweMessage encrypted = await GeneralJweEncryptionExtensions.EncryptAnoncryptAsync(
            Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"type\":\"https://didcomm.org/basicmessage/2.0/message\"}"),
            new List<GeneralJweRecipientInput> { new("did:example:recipient-0#key-1", recipientPublic) },
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            protectedHeaderExtras: null,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            JwtHeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctionsAdapter.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false))
        {
            generalJson = encrypted.ToGeneralJson(TestSetup.Base64UrlEncoder);
        }

        using AeadGeneralMessage parsed = GeneralJweParsing.ParseGeneralJson(
            generalJson,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);

        AssertAlgIsReadThroughTheTable(parsed.Header, WellKnownJweAlgorithms.EcdhEsA256Kw);
    }


    /// <summary>
    /// The unsigned-JAR gate reads the compact request object's protected header <c>alg</c> through the
    /// table's UTF-8 twin before it will treat the bytes as an unsecured JWS: a JAR signed with
    /// <c>ES256</c> is refused, and the refusal reports the exact algorithm the read extracted — a value
    /// only obtainable by matching the header member the table names.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515, Section 4.1.1</see>:
    /// "The JWS Signature value is not valid if the 'alg' value does not represent a supported algorithm
    /// or if there is not a key for use with that algorithm associated with the party that digitally
    /// signed or MACed the content."
    /// </summary>
    [TestMethod]
    public async Task UnsignedJarGateReadsTheProtectedHeaderAlgThroughTheTable()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory signingPublicKey = signingKeys.PublicKey;
        using PrivateKeyMemory signingPrivateKey = signingKeys.PrivateKey;

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingPrivateKey.Tag);
        JwtHeader header = new()
        {
            [WellKnownJoseHeaderNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.OauthAuthzReqJwt
        };

        JwtPayload payload = new()
        {
            ["iss"] = "https://verifier.example.com"
        };

        string compactJar;
        using(JwsMessage signed = await new UnsignedJwt(header, payload).SignAsync(
            signingPrivateKey,
            JwtHeaderSerializer,
            JwtPayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            compactJar = JwsSerialization.SerializeCompact(signed, TestSetup.Base64UrlEncoder);
        }

        SecurityException refusal = await Assert.ThrowsExactlyAsync<SecurityException>(
            async () => await JarExtensions.ParseUnsignedJarAsync(
                compactJar,
                TestSetup.Base64UrlDecoder,
                DeserializeJarSegment,
                DeserializeJarSegment,
                static json => JsonSerializer.Deserialize<DcqlQuery>(json, TestSetup.DefaultSerializationOptions)!,
                static json => JsonSerializer.Deserialize<VerifierClientMetadata>(json, TestSetup.DefaultSerializationOptions)!,
                StateParameterPolicy.Required,
                Pool).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.Contains($"alg='{algorithm}'", refusal.Message, StringComparison.Ordinal,
            $"The gate must report the 'alg' it read from the protected header, proving the read matched the \"{WellKnownJoseHeaderNames.Alg}\" member the table names.");
    }


    /// <summary>Deserializes one decoded compact segment the way the authorization server wires it.</summary>
    /// <param name="jsonBytes">The decoded JSON bytes of one compact segment.</param>
    /// <returns>The segment's members.</returns>
    private static IReadOnlyDictionary<string, object> DeserializeJarSegment(ReadOnlySpan<byte> jsonBytes) =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(jsonBytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("JAR segment JSON parsed to null.");


    /// <summary>
    /// Asserts that a reparsed JOSE header surfaces its algorithm under the table's own interned
    /// <see cref="WellKnownJoseHeaderNames.Alg"/> instance and with the declared value — the parser read
    /// the member through the table rather than through a private literal.
    /// </summary>
    /// <param name="parsedHeader">The header the parser produced.</param>
    /// <param name="expectedAlgorithm">The key management algorithm the message was produced with.</param>
    private static void AssertAlgIsReadThroughTheTable(IReadOnlyDictionary<string, object> parsedHeader, string expectedAlgorithm)
    {
        Assert.IsTrue(parsedHeader.TryGetValue(WellKnownJoseHeaderNames.Alg, out object? parsedAlg),
            "The reparsed protected header must surface its 'alg' Header Parameter; RFC 7515 Section 4.1.1 makes it MUST-be-present and MUST-be-understood.");

        Assert.AreEqual(expectedAlgorithm, parsedAlg as string,
            "The parsed 'alg' must be the algorithm the protected header declares.");

        string algKey = parsedHeader.Keys.Single(WellKnownJoseHeaderNames.IsAlg);

        Assert.AreSame(WellKnownJoseHeaderNames.Alg, algKey,
            "The parser must key the algorithm under the table's interned Alg constant, not under a private \"alg\" literal.");
    }
}
