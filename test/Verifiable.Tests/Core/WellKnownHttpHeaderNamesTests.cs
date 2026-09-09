using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.DidComm.Transport;
using Verifiable.Foundation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Core;

/// <summary>
/// Tests for the HTTP field name table <see cref="WellKnownHttpHeaderNames"/> — its placement in the
/// Core transport vocabulary beside <see cref="HttpHeaderSet"/>, the exact spelling and UTF-8 twin of
/// every entry, the case-insensitive comparison rule of
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>, the
/// canonicalization rows that fold any received casing onto one interned instance, and the
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3">RFC 9110, Section 8.3</see>
/// <c>Content-Type</c> a library-composed POST carries.
/// </summary>
[TestClass]
internal sealed class WellKnownHttpHeaderNamesTests
{
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static Uri DidCommEndpoint { get; } = new("https://recipient.example/didcomm");


    /// <summary>One HTTP field name the table registers.</summary>
    /// <param name="FieldName">The <see cref="WellKnownHttpHeaderNames"/> field that declares it, for messages only.</param>
    /// <param name="TabledValue">The table's own interned constant for this field, read directly rather than by name.</param>
    /// <param name="WireValue">The exact field name as its defining specification spells it.</param>
    /// <param name="LowerCasedValue">
    /// The same field name spelled all-lowercase, as an HTTP/2 or HTTP/3 sender emits it. Written out
    /// rather than computed so the case-insensitivity proof compares two transcribed spellings instead
    /// of a spelling against a transform of itself.
    /// </param>
    /// <param name="UpperCasedValue">The same field name spelled all-uppercase.</param>
    /// <param name="Predicate">The table's own <c>Is*</c> predicate for this name.</param>
    private sealed record TabledHeader(
        string FieldName,
        string TabledValue,
        string WireValue,
        string LowerCasedValue,
        string UpperCasedValue,
        Func<string, bool> Predicate);


    /// <summary>
    /// Every field name the table registers, each row's wire value transcribed from the defining
    /// specification: <c>Authorization</c> (RFC 9110 Section 11.6.2), <c>Accept</c> (Section 12.5.1),
    /// <c>Accept-Language</c> (Section 12.5.4), <c>Content-Language</c> (Section 8.5),
    /// <c>Content-Type</c> (Section 8.3), <c>DPoP</c> / <c>DPoP-Nonce</c> (RFC 9449 Sections 4 and 8),
    /// <c>Cache-Control</c> (RFC 9111 Section 5.2), <c>WWW-Authenticate</c> (RFC 9110 Section 11.6.1),
    /// <c>Location</c> (Section 10.2.2), <c>Date</c> (Section 6.6.1), and <c>Age</c> / <c>Expires</c>
    /// (RFC 9111 Sections 5.1 and 5.3).
    /// </summary>
    /// <returns>The registered names in declaration order.</returns>
    private static TabledHeader[] AllRegisteredHeaders() =>
    [
        new(nameof(WellKnownHttpHeaderNames.Authorization), WellKnownHttpHeaderNames.Authorization, "Authorization", "authorization", "AUTHORIZATION", WellKnownHttpHeaderNames.IsAuthorization),
        new(nameof(WellKnownHttpHeaderNames.Accept), WellKnownHttpHeaderNames.Accept, "Accept", "accept", "ACCEPT", WellKnownHttpHeaderNames.IsAccept),
        new(nameof(WellKnownHttpHeaderNames.AcceptLanguage), WellKnownHttpHeaderNames.AcceptLanguage, "Accept-Language", "accept-language", "ACCEPT-LANGUAGE", WellKnownHttpHeaderNames.IsAcceptLanguage),
        new(nameof(WellKnownHttpHeaderNames.ContentLanguage), WellKnownHttpHeaderNames.ContentLanguage, "Content-Language", "content-language", "CONTENT-LANGUAGE", WellKnownHttpHeaderNames.IsContentLanguage),
        new(nameof(WellKnownHttpHeaderNames.ContentType), WellKnownHttpHeaderNames.ContentType, "Content-Type", "content-type", "CONTENT-TYPE", WellKnownHttpHeaderNames.IsContentType),
        new(nameof(WellKnownHttpHeaderNames.DPoP), WellKnownHttpHeaderNames.DPoP, "DPoP", "dpop", "DPOP", WellKnownHttpHeaderNames.IsDPoP),
        new(nameof(WellKnownHttpHeaderNames.DPoPNonce), WellKnownHttpHeaderNames.DPoPNonce, "DPoP-Nonce", "dpop-nonce", "DPOP-NONCE", WellKnownHttpHeaderNames.IsDPoPNonce),
        new(nameof(WellKnownHttpHeaderNames.CacheControl), WellKnownHttpHeaderNames.CacheControl, "Cache-Control", "cache-control", "CACHE-CONTROL", WellKnownHttpHeaderNames.IsCacheControl),
        new(nameof(WellKnownHttpHeaderNames.WwwAuthenticate), WellKnownHttpHeaderNames.WwwAuthenticate, "WWW-Authenticate", "www-authenticate", "WWW-AUTHENTICATE", WellKnownHttpHeaderNames.IsWwwAuthenticate),
        new(nameof(WellKnownHttpHeaderNames.Location), WellKnownHttpHeaderNames.Location, "Location", "location", "LOCATION", WellKnownHttpHeaderNames.IsLocation),
        new(nameof(WellKnownHttpHeaderNames.Date), WellKnownHttpHeaderNames.Date, "Date", "date", "DATE", WellKnownHttpHeaderNames.IsDate),
        new(nameof(WellKnownHttpHeaderNames.Age), WellKnownHttpHeaderNames.Age, "Age", "age", "AGE", WellKnownHttpHeaderNames.IsAge),
        new(nameof(WellKnownHttpHeaderNames.Expires), WellKnownHttpHeaderNames.Expires, "Expires", "expires", "EXPIRES", WellKnownHttpHeaderNames.IsExpires)
    ];


    /// <summary>
    /// The field names of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see> are a
    /// transport vocabulary every binding reads — HTTP, DIDComm, VCALM, and the did:webvh resolvers
    /// alike — so the table lives in the Core transport namespace beside the header set that carries the
    /// fields, not inside any one protocol's assembly.
    /// </summary>
    [TestMethod]
    public void TheTableLivesInTheCoreTransportNamespaceBesideTheHeaderSet()
    {
        Assert.AreEqual("Verifiable.Core.Transport", typeof(WellKnownHttpHeaderNames).Namespace,
            "The HTTP field name table is a transport vocabulary and must live in Verifiable.Core.Transport.");

        Assert.AreEqual(typeof(HttpHeaderSet).Namespace, typeof(WellKnownHttpHeaderNames).Namespace,
            "The field name table and the header set that carries those fields must be one vocabulary in one namespace.");
    }


    /// <summary>
    /// Every entry reads the exact field name its defining specification spells — the canonical spelling
    /// a sender generates, even though a recipient must accept any casing per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>
    /// ("Field names are case-insensitive and ought to be registered within the 'Hypertext Transfer
    /// Protocol (HTTP) Field Name Registry'").
    /// </summary>
    [TestMethod]
    public void EveryEntrySpellsItsRegisteredFieldNameVerbatim()
    {
        foreach(TabledHeader entry in AllRegisteredHeaders())
        {
            Assert.AreEqual(entry.WireValue, entry.TabledValue,
                $"{entry.FieldName} must read \"{entry.WireValue}\" verbatim as its defining specification spells it.");
        }
    }


    /// <summary>
    /// Every entry carries a UTF-8 twin holding the same bytes as its string, so a span reader and a
    /// string comparison name the identical field of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>
    /// ("field-name = token") rather than drifting apart. The twins are read directly rather than
    /// swept by reflection: a byte span cannot cross the reflection boundary.
    /// </summary>
    [TestMethod]
    public void EveryEntryHasAUtf8TwinHoldingTheSameBytes()
    {
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.Authorization), WellKnownHttpHeaderNames.Authorization, WellKnownHttpHeaderNames.AuthorizationUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.Accept), WellKnownHttpHeaderNames.Accept, WellKnownHttpHeaderNames.AcceptUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.AcceptLanguage), WellKnownHttpHeaderNames.AcceptLanguage, WellKnownHttpHeaderNames.AcceptLanguageUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.ContentLanguage), WellKnownHttpHeaderNames.ContentLanguage, WellKnownHttpHeaderNames.ContentLanguageUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.ContentType), WellKnownHttpHeaderNames.ContentType, WellKnownHttpHeaderNames.ContentTypeUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.DPoP), WellKnownHttpHeaderNames.DPoP, WellKnownHttpHeaderNames.DPoPUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.DPoPNonce), WellKnownHttpHeaderNames.DPoPNonce, WellKnownHttpHeaderNames.DPoPNonceUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.CacheControl), WellKnownHttpHeaderNames.CacheControl, WellKnownHttpHeaderNames.CacheControlUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.WwwAuthenticate), WellKnownHttpHeaderNames.WwwAuthenticate, WellKnownHttpHeaderNames.WwwAuthenticateUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.Location), WellKnownHttpHeaderNames.Location, WellKnownHttpHeaderNames.LocationUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.Date), WellKnownHttpHeaderNames.Date, WellKnownHttpHeaderNames.DateUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.Age), WellKnownHttpHeaderNames.Age, WellKnownHttpHeaderNames.AgeUtf8);
        AssertUtf8Twin(nameof(WellKnownHttpHeaderNames.Expires), WellKnownHttpHeaderNames.Expires, WellKnownHttpHeaderNames.ExpiresUtf8);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>: "Field
    /// names are case-insensitive and ought to be registered within the 'Hypertext Transfer Protocol
    /// (HTTP) Field Name Registry'". Every entry's own predicate therefore recognizes its field name in
    /// the registered spelling, in all-lowercase, and in all-uppercase alike.
    /// </summary>
    [TestMethod]
    public void EveryPredicateIsCaseInsensitiveOverItsOwnFieldName()
    {
        foreach(TabledHeader entry in AllRegisteredHeaders())
        {
            Assert.IsTrue(entry.Predicate(entry.WireValue),
                $"The predicate for {entry.FieldName} must recognize \"{entry.WireValue}\".");

            Assert.IsTrue(entry.Predicate(entry.LowerCasedValue),
                $"Field names are case-insensitive (RFC 9110 Section 5.1), so the predicate for {entry.FieldName} must recognize \"{entry.LowerCasedValue}\".");

            Assert.IsTrue(entry.Predicate(entry.UpperCasedValue),
                $"Field names are case-insensitive (RFC 9110 Section 5.1), so the predicate for {entry.FieldName} must recognize \"{entry.UpperCasedValue}\".");
        }
    }


    /// <summary>
    /// A field name "labels the corresponding field value as having the semantics defined by that name"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>), so
    /// the table's entries must be pairwise distinguishable even under the case-insensitive rule: no
    /// entry's predicate may claim another entry's field name in any casing.
    /// </summary>
    [TestMethod]
    public void EveryPredicateRejectsEveryOtherRegisteredFieldName()
    {
        TabledHeader[] entries = AllRegisteredHeaders();
        for(int i = 0; i < entries.Length; ++i)
        {
            for(int j = 0; j < entries.Length; ++j)
            {
                if(i == j)
                {
                    continue;
                }

                Assert.IsFalse(entries[i].Predicate(entries[j].WireValue),
                    $"The predicate for {entries[i].FieldName} must reject \"{entries[j].WireValue}\" ({entries[j].FieldName}).");

                Assert.IsFalse(entries[i].Predicate(entries[j].LowerCasedValue),
                    $"The predicate for {entries[i].FieldName} must reject \"{entries[j].LowerCasedValue}\" in any casing.");
            }
        }
    }


    /// <summary>
    /// Because "field names are case-insensitive"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>), a
    /// name received in any casing canonicalizes onto the one interned constant the table declares — the
    /// instance, not merely an equal string — so the whole library stores and compares one spelling.
    /// </summary>
    /// <param name="casing">Which casing the received field name arrives in.</param>
    [TestMethod]
    [DataRow("registered")]
    [DataRow("lower")]
    [DataRow("upper")]
    public void GetCanonicalizedValueFoldsAnyReceivedCasingOntoTheInternedInstance(string casing)
    {
        foreach(TabledHeader entry in AllRegisteredHeaders())
        {
            string received = casing switch
            {
                "lower" => new string(entry.LowerCasedValue.ToCharArray()),
                "upper" => new string(entry.UpperCasedValue.ToCharArray()),
                _ => new string(entry.WireValue.ToCharArray())
            };

            Assert.AreSame(entry.TabledValue, WellKnownHttpHeaderNames.GetCanonicalizedValue(received),
                $"\"{received}\" must canonicalize onto the interned {entry.FieldName} constant, since field names are case-insensitive (RFC 9110 Section 5.1).");
        }
    }


    /// <summary>
    /// The registry of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see> is open
    /// — a field name the table does not register still labels a field value — so an unrecognized name
    /// passes through canonicalization unchanged rather than being rewritten or dropped.
    /// </summary>
    [TestMethod]
    public void GetCanonicalizedValueReturnsAnUnregisteredFieldNameUnchanged()
    {
        string unregistered = new("X-Deployment-Trace".ToCharArray());

        Assert.AreSame(unregistered, WellKnownHttpHeaderNames.GetCanonicalizedValue(unregistered),
            "A field name outside this table must pass through GetCanonicalizedValue unchanged.");
    }


    /// <summary>
    /// The table's central comparison rule is the case-insensitive one of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see> ("Field
    /// names are case-insensitive"), applied ordinally: two spellings of one field name are equal, and
    /// two different field names are not, whatever their casing.
    /// </summary>
    /// <param name="nameA">The first field name.</param>
    /// <param name="nameB">The second field name.</param>
    /// <param name="isExpectedEqual">Whether the two name the same HTTP field.</param>
    [TestMethod]
    [DataRow("Content-Type", "content-type", true)]
    [DataRow("Content-Type", "CONTENT-TYPE", true)]
    [DataRow("WWW-Authenticate", "www-authenticate", true)]
    [DataRow("DPoP-Nonce", "dpop-nonce", true)]
    [DataRow("Content-Type", "Content-Language", false)]
    [DataRow("Date", "Age", false)]
    [DataRow("Accept", "Accept-Language", false)]
    public void EqualsIsCaseInsensitiveAndOrdinal(string nameA, string nameB, bool isExpectedEqual)
    {
        Assert.AreEqual(isExpectedEqual, WellKnownHttpHeaderNames.Equals(nameA, nameB),
            $"Field names are case-insensitive (RFC 9110 Section 5.1), so Equals(\"{nameA}\", \"{nameB}\") must be {isExpectedEqual}.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3">RFC 9110, Section 8.3</see>: "A
    /// sender that generates a message containing content SHOULD generate a Content-Type header field in
    /// that message unless the intended media type of the enclosed representation is unknown to the
    /// sender." The DIDComm HTTPS binding is such a sender, and
    /// <c>DidCommHttpTransportTests.TransmitsAsPostWithEncryptedContentType</c> already proves the field
    /// is present on the request it composes. What is proved here instead is that the field it composed
    /// is the one this table names: the header set surfaces it through its
    /// <see cref="HttpHeaderSet.ContentType"/> convenience (which reads
    /// <see cref="WellKnownHttpHeaderNames.ContentType"/>) and through a lookup by the table constant in
    /// any casing, per the case-insensitivity of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TheDidCommPostsContentTypeIsTheFieldThisTableNames()
    {
        OutboundRequest? composed = null;
        ValueTask<OutboundResponse> Capture(OutboundRequest request, ExchangeContext context, CancellationToken cancellationToken)
        {
            composed = request;

            return ValueTask.FromResult(new OutboundResponse { StatusCode = 202 });
        }

        using DidCommEncryptedMessage message = DidCommEncryptedMessage.Create(
            "{\"protected\":\"abc\",\"ciphertext\":\"xyz\"}"u8, BufferTags.Json, Pool);

        DidCommTransmitResult result = await message.TransmitAsync(
            DidCommEndpoint,
            new ExchangeContext(),
            DidCommHttpTransport.CreateSendDelegate(Capture),
            CancellationToken.None).ConfigureAwait(false);

        Assert.IsTrue(result.IsAccepted, "The canned transport answers 202, so the transmit must be an accepted receipt.");
        Assert.IsNotNull(composed, "The binding must compose an outbound request for the POST.");

        Assert.AreEqual("application/didcomm-encrypted+json", composed!.Headers.ContentType,
            "The header set's ContentType convenience reads WellKnownHttpHeaderNames.ContentType; the SHOULD of RFC 9110 Section 8.3 must be satisfied under that name.");

        Assert.IsTrue(composed!.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? byTableConstant),
            "The composed Content-Type must be retrievable by the table's own constant.");

        Assert.AreEqual(composed!.Headers.ContentType, byTableConstant,
            "The convenience and the table-constant lookup must read one and the same field value.");

        Assert.IsTrue(composed!.Headers.TryGetValue("CONTENT-TYPE", out string? byOtherCasing),
            "Field names are case-insensitive (RFC 9110 Section 5.1), so the composed Content-Type must be retrievable under any casing.");

        Assert.AreEqual(composed!.Headers.ContentType, byOtherCasing,
            "A differently cased lookup must read the same field value, not a second field.");
    }


    /// <summary>
    /// Asserts that an entry's UTF-8 source literal decodes to the same field name the entry's string
    /// constant holds — the span readers and the string comparisons name one field.
    /// </summary>
    /// <param name="fieldName">The <see cref="WellKnownHttpHeaderNames"/> field under test, for messages only.</param>
    /// <param name="tabledValue">That field's own interned constant.</param>
    /// <param name="utf8Twin">That entry's UTF-8 source literal.</param>
    private static void AssertUtf8Twin(string fieldName, string tabledValue, ReadOnlySpan<byte> utf8Twin)
    {
        Assert.AreEqual(tabledValue, Encoding.UTF8.GetString(utf8Twin),
            $"{fieldName}Utf8 must be the UTF-8 encoding of {fieldName}.");
    }
}
