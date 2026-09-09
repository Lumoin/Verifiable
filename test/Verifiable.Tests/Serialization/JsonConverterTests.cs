using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;
using Verifiable.Json;
using Verifiable.Json.Converters;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Tests for individual converters. The fragments are objects that contain the property under test.
/// </summary>
[TestClass]
internal sealed class JsonConverterTests
{
    [TestMethod]
    public void RoundtripControllerSingle()
    {
        //A fragment for a single controller instance. Either a single or multiple controller case is possible in one document.
        // lang=json, strict
        const string OriginalInputJson = @"""did:test:0x06048B83FAdaCdCB20198ABc45562Df1A3e289aF""";
        var converter = new SingleOrArrayControllerConverter();
        var controllers = GetConverted(OriginalInputJson, converter);
        Assert.AreEqual(1, controllers?.Length);

        var backConvertedJson = GetConverted(controllers, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    [TestMethod]
    public void RoundtripControllerArray()
    {
        //A fragment for an array of controller instances. Either a single or multiple controller case is possible in one document.
        const string OriginalInputJson = @"[""did:test:0x16048B83FAdaCdCB20198ABc45562Df1A3e289aF"",""did:test:0x26048B83FAdaCdCB20198ABc45562Df1A3e289aF""]";
        var converter = new SingleOrArrayControllerConverter();
        var controllers = GetConverted(OriginalInputJson, converter);
        Assert.AreEqual(2, controllers?.Length);

        var backConvertedJson = GetConverted(controllers, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    [TestMethod]
    public void RoundtripService()
    {
        //A sample test service copied from https://www.w3.org/TR/did-core/.
        const string OriginalInputJson = /*lang=json,strict*/ @"{""id"":""did:example:123456789abcdefghi#oidc"",""type"":""OpenIdConnectVersion1.0Service"",""serviceEndpoint"":""https://openid.example.com/""}";

        var converter = new ServiceConverter();

        var service = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(service);

        var backConvertedJson = GetConverted(service, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    [TestMethod]
    public void RoundtripOneUriContext()
    {
        //The DID URI from https://www.w3.org/TR/did-core/.
        // lang=json, strict
        const string OriginalInputJson = @"""https://www.w3.org/ns/did/v1""";
        var converter = new JsonLdContextConverter();

        var context = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(context);

        var backConvertedJson = GetConverted(context, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    [TestMethod]
    public void RoundtripCollectionUriContext()
    {
        //The DID URI from https://www.w3.org/TR/did-core/.
        const string OriginalInputJson = @"[""https://w3id.org/future-method/v1"",""https://w3id.org/veres-one/v1""]";
        var converter = new JsonLdContextConverter();

        var service = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(service);

        var backConvertedJson = GetConverted(service, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    [TestMethod]
    public void RountripComplexContext1()
    {
        //A sample complex @context copied from https://json-ld.org/playground/ JSON-LD 1.1 compacted Place sample.
        string OriginalInputJson = RemoveWhiteSpace(/*lang=json,strict*/ @"{
            ""@context"": {
            ""name"": ""http://schema.org/name"",
            ""description"": ""http://schema.org/description"",
            ""image"": {
                ""@id"": ""http://schema.org/image"",
                ""@type"": ""@id""
            },
            ""geo"": ""http://schema.org/geo"",
            ""latitude"": {
                ""@id"": ""http://schema.org/latitude"",
                ""@type"": ""xsd:float""
              },
           ""longitude"": {
                ""@id"": ""http://schema.org/longitude"",
                ""@type"": ""xsd:float""
            },
           ""xsd"": ""http://www.w3.org/2001/XMLSchema#""
           },
           ""name"": ""The Empire State Building"",
           ""description"": ""The Empire State Building is a 102-story landmark in New York City."",
           ""image"": ""http://www.civil.usherbrooke.ca/cours/gci215a/empire-state-building.jpg"",
           ""geo"": {
              ""latitude"": ""40.75"",
              ""longitude"": ""73.98""
              }
            }");

        var converter = new JsonLdContextConverter();

        var service = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(service);

        var backConvertedJson = GetConverted(service, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    [TestMethod]
    public void RountripSidetreeIonContest1()
    {
        //A sample complex @context from Sidetree ION with a base64-encoded DID method-specific identifier.
        string OriginalInputJson = RemoveWhiteSpace(/*lang=json,strict*/ @"[ ""https://www.w3.org/ns/did/v1"",
        {
            ""@base"": ""did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0""
        }]");

        var converter = new JsonLdContextConverter();

        var service = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(service);

        var backConvertedJson = GetConverted(service, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    /// <summary>
    /// A single-element array MUST stay an array on roundtrip: <see cref="Verifiable.Core.Model.Common.ContextForm.Array"/>
    /// is a wire-shape choice distinct from a bare scalar string, and a re-serialized document's bytes must not
    /// collapse the two, since JCS-based Data Integrity proofs sign exactly those bytes.
    /// </summary>
    [TestMethod]
    public void RoundtripSingleElementArrayContextStaysAnArray()
    {
        // lang=json, strict
        const string OriginalInputJson = @"[""https://www.w3.org/ns/did/v1""]";
        var converter = new JsonLdContextConverter();

        var context = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(context);
        Assert.AreEqual(Verifiable.Core.Model.Common.ContextForm.Array, context.Form);
        Assert.HasCount(1, context.Entries);

        var backConvertedJson = GetConverted(context, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    /// <summary>
    /// A bare inline context definition (an object, not wrapped in an array) roundtrips as a single
    /// <see cref="Verifiable.Core.Model.Common.ContextEntry.IsDefinition"/> entry in
    /// <see cref="Verifiable.Core.Model.Common.ContextForm.Scalar"/> form.
    /// </summary>
    [TestMethod]
    public void RoundtripScalarObjectContext()
    {
        // lang=json, strict
        const string OriginalInputJson = @"{""@vocab"":""https://example.com/""}";
        var converter = new JsonLdContextConverter();

        var context = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(context);
        Assert.AreEqual(Verifiable.Core.Model.Common.ContextForm.Scalar, context.Form);
        Assert.HasCount(1, context.Entries);
        Assert.IsTrue(context.Entries[0].IsDefinition);

        var backConvertedJson = GetConverted(context, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    /// <summary>
    /// A <see langword="null"/>-valued member inside an inline context definition is data, not
    /// absence — <c>{"@vocab":null}</c> is JSON-LD 1.1's way to clear <c>@vocab</c>/<c>@base</c> or
    /// remove a term (see <see cref="Verifiable.Core.Model.Common.ContextEntry.Definition"/>'s own
    /// remarks) — and round-trips byte-identically rather than being dropped.
    /// </summary>
    [TestMethod]
    public void RoundtripScalarObjectContextWithNullValuedMemberPreservesNull()
    {
        // lang=json, strict
        const string OriginalInputJson = @"{""@vocab"":null}";
        var converter = new JsonLdContextConverter();

        var context = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(context);
        Assert.IsTrue(context.Entries[0].IsDefinition);
        Assert.IsTrue(context.Entries[0].Definition!.ContainsKey("@vocab"));
        Assert.IsNull(context.Entries[0].Definition!["@vocab"]);

        var backConvertedJson = GetConverted(context, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    /// <summary>
    /// A <see langword="null"/> element inside an array-valued member of an inline context
    /// definition is an ordinary array element, not absence, and round-trips byte-identically.
    /// </summary>
    [TestMethod]
    public void RoundtripScalarObjectContextWithArrayMemberContainingNullPreservesNull()
    {
        // lang=json, strict
        const string OriginalInputJson = @"{""a"":[1,null]}";
        var converter = new JsonLdContextConverter();

        var context = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(context);
        var arrayMember = (IReadOnlyList<object>)context.Entries[0].Definition!["a"];
        Assert.HasCount(2, arrayMember);
        Assert.AreEqual(1, arrayMember[0]);
        Assert.IsNull(arrayMember[1]);

        var backConvertedJson = GetConverted(context, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-6">RFC 8259 §6 Numbers</see> permits
    /// exponent notation as one lexical form of a JSON number; it does not require an implementation
    /// to preserve the lexical form it read. An inline context definition is an arbitrary JSON object,
    /// so a number inside one is narrowed like any other JSON number
    /// (<see cref="Verifiable.Json.ManualJsonReader.ReadNumber"/>): exponent notation does not fit
    /// <see cref="int"/> or <see cref="long"/> narrowing and falls back to <see cref="decimal"/>, so
    /// <c>1e2</c> round-trips as the plain decimal <c>100</c>, not byte-identically.
    /// </summary>
    [TestMethod]
    public void RoundtripScalarObjectContextWithNumberMemberNormalizesExponentNotation()
    {
        // lang=json, strict
        const string OriginalInputJson = @"{""a"":1e2}";
        const string NarrowedOutputJson = @"{""a"":100}";
        var converter = new JsonLdContextConverter();

        var context = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(context);
        Assert.AreEqual(100m, context.Entries[0].Definition!["a"]);

        var backConvertedJson = GetConverted(context, converter!);
        Assert.AreEqual(NarrowedOutputJson, backConvertedJson);
    }


    /// <summary>
    /// A member of an inline context definition whose own value is a nested JSON object round-trips
    /// byte-identically, proving <see cref="Verifiable.Core.Model.Common.ContextEntry"/>'s deep-copy
    /// recursion (which the definition's parsed shape passes through) is exercised more than one
    /// level deep, per <see href="https://www.w3.org/TR/json-ld11/#dfn-term-definition">JSON-LD 1.1
    /// §1.4 Terminology, "term definition"</see> (a term definition's value is itself an object).
    /// </summary>
    [TestMethod]
    public void RoundtripScalarObjectContextWithNestedObjectMember()
    {
        // lang=json, strict
        const string OriginalInputJson = @"{""a"":{""b"":{""c"":1}}}";
        var converter = new JsonLdContextConverter();

        var context = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(context);
        var outer = (IReadOnlyDictionary<string, object>)context.Entries[0].Definition!["a"];
        var inner = (IReadOnlyDictionary<string, object>)outer["b"];
        Assert.AreEqual(1, inner["c"]);

        var backConvertedJson = GetConverted(context, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: <c>@context</c> MUST be a URL, an object, or an array of URLs and objects. A
    /// bare number at the top level is none of those and is refused with a
    /// <see cref="JsonException"/> rather than silently coerced.
    /// </summary>
    [TestMethod]
    public void RootContextRejectsNumber()
    {
        // lang=json, strict
        const string InvalidInputJson = @"42";
        var converter = new JsonLdContextConverter();

        Assert.Throws<JsonException>(() => GetConverted(InvalidInputJson, converter));
    }


    /// <summary>
    /// <c>JsonLdContextConverter.Write</c> refuses to write a <see cref="ContextEntry"/> that is
    /// neither an IRI nor a definition — reachable only through the struct's zero value, never
    /// through <see cref="ContextEntry.FromIri"/> or <see cref="ContextEntry.FromDefinition"/> —
    /// since such an entry has no wire form.
    /// </summary>
    [TestMethod]
    public void WriteThrowsForADegenerateContextEntry()
    {
        var degenerate = new Context([default(ContextEntry)], ContextForm.Array);
        var converter = new JsonLdContextConverter();

        Assert.ThrowsExactly<System.InvalidOperationException>(() => GetConverted(degenerate, converter));
    }


    /// <summary>
    /// Order is preserved on read: an array mixing IRIs and an inline definition produces entries in
    /// exactly the order they appeared on the wire.
    /// </summary>
    [TestMethod]
    public void ArrayContextEntriesPreserveWireOrder()
    {
        // lang=json, strict
        const string OriginalInputJson = @"[""https://www.w3.org/ns/did/v1"",{""@vocab"":""https://example.com/""},""https://w3id.org/security/multikey/v1""]";
        var converter = new JsonLdContextConverter();

        var context = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(context);
        Assert.HasCount(3, context.Entries);
        Assert.AreEqual("https://www.w3.org/ns/did/v1", context.Entries[0].Iri);
        Assert.IsTrue(context.Entries[1].IsDefinition);
        Assert.AreEqual("https://w3id.org/security/multikey/v1", context.Entries[2].Iri);
    }


    /// <summary>
    /// VC Data Model 2.0 §4.3 Contexts: array items "MUST be composed of any combination of URLs and
    /// objects". A number entry is neither, so it is refused with a <see cref="JsonException"/> rather
    /// than silently coerced or dropped.
    /// </summary>
    [TestMethod]
    public void ContextArrayRejectsNumberEntry()
    {
        // lang=json, strict
        const string InvalidInputJson = @"[""https://www.w3.org/ns/did/v1"",42]";
        var converter = new JsonLdContextConverter();

        Assert.Throws<JsonException>(() => GetConverted(InvalidInputJson, converter));
    }


    /// <summary>A boolean array entry is refused for the same VC Data Model 2.0 §4.3 reason as a number.</summary>
    [TestMethod]
    public void ContextArrayRejectsBooleanEntry()
    {
        // lang=json, strict
        const string InvalidInputJson = @"[""https://www.w3.org/ns/did/v1"",true]";
        var converter = new JsonLdContextConverter();

        Assert.Throws<JsonException>(() => GetConverted(InvalidInputJson, converter));
    }


    /// <summary>A null array entry is refused for the same VC Data Model 2.0 §4.3 reason as a number.</summary>
    [TestMethod]
    public void ContextArrayRejectsNullEntry()
    {
        // lang=json, strict
        const string InvalidInputJson = @"[""https://www.w3.org/ns/did/v1"",null]";
        var converter = new JsonLdContextConverter();

        Assert.Throws<JsonException>(() => GetConverted(InvalidInputJson, converter));
    }


    /// <summary>A nested array array entry is refused for the same VC Data Model 2.0 §4.3 reason as a number.</summary>
    [TestMethod]
    public void ContextArrayRejectsNestedArrayEntry()
    {
        // lang=json, strict
        const string InvalidInputJson = @"[""https://www.w3.org/ns/did/v1"",[""nested""]]";
        var converter = new JsonLdContextConverter();

        Assert.Throws<JsonException>(() => GetConverted(InvalidInputJson, converter));
    }


    /// <summary>
    /// A JSON <see langword="null"/> value on a <c>credentialSubject</c> claim is data belonging
    /// to that member, not an absent member: <see cref="CredentialSubjectConverter"/> keeps it in
    /// <see cref="Verifiable.Core.Model.Credentials.CredentialSubject.AdditionalData"/> on read
    /// and re-emits the <c>null</c> literal on write rather than dropping it -
    /// <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022">VC Data Integrity EdDSA
    /// Cryptosuites: eddsa-jcs-2022, the "Transformation" algorithm</see> signs the JSON
    /// Canonicalization Scheme (RFC 8785) bytes of the credential as authored, so dropping a
    /// null-valued member on re-serialization would change the bytes a valid proof was signed
    /// over.
    /// </summary>
    [TestMethod]
    public void RoundtripCredentialSubjectWithNullValuedMemberPreservesNull()
    {
        // lang=json, strict
        const string OriginalInputJson = @"{""id"":""did:example:123"",""name"":null}";
        var converter = new CredentialSubjectConverter();

        var subjects = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(subjects);
        Assert.HasCount(1, subjects);
        Assert.IsTrue(subjects[0].AdditionalData!.ContainsKey("name"));
        Assert.IsNull(subjects[0].AdditionalData!["name"]);

        var backConvertedJson = GetConverted(subjects, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    /// <summary>
    /// A JSON <see langword="null"/>-valued <c>id</c> member is distinct from an absent <c>id</c>
    /// member, and the string-typed
    /// <see cref="Verifiable.Core.Model.Credentials.CredentialSubject.Id"/> property cannot carry
    /// that distinction alone, so <see cref="CredentialSubjectConverter"/> keeps the null in
    /// <see cref="Verifiable.Core.Model.Credentials.CredentialSubject.AdditionalData"/> under
    /// <c>id</c> and re-emits it on write - the same byte-preservation requirement
    /// <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022">VC Data Integrity EdDSA
    /// Cryptosuites: eddsa-jcs-2022, the "Transformation" algorithm</see> places on every other
    /// member, since it signs the JSON Canonicalization Scheme (RFC 8785) bytes as authored.
    /// </summary>
    [TestMethod]
    public void RoundtripCredentialSubjectWithNullValuedIdPreservesNull()
    {
        // lang=json, strict
        const string OriginalInputJson = @"{""id"":null,""name"":""x""}";
        var converter = new CredentialSubjectConverter();

        var subjects = GetConverted(OriginalInputJson, converter);
        Assert.IsNotNull(subjects);
        Assert.HasCount(1, subjects);
        Assert.IsNull(subjects[0].Id);
        Assert.IsTrue(subjects[0].AdditionalData!.ContainsKey("id"));
        Assert.IsNull(subjects[0].AdditionalData!["id"]);

        var backConvertedJson = GetConverted(subjects, converter!);
        Assert.AreEqual(OriginalInputJson, backConvertedJson);
    }


    /// <summary>
    /// The open-world "additional data" bucket shared by several POCO types (see
    /// <see cref="AdditionalDataJson"/>) holds any member the typed model does not name; a member
    /// whose value is JSON <see langword="null"/> is data belonging to that member, not an absent
    /// member, so the streaming entry point <see cref="AdditionalDataJson.AddFromReader"/> keeps
    /// it in the bucket and <see cref="AdditionalDataJson.WriteEntries"/> re-emits it as the JSON
    /// <c>null</c> literal rather than dropping it - the same byte-preservation requirement
    /// <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022">VC Data Integrity EdDSA
    /// Cryptosuites: eddsa-jcs-2022, the "Transformation" algorithm</see> places on every
    /// re-serialization of a signed document.
    /// </summary>
    [TestMethod]
    public void AdditionalDataBucketRoundtripsNullValuedMember()
    {
        // lang=json, strict
        const string OriginalInputJson = @"{""a"":null}";
        var utf8JsonReader = new Utf8JsonReader(Encoding.UTF8.GetBytes(OriginalInputJson));
        _ = utf8JsonReader.Read();
        Assert.AreEqual(JsonTokenType.StartObject, utf8JsonReader.TokenType);
        _ = utf8JsonReader.Read();
        Assert.AreEqual(JsonTokenType.PropertyName, utf8JsonReader.TokenType);

        string propertyName = utf8JsonReader.GetString()!;
        _ = utf8JsonReader.Read();

        Dictionary<string, object>? bucket = null;
        AdditionalDataJson.AddFromReader(ref bucket, propertyName, ref utf8JsonReader);
        Assert.IsNotNull(bucket);
        Assert.IsTrue(bucket!.ContainsKey("a"));
        Assert.IsNull(bucket["a"]);

        using(var stream = new MemoryStream())
        {
            using(var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                AdditionalDataJson.WriteEntries(writer, bucket);
                writer.WriteEndObject();
            }

            var backConvertedJson = Encoding.UTF8.GetString(stream.ToArray());
            Assert.AreEqual(OriginalInputJson, backConvertedJson);
        }
    }


    /// <summary>
    /// The buffered entry point <see cref="AdditionalDataJson.AddFromElement"/> - the one every
    /// production converter with an open-world bucket calls - keeps a JSON <see langword="null"/>
    /// value in the bucket the same way the streaming entry point does: the null is data
    /// belonging to the member, not an absent member, and
    /// <see cref="AdditionalDataJson.WriteEntries"/> re-emits it as the <c>null</c> literal
    /// rather than dropping it, which is what a re-serialized signed document needs under
    /// <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022">VC Data Integrity EdDSA
    /// Cryptosuites: eddsa-jcs-2022, the "Transformation" algorithm</see>.
    /// </summary>
    [TestMethod]
    public void AdditionalDataBucketRoundtripsNullValuedMemberFromElement()
    {
        // lang=json, strict
        const string OriginalInputJson = @"{""a"":null}";
        using var jsonDocument = JsonDocument.Parse(OriginalInputJson);
        var rootElement = jsonDocument.RootElement;

        Dictionary<string, object>? bucket = null;
        foreach(var property in rootElement.EnumerateObject())
        {
            AdditionalDataJson.AddFromElement(ref bucket, property.Name, property.Value);
        }

        Assert.IsNotNull(bucket);
        Assert.IsTrue(bucket!.ContainsKey("a"));
        Assert.IsNull(bucket["a"]);

        using(var stream = new MemoryStream())
        {
            using(var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                AdditionalDataJson.WriteEntries(writer, bucket);
                writer.WriteEndObject();
            }

            var backConvertedJson = Encoding.UTF8.GetString(stream.ToArray());
            Assert.AreEqual(OriginalInputJson, backConvertedJson);
        }
    }


    /// <summary>
    /// Removes whitespace from the string: start, end, in between.
    /// </summary>
    /// <param name="str">The string from which to remove whitespace.</param>
    /// <returns>The input <paramref name="str"/> without whitespace.</returns>
    private static string RemoveWhiteSpace(string str)
    {
        return string.Concat(str.Where(c => !char.IsWhiteSpace(c)));
    }


    /// <summary>
    /// Tries to convert the input JSON to a strongly typed object using the given converter.
    /// </summary>
    /// <typeparam name="TConversionTarget">The conversion target type.</typeparam>
    /// <param name="json">The JSON to try to convert.</param>
    /// <param name="converter">The converter to use.</param>
    /// <returns>An instance of the given target type if conversion succeeded.</returns>
    private static TConversionTarget? GetConverted<TConversionTarget>(string json, JsonConverter<TConversionTarget> converter) where TConversionTarget : class
    {
        var utf8JsonReader = new Utf8JsonReader(Encoding.UTF8.GetBytes(json));
        var options = new JsonSerializerOptions();

        Assert.AreEqual(JsonTokenType.None, utf8JsonReader.TokenType);
        _ = utf8JsonReader.Read();

        return converter.Read(ref utf8JsonReader, typeof(TConversionTarget), options);
    }


    /// <summary>
    /// Tries to convert the input type to JSON using the given converter.
    /// </summary>
    /// <typeparam name="TInput">The input type.</typeparam>
    /// <param name="input">The input object.</param>
    /// <param name="converter">The converter to use.</param>
    /// <returns>JSON representation of the given target type if conversion succeeded.</returns>
    private static string? GetConverted<TInput>(TInput input, JsonConverter<TInput> converter)
    {
        using(var stream = new MemoryStream())
        {
            using(var writer = new Utf8JsonWriter(stream))
            {
                converter.Write(writer, input!, new JsonSerializerOptions());
            }

            return Encoding.UTF8.GetString(stream.ToArray());
        }
    }
}
