using CsCheck;
using System.Globalization;
using System.Text;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Property-based tests for <see cref="JwkJsonWriter"/> and <see cref="JwkJsonReader"/>
/// round-trip correctness. Verifies that values written by the writer are correctly
/// recovered by the reader for the EC JWK and JWKS structures used in HAIP 1.0.
/// </summary>
[TestClass]
internal sealed class JwkJsonReaderWriterPropertyTests
{
    //Base64url alphabet: A-Z, a-z, 0-9, '-', '_'. No padding.
    private static readonly Gen<char> GenBase64UrlChar =
        Gen.OneOf(
            Gen.Char['A', 'Z'],
            Gen.Char['a', 'z'],
            Gen.Char['0', '9'],
            Gen.Const('-'),
            Gen.Const('_'));

    //P-256 coordinates are 43 base64url characters (32 bytes, no padding).
    private static readonly Gen<string> GenP256Coordinate =
        Gen.String[GenBase64UrlChar, 43, 43];

    //Short alphanumeric strings for kty, crv, use, kid values.
    private static readonly Gen<string> GenFieldValue =
        Gen.String[Gen.Char.AlphaNumeric, 1, 16];

    //A key-value pair for a flat JWK field.
    private static readonly Gen<(string Key, string Value)> GenKeyValuePair =
        GenFieldValue.SelectMany(k => GenFieldValue.Select(v => (k, v)));


    [TestMethod]
    public void ExtractStringValueRoundtripsWrittenProperty()
    {
        GenKeyValuePair.Sample(kv =>
        {
            (string key, string value) = kv;

            int bufferLength =
                10 + Encoding.UTF8.GetByteCount(key) * 2
                   + Encoding.UTF8.GetByteCount(value) * 2;
            byte[] buffer = new byte[bufferLength];
            JwkJsonWriter writer = new(buffer);
            writer.WriteObjectStart();
            writer.WriteProperty(key, value);
            writer.WriteObjectEnd();

            ReadOnlySpan<byte> json = buffer.AsSpan(0, writer.Position);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            string? extracted = JwkJsonReader.ExtractStringValue(json, keyBytes);

            Assert.AreEqual(value, extracted,
                $"ExtractStringValue must recover the written value for key '{key}'.");
        });
    }


    [TestMethod]
    public void ExtractStringValueReturnsNullForAbsentKey()
    {
        GenKeyValuePair.Sample(kv =>
        {
            (string key, string value) = kv;

            byte[] buffer = new byte[256];
            JwkJsonWriter writer = new(buffer);
            writer.WriteObjectStart();
            writer.WriteProperty(key, value);
            writer.WriteObjectEnd();

            ReadOnlySpan<byte> json = buffer.AsSpan(0, writer.Position);

            string? extracted = JwkJsonReader.ExtractStringValue(json, "absent_key_xyz_123"u8);

            Assert.IsNull(extracted,
                "ExtractStringValue must return null for a key that was not written.");
        });
    }


    [TestMethod]
    public void ContainsKeyAgreesWithExtractStringValue()
    {
        GenKeyValuePair.Sample(kv =>
        {
            (string key, string value) = kv;

            byte[] buffer = new byte[256];
            JwkJsonWriter writer = new(buffer);
            writer.WriteObjectStart();
            writer.WriteProperty(key, value);
            writer.WriteObjectEnd();

            ReadOnlySpan<byte> json = buffer.AsSpan(0, writer.Position);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            bool contains = JwkJsonReader.ContainsKey(json, keyBytes);
            string? extracted = JwkJsonReader.ExtractStringValue(json, keyBytes);

            Assert.AreEqual(contains, extracted is not null,
                $"ContainsKey and ExtractStringValue must agree for key '{key}'.");
        });
    }


    [TestMethod]
    public void ExtractNestedStringValueRoundtripsEpkFields()
    {
        //Simulates a JWE header: {"alg":"ECDH-ES","epk":{"kty":"EC","crv":"P-256","x":"...","y":"..."}}
        GenP256Coordinate.SelectMany(x =>
            GenP256Coordinate.Select(y => (x, y)))
        .Sample(coords =>
        {
            (string x, string y) = coords;

            int bufferLength = 128 + x.Length + y.Length;
            byte[] buffer = new byte[bufferLength];
            JwkJsonWriter writer = new(buffer);

            writer.WriteObjectStart();
            writer.WriteProperty("alg", WellKnownJweAlgorithms.EcdhEs);
            writer.WritePropertySeparator();
            writer.WritePropertyRaw("epk", "");
            writer.WriteObjectStart();
            writer.WriteProperty("kty", WellKnownKeyTypeValues.Ec);
            writer.WritePropertySeparator();
            writer.WriteProperty("crv", WellKnownCurveValues.P256);
            writer.WritePropertySeparator();
            writer.WriteProperty("x", x);
            writer.WritePropertySeparator();
            writer.WriteProperty("y", y);
            writer.WriteObjectEnd();
            writer.WriteObjectEnd();

            ReadOnlySpan<byte> json = buffer.AsSpan(0, writer.Position);

            string? extractedX = JwkJsonReader.ExtractNestedStringValue(json, "epk"u8, "x"u8);
            string? extractedY = JwkJsonReader.ExtractNestedStringValue(json, "epk"u8, "y"u8);
            string? extractedKty = JwkJsonReader.ExtractNestedStringValue(json, "epk"u8, "kty"u8);
            string? extractedCrv = JwkJsonReader.ExtractNestedStringValue(json, "epk"u8, "crv"u8);

            Assert.AreEqual(x, extractedX, "x coordinate must round-trip through epk nesting.");
            Assert.AreEqual(y, extractedY, "y coordinate must round-trip through epk nesting.");
            Assert.AreEqual(WellKnownKeyTypeValues.Ec, extractedKty, "kty must round-trip through epk nesting.");
            Assert.AreEqual(WellKnownCurveValues.P256, extractedCrv, "crv must round-trip through epk nesting.");
        });
    }


    [TestMethod]
    public void ExtractNestedStringValueFromArrayRoundtripsJwksFields()
    {
        //Simulates a JWKS per RFC 7517 §5:
        //{"keys":[{"kty":"EC","crv":"P-256","use":"enc","x":"...","y":"..."}]}
        GenP256Coordinate.SelectMany(x =>
            GenP256Coordinate.Select(y => (x, y)))
        .Sample(coords =>
        {
            (string x, string y) = coords;

            int bufferLength = 128 + x.Length + y.Length;
            byte[] buffer = new byte[bufferLength];
            JwkJsonWriter writer = new(buffer);

            writer.WriteObjectStart();
            writer.WritePropertyRaw("keys", "[");
            writer.WriteObjectStart();
            writer.WriteProperty("kty", WellKnownKeyTypeValues.Ec);
            writer.WritePropertySeparator();
            writer.WriteProperty("crv", WellKnownCurveValues.P256);
            writer.WritePropertySeparator();
            writer.WriteProperty("use", "enc");
            writer.WritePropertySeparator();
            writer.WriteProperty("x", x);
            writer.WritePropertySeparator();
            writer.WriteProperty("y", y);
            writer.WriteObjectEnd();
            writer.WriteArrayEnd();
            writer.WriteObjectEnd();

            ReadOnlySpan<byte> json = buffer.AsSpan(0, writer.Position);

            string? extractedX = JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "x"u8);
            string? extractedY = JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "y"u8);
            string? extractedKty = JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "kty"u8);
            string? extractedCrv = JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "crv"u8);
            string? extractedUse = JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "use"u8);

            Assert.AreEqual(x, extractedX, "x coordinate must round-trip through JWKS array.");
            Assert.AreEqual(y, extractedY, "y coordinate must round-trip through JWKS array.");
            Assert.AreEqual(WellKnownKeyTypeValues.Ec, extractedKty, "kty must round-trip through JWKS array.");
            Assert.AreEqual(WellKnownCurveValues.P256, extractedCrv, "crv must round-trip through JWKS array.");
            Assert.AreEqual("enc", extractedUse, "use must round-trip through JWKS array.");
        });
    }


    //Tokens allowed inside a generated JSON string. Brackets, braces, commas and
    //colons are deliberately included — together with escaped quotes and escaped
    //backslashes they are exactly the bytes that would bias a depth counter that
    //fails to skip string content. Underscore is deliberately absent so generated
    //content can never spell a quoted property key used by these tests.
    private static readonly Gen<string> GenJsonStringToken =
        Gen.OneOf(
            Gen.Char.AlphaNumeric.Select(c => c.ToString()),
            Gen.Const("["),
            Gen.Const("]"),
            Gen.Const("{"),
            Gen.Const("}"),
            Gen.Const(","),
            Gen.Const(":"),
            Gen.Const("\\\""),
            Gen.Const("\\\\"));

    //A complete JSON string literal, quotes included.
    private static readonly Gen<string> GenJsonStringLiteral =
        GenJsonStringToken.Array[0, 8].Select(tokens => "\"" + string.Concat(tokens) + "\"");

    private static readonly Gen<string> GenJsonNumberLiteral =
        Gen.Int.Select(i => i.ToString(CultureInfo.InvariantCulture));


    //A compact JSON array text down to the given nesting depth — the RFC 9396
    //authorization_details shape is an array of objects, so objects appear as
    //elements alongside strings, numbers and nested arrays.
    private static Gen<string> GenJsonArrayText(int depth)
    {
        Gen<string> element = depth <= 0
            ? Gen.OneOf(GenJsonStringLiteral, GenJsonNumberLiteral)
            : Gen.OneOf(
                GenJsonStringLiteral,
                GenJsonNumberLiteral,
                GenJsonArrayText(depth - 1),
                GenJsonObjectText(depth - 1));

        return element.Array[0, 4].Select(elements => "[" + string.Join(",", elements) + "]");
    }


    //A compact JSON object text down to the given nesting depth.
    private static Gen<string> GenJsonObjectText(int depth)
    {
        Gen<string> value = depth <= 0
            ? Gen.OneOf(GenJsonStringLiteral, GenJsonNumberLiteral)
            : Gen.OneOf(
                GenJsonStringLiteral,
                GenJsonNumberLiteral,
                GenJsonArrayText(depth - 1),
                GenJsonObjectText(depth - 1));

        Gen<string> member = GenFieldValue.SelectMany(k => value.Select(v => $"\"{k}\":{v}"));

        return member.Array[0, 4].Select(members => "{" + string.Join(",", members) + "}");
    }


    [TestMethod]
    public void ExtractArrayAsStringReturnsTheVerbatimArraySlice()
    {
        //The verbatim property is what the RFC 9396 carry path depends on: the
        //extracted authorization_details must be EXACTLY the signed text, byte for
        //byte, never a reserialisation — including strings whose content contains
        //brackets, braces and escape sequences.
        GenJsonArrayText(2).Sample(arrayText =>
        {
            string json = $"{{\"before\":\"x\",\"authorization_details\":{arrayText},\"after\":\"y\"}}";
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

            string? extracted = JwkJsonReader.ExtractArrayAsString(jsonBytes, "authorization_details"u8);

            Assert.AreEqual(arrayText, extracted,
                $"ExtractArrayAsString must return the array text verbatim. Input: {json}");
        });
    }


    [TestMethod]
    public void ExtractArrayAsStringReturnsNullForAbsentKeyOrNonArrayValue()
    {
        Gen.OneOf(GenJsonStringLiteral, GenJsonNumberLiteral, GenJsonObjectText(1)).Sample(value =>
        {
            string json = $"{{\"authorization_details\":{value}}}";
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

            Assert.IsNull(JwkJsonReader.ExtractArrayAsString(jsonBytes, "authorization_details"u8),
                $"A non-array value must yield null, not a slice. Input: {json}");
            Assert.IsNull(JwkJsonReader.ExtractArrayAsString(jsonBytes, "absent"u8),
                $"An absent key must yield null. Input: {json}");
        });
    }


    [TestMethod]
    public void ExtractObjectPropertiesRecoversAllStringMembers()
    {
        //The sub_jwk consumer reads every string member of the embedded JWK — each
        //written member must come back, and nothing else.
        Gen.Int[1, 6].SelectMany(count =>
            GenKeyValuePair.Array[count, count]
                .Where(pairs => pairs.Select(p => p.Key).Distinct().Count() == pairs.Length))
        .Sample(pairs =>
        {
            string members = string.Join(",", pairs.Select(p => $"\"{p.Key}\":\"{p.Value}\""));
            string json = $"{{\"sub_jwk\":{{{members}}},\"trailing\":\"t\"}}";
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

            Dictionary<string, object>? extracted =
                JwkJsonReader.ExtractObjectProperties(jsonBytes, "sub_jwk"u8);

            Assert.IsNotNull(extracted, $"The object must be found. Input: {json}");
            Assert.HasCount(pairs.Length, extracted,
                $"Exactly the written members must be returned. Input: {json}");
            foreach((string key, string value) in pairs)
            {
                Assert.AreEqual(value, (string)extracted[key],
                    $"Member '{key}' must round-trip. Input: {json}");
            }
        });
    }


    [TestMethod]
    public void ExtractObjectPropertiesSkipsNonStringMembersWithoutHoisting()
    {
        //Non-string members are skipped wholesale: a nested object's string members
        //must NOT be hoisted into the result, and numbers/booleans/arrays must not
        //derail the scan past the string members that follow them.
        GenKeyValuePair.Sample(kv =>
        {
            (string key, string value) = kv;
            string json =
                $"{{\"sub_jwk\":{{\"n\":42,\"flag\":true,\"arr\":[\"a\",\"b\"],"
                + $"\"obj\":{{\"inner\":\"i\"}},\"{key}9\":\"{value}\"}}}}";
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

            Dictionary<string, object>? extracted =
                JwkJsonReader.ExtractObjectProperties(jsonBytes, "sub_jwk"u8);

            Assert.IsNotNull(extracted, $"The object must be found. Input: {json}");
            Assert.HasCount(1, extracted,
                $"Only the string member must be returned — nothing hoisted. Input: {json}");
            Assert.AreEqual(value, (string)extracted[$"{key}9"],
                $"The string member after the skipped values must be recovered. Input: {json}");
        });
    }


    [TestMethod]
    public void ExtractObjectPropertiesReturnsNullForAbsentKeyOrNonObjectValue()
    {
        Gen.OneOf(GenJsonStringLiteral, GenJsonNumberLiteral, GenJsonArrayText(1)).Sample(value =>
        {
            string json = $"{{\"sub_jwk\":{value}}}";
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

            Assert.IsNull(JwkJsonReader.ExtractObjectProperties(jsonBytes, "sub_jwk"u8),
                $"A non-object value must yield null. Input: {json}");
            Assert.IsNull(JwkJsonReader.ExtractObjectProperties(jsonBytes, "absent"u8),
                $"An absent key must yield null. Input: {json}");
        });
    }


    [TestMethod]
    public void MultiplePropertiesAllExtractCorrectly()
    {
        //Generates objects with 2-5 distinct keys and verifies each is independently retrievable.
        Gen.Int[2, 5].SelectMany(count =>
            GenKeyValuePair.Array[count, count]
                .Where(pairs => pairs.Select(p => p.Key).Distinct().Count() == pairs.Length))
        .Sample(pairs =>
        {
            int bufferLength = pairs.Sum(p =>
                12 + Encoding.UTF8.GetByteCount(p.Key)
                   + Encoding.UTF8.GetByteCount(p.Value));
            byte[] buffer = new byte[bufferLength];
            JwkJsonWriter writer = new(buffer);

            writer.WriteObjectStart();
            for(int i = 0; i < pairs.Length; i++)
            {
                if(i > 0)
                {
                    writer.WritePropertySeparator();
                }

                writer.WriteProperty(pairs[i].Key, pairs[i].Value);
            }
            writer.WriteObjectEnd();

            ReadOnlySpan<byte> json = buffer.AsSpan(0, writer.Position);

            foreach((string key, string value) in pairs)
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                string? extracted = JwkJsonReader.ExtractStringValue(json, keyBytes);

                Assert.AreEqual(value, extracted,
                    $"Each property must be independently recoverable. Failed for key '{key}'.");
            }
        });
    }


    [TestMethod]
    public void TryExtractLongValueRoundtripsIntegerNumericDates()
    {
        //An integer claim value that terminates at a structural byte must round-trip
        //exactly — the NumericDate case (exp/iat/nbf) the scanner exists to read.
        Gen.Long.Sample(expected =>
        {
            string json = $"{{\"before\":\"x\",\"exp\":{expected.ToString(CultureInfo.InvariantCulture)},\"after\":\"y\"}}";
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

            bool found = JwkJsonReader.TryExtractLongValue(jsonBytes, "exp"u8, out long actual);

            Assert.IsTrue(found, $"The integer value must be found. Input: {json}");
            Assert.AreEqual(expected, actual, $"The value must round-trip exactly. Input: {json}");
        });
    }


    //Non-integer JSON numbers that are legal JSON but invalid for an integer claim:
    //exponent form, decimal form, and a trailing-garbage run. Reading only the leading
    //digit run would silently misparse these, so the scanner must reject them.
    private static readonly Gen<string> GenNonIntegerNumberText =
        Gen.OneOf(
            Gen.Int[1, 9].SelectMany(m => Gen.Int[1, 18].Select(e => $"{m}e{e}")),
            Gen.Int[0, 999].SelectMany(w => Gen.Int[1, 999].Select(f => $"{w}.{f}")),
            Gen.Int[1, 9999].Select(n => $"{n}abc"));


    [TestMethod]
    public void TryExtractLongValueRejectsNonIntegerNumberForms()
    {
        GenNonIntegerNumberText.Sample(numberText =>
        {
            string json = $"{{\"exp\":{numberText}}}";
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

            bool found = JwkJsonReader.TryExtractLongValue(jsonBytes, "exp"u8, out long value);

            Assert.IsFalse(found,
                $"A non-integer number must be rejected, not truncated to its leading digits. " +
                $"Input: {json}, misparsed value: {value}");
        });
    }


    [TestMethod]
    public void HasDuplicateTopLevelKeysDetectsRepeatsAndIgnoresNesting()
    {
        //Distinct top-level keys → no duplicate; a repeated top-level key → duplicate; a key
        //that recurs only inside a nested object is legitimate and must NOT be flagged.
        Gen.Int[2, 6].SelectMany(count =>
            GenFieldValue.Array[count, count]
                .Where(keys => keys.Distinct().Count() == keys.Length))
        .Sample(keys =>
        {
            string distinctMembers = string.Join(",", keys.Select(k => $"\"{k}\":\"v\""));
            string distinctJson = $"{{{distinctMembers}}}";
            Assert.IsFalse(
                JwkJsonReader.HasDuplicateTopLevelKeys(Encoding.UTF8.GetBytes(distinctJson)),
                $"Distinct top-level keys must not be flagged. Input: {distinctJson}");

            //Duplicate the first key at the top level.
            string duplicatedJson = $"{{\"{keys[0]}\":\"a\",{distinctMembers}}}";
            Assert.IsTrue(
                JwkJsonReader.HasDuplicateTopLevelKeys(Encoding.UTF8.GetBytes(duplicatedJson)),
                $"A repeated top-level key must be flagged. Input: {duplicatedJson}");

            //The same key name reused ONLY inside a nested object is legitimate.
            string nestedJson = $"{{{distinctMembers},\"nested\":{{\"{keys[0]}\":\"inner\"}}}}";
            Assert.IsFalse(
                JwkJsonReader.HasDuplicateTopLevelKeys(Encoding.UTF8.GetBytes(nestedJson)),
                $"A key reused only at depth must not be flagged. Input: {nestedJson}");
        });
    }
}
