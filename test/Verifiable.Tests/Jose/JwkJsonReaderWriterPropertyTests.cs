using CsCheck;
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
}
