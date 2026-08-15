using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Json;

/// <summary>
/// The JSON implementation of <see cref="TryParseJAdESMessageDelegate"/> — the validation entry seam that
/// locates the three JWS-serialization-form segments (<c>protected</c>/<c>payload</c>/<c>signature</c>/<c>header</c>)
/// across Compact, Flattened JSON, and General JSON, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see> clause 4 and RFC 7515 §7.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Never the shared generic-dictionary converter (mirrors <see cref="JAdESProtectedHeaderJson"/>'s own
/// rationale).</strong> <see cref="JwsParsing"/>'s own JSON-form methods decode the whole envelope through a
/// caller-supplied <c>Dictionary&lt;string, object&gt;</c> deserializer — landmine-prone for JAdES content (the
/// DateTime-sniff hazard) and, more fundamentally, incapable of preserving the <c>etsiU</c> array's own byte-exact
/// wire TEXT once it has been decoded into boxed CLR objects. This type therefore walks the envelope
/// directly via <see cref="JsonDocument"/>/<see cref="JsonElement"/> — <c>GetString()</c> never sniffs, and
/// <c>GetRawText()</c> slices the ORIGINAL underlying buffer rather than re-serializing, so both hazards are
/// avoided by construction, not by convention.
/// </para>
/// <para>
/// <strong>Compact needs none of this.</strong> A JWS Compact serialization carries no unprotected header at
/// all (RFC 7515 §7.1) and its three segments are plain base64url text split on <c>'.'</c> — no JSON parsing
/// whatsoever, so <see cref="JwsParsing.ParseCompact"/> is reused outright, with an inert header
/// deserializer since the generic decoded dictionary is never consulted here; the real, JAdES-typed protected
/// header decode happens one call later, via <see cref="JAdESProtectedHeaderJson.Decode"/> over the SAME raw
/// bytes <see cref="UnverifiedJwsSignature.Protected"/> carries.
/// </para>
/// <para>
/// <strong>Reuses the <c>Unverified*</c> carrier types, not their generic decode.</strong> Every segment this
/// type extracts is fed into the EXISTING <see cref="UnverifiedJwsSignature"/>/<see cref="UnverifiedJwsMessage"/>
/// shapes (reuse over reinvention) — the protected header's decoded dictionary member is populated with an EMPTY
/// <see cref="UnverifiedJwtHeader"/> placeholder, since no caller of this seam ever reads it (JAdES-typed content
/// travels through <see cref="UnverifiedJAdESMessage.EtsiURawBytes"/> and, one call later, the JAdES-specific
/// protected-header decode, never through this generic dictionary).
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "TryParse mints the payload/signature IMemoryOwner<byte> rentals and the etsiU PooledMemory whose ownership transfers into the returned UnverifiedJAdESMessage (via its UnverifiedJwsMessage/UnverifiedJwsSignature members) on success; on every failure path this method disposes every already-rented buffer itself before returning false.")]
public static class JAdESMessageJson
{
    private const string ProtectedMemberName = "protected";
    private const string SignatureMemberName = "signature";
    private const string PayloadMemberName = "payload";
    private const string HeaderMemberName = "header";
    private const string SignaturesMemberName = "signatures";


    /// <summary>The <see cref="TryParseJAdESMessageDelegate"/> binding — see the type remarks.</summary>
    public static TryParseJAdESMessageDelegate TryParse { get; } = static (
        ReadOnlySpan<byte> wireBytes, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool, out UnverifiedJAdESMessage? message, out JoseSerializationFormat format) =>
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        message = null;
        format = JoseSerializationFormat.Compact;

        if(wireBytes.IsEmpty)
        {
            return false;
        }

        try
        {
            if(wireBytes[0] != (byte)'{')
            {
                string compact = Encoding.ASCII.GetString(wireBytes);
                UnverifiedJwsMessage wire = JwsParsing.ParseCompact(compact, base64UrlDecoder, InertHeaderDeserializer, pool);

                message = new UnverifiedJAdESMessage(wire, JoseSerializationFormat.Compact, etsiURawBytes: null);
                format = JoseSerializationFormat.Compact;

                return true;
            }

            using JsonDocument document = JsonDocument.Parse(wireBytes.ToArray().AsMemory());
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            bool isGeneral = root.TryGetProperty(SignaturesMemberName, out JsonElement signaturesEl);
            JsonElement signatureObject;
            if(isGeneral)
            {
                //Scope (see TryParseJAdESMessageDelegate's own remarks): exactly one signature.
                if(signaturesEl.ValueKind != JsonValueKind.Array || signaturesEl.GetArrayLength() != 1)
                {
                    return false;
                }

                signatureObject = signaturesEl[0];
                format = JoseSerializationFormat.GeneralJson;
            }
            else
            {
                if(!root.TryGetProperty(ProtectedMemberName, out _) || !root.TryGetProperty(SignatureMemberName, out _))
                {
                    return false;
                }

                signatureObject = root;
                format = JoseSerializationFormat.FlattenedJson;
            }

            if(!TryReadString(signatureObject, ProtectedMemberName, out string? protectedText)
                || !TryReadString(signatureObject, SignatureMemberName, out string? signatureText))
            {
                return false;
            }

            bool isDetached = !TryReadString(root, PayloadMemberName, out string? payloadText);

            PooledMemory? etsiURawBytes = null;
            if(signatureObject.TryGetProperty(HeaderMemberName, out JsonElement headerEl) && headerEl.ValueKind == JsonValueKind.Object
                && headerEl.TryGetProperty(WellKnownJAdESHeaderNames.EtsiU, out JsonElement etsiUEl))
            {
                etsiURawBytes = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(etsiUEl.GetRawText()), pool, Tag.Create(Purpose.Data));
            }

            IMemoryOwner<byte>? payloadOwner = null;
            ReadOnlyMemory<byte> payload = ReadOnlyMemory<byte>.Empty;
            IMemoryOwner<byte> signatureBytesOwner;
            try
            {
                if(!isDetached)
                {
                    payloadOwner = base64UrlDecoder(payloadText!, pool);
                    payload = payloadOwner.Memory;
                }

                signatureBytesOwner = base64UrlDecoder(signatureText!, pool);
            }
            catch
            {
                payloadOwner?.Dispose();
                etsiURawBytes?.Dispose();
                throw;
            }

            var protectedHeader = new UnverifiedJwtHeader();
            var signature = new UnverifiedJwsSignature(protectedText!, protectedHeader, signatureBytesOwner);
            var wireMessage = new UnverifiedJwsMessage(payloadOwner, payload, signature, isDetached);

            message = new UnverifiedJAdESMessage(wireMessage, format, etsiURawBytes);

            return true;
        }
        catch(Exception exception) when(IsFailClosedParseException(exception))
        {
            message = null;

            return false;
        }
    };


    private static bool TryReadString(JsonElement obj, string memberName, out string? value)
    {
        if(obj.TryGetProperty(memberName, out JsonElement element) && element.ValueKind == JsonValueKind.String)
        {
            value = element.GetString();

            return value is not null;
        }

        value = null;

        return false;
    }


    //Never consulted: JAdES validation reads the protected header's own JAdES-typed decode
    //(JAdESProtectedHeaderJson.Decode) over the raw bytes UnverifiedJwsSignature.Protected carries, not this
    //generic dictionary -- an empty result keeps JwsParsing.ParseCompact's own contract satisfied without
    //re-introducing the DateTime-sniff hazard this file's remarks describe.
    private static IReadOnlyDictionary<string, object> InertHeaderDeserializer(ReadOnlySpan<byte> headerJson) =>
        new Dictionary<string, object>();


    //KeyNotFoundException/InvalidOperationException/OverflowException join JsonException/FormatException/
    //ArgumentException as the fail-closed set, mirroring JAdESProtectedHeaderJson's own IsFailClosedParseException.
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is JsonException or FormatException or ArgumentException or InvalidOperationException or OverflowException or KeyNotFoundException;
}
