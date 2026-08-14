using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Json;

/// <summary>
/// The JSON codec for the JAdES JWS Protected Header — the aggregate ↔ JWS-protected-header-JSON-object
/// round-trip, binding <see cref="EncodeJAdESProtectedHeaderDelegate"/> and
/// <see cref="DecodeJAdESProtectedHeaderDelegate"/> for
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Byte-exactness lives one layer up, not here.</strong> The RFC 7515 §5.1 Signing Input needs the
/// protected header's own base64url TEXT preserved byte-exact — <see cref="Decode"/> achieves that by returning
/// a freshly-decoded <see cref="JAdESProtectedHeaders"/> alongside whatever base64url TEXT the CALLER already
/// holds (e.g. <see cref="UnverifiedJwsSignature.Protected"/>, captured verbatim by <see cref="JwsParsing"/>);
/// this codec never re-derives that text from the decoded model. <see cref="Encode"/> is the one place that DOES
/// mint fresh base64url TEXT (a creation-time serialization, not a re-derivation of already-received wire text),
/// which is exactly what a signer's own first encoding of a NEW header must do.
/// </para>
/// <para>
/// <strong>Decode uses <see cref="JsonDocument"/>/<see cref="JsonElement"/> directly, not the shared
/// <c>Dictionary&lt;string, object&gt;</c> generic-JSON-value converter.</strong> That converter's own
/// <c>ExtractValue</c> auto-sniffs every JSON string token against <see cref="DateTime"/>
/// (<c>reader.TryGetDateTime(...)</c>) before falling back to a plain string — a landmine for the several
/// base64/base64url/opaque-identifier string members this header carries (a coincidentally date-shaped <c>kid</c>
/// or digest string would silently become a <see cref="DateTime"/> instead of the string this codec needs).
/// <see cref="JsonElement.GetString"/> never performs that sniff, so every decode helper in this file and in
/// <see cref="JAdESUnsignedComponentJson"/> reads directly off <see cref="JsonElement"/>.
/// </para>
/// <para>
/// <strong>Fail-closed at the delegate boundary, not in every nested helper.</strong> <see cref="Decode"/> wraps
/// its whole call tree in one try/catch — mirroring <c>CBAdESSignatureSerialization.ParseCBAdESSign1</c>'s
/// "every failure path... funnel through the one catch clause" convention — converting any
/// <see cref="JsonException"/>/<see cref="FormatException"/>/<see cref="ArgumentException"/>/
/// <see cref="InvalidOperationException"/>/<see cref="OverflowException"/> to a <see langword="null"/> return,
/// per the contract IRON RULE that no exception escapes a parse seam.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "FromJson mints several disposable Pki-model carriers (DigestValue/component records) whose ownership transfers into the returned JAdESProtectedHeaders aggregate on success — the caller of Decode owns and disposes the whole tree, mirroring CBAdESSignatureSerialization.ParseCBAdESSign1's identical ownership-transfer suppression. On a partial-construction throw (a later member's decode fails after an earlier one already minted a pooled carrier), FromJson's own catch disposes every carrier that succeeded before rethrowing — Roslyn does not see through that catch-based cleanup, hence the suppression covers both paths, not the success path alone.")]
public static class JAdESProtectedHeaderJson
{
    private const string CritMemberName = "crit";


    /// <summary>The <see cref="EncodeJAdESProtectedHeaderDelegate"/> binding — see the type remarks.</summary>
    public static EncodeJAdESProtectedHeaderDelegate Encode { get; } = static (headers, base64UrlEncoder, pool) =>
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        Dictionary<string, object> json = ToJson(headers, base64UrlEncoder);
        byte[] headerJsonBytes = JsonSerializerExtensions.SerializeToUtf8Bytes(json, JwtClaimsJson.Options);
        string base64Url = base64UrlEncoder(headerJsonBytes);

        return EncodedJoseProtectedHeader.FromBytes(Encoding.ASCII.GetBytes(base64Url), pool);
    };


    /// <summary>The <see cref="DecodeJAdESProtectedHeaderDelegate"/> binding — see the type remarks.</summary>
    public static DecodeJAdESProtectedHeaderDelegate Decode { get; } = static (protectedHeaderJsonBytes, base64UrlDecoder, pool) =>
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            using JsonDocument document = JsonDocument.Parse(protectedHeaderJsonBytes.ToArray().AsMemory());
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            return FromJson(root, base64UrlDecoder, pool);
        }
        catch(Exception exception) when(IsFailClosedParseException(exception))
        {
            return null;
        }
    };


    /// <summary>The <see cref="DetectJAdESX5tPresenceDelegate"/> binding — see that delegate's own remarks (a read-path obligation).</summary>
    public static DetectJAdESX5tPresenceDelegate DetectX5tPresence { get; } = static protectedHeaderJsonBytes =>
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(protectedHeaderJsonBytes.ToArray().AsMemory());

            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty(WellKnownJwkMemberNames.X5t, out _);
        }
        catch(Exception exception) when(IsFailClosedParseException(exception))
        {
            return false;
        }
    };


    private static Dictionary<string, object> ToJson(JAdESProtectedHeaders headers, EncodeDelegate base64UrlEncoder)
    {
        var result = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = headers.Algorithm };

        if(headers.ContentType is not null)
        {
            result[WellKnownJoseHeaderNames.Cty] = headers.ContentType;
        }

        if(headers.KeyId is not null)
        {
            result[WellKnownJwkMemberNames.Kid] = headers.KeyId;
        }

        if(headers.X5U is not null)
        {
            result[WellKnownJwkMemberNames.X5u] = headers.X5U.OriginalString;
        }

        if(headers.X5tHashS256 is not null)
        {
            result[WellKnownJwkMemberNames.X5tHashS256] = base64UrlEncoder(headers.X5tHashS256.AsReadOnlySpan());
        }

        if(headers.X5Chain is not null)
        {
            result[WellKnownJwkMemberNames.X5c] = headers.X5Chain.Select(static c => (object)Convert.ToBase64String(c.Span)).ToList();
        }

        if(headers.CriticalLabels is not null)
        {
            result[CritMemberName] = headers.CriticalLabels.Cast<object>().ToList();
        }

        if(headers.B64.HasValue)
        {
            result[WellKnownJoseHeaderNames.B64] = headers.B64.Value;
        }

        if(headers.IssuedAt is not null)
        {
            result[WellKnownJwtClaimNames.Iat] = headers.IssuedAt.Value.ToUnixTimeSeconds();
        }

        if(headers.SigT is not null)
        {
            result[WellKnownJAdESHeaderNames.SigT] = headers.SigT.Value.ToString("yyyy-MM-ddTHH:mm:ssK", CultureInfo.InvariantCulture);
        }

        if(headers.X5tHashO is not null)
        {
            result[WellKnownJAdESHeaderNames.X5tHashO] = JAdESUnsignedComponentJson.EncodeCertificateThumbprint(headers.X5tHashO);
        }

        if(headers.SigX5ts is not null)
        {
            result[WellKnownJAdESHeaderNames.SigX5ts] = headers.SigX5ts.Thumbprints.Select(static t => (object)JAdESUnsignedComponentJson.EncodeCertificateThumbprint(t)).ToList();
        }

        if(headers.SignerCommitments is not null)
        {
            result[WellKnownJAdESHeaderNames.SrCms] = JAdESUnsignedComponentJson.EncodeSignerCommitments(headers.SignerCommitments);
        }

        if(headers.SignatureProductionPlace is not null)
        {
            result[WellKnownJAdESHeaderNames.SigPl] = JAdESUnsignedComponentJson.EncodeSignatureProductionPlace(headers.SignatureProductionPlace);
        }

        if(headers.SignerAttributes is not null)
        {
            result[WellKnownJAdESHeaderNames.SrAts] = JAdESUnsignedComponentJson.EncodeSignerAttributes(headers.SignerAttributes);
        }

        if(headers.PayloadTimestamps is not null)
        {
            result[WellKnownJAdESHeaderNames.AdoTst] = JAdESUnsignedComponentJson.EncodeTimestampContainer(headers.PayloadTimestamps);
        }

        if(headers.SignaturePolicyIdentifier is not null)
        {
            result[WellKnownJAdESHeaderNames.SigPId] = JAdESUnsignedComponentJson.EncodeSignaturePolicyIdentifier(headers.SignaturePolicyIdentifier);
        }

        if(headers.SigD is not null)
        {
            result[WellKnownJAdESHeaderNames.SigD] = JAdESUnsignedComponentJson.EncodeDetachedDataObjectReference(headers.SigD);
        }

        return result;
    }


    private static JAdESProtectedHeaders FromJson(JsonElement root, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool)
    {
        string algorithm = root.GetProperty(WellKnownJwkMemberNames.Alg).GetString()
            ?? throw new FormatException("alg is required (ETSI TS 119 182-1 V1.2.1, clause 5.1.2, JA-5.1.2-01).");

        string? contentType = GetStringOrNull(root, WellKnownJoseHeaderNames.Cty);
        string? keyId = GetStringOrNull(root, WellKnownJwkMemberNames.Kid);

        Uri? x5u = root.TryGetProperty(WellKnownJwkMemberNames.X5u, out JsonElement x5uEl)
            ? new Uri(x5uEl.GetString() ?? throw new FormatException("x5u must be a string."))
            : null;

        //Everything from here on may mint a pooled/disposable carrier (DigestValue, AdESCertificateThumbprint(s),
        //AdESTimestampContainer, AdESSignaturePolicyIdentifier, JAdESDetachedDataObjectReference) before a LATER
        //member's own decode throws on malformed content -- the catch below disposes whichever of these already
        //succeeded, mirroring JAdESUnsignedComponentJson.DecodeDetachedDataObjectReference's identical
        //dispose-on-throw discipline for its own accumulating loop.
        DigestValue? x5tHashS256 = null;
        AdESCertificateThumbprint? x5tHashO = null;
        AdESCertificateThumbprints? sigX5ts = null;
        AdESTimestampContainer? payloadTimestamps = null;
        AdESSignaturePolicyIdentifier? signaturePolicyIdentifier = null;
        JAdESDetachedDataObjectReference? sigD = null;
        try
        {
            if(root.TryGetProperty(WellKnownJwkMemberNames.X5tHashS256, out JsonElement x5tEl))
            {
                string text = x5tEl.GetString() ?? throw new FormatException("x5t#S256 must be a string.");
                IMemoryOwner<byte> owner = base64UrlDecoder(text, pool);
                x5tHashS256 = new DigestValue(owner, CryptoTags.Sha256Digest);
            }

            List<ReadOnlyMemory<byte>>? x5chain = null;
            if(root.TryGetProperty(WellKnownJwkMemberNames.X5c, out JsonElement x5cEl))
            {
                x5chain = [];
                foreach(JsonElement item in x5cEl.EnumerateArray())
                {
                    x5chain.Add(item.GetBytesFromBase64());
                }
            }

            List<string>? criticalLabels = null;
            if(root.TryGetProperty(CritMemberName, out JsonElement critEl))
            {
                criticalLabels = [];
                foreach(JsonElement item in critEl.EnumerateArray())
                {
                    criticalLabels.Add(item.GetString() ?? throw new FormatException("crit element must be a string."));
                }
            }

            bool? b64 = root.TryGetProperty(WellKnownJoseHeaderNames.B64, out JsonElement b64El) ? b64El.GetBoolean() : null;

            JAdESClaimedSigningTime? issuedAt = root.TryGetProperty(WellKnownJwtClaimNames.Iat, out JsonElement iatEl)
                ? new JAdESClaimedSigningTime(DateTimeOffset.UnixEpoch.AddSeconds(iatEl.GetDouble()))
                : null;

            JAdESClaimedSigningTime? sigT = root.TryGetProperty(WellKnownJAdESHeaderNames.SigT, out JsonElement sigTEl)
                ? new JAdESClaimedSigningTime(DateTimeOffset.Parse(
                    sigTEl.GetString() ?? throw new FormatException("sigT must be a string."),
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind))
                : null;

            x5tHashO = root.TryGetProperty(WellKnownJAdESHeaderNames.X5tHashO, out JsonElement x5tHashOEl)
                ? JAdESUnsignedComponentJson.DecodeCertificateThumbprint(x5tHashOEl, pool)
                : null;

            if(root.TryGetProperty(WellKnownJAdESHeaderNames.SigX5ts, out JsonElement sigX5tsEl))
            {
                var thumbprints = new List<AdESCertificateThumbprint>();
                try
                {
                    foreach(JsonElement item in sigX5tsEl.EnumerateArray())
                    {
                        thumbprints.Add(JAdESUnsignedComponentJson.DecodeCertificateThumbprint(item, pool));
                    }
                }
                catch
                {
                    foreach(AdESCertificateThumbprint thumbprint in thumbprints)
                    {
                        thumbprint.Dispose();
                    }

                    throw;
                }

                sigX5ts = new AdESCertificateThumbprints(thumbprints);
            }

            AdESSignerCommitments? signerCommitments = root.TryGetProperty(WellKnownJAdESHeaderNames.SrCms, out JsonElement srCmsEl)
                ? JAdESUnsignedComponentJson.DecodeSignerCommitments(srCmsEl)
                : null;

            AdESSignatureProductionPlace? signatureProductionPlace = root.TryGetProperty(WellKnownJAdESHeaderNames.SigPl, out JsonElement sigPlEl)
                ? JAdESUnsignedComponentJson.DecodeSignatureProductionPlace(sigPlEl)
                : null;

            AdESSignerAttributes? signerAttributes = root.TryGetProperty(WellKnownJAdESHeaderNames.SrAts, out JsonElement srAtsEl)
                ? JAdESUnsignedComponentJson.DecodeSignerAttributes(srAtsEl)
                : null;

            payloadTimestamps = root.TryGetProperty(WellKnownJAdESHeaderNames.AdoTst, out JsonElement adoTstEl)
                ? JAdESUnsignedComponentJson.DecodeTimestampContainer(adoTstEl)
                : null;

            signaturePolicyIdentifier = root.TryGetProperty(WellKnownJAdESHeaderNames.SigPId, out JsonElement sigPIdEl)
                ? JAdESUnsignedComponentJson.DecodeSignaturePolicyIdentifier(sigPIdEl, pool)
                : null;

            sigD = root.TryGetProperty(WellKnownJAdESHeaderNames.SigD, out JsonElement sigDEl)
                ? JAdESUnsignedComponentJson.DecodeDetachedDataObjectReference(sigDEl, pool)
                : null;

            return new JAdESProtectedHeaders(
                algorithm,
                contentType,
                keyId,
                x5u,
                x5tHashS256,
                x5chain,
                criticalLabels,
                b64,
                issuedAt,
                sigT,
                x5tHashO,
                sigX5ts,
                signerCommitments,
                signatureProductionPlace,
                signerAttributes,
                payloadTimestamps,
                signaturePolicyIdentifier,
                sigD);
        }
        catch
        {
            x5tHashS256?.Dispose();
            x5tHashO?.Dispose();
            sigX5ts?.Dispose();
            payloadTimestamps?.Dispose();
            signaturePolicyIdentifier?.Dispose();
            (sigD as IDisposable)?.Dispose();

            throw;
        }
    }


    private static string? GetStringOrNull(JsonElement obj, string memberName) =>
        obj.TryGetProperty(memberName, out JsonElement value) ? value.GetString() : null;


    //KeyNotFoundException is JsonElement.GetProperty's own throw for a missing mandatory member (e.g. alg) --
    //included alongside the JSON/argument/range exceptions every nested Decode* helper in
    //JAdESUnsignedComponentJson may also throw, so no exception from that whole call tree escapes this seam.
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is JsonException or FormatException or ArgumentException or InvalidOperationException or OverflowException or KeyNotFoundException;
}
