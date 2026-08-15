using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Json;

/// <summary>
/// The JSON implementation of <see cref="TryDecodeJAdESCounterSignatureDelegate"/> — decodes a <c>cSig</c>
/// element's own opaque wire text (clause 5.3.2) into the nested JWS/JAdES message it carries, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Two decode steps, mirroring the delegate's own remarks.</strong> Step one resolves
/// <see cref="JAdESUnsignedHeaderElementCounterSignature.WireText"/> to the clear-JSON <c>{"cSig": &lt;value&gt;}</c>
/// object bytes — base64url-decoded when <c>containerMode</c> is
/// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>, already clear otherwise (the SAME split
/// <see cref="JAdESEtsiUJson"/> applies at the array level, reapplied here at the single-element level since
/// this seam is called independently of that array walk). Step two isolates the <c>cSig</c> member's own value
/// — a JSON string (compact-serialized nested JWS) or a JSON object (JSON-serialized nested JWS/JAdES,
/// <c>GetRawText()</c> slicing the ORIGINAL underlying buffer rather than re-serializing, exactly like
/// <see cref="JAdESMessageJson"/>'s own <c>etsiU</c> extraction) — and hands the resolved bytes to
/// <see cref="JAdESMessageJson.TryParse"/> directly: both types live in this same assembly, so no delegate
/// indirection is needed for that reuse.
/// </para>
/// <para>
/// <strong>Fail-closed, never throws.</strong> Every malformed shape (not JSON, no <c>cSig</c> member, a value
/// that is neither a string nor an object, or a nested message
/// <see cref="JAdESMessageJson.TryParse"/> itself rejects) returns <see langword="false"/> with
/// <c>decoded</c> left <see langword="null"/> — mirroring <see cref="JAdESMessageJson.TryParse"/>'s own
/// contract.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "The base64url-decode IMemoryOwner<byte> is copied into a managed array and disposed " +
        "immediately (using) before this method returns on every path; JAdESMessageJson.TryParse's own success " +
        "path mints the returned UnverifiedJAdESMessage the caller of this delegate owns and disposes.")]
public static class JAdESCounterSignatureJson
{
    /// <summary>The <see cref="TryDecodeJAdESCounterSignatureDelegate"/> binding — see the type remarks.</summary>
    public static TryDecodeJAdESCounterSignatureDelegate TryDecode { get; } = static (
        JAdESUnsignedHeaderElementCounterSignature element,
        JAdESEtsiUIncorporationMode containerMode,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        out UnverifiedJAdESMessage? decoded) =>
    {
        ArgumentNullException.ThrowIfNull(element);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        decoded = null;

        try
        {
            byte[] clearJsonBytes;
            if(containerMode == JAdESEtsiUIncorporationMode.Base64Url)
            {
                string base64UrlText = Encoding.ASCII.GetString(element.WireText.AsReadOnlySpan());
                using IMemoryOwner<byte> owner = base64UrlDecoder(base64UrlText, pool);
                clearJsonBytes = owner.Memory.ToArray();
            }
            else
            {
                clearJsonBytes = element.WireText.AsReadOnlySpan().ToArray();
            }

            using JsonDocument document = JsonDocument.Parse(clearJsonBytes);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty(JAdESUnsignedHeaderElement.CounterSignatureKind, out JsonElement value))
            {
                return false;
            }

            byte[] nestedBytes = value.ValueKind switch
            {
                JsonValueKind.String => Encoding.ASCII.GetBytes(value.GetString() ?? string.Empty),
                JsonValueKind.Object => Encoding.UTF8.GetBytes(value.GetRawText()),
                _ => []
            };

            if(nestedBytes.Length == 0)
            {
                return false;
            }

            return JAdESMessageJson.TryParse(nestedBytes, base64UrlDecoder, pool, out decoded, out _);
        }
        catch(Exception exception) when(IsFailClosedParseException(exception))
        {
            decoded = null;

            return false;
        }
    };


    private static bool IsFailClosedParseException(Exception exception) =>
        exception is JsonException or FormatException or ArgumentException or InvalidOperationException or OverflowException;
}
