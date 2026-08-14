using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;

namespace Verifiable.Json;

/// <summary>
/// The JSON codec for the JAdES <c>etsiU</c> unprotected-header parameter (clause 5.3.1) — the
/// dual-mode array carriage (whole-array duality, byte-exact base64url preservation) binding
/// <see cref="TryParseJAdESEtsiUDelegate"/> and <see cref="EncodeJAdESUnprotectedHeaderDelegate"/> for
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The array-level walk is a hand-rolled span scan, never <see cref="JsonDocument"/>.</strong> Detecting
/// the whole-array duality and capturing a base64url-incorporated element's own wire TEXT byte-exact (/// "decode/re-encode never touches the imprint input") needs the RAW byte range of each top-level array
/// element — <see cref="JsonDocument"/>'s own string decoding does not expose that range, and (per
/// <see cref="JAdESProtectedHeaderJson"/>'s own remarks on the shared generic-dictionary converter) risks
/// mis-sniffing a base64url string that happens to look like a date. <see cref="TryParse"/> therefore walks
/// <c>etsiUJsonBytes</c> byte-by-byte — generalizing the <c>JwkJsonReader</c> span-reader discipline
/// (contract: "the span-reader discipline generalizing JwkJsonReader for byte-range extraction") — classifying
/// each element as a JSON string (base64url incorporation) or JSON object (clear-JSON incorporation) and
/// extracting its raw span before any further processing. Once an element's own span is isolated, its CONTENT is
/// decoded via <see cref="JsonDocument"/> (base64url elements, to determine <see cref="JAdESUnsignedHeaderElement.Kind"/>
/// only — the decoded bytes are discarded immediately afterward; clear-JSON elements, to decode into the typed
/// Pki model via <see cref="JAdESUnsignedComponentJson"/>) — never for the array-level structure itself.
/// </para>
/// <para>
/// <strong>Fail-closed at the delegate boundary.</strong> <see cref="TryParse"/> wraps its whole per-element
/// walk in one try/catch, disposing every already-built element before returning <see langword="false"/> on any
/// malformed input or whole-array mode conflict (JA-5.3.1-10/-11) — mirroring
/// <c>CBAdESSignatureSerialization.ParseCBAdESSign1</c>'s dispose-on-throw convention.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "BuildOpaqueElement/BuildClearElement mint disposable carriers (JAdESOpaqueUnsignedValue<T>/JAdESClearUnsignedValue<T> and the Pki-model values they wrap) whose ownership transfers into the returned JAdESUnsignedHeaderElement, then into the elements list, then into the JAdESUnsignedHeaders TryParse returns via its out parameter — the caller of TryParse owns and disposes the whole tree; any failure along the way is caught by TryParse's own try/catch, which disposes every already-built element (DisposeAll).")]
public static class JAdESEtsiUJson
{
    /// <summary>The <see cref="TryParseJAdESEtsiUDelegate"/> binding — see the type remarks.</summary>
    public static TryParseJAdESEtsiUDelegate TryParse { get; } = static (
        ReadOnlySpan<byte> etsiUJsonBytes, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool, out JAdESUnsignedHeaders? result) =>
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        var elements = new List<JAdESUnsignedHeaderElement>();

        try
        {
            int pos = SkipWhitespace(etsiUJsonBytes, 0);
            if(pos >= etsiUJsonBytes.Length || etsiUJsonBytes[pos] != (byte)'[')
            {
                result = null;
                return false;
            }

            pos++;
            JAdESEtsiUIncorporationMode? mode = null;

            while(true)
            {
                pos = SkipWhitespaceAndCommas(etsiUJsonBytes, pos);
                if(pos >= etsiUJsonBytes.Length)
                {
                    DisposeAll(elements);
                    result = null;
                    return false;
                }

                if(etsiUJsonBytes[pos] == (byte)']')
                {
                    pos++;
                    break;
                }

                byte marker = etsiUJsonBytes[pos];
                if(marker == (byte)'"')
                {
                    if(mode == JAdESEtsiUIncorporationMode.ClearJson)
                    {
                        DisposeAll(elements);
                        result = null;
                        return false;
                    }

                    mode = JAdESEtsiUIncorporationMode.Base64Url;

                    int contentStart = pos + 1;
                    int contentEnd = FindStringEnd(etsiUJsonBytes, contentStart);
                    elements.Add(BuildBase64UrlElement(etsiUJsonBytes[contentStart..contentEnd], base64UrlDecoder, pool));
                    pos = contentEnd + 1;
                }
                else if(marker == (byte)'{')
                {
                    if(mode == JAdESEtsiUIncorporationMode.Base64Url)
                    {
                        DisposeAll(elements);
                        result = null;
                        return false;
                    }

                    mode = JAdESEtsiUIncorporationMode.ClearJson;

                    int objectEnd = FindObjectEnd(etsiUJsonBytes, pos);
                    elements.Add(BuildClearJsonElement(etsiUJsonBytes[pos..objectEnd], pool));
                    pos = objectEnd;
                }
                else
                {
                    //JA-5.3.1-09: an etsiU element is either a JSON string or clear JSON value; every named
                    //kind's clear form is itself a JSON object, so anything else at this position is malformed.
                    DisposeAll(elements);
                    result = null;
                    return false;
                }
            }

            if(SkipWhitespace(etsiUJsonBytes, pos) != etsiUJsonBytes.Length)
            {
                DisposeAll(elements);
                result = null;
                return false;
            }

            if(elements.Count == 0 || mode is null)
            {
                //JA-5.3.1-07: etsiU shall be a non-empty array.
                DisposeAll(elements);
                result = null;
                return false;
            }

            result = new JAdESUnsignedHeaders(mode.Value, elements);
            return true;
        }
        catch(Exception exception) when(IsFailClosedParseException(exception))
        {
            DisposeAll(elements);
            result = null;
            return false;
        }
    };


    /// <summary>The <see cref="EncodeJAdESUnprotectedHeaderDelegate"/> binding — see the type remarks.</summary>
    public static EncodeJAdESUnprotectedHeaderDelegate Encode { get; } = static unsignedHeaders =>
    {
        if(unsignedHeaders is null)
        {
            return null;
        }

        var elements = new List<object>(unsignedHeaders.Count);
        foreach(JAdESUnsignedHeaderElement element in unsignedHeaders)
        {
            elements.Add(ProjectElement(element, unsignedHeaders.Mode));
        }

        return new Dictionary<string, object> { [WellKnownJAdESHeaderNames.EtsiU] = elements };
    };


    //Base64url-decodes and JSON-parses an element's own wire
    //text into the SAME typed model the clear arm holds, carried BESIDE the verbatim wire text on the returned
    //JAdESOpaqueUnsignedValue<T> -- the §1.4 discipline (text for imprints, decoded view for inspection, never
    //re-encoded; see that type's own remarks). A text that does not decode/parse propagates up to TryParse's
    //own try/catch as the identical fail-closed malformed-encoding outcome kind detection alone used to produce.
    private static JAdESUnsignedHeaderElement BuildBase64UrlElement(ReadOnlySpan<byte> base64UrlContent, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool)
    {
        PooledMemory wireText = PooledMemory.FromBytes(base64UrlContent, pool, CryptoTags.JoseEncodedUnsignedHeaderElement);
        try
        {
            string base64UrlText = Encoding.ASCII.GetString(base64UrlContent);
            using IMemoryOwner<byte> decoded = base64UrlDecoder(base64UrlText, pool);
            using JsonDocument document = JsonDocument.Parse(decoded.Memory.ToArray());
            string kind = RequireSingleMemberKind(document.RootElement, out JsonElement value);

            return BuildOpaqueElement(kind, value, wireText, pool);
        }
        catch
        {
            wireText.Dispose();
            throw;
        }
    }


    private static JAdESUnsignedHeaderElement BuildClearJsonElement(ReadOnlySpan<byte> objectSpan, BaseMemoryPool pool)
    {
        using JsonDocument document = JsonDocument.Parse(objectSpan.ToArray());
        string kind = RequireSingleMemberKind(document.RootElement, out JsonElement value);

        return BuildClearElement(kind, value, objectSpan, pool);
    }


    private static string RequireSingleMemberKind(JsonElement root, out JsonElement value)
    {
        if(root.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("An etsiU element's own content must be a single-member {Kind: value} JSON object (ETSI TS 119 182-1 V1.2.1, clause 5.3.1).");
        }

        string? kind = null;
        value = default;
        int count = 0;
        foreach(JsonProperty property in root.EnumerateObject())
        {
            kind = property.Name;
            value = property.Value;
            ++count;
        }

        if(count != 1 || kind is null)
        {
            throw new FormatException("An etsiU element's own content must be a single-member {Kind: value} JSON object (ETSI TS 119 182-1 V1.2.1, clause 5.3.1).");
        }

        return kind;
    }


    //Decodes value (the SAME JsonElement RequireSingleMemberKind already isolated) into the identical
    //typed model BuildClearElement below decodes for the clear arm, wrapping wireText + the decoded value
    //together into the opaque arm's dual carriage. cSig/unknown are mode-agnostic (no typed model at this
    //stage, see JAdESUnsignedHeaderElement's own remarks) and keep their WireText-only shape unchanged.
    private static JAdESUnsignedHeaderElement BuildOpaqueElement(string kind, JsonElement value, PooledMemory wireText, BaseMemoryPool pool) => kind switch
    {
        JAdESUnsignedHeaderElement.SignaturePolicyStoreKind => new JAdESUnsignedHeaderElementSignaturePolicyStore(new JAdESOpaqueUnsignedValue<JAdESSignaturePolicyStore>(wireText, JAdESUnsignedComponentJson.DecodeSignaturePolicyStore(value, pool))),
        JAdESUnsignedHeaderElement.CounterSignatureKind => new JAdESUnsignedHeaderElementCounterSignature(wireText),
        JAdESUnsignedHeaderElement.SignatureTimestampKind => new JAdESUnsignedHeaderElementSignatureTimestamp(new JAdESOpaqueUnsignedValue<AdESTimestampContainer>(wireText, JAdESUnsignedComponentJson.DecodeTimestampContainer(value))),
        JAdESUnsignedHeaderElement.CertificateValuesKind => new JAdESUnsignedHeaderElementCertificateValues(new JAdESOpaqueUnsignedValue<JAdESCertificateValues>(wireText, JAdESUnsignedComponentJson.DecodeCertificateValues(value))),
        JAdESUnsignedHeaderElement.RevocationValuesKind => new JAdESUnsignedHeaderElementRevocationValues(new JAdESOpaqueUnsignedValue<JAdESRevocationValues>(wireText, JAdESUnsignedComponentJson.DecodeRevocationValues(value))),
        JAdESUnsignedHeaderElement.AttributeCertificateValuesKind => new JAdESUnsignedHeaderElementAttributeCertificateValues(new JAdESOpaqueUnsignedValue<JAdESCertificateValues>(wireText, JAdESUnsignedComponentJson.DecodeCertificateValues(value))),
        JAdESUnsignedHeaderElement.AttributeRevocationValuesKind => new JAdESUnsignedHeaderElementAttributeRevocationValues(new JAdESOpaqueUnsignedValue<JAdESRevocationValues>(wireText, JAdESUnsignedComponentJson.DecodeRevocationValues(value))),
        JAdESUnsignedHeaderElement.AnyValidationDataKind => new JAdESUnsignedHeaderElementAnyValidationData(new JAdESOpaqueUnsignedValue<JAdESValidationData>(wireText, JAdESUnsignedComponentJson.DecodeValidationData(value))),
        JAdESUnsignedHeaderElement.TimestampValidationDataKind => new JAdESUnsignedHeaderElementTimestampValidationData(new JAdESOpaqueUnsignedValue<JAdESValidationData>(wireText, JAdESUnsignedComponentJson.DecodeValidationData(value))),
        JAdESUnsignedHeaderElement.ArchiveTimestampKind => new JAdESUnsignedHeaderElementArchiveTimestamp(new JAdESOpaqueUnsignedValue<AdESTimestampContainer>(wireText, JAdESUnsignedComponentJson.DecodeTimestampContainer(value))),
        JAdESUnsignedHeaderElement.CertificateReferencesKind => new JAdESUnsignedHeaderElementCertificateReferences(new JAdESOpaqueUnsignedValue<JAdESCertificateReferenceCollection>(wireText, JAdESUnsignedComponentJson.DecodeCertificateReferenceCollection(value, pool))),
        JAdESUnsignedHeaderElement.RevocationReferencesKind => new JAdESUnsignedHeaderElementRevocationReferences(new JAdESOpaqueUnsignedValue<JAdESRevocationReferenceCollection>(wireText, JAdESUnsignedComponentJson.DecodeRevocationReferenceCollection(value, pool))),
        JAdESUnsignedHeaderElement.AttributeCertificateReferencesKind => new JAdESUnsignedHeaderElementAttributeCertificateReferences(new JAdESOpaqueUnsignedValue<JAdESCertificateReferenceCollection>(wireText, JAdESUnsignedComponentJson.DecodeCertificateReferenceCollection(value, pool))),
        JAdESUnsignedHeaderElement.AttributeRevocationReferencesKind => new JAdESUnsignedHeaderElementAttributeRevocationReferences(new JAdESOpaqueUnsignedValue<JAdESRevocationReferenceCollection>(wireText, JAdESUnsignedComponentJson.DecodeRevocationReferenceCollection(value, pool))),
        JAdESUnsignedHeaderElement.SignatureAndReferencesTimestampKind => new JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new JAdESOpaqueUnsignedValue<AdESTimestampContainer>(wireText, JAdESUnsignedComponentJson.DecodeTimestampContainer(value))),
        JAdESUnsignedHeaderElement.ReferencesTimestampKind => new JAdESUnsignedHeaderElementReferencesTimestamp(new JAdESOpaqueUnsignedValue<AdESTimestampContainer>(wireText, JAdESUnsignedComponentJson.DecodeTimestampContainer(value))),
        _ => new JAdESUnsignedHeaderElementUnknown(kind, wireText)
    };


    private static JAdESUnsignedHeaderElement BuildClearElement(string kind, JsonElement value, ReadOnlySpan<byte> objectSpan, BaseMemoryPool pool) => kind switch
    {
        JAdESUnsignedHeaderElement.SignaturePolicyStoreKind => new JAdESUnsignedHeaderElementSignaturePolicyStore(new JAdESClearUnsignedValue<JAdESSignaturePolicyStore>(JAdESUnsignedComponentJson.DecodeSignaturePolicyStore(value, pool))),
        JAdESUnsignedHeaderElement.CounterSignatureKind => new JAdESUnsignedHeaderElementCounterSignature(PooledMemory.FromBytes(objectSpan, pool, CryptoTags.JoseEncodedUnsignedHeaderElement)),
        JAdESUnsignedHeaderElement.SignatureTimestampKind => new JAdESUnsignedHeaderElementSignatureTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(JAdESUnsignedComponentJson.DecodeTimestampContainer(value))),
        JAdESUnsignedHeaderElement.CertificateValuesKind => new JAdESUnsignedHeaderElementCertificateValues(new JAdESClearUnsignedValue<JAdESCertificateValues>(JAdESUnsignedComponentJson.DecodeCertificateValues(value))),
        JAdESUnsignedHeaderElement.RevocationValuesKind => new JAdESUnsignedHeaderElementRevocationValues(new JAdESClearUnsignedValue<JAdESRevocationValues>(JAdESUnsignedComponentJson.DecodeRevocationValues(value))),
        JAdESUnsignedHeaderElement.AttributeCertificateValuesKind => new JAdESUnsignedHeaderElementAttributeCertificateValues(new JAdESClearUnsignedValue<JAdESCertificateValues>(JAdESUnsignedComponentJson.DecodeCertificateValues(value))),
        JAdESUnsignedHeaderElement.AttributeRevocationValuesKind => new JAdESUnsignedHeaderElementAttributeRevocationValues(new JAdESClearUnsignedValue<JAdESRevocationValues>(JAdESUnsignedComponentJson.DecodeRevocationValues(value))),
        JAdESUnsignedHeaderElement.AnyValidationDataKind => new JAdESUnsignedHeaderElementAnyValidationData(new JAdESClearUnsignedValue<JAdESValidationData>(JAdESUnsignedComponentJson.DecodeValidationData(value))),
        JAdESUnsignedHeaderElement.TimestampValidationDataKind => new JAdESUnsignedHeaderElementTimestampValidationData(new JAdESClearUnsignedValue<JAdESValidationData>(JAdESUnsignedComponentJson.DecodeValidationData(value))),
        JAdESUnsignedHeaderElement.ArchiveTimestampKind => new JAdESUnsignedHeaderElementArchiveTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(JAdESUnsignedComponentJson.DecodeTimestampContainer(value))),
        JAdESUnsignedHeaderElement.CertificateReferencesKind => new JAdESUnsignedHeaderElementCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(JAdESUnsignedComponentJson.DecodeCertificateReferenceCollection(value, pool))),
        JAdESUnsignedHeaderElement.RevocationReferencesKind => new JAdESUnsignedHeaderElementRevocationReferences(new JAdESClearUnsignedValue<JAdESRevocationReferenceCollection>(JAdESUnsignedComponentJson.DecodeRevocationReferenceCollection(value, pool))),
        JAdESUnsignedHeaderElement.AttributeCertificateReferencesKind => new JAdESUnsignedHeaderElementAttributeCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(JAdESUnsignedComponentJson.DecodeCertificateReferenceCollection(value, pool))),
        JAdESUnsignedHeaderElement.AttributeRevocationReferencesKind => new JAdESUnsignedHeaderElementAttributeRevocationReferences(new JAdESClearUnsignedValue<JAdESRevocationReferenceCollection>(JAdESUnsignedComponentJson.DecodeRevocationReferenceCollection(value, pool))),
        JAdESUnsignedHeaderElement.SignatureAndReferencesTimestampKind => new JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(JAdESUnsignedComponentJson.DecodeTimestampContainer(value))),
        JAdESUnsignedHeaderElement.ReferencesTimestampKind => new JAdESUnsignedHeaderElementReferencesTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(JAdESUnsignedComponentJson.DecodeTimestampContainer(value))),
        _ => new JAdESUnsignedHeaderElementUnknown(kind, PooledMemory.FromBytes(objectSpan, pool, CryptoTags.JoseEncodedUnsignedHeaderElement))
    };


    private static object ProjectElement(JAdESUnsignedHeaderElement element, JAdESEtsiUIncorporationMode mode) => element switch
    {
        JAdESUnsignedHeaderElementCounterSignature cSig => ProjectWireTextOnly(cSig.WireText, mode),
        JAdESUnsignedHeaderElementUnknown unknown => ProjectWireTextOnly(unknown.WireText, mode),
        _ => ProjectTypedElement(element, mode)
    };


    //cSig/unknown carry no JAdESUnsignedValue duality of their own (WireText always holds the element's raw
    //wire text, base64url or clear-JSON per the container's own Mode) -- projecting it onto the generic writer
    //shape needs different handling per mode: a plain string under Base64Url, or a re-parsed JSON structure
    //under ClearJson (the raw text already IS the {Kind: value} object; wrapping it as a STRING would double-
    //encode it).
    private static object ProjectWireTextOnly(PooledMemory wireText, JAdESEtsiUIncorporationMode mode)
    {
        if(mode == JAdESEtsiUIncorporationMode.Base64Url)
        {
            return Encoding.ASCII.GetString(wireText.AsReadOnlySpan());
        }

        using JsonDocument document = JsonDocument.Parse(wireText.AsReadOnlyMemory());

        return JsonElementToGenericValue(document.RootElement) ?? throw new InvalidOperationException("A cSig/unknown clear-JSON element's own text must not be JSON null.");
    }


    private static object ProjectTypedElement(JAdESUnsignedHeaderElement element, JAdESEtsiUIncorporationMode mode)
    {
        if(mode == JAdESEtsiUIncorporationMode.Base64Url)
        {
            return Encoding.ASCII.GetString(GetOpaqueWireText(element).Span);
        }

        return new Dictionary<string, object> { [element.Kind] = EncodeClearValue(element) };
    }


    //Mirrors JAdESMessageImprints.GetOpaqueWireText's identical switch shape -- safe by the same construction
    //argument that method's own remarks document (every mode-reporting arm under Base64Url mode is guaranteed
    //to carry a JAdESOpaqueUnsignedValue{TValue} carriage, JAdESUnsignedHeaders's own invariant).
    private static ReadOnlyMemory<byte> GetOpaqueWireText(JAdESUnsignedHeaderElement element) => element switch
    {
        JAdESUnsignedHeaderElementSignaturePolicyStore e => ((JAdESOpaqueUnsignedValue<JAdESSignaturePolicyStore>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementSignatureTimestamp e => ((JAdESOpaqueUnsignedValue<AdESTimestampContainer>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementCertificateValues e => ((JAdESOpaqueUnsignedValue<JAdESCertificateValues>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementRevocationValues e => ((JAdESOpaqueUnsignedValue<JAdESRevocationValues>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementAttributeCertificateValues e => ((JAdESOpaqueUnsignedValue<JAdESCertificateValues>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementAttributeRevocationValues e => ((JAdESOpaqueUnsignedValue<JAdESRevocationValues>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementAnyValidationData e => ((JAdESOpaqueUnsignedValue<JAdESValidationData>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementTimestampValidationData e => ((JAdESOpaqueUnsignedValue<JAdESValidationData>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementArchiveTimestamp e => ((JAdESOpaqueUnsignedValue<AdESTimestampContainer>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementCertificateReferences e => ((JAdESOpaqueUnsignedValue<JAdESCertificateReferenceCollection>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementRevocationReferences e => ((JAdESOpaqueUnsignedValue<JAdESRevocationReferenceCollection>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementAttributeCertificateReferences e => ((JAdESOpaqueUnsignedValue<JAdESCertificateReferenceCollection>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementAttributeRevocationReferences e => ((JAdESOpaqueUnsignedValue<JAdESRevocationReferenceCollection>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp e => ((JAdESOpaqueUnsignedValue<AdESTimestampContainer>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementReferencesTimestamp e => ((JAdESOpaqueUnsignedValue<AdESTimestampContainer>)e.Carriage).WireText.AsReadOnlyMemory(),
        _ => throw new NotSupportedException($"Unknown etsiU element arm '{element.GetType()}'.")
    };


    private static object EncodeClearValue(JAdESUnsignedHeaderElement element) => element switch
    {
        JAdESUnsignedHeaderElementSignaturePolicyStore e => JAdESUnsignedComponentJson.EncodeSignaturePolicyStore(((JAdESClearUnsignedValue<JAdESSignaturePolicyStore>)e.Carriage).Value),
        JAdESUnsignedHeaderElementSignatureTimestamp e => JAdESUnsignedComponentJson.EncodeTimestampContainer(((JAdESClearUnsignedValue<AdESTimestampContainer>)e.Carriage).Value),
        JAdESUnsignedHeaderElementCertificateValues e => JAdESUnsignedComponentJson.EncodeCertificateValues(((JAdESClearUnsignedValue<JAdESCertificateValues>)e.Carriage).Value),
        JAdESUnsignedHeaderElementRevocationValues e => JAdESUnsignedComponentJson.EncodeRevocationValues(((JAdESClearUnsignedValue<JAdESRevocationValues>)e.Carriage).Value),
        JAdESUnsignedHeaderElementAttributeCertificateValues e => JAdESUnsignedComponentJson.EncodeCertificateValues(((JAdESClearUnsignedValue<JAdESCertificateValues>)e.Carriage).Value),
        JAdESUnsignedHeaderElementAttributeRevocationValues e => JAdESUnsignedComponentJson.EncodeRevocationValues(((JAdESClearUnsignedValue<JAdESRevocationValues>)e.Carriage).Value),
        JAdESUnsignedHeaderElementAnyValidationData e => JAdESUnsignedComponentJson.EncodeValidationData(((JAdESClearUnsignedValue<JAdESValidationData>)e.Carriage).Value),
        JAdESUnsignedHeaderElementTimestampValidationData e => JAdESUnsignedComponentJson.EncodeValidationData(((JAdESClearUnsignedValue<JAdESValidationData>)e.Carriage).Value),
        JAdESUnsignedHeaderElementArchiveTimestamp e => JAdESUnsignedComponentJson.EncodeTimestampContainer(((JAdESClearUnsignedValue<AdESTimestampContainer>)e.Carriage).Value),
        JAdESUnsignedHeaderElementCertificateReferences e => JAdESUnsignedComponentJson.EncodeCertificateReferenceCollection(((JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>)e.Carriage).Value),
        JAdESUnsignedHeaderElementRevocationReferences e => JAdESUnsignedComponentJson.EncodeRevocationReferenceCollection(((JAdESClearUnsignedValue<JAdESRevocationReferenceCollection>)e.Carriage).Value),
        JAdESUnsignedHeaderElementAttributeCertificateReferences e => JAdESUnsignedComponentJson.EncodeCertificateReferenceCollection(((JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>)e.Carriage).Value),
        JAdESUnsignedHeaderElementAttributeRevocationReferences e => JAdESUnsignedComponentJson.EncodeRevocationReferenceCollection(((JAdESClearUnsignedValue<JAdESRevocationReferenceCollection>)e.Carriage).Value),
        JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp e => JAdESUnsignedComponentJson.EncodeTimestampContainer(((JAdESClearUnsignedValue<AdESTimestampContainer>)e.Carriage).Value),
        JAdESUnsignedHeaderElementReferencesTimestamp e => JAdESUnsignedComponentJson.EncodeTimestampContainer(((JAdESClearUnsignedValue<AdESTimestampContainer>)e.Carriage).Value),
        _ => throw new NotSupportedException($"Unknown etsiU element arm '{element.GetType()}'.")
    };


    //Converts an arbitrary JsonElement into the plain Dictionary<string,object>/List<object>/primitive object
    //graph Converters.DictionaryStringObjectJsonConverter already knows how to write -- deliberately WITHOUT
    //that converter's own string->DateTime auto-sniff (see the type remarks on JAdESProtectedHeaderJson).
    private static object? JsonElementToGenericValue(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => EnumerateObjectToDictionary(element),
        JsonValueKind.Array => EnumerateArrayToList(element),
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Number => element.TryGetInt64(out long integer) ? integer : element.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null or JsonValueKind.Undefined => null,
        _ => throw new NotSupportedException($"Unsupported JsonValueKind '{element.ValueKind}'.")
    };


    private static Dictionary<string, object> EnumerateObjectToDictionary(JsonElement element)
    {
        var result = new Dictionary<string, object>();
        foreach(JsonProperty property in element.EnumerateObject())
        {
            result[property.Name] = JsonElementToGenericValue(property.Value)!;
        }

        return result;
    }


    private static List<object> EnumerateArrayToList(JsonElement element)
    {
        var result = new List<object>();
        foreach(JsonElement item in element.EnumerateArray())
        {
            result.Add(JsonElementToGenericValue(item)!);
        }

        return result;
    }


    private static void DisposeAll(List<JAdESUnsignedHeaderElement> elements)
    {
        foreach(JAdESUnsignedHeaderElement element in elements)
        {
            if(element is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }


    private static int SkipWhitespace(ReadOnlySpan<byte> json, int pos)
    {
        while(pos < json.Length && IsWhitespace(json[pos]))
        {
            ++pos;
        }

        return pos;
    }


    private static int SkipWhitespaceAndCommas(ReadOnlySpan<byte> json, int pos)
    {
        while(pos < json.Length && (IsWhitespace(json[pos]) || json[pos] == (byte)','))
        {
            ++pos;
        }

        return pos;
    }


    private static bool IsWhitespace(byte b) => b == (byte)' ' || b == (byte)'\t' || b == (byte)'\r' || b == (byte)'\n';


    //Returns the index of the closing quote (not itself part of the content), given pos = the index of the
    //first byte after the opening quote. Honors backslash escapes so a quoted quote inside the string does not
    //terminate the scan early; the content itself is returned verbatim (unescaped), matching the byte-exact
    //preservation this whole codec's base64url arm requires -- valid base64url text carries no character
    //that needs JSON escaping, so this is a no-op transform for every conformant producer.
    private static int FindStringEnd(ReadOnlySpan<byte> json, int pos)
    {
        while(pos < json.Length && json[pos] != (byte)'"')
        {
            if(json[pos] == (byte)'\\')
            {
                ++pos;
            }

            ++pos;
        }

        if(pos >= json.Length)
        {
            throw new FormatException("Unterminated JSON string in the etsiU array.");
        }

        return pos;
    }


    //pos points AT the object's opening '{'. Returns the index immediately AFTER the matching closing '}',
    //skipping over quoted string content (so a brace inside a string value never biases the depth counter).
    private static int FindObjectEnd(ReadOnlySpan<byte> json, int pos)
    {
        int depth = 0;
        while(pos < json.Length)
        {
            byte b = json[pos];
            if(b == (byte)'"')
            {
                pos = FindStringEnd(json, pos + 1) + 1;
                continue;
            }

            if(b == (byte)'{')
            {
                ++depth;
            }
            else if(b == (byte)'}')
            {
                --depth;
                if(depth == 0)
                {
                    return pos + 1;
                }
            }

            ++pos;
        }

        throw new FormatException("Unterminated JSON object in the etsiU array.");
    }


    //KeyNotFoundException is JsonElement.GetProperty's own throw for a missing mandatory member -- included
    //alongside the JSON/argument/range exceptions every nested Decode* helper in JAdESUnsignedComponentJson may
    //also throw, so no exception from that whole call tree escapes this seam.
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is JsonException or FormatException or ArgumentException or InvalidOperationException or OverflowException or KeyNotFoundException;
}
