using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Verifier-side CBOR reader for the ISO/IEC 18013-5 §8.3.2.1 <c>DeviceResponse</c>
/// wire envelope — the inverse of <see cref="MdocCborDeviceResponseWriter"/>.
/// Parses the bytes a wallet returns (the base64url-decoded OID4VP
/// <c>vp_token</c> value) into an owned <see cref="MdocParsedDeviceResponse"/>
/// the verifier runs issuer-auth, digest-binding, and device-signed
/// verification against.
/// </summary>
/// <remarks>
/// <para>
/// The four nested wire shapes (top-down): <c>DeviceResponse</c> envelope →
/// <c>Document</c> map → <c>IssuerSigned</c> map → namespaced ordered arrays of
/// Tag-24-wrapped <c>IssuerSignedItemBytes</c>, plus the optional
/// <c>DeviceSigned</c> map on each document. The reader composes the existing
/// component readers — <see cref="MdocCborIssuerAuthReader"/> for the
/// <c>issuerAuth</c> COSE_Sign1 (which in turn reads the MSO and the bound
/// device key) — and preserves the two byte runs verification re-hashes
/// verbatim: each item's <see cref="MdocIssuerSignedItem.WireBytes"/> (the MSO
/// digest commitment input) and the device half's
/// <see cref="MdocDeviceSigned.EncodedDeviceNameSpacesBytes"/> (the
/// <c>DeviceAuthentication</c> commitment input). Re-encoding either would shift
/// bytes and break the commitments.
/// </para>
/// <para>
/// <strong>Ownership.</strong> A successful read returns an owned
/// <see cref="MdocParsedDeviceResponse"/>; the caller disposes it. Because a
/// verifier parses untrusted bytes, every partial-parse failure path disposes
/// the carriers materialised so far before rethrowing, so a malformed
/// DeviceResponse never leaks pool memory.
/// </para>
/// <para>
/// Pool-routed carriers (per-item random salts, the device-side COSE wire
/// bytes) are rented from the supplied <paramref name="pool"/>; pass the same
/// <see cref="BaseMemoryPool"/> the rest of the verification flow uses
/// so the carriers' <c>Length</c> reflects the exact byte count.
/// </para>
/// </remarks>
public static class MdocCborDeviceResponseReader
{
    /// <summary>
    /// Reads a complete <c>DeviceResponse</c> from the supplied CBOR bytes.
    /// </summary>
    /// <param name="encodedDeviceResponse">The CBOR-encoded DeviceResponse map bytes.</param>
    /// <param name="pool">Memory pool the owned carriers rent from. Caller owns the returned response and must dispose it.</param>
    /// <returns>The parsed, owned <see cref="MdocParsedDeviceResponse"/>.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the bytes do not satisfy the ISO/IEC 18013-5 §8.3.2.1
    /// DeviceResponse wire shape or a required field is missing.
    /// </exception>
    public static MdocParsedDeviceResponse Read(ReadOnlySpan<byte> encodedDeviceResponse, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new CborReader(encodedDeviceResponse.ToArray(), CborConformanceMode.Lax);

        return ReadDeviceResponse(reader, pool);
    }


    private static MdocParsedDeviceResponse ReadDeviceResponse(CborReader reader, MemoryPool<byte> pool)
    {
        int? entryCount = reader.ReadStartMap();

        string? version = null;
        uint? status = null;
        List<MdocParsedDocument>? documents = null;
        ReadOnlyMemory<byte>? documentErrors = null;

        try
        {
            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string key = reader.ReadTextString();
                entriesRead++;

                switch(key)
                {
                    case MdocWellKnownKeys.Version:
                    {
                        version = reader.ReadTextString();

                        break;
                    }
                    case MdocWellKnownKeys.Documents:
                    {
                        documents = ReadDocuments(reader, pool);

                        break;
                    }
                    case MdocWellKnownKeys.DocumentErrors:
                    {
                        documentErrors = reader.ReadEncodedValue();

                        break;
                    }
                    case MdocWellKnownKeys.Status:
                    {
                        status = (uint)reader.ReadUInt64();

                        break;
                    }
                    default:
                    {
                        reader.SkipValue();

                        break;
                    }
                }
            }

            reader.ReadEndMap();
        }
        catch
        {
            DisposeDocuments(documents);

            throw;
        }

        if(version is null || status is null)
        {
            DisposeDocuments(documents);

            throw new CborContentException(
                "DeviceResponse is missing one or more required fields per ISO/IEC 18013-5 §8.3.2.1.1: version, status.");
        }

        return new MdocParsedDeviceResponse(
            version: version,
            documents: documents ?? [],
            status: status.Value,
            encodedDocumentErrors: documentErrors);
    }


    private static List<MdocParsedDocument> ReadDocuments(CborReader reader, MemoryPool<byte> pool)
    {
        int? count = reader.ReadStartArray();
        List<MdocParsedDocument> documents = new(count ?? 0);

        try
        {
            int read = 0;
            while(count is null ? reader.PeekState() != CborReaderState.EndArray : read < count.Value)
            {
                documents.Add(ReadDocument(reader, pool));
                read++;
            }

            reader.ReadEndArray();
        }
        catch
        {
            DisposeDocuments(documents);

            throw;
        }

        return documents;
    }


    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parsed issuer-signed and device-signed halves transfers to the returned MdocParsedDocument; the partial-parse failure paths dispose them explicitly.")]
    private static MdocParsedDocument ReadDocument(CborReader reader, MemoryPool<byte> pool)
    {
        int? entryCount = reader.ReadStartMap();

        string? docType = null;
        MdocIssuerSigned? issuerSigned = null;
        MdocDeviceSigned? deviceSigned = null;

        try
        {
            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string key = reader.ReadTextString();
                entriesRead++;

                switch(key)
                {
                    case MdocWellKnownKeys.DocType:
                    {
                        docType = reader.ReadTextString();

                        break;
                    }
                    case MdocWellKnownKeys.IssuerSigned:
                    {
                        issuerSigned = ReadIssuerSigned(reader, pool);

                        break;
                    }
                    case MdocWellKnownKeys.DeviceSigned:
                    {
                        deviceSigned = ReadDeviceSigned(reader, pool);

                        break;
                    }
                    default:
                    {
                        reader.SkipValue();

                        break;
                    }
                }
            }

            reader.ReadEndMap();
        }
        catch
        {
            issuerSigned?.Dispose();
            deviceSigned?.Dispose();

            throw;
        }

        if(string.IsNullOrEmpty(docType) || issuerSigned is null)
        {
            issuerSigned?.Dispose();
            deviceSigned?.Dispose();

            throw new CborContentException(
                "DeviceResponse Document is missing one or more required fields per ISO/IEC 18013-5 §8.3.2.1: docType, issuerSigned.");
        }

        return new MdocParsedDocument(docType, issuerSigned, deviceSigned);
    }


    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parsed namespaces items and issuerAuth transfers to the returned MdocIssuerSigned; the partial-parse failure paths dispose them explicitly.")]
    private static MdocIssuerSigned ReadIssuerSigned(CborReader reader, MemoryPool<byte> pool)
    {
        int? entryCount = reader.ReadStartMap();

        Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>>? nameSpaces = null;
        MdocIssuerAuth? issuerAuth = null;

        try
        {
            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string key = reader.ReadTextString();
                entriesRead++;

                switch(key)
                {
                    case MdocWellKnownKeys.NameSpaces:
                    {
                        nameSpaces = ReadIssuerNameSpaces(reader, pool);

                        break;
                    }
                    case MdocWellKnownKeys.IssuerAuth:
                    {
                        //issuerAuth is a COSE_Sign1 (Tag 18) whose payload is the Tag-24-wrapped
                        //MSO; the composed reader parses both layers and pool-routes the wire bytes.
                        ReadOnlyMemory<byte> encodedCoseSign1 = reader.ReadEncodedValue();
                        issuerAuth = MdocCborIssuerAuthReader.Read(encodedCoseSign1.Span, pool);

                        break;
                    }
                    default:
                    {
                        reader.SkipValue();

                        break;
                    }
                }
            }

            reader.ReadEndMap();
        }
        catch
        {
            DisposeNameSpaces(nameSpaces);
            issuerAuth?.Dispose();

            throw;
        }

        if(issuerAuth is null)
        {
            DisposeNameSpaces(nameSpaces);

            throw new CborContentException(
                "IssuerSigned is missing the mandatory issuerAuth field per ISO/IEC 18013-5 §8.3.2.1.2.");
        }

        return new MdocIssuerSigned(
            nameSpaces ?? new Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>>(StringComparer.Ordinal),
            issuerAuth);
    }


    private static Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>> ReadIssuerNameSpaces(CborReader reader, MemoryPool<byte> pool)
    {
        int? namespaceCount = reader.ReadStartMap();
        Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>> nameSpaces = new(StringComparer.Ordinal);

        try
        {
            int nsRead = 0;
            while(namespaceCount is null ? reader.PeekState() != CborReaderState.EndMap : nsRead < namespaceCount.Value)
            {
                string nameSpace = reader.ReadTextString();
                nsRead++;

                nameSpaces[nameSpace] = ReadIssuerSignedItems(reader, pool);
            }

            reader.ReadEndMap();
        }
        catch
        {
            DisposeNameSpaces(nameSpaces);

            throw;
        }

        return nameSpaces;
    }


    private static List<MdocIssuerSignedItem> ReadIssuerSignedItems(CborReader reader, MemoryPool<byte> pool)
    {
        int? itemCount = reader.ReadStartArray();
        List<MdocIssuerSignedItem> items = new(itemCount ?? 0);

        try
        {
            int itemsRead = 0;
            while(itemCount is null ? reader.PeekState() != CborReaderState.EndArray : itemsRead < itemCount.Value)
            {
                items.Add(ReadIssuerSignedItem(reader, pool));
                itemsRead++;
            }

            reader.ReadEndArray();
        }
        catch
        {
            foreach(MdocIssuerSignedItem item in items)
            {
                item.Dispose();
            }

            throw;
        }

        return items;
    }


    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the pool-routed random salt transfers to the returned MdocIssuerSignedItem; the caller's namespaces aggregation disposes it on later failure.")]
    private static MdocIssuerSignedItem ReadIssuerSignedItem(CborReader reader, MemoryPool<byte> pool)
    {
        //Preserve the exact Tag-24 wrapper bytes — the MSO digest commitment hashes them verbatim,
        //so the verifier MUST hash the same byte pattern the issuer committed to.
        EncodedCborItem wrapper = EncodedCborItem.Read(reader);

        var inner = new CborReader(wrapper.InnerBytes.ToArray(), CborConformanceMode.Lax);
        int? entryCount = inner.ReadStartMap();

        uint? digestId = null;
        byte[]? randomBytes = null;
        string? elementIdentifier = null;
        ReadOnlyMemory<byte>? encodedElementValue = null;

        int entriesRead = 0;
        while(entryCount is null ? inner.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
        {
            string key = inner.ReadTextString();
            entriesRead++;

            switch(key)
            {
                case MdocWellKnownKeys.DigestId:
                {
                    digestId = (uint)inner.ReadUInt64();

                    break;
                }
                case MdocWellKnownKeys.Random:
                {
                    randomBytes = inner.ReadByteString();

                    break;
                }
                case MdocWellKnownKeys.ElementIdentifier:
                {
                    elementIdentifier = inner.ReadTextString();

                    break;
                }
                case MdocWellKnownKeys.ElementValue:
                {
                    encodedElementValue = inner.ReadEncodedValue();

                    break;
                }
                default:
                {
                    inner.SkipValue();

                    break;
                }
            }
        }

        inner.ReadEndMap();

        if(digestId is null || randomBytes is null || string.IsNullOrEmpty(elementIdentifier) || encodedElementValue is null)
        {
            throw new CborContentException(
                "IssuerSignedItem is missing one or more required fields per ISO/IEC 18013-5 §8.3.2.1.2.2: " +
                "digestID, random, elementIdentifier, elementValue.");
        }

        //Pool-route the per-item random into a tracked Salt carrier so it has a clear owner
        //and CBOM provenance, matching the issuance-side salt ownership.
        IMemoryOwner<byte> randomOwner = pool.Rent(randomBytes.Length);
        randomBytes.CopyTo(randomOwner.Memory.Span);
        Salt random = new(randomOwner, CryptoTags.MdocIssuerSignedItemRandom);

        return new MdocIssuerSignedItem(
            digestId: digestId.Value,
            random: random,
            elementIdentifier: elementIdentifier,
            encodedElementValue: encodedElementValue.Value,
            wireBytes: wrapper.WireBytes);
    }


    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parsed deviceAuth transfers to the returned MdocDeviceSigned; the partial-parse failure paths dispose it explicitly.")]
    private static MdocDeviceSigned ReadDeviceSigned(CborReader reader, MemoryPool<byte> pool)
    {
        int? entryCount = reader.ReadStartMap();

        ReadOnlyMemory<byte>? encodedDeviceNameSpacesBytes = null;
        MdocDeviceNameSpaces? deviceNameSpaces = null;
        MdocDeviceAuth? deviceAuth = null;

        try
        {
            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string key = reader.ReadTextString();
                entriesRead++;

                switch(key)
                {
                    case MdocWellKnownKeys.NameSpaces:
                    {
                        //The device nameSpaces slot is the Tag-24 wrapper the DeviceAuthentication
                        //array commits to; preserve it verbatim so the signature reconstruction matches,
                        //and parse the inner map for the device-asserted claims. Parsing inside the try
                        //keeps a malformed-namespaces failure from leaking an already-read deviceAuth.
                        encodedDeviceNameSpacesBytes = reader.ReadEncodedValue();
                        deviceNameSpaces = ReadDeviceNameSpaces(encodedDeviceNameSpacesBytes.Value);

                        break;
                    }
                    case MdocWellKnownKeys.DeviceAuth:
                    {
                        deviceAuth = ReadDeviceAuth(reader, pool);

                        break;
                    }
                    default:
                    {
                        reader.SkipValue();

                        break;
                    }
                }
            }

            reader.ReadEndMap();
        }
        catch
        {
            deviceAuth?.Dispose();

            throw;
        }

        if(encodedDeviceNameSpacesBytes is null || deviceNameSpaces is null || deviceAuth is null)
        {
            deviceAuth?.Dispose();

            throw new CborContentException(
                "DeviceSigned is missing one or more required fields per ISO/IEC 18013-5 §8.3.2.1.2.3: nameSpaces, deviceAuth.");
        }

        return new MdocDeviceSigned(deviceNameSpaces, encodedDeviceNameSpacesBytes.Value, deviceAuth);
    }


    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the pool-routed COSE carrier transfers through the MdocDeviceSignature/MdocDeviceMac into the returned MdocDeviceAuth; the failure path disposes it explicitly.")]
    private static MdocDeviceAuth ReadDeviceAuth(CborReader reader, MemoryPool<byte> pool)
    {
        int? entryCount = reader.ReadStartMap();

        MdocDeviceAuth? deviceAuth = null;

        try
        {
            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                string key = reader.ReadTextString();
                entriesRead++;

                switch(key)
                {
                    case MdocWellKnownKeys.DeviceSignature:
                    {
                        ReadOnlyMemory<byte> encoded = reader.ReadEncodedValue();
                        EncodedCoseSign1 carrier = PoolRoute(encoded.Span, CryptoTags.CoseEncodedSign1, pool);
                        deviceAuth = new MdocDeviceAuth(new MdocDeviceSignature(carrier));

                        break;
                    }
                    case MdocWellKnownKeys.DeviceMac:
                    {
                        ReadOnlyMemory<byte> encoded = reader.ReadEncodedValue();
                        IMemoryOwner<byte> owner = pool.Rent(encoded.Length);
                        encoded.Span.CopyTo(owner.Memory.Span);
                        deviceAuth = new MdocDeviceAuth(new MdocDeviceMac(new EncodedCoseMac0(owner, CryptoTags.CoseEncodedMac0)));

                        break;
                    }
                    default:
                    {
                        reader.SkipValue();

                        break;
                    }
                }
            }

            reader.ReadEndMap();
        }
        catch
        {
            deviceAuth?.Dispose();

            throw;
        }

        if(deviceAuth is null)
        {
            throw new CborContentException(
                "DeviceAuth carries neither a deviceSignature nor a deviceMac per ISO/IEC 18013-5 §9.1.3.4.");
        }

        return deviceAuth;
    }


    /// <summary>
    /// Parses the verbatim Tag-24 <c>DeviceNameSpacesBytes</c> into the typed
    /// <see cref="MdocDeviceNameSpaces"/> view. The byte preservation that
    /// signature reconstruction relies on lives on
    /// <see cref="MdocDeviceSigned.EncodedDeviceNameSpacesBytes"/>; this parse
    /// only surfaces the device-asserted claims (empty in the common case).
    /// </summary>
    private static MdocDeviceNameSpaces ReadDeviceNameSpaces(ReadOnlyMemory<byte> encodedDeviceNameSpacesBytes)
    {
        EncodedCborItem wrapper = EncodedCborItem.Read(new CborReader(encodedDeviceNameSpacesBytes, CborConformanceMode.Lax));

        var inner = new CborReader(wrapper.InnerBytes.ToArray(), CborConformanceMode.Lax);
        int? namespaceCount = inner.ReadStartMap();
        Dictionary<string, IReadOnlyDictionary<string, ReadOnlyMemory<byte>>> entries = new(StringComparer.Ordinal);

        int nsRead = 0;
        while(namespaceCount is null ? inner.PeekState() != CborReaderState.EndMap : nsRead < namespaceCount.Value)
        {
            string nameSpace = inner.ReadTextString();
            nsRead++;

            int? elementCount = inner.ReadStartMap();
            Dictionary<string, ReadOnlyMemory<byte>> elements = new(StringComparer.Ordinal);

            int elementsRead = 0;
            while(elementCount is null ? inner.PeekState() != CborReaderState.EndMap : elementsRead < elementCount.Value)
            {
                string elementIdentifier = inner.ReadTextString();
                elements[elementIdentifier] = inner.ReadEncodedValue();
                elementsRead++;
            }

            inner.ReadEndMap();
            entries[nameSpace] = elements;
        }

        inner.ReadEndMap();

        return new MdocDeviceNameSpaces(entries);
    }


    private static EncodedCoseSign1 PoolRoute(ReadOnlySpan<byte> bytes, Tag tag, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new EncodedCoseSign1(owner, tag);
    }


    private static void DisposeDocuments(List<MdocParsedDocument>? documents)
    {
        if(documents is null)
        {
            return;
        }

        foreach(MdocParsedDocument document in documents)
        {
            document.Dispose();
        }
    }


    private static void DisposeNameSpaces(Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>>? nameSpaces)
    {
        if(nameSpaces is null)
        {
            return;
        }

        foreach(IReadOnlyList<MdocIssuerSignedItem> items in nameSpaces.Values)
        {
            foreach(MdocIssuerSignedItem item in items)
            {
                item.Dispose();
            }
        }
    }
}
