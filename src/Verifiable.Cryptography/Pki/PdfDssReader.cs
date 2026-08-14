using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Locates and decodes a document's DSS/VRI material (ETSI EN 319 142-1 clauses 5.4.2.2/5.4.2.3), composing
/// <see cref="PdfByteSurfaceReader"/>'s own object-index and object-resolution primitives (RP-1: no general PDF
/// object model — every array/dictionary this reader walks is one of the handful clause 5.4.2's own tables name).
/// </summary>
/// <remarks>
/// <strong>Fail-closed, promotion-shaped (RP-4).</strong> Every array entry and every VRI map entry is required to
/// be exactly the shape clause 5.4.2's own tables state — an indirect reference to a stream for a certificate/CRL/OCSP
/// array element, an indirect reference to a dictionary for a VRI map entry — and a document that deviates fails
/// the whole <see cref="Locate"/> call rather than silently dropping the malformed entry: DSS/VRI is validation
/// material a relying party trusts for revocation and existence decisions, unlike <see cref="PdfByteSurfaceReader.Locate"/>'s
/// own per-candidate skipping of decoy signature-shaped objects, where excluding one candidate can never make a
/// document's other, genuinely valid signatures unreachable.
/// </remarks>
public static class PdfDssReader
{
    /// <summary>The most entries one DSS-level or VRI-level array (<c>Certs</c>/<c>CRLs</c>/<c>OCSPs</c>/<c>Cert</c>/<c>CRL</c>/<c>OCSP</c>) may declare before this reader fails closed.</summary>
    private const int MaxArrayEntries = 65_536;

    /// <summary>The most entries the <c>VRI</c> map may declare before this reader fails closed.</summary>
    private const int MaxVriEntries = 65_536;


    /// <summary>
    /// Locates the document catalog through the trailer's own <c>/Root</c> reference and, when present, decodes
    /// its <c>DSS</c> entry.
    /// </summary>
    /// <param name="document">The whole PDF document's bytes. Borrowed: every carrier the result owns holds a copy of what it needs, so <paramref name="document"/> need not outlive the returned result.</param>
    /// <param name="pool">The memory pool every carrier the returned result owns is rented from.</param>
    /// <returns>The Unverified parse carriage. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static PdfDssParseResult Locate(ReadOnlyMemory<byte> document, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> s = document.Span;
        if(s.IsEmpty)
        {
            return PdfDssParseResult.Failure("The document is empty.");
        }

        if(!PdfByteSurfaceReader.TryBuildObjectIndex(s, out Dictionary<long, long> objectOffsets, out (long ObjectNumber, long Generation)? rootReference, out string? error))
        {
            return PdfDssParseResult.Failure(error);
        }

        if(rootReference is not { } root)
        {
            return PdfDssParseResult.Failure("No trailer '/Root' entry was found.");
        }

        if(!PdfByteSurfaceReader.TryResolveObject(s, objectOffsets, root.ObjectNumber, out PdfValue catalog, out error))
        {
            return PdfDssParseResult.Failure(error);
        }

        if(catalog.Kind != PdfValueKind.Dictionary || catalog.Entries is null)
        {
            return PdfDssParseResult.Failure("The document catalog is not a dictionary.");
        }

        if(!catalog.Entries.TryGetValue("DSS", out PdfValue dssReference))
        {
            return PdfDssParseResult.NoDss();
        }

        if(dssReference.Kind != PdfValueKind.Reference)
        {
            return PdfDssParseResult.Failure("The catalog's 'DSS' entry is not an indirect reference (PA-5.4.2.1-T1).");
        }

        if(!PdfByteSurfaceReader.TryResolveObject(s, objectOffsets, dssReference.Number, out PdfValue dss, out error))
        {
            return PdfDssParseResult.Failure(error);
        }

        if(dss.Kind != PdfValueKind.Dictionary || dss.Entries is null)
        {
            return PdfDssParseResult.Failure("The DSS object is not a dictionary (PA-5.4.2.2-01).");
        }

        //Every failure return below disposes whatever was already decoded first (metered custody): a partial
        //DSS read must never leak the pooled buffers its earlier, successfully decoded arrays already rented.
        if(!TryReadObjectArray(s, objectOffsets, dss.Entries, "Certs", PkiCertificateTags.X509Certificate, pool, out List<PkiCertificateMemory> certificates, out error))
        {
            DisposeAll(certificates);

            return PdfDssParseResult.Failure(error);
        }

        if(!TryReadObjectArray(s, objectOffsets, dss.Entries, "CRLs", PkiCertificateTags.X509Crl, pool, out List<PkiCertificateMemory> crls, out error))
        {
            DisposeAll(certificates);
            DisposeAll(crls);

            return PdfDssParseResult.Failure(error);
        }

        if(!TryReadObjectArray(s, objectOffsets, dss.Entries, "OCSPs", PkiCertificateTags.OcspResponse, pool, out List<PkiCertificateMemory> ocsps, out error))
        {
            DisposeAll(certificates);
            DisposeAll(crls);
            DisposeAll(ocsps);

            return PdfDssParseResult.Failure(error);
        }

        if(!TryReadVriMap(s, objectOffsets, dss.Entries, pool, out Dictionary<string, PdfVriDictionary> vriEntries, out error))
        {
            DisposeAll(certificates);
            DisposeAll(crls);
            DisposeAll(ocsps);
            foreach(PdfVriDictionary vri in vriEntries.Values)
            {
                vri.Dispose();
            }

            return PdfDssParseResult.Failure(error);
        }

        return PdfDssParseResult.Success(new PdfDssDictionary(certificates, crls, ocsps, vriEntries));
    }


    /// <summary>Reads an optional array of indirect references to streams (<c>Certs</c>/<c>CRLs</c>/<c>OCSPs</c>/<c>Cert</c>/<c>CRL</c>/<c>OCSP</c>), copying each stream's own data into a tagged carrier.</summary>
    private static bool TryReadObjectArray(
        ReadOnlySpan<byte> s, Dictionary<long, long> objectOffsets, IReadOnlyDictionary<string, PdfValue> entries,
        string key, Tag tag, BaseMemoryPool pool, out List<PkiCertificateMemory> items, [NotNullWhen(false)] out string? error)
    {
        items = [];
        error = null;
        if(!entries.TryGetValue(key, out PdfValue arrayValue))
        {
            return true;
        }

        if(arrayValue.Kind != PdfValueKind.Array || arrayValue.Items is null)
        {
            error = $"The DSS/VRI '{key}' entry is not an Array.";

            return false;
        }

        if(arrayValue.Items.Count == 0)
        {
            //PA-5.4.2.3-03/-06/-08: "if present, it shall not be an empty array" (the VRI-level instances of this
            //array); the DSS-level arrays state no such restriction, so an empty array is decoded, not rejected —
            //the specific "shall not be empty" enforcement belongs to the facts-binding stage that reconciles
            //against which dictionary (DSS vs. VRI) this call is reading.
            return true;
        }

        if(arrayValue.Items.Count > MaxArrayEntries)
        {
            error = $"The DSS/VRI '{key}' array declares more entries than this reader supports.";

            return false;
        }

        for(int i = 0; i < arrayValue.Items.Count; ++i)
        {
            PdfValue element = arrayValue.Items[i];
            if(element.Kind != PdfValueKind.Reference)
            {
                error = $"An element of the DSS/VRI '{key}' array is not an indirect reference.";

                return false;
            }

            if(!PdfByteSurfaceReader.TryResolveObject(s, objectOffsets, element.Number, out PdfValue streamValue, out error))
            {
                return false;
            }

            if(streamValue.Kind != PdfValueKind.Stream)
            {
                error = $"An element of the DSS/VRI '{key}' array does not resolve to a stream.";

                return false;
            }

            items.Add(CopyStreamToCarrier(s, streamValue, tag, pool));
        }

        return true;
    }


    /// <summary>Reads the optional <c>VRI</c> map, decoding every entry's own <c>Cert</c>/<c>CRL</c>/<c>OCSP</c> arrays and <c>TU</c>/<c>TS</c> claimed-time entries.</summary>
    private static bool TryReadVriMap(
        ReadOnlySpan<byte> s, Dictionary<long, long> objectOffsets, IReadOnlyDictionary<string, PdfValue> dssEntries,
        BaseMemoryPool pool, out Dictionary<string, PdfVriDictionary> vriEntries, [NotNullWhen(false)] out string? error)
    {
        vriEntries = new Dictionary<string, PdfVriDictionary>(StringComparer.Ordinal);
        error = null;
        if(!dssEntries.TryGetValue("VRI", out PdfValue vriMapValue))
        {
            return true;
        }

        if(vriMapValue.Kind != PdfValueKind.Dictionary || vriMapValue.Entries is null)
        {
            error = "The DSS 'VRI' entry is not a Dictionary (PA-5.4.2.2-T2).";

            return false;
        }

        if(vriMapValue.Entries.Count > MaxVriEntries)
        {
            error = "The 'VRI' map declares more entries than this reader supports.";

            return false;
        }

        foreach((string key, PdfValue entryRef) in vriMapValue.Entries)
        {
            if(entryRef.Kind != PdfValueKind.Reference)
            {
                error = $"The VRI entry '{key}' is not an indirect reference.";

                return false;
            }

            if(!PdfByteSurfaceReader.TryResolveObject(s, objectOffsets, entryRef.Number, out PdfValue vriValue, out error))
            {
                return false;
            }

            if(vriValue.Kind != PdfValueKind.Dictionary || vriValue.Entries is null)
            {
                error = $"The VRI entry '{key}' does not resolve to a dictionary (PA-5.4.2.3-01).";

                return false;
            }

            //Every failure return below disposes whatever this one VRI entry already decoded first (metered
            //custody); entries already committed to vriEntries are the caller's own cleanup responsibility.
            if(!TryReadObjectArray(s, objectOffsets, vriValue.Entries, "Cert", PkiCertificateTags.X509Certificate, pool, out List<PkiCertificateMemory> certs, out error))
            {
                DisposeAll(certs);

                return false;
            }

            if(!TryReadObjectArray(s, objectOffsets, vriValue.Entries, "CRL", PkiCertificateTags.X509Crl, pool, out List<PkiCertificateMemory> crls, out error))
            {
                DisposeAll(certs);
                DisposeAll(crls);

                return false;
            }

            if(!TryReadObjectArray(s, objectOffsets, vriValue.Entries, "OCSP", PkiCertificateTags.OcspResponse, pool, out List<PkiCertificateMemory> ocsps, out error))
            {
                DisposeAll(certs);
                DisposeAll(crls);
                DisposeAll(ocsps);

                return false;
            }

            if(!PdfByteSurfaceReader.TryDecodeOptionalTextEntry(vriValue.Entries, "TU", out string? timeUpdatedText, out error))
            {
                DisposeAll(certs);
                DisposeAll(crls);
                DisposeAll(ocsps);

                return false;
            }

            DateTimeOffset? timeUpdated = null;
            if(timeUpdatedText is not null)
            {
                if(!PdfByteSurfaceReader.TryParsePdfDate(timeUpdatedText, out DateTimeOffset parsedTimeUpdated))
                {
                    DisposeAll(certs);
                    DisposeAll(crls);
                    DisposeAll(ocsps);
                    error = $"The VRI entry '{key}' TU value is not a well-formed ISO 32000-1 date string.";

                    return false;
                }

                timeUpdated = parsedTimeUpdated;
            }

            PkiCertificateMemory? timeStampToken = null;
            if(vriValue.Entries.TryGetValue("TS", out PdfValue tsReference))
            {
                if(tsReference.Kind != PdfValueKind.Reference)
                {
                    DisposeAll(certs);
                    DisposeAll(crls);
                    DisposeAll(ocsps);
                    error = $"The VRI entry '{key}' TS entry is not an indirect reference.";

                    return false;
                }

                if(!PdfByteSurfaceReader.TryResolveObject(s, objectOffsets, tsReference.Number, out PdfValue tsValue, out error))
                {
                    DisposeAll(certs);
                    DisposeAll(crls);
                    DisposeAll(ocsps);

                    return false;
                }

                if(tsValue.Kind != PdfValueKind.Stream)
                {
                    DisposeAll(certs);
                    DisposeAll(crls);
                    DisposeAll(ocsps);
                    error = $"The VRI entry '{key}' TS entry does not resolve to a stream (PA-5.4.2.3-12).";

                    return false;
                }

                timeStampToken = CopyStreamToCarrier(s, tsValue, PkiCertificateTags.TimestampToken, pool);
            }

            vriEntries[key] = new PdfVriDictionary(certs, crls, ocsps, timeUpdated, timeStampToken);
        }

        return true;
    }


    /// <summary>Copies a stream object's own data into a pooled, tagged carrier.</summary>
    private static PkiCertificateMemory CopyStreamToCarrier(ReadOnlySpan<byte> s, PdfValue streamValue, Tag tag, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> data = s.Slice(streamValue.StreamDataStart, streamValue.StreamDataLength);
        IMemoryOwner<byte> owner = pool.Rent(data.Length);
        try
        {
            data.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, tag);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    private static void DisposeAll(List<PkiCertificateMemory>? items)
    {
        if(items is null)
        {
            return;
        }

        for(int i = 0; i < items.Count; ++i)
        {
            items[i].Dispose();
        }
    }
}
