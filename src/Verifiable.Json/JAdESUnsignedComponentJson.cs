using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Json;

/// <summary>
/// The JSON codec for the JAdES shared-syntax and component MODELS (<c>Verifiable.Cryptography.Pki</c>) that
/// both the JWS Protected Header codec (<see cref="JAdESProtectedHeaderJson"/>) and the <c>etsiU</c> codec
/// (<see cref="JAdESEtsiUJson"/>) compose, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see> (concrete JSON encodings live in
/// <c>Verifiable.Json</c>).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Decode never escapes an exception on its own; the callers do.</strong> Every <c>Decode*</c> method
/// here throws naturally (<see cref="JsonException"/> from a wrong-shaped <see cref="JsonElement"/> access,
/// <see cref="FormatException"/> for a hand-checked structural violation, <see cref="ArgumentException"/> from a
/// Pki model constructor's own invariant) rather than swallowing anything locally — <see cref="JAdESProtectedHeaderJson"/>
/// and <see cref="JAdESEtsiUJson"/> each wrap their OWN single call tree in one try/catch (mirroring
/// <c>CBAdESSignatureSerialization</c>'s "every failure path... funnel through the one catch clause"
/// convention), so the fail-closed contract (contract IRON RULES) is honored at the public delegate boundary,
/// not re-implemented in every nested helper.
/// </para>
/// <para>
/// <strong>Encode never needs a memory pool.</strong> Every <c>Encode*</c> method here projects an
/// already-built Pki model onto a plain <c>Dictionary&lt;string, object&gt;</c>/<c>List&lt;object&gt;</c>/
/// primitive object graph — the shape <see cref="Converters.DictionaryStringObjectJsonConverter"/> already knows
/// how to write (including a <see cref="JsonElement"/> value passed through verbatim for an opaque member) — so
/// no new buffer is ever rented on the encode side.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "Every Decode* method here mints a disposable Pki-model carrier (DigestValue/PooledMemory-owning record) whose ownership transfers into the caller's returned aggregate (JAdESProtectedHeaderJson/JAdESEtsiUJson's own public entry points) — the ultimate caller of THOSE delegates owns and disposes the whole tree, mirroring CBAdESSignatureSerialization's identical class-level suppression for the same ownership-transfer chain.")]
internal static class JAdESUnsignedComponentJson
{
    /// <summary>Decodes the <c>oId</c> shared-syntax type (clause 5.4.1).</summary>
    public static AdESObjectIdentifier DecodeObjectIdentifier(JsonElement obj)
    {
        string id = obj.GetProperty(JAdESWireNames.ObjectIdentifierId).GetString()
            ?? throw new FormatException("oId.id is required.");

        string? desc = obj.TryGetProperty(JAdESWireNames.ObjectIdentifierDesc, out JsonElement descEl)
            ? descEl.GetString()
            : null;

        List<Uri>? docRefs = null;
        if(obj.TryGetProperty(JAdESWireNames.ObjectIdentifierDocRefs, out JsonElement docRefsEl))
        {
            docRefs = [];
            foreach(JsonElement item in docRefsEl.EnumerateArray())
            {
                docRefs.Add(new Uri(item.GetString() ?? throw new FormatException("oId.docRefs element must be a string.")));
            }
        }

        return new AdESObjectIdentifier(id, desc, docRefs);
    }


    /// <summary>Encodes the <c>oId</c> shared-syntax type (clause 5.4.1).</summary>
    public static Dictionary<string, object> EncodeObjectIdentifier(AdESObjectIdentifier value)
    {
        var result = new Dictionary<string, object> { [JAdESWireNames.ObjectIdentifierId] = value.Id };
        SetIfNotNull(result, JAdESWireNames.ObjectIdentifierDesc, value.Desc);

        if(value.DocRefs is not null)
        {
            result[JAdESWireNames.ObjectIdentifierDocRefs] = value.DocRefs.Select(static uri => (object)uri.OriginalString).ToList();
        }

        return result;
    }


    /// <summary>Decodes the <c>pkiOb</c> shared-syntax type (clause 5.4.2).</summary>
    public static AdESPkiObject DecodePkiObject(JsonElement obj)
    {
        byte[] val = obj.GetProperty(JAdESWireNames.PkiObjectVal).GetBytesFromBase64();
        string? encoding = obj.TryGetProperty(JAdESWireNames.PkiObjectEncoding, out JsonElement encodingEl) ? encodingEl.GetString() : null;
        string? specRef = obj.TryGetProperty(JAdESWireNames.PkiObjectSpecRef, out JsonElement specRefEl) ? specRefEl.GetString() : null;

        return new AdESPkiObject { Val = val, Encoding = encoding, SpecRef = specRef };
    }


    /// <summary>Encodes the <c>pkiOb</c> shared-syntax type (clause 5.4.2).</summary>
    public static Dictionary<string, object> EncodePkiObject(AdESPkiObject value)
    {
        var result = new Dictionary<string, object> { [JAdESWireNames.PkiObjectVal] = Convert.ToBase64String(value.Val.Span) };
        SetIfNotNull(result, JAdESWireNames.PkiObjectEncoding, value.Encoding);
        SetIfNotNull(result, JAdESWireNames.PkiObjectSpecRef, value.SpecRef);

        return result;
    }


    /// <summary>Decodes the <c>tstToken</c> shared-syntax type (clause 5.4.3.3).</summary>
    public static AdESTimestampToken DecodeTimestampToken(JsonElement obj)
    {
        byte[] val = obj.GetProperty(JAdESWireNames.TimestampTokenVal).GetBytesFromBase64();
        string? type = obj.TryGetProperty(JAdESWireNames.TimestampTokenType, out JsonElement typeEl) ? typeEl.GetString() : null;
        string? encoding = obj.TryGetProperty(JAdESWireNames.TimestampTokenEncoding, out JsonElement encodingEl) ? encodingEl.GetString() : null;
        string? specRef = obj.TryGetProperty(JAdESWireNames.TimestampTokenSpecRef, out JsonElement specRefEl) ? specRefEl.GetString() : null;

        return new AdESTimestampToken { Val = val, Type = type, Encoding = encoding, SpecRef = specRef };
    }


    /// <summary>Encodes the <c>tstToken</c> shared-syntax type (clause 5.4.3.3).</summary>
    public static Dictionary<string, object> EncodeTimestampToken(AdESTimestampToken value)
    {
        var result = new Dictionary<string, object> { [JAdESWireNames.TimestampTokenVal] = Convert.ToBase64String(value.Val.Span) };
        SetIfNotNull(result, JAdESWireNames.TimestampTokenType, value.Type);
        SetIfNotNull(result, JAdESWireNames.TimestampTokenEncoding, value.Encoding);
        SetIfNotNull(result, JAdESWireNames.TimestampTokenSpecRef, value.SpecRef);

        return result;
    }


    /// <summary>Decodes the <c>tstContainer</c> shared-syntax type (clause 5.4.3.3).</summary>
    public static AdESTimestampContainer DecodeTimestampContainer(JsonElement obj)
    {
        var tokens = new List<AdESTimestampToken>();
        foreach(JsonElement item in obj.GetProperty(JAdESWireNames.TimestampContainerTstTokens).EnumerateArray())
        {
            tokens.Add(DecodeTimestampToken(item));
        }

        string? canonAlg = obj.TryGetProperty(JAdESWireNames.TimestampContainerCanonAlg, out JsonElement canonAlgEl)
            ? canonAlgEl.GetString()
            : null;

        return new AdESTimestampContainer(tokens, canonAlg);
    }


    /// <summary>Encodes the <c>tstContainer</c> shared-syntax type (clause 5.4.3.3).</summary>
    public static Dictionary<string, object> EncodeTimestampContainer(AdESTimestampContainer value)
    {
        var result = new Dictionary<string, object>
        {
            [JAdESWireNames.TimestampContainerTstTokens] = value.TstTokens.Select(EncodeTimestampToken).Cast<object>().ToList()
        };
        SetIfNotNull(result, JAdESWireNames.TimestampContainerCanonAlg, value.CanonAlg);

        return result;
    }


    /// <summary>Decodes the <c>x5t#o</c>-shaped digest-reference object (clause 5.2.2.2; also Annex A's <c>CertId</c> core).</summary>
    public static AdESCertificateThumbprint DecodeCertificateThumbprint(JsonElement obj, BaseMemoryPool pool)
    {
        string hashAlgorithm = obj.GetProperty(JAdESWireNames.CertificateThumbprintHashAlgorithm).GetString()
            ?? throw new FormatException("x5t#o.digAlg is required.");
        byte[] digestBytes = obj.GetProperty(JAdESWireNames.CertificateThumbprintDigest).GetBytesFromBase64();

        return new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier(hashAlgorithm), CreateDigestValue(digestBytes, hashAlgorithm, pool));
    }


    /// <summary>Encodes the <c>x5t#o</c>-shaped digest-reference object.</summary>
    public static Dictionary<string, object> EncodeCertificateThumbprint(AdESCertificateThumbprint value) => new()
    {
        [JAdESWireNames.CertificateThumbprintHashAlgorithm] = EncodeDigestAlgorithmIdentifier(value.HashAlgorithm),
        [JAdESWireNames.CertificateThumbprintDigest] = Convert.ToBase64String(value.Digest.AsReadOnlySpan())
    };


    /// <summary>Decodes the <c>sigPSt</c> unsigned component (clause 5.3.3).</summary>
    public static JAdESSignaturePolicyStore DecodeSignaturePolicyStore(JsonElement obj, BaseMemoryPool pool)
    {
        JAdESSignaturePolicyStoreContent content;
        if(obj.TryGetProperty(JAdESSignaturePolicyStore.SigPolDocMemberName, out JsonElement docEl))
        {
            byte[] document = docEl.GetBytesFromBase64();
            content = new JAdESSignaturePolicyStoreDocument(PooledMemory.FromBytes(document, pool, CryptoTags.JAdESSignaturePolicyDocument));
        }
        else if(obj.TryGetProperty(JAdESSignaturePolicyStore.SigPolLocalUriMemberName, out JsonElement uriEl))
        {
            content = new JAdESSignaturePolicyStoreLocalUri(new Uri(uriEl.GetString() ?? throw new FormatException("sigPSt.sigPolLocalURI must be a string.")));
        }
        else
        {
            throw new FormatException("sigPSt shall contain either sigPolDoc or sigPolLocalURI (ETSI TS 119 182-1 V1.2.1, clause 5.3.3, JA-5.3.3-01).");
        }

        try
        {
            AdESObjectIdentifier? spDSpec = obj.TryGetProperty(JAdESSignaturePolicyStore.SpDSpecMemberName, out JsonElement spDSpecEl)
                ? DecodeObjectIdentifier(spDSpecEl)
                : null;

            return new JAdESSignaturePolicyStore(content, spDSpec);
        }
        catch
        {
            //content may already own a pooled PooledMemory (the sigPolDoc arm) even though spDSpec's own decode
            //is what threw -- dispose it here rather than leaking it, mirroring this file's other accumulating
            //decode paths.
            (content as IDisposable)?.Dispose();

            throw;
        }
    }


    /// <summary>Encodes the <c>sigPSt</c> unsigned component (clause 5.3.3).</summary>
    public static Dictionary<string, object> EncodeSignaturePolicyStore(JAdESSignaturePolicyStore value)
    {
        var result = new Dictionary<string, object>();
        switch(value.Content)
        {
            case JAdESSignaturePolicyStoreDocument document:
                result[JAdESSignaturePolicyStore.SigPolDocMemberName] = Convert.ToBase64String(document.Document.AsReadOnlySpan());
                break;

            case JAdESSignaturePolicyStoreLocalUri localUri:
                result[JAdESSignaturePolicyStore.SigPolLocalUriMemberName] = localUri.Location.OriginalString;
                break;
        }

        if(value.SpDSpec is not null)
        {
            result[JAdESSignaturePolicyStore.SpDSpecMemberName] = EncodeObjectIdentifier(value.SpDSpec);
        }

        return result;
    }


    /// <summary>Decodes the <c>xVals</c>/<c>axVals</c> shared JSON-array shape (clause 5.3.5.2).</summary>
    public static JAdESCertificateValues DecodeCertificateValues(JsonElement array)
    {
        var items = new List<JAdESCertificateChoice>();
        foreach(JsonElement item in array.EnumerateArray())
        {
            if(item.TryGetProperty(JAdESCertificateChoice.X509CertMemberName, out JsonElement x509El))
            {
                items.Add(new JAdESX509Certificate(DecodePkiObject(x509El)));
            }
            else if(item.TryGetProperty(JAdESCertificateChoice.OtherCertMemberName, out JsonElement otherEl))
            {
                items.Add(new JAdESOtherCertificate(DecodePkiObject(otherEl)));
            }
            else
            {
                throw new FormatException("xVals item shall contain either x509Cert or otherCert (ETSI TS 119 182-1 V1.2.1, clause 5.3.5.2).");
            }
        }

        return new JAdESCertificateValues(items);
    }


    /// <summary>Encodes the <c>xVals</c>/<c>axVals</c> shared JSON-array shape (clause 5.3.5.2).</summary>
    public static List<object> EncodeCertificateValues(JAdESCertificateValues value) =>
        value.Items.Select(static item => (object)(item switch
        {
            JAdESX509Certificate x509 => new Dictionary<string, object> { [JAdESCertificateChoice.X509CertMemberName] = EncodePkiObject(x509.Certificate) },
            JAdESOtherCertificate other => new Dictionary<string, object> { [JAdESCertificateChoice.OtherCertMemberName] = EncodePkiObject(other.Certificate) },
            _ => throw new NotSupportedException($"Unknown certificate choice arm '{item.GetType()}'.")
        })).ToList();


    /// <summary>Decodes the <c>rVals</c>/<c>arVals</c> shared JSON-object shape (clause 5.3.5.3).</summary>
    public static JAdESRevocationValues DecodeRevocationValues(JsonElement obj)
    {
        List<AdESPkiObject>? crlValues = DecodeOptionalPkiObjectArray(obj, JAdESRevocationValues.CrlValsMemberName);
        List<AdESPkiObject>? ocspValues = DecodeOptionalPkiObjectArray(obj, JAdESRevocationValues.OcspValsMemberName);
        List<AdESPkiObject>? otherValues = DecodeOptionalPkiObjectArray(obj, JAdESRevocationValues.OtherValsMemberName);

        return new JAdESRevocationValues(crlValues, ocspValues, otherValues);
    }


    /// <summary>Encodes the <c>rVals</c>/<c>arVals</c> shared JSON-object shape (clause 5.3.5.3).</summary>
    public static Dictionary<string, object> EncodeRevocationValues(JAdESRevocationValues value)
    {
        var result = new Dictionary<string, object>();
        SetPkiObjectArrayIfNotNull(result, JAdESRevocationValues.CrlValsMemberName, value.CrlValues);
        SetPkiObjectArrayIfNotNull(result, JAdESRevocationValues.OcspValsMemberName, value.OcspValues);
        SetPkiObjectArrayIfNotNull(result, JAdESRevocationValues.OtherValsMemberName, value.OtherValues);

        return result;
    }


    /// <summary>Decodes the <c>validationVals</c> shared JSON-object shape (<c>anyValData</c>/<c>tstVD</c>).</summary>
    public static JAdESValidationData DecodeValidationData(JsonElement obj)
    {
        JAdESCertificateValues? certificateValues = obj.TryGetProperty(JAdESValidationData.XValsMemberName, out JsonElement xValsEl)
            ? DecodeCertificateValues(xValsEl)
            : null;

        JAdESRevocationValues? revocationValues = obj.TryGetProperty(JAdESValidationData.RValsMemberName, out JsonElement rValsEl)
            ? DecodeRevocationValues(rValsEl)
            : null;

        return new JAdESValidationData(certificateValues, revocationValues);
    }


    /// <summary>Encodes the <c>validationVals</c> shared JSON-object shape (<c>anyValData</c>/<c>tstVD</c>).</summary>
    public static Dictionary<string, object> EncodeValidationData(JAdESValidationData value)
    {
        var result = new Dictionary<string, object>();
        if(value.CertificateValues is not null)
        {
            result[JAdESValidationData.XValsMemberName] = EncodeCertificateValues(value.CertificateValues);
        }

        if(value.RevocationValues is not null)
        {
            result[JAdESValidationData.RValsMemberName] = EncodeRevocationValues(value.RevocationValues);
        }

        return result;
    }


    /// <summary>Decodes the <c>x5Ids</c> shared JSON-array shape (Annex A.1.1's <c>xRefs</c>/A.1.3's <c>axRefs</c>).</summary>
    public static JAdESCertificateReferenceCollection DecodeCertificateReferenceCollection(JsonElement array, BaseMemoryPool pool)
    {
        var items = new List<AdESCertificateThumbprint>();
        try
        {
            foreach(JsonElement item in array.EnumerateArray())
            {
                items.Add(DecodeCertificateThumbprint(item, pool));
            }
        }
        catch
        {
            foreach(AdESCertificateThumbprint thumbprint in items)
            {
                thumbprint.Dispose();
            }

            throw;
        }

        return new JAdESCertificateReferenceCollection(items);
    }


    /// <summary>Encodes the <c>x5Ids</c> shared JSON-array shape.</summary>
    public static List<object> EncodeCertificateReferenceCollection(JAdESCertificateReferenceCollection value) =>
        value.Items.Select(static item => (object)EncodeCertificateThumbprint(item)).ToList();


    /// <summary>Decodes the <c>rRefs</c> shared JSON-object shape (Annex A.1.2's <c>rRefs</c>/A.1.4's <c>arRefs</c>).</summary>
    public static JAdESRevocationReferenceCollection DecodeRevocationReferenceCollection(JsonElement obj, BaseMemoryPool pool)
    {
        //All three loops run inside one guard: a later loop's throw (ocspRefs/otherRefs) must not leak the
        //pooled digests an earlier loop (crlRefs/ocspRefs) already accumulated, mirroring
        //DecodeDetachedDataObjectReference's identical accumulating-loop dispose-on-throw discipline.
        List<AdESCertificateThumbprint>? crlReferences = null;
        List<AdESCertificateThumbprint>? ocspReferences = null;
        try
        {
            if(obj.TryGetProperty("crlRefs", out JsonElement crlEl))
            {
                crlReferences = [];
                foreach(JsonElement item in crlEl.EnumerateArray())
                {
                    crlReferences.Add(DecodeCertificateThumbprint(item, pool));
                }
            }

            if(obj.TryGetProperty("ocspRefs", out JsonElement ocspEl))
            {
                ocspReferences = [];
                foreach(JsonElement item in ocspEl.EnumerateArray())
                {
                    ocspReferences.Add(DecodeCertificateThumbprint(item, pool));
                }
            }

            List<ReadOnlyMemory<byte>>? otherReferences = null;
            if(obj.TryGetProperty("otherRefs", out JsonElement otherEl))
            {
                otherReferences = [];
                foreach(JsonElement item in otherEl.EnumerateArray())
                {
                    otherReferences.Add(item.GetBytesFromBase64());
                }
            }

            return new JAdESRevocationReferenceCollection(crlReferences, ocspReferences, otherReferences);
        }
        catch
        {
            if(crlReferences is not null)
            {
                foreach(AdESCertificateThumbprint thumbprint in crlReferences)
                {
                    thumbprint.Dispose();
                }
            }

            if(ocspReferences is not null)
            {
                foreach(AdESCertificateThumbprint thumbprint in ocspReferences)
                {
                    thumbprint.Dispose();
                }
            }

            throw;
        }
    }


    /// <summary>Encodes the <c>rRefs</c> shared JSON-object shape.</summary>
    public static Dictionary<string, object> EncodeRevocationReferenceCollection(JAdESRevocationReferenceCollection value)
    {
        var result = new Dictionary<string, object>();
        if(value.CrlReferences.Count > 0)
        {
            result["crlRefs"] = value.CrlReferences.Select(static item => (object)EncodeCertificateThumbprint(item)).ToList();
        }

        if(value.OcspReferences.Count > 0)
        {
            result["ocspRefs"] = value.OcspReferences.Select(static item => (object)EncodeCertificateThumbprint(item)).ToList();
        }

        if(value.OtherReferences.Count > 0)
        {
            result["otherRefs"] = value.OtherReferences.Select(static item => (object)Convert.ToBase64String(item.Span)).ToList();
        }

        return result;
    }


    /// <summary>Decodes the <c>srCms</c> signed header parameter's own JSON-array value (clause 5.2.3).</summary>
    public static AdESSignerCommitments DecodeSignerCommitments(JsonElement array)
    {
        var commitments = new List<AdESCommitment>();
        foreach(JsonElement item in array.EnumerateArray())
        {
            AdESObjectIdentifier commitmentId = DecodeObjectIdentifier(item.GetProperty(JAdESWireNames.SignerCommitmentsCommitmentId));

            List<object>? qualifiers = null;
            if(item.TryGetProperty(JAdESWireNames.SignerCommitmentsCommitmentQualifiers, out JsonElement qualsEl))
            {
                qualifiers = [];
                foreach(JsonElement qual in qualsEl.EnumerateArray())
                {
                    qualifiers.Add(qual.Clone());
                }
            }

            commitments.Add(new AdESCommitment(commitmentId, qualifiers));
        }

        return new AdESSignerCommitments(commitments);
    }


    /// <summary>Encodes the <c>srCms</c> signed header parameter's own JSON-array value (clause 5.2.3).</summary>
    public static List<object> EncodeSignerCommitments(AdESSignerCommitments value) =>
        value.Commitments.Select(static commitment =>
        {
            var entry = new Dictionary<string, object>
            {
                [JAdESWireNames.SignerCommitmentsCommitmentId] = EncodeObjectIdentifier(commitment.CommitmentId)
            };

            if(commitment.CommitmentQualifiers is not null)
            {
                entry[JAdESWireNames.SignerCommitmentsCommitmentQualifiers] = commitment.CommitmentQualifiers.ToList();
            }

            return (object)entry;
        }).ToList();


    /// <summary>Decodes the <c>sigPl</c> signed header parameter (clause 5.2.4).</summary>
    public static AdESSignatureProductionPlace DecodeSignatureProductionPlace(JsonElement obj) => new()
    {
        AddressCountry = GetStringOrNull(obj, JAdESWireNames.SignatureProductionPlaceAddressCountry),
        AddressLocality = GetStringOrNull(obj, JAdESWireNames.SignatureProductionPlaceAddressLocality),
        AddressRegion = GetStringOrNull(obj, JAdESWireNames.SignatureProductionPlaceAddressRegion),
        PostOfficeBoxNumber = GetStringOrNull(obj, JAdESWireNames.SignatureProductionPlacePostOfficeBoxNumber),
        PostalCode = GetStringOrNull(obj, JAdESWireNames.SignatureProductionPlacePostalCode),
        StreetAddress = GetStringOrNull(obj, JAdESWireNames.SignatureProductionPlaceStreetAddress)
    };


    /// <summary>Encodes the <c>sigPl</c> signed header parameter (clause 5.2.4).</summary>
    public static Dictionary<string, object> EncodeSignatureProductionPlace(AdESSignatureProductionPlace value)
    {
        var result = new Dictionary<string, object>();
        SetIfNotNull(result, JAdESWireNames.SignatureProductionPlaceAddressCountry, value.AddressCountry);
        SetIfNotNull(result, JAdESWireNames.SignatureProductionPlaceAddressLocality, value.AddressLocality);
        SetIfNotNull(result, JAdESWireNames.SignatureProductionPlaceAddressRegion, value.AddressRegion);
        SetIfNotNull(result, JAdESWireNames.SignatureProductionPlacePostOfficeBoxNumber, value.PostOfficeBoxNumber);
        SetIfNotNull(result, JAdESWireNames.SignatureProductionPlacePostalCode, value.PostalCode);
        SetIfNotNull(result, JAdESWireNames.SignatureProductionPlaceStreetAddress, value.StreetAddress);

        return result;
    }


    /// <summary>Decodes the <c>srAts</c> signed header parameter (clause 5.2.5).</summary>
    public static AdESSignerAttributes DecodeSignerAttributes(JsonElement obj)
    {
        List<AdESCertifiedAttribute>? certified = null;
        if(obj.TryGetProperty(JAdESWireNames.SignerAttributesCertified, out JsonElement certifiedEl))
        {
            certified = [];
            foreach(JsonElement item in certifiedEl.EnumerateArray())
            {
                if(item.TryGetProperty(JAdESWireNames.CertifiedAttributeX509AttrCert, out JsonElement x509El))
                {
                    certified.Add(new AdESX509AttributeCertificate(DecodePkiObject(x509El)));
                }
                else if(item.TryGetProperty(JAdESWireNames.CertifiedAttributeOtherAttrCert, out JsonElement otherEl))
                {
                    certified.Add(new AdESOtherAttributeCertificate(DecodePkiObject(otherEl)));
                }
                else
                {
                    throw new FormatException("certifiedAttrs item shall contain either x509AttrCert or otherAttrCert (ETSI TS 119 182-1 V1.2.1, clause 5.2.5).");
                }
            }
        }

        return new AdESSignerAttributes(
            certified,
            DecodeOptionalQualifyingAttributeArray(obj, JAdESWireNames.SignerAttributesSignedAssertions),
            DecodeOptionalQualifyingAttributeArray(obj, JAdESWireNames.SignerAttributesClaimed));
    }


    /// <summary>Encodes the <c>srAts</c> signed header parameter (clause 5.2.5).</summary>
    public static Dictionary<string, object> EncodeSignerAttributes(AdESSignerAttributes value)
    {
        var result = new Dictionary<string, object>();
        if(value.Certified is not null)
        {
            result[JAdESWireNames.SignerAttributesCertified] = value.Certified.Select(static item => (object)(item switch
            {
                AdESX509AttributeCertificate x509 => new Dictionary<string, object> { [JAdESWireNames.CertifiedAttributeX509AttrCert] = EncodePkiObject(x509.Certificate) },
                AdESOtherAttributeCertificate other => new Dictionary<string, object> { [JAdESWireNames.CertifiedAttributeOtherAttrCert] = EncodePkiObject(other.Certificate) },
                _ => throw new NotSupportedException($"Unknown certifiedAttrs arm '{item.GetType()}'.")
            })).ToList();
        }

        if(value.SignedAssertions is not null)
        {
            result[JAdESWireNames.SignerAttributesSignedAssertions] = value.SignedAssertions.Select(static item => (object)EncodeQualifyingAttribute((JAdESQualifyingAttribute)item)).ToList();
        }

        if(value.Claimed is not null)
        {
            result[JAdESWireNames.SignerAttributesClaimed] = value.Claimed.Select(static item => (object)EncodeQualifyingAttribute((JAdESQualifyingAttribute)item)).ToList();
        }

        return result;
    }


    /// <summary>Decodes the <c>sigPId</c> signed header parameter (clause 5.2.7.1).</summary>
    public static AdESSignaturePolicyIdentifier DecodeSignaturePolicyIdentifier(JsonElement obj, BaseMemoryPool pool)
    {
        AdESObjectIdentifier id = DecodeObjectIdentifier(obj.GetProperty(JAdESWireNames.SignaturePolicyIdentifierId));
        string? hashAlgorithm = obj.TryGetProperty(JAdESWireNames.SignaturePolicyIdentifierHashAlgorithm, out JsonElement hashAlgEl)
            ? hashAlgEl.GetString()
            : null;

        DigestValue? digest = null;
        try
        {
            if(obj.TryGetProperty(JAdESWireNames.SignaturePolicyIdentifierDigest, out JsonElement digestEl))
            {
                digest = CreateDigestValue(digestEl.GetBytesFromBase64(), hashAlgorithm, pool);
            }

            bool digestIsPerSpecification = obj.TryGetProperty(JAdESWireNames.SignaturePolicyIdentifierDigestIsPerSpecification, out JsonElement digPSpEl)
                && digPSpEl.GetBoolean();

            List<AdESSignaturePolicyQualifier>? qualifiers = null;
            if(obj.TryGetProperty(JAdESWireNames.SignaturePolicyIdentifierQualifiers, out JsonElement qualsEl))
            {
                qualifiers = [];
                foreach(JsonElement item in qualsEl.EnumerateArray())
                {
                    qualifiers.Add(DecodeSignaturePolicyQualifier(item));
                }
            }

            return new AdESSignaturePolicyIdentifier(
                id,
                hashAlgorithm is not null ? new AdESDigestAlgorithmTextIdentifier(hashAlgorithm) : null,
                digest,
                digestIsPerSpecification,
                qualifiers);
        }
        catch
        {
            //digest may already be a rented pooled DigestValue even though a LATER member (qualifiers) is what
            //threw -- dispose it here rather than leaking it.
            digest?.Dispose();

            throw;
        }
    }


    /// <summary>Encodes the <c>sigPId</c> signed header parameter (clause 5.2.7.1).</summary>
    public static Dictionary<string, object> EncodeSignaturePolicyIdentifier(AdESSignaturePolicyIdentifier value)
    {
        var result = new Dictionary<string, object> { [JAdESWireNames.SignaturePolicyIdentifierId] = EncodeObjectIdentifier(value.Id) };
        if(value.HashAlgorithm is not null)
        {
            result[JAdESWireNames.SignaturePolicyIdentifierHashAlgorithm] = EncodeDigestAlgorithmIdentifier(value.HashAlgorithm);
        }

        if(value.Digest is not null)
        {
            result[JAdESWireNames.SignaturePolicyIdentifierDigest] = Convert.ToBase64String(value.Digest.AsReadOnlySpan());
        }

        if(value.DigestIsPerSpecification)
        {
            result[JAdESWireNames.SignaturePolicyIdentifierDigestIsPerSpecification] = true;
        }

        if(value.Qualifiers is not null)
        {
            result[JAdESWireNames.SignaturePolicyIdentifierQualifiers] = value.Qualifiers.Select(static q => (object)EncodeSignaturePolicyQualifier(q)).ToList();
        }

        return result;
    }


    /// <summary>Decodes the <c>sigD</c> signed header parameter (clause 5.2.8.1).</summary>
    public static JAdESDetachedDataObjectReference DecodeDetachedDataObjectReference(JsonElement obj, BaseMemoryPool pool)
    {
        string mechanismId = obj.GetProperty(JAdESDetachedDataObjectReference.MechanismIdentifierMemberName).GetString()
            ?? throw new FormatException("sigD.mId is required.");

        var pars = new List<string>();
        foreach(JsonElement item in obj.GetProperty(JAdESDetachedDataObjectReference.ReferencesMemberName).EnumerateArray())
        {
            pars.Add(item.GetString() ?? throw new FormatException("sigD.pars element must be a string."));
        }

        if(JAdESDetachedMechanisms.IsHttpHeaders(mechanismId))
        {
            return new JAdESHttpHeadersReference(pars);
        }

        string? hashM = obj.TryGetProperty(JAdESDetachedDataObjectReference.HashAlgorithmMemberName, out JsonElement hashMEl)
            ? hashMEl.GetString()
            : null;

        List<byte[]>? hashV = null;
        if(obj.TryGetProperty(JAdESDetachedDataObjectReference.DigestsMemberName, out JsonElement hashVEl))
        {
            hashV = [];
            foreach(JsonElement item in hashVEl.EnumerateArray())
            {
                hashV.Add(item.GetBytesFromBase64());
            }

            if(hashV.Count != pars.Count)
            {
                throw new FormatException("sigD.hashV shall carry one entry per sigD.pars entry (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1, JA-5.2.8.1-21).");
            }
        }

        List<string?>? ctys = null;
        if(obj.TryGetProperty(JAdESDetachedDataObjectReference.ContentTypesMemberName, out JsonElement ctysEl))
        {
            ctys = [];
            foreach(JsonElement item in ctysEl.EnumerateArray())
            {
                ctys.Add(item.ValueKind == JsonValueKind.Null ? null : item.GetString());
            }

            if(ctys.Count != pars.Count)
            {
                throw new FormatException("sigD.ctys shall carry one entry per sigD.pars entry (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1, JA-5.2.8.1-27).");
            }
        }

        var references = new List<JAdESReferencedDataObject>(pars.Count);
        try
        {
            for(int i = 0; i < pars.Count; ++i)
            {
                DigestValue? digest = hashV is not null ? CreateDigestValue(hashV[i], hashM, pool) : null;
                try
                {
                    references.Add(new JAdESReferencedDataObject(pars[i], ctys?[i], digest));
                }
                catch
                {
                    //digest was already rented from the pool but JAdESReferencedDataObject's own constructor
                    //(the pars[i]-non-empty guard) rejected it before it could be added to `references` --
                    //without this, the loose digest would never reach the outer catch's disposal of
                    //`references`, since it never made it into that list.
                    digest?.Dispose();
                    throw;
                }
            }

            if(JAdESDetachedMechanisms.IsObjectIdByUri(mechanismId))
            {
                return new JAdESObjectIdByUriReference(references);
            }

            if(JAdESDetachedMechanisms.IsObjectIdByUriHash(mechanismId))
            {
                return new JAdESObjectIdByUriHashReference(
                    hashM ?? throw new FormatException("ObjectIdByURIHash requires hashM (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.3.3, JA-5.2.8.3.3-02)."),
                    references);
            }

            return new JAdESUnknownDetachedDataObjectReference(mechanismId, references, hashM);
        }
        catch
        {
            foreach(JAdESReferencedDataObject reference in references)
            {
                reference.Dispose();
            }

            throw;
        }
    }


    /// <summary>Encodes the <c>sigD</c> signed header parameter (clause 5.2.8.1).</summary>
    public static Dictionary<string, object> EncodeDetachedDataObjectReference(JAdESDetachedDataObjectReference value)
    {
        return value switch
        {
            JAdESHttpHeadersReference httpHeaders => new Dictionary<string, object>
            {
                [JAdESDetachedDataObjectReference.MechanismIdentifierMemberName] = JAdESHttpHeadersReference.MechanismIdentifier,
                [JAdESDetachedDataObjectReference.ReferencesMemberName] = httpHeaders.HeaderNames.Cast<object>().ToList()
            },
            JAdESObjectIdByUriReference objectIdByUri => EncodeReferencedObjects(JAdESObjectIdByUriReference.MechanismIdentifier, null, objectIdByUri.References),
            JAdESObjectIdByUriHashReference objectIdByUriHash => EncodeReferencedObjects(JAdESObjectIdByUriHashReference.MechanismIdentifier, objectIdByUriHash.HashAlgorithm, objectIdByUriHash.References),
            JAdESUnknownDetachedDataObjectReference unknown => EncodeReferencedObjects(unknown.MechanismIdentifier, unknown.HashAlgorithm, unknown.References),
            _ => throw new NotSupportedException($"Unknown sigD arm '{value.GetType()}'.")
        };

        static Dictionary<string, object> EncodeReferencedObjects(string mechanismId, string? hashAlgorithm, IReadOnlyList<JAdESReferencedDataObject> references)
        {
            var result = new Dictionary<string, object>
            {
                [JAdESDetachedDataObjectReference.MechanismIdentifierMemberName] = mechanismId,
                [JAdESDetachedDataObjectReference.ReferencesMemberName] = references.Select(static r => (object)r.Reference).ToList()
            };
            SetIfNotNull(result, JAdESDetachedDataObjectReference.HashAlgorithmMemberName, hashAlgorithm);

            if(references.Any(static r => r.Digest is not null))
            {
                var digests = new List<object>(references.Count);
                foreach(JAdESReferencedDataObject reference in references)
                {
                    digests.Add(reference.Digest is null ? null! : Convert.ToBase64String(reference.Digest.AsReadOnlySpan()));
                }

                result[JAdESDetachedDataObjectReference.DigestsMemberName] = digests;
            }

            if(references.Any(static r => r.ContentType is not null))
            {
                var contentTypes = new List<object>(references.Count);
                foreach(JAdESReferencedDataObject reference in references)
                {
                    contentTypes.Add(reference.ContentType is null ? null! : reference.ContentType);
                }

                result[JAdESDetachedDataObjectReference.ContentTypesMemberName] = contentTypes;
            }

            return result;
        }
    }


    private static AdESSignaturePolicyQualifier DecodeSignaturePolicyQualifier(JsonElement obj)
    {
        if(obj.TryGetProperty(JAdESWireNames.SignaturePolicyQualifierSpUri, out JsonElement spUriEl))
        {
            return new AdESSignaturePolicyUri(spUriEl.GetString() ?? throw new FormatException("sigPQual.spURI must be a string."));
        }

        if(obj.TryGetProperty(JAdESWireNames.SignaturePolicyQualifierSpUserNotice, out JsonElement noticeEl))
        {
            AdESSignaturePolicyNoticeReference? noticeRef = null;
            if(noticeEl.TryGetProperty(JAdESWireNames.SignaturePolicyUserNoticeNoticeReference, out JsonElement noticeRefEl))
            {
                string organization = noticeRefEl.GetProperty(JAdESWireNames.SignaturePolicyNoticeReferenceOrganization).GetString()
                    ?? throw new FormatException("noticeRef.organization is required.");
                var noticeNumbers = new List<uint>();
                foreach(JsonElement number in noticeRefEl.GetProperty(JAdESWireNames.SignaturePolicyNoticeReferenceNoticeNumbers).EnumerateArray())
                {
                    int rawNumber = number.GetInt32();
                    if(rawNumber < 0)
                    {
                        throw new FormatException(
                            "noticeRef.noticeNumbers entries shall be positive integers identifying the " +
                            "referenced organization's notices (ETSI TS 119 182-1 V1.2.1, clause 5.2.7.2).");
                    }

                    noticeNumbers.Add((uint)rawNumber);
                }

                noticeRef = new AdESSignaturePolicyNoticeReference(organization, noticeNumbers);
            }

            string? explicitText = noticeEl.TryGetProperty(JAdESWireNames.SignaturePolicyUserNoticeExplicitText, out JsonElement explTextEl)
                ? explTextEl.GetString()
                : null;

            return new AdESSignaturePolicyUserNotice(noticeRef, explicitText);
        }

        if(obj.TryGetProperty(JAdESWireNames.SignaturePolicyQualifierSpDSpec, out JsonElement spDSpecEl))
        {
            return new AdESSignaturePolicyDocumentSpecification(DecodeObjectIdentifier(spDSpecEl));
        }

        throw new FormatException("sigPQual shall contain exactly one of spURI/spUserNotice/spDSpec (ETSI TS 119 182-1 V1.2.1, clause 5.2.7.2).");
    }


    private static Dictionary<string, object> EncodeSignaturePolicyQualifier(AdESSignaturePolicyQualifier qualifier) => qualifier switch
    {
        AdESSignaturePolicyUri uri => new Dictionary<string, object> { [JAdESWireNames.SignaturePolicyQualifierSpUri] = uri.Location },
        AdESSignaturePolicyUserNotice notice => new Dictionary<string, object> { [JAdESWireNames.SignaturePolicyQualifierSpUserNotice] = EncodeUserNotice(notice) },
        AdESSignaturePolicyDocumentSpecification spec => new Dictionary<string, object> { [JAdESWireNames.SignaturePolicyQualifierSpDSpec] = EncodeObjectIdentifier(spec.Specification) },
        _ => throw new NotSupportedException($"Unknown sigPQual arm '{qualifier.GetType()}'.")
    };


    private static Dictionary<string, object> EncodeUserNotice(AdESSignaturePolicyUserNotice notice)
    {
        var result = new Dictionary<string, object>();
        if(notice.NoticeReference is not null)
        {
            result[JAdESWireNames.SignaturePolicyUserNoticeNoticeReference] = new Dictionary<string, object>
            {
                [JAdESWireNames.SignaturePolicyNoticeReferenceOrganization] = notice.NoticeReference.Organization,
                [JAdESWireNames.SignaturePolicyNoticeReferenceNoticeNumbers] = notice.NoticeReference.NoticeNumbers.Select(static n => (object)(long)n).ToList()
            };
        }

        SetIfNotNull(result, JAdESWireNames.SignaturePolicyUserNoticeExplicitText, notice.ExplicitText);

        return result;
    }


    private static Dictionary<string, object> EncodeQualifyingAttribute(JAdESQualifyingAttribute value) => new()
    {
        [JAdESQualifyingAttribute.MediaTypeMemberName] = value.MediaType,
        [JAdESQualifyingAttribute.EncodingMemberName] = value.Encoding,
        [JAdESQualifyingAttribute.QualifyingValuesMemberName] = value.QualifyingValues.ToList()
    };


    private static List<JAdESQualifyingAttribute>? DecodeOptionalQualifyingAttributeArray(JsonElement obj, string memberName)
    {
        if(!obj.TryGetProperty(memberName, out JsonElement arrayEl))
        {
            return null;
        }

        var result = new List<JAdESQualifyingAttribute>();
        foreach(JsonElement item in arrayEl.EnumerateArray())
        {
            string mediaType = item.GetProperty(JAdESQualifyingAttribute.MediaTypeMemberName).GetString()
                ?? throw new FormatException("qArrays item's mediaType is required.");
            string encoding = item.GetProperty(JAdESQualifyingAttribute.EncodingMemberName).GetString()
                ?? throw new FormatException("qArrays item's encoding is required.");

            var qualifyingValues = new List<object>();
            foreach(JsonElement value in item.GetProperty(JAdESQualifyingAttribute.QualifyingValuesMemberName).EnumerateArray())
            {
                qualifyingValues.Add(value.Clone());
            }

            result.Add(new JAdESQualifyingAttribute(mediaType, encoding, qualifyingValues));
        }

        return result;
    }


    private static List<AdESPkiObject>? DecodeOptionalPkiObjectArray(JsonElement obj, string memberName)
    {
        if(!obj.TryGetProperty(memberName, out JsonElement arrayEl))
        {
            return null;
        }

        var result = new List<AdESPkiObject>();
        foreach(JsonElement item in arrayEl.EnumerateArray())
        {
            result.Add(DecodePkiObject(item));
        }

        return result;
    }


    private static void SetPkiObjectArrayIfNotNull(Dictionary<string, object> target, string memberName, IReadOnlyList<AdESPkiObject>? values)
    {
        if(values is not null)
        {
            target[memberName] = values.Select(static v => (object)EncodePkiObject(v)).ToList();
        }
    }


    /// <summary>Resolves a digest-algorithm identifier string to this library's <see cref="Tag"/>, falling back to a generic digest tag for an identifier this library has no named mapping for — the IANA "Named Information Hash Algorithm Registry" (JA-5.2.2.2-06) is open-ended, so an unrecognized-but-well-formed identifier is not itself malformed input.</summary>
    private static Tag ResolveDigestTag(string? hashAlgorithm) => hashAlgorithm?.Trim().ToUpperInvariant() switch
    {
        "SHA-256" or "SHA256" => CryptoTags.Sha256Digest,
        "SHA-384" or "SHA384" => CryptoTags.Sha384Digest,
        "SHA-512" or "SHA512" => CryptoTags.Sha512Digest,
        _ => Tag.Create(Purpose.Digest).With(EncodingScheme.Raw)
    };


    /// <summary>Builds a pool-owned <see cref="DigestValue"/> from decoded digest bytes and its algorithm identifier.</summary>
    private static DigestValue CreateDigestValue(byte[] digestBytes, string? hashAlgorithm, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(digestBytes.Length, 1));
        digestBytes.CopyTo(owner.Memory);

        return new DigestValue(owner, ResolveDigestTag(hashAlgorithm));
    }


    /// <summary>
    /// Projects a digest-algorithm identifier onto a JAdES <c>digAlg</c> wire string. A JAdES <c>digAlg</c> is
    /// always textual — an IANA Named Information Hash Algorithm Registry identifier (ETSI TS 119 182-1 V1.2.1,
    /// clauses 5.2.2.2/5.2.7.1) — so only <see cref="AdESDigestAlgorithmTextIdentifier"/> is representable here;
    /// <see cref="AdESDigestAlgorithmIntegerIdentifier"/> is a CB-AdES-only wire shape this format has no way to
    /// carry.
    /// </summary>
    private static string EncodeDigestAlgorithmIdentifier(AdESDigestAlgorithmIdentifier value) => value switch
    {
        AdESDigestAlgorithmTextIdentifier text => text.Value,
        _ => throw new FormatException(
            "A JAdES digAlg is a textual IANA Named Information Hash Algorithm Registry identifier (ETSI TS " +
            "119 182-1 V1.2.1, clauses 5.2.2.2/5.2.7.1); an integer digest-algorithm identifier cannot be " +
            "encoded on this wire.")
    };


    private static string? GetStringOrNull(JsonElement obj, string memberName) =>
        obj.TryGetProperty(memberName, out JsonElement value) ? value.GetString() : null;


    private static void SetIfNotNull(Dictionary<string, object> target, string memberName, string? value)
    {
        if(value is not null)
        {
            target[memberName] = value;
        }
    }
}
