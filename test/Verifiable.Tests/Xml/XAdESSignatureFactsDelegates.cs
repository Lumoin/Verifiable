using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// The <c>Verifiable.Xml</c>-backed composition-root implementation of <see
/// cref="ParseXAdESQualifyingPropertiesDelegate"/>/<see cref="VerifyXAdESSignatureValueDelegate"/> — the own
/// "implementations injected" half, mirroring the
/// <c>TrustedListXmlParser</c>/<c>TrustedListXmlSignatureVerifier</c> worked-example precedent: public by design
/// (the future promotion boundary), test-project-only, staged "leaf-adjacent" to the XAdES leaf's own test
/// files.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope: one <c>ds:Signature</c>, its directly-incorporated <c>QualifyingProperties</c>.</strong>
/// Mirrors <see cref="CAdESSignatureFacts"/>'s own "first/only SignerInfo" posture: a document must carry
/// exactly one <c>ds:Signature</c>, and its <c>QualifyingProperties</c> must be direct-incorporated (clause
/// 4.4.1) with a <c>SignedProperties</c> child. Indirect incorporation (<c>QualifyingPropertiesReference</c>)
/// is counted but never resolved (the own recorded scope refusal — this library is transport-agnostic).
/// </para>
/// <para>
/// <strong><see cref="VerifyValueAsync"/> uses the BCL's <see cref="SignedXml"/></strong> for the actual
/// cryptographic check (canonicalization, per-reference digest verification, signature-value verification under the
/// caller-identified certificate) — the same test-project-only composition <c>TrustedListXmlSignatureVerifier</c>
/// already uses for the identical "XMLDSIG cryptographic core" territory, under the same test-only-NuGet exception
/// (<c>System.Security.Cryptography.Xml</c> is pinned centrally, referenced by no shipped project). This keeps this
/// implementation's own effort on the FACTS seam (the actual scope) rather than re-deriving XML canonicalization
/// from the hand-rolled leaf a second time; a production composition root is free to compose the leaf's own
/// canonicalization/reference-processing engines with this library's registered digest/verification seams instead —
/// the delegate CONTRACT does not care which.
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1515:Consider making public types internal",
    Justification = "Staged, promotable worked example (mirrors TrustedListXmlParser/TrustedListXmlSignatureVerifier): public by design so the boundary is already the future package's API boundary.")]
public static class XAdESSignatureFactsDelegates
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";


    /// <summary>The <see cref="ParseXAdESQualifyingPropertiesDelegate"/> implementation.</summary>
    /// <param name="xmlDocument">The XML document octets.</param>
    /// <param name="pool">The memory pool every carrier the returned facts own is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The parse result.</returns>
    public static ValueTask<XAdESQualifyingPropertiesParseResult> ParseAsync(
        ReadOnlyMemory<byte> xmlDocument,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if(!XmlNodeTable.TryParse(xmlDocument, pool, out XmlNodeTable? table, out XmlReadError readError))
        {
            return ValueTask.FromResult(XAdESQualifyingPropertiesParseResult.Failed(
                $"The document is not well-formed XML: {readError.Failure} at offset {readError.ByteOffset}."));
        }

        using(table)
        {
            return ValueTask.FromResult(ParseSignature(table!, pool));
        }
    }


    /// <summary>Parses the sole <c>ds:Signature</c> of an already-parsed document into <see cref="XAdESQualifyingPropertiesFacts"/>.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Two flagged sites, both traced false-positive. 'out signaturePolicy' (TryReadSignaturePolicyIdentifier) is disposed on every failure path by the local Fail() function's own 'signaturePolicy?.Dispose()' and, on the success path, ownership transfers into the 'facts' this method returns -- Roslyn's CA2000 dataflow does not follow that transfer through a closure. The constructed XAdESQualifyingPropertiesFacts itself transfers into the XAdESQualifyingPropertiesParseResult this method returns, which the caller disposes; the analyzer cannot see across that wrapping either -- the identical CBAdESSignatureFacts/JAdESSignatureFacts suppression precedent for the identical shape.")]
    private static XAdESQualifyingPropertiesParseResult ParseSignature(XmlNodeTable table, BaseMemoryPool pool)
    {
        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table);
        if(signatureIndices.Length != 1)
        {
            return XAdESQualifyingPropertiesParseResult.Failed(
                $"The document must carry exactly one ds:Signature; found {signatureIndices.Length}.");
        }

        if(!XmlSignature.TryRead(table, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError))
        {
            return XAdESQualifyingPropertiesParseResult.Failed($"The ds:Signature did not read: {signatureError.Failure}.");
        }

        using(signature)
        {
            if(!XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature!, out XAdESQualifyingPropertiesDiscoveryResult discovery, out XAdESProcessingError discoveryError))
            {
                return XAdESQualifyingPropertiesParseResult.Failed($"XAdES discovery refused: {discoveryError.Failure}.");
            }

            if(!discovery.HasQualifyingProperties)
            {
                return XAdESQualifyingPropertiesParseResult.Failed("The signature carries no directly-incorporated QualifyingProperties.");
            }

            bool targetResolved = XAdESQualifyingPropertiesDiscovery.TryVerifyTargetBinding(
                table, discovery.QualifyingProperties, signature!, out XAdESProcessingError _);

            XAdESQualifyingProperties qualifyingProperties = discovery.QualifyingProperties;
            if(!qualifyingProperties.HasSignedProperties)
            {
                return XAdESQualifyingPropertiesParseResult.Failed("The QualifyingProperties carries no SignedProperties.");
            }

            XAdESSignedProperties signedProperties = qualifyingProperties.SignedProperties;
            bool signedPropertiesReferenceBound = XAdESQualifyingPropertiesDiscovery.TryVerifySignedPropertiesReferenceBinding(
                table, signature!, signedProperties, resolver: null, pool, out XmlReference _, out XAdESProcessingError referenceError);
            bool signedPropertiesReferencePresent = signedPropertiesReferenceBound
                || referenceError.Failure != XAdESProcessingFailure.SignedPropertiesReferenceNotFound;

            var discoveryFact = new XAdESDiscoveryFact
            {
                HasQualifyingProperties = true,
                TargetResolvedToSignature = targetResolved,
                SignedPropertiesReferencePresent = signedPropertiesReferencePresent,
                SignedPropertiesReferenceResolvedToDiscoveredNode = signedPropertiesReferenceBound,
                QualifyingPropertiesReferenceCount = discovery.QualifyingPropertiesReferences.Count
            };

            var signingCertificateDigests = new List<XAdESSigningCertificateDigestFact>();
            XAdESSignaturePolicyFact? signaturePolicy = null;
            var timestamps = new List<EmbeddedTimestamp>();
            var embeddedCertificates = new List<PkiCertificateMemory>();
            var embeddedCrls = new List<PkiCertificateMemory>();
            var embeddedOcsp = new List<PkiCertificateMemory>();
            var completeCertificateRefs = new List<XAdESCertificateReferenceDigestFact>();
            var attributeCertificateRefs = new List<XAdESCertificateReferenceDigestFact>();
            var completeRevocationCrlRefs = new List<XAdESCrlReferenceFact>();
            var completeRevocationOcspRefs = new List<XAdESOcspReferenceFact>();
            var attributeRevocationCrlRefs = new List<XAdESCrlReferenceFact>();
            var attributeRevocationOcspRefs = new List<XAdESOcspReferenceFact>();

            //Disposes every carrier rented so far -- called from every failure return below a real allocation
            //could already have happened, so a property that fails to read after an earlier property succeeded
            //never leaks the earlier property's own pooled memory. Mirrors the house's own fail-closed custody
            //discipline (no naked bytes, every rental returned on every path).
            XAdESQualifyingPropertiesParseResult Fail(string reason)
            {
                for(int i = 0; i < signingCertificateDigests.Count; ++i)
                {
                    signingCertificateDigests[i].Dispose();
                }

                signaturePolicy?.Dispose();
                for(int i = 0; i < timestamps.Count; ++i)
                {
                    timestamps[i].Token.Dispose();
                }

                DisposeAll(embeddedCertificates);
                DisposeAll(embeddedCrls);
                DisposeAll(embeddedOcsp);

                for(int i = 0; i < completeCertificateRefs.Count; ++i)
                {
                    completeCertificateRefs[i].Dispose();
                }

                for(int i = 0; i < attributeCertificateRefs.Count; ++i)
                {
                    attributeCertificateRefs[i].Dispose();
                }

                for(int i = 0; i < completeRevocationCrlRefs.Count; ++i)
                {
                    completeRevocationCrlRefs[i].Dispose();
                }

                for(int i = 0; i < completeRevocationOcspRefs.Count; ++i)
                {
                    completeRevocationOcspRefs[i].Dispose();
                }

                for(int i = 0; i < attributeRevocationCrlRefs.Count; ++i)
                {
                    attributeRevocationCrlRefs[i].Dispose();
                }

                for(int i = 0; i < attributeRevocationOcspRefs.Count; ++i)
                {
                    attributeRevocationOcspRefs[i].Dispose();
                }

                return XAdESQualifyingPropertiesParseResult.Failed(reason);

                static void DisposeAll(List<PkiCertificateMemory> carriers)
                {
                    for(int i = 0; i < carriers.Count; ++i)
                    {
                        carriers[i].Dispose();
                    }
                }
            }

            try
            {
                var signedCounts = new Dictionary<string, int>(StringComparer.Ordinal);
                var unsignedCounts = new Dictionary<string, int>(StringComparer.Ordinal);

                string? signingTimeLexical = null;
                DateTimeOffset? signingTime = null;
                var commitmentTypeIdentifiers = new List<AdESObjectIdentifier>();
                AdESSignerAttributes? signerRole = null;
                bool hasSignatureProductionPlace = false;
                int dataObjectFormatCount = 0;
                int allDataObjectsTimeStampOrdinal = 0;
                int individualDataObjectsTimeStampOrdinal = 0;
                var dataObjectFormats = new List<XAdESDataObjectFormat>();

                var timestampContainers = new List<XAdESTimestampContainerMetadata>();

                if(signedProperties.HasSignedSignatureProperties)
                {
                    IReadOnlyList<XAdESSignedSignaturePropertyEntry> entries = signedProperties.SignedSignatureProperties.Properties;
                    for(int i = 0; i < entries.Count; ++i)
                    {
                        XAdESSignedSignaturePropertyEntry entry = entries[i];
                        Increment(signedCounts, RowName(entry.Name));

                        switch(entry.Name)
                        {
                            case XAdESSignedSignaturePropertyName.SigningTime:
                                if(!TryReadSigningTime(table, entry.ElementIndex, out signingTimeLexical, out signingTime, out string? signingTimeFailure))
                                {
                                    return Fail(signingTimeFailure!);
                                }

                                break;

                            case XAdESSignedSignaturePropertyName.SigningCertificateV2:
                                if(!TryReadSigningCertificateV2(table, entry.ElementIndex, pool, signingCertificateDigests, out string? certFailure))
                                {
                                    return Fail(certFailure!);
                                }

                                break;

                            case XAdESSignedSignaturePropertyName.SignaturePolicyIdentifier:
                                if(!TryReadSignaturePolicyIdentifier(table, entry.ElementIndex, pool, out signaturePolicy, out string? policyFailure))
                                {
                                    return Fail(policyFailure!);
                                }

                                break;

                            case XAdESSignedSignaturePropertyName.SignatureProductionPlaceV2:
                                hasSignatureProductionPlace = true;

                                break;

                            case XAdESSignedSignaturePropertyName.SignerRoleV2:
                                if(!TryReadSignerRoleV2(table, entry.ElementIndex, pool, out signerRole, out string? roleFailure))
                                {
                                    return Fail(roleFailure!);
                                }

                                break;
                        }
                    }
                }

                if(signedProperties.HasSignedDataObjectProperties)
                {
                    IReadOnlyList<XAdESSignedDataObjectPropertyEntry> entries = signedProperties.SignedDataObjectProperties.Properties;
                    for(int i = 0; i < entries.Count; ++i)
                    {
                        XAdESSignedDataObjectPropertyEntry entry = entries[i];
                        Increment(signedCounts, RowName(entry.Name));

                        switch(entry.Name)
                        {
                            case XAdESSignedDataObjectPropertyName.DataObjectFormat:
                                ++dataObjectFormatCount;
                                if(!XAdESDataObjectFormat.TryRead(table, entry.ElementIndex, out XAdESDataObjectFormat dataObjectFormat, out XAdESReadError dofError))
                                {
                                    return Fail($"DataObjectFormat did not read: {dofError.Failure}.");
                                }

                                dataObjectFormats.Add(dataObjectFormat);

                                break;

                            case XAdESSignedDataObjectPropertyName.CommitmentTypeIndication:
                                if(!XAdESCommitmentTypeIndication.TryRead(table, entry.ElementIndex, out XAdESCommitmentTypeIndication commitment, out XAdESReadError commitmentError))
                                {
                                    return Fail($"CommitmentTypeIndication did not read: {commitmentError.Failure}.");
                                }

                                commitmentTypeIdentifiers.Add(ToObjectIdentifier(table, commitment.CommitmentTypeId));

                                break;

                            case XAdESSignedDataObjectPropertyName.AllDataObjectsTimeStamp:
                                if(!XAdESAllDataObjectsTimeStamp.TryRead(table, entry.ElementIndex, pool, out XAdESAllDataObjectsTimeStamp? adoTst, out XAdESReadError adoTstError))
                                {
                                    return Fail($"AllDataObjectsTimeStamp did not read: {adoTstError.Failure}.");
                                }

                                using(adoTst)
                                {
                                    CopyTimeStampContainer(table, adoTst!.TimeStamp, SignatureTimestampClass.ContentTimestamp, "AllDataObjectsTimeStamp",
                                        ref allDataObjectsTimeStampOrdinal, pool, timestamps, timestampContainers);
                                }

                                break;

                            case XAdESSignedDataObjectPropertyName.IndividualDataObjectsTimeStamp:
                                if(!XAdESIndividualDataObjectsTimeStamp.TryRead(table, entry.ElementIndex, pool, out XAdESIndividualDataObjectsTimeStamp? idoTst, out XAdESReadError idoTstError))
                                {
                                    return Fail($"IndividualDataObjectsTimeStamp did not read: {idoTstError.Failure}.");
                                }

                                using(idoTst)
                                {
                                    CopyTimeStampContainer(table, idoTst!.TimeStamp, SignatureTimestampClass.ContentTimestamp, "IndividualDataObjectsTimeStamp",
                                        ref individualDataObjectsTimeStampOrdinal, pool, timestamps, timestampContainers);
                                }

                                break;
                        }
                    }
                }

                //Letter k) (XA-6.3-t08): computed here, over the read signature, since the bijection needs
                //ds:SignedInfo membership the crypto-free facts shape never carries -- the RESULT rides as a
                //fact (XAdESQualifyingPropertiesFacts.IsDataObjectFormatCoverageSatisfied).
                bool dataObjectFormatCoverageSatisfied = XAdESDataObjectFormatCoverage.TryVerify(table, signature!, dataObjectFormats, out XAdESProcessingError _);

                int counterSignatureCount = 0;
                var validationDataCounts = new XAdESValidationDataCounts();
                var unknownProperties = new List<string>();

                int sigTstOrdinal = 0;
                int arcTstOrdinal = 0;
                int validationDataTimestampOrdinal = 0;
                bool validationDataForTimestampsHasContent = false;

                if(qualifyingProperties.HasUnsignedProperties && qualifyingProperties.UnsignedProperties.HasUnsignedSignatureProperties)
                {
                    IReadOnlyList<XAdESUnsignedSignaturePropertyEntry> entries = qualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.Properties;
                    for(int i = 0; i < entries.Count; ++i)
                    {
                        XAdESUnsignedSignaturePropertyEntry entry = entries[i];
                        if(entry.Name != XAdESUnsignedSignaturePropertyName.Unrecognized)
                        {
                            Increment(unsignedCounts, RowName(entry.Name));
                        }

                        switch(entry.Name)
                        {
                            case XAdESUnsignedSignaturePropertyName.CounterSignature:
                                ++counterSignatureCount;

                                break;

                            case XAdESUnsignedSignaturePropertyName.SignatureTimeStamp:
                                if(!XAdESSignatureTimeStamp.TryRead(table, entry.ElementIndex, pool, out XAdESSignatureTimeStamp? sigTst, out XAdESReadError sigTstError))
                                {
                                    return Fail($"SignatureTimeStamp did not read: {sigTstError.Failure}.");
                                }

                                using(sigTst)
                                {
                                    CopyTimeStampContainer(table, sigTst!.TimeStamp, SignatureTimestampClass.SignatureTimestamp, "SignatureTimeStamp",
                                        ref sigTstOrdinal, pool, timestamps, timestampContainers);
                                }

                                break;

                            case XAdESUnsignedSignaturePropertyName.CompleteRevocationRefs:
                                if(!TryReadCompleteRevocationRefs(table, entry.ElementIndex, pool, isAttributeRevocationRefs: false, completeRevocationCrlRefs, completeRevocationOcspRefs, out string? crrFailure))
                                {
                                    return Fail(crrFailure!);
                                }

                                validationDataCounts = validationDataCounts with { CompleteRevocationRefsCount = validationDataCounts.CompleteRevocationRefsCount + 1 };

                                break;

                            case XAdESUnsignedSignaturePropertyName.AttributeRevocationRefs:
                                if(!TryReadCompleteRevocationRefs(table, entry.ElementIndex, pool, isAttributeRevocationRefs: true, attributeRevocationCrlRefs, attributeRevocationOcspRefs, out string? arrFailure))
                                {
                                    return Fail(arrFailure!);
                                }

                                validationDataCounts = validationDataCounts with { AttributeRevocationRefsCount = validationDataCounts.AttributeRevocationRefsCount + 1 };

                                break;

                            case XAdESUnsignedSignaturePropertyName.CertificateValues:
                                if(!TryReadCertificateValues(table, entry.ElementIndex, pool, embeddedCertificates, out string? cvFailure))
                                {
                                    return Fail(cvFailure!);
                                }

                                validationDataCounts = validationDataCounts with { CertificateValuesCount = validationDataCounts.CertificateValuesCount + 1 };

                                break;

                            case XAdESUnsignedSignaturePropertyName.RevocationValues:
                                if(!TryReadRevocationValues(table, entry.ElementIndex, pool, embeddedCrls, embeddedOcsp, out string? rvFailure))
                                {
                                    return Fail(rvFailure!);
                                }

                                validationDataCounts = validationDataCounts with { RevocationValuesCount = validationDataCounts.RevocationValuesCount + 1 };

                                break;

                            case XAdESUnsignedSignaturePropertyName.AttrAuthoritiesCertValues:
                                if(!TryReadCertificateValues(table, entry.ElementIndex, pool, embeddedCertificates, out string? aacvFailure))
                                {
                                    return Fail(aacvFailure!);
                                }

                                validationDataCounts = validationDataCounts with { AttrAuthoritiesCertValuesCount = validationDataCounts.AttrAuthoritiesCertValuesCount + 1 };

                                break;

                            case XAdESUnsignedSignaturePropertyName.AttributeRevocationValues:
                                if(!TryReadRevocationValues(table, entry.ElementIndex, pool, embeddedCrls, embeddedOcsp, out string? arvFailure))
                                {
                                    return Fail(arvFailure!);
                                }

                                validationDataCounts = validationDataCounts with { AttributeRevocationValuesCount = validationDataCounts.AttributeRevocationValuesCount + 1 };

                                break;

                            case XAdESUnsignedSignaturePropertyName.Unrecognized:
                                if(!TryDispatchUnrecognized(
                                    table, entry.ElementIndex, pool, unsignedCounts, ref validationDataCounts, embeddedCertificates,
                                    embeddedCrls, embeddedOcsp, timestamps, timestampContainers, ref arcTstOrdinal, ref validationDataTimestampOrdinal,
                                    completeCertificateRefs, attributeCertificateRefs, unknownProperties, ref validationDataForTimestampsHasContent,
                                    out string? unrecognizedFailure))
                                {
                                    return Fail(unrecognizedFailure!);
                                }

                                break;
                        }
                    }
                }

                bool certificateValidationDataTriggered = false;
                bool revocationValidationDataTriggered = false;
                if(qualifyingProperties.HasUnsignedProperties && qualifyingProperties.UnsignedProperties.HasUnsignedSignatureProperties)
                {
                    XAdESUnsignedSignatureProperties unsignedSignatureProperties = qualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
                    if(XAdESValidationDataTrigger.TryDetermine(table, unsignedSignatureProperties, XAdESValidationDataFamily.Certificate, out XAdESValidationDataTriggerResult certTrigger, out XAdESProcessingError _))
                    {
                        certificateValidationDataTriggered = certTrigger.IsTriggered;
                    }

                    if(XAdESValidationDataTrigger.TryDetermine(table, unsignedSignatureProperties, XAdESValidationDataFamily.Revocation, out XAdESValidationDataTriggerResult revTrigger, out XAdESProcessingError _))
                    {
                        revocationValidationDataTriggered = revTrigger.IsTriggered;
                    }
                }

                var facts = new XAdESQualifyingPropertiesFacts
                {
                    Discovery = discoveryFact,
                    SigningTimeLexical = signingTimeLexical,
                    SigningTime = signingTime,
                    SigningCertificateDigests = signingCertificateDigests,
                    SignaturePolicy = signaturePolicy,
                    CommitmentTypeIdentifiers = commitmentTypeIdentifiers,
                    SignerRole = signerRole,
                    HasSignatureProductionPlace = hasSignatureProductionPlace,
                    DataObjectFormatCount = dataObjectFormatCount,
                    IsDataObjectFormatCoverageSatisfied = dataObjectFormatCoverageSatisfied,
                    CounterSignatureCount = counterSignatureCount,
                    Timestamps = timestamps,
                    TimestampContainers = timestampContainers,
                    ValidationData = validationDataCounts,
                    ValidationDataForTimestampsHasContent = validationDataForTimestampsHasContent,
                    EmbeddedCertificates = embeddedCertificates,
                    EmbeddedCertificateRevocationLists = embeddedCrls,
                    EmbeddedOcspResponses = embeddedOcsp,
                    CompleteCertificateRefs = completeCertificateRefs,
                    AttributeCertificateRefs = attributeCertificateRefs,
                    CompleteRevocationCrlRefs = completeRevocationCrlRefs,
                    CompleteRevocationOcspRefs = completeRevocationOcspRefs,
                    AttributeRevocationCrlRefs = attributeRevocationCrlRefs,
                    AttributeRevocationOcspRefs = attributeRevocationOcspRefs,
                    CertificateValidationDataTriggered = certificateValidationDataTriggered,
                    RevocationValidationDataTriggered = revocationValidationDataTriggered,
                    SignedPropertyOccurrenceCounts = signedCounts,
                    UnsignedPropertyOccurrenceCounts = unsignedCounts,
                    DeprecatedPropertyObservations = [],
                    UnknownPropertyObservations = unknownProperties
                };

                return XAdESQualifyingPropertiesParseResult.Parsed(facts);
            }
            catch
            {
                Fail("unreachable -- disposal only; the exception below is what actually propagates.");

                throw;
            }
        }
    }


    private static void Increment(Dictionary<string, int> counts, string name)
    {
        counts[name] = counts.TryGetValue(name, out int current) ? current + 1 : 1;
    }


    private static string RowName(XAdESSignedSignaturePropertyName name) => name switch
    {
        XAdESSignedSignaturePropertyName.SigningTime => XAdESBaselineLevelTable.SigningTime.Name,
        XAdESSignedSignaturePropertyName.SigningCertificateV2 => XAdESBaselineLevelTable.SigningCertificateV2.Name,
        XAdESSignedSignaturePropertyName.SignaturePolicyIdentifier => XAdESBaselineLevelTable.SignaturePolicyIdentifier.Name,
        XAdESSignedSignaturePropertyName.SignatureProductionPlaceV2 => XAdESBaselineLevelTable.SignatureProductionPlaceV2.Name,
        XAdESSignedSignaturePropertyName.SignerRoleV2 => XAdESBaselineLevelTable.SignerRoleV2.Name,
        _ => name.ToString()
    };


    private static string RowName(XAdESSignedDataObjectPropertyName name) => name switch
    {
        XAdESSignedDataObjectPropertyName.DataObjectFormat => XAdESBaselineLevelTable.DataObjectFormat.Name,
        XAdESSignedDataObjectPropertyName.CommitmentTypeIndication => XAdESBaselineLevelTable.CommitmentTypeIndication.Name,
        XAdESSignedDataObjectPropertyName.AllDataObjectsTimeStamp => XAdESBaselineLevelTable.AllDataObjectsTimeStamp.Name,
        XAdESSignedDataObjectPropertyName.IndividualDataObjectsTimeStamp => XAdESBaselineLevelTable.IndividualDataObjectsTimeStamp.Name,
        _ => name.ToString()
    };


    private static string RowName(XAdESUnsignedSignaturePropertyName name) => name switch
    {
        XAdESUnsignedSignaturePropertyName.CounterSignature => XAdESBaselineLevelTable.CounterSignature.Name,
        XAdESUnsignedSignaturePropertyName.SignatureTimeStamp => XAdESBaselineLevelTable.SignatureTimeStamp.Name,
        XAdESUnsignedSignaturePropertyName.CompleteRevocationRefs => XAdESBaselineLevelTable.CompleteRevocationRefs.Name,
        XAdESUnsignedSignaturePropertyName.AttributeRevocationRefs => XAdESBaselineLevelTable.AttributeRevocationRefs.Name,
        XAdESUnsignedSignaturePropertyName.CertificateValues => XAdESBaselineLevelTable.CertificateValues.Name,
        XAdESUnsignedSignaturePropertyName.RevocationValues => XAdESBaselineLevelTable.RevocationValues.Name,
        XAdESUnsignedSignaturePropertyName.AttrAuthoritiesCertValues => XAdESBaselineLevelTable.AttrAuthoritiesCertValues.Name,
        XAdESUnsignedSignaturePropertyName.AttributeRevocationValues => XAdESBaselineLevelTable.AttributeRevocationValues.Name,
        _ => name.ToString()
    };


    private static string Utf8(ReadOnlySpan<byte> value) => Encoding.UTF8.GetString(value);


    private static AdESObjectIdentifier ToObjectIdentifier(XmlNodeTable table, XAdESObjectIdentifier identifier)
    {
        string id = Utf8(identifier.Identifier);
        string? description = identifier.HasDescription ? Utf8(identifier.Description) : null;

        return new AdESObjectIdentifier(id, description);
    }


    private static bool TryReadSigningTime(XmlNodeTable table, int elementIndex, out string? lexical, out DateTimeOffset? parsed, out string? failureReason)
    {
        lexical = null;
        parsed = null;
        if(!XAdESSigningTime.TryRead(table, elementIndex, out XAdESSigningTime value, out XAdESReadError error))
        {
            failureReason = $"SigningTime did not read: {error.Failure}.";

            return false;
        }

        if(XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, elementIndex, out int textNodeIndex, out _))
        {
            lexical = Utf8(table.ValueOf(textNodeIndex));
        }

        parsed = ToDateTimeOffset(value.Value);
        failureReason = null;

        return true;
    }


    /// <summary>
    /// Converts a parsed <see cref="XAdESDateTime"/> to a <see cref="DateTimeOffset"/> on a best-effort basis;
    /// <see langword="null"/> for a value <see cref="DateTimeOffset"/> cannot represent (e.g. the XML Schema
    /// hour-24 end-of-day form, or a year outside 1-9999) — the LEXICAL text is still preserved separately, so
    /// no information is lost, only the parsed convenience value is withheld.
    /// </summary>
    private static DateTimeOffset? ToDateTimeOffset(XAdESDateTime value)
    {
        if(value.IsNegativeYear || value.Year is < 1 or > 9999 || value.Hour is < 0 or > 23)
        {
            return null;
        }

        try
        {
            var dateTime = new DateTime((int)value.Year, value.Month, value.Day, value.Hour, value.Minute, value.Second, DateTimeKind.Unspecified);
            if(value.HasFractionalSecond && value.FractionalSecondDigitCount > 0)
            {
                double fraction = value.FractionalSecondNumerator / Math.Pow(10, value.FractionalSecondDigitCount);
                dateTime = dateTime.AddTicks((long)(fraction * TimeSpan.TicksPerSecond));
            }

            TimeSpan offset = TimeSpan.Zero;
            if(value.HasTimezone && !value.IsUtcTimezone)
            {
                offset = new TimeSpan(value.TimezoneHours, value.TimezoneMinutes, 0);
                if(value.IsTimezoneNegative)
                {
                    offset = -offset;
                }
            }

            return new DateTimeOffset(dateTime, value.HasTimezone ? offset : TimeSpan.Zero);
        }
        catch(ArgumentOutOfRangeException)
        {
            return null;
        }
    }


    private static bool TryReadSigningCertificateV2(
        XmlNodeTable table, int elementIndex, BaseMemoryPool pool,
        List<XAdESSigningCertificateDigestFact> collected, out string? failureReason)
    {
        if(!XAdESSigningCertificateV2.TryRead(table, elementIndex, pool, out XAdESSigningCertificateV2? value, out XAdESReadError error))
        {
            failureReason = $"SigningCertificateV2 did not read: {error.Failure}.";

            return false;
        }

        using(value)
        {
            for(int i = 0; i < value!.Certs.Count; ++i)
            {
                XAdESCertIdV2 cert = value.Certs[i];
                string digestUri = Utf8(cert.CertDigest.DigestMethodAlgorithm);
                PkiDigestAlgorithm? resolved = XmlSignatureWellKnown.DigestAlgorithmFromUri(digestUri);
                AlgorithmIdentifier algorithmIdentifier = resolved?.Identifier ?? new AlgorithmIdentifier(digestUri) { Name = digestUri };
                DigestValue digest = CopyDigest(cert.CertDigest.DigestValueOctets.AsReadOnlySpan(), resolved?.DigestTag ?? CryptoTags.Sha256Digest, pool);

                PkiCertificateMemory? issuerSerialV2 = null;
                if(cert.HasIssuerSerialV2 && cert.IssuerSerialV2Octets is PooledMemory issuerSerialOctets)
                {
                    issuerSerialV2 = CopyCertificate(issuerSerialOctets.AsReadOnlySpan(), PkiCertificateTags.IssuerSerial, pool);
                }

                var fact = new XAdESSigningCertificateDigestFact
                {
                    Reference = new SigningCertificateReference
                    {
                        DigestAlgorithm = algorithmIdentifier,
                        CertificateDigest = digest,
                        IssuerName = null,
                        SerialNumber = null,
                        IsSignerReference = i == 0
                    },
                    IssuerSerialV2 = issuerSerialV2
                };
                collected.Add(fact);
            }
        }

        failureReason = null;

        return true;
    }


    private static bool TryReadSignaturePolicyIdentifier(
        XmlNodeTable table, int elementIndex, BaseMemoryPool pool,
        out XAdESSignaturePolicyFact? fact, out string? failureReason)
    {
        fact = null;
        if(!Verifiable.Xml.XAdESSignaturePolicyIdentifier.TryRead(table, elementIndex, pool, out Verifiable.Xml.XAdESSignaturePolicyIdentifier? value, out XAdESReadError error))
        {
            failureReason = $"SignaturePolicyIdentifier did not read: {error.Failure}.";

            return false;
        }

        using(value)
        {
            if(value!.Choice == XAdESSignaturePolicyIdentifierChoice.SignaturePolicyImplied)
            {
                fact = new XAdESSignaturePolicyFact { IsImplied = true };
                failureReason = null;

                return true;
            }

            XAdESSignaturePolicyId policyId = value.SignaturePolicyId!;
            AdESObjectIdentifier id = ToObjectIdentifier(table, policyId.SigPolicyId);
            string hashUri = Utf8(policyId.SigPolicyHash.DigestMethodAlgorithm);
            PkiDigestAlgorithm? resolved = XmlSignatureWellKnown.DigestAlgorithmFromUri(hashUri);
            AlgorithmIdentifier hashAlgorithm = resolved?.Identifier ?? new AlgorithmIdentifier(hashUri) { Name = hashUri };
            DigestValue hash = CopyDigest(policyId.SigPolicyHash.DigestValueOctets.AsReadOnlySpan(), resolved?.DigestTag ?? CryptoTags.Sha256Digest, pool);

            var result = new XAdESSignaturePolicyFact
            {
                IsImplied = false,
                Id = id,
                HashAlgorithm = hashAlgorithm,
                Hash = hash,
                HasQualifiers = policyId.HasSigPolicyQualifiers,
                QualifierCount = policyId.HasSigPolicyQualifiers ? policyId.SigPolicyQualifiers.Count : 0
            };
            fact = result;
        }

        failureReason = null;

        return true;
    }


    private static bool TryReadSignerRoleV2(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out AdESSignerAttributes? role, out string? failureReason)
    {
        role = null;
        if(!XAdESSignerRoleV2.TryRead(table, elementIndex, pool, out XAdESSignerRoleV2? value, out XAdESReadError error))
        {
            failureReason = $"SignerRoleV2 did not read: {error.Failure}.";

            return false;
        }

        using(value)
        {
            List<AdESCertifiedAttribute>? certified = value!.HasCertifiedRolesV2
                ? BuildPlaceholders<AdESCertifiedAttribute>(value.CertifiedRoles.Count, static () => new AdESX509AttributeCertificate(new AdESPkiObject { Val = ReadOnlyMemory<byte>.Empty }))
                : null;
            List<object>? claimed = value.HasClaimedRoles ? BuildPlaceholders<object>(value.ClaimedRoles.Count, static () => string.Empty) : null;
            List<object>? signedAssertions = value.HasSignedAssertions ? BuildPlaceholders<object>(value.SignedAssertions.Count, static () => string.Empty) : null;

            role = certified is null && claimed is null && signedAssertions is null
                ? null
                : new AdESSignerAttributes(certified, signedAssertions, claimed);
        }

        failureReason = null;

        return true;
    }


    private static List<T> BuildPlaceholders<T>(int count, Func<T> factory)
    {
        var list = new List<T>(count);
        for(int i = 0; i < count; ++i)
        {
            list.Add(factory());
        }

        return list;
    }


    private static void CopyTimeStampContainer(
        XmlNodeTable table, XAdESTimeStamp timeStamp, SignatureTimestampClass timestampClass, string identifier,
        ref int ordinal, BaseMemoryPool pool, List<EmbeddedTimestamp> timestamps, List<XAdESTimestampContainerMetadata> containers)
    {
        int tokenCount = 0;
        for(int t = 0; t < timeStamp.TimeStamps.Count; ++t)
        {
            XAdESTimeStampEntry entry = timeStamp.TimeStamps[t];
            if(entry.Kind != XAdESTimeStampEntryKind.EncapsulatedTimeStamp)
            {
                // XMLTimeStamp content: an unmodeled fact this delegate does not surface as a token per clause
                // 6.3's own baseline restriction (RFC 3161 tokens only) -- the container-level metadata below still records
                // its presence via CarriesOnlyRfc3161Tokens, which XAdESLevelRules.Check enforces (XA-6.3-04).
                continue;
            }

            PkiCertificateMemory token = CopyCertificate(entry.EncapsulatedTimeStamp.Content.AsReadOnlySpan(), PkiCertificateTags.TimestampToken, pool);
            timestamps.Add(new EmbeddedTimestamp
            {
                Class = timestampClass,
                Identifier = identifier,
                Token = token,
                Ordinal = ordinal++
            });
            ++tokenCount;
        }

        string? canonicalizationUri = timeStamp.HasCanonicalizationMethod ? Utf8(timeStamp.CanonicalizationMethod.Algorithm) : null;
        containers.Add(new XAdESTimestampContainerMetadata
        {
            Kind = identifier switch
            {
                "AllDataObjectsTimeStamp" => XAdESTimestampContainerKind.AllDataObjectsTimeStamp,
                "IndividualDataObjectsTimeStamp" => XAdESTimestampContainerKind.IndividualDataObjectsTimeStamp,
                "SignatureTimeStamp" => XAdESTimestampContainerKind.SignatureTimeStamp,
                "SigAndRefsTimeStampV2" => XAdESTimestampContainerKind.SigAndRefsTimeStampV2,
                "RefsOnlyTimeStampV2" => XAdESTimestampContainerKind.RefsOnlyTimeStampV2,
                "ArchiveTimeStamp" => XAdESTimestampContainerKind.ArchiveTimeStamp,
                _ => XAdESTimestampContainerKind.Unknown
            },
            TokenCount = tokenCount,
            HasInclude = timeStamp.Includes.Count > 0,
            IncludeCount = timeStamp.Includes.Count,
            CanonicalizationUri = canonicalizationUri,
            CarriesOnlyRfc3161Tokens = XAdESBaselineIncorporationRequirements.ContainsOnlyRfc3161TimeStamps(timeStamp.TimeStamps)
        });
    }


    private static bool TryReadCertificateValues(
        XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PkiCertificateMemory> certificates, out string? failureReason)
    {
        if(!XAdESCertificateValues.TryRead(table, elementIndex, pool, out XAdESCertificateValues? value, out XAdESReadError error))
        {
            failureReason = $"CertificateValues-shaped property did not read: {error.Failure}.";

            return false;
        }

        using(value)
        {
            for(int i = 0; i < value!.Entries.Count; ++i)
            {
                if(value.Entries[i].Kind == XAdESCertificateValueKind.EncapsulatedX509Certificate)
                {
                    certificates.Add(CopyCertificate(value.Entries[i].EncapsulatedX509Certificate.Content.AsReadOnlySpan(), PkiCertificateTags.X509Certificate, pool));
                }
            }
        }

        failureReason = null;

        return true;
    }


    private static bool TryReadRevocationValues(
        XmlNodeTable table, int elementIndex, BaseMemoryPool pool,
        List<PkiCertificateMemory> crls, List<PkiCertificateMemory> ocsp, out string? failureReason)
    {
        if(!XAdESRevocationValues.TryRead(table, elementIndex, pool, out XAdESRevocationValues? value, out XAdESReadError error))
        {
            failureReason = $"RevocationValues-shaped property did not read: {error.Failure}.";

            return false;
        }

        using(value)
        {
            if(value!.HasCrlValues)
            {
                for(int i = 0; i < value.CrlValues.Count; ++i)
                {
                    crls.Add(CopyCertificate(value.CrlValues[i].Content.AsReadOnlySpan(), PkiCertificateTags.X509Crl, pool));
                }
            }

            if(value.HasOcspValues)
            {
                for(int i = 0; i < value.OcspValues.Count; ++i)
                {
                    ocsp.Add(CopyCertificate(value.OcspValues[i].Content.AsReadOnlySpan(), PkiCertificateTags.OcspResponse, pool));
                }
            }
        }

        failureReason = null;

        return true;
    }


    /// <summary>Reads a <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c> element's <c>Cert</c> entries into <see cref="XAdESCertificateReferenceDigestFact"/>s — the same digest/<c>IssuerSerialV2</c> shape <see cref="TryReadSigningCertificateV2"/> reads for the sibling <c>SigningCertificateV2</c> property (the shared <c>CertIDListV2Type</c>).</summary>
    private static bool TryReadCompleteCertificateRefs(
        XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<XAdESCertificateReferenceDigestFact> collected, out string? failureReason)
    {
        if(!XAdESCompleteCertificateRefsV2.TryRead(table, elementIndex, pool, out XAdESCompleteCertificateRefsV2? value, out XAdESReadError error))
        {
            failureReason = $"CompleteCertificateRefsV2-shaped property did not read: {error.Failure}.";

            return false;
        }

        using(value)
        {
            for(int i = 0; i < value!.CertRefs.Count; ++i)
            {
                XAdESCertIdV2 cert = value.CertRefs[i];
                (AlgorithmIdentifier algorithmIdentifier, DigestValue digest) = ReadDigestAlgAndValue(cert.CertDigest, pool);

                PkiCertificateMemory? issuerSerialV2 = null;
                if(cert.HasIssuerSerialV2 && cert.IssuerSerialV2Octets is PooledMemory issuerSerialOctets)
                {
                    issuerSerialV2 = CopyCertificate(issuerSerialOctets.AsReadOnlySpan(), PkiCertificateTags.IssuerSerial, pool);
                }

                collected.Add(new XAdESCertificateReferenceDigestFact
                {
                    DigestAlgorithm = algorithmIdentifier,
                    Digest = digest,
                    IssuerSerialV2 = issuerSerialV2
                });
            }
        }

        failureReason = null;

        return true;
    }


    /// <summary>Reads a <c>CompleteRevocationRefs</c>/<c>AttributeRevocationRefs</c> element's <c>CRLRef</c>/<c>OCSPRef</c> entries into <see cref="XAdESCrlReferenceFact"/>/<see cref="XAdESOcspReferenceFact"/> lists, dispatching to the property-specific binding (<see cref="XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs"/> for A.1.2's empty-container floor, <see cref="XAdESCompleteRevocationRefs.TryReadAttributeRevocationRefs"/> for A.1.4's absence of that floor).</summary>
    private static bool TryReadCompleteRevocationRefs(
        XmlNodeTable table, int elementIndex, BaseMemoryPool pool, bool isAttributeRevocationRefs,
        List<XAdESCrlReferenceFact> crlRefs, List<XAdESOcspReferenceFact> ocspRefs, out string? failureReason)
    {
        //value is an out-parameter target, assigned by TryReadAttributeRevocationRefs/
        //TryReadCompleteRevocationRefs below; a using declaration cannot target a variable assigned
        //through an out parameter after declaration.
        XAdESCompleteRevocationRefs? value = null;
        try
        {
            XAdESReadError error = default;
            bool isRead = isAttributeRevocationRefs
                ? XAdESCompleteRevocationRefs.TryReadAttributeRevocationRefs(table, elementIndex, pool, out value, out error)
                : XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs(table, elementIndex, pool, out value, out error);

            if(!isRead)
            {
                failureReason = $"CompleteRevocationRefs-shaped property did not read: {error.Failure}.";

                return false;
            }

            for(int i = 0; i < value!.CrlRefs.Count; ++i)
            {
                XAdESCrlRef crlRef = value.CrlRefs[i];
                (AlgorithmIdentifier algorithmIdentifier, DigestValue digest) = ReadDigestAlgAndValue(crlRef.DigestAlgAndValue, pool);

                bool hasCrlIdentifier = crlRef.HasCrlIdentifier;
                string? issuer = null;
                string? issueTimeLexical = null;
                DateTimeOffset? issueTime = null;
                bool hasNumber = false;
                bool isNumberNegative = false;
                long number = 0;
                bool hasUri = false;
                string? uri = null;
                if(hasCrlIdentifier)
                {
                    XAdESCrlIdentifier identifier = crlRef.CrlIdentifier;
                    issuer = Utf8(identifier.Issuer);
                    issueTimeLexical = TryGetChildSimpleContentLexical(table, identifier.ElementIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "IssueTime"u8) ?? string.Empty;
                    issueTime = ToDateTimeOffset(identifier.IssueTime);
                    hasNumber = identifier.HasNumber;
                    isNumberNegative = identifier.IsNumberNegative;
                    number = identifier.Number;
                    hasUri = identifier.HasUri;
                    uri = hasUri ? Utf8(identifier.Uri) : null;
                }

                crlRefs.Add(new XAdESCrlReferenceFact
                {
                    DigestAlgorithm = algorithmIdentifier,
                    Digest = digest,
                    HasCrlIdentifier = hasCrlIdentifier,
                    Issuer = issuer,
                    IssueTimeLexical = issueTimeLexical,
                    IssueTime = issueTime,
                    HasNumber = hasNumber,
                    IsNumberNegative = isNumberNegative,
                    Number = number,
                    HasUri = hasUri,
                    Uri = uri
                });
            }

            for(int i = 0; i < value.OcspRefs.Count; ++i)
            {
                XAdESOcspRef ocspRef = value.OcspRefs[i];
                bool hasDigest = ocspRef.HasDigestAlgAndValue;
                AlgorithmIdentifier? digestAlgorithm = null;
                DigestValue? digest = null;
                if(hasDigest)
                {
                    (AlgorithmIdentifier resolvedAlgorithm, DigestValue resolvedDigest) = ReadDigestAlgAndValue(ocspRef.DigestAlgAndValue, pool);
                    digestAlgorithm = resolvedAlgorithm;
                    digest = resolvedDigest;
                }

                XAdESOcspIdentifier identifier = ocspRef.OcspIdentifier;
                XAdESOcspResponderIdKind responderKind = identifier.ResponderKind == XAdESResponderIdKind.ByName
                    ? XAdESOcspResponderIdKind.ByName
                    : XAdESOcspResponderIdKind.ByKey;
                string? responderByName = responderKind == XAdESOcspResponderIdKind.ByName ? Utf8(identifier.ByName) : null;
                PkiCertificateMemory? responderByKeyOctets = responderKind == XAdESOcspResponderIdKind.ByKey && identifier.ByKeyOctets is PooledMemory byKeyOctets
                    ? CopyCertificate(byKeyOctets.AsReadOnlySpan(), PkiCertificateTags.OcspResponderKeyHash, pool)
                    : null;

                string producedAtLexical = TryGetChildSimpleContentLexical(table, identifier.ElementIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ProducedAt"u8) ?? string.Empty;

                ocspRefs.Add(new XAdESOcspReferenceFact
                {
                    HasDigestAlgAndValue = hasDigest,
                    DigestAlgorithm = digestAlgorithm,
                    Digest = digest,
                    ResponderKind = responderKind,
                    ResponderByName = responderByName,
                    ResponderByKeyOctets = responderByKeyOctets,
                    ProducedAtLexical = producedAtLexical,
                    ProducedAt = ToDateTimeOffset(identifier.ProducedAt),
                    HasUri = identifier.HasUri,
                    Uri = identifier.HasUri ? Utf8(identifier.Uri) : null
                });
            }

            failureReason = null;

            return true;
        }
        finally
        {
            value?.Dispose();
        }
    }


    /// <summary>Resolves a <see cref="XAdESDigestAlgAndValue"/>'s algorithm URI onto this library's <see cref="AlgorithmIdentifier"/> vocabulary and copies its digest octets into a pooled <see cref="DigestValue"/> — the one digest-carrier decode every refs-family reader shares.</summary>
    private static (AlgorithmIdentifier Algorithm, DigestValue Digest) ReadDigestAlgAndValue(XAdESDigestAlgAndValue digestAlgAndValue, BaseMemoryPool pool)
    {
        string digestUri = Utf8(digestAlgAndValue.DigestMethodAlgorithm);
        PkiDigestAlgorithm? resolved = XmlSignatureWellKnown.DigestAlgorithmFromUri(digestUri);
        AlgorithmIdentifier algorithmIdentifier = resolved?.Identifier ?? new AlgorithmIdentifier(digestUri) { Name = digestUri };
        DigestValue digest = CopyDigest(digestAlgAndValue.DigestValueOctets.AsReadOnlySpan(), resolved?.DigestTag ?? CryptoTags.Sha256Digest, pool);

        return (algorithmIdentifier, digest);
    }


    /// <summary>
    /// Finds <paramref name="parentElementIndex"/>'s child named (<paramref name="namespaceUri"/>, <paramref name="localName"/>)
    /// and returns its simple-content lexical text, or <see langword="null"/> when no such child exists —
    /// the same lexical-text-alongside-parsed-value posture <see cref="TryReadSigningTime"/> takes for
    /// <c>SigningTime</c>, applied to a child the leaf's own read model exposes only as a parsed
    /// <see cref="XAdESDateTime"/> (<c>CRLIdentifier/IssueTime</c>, <c>OCSPIdentifier/ProducedAt</c>).
    /// </summary>
    private static string? TryGetChildSimpleContentLexical(XmlNodeTable table, int parentElementIndex, ReadOnlySpan<byte> namespaceUri, ReadOnlySpan<byte> localName)
    {
        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, parentElementIndex, out int child);
        while(scan == ElementScanResult.Found)
        {
            if(XmlSignatureModelGrammar.IsElement(table, child, namespaceUri, localName))
            {
                return XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out int textNodeIndex, out _) && textNodeIndex >= 0
                    ? Utf8(table.ValueOf(textNodeIndex))
                    : string.Empty;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
        }

        return null;
    }


    /// <summary>
    /// Dispatches one <c>UnsignedSignatureProperty</c> the caller's own switch did not recognize by name to
    /// its XAdES v1.4.1 element shape. The four <see langword="ref"/> parameters are accumulators the
    /// caller's enclosing scan loop owns across every property it dispatches (the running validation-data
    /// counts, the archive- and validation-data-timestamp ordinals, and the "has content" flag); bundling
    /// them into a carrier would be a wider refactor of the whole scan loop, not this dispatch alone.
    /// </summary>
    private static bool TryDispatchUnrecognized(
        XmlNodeTable table, int elementIndex, BaseMemoryPool pool,
        Dictionary<string, int> unsignedCounts, ref XAdESValidationDataCounts validationDataCounts,
        List<PkiCertificateMemory> embeddedCertificates, List<PkiCertificateMemory> embeddedCrls, List<PkiCertificateMemory> embeddedOcsp,
        List<EmbeddedTimestamp> timestamps, List<XAdESTimestampContainerMetadata> timestampContainers,
        ref int arcTstOrdinal, ref int validationDataTimestampOrdinal,
        List<XAdESCertificateReferenceDigestFact> completeCertificateRefs, List<XAdESCertificateReferenceDigestFact> attributeCertificateRefs,
        List<string> unknownProperties, ref bool validationDataForTimestampsHasContent, out string? failureReason)
    {
        ReadOnlySpan<byte> v141 = XAdESIdentifiers.XAdESNamespaceV141Utf8;

        if(XmlSignatureModelGrammar.IsElement(table, elementIndex, v141, "ArchiveTimeStamp"u8))
        {
            Increment(unsignedCounts, XAdESBaselineLevelTable.ArchiveTimeStamp.Name);
            if(!XAdESArchiveTimeStamp.TryRead(table, elementIndex, pool, out XAdESArchiveTimeStamp? arcTst, out XAdESReadError arcTstError))
            {
                failureReason = $"ArchiveTimeStamp did not read: {arcTstError.Failure}.";

                return false;
            }

            using(arcTst)
            {
                CopyTimeStampContainer(table, arcTst!.TimeStamp, SignatureTimestampClass.ArchiveTimestamp, "ArchiveTimeStamp", ref arcTstOrdinal, pool, timestamps, timestampContainers);
            }

            failureReason = null;

            return true;
        }

        if(XmlSignatureModelGrammar.IsElement(table, elementIndex, v141, "SigAndRefsTimeStampV2"u8))
        {
            Increment(unsignedCounts, XAdESBaselineLevelTable.SigAndRefsTimeStampV2.Name);
            if(!XAdESSigAndRefsTimeStampV2.TryRead(table, elementIndex, pool, out XAdESSigAndRefsTimeStampV2? sigRTst, out XAdESReadError sigRTstError))
            {
                failureReason = $"SigAndRefsTimeStampV2 did not read: {sigRTstError.Failure}.";

                return false;
            }

            using(sigRTst)
            {
                CopyTimeStampContainer(table, sigRTst!.TimeStamp, SignatureTimestampClass.ValidationDataTimestamp, "SigAndRefsTimeStampV2", ref validationDataTimestampOrdinal, pool, timestamps, timestampContainers);
            }

            failureReason = null;

            return true;
        }

        if(XmlSignatureModelGrammar.IsElement(table, elementIndex, v141, "RefsOnlyTimeStampV2"u8))
        {
            Increment(unsignedCounts, XAdESBaselineLevelTable.RefsOnlyTimeStampV2.Name);
            if(!XAdESRefsOnlyTimeStampV2.TryRead(table, elementIndex, pool, out XAdESRefsOnlyTimeStampV2? rfsTst, out XAdESReadError rfsTstError))
            {
                failureReason = $"RefsOnlyTimeStampV2 did not read: {rfsTstError.Failure}.";

                return false;
            }

            using(rfsTst)
            {
                CopyTimeStampContainer(table, rfsTst!.TimeStamp, SignatureTimestampClass.ValidationDataTimestamp, "RefsOnlyTimeStampV2", ref validationDataTimestampOrdinal, pool, timestamps, timestampContainers);
            }

            failureReason = null;

            return true;
        }

        if(XmlSignatureModelGrammar.IsElement(table, elementIndex, v141, "CompleteCertificateRefsV2"u8))
        {
            Increment(unsignedCounts, XAdESBaselineLevelTable.CompleteCertificateRefsV2.Name);
            if(!TryReadCompleteCertificateRefs(table, elementIndex, pool, completeCertificateRefs, out string? ccrFailure))
            {
                failureReason = ccrFailure;

                return false;
            }

            validationDataCounts = validationDataCounts with { CompleteCertificateRefsV2Count = validationDataCounts.CompleteCertificateRefsV2Count + 1 };
            failureReason = null;

            return true;
        }

        if(XmlSignatureModelGrammar.IsElement(table, elementIndex, v141, "AttributeCertificateRefsV2"u8))
        {
            Increment(unsignedCounts, XAdESBaselineLevelTable.AttributeCertificateRefsV2.Name);
            if(!TryReadCompleteCertificateRefs(table, elementIndex, pool, attributeCertificateRefs, out string? acrFailure))
            {
                failureReason = acrFailure;

                return false;
            }

            validationDataCounts = validationDataCounts with { AttributeCertificateRefsV2Count = validationDataCounts.AttributeCertificateRefsV2Count + 1 };
            failureReason = null;

            return true;
        }

        if(XmlSignatureModelGrammar.IsElement(table, elementIndex, v141, "SignaturePolicyStore"u8))
        {
            Increment(unsignedCounts, XAdESBaselineLevelTable.SignaturePolicyStore.Name);
            validationDataCounts = validationDataCounts with { SignaturePolicyStoreCount = validationDataCounts.SignaturePolicyStoreCount + 1 };
            failureReason = null;

            return true;
        }

        if(XmlSignatureModelGrammar.IsElement(table, elementIndex, v141, "RenewedDigestsV2"u8))
        {
            Increment(unsignedCounts, XAdESBaselineLevelTable.RenewedDigestsV2.Name);
            validationDataCounts = validationDataCounts with { RenewedDigestsV2Count = validationDataCounts.RenewedDigestsV2Count + 1 };
            failureReason = null;

            return true;
        }

        if(XmlSignatureModelGrammar.IsElement(table, elementIndex, v141, "TimeStampValidationData"u8))
        {
            Increment(unsignedCounts, XAdESBaselineLevelTable.TimeStampValidationDataOption.Name);
            if(!XAdESValidationData.TryReadTimeStampValidationData(table, elementIndex, pool, out XAdESValidationData? tstVD, out XAdESReadError tstVdError))
            {
                failureReason = $"TimeStampValidationData did not read: {tstVdError.Failure}.";

                return false;
            }

            using(tstVD)
            {
                validationDataForTimestampsHasContent |= CopyValidationData(tstVD!, embeddedCertificates, embeddedCrls, embeddedOcsp, pool);
            }

            validationDataCounts = validationDataCounts with { TimeStampValidationDataCount = validationDataCounts.TimeStampValidationDataCount + 1 };
            failureReason = null;

            return true;
        }

        if(XmlSignatureModelGrammar.IsElement(table, elementIndex, v141, "AnyValidationData"u8))
        {
            Increment(unsignedCounts, XAdESBaselineLevelTable.AnyValidationData.Name);
            if(!XAdESValidationData.TryReadAnyValidationData(table, elementIndex, pool, out XAdESValidationData? anyValData, out XAdESReadError anyValDataError))
            {
                failureReason = $"AnyValidationData did not read: {anyValDataError.Failure}.";

                return false;
            }

            using(anyValData)
            {
                validationDataForTimestampsHasContent |= CopyValidationData(anyValData!, embeddedCertificates, embeddedCrls, embeddedOcsp, pool);
            }

            validationDataCounts = validationDataCounts with { AnyValidationDataCount = validationDataCounts.AnyValidationDataCount + 1 };
            failureReason = null;

            return true;
        }

        // Genuinely foreign/unclassified content -- tolerated by this library's own posture, recorded rather than refused. The
        // namespace is recorded alongside the local name in Clark notation: a foreign element deliberately
        // named e.g. ArchiveTimeStamp in an attacker-chosen namespace must stay distinguishable from the real
        // property; Clark notation's braces cannot collide with a namespace URI that itself ends in '#' or
        // '/', unlike a bare separator would.
        unknownProperties.Add($"{{{Utf8(table.NamespaceUriOf(elementIndex))}}}{Utf8(table.LocalNameOf(elementIndex))}");
        failureReason = null;

        return true;
    }


    /// <summary>
    /// Copies a <c>TimeStampValidationData</c>/<c>AnyValidationData</c> occurrence's embedded material into the
    /// signature-wide flattened lists, reporting whether it carried at least one certificate/CRL/OCSP-response
    /// entry — a content signal (<see cref="XAdESQualifyingPropertiesFacts.ValidationDataForTimestampsHasContent"/>),
    /// distinct from mere container presence.
    /// </summary>
    private static bool CopyValidationData(
        XAdESValidationData validationData, List<PkiCertificateMemory> certificates, List<PkiCertificateMemory> crls, List<PkiCertificateMemory> ocsp, BaseMemoryPool pool)
    {
        bool hasContent = false;
        if(validationData.HasCertificateValues && validationData.CertificateValues is XAdESCertificateValues certificateValues)
        {
            for(int i = 0; i < certificateValues.Entries.Count; ++i)
            {
                if(certificateValues.Entries[i].Kind == XAdESCertificateValueKind.EncapsulatedX509Certificate)
                {
                    certificates.Add(CopyCertificate(certificateValues.Entries[i].EncapsulatedX509Certificate.Content.AsReadOnlySpan(), PkiCertificateTags.X509Certificate, pool));
                    hasContent = true;
                }
            }
        }

        if(validationData.HasRevocationValues && validationData.RevocationValues is XAdESRevocationValues revocationValues)
        {
            if(revocationValues.HasCrlValues)
            {
                for(int i = 0; i < revocationValues.CrlValues.Count; ++i)
                {
                    crls.Add(CopyCertificate(revocationValues.CrlValues[i].Content.AsReadOnlySpan(), PkiCertificateTags.X509Crl, pool));
                    hasContent = true;
                }
            }

            if(revocationValues.HasOcspValues)
            {
                for(int i = 0; i < revocationValues.OcspValues.Count; ++i)
                {
                    ocsp.Add(CopyCertificate(revocationValues.OcspValues[i].Content.AsReadOnlySpan(), PkiCertificateTags.OcspResponse, pool));
                    hasContent = true;
                }
            }
        }

        return hasContent;
    }


    private static PkiCertificateMemory CopyCertificate(ReadOnlySpan<byte> bytes, Tag tag, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    private static DigestValue CopyDigest(ReadOnlySpan<byte> bytes, Tag tag, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new DigestValue(owner, tag);
    }


    /// <summary>The <see cref="VerifyXAdESSignatureValueDelegate"/> implementation — see the type remarks for why this composes <see cref="SignedXml"/>.</summary>
    /// <param name="xmlDocument">The XML document octets carrying the <c>ds:Signature</c> to verify.</param>
    /// <param name="signingCertificate">The signing certificate identified by an earlier building block.</param>
    /// <param name="pool">Unused by this implementation (no scratch buffer is rented); present to satisfy the delegate contract.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome in Table 15's vocabulary.</returns>
    public static ValueTask<SignatureCryptographicVerification> VerifyValueAsync(
        ReadOnlyMemory<byte> xmlDocument,
        PkiCertificateMemory signingCertificate,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        cancellationToken.ThrowIfCancellationRequested();

        var document = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        try
        {
            var readerSettings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using var stream = new System.IO.MemoryStream(xmlDocument.ToArray(), writable: false);
            using XmlReader reader = XmlReader.Create(stream, readerSettings);
            document.Load(reader);
        }
        catch(XmlException ex)
        {
            return ValueTask.FromResult(new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.SignedDataNotFound,
                Reason = $"The document is not well-formed XML: {ex.Message}"
            });
        }

        // Single-ds:Signature guard: mirrors XAdESHouseEngineSignatureVerification.VerifyValueAsync's own
        // FindSignatures.Length != 1 refusal, so the twin agrees beyond the crypto-compute axis even on an
        // adversarial multi-ds:Signature input -- confined to test/** and never reachable through ParseAsync's
        // own independent multi-signature refusal (no facts, no Verified<T>, in the real pipeline), but a latent
        // test-oracle divergence otherwise.
        XmlNodeList signatureNodes = document.GetElementsByTagName("Signature", DsNamespace);
        if(signatureNodes.Count != 1 || signatureNodes[0] is not XmlElement signatureElement)
        {
            return ValueTask.FromResult(new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.SignedDataNotFound,
                Reason = $"The document must carry exactly one ds:Signature; found {signatureNodes.Count}."
            });
        }

        var signedXml = new SignedXml(document);
        try
        {
            signedXml.LoadXml(signatureElement);
        }
        catch(Exception ex) when(ex is CryptographicException or FormatException)
        {
            return ValueTask.FromResult(new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.SignedDataNotFound,
                Reason = $"The ds:Signature element did not parse: {ex.Message}"
            });
        }

        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(signingCertificate.AsReadOnlySpan());
        try
        {
            //verifySignatureOnly: identification of the signing certificate is this seam's caller's own job
            //(Table 14's own "Signing Certificate" input); this delegate only checks the cryptography.
            bool verified = signedXml.CheckSignature(certificate, verifySignatureOnly: true);

            //The BCL's CheckSignature does not separate a per-reference digest mismatch from a signature-value
            //mismatch, so both map to SignatureValueFailure -- a documented, coarser-than-Table-15-ideal
            //granularity this test-only composition accepts (see the type remarks).
            return ValueTask.FromResult(verified
                ? new SignatureCryptographicVerification { Outcome = SignatureCryptographicOutcome.Verified, SigningCertificate = signingCertificate }
                : new SignatureCryptographicVerification
                {
                    Outcome = SignatureCryptographicOutcome.SignatureValueFailure,
                    Reason = "The ds:Signature did not verify (message-digest or signature-value check failed)."
                });
        }
        catch(CryptographicException ex)
        {
            return ValueTask.FromResult(new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.SignatureValueFailure,
                Reason = $"The registered verification threw: {ex.Message}"
            });
        }
    }
}
