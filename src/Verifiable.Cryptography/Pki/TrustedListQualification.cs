using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The certificate and trust-service qualification procedures of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4</see>, evaluated over the parsed <see cref="TrustedList"/> model:
/// clause 4.3 (obtaining listed services matching a certificate), clause 4.4 (EU qualified certificate
/// determination), clause 4.5 (QSCD determination), clause 4.6 (EU trust service token issuer qualification
/// determination) and clause 4.7 (EU qualified time stamp determination).
/// </summary>
/// <remarks>
/// <para>
/// <strong>The caller authenticates the trusted list.</strong> The specification's clauses 4.1 and 4.2
/// (authenticating the List Of Trusted Lists and a member state list, including the pivot-LOTL cascade)
/// are fetch-and-verify orchestration this library models through its existing seams
/// (<see cref="ParseTrustedListDelegate"/>, <see cref="VerifyTrustedListSignatureDelegate"/>, and the
/// <see cref="OtherTrustedListPointer"/> data); every procedure here therefore takes an
/// already-authenticated <see cref="TrustedList"/> and never fetches anything. Where the specification's
/// PRO-4.3.4-01/-02 would fail on an unauthenticated or unavailable list, this API's precondition stands
/// in: supplying a list whose <see cref="TrustedListSchemeInformation.SchemeTerritory"/> contradicts the
/// certificate-derived country code throws <see cref="ArgumentException"/> — a composition error, not a
/// determination outcome.
/// </para>
/// <para>
/// <strong>Documented deviations, each an editorial correction or a specification-permitted choice.</strong>
/// PRO-4.4.4-18A and PRO-4.4.4-26A instruct setting <c>CHECK_1</c> to values (<c>"INDET_QC_For_eSeal"</c> /
/// <c>"INDET_QWAC"</c>) that are not in <c>CHECK_1</c>'s domain — obvious editorial slips for <c>CHECK_2</c>
/// and <c>CHECK_3</c>, implemented as such. PRO-4.4.4-33 (f) passes the process without copying the three
/// <c>CHECK</c> values into <c>QC-Results</c>; this implementation reports them (all three are
/// not-qualified indications there, so reporting remains fail-closed). Sub-status values the specification
/// leaves as "appropriate values" are library-defined, which GPR-4.0-01 permits. Sub-status lists use set
/// semantics: repeating an identical indication adds no information.
/// </para>
/// </remarks>
public static class TrustedListQualification
{
    /// <summary>
    /// Resolves a certificate's <c>countryName</c> value to the territory code its member state trusted
    /// list is published under, per PRO-4.4.4-01 / PRO-4.6.4-02: upper-case ISO 3166-1 alpha-2 with
    /// <c>"GB"</c> converted to <c>"UK"</c> and <c>"GR"</c> converted to <c>"EL"</c>.
    /// </summary>
    /// <param name="countryCode">The certificate's country attribute value.</param>
    /// <returns>The trusted-list territory code.</returns>
    public static string ResolveTrustedListTerritory(string countryCode)
    {
        ArgumentNullException.ThrowIfNull(countryCode);

        string upperCased = countryCode.ToUpperInvariant();
        return upperCased switch
        {
            "GB" => "UK",
            "GR" => "EL",
            _ => upperCased
        };
    }


    /// <summary>
    /// Obtains the trust services of <paramref name="trustedList"/> that match
    /// <paramref name="certificate"/> for <paramref name="serviceTypeIdentifier"/> at
    /// <paramref name="evaluationTime"/>, per clause 4.3 (PRO-4.3.4-03 through PRO-4.3.4-11).
    /// </summary>
    /// <param name="trustedList">The authenticated member state trusted list (see the type remarks: clauses 4.1/4.2 are the caller's obligation).</param>
    /// <param name="certificate">The certificate to match (<c>CERT</c>). The caller retains ownership.</param>
    /// <param name="serviceTypeIdentifier">The service type to match (<c>TLS-Sti</c>).</param>
    /// <param name="evaluationTime">The instant to evaluate at (<c>Date-time</c>).</param>
    /// <param name="matchCertificateToService">The seam deciding PRO-4.3.4-03 check (ii) for each candidate service.</param>
    /// <param name="pool">The memory pool the matching seam rents any scratch buffers from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The clause 4.3.3 outputs.</returns>
    public static async ValueTask<ListedServicesMatchResult> ObtainListedServicesMatchingCertificateAsync(
        TrustedList trustedList,
        PkiCertificateMemory certificate,
        TrustServiceTypeIdentifier serviceTypeIdentifier,
        DateTimeOffset evaluationTime,
        MatchCertificateToTrustServiceAsyncDelegate matchCertificateToService,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trustedList);
        ArgumentNullException.ThrowIfNull(matchCertificateToService);
        ArgumentNullException.ThrowIfNull(pool);

        var subStatuses = new List<TrustedListQualificationSubStatus>();
        var matches = new List<MatchedServiceInformation>();

        //PRO-4.3.4-03: every service whose type identifier matches and whose digital identity recognises
        //the certificate contributes a tuple, with the state applicable at the evaluation time.
        foreach(TrustServiceProvider provider in trustedList.TrustServiceProviders)
        {
            foreach(TrustService service in provider.Services)
            {
                if(!string.Equals(service.ServiceTypeIdentifier.Value, serviceTypeIdentifier.Value, StringComparison.Ordinal))
                {
                    continue;
                }

                if(!await matchCertificateToService(certificate, service.DigitalIdentity, evaluationTime, pool, cancellationToken).ConfigureAwait(false))
                {
                    continue;
                }

                TrustServiceStateAtTime? state = SelectStateAtTime(service, evaluationTime);
                if(state is null)
                {
                    //No state of this service covered the evaluation time (the service was first listed
                    //later): there is nothing the list confirms about the certificate at that instant, so
                    //the service contributes no tuple. PRO-4.3.4-03 (b) enumerates only the covered cases.
                    continue;
                }

                matches.Add(new MatchedServiceInformation
                {
                    Service = service,
                    StateAtTime = state,
                    ProviderNames = provider.Names,
                    ProviderTradeNames = provider.TradeNames,
                    DigitalIdentity = service.DigitalIdentity
                });
            }
        }

        //PRO-4.3.4-03A: the history instances of every matched service must be in strictly descending
        //status-starting-time order; a disorder or an exact duplicate stops the process with an error.
        foreach(MatchedServiceInformation match in matches)
        {
            for(int i = 1; i < match.Service.History.Count; ++i)
            {
                if(match.Service.History[i - 1].StatusStartingTime <= match.Service.History[i].StatusStartingTime)
                {
                    AddUnique(subStatuses, TrustedListQualificationSubStatus.ErrorServiceHistoryOrder);
                    return new ListedServicesMatchResult
                    {
                        Status = TrustedListProcessStatus.Failed,
                        SubStatuses = subStatuses,
                        Matches = matches
                    };
                }
            }
        }

        //PRO-4.3.4-05 through PRO-4.3.4-10: duplication indications per additional-service-information
        //type. PRO-4.3.4-04 sets the passed status these can only supplement.
        AddDuplicationIndications(matches, subStatuses, TrustServiceAdditionalInformationType.ForElectronicSignatures, TrustedListQualificationSubStatus.WarningType1Duplication, TrustedListQualificationSubStatus.ErrorType1Duplication);
        AddDuplicationIndications(matches, subStatuses, TrustServiceAdditionalInformationType.ForElectronicSeals, TrustedListQualificationSubStatus.WarningType2Duplication, TrustedListQualificationSubStatus.ErrorType2Duplication);
        AddDuplicationIndications(matches, subStatuses, TrustServiceAdditionalInformationType.ForWebSiteAuthentication, TrustedListQualificationSubStatus.WarningType3Duplication, TrustedListQualificationSubStatus.ErrorType3Duplication);

        //PRO-4.3.4-11: matches spread across providers with different names cannot be soundly attributed.
        if(HasProviderNameConflict(matches))
        {
            AddUnique(subStatuses, TrustedListQualificationSubStatus.ErrorTrustServiceProviderConflict);
            return new ListedServicesMatchResult
            {
                Status = TrustedListProcessStatus.Failed,
                SubStatuses = subStatuses,
                Matches = matches
            };
        }

        return new ListedServicesMatchResult
        {
            Status = TrustedListProcessStatus.Passed,
            SubStatuses = subStatuses,
            Matches = matches
        };


        /// <summary>PRO-4.3.4-03 (b): the current information when the evaluation time is at or after its start, else the first (newest-first) history instance whose start is at or before the evaluation time.</summary>
        static TrustServiceStateAtTime? SelectStateAtTime(TrustService service, DateTimeOffset evaluationTime)
        {
            if(evaluationTime >= service.StatusStartingTime)
            {
                return TrustServiceStateAtTime.FromCurrent(service);
            }

            foreach(TrustServiceHistoryEntry entry in service.History)
            {
                if(entry.StatusStartingTime <= evaluationTime)
                {
                    return TrustServiceStateAtTime.FromHistory(entry);
                }
            }

            return null;
        }


        /// <summary>PRO-4.3.4-05 through PRO-4.3.4-10: among matches asserting <paramref name="informationType"/>, an identical-status pair adds the warning and a differing-status pair adds the error.</summary>
        static void AddDuplicationIndications(
            List<MatchedServiceInformation> matches,
            List<TrustedListQualificationSubStatus> subStatuses,
            TrustServiceAdditionalInformationType informationType,
            TrustedListQualificationSubStatus identicalStatusWarning,
            TrustedListQualificationSubStatus differingStatusError)
        {
            var statuses = new List<TrustServiceStatus>();
            foreach(MatchedServiceInformation match in matches)
            {
                if(ContainsInformationType(match.StateAtTime.AdditionalServiceInformation, informationType))
                {
                    statuses.Add(match.StateAtTime.Status);
                }
            }

            if(statuses.Count < 2)
            {
                return;
            }

            bool anyIdentical = false;
            bool anyDiffering = false;
            for(int i = 0; i < statuses.Count; ++i)
            {
                for(int j = i + 1; j < statuses.Count; ++j)
                {
                    if(string.Equals(statuses[i].Value, statuses[j].Value, StringComparison.Ordinal))
                    {
                        anyIdentical = true;
                    }
                    else
                    {
                        anyDiffering = true;
                    }
                }
            }

            if(anyIdentical)
            {
                AddUnique(subStatuses, identicalStatusWarning);
            }

            if(anyDiffering)
            {
                AddUnique(subStatuses, differingStatusError);
            }
        }


        /// <summary>PRO-4.3.4-11: whether two matches carry provider names that are not value-equal.</summary>
        static bool HasProviderNameConflict(List<MatchedServiceInformation> matches)
        {
            for(int i = 1; i < matches.Count; ++i)
            {
                if(!LocalizedTextListsEqual(matches[0].ProviderNames, matches[i].ProviderNames))
                {
                    return true;
                }
            }

            return false;
        }


        /// <summary>Compares two localized-name lists by value (language and text, ordinal).</summary>
        static bool LocalizedTextListsEqual(IReadOnlyList<LocalizedText> first, IReadOnlyList<LocalizedText> second)
        {
            if(first.Count != second.Count)
            {
                return false;
            }

            for(int i = 0; i < first.Count; ++i)
            {
                if(!string.Equals(first[i].Language, second[i].Language, StringComparison.Ordinal)
                    || !string.Equals(first[i].Value, second[i].Value, StringComparison.Ordinal))
                {
                    return false;
                }
            }

            return true;
        }
    }


    /// <summary>
    /// Determines whether <paramref name="certificate"/> was an EU qualified certificate, and of which
    /// type, at <paramref name="evaluationTime"/> according to <paramref name="trustedList"/>, per
    /// clause 4.4 — including the PRO-4.4.4-34/-36 re-determination at the certificate's NotBefore instant
    /// and the comparison of the two.
    /// </summary>
    /// <param name="trustedList">The authenticated trusted list of the member state named by the certificate's issuer country (see the type remarks).</param>
    /// <param name="certificate">The certificate to determine (<c>CERT</c>). The caller retains ownership.</param>
    /// <param name="certificateFacts">The certificate's extracted facts.</param>
    /// <param name="evaluationTime">The instant to evaluate at (<c>Date-time</c>).</param>
    /// <param name="matchCertificateToService">The seam deciding PRO-4.3.4-03 check (ii) for each candidate service.</param>
    /// <param name="pool">The memory pool the matching seam rents any scratch buffers from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The clause 4.4.3 outputs.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="trustedList"/>'s scheme territory contradicts the certificate's issuer country (a composition error; see the type remarks).</exception>
    public static async ValueTask<EuQualifiedCertificateDeterminationResult> DetermineEuQualifiedCertificateAsync(
        TrustedList trustedList,
        PkiCertificateMemory certificate,
        QualifiedCertificateFacts certificateFacts,
        DateTimeOffset evaluationTime,
        MatchCertificateToTrustServiceAsyncDelegate matchCertificateToService,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trustedList);
        ArgumentNullException.ThrowIfNull(certificateFacts);
        ArgumentNullException.ThrowIfNull(matchCertificateToService);
        ArgumentNullException.ThrowIfNull(pool);

        EnsureTerritoryConsistency(trustedList, certificateFacts.IssuerCountryCode);

        SinglePassDetermination firstPass = await DetermineSinglePassAsync(
            trustedList, certificate, certificateFacts, evaluationTime, matchCertificateToService, pool, cancellationToken).ConfigureAwait(false);
        if(!firstPass.ContinueToNotBeforeComparison)
        {
            return firstPass.ToResult();
        }

        //PRO-4.4.4-34: the determination is repeated at the certificate's NotBefore instant; a certificate
        //whose qualification differs between issuance and the evaluation time is not confirmable.
        SinglePassDetermination notBeforePass = await DetermineSinglePassAsync(
            trustedList, certificate, certificateFacts, certificateFacts.NotBefore, matchCertificateToService, pool, cancellationToken).ConfigureAwait(false);

        //PRO-4.4.4-35: a failed NotBefore run fails the whole determination.
        if(notBeforePass.Status == TrustedListProcessStatus.Failed)
        {
            AddUnique(firstPass.SubStatuses, TrustedListQualificationSubStatus.Propagated(TrustedListProcessStatusMapping.ToWireValue(notBeforePass.Status)));
            foreach(TrustedListQualificationSubStatus subStatus in notBeforePass.SubStatuses)
            {
                AddUnique(firstPass.SubStatuses, subStatus);
            }

            firstPass.Status = TrustedListProcessStatus.Failed;
            return firstPass.ToResult();
        }

        //PRO-4.4.4-36 (a): the two indication sets must be exactly equal.
        if(!IndicationSetsEqual(firstPass.Indications, notBeforePass.Indications))
        {
            AddUnique(firstPass.SubStatuses, TrustedListQualificationSubStatus.ErrorIndicationsDifferBetweenEvaluationTimeAndNotBefore);
            firstPass.Status = TrustedListProcessStatus.Failed;
            return firstPass.ToResult();
        }

        //PRO-4.4.4-36 (b): warnings from the NotBefore run surface on the overall outcome.
        if(notBeforePass.Status == TrustedListProcessStatus.PassedWithWarning)
        {
            firstPass.Status = TrustedListProcessStatus.PassedWithWarning;
            AddUnique(firstPass.SubStatuses, TrustedListQualificationSubStatus.Propagated(TrustedListProcessStatusMapping.ToWireValue(notBeforePass.Status)));
            foreach(TrustedListQualificationSubStatus subStatus in notBeforePass.SubStatuses)
            {
                AddUnique(firstPass.SubStatuses, subStatus);
            }
        }

        return firstPass.ToResult();


        /// <summary>PRO-4.4.4-36 (a): set equality of the indication multisets (each side is duplicate-free by construction).</summary>
        static bool IndicationSetsEqual(List<EuQualifiedCertificateIndication> first, List<EuQualifiedCertificateIndication> second)
        {
            if(first.Count != second.Count)
            {
                return false;
            }

            foreach(EuQualifiedCertificateIndication indication in first)
            {
                if(!second.Contains(indication))
                {
                    return false;
                }
            }

            return true;
        }
    }


    /// <summary>
    /// Determines whether the private key of <paramref name="certificate"/> resided in a qualified
    /// electronic signature/seal creation device at <paramref name="evaluationTime"/> according to
    /// <paramref name="trustedList"/>, per clause 4.5.
    /// </summary>
    /// <param name="trustedList">The authenticated trusted list of the member state named by the certificate's issuer country (see the type remarks).</param>
    /// <param name="certificate">The certificate to determine (<c>CERT</c>). The caller retains ownership.</param>
    /// <param name="certificateFacts">The certificate's extracted facts.</param>
    /// <param name="evaluationTime">The instant to evaluate at (<c>Date-time</c>).</param>
    /// <param name="matchCertificateToService">The seam deciding PRO-4.3.4-03 check (ii) for each candidate service.</param>
    /// <param name="pool">The memory pool the matching seam rents any scratch buffers from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The clause 4.5.3 outputs.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="trustedList"/>'s scheme territory contradicts the certificate's issuer country (a composition error; see the type remarks).</exception>
    public static async ValueTask<QualifiedSignatureCreationDeviceDeterminationResult> DetermineQualifiedSignatureCreationDeviceAsync(
        TrustedList trustedList,
        PkiCertificateMemory certificate,
        QualifiedCertificateFacts certificateFacts,
        DateTimeOffset evaluationTime,
        MatchCertificateToTrustServiceAsyncDelegate matchCertificateToService,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificateFacts);

        //PRO-4.5.4-01: the certificate determination runs first; the device information in a trusted list
        //exists only for qualified certificates of a determined type.
        EuQualifiedCertificateDeterminationResult certificateDetermination = await DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, certificateFacts, evaluationTime, matchCertificateToService, pool, cancellationToken).ConfigureAwait(false);

        var subStatuses = new List<TrustedListQualificationSubStatus>();

        //PRO-4.5.4-02: a failed certificate determination fails the device determination.
        if(certificateDetermination.Status == TrustedListProcessStatus.Failed)
        {
            AddUnique(subStatuses, TrustedListQualificationSubStatus.Propagated(TrustedListProcessStatusMapping.ToWireValue(certificateDetermination.Status)));
            foreach(TrustedListQualificationSubStatus subStatus in certificateDetermination.SubStatuses)
            {
                AddUnique(subStatuses, subStatus);
            }

            return new QualifiedSignatureCreationDeviceDeterminationResult
            {
                Status = TrustedListProcessStatus.Failed,
                SubStatuses = subStatuses,
                Indication = null
            };
        }

        //PRO-4.5.4-03: the Directive regime knows only SSCD terminology and only signature certificates.
        if(evaluationTime < TrustedListQualificationWellKnown.EidasRegulationApplicationInstant)
        {
            if(!certificateDetermination.Indications.Contains(EuQualifiedCertificateIndication.QualifiedForESignature))
            {
                return new QualifiedSignatureCreationDeviceDeterminationResult
                {
                    Status = TrustedListProcessStatus.Passed,
                    SubStatuses = subStatuses,
                    Indication = QualifiedSignatureCreationDeviceIndication.Indeterminate
                };
            }

            var directiveQualifiers = CollectQualifierValues(certificateDetermination.ESignatureQualificationElements);
            bool withSscd = directiveQualifiers.Contains(ServiceQualifier.WithSscd.Value);
            bool noSscd = directiveQualifiers.Contains(ServiceQualifier.NoSscd.Value);
            bool sscdAsInCertificate = directiveQualifiers.Contains(ServiceQualifier.SscdStatusAsInCertificate.Value);

            //PRO-4.5.4-03 (a) (2): mutually inconsistent SSCD qualifiers make the device status unknowable.
            if((withSscd && noSscd) || (sscdAsInCertificate && withSscd) || (sscdAsInCertificate && noSscd))
            {
                AddUnique(subStatuses, TrustedListQualificationSubStatus.WarningSscdQualifierInconsistency);
                return new QualifiedSignatureCreationDeviceDeterminationResult
                {
                    Status = TrustedListProcessStatus.PassedWithWarning,
                    SubStatuses = subStatuses,
                    Indication = QualifiedSignatureCreationDeviceIndication.Indeterminate
                };
            }

            //PRO-4.5.4-03 (a) (3)-(4): Table 6 over the certificate's QcSSCD statement / QCP+ policy and
            //the trusted list's SSCD qualifier.
            bool certificateAssertsDevice = certificateFacts.HasQcSscdStatement
                || ContainsOrdinal(certificateFacts.CertificatePolicyOids, WellKnownOids.QcpPublicWithSscd);
            QualifiedSignatureCreationDeviceIndication directiveIndication = (withSscd, noSscd) switch
            {
                (true, _) => QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice,
                (_, true) => QualifiedSignatureCreationDeviceIndication.PrivateKeyNotOnDevice,
                _ => certificateAssertsDevice
                    ? QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice
                    : QualifiedSignatureCreationDeviceIndication.PrivateKeyNotOnDevice
            };

            return new QualifiedSignatureCreationDeviceDeterminationResult
            {
                Status = TrustedListProcessStatus.Passed,
                SubStatuses = subStatuses,
                Indication = directiveIndication
            };
        }

        //PRO-4.5.4-04 / PRO-4.5.4-05: the Regulation regime reads QSCD qualifiers from the qualification
        //elements of the determined type (electronic signature or electronic seal).
        IReadOnlyList<QualificationElement> applicableElements;
        if(certificateDetermination.Indications.Contains(EuQualifiedCertificateIndication.QualifiedForESignature))
        {
            applicableElements = certificateDetermination.ESignatureQualificationElements;
        }
        else if(certificateDetermination.Indications.Contains(EuQualifiedCertificateIndication.QualifiedForESeal))
        {
            applicableElements = certificateDetermination.ESealQualificationElements;
        }
        else
        {
            return new QualifiedSignatureCreationDeviceDeterminationResult
            {
                Status = TrustedListProcessStatus.Passed,
                SubStatuses = subStatuses,
                Indication = QualifiedSignatureCreationDeviceIndication.Indeterminate
            };
        }

        //PRO-4.5.4-04 (b): a qualifier this implementation does not know fails the determination when its
        //carrying extension was critical and only warns otherwise.
        foreach(QualificationElement element in applicableElements)
        {
            foreach(ServiceQualifier qualifier in element.Qualifiers)
            {
                if(!KnownCertificateQualifierValues.Contains(qualifier.Value))
                {
                    if(element.IsCritical)
                    {
                        AddUnique(subStatuses, TrustedListQualificationSubStatus.ErrorUnknownCriticalQualifiers);
                        return new QualifiedSignatureCreationDeviceDeterminationResult
                        {
                            Status = TrustedListProcessStatus.Failed,
                            SubStatuses = subStatuses,
                            Indication = null
                        };
                    }

                    AddUnique(subStatuses, TrustedListQualificationSubStatus.WarningUnknownQualifiers);
                }
            }
        }

        var qualifierValues = CollectQualifierValues(applicableElements);
        bool withQscd = qualifierValues.Contains(ServiceQualifier.WithQscd.Value);
        bool noQscd = qualifierValues.Contains(ServiceQualifier.NoQscd.Value);
        bool managedOnBehalf = qualifierValues.Contains(ServiceQualifier.QscdManagedOnBehalf.Value);
        bool qscdAsInCertificate = qualifierValues.Contains(ServiceQualifier.QscdStatusAsInCertificate.Value);
        bool legacyWithSscd = qualifierValues.Contains(ServiceQualifier.WithSscd.Value);
        bool legacyNoSscd = qualifierValues.Contains(ServiceQualifier.NoSscd.Value);

        //PRO-4.5.4-04 (c): mutually inconsistent QSCD qualifiers (including the TLv5 SSCD terminology
        //appearing without its Regulation counterpart) make the device status unknowable.
        if((legacyWithSscd && !withQscd)
            || (legacyNoSscd && !noQscd)
            || (withQscd && noQscd)
            || (managedOnBehalf && noQscd)
            || (qscdAsInCertificate && (withQscd || noQscd || managedOnBehalf)))
        {
            AddUnique(subStatuses, TrustedListQualificationSubStatus.WarningQscdQualifierInconsistency);
            return new QualifiedSignatureCreationDeviceDeterminationResult
            {
                Status = TrustedListProcessStatus.PassedWithWarning,
                SubStatuses = subStatuses,
                Indication = QualifiedSignatureCreationDeviceIndication.Indeterminate
            };
        }

        //PRO-4.5.4-04 (d)-(e): Table 7 over the certificate's QcSSCD statement and the trusted list's
        //QSCD qualifier.
        QualifiedSignatureCreationDeviceIndication indication = (withQscd || managedOnBehalf, noQscd) switch
        {
            (true, _) => QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice,
            (_, true) => QualifiedSignatureCreationDeviceIndication.PrivateKeyNotOnDevice,
            _ => certificateFacts.HasQcSscdStatement
                ? QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice
                : QualifiedSignatureCreationDeviceIndication.PrivateKeyNotOnDevice
        };

        return new QualifiedSignatureCreationDeviceDeterminationResult
        {
            Status = TrustedListProcessStatus.Passed,
            SubStatuses = subStatuses,
            Indication = indication
        };
    }


    /// <summary>
    /// Determines whether the issuer identified by <paramref name="certificate"/> was an EU qualified
    /// trust service provider for <paramref name="serviceTypeIdentifier"/> at
    /// <paramref name="evaluationTime"/> according to <paramref name="trustedList"/>, per clause 4.6.
    /// </summary>
    /// <param name="trustedList">The authenticated trusted list of the member state named by the certificate's SUBJECT country (PRO-4.6.4-02; see the type remarks).</param>
    /// <param name="certificate">The trust service token signer's certificate (<c>CERT</c>). The caller retains ownership.</param>
    /// <param name="certificateFacts">The certificate's extracted facts.</param>
    /// <param name="serviceTypeIdentifier">The service type whose qualification is asked about (<c>TLS-Sti</c>).</param>
    /// <param name="evaluationTime">The instant to evaluate at (<c>Date-time</c>).</param>
    /// <param name="matchCertificateToService">The seam deciding PRO-4.3.4-03 check (ii) for each candidate service.</param>
    /// <param name="pool">The memory pool the matching seam rents any scratch buffers from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The clause 4.6.3 outputs.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="trustedList"/>'s scheme territory contradicts the certificate's subject country (a composition error; see the type remarks).</exception>
    public static async ValueTask<TrustServiceTokenIssuerQualificationResult> DetermineTrustServiceTokenIssuerQualificationAsync(
        TrustedList trustedList,
        PkiCertificateMemory certificate,
        QualifiedCertificateFacts certificateFacts,
        TrustServiceTypeIdentifier serviceTypeIdentifier,
        DateTimeOffset evaluationTime,
        MatchCertificateToTrustServiceAsyncDelegate matchCertificateToService,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trustedList);
        ArgumentNullException.ThrowIfNull(certificateFacts);

        var subStatuses = new List<TrustedListQualificationSubStatus>();

        //PRO-4.6.4-01: no service was EU qualified before the Regulation applied.
        if(evaluationTime < TrustedListQualificationWellKnown.EidasRegulationApplicationInstant)
        {
            return new TrustServiceTokenIssuerQualificationResult
            {
                Status = TrustedListProcessStatus.Passed,
                SubStatuses = subStatuses,
                Indication = TrustServiceTokenIssuerIndication.NotQualified,
                ProviderNames = []
            };
        }

        //PRO-4.6.4-02: the provider's own member state comes from the certificate's SUBJECT country.
        if(certificateFacts.SubjectCountryCode is null)
        {
            AddUnique(subStatuses, TrustedListQualificationSubStatus.CountryCodeNotRepresentingEuMemberState);
            return new TrustServiceTokenIssuerQualificationResult
            {
                Status = TrustedListProcessStatus.Failed,
                SubStatuses = subStatuses,
                Indication = TrustServiceTokenIssuerIndication.Indeterminate,
                ProviderNames = []
            };
        }

        EnsureTerritoryConsistency(trustedList, certificateFacts.SubjectCountryCode);

        //PRO-4.6.4-03: the clause 4.3 matching runs for the requested service type.
        ListedServicesMatchResult serviceMatch = await ObtainListedServicesMatchingCertificateAsync(
            trustedList, certificate, serviceTypeIdentifier, evaluationTime, matchCertificateToService, pool, cancellationToken).ConfigureAwait(false);

        //PRO-4.6.4-04: a failed matching leaves the qualification indeterminate.
        if(serviceMatch.Status == TrustedListProcessStatus.Failed)
        {
            AddUnique(subStatuses, TrustedListQualificationSubStatus.Propagated(TrustedListProcessStatusMapping.ToWireValue(serviceMatch.Status)));
            foreach(TrustedListQualificationSubStatus subStatus in serviceMatch.SubStatuses)
            {
                AddUnique(subStatuses, subStatus);
            }

            return new TrustServiceTokenIssuerQualificationResult
            {
                Status = TrustedListProcessStatus.Failed,
                SubStatuses = subStatuses,
                Indication = TrustServiceTokenIssuerIndication.Indeterminate,
                ProviderNames = []
            };
        }

        //PRO-4.6.4-05: no matching service means the provider is not confirmed as qualified.
        if(serviceMatch.Matches.Count == 0)
        {
            return new TrustServiceTokenIssuerQualificationResult
            {
                Status = TrustedListProcessStatus.Passed,
                SubStatuses = subStatuses,
                Indication = TrustServiceTokenIssuerIndication.NotQualified,
                ProviderNames = []
            };
        }

        //PRO-4.6.4-06: conflicting statuses among matches make the qualification indeterminate.
        for(int i = 1; i < serviceMatch.Matches.Count; ++i)
        {
            if(!string.Equals(serviceMatch.Matches[0].StateAtTime.Status.Value, serviceMatch.Matches[i].StateAtTime.Status.Value, StringComparison.Ordinal))
            {
                AddUnique(subStatuses, TrustedListQualificationSubStatus.ErrorTokenIssuerStatusInconsistency);
                return new TrustServiceTokenIssuerQualificationResult
                {
                    Status = TrustedListProcessStatus.Failed,
                    SubStatuses = subStatuses,
                    Indication = TrustServiceTokenIssuerIndication.Indeterminate,
                    ProviderNames = []
                };
            }
        }

        //PRO-4.6.4-07: consistent statuses but different service keys still indicate a duplication worth
        //surfacing. Keys are compared through the library's managed certificate reader; a pair whose key
        //material it does not recognise is not compared.
        if(HasDifferingServiceKeys(serviceMatch.Matches))
        {
            AddUnique(subStatuses, TrustedListQualificationSubStatus.WarningTokenIssuerServiceInformationDuplication);
        }

        //PRO-4.6.4-08: the certificate's subject organization must identify the matched provider.
        if(!AnyNameMatches(certificateFacts.SubjectOrganizationNames, serviceMatch.Matches))
        {
            AddUnique(subStatuses, TrustedListQualificationSubStatus.ErrorTokenIssuerNameInconsistency);
            return new TrustServiceTokenIssuerQualificationResult
            {
                Status = TrustedListProcessStatus.Failed,
                SubStatuses = subStatuses,
                Indication = TrustServiceTokenIssuerIndication.Indeterminate,
                ProviderNames = []
            };
        }

        //PRO-4.6.4-09: granted at the evaluation time means qualified; any other status means not.
        bool granted = serviceMatch.Matches[0].StateAtTime.Status.IsGranted;
        TrustedListProcessStatus finalStatus = subStatuses.Count > 0
            ? TrustedListProcessStatus.PassedWithWarning
            : TrustedListProcessStatus.Passed;
        return new TrustServiceTokenIssuerQualificationResult
        {
            Status = finalStatus,
            SubStatuses = subStatuses,
            Indication = granted ? TrustServiceTokenIssuerIndication.Qualified : TrustServiceTokenIssuerIndication.NotQualified,
            ProviderNames = serviceMatch.Matches[0].ProviderNames
        };


        /// <summary>PRO-4.6.4-07: whether two matches carry recognisably different public keys in their digital identities.</summary>
        static bool HasDifferingServiceKeys(IReadOnlyList<MatchedServiceInformation> matches)
        {
            for(int i = 1; i < matches.Count; ++i)
            {
                if(TryGetComparableKey(matches[0].DigitalIdentity, out ReadOnlyMemory<byte> firstKey)
                    && TryGetComparableKey(matches[i].DigitalIdentity, out ReadOnlyMemory<byte> otherKey)
                    && !firstKey.Span.SequenceEqual(otherKey.Span))
                {
                    return true;
                }
            }

            return false;
        }


        /// <summary>Extracts a comparable public-key representation from the identity's first certificate entry via the managed reader; false when none is recognised.</summary>
        static bool TryGetComparableKey(ServiceDigitalIdentity identity, out ReadOnlyMemory<byte> key)
        {
            foreach(ServiceDigitalIdentityEntry entry in identity.Entries)
            {
                if(entry is X509CertificateIdentity certificateEntry)
                {
                    try
                    {
                        ManagedCertificate parsed = ManagedCertificate.Parse(certificateEntry.Certificate.AsReadOnlySpan().ToArray());
                        if(!parsed.PublicPoint.IsEmpty)
                        {
                            key = parsed.PublicPoint;
                            return true;
                        }

                        if(!parsed.RsaModulus.IsEmpty)
                        {
                            key = parsed.RsaModulus;
                            return true;
                        }
                    }
                    catch(System.Security.Cryptography.CryptographicException)
                    {
                        //An unparseable certificate entry contributes no comparable key; the next entry may.
                    }
                }
            }

            key = default;
            return false;
        }


        /// <summary>PRO-4.6.4-08: whether any subject organization name identifies any matched provider by legal or trade name.</summary>
        static bool AnyNameMatches(IReadOnlyList<string> organizationNames, IReadOnlyList<MatchedServiceInformation> matches)
        {
            foreach(string organizationName in organizationNames)
            {
                foreach(MatchedServiceInformation match in matches)
                {
                    if(MatchesAnyLocalizedName(organizationName, match.ProviderNames) || MatchesAnyLocalizedName(organizationName, match.ProviderTradeNames))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Determines whether a time stamp token was an EU qualified electronic time stamp, per clause 4.7:
    /// the clause 4.6 determination for the
    /// <see cref="TrustServiceTypeIdentifier.QualifiedTimeStampAuthority"/> service type, run both at
    /// <paramref name="evaluationTime"/> and at the token's <paramref name="tokenGenerationTime"/>, with
    /// the two outcomes required to agree (PRO-4.7.4-06).
    /// </summary>
    /// <param name="trustedList">The authenticated trusted list of the member state named by the certificate's subject country (see the type remarks).</param>
    /// <param name="certificate">The time stamp token signer's certificate. The caller retains ownership.</param>
    /// <param name="certificateFacts">The certificate's extracted facts.</param>
    /// <param name="evaluationTime">The instant to evaluate at (<c>Date-time</c>).</param>
    /// <param name="tokenGenerationTime">The token's generation time (for example RFC 3161 <c>TSTInfo.genTime</c>), which the caller reads from the already-validated token.</param>
    /// <param name="matchCertificateToService">The seam deciding PRO-4.3.4-03 check (ii) for each candidate service.</param>
    /// <param name="pool">The memory pool the matching seam rents any scratch buffers from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The clause 4.7.3 outputs.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="trustedList"/>'s scheme territory contradicts the certificate's subject country (a composition error; see the type remarks).</exception>
    public static async ValueTask<TrustServiceTokenIssuerQualificationResult> DetermineEuQualifiedTimeStampAsync(
        TrustedList trustedList,
        PkiCertificateMemory certificate,
        QualifiedCertificateFacts certificateFacts,
        DateTimeOffset evaluationTime,
        DateTimeOffset tokenGenerationTime,
        MatchCertificateToTrustServiceAsyncDelegate matchCertificateToService,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        //PRO-4.7.4-01 through PRO-4.7.4-03: the token issuer determination at the evaluation time is the
        //reported outcome.
        TrustServiceTokenIssuerQualificationResult atEvaluationTime = await DetermineTrustServiceTokenIssuerQualificationAsync(
            trustedList, certificate, certificateFacts, TrustServiceTypeIdentifier.QualifiedTimeStampAuthority, evaluationTime, matchCertificateToService, pool, cancellationToken).ConfigureAwait(false);

        //PRO-4.7.4-04: the same determination at the token's generation time.
        TrustServiceTokenIssuerQualificationResult atGenerationTime = await DetermineTrustServiceTokenIssuerQualificationAsync(
            trustedList, certificate, certificateFacts, TrustServiceTypeIdentifier.QualifiedTimeStampAuthority, tokenGenerationTime, matchCertificateToService, pool, cancellationToken).ConfigureAwait(false);

        //PRO-4.7.4-05: a failed generation-time run fails the whole determination.
        if(atGenerationTime.Status == TrustedListProcessStatus.Failed)
        {
            var failedSubStatuses = new List<TrustedListQualificationSubStatus>(atEvaluationTime.SubStatuses);
            AddUnique(failedSubStatuses, TrustedListQualificationSubStatus.Propagated(TrustedListProcessStatusMapping.ToWireValue(atGenerationTime.Status)));
            foreach(TrustedListQualificationSubStatus subStatus in atGenerationTime.SubStatuses)
            {
                AddUnique(failedSubStatuses, subStatus);
            }

            return atEvaluationTime with
            {
                Status = TrustedListProcessStatus.Failed,
                SubStatuses = failedSubStatuses
            };
        }

        //PRO-4.7.4-06: the two runs must reach the same indication.
        if(atEvaluationTime.Indication != atGenerationTime.Indication)
        {
            var differingSubStatuses = new List<TrustedListQualificationSubStatus>(atEvaluationTime.SubStatuses);
            AddUnique(differingSubStatuses, TrustedListQualificationSubStatus.ErrorTimeStampIndicationsDifferBetweenEvaluationAndGenerationTime);
            return atEvaluationTime with
            {
                Status = TrustedListProcessStatus.Failed,
                SubStatuses = differingSubStatuses
            };
        }

        return atEvaluationTime;
    }


    /// <summary>The qualifier values ETSI TS 119 612 V2.4.1 clause 5.5.9.2.3 registers for CA/QC services — the "known" set PRO-4.5.4-04 (b) tests against.</summary>
    private static HashSet<string> KnownCertificateQualifierValues { get; } = new(StringComparer.Ordinal)
    {
        ServiceQualifier.ForElectronicSignature.Value,
        ServiceQualifier.ForElectronicSeal.Value,
        ServiceQualifier.ForWebSiteAuthentication.Value,
        ServiceQualifier.ForLegalPerson.Value,
        ServiceQualifier.QualifiedCertificateStatement.Value,
        ServiceQualifier.NotQualified.Value,
        ServiceQualifier.QscdStatusAsInCertificate.Value,
        ServiceQualifier.WithQscd.Value,
        ServiceQualifier.NoQscd.Value,
        ServiceQualifier.QscdManagedOnBehalf.Value,
        ServiceQualifier.SscdStatusAsInCertificate.Value,
        ServiceQualifier.WithSscd.Value,
        ServiceQualifier.NoSscd.Value
    };


    /// <summary>
    /// The outcome of one clause 4.4 determination pass (PRO-4.4.4-01 through PRO-4.4.4-33) — mutable
    /// because the outer determination amends the first pass's status and sub-statuses with the
    /// NotBefore-comparison outcomes of PRO-4.4.4-35/-36.
    /// </summary>
    private sealed class SinglePassDetermination
    {
        /// <summary>The pass's main status.</summary>
        public TrustedListProcessStatus Status { get; set; }

        /// <summary>The pass's accumulated sub-statuses.</summary>
        public List<TrustedListQualificationSubStatus> SubStatuses { get; } = [];

        /// <summary>The pass's determined indications.</summary>
        public List<EuQualifiedCertificateIndication> Indications { get; } = [];

        /// <summary>The for-eSignatures qualification elements whose criteria identified the certificate.</summary>
        public List<QualificationElement> ESignatureQualificationElements { get; } = [];

        /// <summary>The for-eSeals qualification elements whose criteria identified the certificate.</summary>
        public List<QualificationElement> ESealQualificationElements { get; } = [];

        /// <summary>The for-website-authentication qualification elements whose criteria identified the certificate.</summary>
        public List<QualificationElement> WebsiteAuthenticationQualificationElements { get; } = [];

        /// <summary>Whether the pass completed PRO-4.4.4-32 or PRO-4.4.4-33 (rather than stopping earlier), so the outer determination proceeds to the PRO-4.4.4-34 NotBefore comparison.</summary>
        public bool ContinueToNotBeforeComparison { get; set; }


        /// <summary>Projects the pass into the public result shape.</summary>
        public EuQualifiedCertificateDeterminationResult ToResult() => new()
        {
            Status = Status,
            SubStatuses = SubStatuses,
            Indications = Indications,
            ESignatureQualificationElements = ESignatureQualificationElements,
            ESealQualificationElements = ESealQualificationElements,
            WebsiteAuthenticationQualificationElements = WebsiteAuthenticationQualificationElements
        };
    }


    /// <summary>
    /// One clause 4.4 determination pass: PRO-4.4.4-01 through PRO-4.4.4-32 (Regulation regime) or
    /// PRO-4.4.4-33 (Directive regime), without the PRO-4.4.4-34 re-run — exactly the scope PRO-4.4.4-34
    /// prescribes for its own inner run.
    /// </summary>
    private static async ValueTask<SinglePassDetermination> DetermineSinglePassAsync(
        TrustedList trustedList,
        PkiCertificateMemory certificate,
        QualifiedCertificateFacts certificateFacts,
        DateTimeOffset evaluationTime,
        MatchCertificateToTrustServiceAsyncDelegate matchCertificateToService,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        var pass = new SinglePassDetermination();

        //PRO-4.4.4-01: the member state is named by the certificate's issuer country; a certificate that
        //names none cannot select a trusted list, which surfaces as the clause 4.3 country failure.
        if(certificateFacts.IssuerCountryCode is null)
        {
            pass.Status = TrustedListProcessStatus.Failed;
            AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.CountryCodeNotRepresentingEuMemberState);
            return pass;
        }

        //PRO-4.4.4-02/-03: the clause 4.3 matching for CA/QC services at the pass's evaluation time.
        ListedServicesMatchResult serviceMatch = await ObtainListedServicesMatchingCertificateAsync(
            trustedList, certificate, TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates, evaluationTime, matchCertificateToService, pool, cancellationToken).ConfigureAwait(false);

        //PRO-4.4.4-04: a failed matching fails the determination.
        if(serviceMatch.Status == TrustedListProcessStatus.Failed)
        {
            pass.Status = TrustedListProcessStatus.Failed;
            AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.Propagated(TrustedListProcessStatusMapping.ToWireValue(serviceMatch.Status)));
            foreach(TrustedListQualificationSubStatus subStatus in serviceMatch.SubStatuses)
            {
                AddUnique(pass.SubStatuses, subStatus);
            }

            return pass;
        }

        //PRO-4.4.4-05: no match means the list simply does not confirm the certificate.
        if(serviceMatch.Matches.Count == 0)
        {
            pass.Status = TrustedListProcessStatus.Passed;
            AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.NoConfirmationFound);
            pass.Indications.Add(EuQualifiedCertificateIndication.NotQualified);
            return pass;
        }

        //PRO-4.4.4-06: the certificate's issuer must identify the matched provider — by organization name
        //when the issuer carries one, else by the fallback strategies (common name against the provider
        //names, or the issuer distinguished name against a subject-name digital identity).
        if(!IssuerIdentifiesProvider(certificateFacts, serviceMatch.Matches))
        {
            pass.Status = TrustedListProcessStatus.Failed;
            pass.Indications.Add(EuQualifiedCertificateIndication.Indeterminate);
            AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.ErrorTrustServiceProviderNameInconsistency);
            return pass;
        }

        //PRO-4.4.4-07: either instant preceding the Regulation routes the pass to the Directive regime.
        if(evaluationTime < TrustedListQualificationWellKnown.EidasRegulationApplicationInstant || certificateFacts.NotBefore < TrustedListQualificationWellKnown.EidasRegulationApplicationInstant)
        {
            DetermineUnderDirectiveRegime(pass, serviceMatch, certificateFacts, evaluationTime);
            return pass;
        }

        //PRO-4.4.4-08 through PRO-4.4.4-15: CHECK_1, the for-eSignatures dimension.
        (EuQualifiedCertificateIndication check1, List<QualificationElement> check1Elements) = DetermineDimension(
            pass,
            serviceMatch,
            certificateFacts,
            TrustServiceAdditionalInformationType.ForElectronicSignatures,
            ServiceQualifier.ForElectronicSignature,
            [ServiceQualifier.ForElectronicSeal.Value, ServiceQualifier.ForWebSiteAuthentication.Value, ServiceQualifier.ForLegalPerson.Value],
            TrustedListQualificationSubStatus.ErrorType1Duplication,
            TrustedListQualificationSubStatus.WarningType1QualifierInconsistency,
            TrustedListQualificationSubStatus.WarningType1NotEnoughInformationOnQcType,
            EuQualifiedCertificateType.ElectronicSignature,
            typelessCompliantIsQualified: true,
            EuQualifiedCertificateIndication.QualifiedForESignature,
            EuQualifiedCertificateIndication.NotQualifiedForESignature,
            EuQualifiedCertificateIndication.IndeterminateForESignature);
        pass.ESignatureQualificationElements.AddRange(check1Elements);

        //PRO-4.4.4-16 through PRO-4.4.4-23: CHECK_2, the for-eSeals dimension.
        (EuQualifiedCertificateIndication check2, List<QualificationElement> check2Elements) = DetermineDimension(
            pass,
            serviceMatch,
            certificateFacts,
            TrustServiceAdditionalInformationType.ForElectronicSeals,
            ServiceQualifier.ForElectronicSeal,
            [ServiceQualifier.ForElectronicSignature.Value, ServiceQualifier.ForWebSiteAuthentication.Value],
            TrustedListQualificationSubStatus.ErrorType2Duplication,
            TrustedListQualificationSubStatus.WarningType2QualifierInconsistency,
            TrustedListQualificationSubStatus.WarningType2NotEnoughInformationOnQcType,
            EuQualifiedCertificateType.ElectronicSeal,
            typelessCompliantIsQualified: false,
            EuQualifiedCertificateIndication.QualifiedForESeal,
            EuQualifiedCertificateIndication.NotQualifiedForESeal,
            EuQualifiedCertificateIndication.IndeterminateForESeal);
        pass.ESealQualificationElements.AddRange(check2Elements);

        //PRO-4.4.4-24 through PRO-4.4.4-31: CHECK_3, the for-website-authentication dimension.
        (EuQualifiedCertificateIndication check3, List<QualificationElement> check3Elements) = DetermineDimension(
            pass,
            serviceMatch,
            certificateFacts,
            TrustServiceAdditionalInformationType.ForWebSiteAuthentication,
            ServiceQualifier.ForWebSiteAuthentication,
            [ServiceQualifier.ForElectronicSignature.Value, ServiceQualifier.ForElectronicSeal.Value],
            TrustedListQualificationSubStatus.ErrorType3Duplication,
            TrustedListQualificationSubStatus.WarningType3QualifierInconsistency,
            TrustedListQualificationSubStatus.WarningType3NotEnoughInformationOnQcType,
            EuQualifiedCertificateType.WebsiteAuthentication,
            typelessCompliantIsQualified: false,
            EuQualifiedCertificateIndication.QualifiedForWebsiteAuthentication,
            EuQualifiedCertificateIndication.NotQualifiedForWebsiteAuthentication,
            EuQualifiedCertificateIndication.IndeterminateForWebsiteAuthentication);
        pass.WebsiteAuthenticationQualificationElements.AddRange(check3Elements);

        //PRO-4.4.4-32: the three dimensions must be mutually consistent per Table 4 — two positive
        //determinations of different types are an error, an indeterminate paired with anything is a
        //warning.
        bool anyPairError = false;
        bool anyPairWarning = false;
        ClassifyPair(check1, check2, pass, ref anyPairError, ref anyPairWarning);
        ClassifyPair(check1, check3, pass, ref anyPairError, ref anyPairWarning);
        ClassifyPair(check2, check3, pass, ref anyPairError, ref anyPairWarning);
        if(anyPairError)
        {
            pass.Status = TrustedListProcessStatus.Failed;
            return pass;
        }

        pass.Status = anyPairWarning ? TrustedListProcessStatus.PassedWithWarning : TrustedListProcessStatus.Passed;
        pass.Indications.Add(check1);
        pass.Indications.Add(check2);
        pass.Indications.Add(check3);
        pass.ContinueToNotBeforeComparison = true;
        return pass;


        /// <summary>PRO-4.4.4-32 / Table 4: classifies one two-by-two combination and records its sub-status.</summary>
        static void ClassifyPair(EuQualifiedCertificateIndication first, EuQualifiedCertificateIndication second, SinglePassDetermination pass, ref bool anyPairError, ref bool anyPairWarning)
        {
            bool firstPositive = IsPositive(first);
            bool secondPositive = IsPositive(second);
            bool anyIndeterminate = IsIndeterminate(first) || IsIndeterminate(second);
            if(firstPositive && secondPositive)
            {
                anyPairError = true;
                AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.ForIndicationPair(isError: true, first, second));
            }
            else if(anyIndeterminate)
            {
                anyPairWarning = true;
                AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.ForIndicationPair(isError: false, first, second));
            }
        }


        /// <summary>Whether the indication asserts a qualified status (Table 4's error-generating class).</summary>
        static bool IsPositive(EuQualifiedCertificateIndication indication) =>
            indication is EuQualifiedCertificateIndication.QualifiedForESignature
                or EuQualifiedCertificateIndication.QualifiedForESeal
                or EuQualifiedCertificateIndication.QualifiedForWebsiteAuthentication;


        /// <summary>Whether the indication is one of the indeterminate values (Table 4's warning-generating class).</summary>
        static bool IsIndeterminate(EuQualifiedCertificateIndication indication) =>
            indication is EuQualifiedCertificateIndication.IndeterminateForESignature
                or EuQualifiedCertificateIndication.IndeterminateForESeal
                or EuQualifiedCertificateIndication.IndeterminateForWebsiteAuthentication;
    }


    /// <summary>
    /// One dimension of the Regulation-regime determination (CHECK_1 / CHECK_2 / CHECK_3, PRO-4.4.4-08
    /// through PRO-4.4.4-31): duplication and status gates, the qualifier-consistency gate, and the
    /// Table 1/2/3 cell selection.
    /// </summary>
    private static (EuQualifiedCertificateIndication Check, List<QualificationElement> Elements) DetermineDimension(
        SinglePassDetermination pass,
        ListedServicesMatchResult serviceMatch,
        QualifiedCertificateFacts certificateFacts,
        TrustServiceAdditionalInformationType informationType,
        ServiceQualifier positiveQualifier,
        string[] foreignTypeQualifierValues,
        TrustedListQualificationSubStatus duplicationError,
        TrustedListQualificationSubStatus qualifierInconsistencyWarning,
        TrustedListQualificationSubStatus notEnoughInformationWarning,
        EuQualifiedCertificateType relevantType,
        bool typelessCompliantIsQualified,
        EuQualifiedCertificateIndication qualified,
        EuQualifiedCertificateIndication notQualified,
        EuQualifiedCertificateIndication indeterminate)
    {
        var elements = new List<QualificationElement>();

        //PRO-4.4.4-09 / -17 / -25: a conflicting duplication found by clause 4.3 pre-empts the dimension.
        if(serviceMatch.SubStatuses.Contains(duplicationError))
        {
            return (indeterminate, elements);
        }

        //PRO-4.4.4-10 / -18 / -26: no state asserting this dimension's information type — or any asserting
        //state withdrawn — means not qualified for this dimension.
        var dimensionStates = new List<TrustServiceStateAtTime>();
        foreach(MatchedServiceInformation match in serviceMatch.Matches)
        {
            if(ContainsInformationType(match.StateAtTime.AdditionalServiceInformation, informationType))
            {
                dimensionStates.Add(match.StateAtTime);
            }
        }

        if(dimensionStates.Count == 0)
        {
            return (notQualified, elements);
        }

        foreach(TrustServiceStateAtTime state in dimensionStates)
        {
            if(state.Status.IsWithdrawn)
            {
                return (notQualified, elements);
            }
        }

        //PRO-4.4.4-10A / -18A / -26A: under the Regulation regime a state must be granted or withdrawn;
        //anything else is a list non-compliance that leaves the dimension indeterminate. (The
        //specification's -18A/-26A name CHECK_1 for the value to set — an editorial slip for
        //CHECK_2/CHECK_3, see the type remarks.)
        foreach(TrustServiceStateAtTime state in dimensionStates)
        {
            if(!state.Status.IsGranted && !state.Status.IsWithdrawn)
            {
                AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.ErrorServiceStatusNoncompliance);
                return (indeterminate, elements);
            }
        }

        //PRO-4.4.4-11 / -19 / -27: the qualification elements whose criteria identify the certificate.
        CollectIdentifyingElements(dimensionStates, certificateFacts, elements, pass.SubStatuses);

        //PRO-4.4.4-12 / -20 / -28: a foreign-type qualifier, or NotQualified together with QCStatement,
        //makes the trusted list inconsistent for this dimension.
        var qualifierValues = CollectQualifierValues(elements);
        bool inconsistent = qualifierValues.Contains(ServiceQualifier.NotQualified.Value) && qualifierValues.Contains(ServiceQualifier.QualifiedCertificateStatement.Value);
        foreach(string foreignValue in foreignTypeQualifierValues)
        {
            inconsistent |= qualifierValues.Contains(foreignValue);
        }

        if(inconsistent)
        {
            AddUnique(pass.SubStatuses, qualifierInconsistencyWarning);
            return (indeterminate, elements);
        }

        //PRO-4.4.4-13/-14 (and the -21/-22, -29/-30 repetitions): more than one QcType is an EN 319 412-5
        //non-compliance worth warning about.
        if(certificateFacts.QcTypes.Count > 1)
        {
            AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.WarningCertificateQcTypeInconsistency);
        }

        //PRO-4.4.4-15 / -23 / -31: the Table 1/2/3 cell.
        bool notQualifiedApplies = qualifierValues.Contains(ServiceQualifier.NotQualified.Value);
        bool statementApplies = qualifierValues.Contains(ServiceQualifier.QualifiedCertificateStatement.Value);
        bool positiveApplies = qualifierValues.Contains(positiveQualifier.Value);
        return (SelectTableCell(
            certificateFacts,
            relevantType,
            typelessCompliantIsQualified,
            notQualifiedApplies,
            statementApplies,
            positiveApplies,
            qualified,
            notQualified,
            indeterminate,
            notEnoughInformationWarning,
            pass.SubStatuses), elements);
    }


    /// <summary>
    /// Selects the determination cell of Table 1, 2 or 3: the row from the certificate's QcCompliance and
    /// QcType statements, the column from the applicable trusted-list qualifiers. The 16-by-5 grids reduce
    /// to one closed form over the row and column selectors; the conformance tests hold the literal grids
    /// and verify every cell against this reduction.
    /// </summary>
    private static EuQualifiedCertificateIndication SelectTableCell(
        QualifiedCertificateFacts certificateFacts,
        EuQualifiedCertificateType relevantType,
        bool typelessCompliantIsQualified,
        bool notQualifiedApplies,
        bool statementApplies,
        bool positiveApplies,
        EuQualifiedCertificateIndication qualified,
        EuQualifiedCertificateIndication notQualified,
        EuQualifiedCertificateIndication indeterminate,
        TrustedListQualificationSubStatus notEnoughInformationWarning,
        List<TrustedListQualificationSubStatus> subStatuses)
    {
        bool hasCompliance = certificateFacts.HasQcCompliance;
        bool hasNoTypes = certificateFacts.QcTypes.Count == 0;
        bool hasRelevantType = certificateFacts.QcTypes.Contains(relevantType);
        bool hasOnlyRelevantType = hasRelevantType && AllTypesAre(certificateFacts.QcTypes, relevantType);

        //Column 2: the NotQualified qualifier overrides everything else in the certificate.
        if(notQualifiedApplies)
        {
            return notQualified;
        }

        //Column 5: QCStatement together with the type qualifier confirms unconditionally.
        if(statementApplies && positiveApplies)
        {
            return qualified;
        }

        //Column 4: the type qualifier alone confirms a compliant certificate and cannot rescue a
        //non-compliant one.
        if(positiveApplies)
        {
            return hasCompliance ? qualified : notQualified;
        }

        //Columns 1 and 3 share the compliance interpretation; column 3 additionally lets QCStatement stand
        //in for an absent QcCompliance. Table 1 differs from Tables 2 and 3 in exactly one aspect: a
        //compliant certificate with no QcType at all defaults to the electronic-signature dimension
        //(the pre-QcType issuance practice Table 1 row1 preserves).
        if(hasCompliance)
        {
            if(hasNoTypes)
            {
                //Table 1 treats "QcCompliance or QcCompliance + QcType 1" as one row; a typeless compliant
                //certificate is qualified only on the electronic-signature dimension.
                return typelessCompliantIsQualified ? qualified : notQualified;
            }

            if(hasOnlyRelevantType)
            {
                return qualified;
            }

            return hasRelevantType ? indeterminate : notQualified;
        }

        if(statementApplies)
        {
            //Column 3 without QcCompliance: QCStatement asserts qualification, the certificate's QcTypes
            //decide the type — no types at all is the row8/column3 "not enough information" cell.
            if(hasNoTypes)
            {
                AddUnique(subStatuses, notEnoughInformationWarning);
                return indeterminate;
            }

            if(hasOnlyRelevantType)
            {
                return qualified;
            }

            return hasRelevantType ? indeterminate : notQualified;
        }

        //Column 1 without QcCompliance: nothing asserts qualification.
        return notQualified;


        /// <summary>Whether every declared type equals <paramref name="relevantType"/> (duplicates permitted).</summary>
        static bool AllTypesAre(IReadOnlyList<EuQualifiedCertificateType> types, EuQualifiedCertificateType relevantType)
        {
            foreach(EuQualifiedCertificateType type in types)
            {
                if(type != relevantType)
                {
                    return false;
                }
            }

            return true;
        }
    }


    /// <summary>
    /// PRO-4.4.4-33: the Directive-regime determination — reached when the evaluation time or the
    /// certificate's NotBefore precedes the Regulation, and expressed in the Directive's supervision
    /// statuses, SSCD terminology and QCP/QCP+ policy identifiers.
    /// </summary>
    private static void DetermineUnderDirectiveRegime(
        SinglePassDetermination pass,
        ListedServicesMatchResult serviceMatch,
        QualifiedCertificateFacts certificateFacts,
        DateTimeOffset evaluationTime)
    {
        //PRO-4.4.4-33 (a)/(b): the Directive knew no seal or website-authentication qualification.
        EuQualifiedCertificateIndication check2 = EuQualifiedCertificateIndication.NotQualifiedForESeal;
        EuQualifiedCertificateIndication check3 = EuQualifiedCertificateIndication.NotQualifiedForWebsiteAuthentication;

        //PRO-4.4.4-33 (c)/(d): duplication over the matched states' statuses, without the Regulation
        //regime's information-type filtering (additional service information did not exist yet).
        bool anyIdentical = false;
        bool anyDiffering = false;
        for(int i = 0; i < serviceMatch.Matches.Count; ++i)
        {
            for(int j = i + 1; j < serviceMatch.Matches.Count; ++j)
            {
                if(string.Equals(serviceMatch.Matches[i].StateAtTime.Status.Value, serviceMatch.Matches[j].StateAtTime.Status.Value, StringComparison.Ordinal))
                {
                    anyIdentical = true;
                }
                else
                {
                    anyDiffering = true;
                }
            }
        }

        if(anyIdentical)
        {
            AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.WarningServiceEntryDuplication);
        }

        if(anyDiffering)
        {
            AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.ErrorServiceEntryDuplicationStatusConflict);
            pass.Status = TrustedListProcessStatus.Failed;
            return;
        }

        //PRO-4.4.4-33 (f): the not-qualified short-circuit — under the Directive a ceased or revoked
        //supervision/accreditation, and under the Regulation the absence of a granted for-eSignatures
        //state, settle the determination.
        bool notQualifiedShortCircuit;
        if(evaluationTime < TrustedListQualificationWellKnown.EidasRegulationApplicationInstant)
        {
            notQualifiedShortCircuit = false;
            foreach(MatchedServiceInformation match in serviceMatch.Matches)
            {
                string status = match.StateAtTime.Status.Value;
                if(string.Equals(status, TrustServiceStatus.SupervisionCeased.Value, StringComparison.Ordinal)
                    || string.Equals(status, TrustServiceStatus.SupervisionRevoked.Value, StringComparison.Ordinal)
                    || string.Equals(status, TrustServiceStatus.AccreditationCeased.Value, StringComparison.Ordinal)
                    || string.Equals(status, TrustServiceStatus.AccreditationRevoked.Value, StringComparison.Ordinal))
                {
                    notQualifiedShortCircuit = true;
                    break;
                }
            }
        }
        else
        {
            bool anyForESignatures = false;
            bool anyWithdrawn = false;
            foreach(MatchedServiceInformation match in serviceMatch.Matches)
            {
                if(ContainsInformationType(match.StateAtTime.AdditionalServiceInformation, TrustServiceAdditionalInformationType.ForElectronicSignatures))
                {
                    anyForESignatures = true;
                    if(match.StateAtTime.Status.IsWithdrawn)
                    {
                        anyWithdrawn = true;
                    }
                }
            }

            notQualifiedShortCircuit = !anyForESignatures || anyWithdrawn;
        }

        if(notQualifiedShortCircuit)
        {
            //The specification stops here without copying the CHECK values into QC-Results — an editorial
            //omission (see the type remarks); the three not-qualified indications are reported.
            pass.Status = TrustedListProcessStatus.Passed;
            pass.Indications.Add(EuQualifiedCertificateIndication.NotQualifiedForESignature);
            pass.Indications.Add(check2);
            pass.Indications.Add(check3);
            return;
        }

        //PRO-4.4.4-33 (g): the identifying qualification elements, from every matched state.
        var states = new List<TrustServiceStateAtTime>();
        foreach(MatchedServiceInformation match in serviceMatch.Matches)
        {
            states.Add(match.StateAtTime);
        }

        CollectIdentifyingElements(states, certificateFacts, pass.ESignatureQualificationElements, pass.SubStatuses);

        //PRO-4.4.4-33 (h): inconsistent qualifiers fail the Directive-regime determination outright.
        var qualifierValues = CollectQualifierValues(pass.ESignatureQualificationElements);
        if(qualifierValues.Contains(ServiceQualifier.ForElectronicSeal.Value)
            || qualifierValues.Contains(ServiceQualifier.ForWebSiteAuthentication.Value)
            || (qualifierValues.Contains(ServiceQualifier.NotQualified.Value) && qualifierValues.Contains(ServiceQualifier.QualifiedCertificateStatement.Value)))
        {
            AddUnique(pass.SubStatuses, TrustedListQualificationSubStatus.ErrorType1QualifierInconsistency);
            pass.Status = TrustedListProcessStatus.Failed;
            pass.Indications.Add(EuQualifiedCertificateIndication.IndeterminateForESignature);
            return;
        }

        //PRO-4.4.4-33 (i)-(k): Table 5 over the certificate's QcCompliance/QCP/QCP+ marks and the
        //NotQualified/QCStatement qualifiers.
        bool anyQualifiedMark = certificateFacts.HasQcCompliance
            || ContainsOrdinal(certificateFacts.CertificatePolicyOids, WellKnownOids.QcpPublic)
            || ContainsOrdinal(certificateFacts.CertificatePolicyOids, WellKnownOids.QcpPublicWithSscd);
        EuQualifiedCertificateIndication check1;
        if(qualifierValues.Contains(ServiceQualifier.NotQualified.Value))
        {
            check1 = EuQualifiedCertificateIndication.NotQualifiedForESignature;
        }
        else if(qualifierValues.Contains(ServiceQualifier.QualifiedCertificateStatement.Value))
        {
            check1 = EuQualifiedCertificateIndication.QualifiedForESignature;
        }
        else
        {
            check1 = anyQualifiedMark
                ? EuQualifiedCertificateIndication.QualifiedForESignature
                : EuQualifiedCertificateIndication.NotQualifiedForESignature;
        }

        //PRO-4.4.4-33 (l)/(m): the pass completes with the three checks, and the outer determination
        //proceeds to the PRO-4.4.4-34 comparison.
        pass.Status = TrustedListProcessStatus.Passed;
        pass.Indications.Add(check1);
        pass.Indications.Add(check2);
        pass.Indications.Add(check3);
        pass.ContinueToNotBeforeComparison = true;
    }


    /// <summary>
    /// PRO-4.4.4-11 / -19 / -27 / -33 (g): collects the qualification elements of the given states whose
    /// criteria identify the certificate; an element whose criteria cannot be soundly evaluated is treated
    /// as not identifying, with the condition surfaced as a warning.
    /// </summary>
    private static void CollectIdentifyingElements(
        List<TrustServiceStateAtTime> states,
        QualifiedCertificateFacts certificateFacts,
        List<QualificationElement> elements,
        List<TrustedListQualificationSubStatus> subStatuses)
    {
        foreach(TrustServiceStateAtTime state in states)
        {
            foreach(QualificationElement element in state.Qualifications)
            {
                switch(TrustedListCriteriaEvaluation.Evaluate(element.Condition, certificateFacts))
                {
                    case CriteriaMatchResult.Matched:
                        elements.Add(element);
                        break;

                    case CriteriaMatchResult.Indeterminate:
                        AddUnique(subStatuses, TrustedListQualificationSubStatus.WarningCriteriaNotEvaluable);
                        break;

                    default:
                        break;
                }
            }
        }
    }


    /// <summary>PRO-4.4.4-06: whether the certificate's issuer identifies the matched provider.</summary>
    private static bool IssuerIdentifiesProvider(QualifiedCertificateFacts certificateFacts, IReadOnlyList<MatchedServiceInformation> matches)
    {
        if(certificateFacts.IssuerOrganizationNames.Count > 0)
        {
            foreach(string organizationName in certificateFacts.IssuerOrganizationNames)
            {
                foreach(MatchedServiceInformation match in matches)
                {
                    if(MatchesAnyLocalizedName(organizationName, match.ProviderNames) || MatchesAnyLocalizedName(organizationName, match.ProviderTradeNames))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        //PRO-4.4.4-06 (b): with no issuer organization name, the fallback strategies — common name against
        //the provider names, or the issuer distinguished name against a subject-name digital identity.
        foreach(string commonName in certificateFacts.IssuerCommonNames)
        {
            foreach(MatchedServiceInformation match in matches)
            {
                if(MatchesAnyLocalizedName(commonName, match.ProviderNames) || MatchesAnyLocalizedName(commonName, match.ProviderTradeNames))
                {
                    return true;
                }
            }
        }

        if(certificateFacts.IssuerDistinguishedName is not null)
        {
            foreach(MatchedServiceInformation match in matches)
            {
                foreach(ServiceDigitalIdentityEntry entry in match.DigitalIdentity.Entries)
                {
                    if(entry is X509SubjectNameIdentity subjectNameEntry
                        && NormalizedNameEquals(certificateFacts.IssuerDistinguishedName, subjectNameEntry.SubjectName))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }


    /// <summary>Throws when the list's scheme territory contradicts the certificate-derived country — a composition error, not a determination outcome.</summary>
    private static void EnsureTerritoryConsistency(TrustedList trustedList, string? countryCode)
    {
        if(countryCode is null || trustedList.SchemeInformation.SchemeTerritory is null)
        {
            return;
        }

        string expectedTerritory = ResolveTrustedListTerritory(countryCode);
        if(!string.Equals(trustedList.SchemeInformation.SchemeTerritory, expectedTerritory, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The supplied trusted list covers territory '{trustedList.SchemeInformation.SchemeTerritory}' but the certificate names country '{countryCode}' (territory '{expectedTerritory}'). Supply the member state list the certificate's country resolves to.");
        }
    }


    /// <summary>Collects the distinct qualifier URI values of the given qualification elements.</summary>
    private static HashSet<string> CollectQualifierValues(IReadOnlyList<QualificationElement> elements)
    {
        var values = new HashSet<string>(StringComparer.Ordinal);
        foreach(QualificationElement element in elements)
        {
            foreach(ServiceQualifier qualifier in element.Qualifiers)
            {
                values.Add(qualifier.Value);
            }
        }

        return values;
    }


    /// <summary>Whether <paramref name="values"/> contains <paramref name="candidate"/> by ordinal comparison.</summary>
    private static bool ContainsOrdinal(IReadOnlyList<string> values, string candidate)
    {
        foreach(string value in values)
        {
            if(string.Equals(value, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Whether the additional-service-information list contains the given type by URI value.</summary>
    private static bool ContainsInformationType(IReadOnlyList<TrustServiceAdditionalInformationType> informationTypes, TrustServiceAdditionalInformationType candidate)
    {
        foreach(TrustServiceAdditionalInformationType informationType in informationTypes)
        {
            if(string.Equals(informationType.Value, candidate.Value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Whether <paramref name="name"/> matches any of the localized names under the RFC 5280 section 7.1 style comparison.</summary>
    private static bool MatchesAnyLocalizedName(string name, IReadOnlyList<LocalizedText> localizedNames)
    {
        foreach(LocalizedText localizedName in localizedNames)
        {
            if(NormalizedNameEquals(name, localizedName.Value))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// The RFC 5280 section 7.1 <c>caseIgnoreMatch</c>-style comparison PRO-4.4.4-06 prescribes,
    /// approximated as: leading/trailing white space removed, internal white space runs collapsed to one
    /// space, then an ordinal case-insensitive comparison.
    /// </summary>
    private static bool NormalizedNameEquals(string first, string second) =>
        string.Equals(NormalizeName(first), NormalizeName(second), StringComparison.OrdinalIgnoreCase);


    /// <summary>Trims and collapses internal white space runs to single spaces.</summary>
    private static string NormalizeName(string value)
    {
        Span<char> buffer = value.Length <= 256 ? stackalloc char[value.Length] : new char[value.Length];
        int length = 0;
        bool pendingSpace = false;
        foreach(char character in value.AsSpan().Trim())
        {
            if(char.IsWhiteSpace(character))
            {
                pendingSpace = true;
                continue;
            }

            if(pendingSpace && length > 0)
            {
                buffer[length++] = ' ';
            }

            pendingSpace = false;
            buffer[length++] = character;
        }

        return new string(buffer[..length]);
    }


    /// <summary>Adds <paramref name="subStatus"/> unless an identical value is already present (sub-status lists carry set semantics; see the type remarks).</summary>
    private static void AddUnique(List<TrustedListQualificationSubStatus> subStatuses, TrustedListQualificationSubStatus subStatus)
    {
        foreach(TrustedListQualificationSubStatus existing in subStatuses)
        {
            if(string.Equals(existing.Value, subStatus.Value, StringComparison.Ordinal))
            {
                return;
            }
        }

        subStatuses.Add(subStatus);
    }
}
