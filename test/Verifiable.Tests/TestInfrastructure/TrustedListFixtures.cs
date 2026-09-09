using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Builds in-memory <see cref="TrustedList"/> object graphs for the
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OID4VP 1.0
/// §6.1.1.2</see> <c>etsi_tl</c> membership tests: a member-state list whose one Trust Service Provider carries
/// a service recognised by an <see cref="X509CertificateIdentity"/>, an <see cref="X509SubjectKeyIdentifierIdentity"/>,
/// an <see cref="X509SubjectNameIdentity"/> or an <see cref="OtherDigitalIdentity"/> for a given certificate; a
/// List Of the Trusted Lists whose <see cref="TrustedListSchemeInformation.PointersToOtherTrustedLists"/> name
/// another list's distribution point (ETSI TS 119 612 V2.4.1 clause 5.3.13); two-level cascades and pointer
/// cycles over those pointers.
/// </summary>
/// <remarks>
/// The graphs follow the <see cref="QualifiedTrustedListComposition.ComposeQualifiedTrustedList"/> shape but
/// carry only the fields <see cref="TrustedListMembership.Evaluate(IReadOnlyList{PkiCertificateMemory}, IReadOnlyList{TrustedList}, ReadCertificateSubjectKeyIdentifierDelegate, ReadCertificateSubjectNameDelegate)"/>
/// reads — a list's <see cref="TrustedListSchemeInformation.DistributionPoints"/> identity, its pointers, and
/// its services' digital identities — leaving every other schema-required field a minimal placeholder. The
/// certificates are minted by <see cref="X509.X509ChainTestRing"/>; a <see cref="X509SubjectKeyIdentifierIdentity"/>
/// entry's base64 is derived here from the certificate's own <see cref="X509SubjectKeyIdentifierExtension.SubjectKeyIdentifierBytes"/>,
/// never read back through the backend delegate under test.
/// </remarks>
internal static class TrustedListFixtures
{
    /// <summary>
    /// The List Of the Trusted Lists identifier from the §6.1.1.2 non-normative example
    /// (<c>{"type": "etsi_tl", "values": ["https://lotl.example.com"]}</c>).
    /// </summary>
    internal const string ListOfTheListsIdentifier = "https://lotl.example.com";

    /// <summary>The <c>StatusDeterminationApproach</c> URI naming the EU "appropriate" approach (ETSI TS 119 612 clause 5.3.8).</summary>
    private const string StatusDeterminationApproach = "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate";


    /// <summary>
    /// Copies <paramref name="certificate"/>'s DER into a pooled <see cref="PkiCertificateMemory"/> carrier the
    /// caller disposes — the shape a credential's certificate chain reaches
    /// <see cref="TrustedListMembership.Evaluate(IReadOnlyList{PkiCertificateMemory}, IReadOnlyList{TrustedList}, ReadCertificateSubjectKeyIdentifierDelegate, ReadCertificateSubjectNameDelegate)"/>
    /// as.
    /// </summary>
    /// <param name="certificate">The certificate whose DER is copied.</param>
    /// <param name="pool">The pool the carrier is rented from.</param>
    /// <returns>The pooled carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory ToCertificateCarrier(X509Certificate2 certificate, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] der = certificate.RawData;
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Reads <paramref name="certificate"/>'s SubjectKeyIdentifier (RFC 5280 §4.2.1.2) directly from its
    /// framework extension and renders it as standard base64 — the encoding ETSI TS 119 612 V2.4.1 clause 5.5.3
    /// gives an <c>X509SKI</c> entry, and the independent oracle a
    /// <see cref="X509SubjectKeyIdentifierIdentity"/> entry is built from so its value is never taken from the
    /// backend reader the membership walk exercises.
    /// </summary>
    /// <param name="certificate">The certificate whose SubjectKeyIdentifier is read.</param>
    /// <returns>The standard-base64 SubjectKeyIdentifier bytes.</returns>
    internal static string SubjectKeyIdentifierBase64(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        X509SubjectKeyIdentifierExtension extension = certificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>().First();

        return Convert.ToBase64String(extension.SubjectKeyIdentifierBytes.Span);
    }


    /// <summary>
    /// Builds an <see cref="X509CertificateIdentity"/> entry recognising <paramref name="certificate"/> by its
    /// full DER (ETSI TS 119 612 clause 5.5.3's most specific form). Ownership of the copied certificate
    /// transfers to the entry's containing <see cref="TrustedList"/>, which disposes it.
    /// </summary>
    /// <param name="certificate">The certificate the entry recognises.</param>
    /// <param name="pool">The pool the copied certificate is rented from.</param>
    /// <returns>The entry.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the copied certificate carrier transfers to the returned X509CertificateIdentity, disposed through the containing TrustedList's Dispose.")]
    internal static X509CertificateIdentity CertificateEntry(X509Certificate2 certificate, BaseMemoryPool pool)
    {
        return new X509CertificateIdentity(ToCertificateCarrier(certificate, pool));
    }


    /// <summary>
    /// Builds an <see cref="X509SubjectKeyIdentifierIdentity"/> entry recognising <paramref name="certificate"/>
    /// by the standard base64 of its SubjectKeyIdentifier bytes.
    /// </summary>
    /// <param name="certificate">The certificate the entry recognises.</param>
    /// <returns>The entry.</returns>
    internal static X509SubjectKeyIdentifierIdentity SubjectKeyIdentifierEntry(X509Certificate2 certificate)
    {
        return new X509SubjectKeyIdentifierIdentity(SubjectKeyIdentifierBase64(certificate));
    }


    /// <summary>
    /// Builds an <see cref="X509SubjectNameIdentity"/> entry recognising a certificate by the RFC 4514
    /// distinguished name string <paramref name="rfc4514SubjectName"/> — hand-authored by the caller from the
    /// certificate's known Subject rather than rendered through the backend reader under test.
    /// </summary>
    /// <param name="rfc4514SubjectName">The RFC 4514 Subject distinguished name the entry recognises.</param>
    /// <returns>The entry.</returns>
    internal static X509SubjectNameIdentity SubjectNameEntry(string rfc4514SubjectName)
    {
        return new X509SubjectNameIdentity(rfc4514SubjectName);
    }


    /// <summary>
    /// Builds an <see cref="OtherDigitalIdentity"/> entry — the schema's <c>Other</c> extension point, which
    /// clause 5.5.3 does not model as a certificate reference and which the membership walk never matches a
    /// chain certificate against.
    /// </summary>
    /// <param name="localName">The unrecognised element name the entry records.</param>
    /// <returns>The entry.</returns>
    internal static OtherDigitalIdentity OtherEntry(string localName = "KeyValue")
    {
        return new OtherDigitalIdentity(localName);
    }


    /// <summary>
    /// Builds an <see cref="OtherTrustedListPointer"/> whose <see cref="OtherTrustedListPointer.TslLocation"/>
    /// names <paramref name="tslLocation"/> — the clause 5.3.13 edge the membership walk follows to a pointed-to
    /// list among the held lists. The pointer carries no bootstrap digital identities and minimal additional
    /// information, since the walk reads only the location.
    /// </summary>
    /// <param name="tslLocation">The absolute URI the pointer names.</param>
    /// <returns>The pointer; its owner disposes it.</returns>
    private static OtherTrustedListPointer PointerTo(string tslLocation)
    {
        return new OtherTrustedListPointer
        {
            TslLocation = new Uri(tslLocation, UriKind.Absolute),
            ServiceDigitalIdentities = ServiceDigitalIdentity.Empty,
            AdditionalInformation = new OtherTrustedListPointerAdditionalInformation()
        };
    }


    /// <summary>
    /// Builds the clause 5.3.13 pointers naming each of <paramref name="pointerTargets"/> in turn.
    /// </summary>
    /// <param name="pointerTargets">The absolute URIs the pointers name.</param>
    /// <returns>One pointer per target.</returns>
    private static List<OtherTrustedListPointer> PointersTo(IReadOnlyList<string> pointerTargets)
    {
        List<OtherTrustedListPointer> pointers = [];
        foreach(string target in pointerTargets)
        {
            pointers.Add(PointerTo(target));
        }

        return pointers;
    }


    /// <summary>
    /// Composes a <see cref="TrustedList"/> published at <paramref name="distributionPoints"/> whose single
    /// Trust Service Provider operates one service recognised by <paramref name="currentEntries"/> now and by
    /// <paramref name="historyEntries"/> in a prior state, and which points at <paramref name="pointerTargets"/>.
    /// </summary>
    /// <param name="distributionPoints">The list's own identifiers (clause 5.3.16).</param>
    /// <param name="currentEntries">The current service digital identity's entries.</param>
    /// <param name="historyEntries">A prior state's entries, or <see langword="null"/> for no history.</param>
    /// <param name="pointerTargets">The absolute URIs the list points at (clause 5.3.13), or <see langword="null"/> for none.</param>
    /// <param name="kind">The list kind (clause 5.3.3); defaults to <see cref="TrustedListKind.Generic"/>.</param>
    /// <returns>The composed list; the caller disposes it, which disposes every owned certificate.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the composed service, provider and pointers transfers to the returned TrustedList, disposed through its Dispose.")]
    internal static TrustedList BuildTrustedList(
        IReadOnlyList<string> distributionPoints,
        IReadOnlyList<ServiceDigitalIdentityEntry> currentEntries,
        IReadOnlyList<ServiceDigitalIdentityEntry>? historyEntries = null,
        IReadOnlyList<string>? pointerTargets = null,
        TrustedListKind? kind = null)
    {
        ArgumentNullException.ThrowIfNull(distributionPoints);
        ArgumentNullException.ThrowIfNull(currentEntries);

        List<TrustServiceHistoryEntry> history = [];
        if(historyEntries is not null)
        {
            history.Add(new TrustServiceHistoryEntry
            {
                ServiceTypeIdentifier = TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates,
                ServiceNames = [new LocalizedText("en", "Qualified certificate issuance service (prior state)")],
                DigitalIdentity = new ServiceDigitalIdentity { Entries = historyEntries },
                PreviousStatus = TrustServiceStatus.Granted,
                StatusStartingTime = SchemeIssueInstant.AddYears(-1)
            });
        }

        var service = new TrustService
        {
            ServiceTypeIdentifier = TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates,
            ServiceNames = [new LocalizedText("en", "Qualified certificate issuance service")],
            DigitalIdentity = new ServiceDigitalIdentity { Entries = currentEntries },
            Status = TrustServiceStatus.Granted,
            StatusStartingTime = SchemeIssueInstant,
            History = history
        };

        var provider = new TrustServiceProvider
        {
            Names = [new LocalizedText("en", "Verifiable Test Trust Service Provider")],
            PostalAddresses = [],
            ElectronicAddresses = [],
            InformationUris = [],
            Services = [service]
        };

        return new TrustedList
        {
            SchemeInformation = SchemeInformation(kind ?? TrustedListKind.Generic, distributionPoints, PointersTo(pointerTargets ?? [])),
            TrustServiceProviders = [provider]
        };
    }


    /// <summary>
    /// Composes a List Of the Trusted Lists published at <paramref name="distributionPoints"/> that carries no
    /// services of its own, only pointers naming <paramref name="pointerTargets"/> — the common LOTL shape
    /// (clause 5.3.13).
    /// </summary>
    /// <param name="distributionPoints">The LOTL's own identifiers (clause 5.3.16).</param>
    /// <param name="pointerTargets">The absolute URIs the LOTL points at.</param>
    /// <returns>The composed LOTL; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the composed pointers transfers to the returned TrustedList, disposed through its Dispose.")]
    internal static TrustedList BuildListOfTheLists(
        IReadOnlyList<string> distributionPoints,
        IReadOnlyList<string> pointerTargets)
    {
        ArgumentNullException.ThrowIfNull(distributionPoints);
        ArgumentNullException.ThrowIfNull(pointerTargets);

        return new TrustedList
        {
            SchemeInformation = SchemeInformation(TrustedListKind.ListOfTheLists, distributionPoints, PointersTo(pointerTargets)),
            TrustServiceProviders = []
        };
    }


    /// <summary>The instant every composed list's current status starts and is issued at — an arbitrary fixed instant, since the membership walk reads no time.</summary>
    private static DateTimeOffset SchemeIssueInstant { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// Builds the minimal <see cref="TrustedListSchemeInformation"/> the membership walk reads —
    /// <paramref name="kind"/>, <paramref name="distributionPoints"/> and <paramref name="pointers"/> — filling
    /// every other schema-required field with a procedure-irrelevant placeholder.
    /// </summary>
    /// <param name="kind">The list kind (clause 5.3.3).</param>
    /// <param name="distributionPoints">The list's own identifiers (clause 5.3.16).</param>
    /// <param name="pointers">The list's pointers to other lists (clause 5.3.13).</param>
    /// <returns>The scheme information.</returns>
    private static TrustedListSchemeInformation SchemeInformation(
        TrustedListKind kind,
        IReadOnlyList<string> distributionPoints,
        IReadOnlyList<OtherTrustedListPointer> pointers)
    {
        return new TrustedListSchemeInformation
        {
            TslVersionIdentifier = 6,
            TslSequenceNumber = 1,
            TslType = kind,
            SchemeOperatorNames = [],
            SchemeOperatorPostalAddresses = [],
            SchemeOperatorElectronicAddresses = [],
            SchemeNames = [],
            SchemeInformationUris = [],
            StatusDeterminationApproach = StatusDeterminationApproach,
            HistoricalInformationPeriodYears = 5,
            ListIssueDateTime = SchemeIssueInstant,
            DistributionPoints = distributionPoints,
            PointersToOtherTrustedLists = pointers
        };
    }
}
