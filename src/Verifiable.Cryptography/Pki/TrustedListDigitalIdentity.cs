using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One entry of a <c>ServiceDigitalIdentity</c> — the material a <see cref="TrustService"/> or
/// <see cref="OtherTrustedListPointer"/> is recognised by, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.3</see>. The schema's <c>DigitalIdentityType</c> is a choice of exactly
/// one representation per <c>DigitalId</c> element; this closed sum mirrors that choice so a caller matching
/// a certificate against a service's digital identity switches exhaustively rather than probing optional
/// fields.
/// </summary>
public abstract record ServiceDigitalIdentityEntry
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected ServiceDigitalIdentityEntry()
    {
    }
}


/// <summary>
/// The digital identity is the service's X.509 v3 certificate (the most common and most specific form —
/// clause 5.5.3 recommends including the certificate whenever available).
/// </summary>
/// <param name="Certificate">The DER-encoded certificate. The caller owns it and must dispose it.</param>
public sealed record X509CertificateIdentity(PkiCertificateMemory Certificate) : ServiceDigitalIdentityEntry;


/// <summary>
/// The digital identity is the service key's Subject Key Identifier (RFC 5280 §4.2.1.2) rather than the
/// full certificate. Carried as a base64 string rather than raw bytes: like
/// <see cref="ExtractAuthorityKeyIdentifierDelegate"/>'s return value, a Subject Key Identifier is public
/// certificate metadata, not sensitive material a carrier's dispose contract needs to guard.
/// </summary>
/// <param name="SubjectKeyIdentifierBase64">The base64-encoded (schema <c>base64Binary</c>) key identifier, exactly as the document encodes it.</param>
public sealed record X509SubjectKeyIdentifierIdentity(string SubjectKeyIdentifierBase64) : ServiceDigitalIdentityEntry;


/// <summary>
/// The digital identity is the service's certificate Subject distinguished name as plain text, without a
/// certificate or key identifier alongside it — a rarer, weaker form of identification.
/// </summary>
/// <param name="SubjectName">The Subject distinguished name text exactly as the document encodes it.</param>
public sealed record X509SubjectNameIdentity(string SubjectName) : ServiceDigitalIdentityEntry;


/// <summary>
/// The digital identity uses the schema's <c>Other</c> extension point — a representation this model does
/// not otherwise recognise (for example a raw XML DSIG <c>KeyValue</c>). Nothing about the entry's content
/// is modelled; only that one was present, so a caller can see the entry existed instead of it silently
/// disappearing.
/// </summary>
/// <param name="LocalName">The local (unqualified) element name the test-side XML binding found inside <c>Other</c>.</param>
public sealed record OtherDigitalIdentity(string LocalName) : ServiceDigitalIdentityEntry;


/// <summary>
/// The full <c>ServiceDigitalIdentity</c> of a <see cref="TrustService"/>, <see cref="TrustServiceHistoryEntry"/>,
/// or <see cref="OtherTrustedListPointer"/> — zero or more alternative representations of the same key/service,
/// per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.3</see>. The list is disjunctive — any one entry matching is sufficient
/// to recognise the service — not a chain.
/// </summary>
public sealed record ServiceDigitalIdentity : IDisposable
{
    /// <summary>The alternative identity entries. Empty when the document supplied none.</summary>
    public required IReadOnlyList<ServiceDigitalIdentityEntry> Entries { get; init; }

    /// <summary>A <see cref="ServiceDigitalIdentity"/> with no entries.</summary>
    public static ServiceDigitalIdentity Empty { get; } = new() { Entries = [] };


    /// <summary>Disposes every <see cref="X509CertificateIdentity.Certificate"/> this identity owns.</summary>
    public void Dispose()
    {
        foreach(ServiceDigitalIdentityEntry entry in Entries)
        {
            if(entry is X509CertificateIdentity certificateEntry)
            {
                certificateEntry.Certificate.Dispose();
            }
        }
    }
}
