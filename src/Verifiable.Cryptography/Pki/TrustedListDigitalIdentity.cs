using System;
using System.Collections.Generic;
using System.Diagnostics;

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
public abstract class ServiceDigitalIdentityEntry
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected ServiceDigitalIdentityEntry()
    {
    }
}


/// <summary>
/// The digital identity is the service's X.509 v3 certificate (the most common and most specific form —
/// clause 5.5.3 recommends including the certificate whenever available).
/// </summary>
[DebuggerDisplay("X509CertificateIdentity: {Certificate.Length} octets")]
public sealed class X509CertificateIdentity : ServiceDigitalIdentityEntry
{
    /// <summary>Initializes a new <see cref="X509CertificateIdentity"/>.</summary>
    /// <param name="certificate">The DER-encoded certificate. Ownership transfers to the containing <see cref="ServiceDigitalIdentity"/>, which disposes it.</param>
    public X509CertificateIdentity(PkiCertificateMemory certificate)
    {
        Certificate = certificate;
    }

    /// <summary>The DER-encoded certificate. The containing <see cref="ServiceDigitalIdentity"/> owns and disposes it.</summary>
    public PkiCertificateMemory Certificate { get; }
}


/// <summary>
/// The digital identity is the service key's Subject Key Identifier (RFC 5280 §4.2.1.2) rather than the
/// full certificate. Carried as a base64 string rather than raw bytes: like
/// <see cref="ExtractAuthorityKeyIdentifierDelegate"/>'s return value, a Subject Key Identifier is public
/// certificate metadata, not sensitive material a carrier's dispose contract needs to guard.
/// </summary>
/// <remarks>
/// Equality is the encoded key identifier's, compared ordinally. A trusted list is matched against, not held
/// by reference: two entries carrying the same base64 identifier recognise the same key, so they are the same
/// entry however each was read.
/// </remarks>
[DebuggerDisplay("X509SubjectKeyIdentifierIdentity: {SubjectKeyIdentifierBase64}")]
public sealed class X509SubjectKeyIdentifierIdentity : ServiceDigitalIdentityEntry, IEquatable<X509SubjectKeyIdentifierIdentity>
{
    /// <summary>Initializes a new <see cref="X509SubjectKeyIdentifierIdentity"/>.</summary>
    /// <param name="subjectKeyIdentifierBase64">The base64-encoded (schema <c>base64Binary</c>) key identifier, exactly as the document encodes it.</param>
    public X509SubjectKeyIdentifierIdentity(string subjectKeyIdentifierBase64)
    {
        SubjectKeyIdentifierBase64 = subjectKeyIdentifierBase64;
    }

    /// <summary>The base64-encoded (schema <c>base64Binary</c>) key identifier, exactly as the document encodes it.</summary>
    public string SubjectKeyIdentifierBase64 { get; }

    /// <inheritdoc/>
    public bool Equals(X509SubjectKeyIdentifierIdentity? other)
    {
        return other is not null && string.Equals(SubjectKeyIdentifierBase64, other.SubjectKeyIdentifierBase64, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as X509SubjectKeyIdentifierIdentity);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(SubjectKeyIdentifierBase64);
    }

    /// <summary>Reports whether two entries carry the same encoded key identifier.</summary>
    public static bool operator ==(X509SubjectKeyIdentifierIdentity? left, X509SubjectKeyIdentifierIdentity? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two entries carry a different encoded key identifier.</summary>
    public static bool operator !=(X509SubjectKeyIdentifierIdentity? left, X509SubjectKeyIdentifierIdentity? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The digital identity is the service's certificate Subject distinguished name as plain text, without a
/// certificate or key identifier alongside it — a rarer, weaker form of identification.
/// </summary>
/// <remarks>
/// The entry is the distinguished name text it states, so equality compares that text ordinally — byte for
/// byte as the document encoded it, since this model deliberately does not parse or normalise the name and has
/// no grounds to treat two spellings as one.
/// </remarks>
[DebuggerDisplay("X509SubjectNameIdentity: {SubjectName}")]
public sealed class X509SubjectNameIdentity : ServiceDigitalIdentityEntry, IEquatable<X509SubjectNameIdentity>
{
    /// <summary>Initializes a new <see cref="X509SubjectNameIdentity"/>.</summary>
    /// <param name="subjectName">The Subject distinguished name text exactly as the document encodes it.</param>
    public X509SubjectNameIdentity(string subjectName)
    {
        SubjectName = subjectName;
    }

    /// <summary>The Subject distinguished name text exactly as the document encodes it.</summary>
    public string SubjectName { get; }

    /// <inheritdoc/>
    public bool Equals(X509SubjectNameIdentity? other)
    {
        return other is not null && string.Equals(SubjectName, other.SubjectName, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as X509SubjectNameIdentity);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(SubjectName);
    }

    /// <summary>Reports whether two entries state the same Subject distinguished name text.</summary>
    public static bool operator ==(X509SubjectNameIdentity? left, X509SubjectNameIdentity? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two entries state different Subject distinguished name text.</summary>
    public static bool operator !=(X509SubjectNameIdentity? left, X509SubjectNameIdentity? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The digital identity uses the schema's <c>Other</c> extension point — a representation this model does
/// not otherwise recognise (for example a raw XML DSIG <c>KeyValue</c>). Nothing about the entry's content
/// is modelled; only that one was present, so a caller can see the entry existed instead of it silently
/// disappearing.
/// </summary>
/// <remarks>
/// All this entry knows is the element name it saw, so that name — compared ordinally, as XML local names are
/// case-sensitive — is all its equality can be about: two sightings of the same unrecognised element are one
/// and the same observation.
/// </remarks>
[DebuggerDisplay("OtherDigitalIdentity: {LocalName}")]
public sealed class OtherDigitalIdentity : ServiceDigitalIdentityEntry, IEquatable<OtherDigitalIdentity>
{
    /// <summary>Initializes a new <see cref="OtherDigitalIdentity"/>.</summary>
    /// <param name="localName">The local (unqualified) element name the test-side XML binding found inside <c>Other</c>.</param>
    public OtherDigitalIdentity(string localName)
    {
        LocalName = localName;
    }

    /// <summary>The local (unqualified) element name the test-side XML binding found inside <c>Other</c>.</summary>
    public string LocalName { get; }

    /// <inheritdoc/>
    public bool Equals(OtherDigitalIdentity? other)
    {
        return other is not null && string.Equals(LocalName, other.LocalName, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as OtherDigitalIdentity);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(LocalName);
    }

    /// <summary>Reports whether two entries name the same unrecognised element.</summary>
    public static bool operator ==(OtherDigitalIdentity? left, OtherDigitalIdentity? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two entries name a different unrecognised element.</summary>
    public static bool operator !=(OtherDigitalIdentity? left, OtherDigitalIdentity? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The full <c>ServiceDigitalIdentity</c> of a <see cref="TrustService"/>, <see cref="TrustServiceHistoryEntry"/>,
/// or <see cref="OtherTrustedListPointer"/> — zero or more alternative representations of the same key/service,
/// per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.3</see>. The list is disjunctive — any one entry matching is sufficient
/// to recognise the service — not a chain.
/// </summary>
[DebuggerDisplay("ServiceDigitalIdentity: {Entries.Count} entries")]
public sealed class ServiceDigitalIdentity : IDisposable
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
