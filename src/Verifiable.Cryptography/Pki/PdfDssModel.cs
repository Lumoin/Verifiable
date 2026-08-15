using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One Signature VRI dictionary read from an existing document (ETSI EN 319 142-1 clause 5.4.2.3) — the
/// Unverified carriage (RP-4) <see cref="PdfDssReader.Locate"/> produces for one entry of the DSS dictionary's own
/// <c>VRI</c> map.
/// </summary>
/// <remarks>Ownership: owns every carrier it exposes; <see cref="Dispose"/> disposes all of them.</remarks>
[DebuggerDisplay("PdfVriDictionary: {Certificates.Count} cert(s), {CertificateRevocationLists.Count} CRL(s), {OcspResponses.Count} OCSP(s)")]
public sealed class PdfVriDictionary: IDisposable
{
    private bool disposed;


    /// <summary>Initializes a new <see cref="PdfVriDictionary"/>. Ownership of every carrier transfers to this instance.</summary>
    /// <param name="certificates">See <see cref="Certificates"/>.</param>
    /// <param name="certificateRevocationLists">See <see cref="CertificateRevocationLists"/>.</param>
    /// <param name="ocspResponses">See <see cref="OcspResponses"/>.</param>
    /// <param name="timeUpdated">See <see cref="TimeUpdated"/>.</param>
    /// <param name="timeStampToken">See <see cref="TimeStampToken"/>.</param>
    public PdfVriDictionary(
        IReadOnlyList<PkiCertificateMemory> certificates,
        IReadOnlyList<PkiCertificateMemory> certificateRevocationLists,
        IReadOnlyList<PkiCertificateMemory> ocspResponses,
        DateTimeOffset? timeUpdated,
        PkiCertificateMemory? timeStampToken)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(certificateRevocationLists);
        ArgumentNullException.ThrowIfNull(ocspResponses);

        Certificates = certificates;
        CertificateRevocationLists = certificateRevocationLists;
        OcspResponses = ocspResponses;
        TimeUpdated = timeUpdated;
        TimeStampToken = timeStampToken;
    }


    /// <summary>Gets the <c>Cert</c> array's own certificates (PA-5.4.2.3-03/-04/-05), empty when the entry was absent.</summary>
    public IReadOnlyList<PkiCertificateMemory> Certificates { get; }

    /// <summary>Gets the <c>CRL</c> array's own CRLs (PA-5.4.2.3-06/-07), empty when the entry was absent.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateRevocationLists { get; }

    /// <summary>Gets the <c>OCSP</c> array's own responses (PA-5.4.2.3-08/-09), empty when the entry was absent.</summary>
    public IReadOnlyList<PkiCertificateMemory> OcspResponses { get; }

    /// <summary>Gets the <c>TU</c> claimed-generation time, or <see langword="null"/> when absent. Mutually exclusive with <see cref="TimeStampToken"/> (PA-5.4.2.3-10/-13).</summary>
    public DateTimeOffset? TimeUpdated { get; }

    /// <summary>Gets the <c>TS</c> DER-encoded RFC 3161 time-stamp token, or <see langword="null"/> when absent. Mutually exclusive with <see cref="TimeUpdated"/> (PA-5.4.2.3-10/-13). Owned by this instance.</summary>
    public PkiCertificateMemory? TimeStampToken { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        DisposeAll(Certificates);
        DisposeAll(CertificateRevocationLists);
        DisposeAll(OcspResponses);
        TimeStampToken?.Dispose();
        disposed = true;
    }


    private static void DisposeAll(IReadOnlyList<PkiCertificateMemory> items)
    {
        for(int i = 0; i < items.Count; ++i)
        {
            items[i].Dispose();
        }
    }
}


/// <summary>
/// The Document Security Store dictionary read from an existing document (ETSI EN 319 142-1 clause 5.4.2.2) —
/// the Unverified carriage (RP-4) <see cref="PdfDssReader.Locate"/> produces.
/// </summary>
/// <remarks>Ownership: owns every carrier it exposes, including every <see cref="PdfVriDictionary"/> in <see cref="VriEntries"/>; <see cref="Dispose"/> disposes all of them.</remarks>
[DebuggerDisplay("PdfDssDictionary: {Certificates.Count} cert(s), {CertificateRevocationLists.Count} CRL(s), {OcspResponses.Count} OCSP(s), {VriEntries.Count} VRI entry/entries")]
public sealed class PdfDssDictionary: IDisposable
{
    private bool disposed;


    /// <summary>Initializes a new <see cref="PdfDssDictionary"/>. Ownership of every carrier transfers to this instance.</summary>
    /// <param name="certificates">See <see cref="Certificates"/>.</param>
    /// <param name="certificateRevocationLists">See <see cref="CertificateRevocationLists"/>.</param>
    /// <param name="ocspResponses">See <see cref="OcspResponses"/>.</param>
    /// <param name="vriEntries">See <see cref="VriEntries"/>.</param>
    public PdfDssDictionary(
        IReadOnlyList<PkiCertificateMemory> certificates,
        IReadOnlyList<PkiCertificateMemory> certificateRevocationLists,
        IReadOnlyList<PkiCertificateMemory> ocspResponses,
        IReadOnlyDictionary<string, PdfVriDictionary> vriEntries)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(certificateRevocationLists);
        ArgumentNullException.ThrowIfNull(ocspResponses);
        ArgumentNullException.ThrowIfNull(vriEntries);

        Certificates = certificates;
        CertificateRevocationLists = certificateRevocationLists;
        OcspResponses = ocspResponses;
        VriEntries = vriEntries;
    }


    /// <summary>Gets the <c>Certs</c> array's own certificates (PA-5.4.2.2-06), empty when the entry was absent.</summary>
    public IReadOnlyList<PkiCertificateMemory> Certificates { get; }

    /// <summary>Gets the <c>CRLs</c> array's own CRLs (PA-5.4.2.2-08), empty when the entry was absent.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateRevocationLists { get; }

    /// <summary>Gets the <c>OCSPs</c> array's own responses (PA-5.4.2.2-07), empty when the entry was absent.</summary>
    public IReadOnlyList<PkiCertificateMemory> OcspResponses { get; }

    /// <summary>Gets the <c>VRI</c> dictionary's own entries, keyed by the base-16 uppercase SHA-1 digest <see cref="PdfVriKey"/> computes (PA-5.4.2.2-T2), empty when the entry was absent.</summary>
    public IReadOnlyDictionary<string, PdfVriDictionary> VriEntries { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        DisposeAll(Certificates);
        DisposeAll(CertificateRevocationLists);
        DisposeAll(OcspResponses);
        foreach(PdfVriDictionary vri in VriEntries.Values)
        {
            vri.Dispose();
        }

        disposed = true;
    }


    private static void DisposeAll(IReadOnlyList<PkiCertificateMemory> items)
    {
        for(int i = 0; i < items.Count; ++i)
        {
            items[i].Dispose();
        }
    }
}


/// <summary>
/// The outcome of <see cref="PdfDssReader.Locate"/> — the promotion-shaped (RP-4) Unverified carriage of a
/// document's DSS dictionary, mirroring <see cref="PdfByteSurfaceParseResult"/>'s own three-way shape: a
/// structural failure, a well-formed document that simply carries no DSS, and a successfully decoded DSS.
/// </summary>
[DebuggerDisplay("PdfDssParseResult: {IsSuccess}, HasDss={HasDss}")]
public sealed class PdfDssParseResult: IDisposable
{
    private bool disposed;


    private PdfDssParseResult(bool isSuccess, string? failureReason, bool hasDss, PdfDssDictionary? dss)
    {
        IsSuccess = isSuccess;
        FailureReason = failureReason;
        HasDss = hasDss;
        Dss = dss;
    }


    /// <summary>Gets whether the document's catalog and (when present) DSS dictionary could be located and decoded. When <see langword="false"/>, <see cref="Dss"/> is <see langword="null"/>.</summary>
    public bool IsSuccess { get; }

    /// <summary>Gets why locating or decoding failed, or <see langword="null"/> when <see cref="IsSuccess"/> is <see langword="true"/>.</summary>
    public string? FailureReason { get; }

    /// <summary>Gets whether the document catalog carries a <c>DSS</c> entry at all. A well-formed document without one is a legitimate outcome (<see cref="IsSuccess"/> <see langword="true"/>, this <see langword="false"/>, <see cref="Dss"/> <see langword="null"/>) — clause 5.4.2.2 states the entry is optional.</summary>
    public bool HasDss { get; }

    /// <summary>Gets the decoded DSS dictionary, or <see langword="null"/> when <see cref="HasDss"/> is <see langword="false"/> or <see cref="IsSuccess"/> is <see langword="false"/>. Owned by this instance.</summary>
    public PdfDssDictionary? Dss { get; }


    /// <summary>Mints a result for a document carrying a successfully decoded DSS. Ownership of <paramref name="dss"/> transfers.</summary>
    internal static PdfDssParseResult Success(PdfDssDictionary dss) => new(true, null, true, dss);


    /// <summary>Mints a result for a well-formed document that carries no <c>DSS</c> catalog entry.</summary>
    internal static PdfDssParseResult NoDss() => new(true, null, false, null);


    /// <summary>Mints a failed result carrying no decoded content.</summary>
    internal static PdfDssParseResult Failure(string reason) => new(false, reason, false, null);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        Dss?.Dispose();
        disposed = true;
    }
}
