using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// An ICAO CSCA Master List (ICAO Doc 9303 Part 12 §7.1, the ICAO PKD interface): a CMS SignedData whose
/// encapsulated content is a <c>CscaMasterList</c> — a set of Country Signing CA certificates a state (or
/// the ICAO PKD) publishes so a relying party can obtain the trust anchors Passive Authentication needs.
/// </summary>
/// <remarks>
/// <para>
/// The structure layers on the neutral CMS signature-verification seam exactly as the eMRTD Document
/// Security Object does: the signature over the encapsulated content is verified (fail-closed), then the
/// encapsulated content type is checked to be <c>id-icao-cscaMasterList</c> and the content is parsed as
/// <c>CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF Certificate }</c>. Each member of the
/// set is an X.509 CSCA certificate, surfaced as a <see cref="PkiCertificateMemory"/> ready to feed
/// <see cref="PassiveAuthentication.VerifyAsync"/> as a trust anchor.
/// </para>
/// <para>
/// Verifying the master list's CMS signature proves its integrity. Establishing trust in the master list's
/// signer — chaining the Master List Signer certificate (<see cref="CscaMasterListContent.SignerCertificate"/>)
/// to an already-trusted CSCA or the ICAO root — is the relying party's separate policy, performed through
/// the certificate-chain seam, mirroring how this library keeps signature verification and trust
/// establishment composable.
/// </para>
/// </remarks>
public static class CscaMasterList
{
    /// <summary>The <c>id-icao-cscaMasterList</c> encapsulated content type (ICAO Doc 9303 Part 12).</summary>
    public const string ContentTypeOid = "2.23.136.1.1.2";

    private const byte SequenceTag = 0x30;
    private const byte IntegerTag = 0x02;
    private const byte SetTag = 0x31;


    /// <summary>
    /// Verifies a CSCA Master List's CMS signature and extracts the Country Signing CA certificates it carries.
    /// </summary>
    /// <param name="masterList">The CMS SignedData of the master list.</param>
    /// <param name="pool">The memory pool for the extracted certificate carriers.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The parsed master-list content. The caller disposes it.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the CMS signature does not verify.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the signed content is not an <c>id-icao-cscaMasterList</c> or is malformed.</exception>
    public static async ValueTask<CscaMasterListContent> ParseAsync(
        CmsSignedData masterList,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(masterList);
        ArgumentNullException.ThrowIfNull(pool);

        VerifyCmsSignedDataDelegate verifyCms = Resolve<VerifyCmsSignedDataDelegate>();

        //Step 1: verify the master list's CMS signature (fail-closed), as the Document Security Object does.
        using CmsVerifiedContent verified = await verifyCms(masterList, pool, cancellationToken).ConfigureAwait(false);

        //Step 2: the signed content must be a CSCA Master List, not some other CMS payload.
        if(!string.Equals(verified.ContentType, ContentTypeOid, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The signed content type '{verified.ContentType}' is not the CSCA Master List content type '{ContentTypeOid}'.");
        }

        //Step 3: parse the CscaMasterList and copy out the signer and the CSCA certificates into owned carriers.
        return ParseContent(verified.Content.Span, verified.SignerCertificate.AsReadOnlySpan(), pool);
    }


    /// <summary>
    /// Parses the <c>CscaMasterList</c> content (<c>SEQUENCE { version INTEGER, certList SET OF Certificate }</c>)
    /// and copies the signer and each CSCA certificate into owned carriers. Synchronous so the
    /// <see cref="ApduReader"/> ref struct never crosses an <see langword="await"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the signer and certificate carriers transfers to the returned content; the catch disposes them on a partial parse failure.")]
    private static CscaMasterListContent ParseContent(ReadOnlySpan<byte> content, ReadOnlySpan<byte> signerCertificate, MemoryPool<byte> pool)
    {
        var reader = new ApduReader(content);
        ExpectTag(ref reader, SequenceTag, "CSCA Master List");
        _ = reader.ReadTlvLength();

        int version = ReadInteger(ref reader);

        ExpectTag(ref reader, SetTag, "certificate list");
        int setLength = reader.ReadTlvLength();
        int setEnd = reader.Consumed + setLength;

        PkiCertificateMemory? signer = null;
        var certificates = new List<PkiCertificateMemory>();
        try
        {
            while(reader.Consumed < setEnd)
            {
                int elementStart = reader.Consumed;
                if(reader.ReadByte() != SequenceTag)
                {
                    throw new InvalidOperationException("A CSCA Master List certificate must be a DER SEQUENCE.");
                }

                int certificateLength = reader.ReadTlvLength();
                int headerLength = reader.Consumed - elementStart;
                ReadOnlySpan<byte> certificate = content.Slice(elementStart, headerLength + certificateLength);
                reader.Skip(certificateLength);

                certificates.Add(CopyCertificate(certificate, pool));
            }

            signer = CopyCertificate(signerCertificate, pool);

            return new CscaMasterListContent(version, signer, certificates);
        }
        catch
        {
            signer?.Dispose();
            foreach(PkiCertificateMemory certificate in certificates)
            {
                certificate.Dispose();
            }

            throw;
        }
    }


    /// <summary>
    /// Copies a DER certificate into a pooled <see cref="PkiCertificateMemory"/> tagged as an X.509 certificate.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned PkiCertificateMemory; the catch disposes it on failure.")]
    private static PkiCertificateMemory CopyCertificate(ReadOnlySpan<byte> der, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        try
        {
            der.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Reads a small non-negative INTEGER (the master-list version).
    /// </summary>
    private static int ReadInteger(ref ApduReader reader)
    {
        ExpectTag(ref reader, IntegerTag, "version");
        int length = reader.ReadTlvLength();
        ReadOnlySpan<byte> value = reader.ReadBytes(length);

        int result = 0;
        foreach(byte octet in value)
        {
            result = (result << 8) | octet;
        }

        return result;
    }


    /// <summary>
    /// Reads and checks the expected tag, throwing when it does not match.
    /// </summary>
    private static void ExpectTag(ref ApduReader reader, byte expectedTag, string elementName)
    {
        if(reader.ReadByte() != expectedTag)
        {
            throw new InvalidOperationException($"Expected a {elementName} element (tag 0x{expectedTag:X2}).");
        }
    }


    /// <summary>
    /// Resolves a registered delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}


/// <summary>
/// The verified content of an ICAO CSCA Master List: its version, the Master List Signer certificate the CMS
/// carried, and the Country Signing CA certificates it lists — trust anchors for Passive Authentication. Owns
/// and disposes every certificate carrier.
/// </summary>
public sealed class CscaMasterListContent: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initialises a new <see cref="CscaMasterListContent"/>. Ownership of the signer certificate and every
    /// Country Signing CA certificate transfers to this instance.
    /// </summary>
    /// <param name="version">The master-list version (<c>0</c> for the only defined version).</param>
    /// <param name="signerCertificate">The Master List Signer certificate from the CMS.</param>
    /// <param name="countrySigningCertificateAuthorities">The Country Signing CA certificates the list carries.</param>
    public CscaMasterListContent(
        int version,
        PkiCertificateMemory signerCertificate,
        IReadOnlyList<PkiCertificateMemory> countrySigningCertificateAuthorities)
    {
        ArgumentNullException.ThrowIfNull(signerCertificate);
        ArgumentNullException.ThrowIfNull(countrySigningCertificateAuthorities);

        Version = version;
        SignerCertificate = signerCertificate;
        CountrySigningCertificateAuthorities = countrySigningCertificateAuthorities;
    }


    /// <summary>Gets the master-list version.</summary>
    public int Version { get; }

    /// <summary>Gets the Master List Signer certificate the CMS embedded. Owned by this instance.</summary>
    public PkiCertificateMemory SignerCertificate { get; }

    /// <summary>Gets the Country Signing CA certificates the master list carries — Passive Authentication trust anchors. Owned by this instance.</summary>
    public IReadOnlyList<PkiCertificateMemory> CountrySigningCertificateAuthorities { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            SignerCertificate.Dispose();
            foreach(PkiCertificateMemory certificate in CountrySigningCertificateAuthorities)
            {
                certificate.Dispose();
            }

            disposed = true;
        }
    }
}
