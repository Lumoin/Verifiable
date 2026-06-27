using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu.Eac;

/// <summary>
/// A Certificate Holder Authorization Template (CHAT, tag <c>7F4C</c>) from a card-verifiable certificate
/// body — the certificate holder's terminal type and relative authorization (role and access rights)
/// granted by the issuing authority. The template is a <see cref="TerminalType"/>-selecting object
/// identifier followed by a discretionary-data value (<c>53</c>) whose leading two bits encode the
/// <see cref="CertificateRole"/> and whose remaining bits are the terminal-type-specific access-rights
/// bitmask (BSI TR-03110-3 §C.1.5, with the bit layout defined in TR-03110 Part 4).
/// </summary>
/// <remarks>
/// <para>
/// A tracked carrier rather than a naked buffer: it owns the pooled discretionary-data bytes, clears them
/// on disposal, and carries <see cref="ApduTags.CertificateHolderAuthorization"/> for provenance. The raw
/// access-rights value (including the role bits) is exposed through the inherited
/// <see cref="SensitiveMemory.AsReadOnlySpan"/>; <see cref="Role"/> decodes the leading two bits and
/// <see cref="TerminalType"/> the object identifier.
/// </para>
/// </remarks>
[DebuggerDisplay("CHAT({TerminalType}, {Role})")]
public sealed class CertificateHolderAuthorizationTemplate: SensitiveMemory
{
    /// <summary>The relative-authorization bits an Inspection System template uses for eMRTD sensitive-data read access (EF.DG3 and EF.DG4); the leading two role bits and the remaining reserved bits are masked off.</summary>
    private const byte EmrtdReadAccessMask = (byte)(InspectionSystemAccess.ReadDataGroup3Fingerprint | InspectionSystemAccess.ReadDataGroup4Iris);

    /// <summary>
    /// Initialises a new <see cref="CertificateHolderAuthorizationTemplate"/> from owned discretionary-data bytes.
    /// </summary>
    /// <param name="discretionaryData">The owned discretionary-data (<c>53</c>) bytes — role and access rights. Ownership transfers to this instance.</param>
    /// <param name="terminalType">The terminal type the object identifier selects.</param>
    /// <param name="role">The certificate holder's role, decoded from the leading two bits.</param>
    internal CertificateHolderAuthorizationTemplate(IMemoryOwner<byte> discretionaryData, TerminalType terminalType, CertificateRole role)
        : base(discretionaryData, ApduTags.CertificateHolderAuthorization)
    {
        ArgumentNullException.ThrowIfNull(discretionaryData);
        TerminalType = terminalType;
        Role = role;
    }


    /// <summary>Gets the terminal type the certificate holder is authorised as (Inspection System, Authentication Terminal, or Signature Terminal).</summary>
    public TerminalType TerminalType { get; }

    /// <summary>Gets the certificate holder's role relative to the issuing authority, decoded from the leading two bits of the access-rights value.</summary>
    public CertificateRole Role { get; }

    /// <summary>Gets the length of the discretionary-data (access-rights) value in bytes — one for an Inspection System or Signature Terminal, five for an Authentication Terminal.</summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets the eMRTD sensitive-data read access this template grants when read as an Inspection System
    /// relative authorization (id-IS, BSI TR-03110 Part 4): the chip releases EF.DG3 (fingerprints) and
    /// EF.DG4 (iris) only to an authenticated terminal whose effective authorization sets the matching bit.
    /// Decoded from the first relative-authorization octet — bit 1 grants EF.DG4, bit 2 grants EF.DG3 — with
    /// the leading two role bits and the reserved bits masked off. An Authentication Terminal or Signature
    /// Terminal template carries no eMRTD read bits in that octet, so the result is
    /// <see cref="InspectionSystemAccess.None"/>.
    /// </summary>
    public InspectionSystemAccess InspectionSystemReadAccess => (InspectionSystemAccess)(AsReadOnlySpan()[0] & EmrtdReadAccessMask);
}


/// <summary>
/// The terminal type a Certificate Holder Authorization Template authorises, selected by its object
/// identifier (<c>id-IS</c>, <c>id-AT</c>, <c>id-ST</c> under <c>0.4.0.127.0.7.3.1.2</c>, BSI TR-03110 Part 4).
/// </summary>
public enum TerminalType
{
    /// <summary>Inspection System (<c>id-IS</c>) — reads the more-sensitive eMRTD data groups (e.g. fingerprints).</summary>
    InspectionSystem,

    /// <summary>Authentication Terminal (<c>id-AT</c>) — an eID terminal reading eID data groups under a per-terminal access-rights set.</summary>
    AuthenticationTerminal,

    /// <summary>Signature Terminal (<c>id-ST</c>) — a terminal authorising a qualified electronic signature.</summary>
    SignatureTerminal
}


/// <summary>
/// The role a card-verifiable certificate holder has relative to the issuing authority, encoded in the
/// leading two bits of the Certificate Holder Authorization discretionary data (BSI TR-03110 Part 4). The
/// role bounds the certificate's position in the chain: a CVCA issues Document Verifier certificates, a
/// Document Verifier issues terminal certificates.
/// </summary>
public enum CertificateRole
{
    /// <summary>An end-entity terminal certificate (role bits <c>00</c>).</summary>
    Terminal,

    /// <summary>A non-official or foreign Document Verifier (role bits <c>01</c>).</summary>
    DocumentVerifierNonOfficialOrForeign,

    /// <summary>An official domestic Document Verifier (role bits <c>10</c>).</summary>
    DocumentVerifierOfficialDomestic,

    /// <summary>A Country Verifying Certification Authority — the trust anchor (role bits <c>11</c>).</summary>
    CertificationAuthority
}


/// <summary>
/// The eMRTD sensitive-data read access an Inspection System's effective authorization grants, decoded from
/// the relative-authorization byte of a Certificate Holder Authorization Template (id-IS, BSI TR-03110
/// Part 4). After Terminal Authentication the chip releases EF.DG3 and EF.DG4 only when the effective
/// authorization — the bitwise AND of the Certificate Holder Authorization Templates along the verified
/// chain (the Terminal, Document Verifier, and Country Verifying Certification Authority certificates,
/// BSI TR-03110-3 §2.7) — sets the corresponding bit.
/// </summary>
[Flags]
public enum InspectionSystemAccess
{
    /// <summary>No sensitive-data read access (the relative-authorization octet carries only role and reserved bits).</summary>
    None = 0,

    /// <summary>Read access to EF.DG4 (iris), the first relative-authorization bit (<c>0x01</c>).</summary>
    ReadDataGroup4Iris = 0x01,

    /// <summary>Read access to EF.DG3 (fingerprints), the second relative-authorization bit (<c>0x02</c>).</summary>
    ReadDataGroup3Fingerprint = 0x02
}
