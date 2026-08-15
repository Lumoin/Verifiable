using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One <c>AttributeTypeAndValue</c> of an RFC 5280 §4.1.2.4 <c>Name</c>: an attribute type identifier, its
/// text value, and the ASN.1 string form the value is encoded in.
/// </summary>
/// <param name="AttributeTypeOid">The attribute type identifier (for example <see cref="WellKnownOids.CountryName"/>).</param>
/// <param name="Value">The attribute value text.</param>
/// <param name="Encoding">The character string form the value is encoded in (typically <see cref="UniversalTagNumber.PrintableString"/> or <see cref="UniversalTagNumber.UTF8String"/>).</param>
[DebuggerDisplay("DirectoryNameAttribute: {AttributeTypeOid}={Value}")]
public readonly record struct DirectoryNameAttribute(string AttributeTypeOid, string Value, UniversalTagNumber Encoding);


/// <summary>
/// One <c>Extension</c> (RFC 5280 §4.1.2.9) to place in a minted certificate's <c>extensions</c> field: an
/// extension identifier, its criticality, and its already-DER-encoded inner value — the bytes that become
/// the content of the extension's <c>extnValue</c> OCTET STRING, before that outer wrapper is applied.
/// </summary>
/// <remarks>
/// <see cref="QualifiedCertificateMinting"/>'s extension writers return instances of this type. The pooled
/// <see cref="Value"/> is owned by this instance; the caller disposes it once the extension has been placed
/// into a <see cref="CertificateMintRequest"/> and the mint call has returned.
/// </remarks>
[DebuggerDisplay("CertificateExtensionContent: {ExtensionOid}, critical={IsCritical}, {Value.Length} octets")]
public sealed class CertificateExtensionContent: IDisposable
{
    /// <summary>Creates an extension content carrier, taking ownership of <paramref name="value"/>.</summary>
    /// <param name="extensionOid">The extension identifier (<c>extnID</c>).</param>
    /// <param name="isCritical">The extension's <c>critical</c> flag.</param>
    /// <param name="value">The DER-encoded inner extension value; ownership transfers to this instance.</param>
    public CertificateExtensionContent(string extensionOid, bool isCritical, PooledMemory value)
    {
        ArgumentNullException.ThrowIfNull(extensionOid);
        ArgumentNullException.ThrowIfNull(value);

        ExtensionOid = extensionOid;
        IsCritical = isCritical;
        Value = value;
    }

    /// <summary>The extension identifier (<c>extnID</c>).</summary>
    public string ExtensionOid { get; }

    /// <summary>The extension's <c>critical</c> flag.</summary>
    public bool IsCritical { get; }

    /// <summary>The DER-encoded inner extension value (the future content of <c>extnValue</c>).</summary>
    public PooledMemory Value { get; }

    /// <summary>Disposes the pooled <see cref="Value"/>.</summary>
    public void Dispose()
    {
        Value.Dispose();
    }
}


/// <summary>
/// The caller-supplied inputs to <see cref="QualifiedCertificateMinting.MintCertificateAsync(CertificateMintRequest, PrivateKeyMemory, BaseMemoryPool, CancellationToken)"/>:
/// the RFC 5280 to-be-signed fields every X.509 v3 certificate carries, short of the version, serial number
/// and signature — those are the minter's own concern (a fresh serial per RFC 5280 §4.1.2.2, version 3, and
/// a signature over exactly these fields, computed through the registry). A plain class, not a record: two
/// instances carrying disposable <see cref="Extensions"/> entries are never interchangeable by content, so
/// synthesized structural equality has no sound meaning here.
/// </summary>
[DebuggerDisplay("CertificateMintRequest: {Extensions.Count} extensions, NotBefore={NotBefore}, NotAfter={NotAfter}")]
public sealed class CertificateMintRequest
{
    /// <summary>The issuer <c>Name</c> (RFC 5280 §4.1.2.4), already DER-encoded (tag and length included) — typically <see cref="QualifiedCertificateMinting.WriteDirectoryName"/>'s output, or an issuing CA's own subject <c>Name</c> read straight off its certificate.</summary>
    public required ReadOnlyMemory<byte> IssuerName { get; init; }

    /// <summary>The subject <c>Name</c> (RFC 5280 §4.1.2.4), already DER-encoded (tag and length included).</summary>
    public required ReadOnlyMemory<byte> SubjectName { get; init; }

    /// <summary>The validity period's start.</summary>
    public required DateTimeOffset NotBefore { get; init; }

    /// <summary>The validity period's end.</summary>
    public required DateTimeOffset NotAfter { get; init; }

    /// <summary>The subject's public key, encoded into <c>subjectPublicKeyInfo</c> per its <see cref="Tag"/>'s <see cref="CryptoAlgorithm"/>. The caller retains ownership.</summary>
    public required PublicKeyMemory SubjectPublicKey { get; init; }

    /// <summary>The certificate's extensions, in certificate order; empty for none. The caller retains ownership of every entry.</summary>
    public required IReadOnlyList<CertificateExtensionContent> Extensions { get; init; }
}


/// <summary>
/// The optional <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
/// ETSI EN 319 412-5 V2.6.1</see> clause 4.3 generic <c>QCStatement</c>s a qualified certificate's
/// <c>qcStatements</c> extension may carry alongside the mandatory <c>QcCompliance</c> and <c>QcType</c>
/// statements <see cref="QualifiedCertificateMinting.WriteQcStatementsExtension"/> always writes. There is
/// deliberately no <c>QcCClegislation</c> (clause 4.2.4) member: every certificate this type feeds declares
/// the EU-qualified aim clause 4.2.1's heading names first ("a EU qualified certificate ... issued according
/// to Directive 1999/93/EC [i.3] or the Annex I, III or IV of Regulation (EU) No 910/2014 [i.8]"), which
/// QCS-4.2.1-01 a) forbids from carrying a <c>QcCClegislation</c> statement; the heading's other case ("a
/// certificate being qualified within a defined legal framework from an identified country or set of
/// countries", clause 4.2.4's own audience) is out of this surface's scope, so the shape that would violate
/// the rule is not representable.
/// </summary>
[DebuggerDisplay("QualifiedCertificateStatements: limitValue={LimitValue is not null}, retention={RetentionPeriodYears}, pds={PdsLocations.Count}, method={IdentificationMethod}")]
public sealed record QualifiedCertificateStatements
{
    /// <summary>The clause 4.3.2 <c>QcLimitValue</c> statement's transaction-value limit, or <see langword="null"/> to omit the statement.</summary>
    public QcMonetaryValue? LimitValue { get; init; }

    /// <summary>The clause 4.3.3 <c>QcRetentionPeriod</c> statement's retention period in years, or <see langword="null"/> to omit the statement.</summary>
    public BigInteger? RetentionPeriodYears { get; init; }

    /// <summary>The clause 4.3.4 <c>QcPDS</c> statement's PKI Disclosure Statement locations, in statement order; empty to omit the statement.</summary>
    public IReadOnlyList<PdsLocation> PdsLocations { get; init; } = [];

    /// <summary>
    /// The clause 4.3.5 <c>QcIdentMethod</c> statement's declared identification method — Annex B's
    /// <c>QcIdentMethod ::= SEQUENCE SIZE (1) OF OBJECT IDENTIFIER</c> (:904, clause 4.3.5.1 :534; QCS-4.1-04
    /// gives Annex B precedence over the body text in case of discrepancy) takes exactly one value — or
    /// <see langword="null"/> to omit the statement.
    /// </summary>
    public EuIdentityVerificationMethod? IdentificationMethod { get; init; }

    /// <summary>The clause 4.2.5 <c>QcQSCDlegislation</c> statement's country codes, in statement order; empty to omit the statement.</summary>
    public IReadOnlyList<string> QscdLegislationCountryCodes { get; init; } = [];
}


/// <summary>
/// Mints X.509 v3 certificates for the EU-qualified issuance profile with <see cref="AsnWriter"/> only — no
/// <see cref="System.Security.Cryptography.X509Certificates.CertificateRequest"/>, no platform certificate
/// type on this surface — in the register of the library's other creation surfaces
/// (<see cref="CAdESSignatureCreation"/>, <see cref="OcspRequests"/>, <see cref="TimestampRequests"/>): this
/// type mints artifacts, signed through the same <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
/// seam <see cref="CAdESSignatureCreation.SignAsync(PkiCertificateMemory, PrivateKeyMemory, ReadOnlyMemory{byte}?, ReadOnlyMemory{byte}?, DateTimeOffset, IReadOnlyList{PkiCertificateMemory}?, CryptographicConstraints?, bool, BaseMemoryPool, CancellationToken)"/>
/// uses, never a behavioral automaton. The minter never generates key material: every certificate's subject
/// key and every issuer's signing key are caller-supplied.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This surface enforces the EU-qualified issuance profile by construction and refuses everything
/// else.</strong> There is no hostile or permissive mode: a caller who wants a nonconformant, malformed, or
/// third-country-profile certificate for negative testing builds one directly with <see cref="AsnWriter"/>
/// (the library's own conformance tests do exactly that). <see cref="WriteQcStatementsExtension"/> and
/// <see cref="MintQualifiedCertificateAsync"/> refuse a profile-rule violation they can detect with
/// <see cref="ArgumentException"/> naming the ETSI requirement key; several rules are unrepresentable rather
/// than checked, because the input model has no parameter through which to violate them:
/// </para>
/// <list type="bullet">
/// <item><description>QCS-4.1-02 (the <c>qcStatements</c> extension "shall not be marked as critical"): the writer always emits <c>critical = FALSE</c>; there is no parameter to flip it.</description></item>
/// <item><description>QCS-4.1-02A (no more than one instance of a statement): each statement kind is one record field, so a duplicate cannot be constructed.</description></item>
/// <item><description>QCS-4.1-04 (Annex B shapes only): the writer emits only the shapes it implements.</description></item>
/// <item><description>Clause 4.2.3's <c>QcType ::= SEQUENCE SIZE (1) OF OBJECT IDENTIFIER</c>: <see cref="EuQualifiedCertificateType"/> is a single value, not a list.</description></item>
/// <item><description>Clause 4.3.5.1's <c>QcIdentMethod ::= SEQUENCE SIZE (1) OF OBJECT IDENTIFIER</c> (Annex B :904; QCS-4.1-04 gives Annex B precedence): <see cref="QualifiedCertificateStatements.IdentificationMethod"/> is a single nullable value, not a list.</description></item>
/// <item><description>QCS-4.2.1-01 a) (no <c>QcCClegislation</c> alongside <c>QcCompliance</c>): see <see cref="QualifiedCertificateStatements"/>'s remarks.</description></item>
/// <item><description>Table 2's mandatory <c>QcCompliance</c> and forbidden <c>QcCClegislation</c>: the former is always written, the latter is never reachable.</description></item>
/// <item><description>Table 2's <c>esi4-qcStatement-6</c> (<c>QcType</c>) condition (present when the certificate is eseal/web): always written for all three types, so the condition is vacuously satisfied.</description></item>
/// </list>
/// <para>
/// The rules that <em>are</em> checked at call time — because the input model can state a value that
/// violates them — are EN 319 411-2 GEN-6.6.1-03/-04 (a clause 5.3 [QCP-n-qscd]/[QCP-l-qscd] policy
/// identifier must agree with the <c>QcSSCD</c> statement's presence, cross-checked in
/// <see cref="MintQualifiedCertificateAsync"/> against <see cref="WriteCertificatePoliciesExtension"/>'s own
/// input), GEN-6.6.1-04's website-authentication/QSCD combination (checked in
/// <see cref="WriteQcStatementsExtension"/> against the declared <see cref="EuQualifiedCertificateType"/>),
/// GEN-6.6.1-05 (at least one certificate policy identifier, and the [QEVCP-w]/[QNCP-w] conjunction that
/// refuses <see cref="WellKnownOids.QcpWeb"/> or <see cref="WellKnownOids.QncpWeb"/> standing alone),
/// QCS-4.2.5-01 (the <c>QcQSCDlegislation</c> EU/EEA refusal), QCS-4.3.4-01/-03 with Table 2's PDS
/// conditions (language code shape, <c>https</c> scheme, one English PDS, no duplicate language), clause
/// 4.3.2's <c>Iso4217CurrencyCode</c> syntax, and QCS-4.3.5-02 (only a known <c>QcIdentMethod</c>
/// identifier).
/// </para>
/// <para>
/// <strong>Mint/read asymmetry.</strong> <see cref="QualifiedCertificateFactsExtractor"/> deliberately
/// tolerates on read several encodings this minter refuses to emit (see that type's own remarks) — a
/// duplicate statement, a malformed <c>statementInfo</c>, an unrecognised identifier. That asymmetry is
/// intentional: the extractor reads whatever a real-world certificate carries, while this minter only ever
/// produces the profile it enforces.
/// </para>
/// </remarks>
public static class QualifiedCertificateMinting
{
    /// <summary>The number of CSPRNG bytes drawn for a certificate serial number (RFC 5280 §4.1.2.2 caps the encoded value at 20 octets; 8 bytes plus a possible DER sign-extension octet stays well inside that).</summary>
    private const int SerialNumberByteLength = 8;

    /// <summary>The <c>tbsCertificate.version</c> value for X.509 v3 (RFC 5280 §4.1.2.1: the INTEGER value is one less than the version number).</summary>
    private const int CertificateVersion3 = 2;

    /// <summary>The first year a <c>Validity</c> time is encoded as <c>GeneralizedTime</c> rather than <c>UTCTime</c> (RFC 5280 §4.1.2.5).</summary>
    private const int GeneralizedTimePivotYear = 2050;

    /// <summary>The <c>[0]</c> constructed context tag: <c>tbsCertificate.version</c> (RFC 5280 §4.1.2.1) and the <c>extensions</c> field's own <c>[3]</c> tag is written inline where used.</summary>
    private static Asn1Tag VersionContextTag { get; } = new(TagClass.ContextSpecific, 0, isConstructed: true);

    /// <summary>The <c>[3]</c> constructed context tag: <c>tbsCertificate.extensions</c> (RFC 5280 §4.1.2.9).</summary>
    private static Asn1Tag ExtensionsContextTag { get; } = new(TagClass.ContextSpecific, 3, isConstructed: true);

    /// <summary>The <c>[0]</c> IMPLICIT primitive context tag: <c>AuthorityKeyIdentifier.keyIdentifier</c> (RFC 5280 §4.2.1.1).</summary>
    private static Asn1Tag AuthorityKeyIdentifierKeyIdTag { get; } = new(TagClass.ContextSpecific, 0);

    /// <summary>An empty <see cref="QualifiedCertificateStatements"/>, used when a caller supplies none.</summary>
    private static QualifiedCertificateStatements EmptyStatements { get; } = new();

    /// <summary>Tags a pooled buffer holding a DER-encoded fragment of public certificate content, via the shared <see cref="CryptoTags.DerEncodedCertificateContent"/> entry.</summary>
    private static Tag DerFragmentTag { get; } = CryptoTags.DerEncodedCertificateContent;

    /// <summary>
    /// The ISO 3166-1 alpha-2 codes of the EU member states plus the non-EU EEA members (Iceland, Liechtenstein,
    /// Norway), and "EL" (the EU trusted-list territory code this library's own
    /// <see cref="TrustedListQualification.ResolveTrustedListTerritory"/> produces for Greece, alongside the
    /// ISO code "GR"), for the QCS-4.2.5-01 refusal: "CountryName shall not have as value any code
    /// identifying: a country of the European Union (EU); or a country of the European Economic Area (EEA);
    /// or a group of EU or EEA countries; or the value of 'EU'." Compared case-insensitively, matching
    /// <c>CountryName</c>'s PrintableString case tolerance. "GB"/"UK" are deliberately absent: the United
    /// Kingdom withdrew from the EU and is not an EEA member, so a code identifying it does not fall under
    /// this refusal.
    /// </summary>
    private static FrozenSet<string> EuAndEeaCountryCodes { get; } = new[]
    {
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "EL", "HU", "IE", "IT",
        "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
        "IS", "LI", "NO"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);


    /// <summary>
    /// Assembles and signs an X.509 v3 certificate from <paramref name="request"/>, resolving the
    /// <see cref="SigningDelegate"/> from <paramref name="issuerPrivateKey"/>'s <see cref="Tag"/> through
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> — the tag-resolving convenience
    /// mirroring <see cref="CAdESSignatureCreation.SignAsync(PkiCertificateMemory, PrivateKeyMemory, ReadOnlyMemory{byte}?, ReadOnlyMemory{byte}?, DateTimeOffset, IReadOnlyList{PkiCertificateMemory}?, CryptographicConstraints?, bool, BaseMemoryPool, CancellationToken)"/>.
    /// </summary>
    /// <param name="request">The certificate's to-be-signed fields.</param>
    /// <param name="issuerPrivateKey">The issuer's signing key; its <see cref="Tag"/> resolves both the signing delegate and the signature algorithm identity.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled, signed certificate, tagged <see cref="PkiCertificateTags.X509Certificate"/>. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="request"/>, <paramref name="issuerPrivateKey"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="NotSupportedException">When <paramref name="issuerPrivateKey"/>'s algorithm is not one this surface signs with (P-256/P-384/P-521, RSA-2048/4096, or ML-DSA-44/65/87).</exception>
    public static ValueTask<PkiCertificateMemory> MintCertificateAsync(
        CertificateMintRequest request,
        PrivateKeyMemory issuerPrivateKey,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);

        CryptoAlgorithm algorithm = issuerPrivateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = issuerPrivateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return MintCertificateAsync(request, issuerPrivateKey, signingDelegate, pool, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Assembles and signs an X.509 v3 certificate from <paramref name="request"/> through an explicit
    /// <see cref="SigningDelegate"/> — for a caller that has already resolved one (testing, or a custom
    /// cryptographic backend) rather than routing through the registry.
    /// </summary>
    /// <param name="request">The certificate's to-be-signed fields.</param>
    /// <param name="issuerPrivateKey">The issuer's signing key; its <see cref="Tag"/> resolves the signature algorithm identity. Passed to <paramref name="signingDelegate"/> as the key bytes.</param>
    /// <param name="signingDelegate">The signing delegate to invoke over the encoded <c>tbsCertificate</c>.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="eventSink">Receives the <see cref="SignatureProducedEvent"/> <paramref name="signingDelegate"/> constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled, signed certificate, tagged <see cref="PkiCertificateTags.X509Certificate"/>. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="request"/>, <paramref name="issuerPrivateKey"/>, <paramref name="signingDelegate"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="NotSupportedException">When <paramref name="issuerPrivateKey"/>'s algorithm is not one this surface signs with, or <see cref="CertificateMintRequest.SubjectPublicKey"/>'s algorithm has no known <c>SubjectPublicKeyInfo</c> encoding.</exception>
    public static async ValueTask<PkiCertificateMemory> MintCertificateAsync(
        CertificateMintRequest request,
        PrivateKeyMemory issuerPrivateKey,
        SigningDelegate signingDelegate,
        BaseMemoryPool pool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.SubjectPublicKey);
        ArgumentNullException.ThrowIfNull(request.Extensions);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        CryptoAlgorithm signingAlgorithm = issuerPrivateKey.Tag.Get<CryptoAlgorithm>();
        MintingSigningProfile profile = ResolveSigningProfile(signingAlgorithm);

        using Salt serialNumber = CryptographicKeyEvents.GenerateSalt(SerialNumberByteLength, CryptoTags.X509CertificateSerialNumber, pool);
        using PooledMemory tbsCertificate = WriteTbsCertificate(request, profile, serialNumber.AsReadOnlySpan(), pool);

        (Signature signature, CryptoEvent? evt) = await signingDelegate(
            issuerPrivateKey.AsReadOnlyMemory(), tbsCertificate.AsReadOnlyMemory(), pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        using(signature)
        {
            if(evt is not null)
            {
                (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
            }

            if(profile.IsEllipticCurve)
            {
                //The registered signing seam produces the fixed-width IEEE P1363 r‖s form; X.509 wire encoding
                //requires the DER Ecdsa-Sig-Value SEQUENCE.
                using IMemoryOwner<byte> derSignature = EcdsaSignatureEncoding.ConvertP1363ToDer(signature.AsReadOnlySpan(), pool, out int derLength);

                return AssembleCertificate(tbsCertificate, profile, derSignature.Memory[..derLength].Span, pool);
            }

            return AssembleCertificate(tbsCertificate, profile, signature.AsReadOnlySpan(), pool);
        }
    }


    /// <summary>
    /// Encodes an RFC 5280 §4.1.2.4 <c>Name</c> (an <c>RDNSequence</c>) from directory attributes — one inner
    /// list per relative distinguished name, so a multi-valued RDN is a multi-attribute inner list.
    /// </summary>
    /// <param name="relativeDistinguishedNames">The relative distinguished names, in certificate order.</param>
    /// <param name="pool">The memory pool the returned buffer is rented from.</param>
    /// <returns>The encoded <c>Name</c> (tag and length included). The caller owns and disposes it.</returns>
    public static PooledMemory WriteDirectoryName(IReadOnlyList<IReadOnlyList<DirectoryNameAttribute>> relativeDistinguishedNames, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(relativeDistinguishedNames);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            foreach(IReadOnlyList<DirectoryNameAttribute> relativeName in relativeDistinguishedNames)
            {
                using(writer.PushSetOf())
                {
                    foreach(DirectoryNameAttribute attribute in relativeName)
                    {
                        using(writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(attribute.AttributeTypeOid);
                            writer.WriteCharacterString(attribute.Encoding, attribute.Value);
                        }
                    }
                }
            }
        }

        return Materialize(writer, pool);
    }


    /// <summary>
    /// Writes a qualified certificate's <c>qcStatements</c> extension (RFC 3739 §3.2.6, profiled by
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
    /// ETSI EN 319 412-5 V2.6.1</see>): always <c>id-etsi-qcs-QcCompliance</c> and exactly one
    /// <c>id-etsi-qcs-QcType</c> value (Table 2, clause 4.2.3), <c>id-etsi-qcs-QcSSCD</c> when
    /// <paramref name="requiresQualifiedSignatureCreationDevice"/> is <see langword="true"/> (Table 2, EN 319
    /// 411-2 GEN-6.6.1-03/-04), and the clause 4.3 generic statements <paramref name="additionalStatements"/>
    /// selects.
    /// </summary>
    /// <param name="certificateType">The declared <c>QcType</c> value.</param>
    /// <param name="requiresQualifiedSignatureCreationDevice">Whether the <c>QcSSCD</c> statement is written.</param>
    /// <param name="additionalStatements">The clause 4.3 generic statements to include, or <see langword="null"/> for none.</param>
    /// <param name="pool">The memory pool the returned buffer is rented from.</param>
    /// <returns>The non-critical <c>qcStatements</c> extension. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="certificateType"/> is <see cref="EuQualifiedCertificateType.None"/>; when
    /// <paramref name="certificateType"/> is <see cref="EuQualifiedCertificateType.WebsiteAuthentication"/> and
    /// <paramref name="requiresQualifiedSignatureCreationDevice"/> is <see langword="true"/> (GEN-6.6.1-04);
    /// when a supplied <see cref="QualifiedCertificateStatements.LimitValue"/> violates clause 4.3.2's
    /// <c>Iso4217CurrencyCode</c> CHOICE syntax; or when
    /// <see cref="QualifiedCertificateStatements.QscdLegislationCountryCodes"/> or
    /// <see cref="QualifiedCertificateStatements.PdsLocations"/> violate QCS-4.2.5-01, QCS-4.3.4-01,
    /// QCS-4.3.4-03, or Table 2's PDS conditions, or when
    /// <see cref="QualifiedCertificateStatements.IdentificationMethod"/> names none of the EN 319 412-5
    /// identification methods (QCS-4.3.5-02).
    /// </exception>
    public static CertificateExtensionContent WriteQcStatementsExtension(
        EuQualifiedCertificateType certificateType,
        bool requiresQualifiedSignatureCreationDevice,
        QualifiedCertificateStatements? additionalStatements,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(certificateType == EuQualifiedCertificateType.None)
        {
            throw new ArgumentException(
                "Clause 4.2.3: QcType ::= SEQUENCE SIZE (1) OF OBJECT IDENTIFIER declares exactly one certificate type; EuQualifiedCertificateType.None names none.",
                nameof(certificateType));
        }

        if(certificateType == EuQualifiedCertificateType.WebsiteAuthentication && requiresQualifiedSignatureCreationDevice)
        {
            throw new ArgumentException(
                "GEN-6.6.1-04: the QcSSCD statement shall not be included in certificates that are not issued according to [QCP-n-qscd] or [QCP-l-qscd]; website authentication has no QSCD-flavoured clause 5.3 policy.",
                nameof(requiresQualifiedSignatureCreationDevice));
        }

        QualifiedCertificateStatements statements = additionalStatements ?? EmptyStatements;
        if(statements.LimitValue is { } limitValue)
        {
            ValidateMonetaryValue(limitValue, nameof(additionalStatements));
        }

        ValidatePdsLocations(statements.PdsLocations, nameof(additionalStatements));
        ValidateQscdLegislationCountryCodes(statements.QscdLegislationCountryCodes, nameof(additionalStatements));

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            WriteQcStatement(writer, WellKnownOids.QcCompliance, static _ => { });

            if(statements.LimitValue is { } limit)
            {
                WriteQcStatement(writer, WellKnownOids.QcLimitValue, w => WriteMonetaryValue(w, limit));
            }

            if(statements.RetentionPeriodYears is { } retentionPeriodYears)
            {
                WriteQcStatement(writer, WellKnownOids.QcRetentionPeriod, w => w.WriteInteger(retentionPeriodYears));
            }

            if(requiresQualifiedSignatureCreationDevice)
            {
                WriteQcStatement(writer, WellKnownOids.QcSscd, static _ => { });
            }

            if(statements.PdsLocations.Count > 0)
            {
                WriteQcStatement(writer, WellKnownOids.QcPds, w => WritePdsLocations(w, statements.PdsLocations));
            }

            WriteQcStatement(writer, WellKnownOids.QcType, w =>
            {
                using(w.PushSequence())
                {
                    w.WriteObjectIdentifier(EuQualifiedCertificateTypeMapping.ToOid(certificateType));
                }
            });

            if(statements.IdentificationMethod is { } identificationMethod)
            {
                if(identificationMethod == EuIdentityVerificationMethod.None || !Enum.IsDefined(identificationMethod))
                {
                    throw new ArgumentException($"QCS-4.3.5-02: a QcIdentMethod statement shall contain the OID value corresponding to the identification used for identity verification; '{identificationMethod}' names none of the EN 319 412-5 identification methods.", nameof(additionalStatements));
                }

                WriteQcStatement(writer, WellKnownOids.QcIdentMethod, w =>
                {
                    using(w.PushSequence())
                    {
                        w.WriteObjectIdentifier(EuIdentityVerificationMethodMapping.ToOid(identificationMethod));
                    }
                });
            }

            if(statements.QscdLegislationCountryCodes.Count > 0)
            {
                WriteQcStatement(writer, WellKnownOids.QcQscdLegislation, w => WriteCountryCodes(w, statements.QscdLegislationCountryCodes));
            }
        }

        return EncodeExtension(WellKnownOids.QcStatementsExtension, isCritical: false, writer, pool);
    }


    /// <summary>
    /// Writes a <c>CertificatePolicies</c> extension (RFC 5280 §4.2.1.4) carrying
    /// <paramref name="policyOids"/>, in extension order.
    /// </summary>
    /// <param name="policyOids">The certificate policy identifiers — a clause 5.3 policy identifier and/or a TSP-allocated one (EN 319 411-2 GEN-6.6.1-05's CHOICE).</param>
    /// <param name="pool">The memory pool the returned buffer is rented from.</param>
    /// <returns>The non-critical <c>CertificatePolicies</c> extension. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="policyOids"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="policyOids"/> is empty (GEN-6.6.1-05: "The certificate shall include at least one
    /// of the following policy identifier"), or its only member is <see cref="WellKnownOids.QcpWeb"/> or
    /// <see cref="WellKnownOids.QncpWeb"/> — GEN-6.6.1-05's [QEVCP-w]/[QNCP-w] bullets conjunctively require an
    /// EVCG/BRG-specified OID alongside the clause 5.3 identifier, so that identifier cannot stand alone.
    /// </exception>
    public static CertificateExtensionContent WriteCertificatePoliciesExtension(IReadOnlyList<string> policyOids, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(policyOids);
        ArgumentNullException.ThrowIfNull(pool);
        if(policyOids.Count == 0)
        {
            throw new ArgumentException(
                "GEN-6.6.1-05: the certificate shall include at least one clause 5.3 and/or TSP-allocated policy identifier.",
                nameof(policyOids));
        }

        if(policyOids.Count == 1 && string.Equals(policyOids[0], WellKnownOids.QcpWeb, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "GEN-6.6.1-05 [QEVCP-w]: \"an OID as specified in EVCG [i.7], clause 7.1.6.1; and at least one of the following policy identifiers: as defined in clause 5.3 item e); and/or an OID allocated by the TSP\" — the clause 5.3 item e) identifier alone, with no EVCG OID, does not satisfy that conjunction.",
                nameof(policyOids));
        }

        if(policyOids.Count == 1 && string.Equals(policyOids[0], WellKnownOids.QncpWeb, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "GEN-6.6.1-05 [QNCP-w]: \"an OID as specified in BRG [i.3], clause 1.2 or 7.1.6.1; and at least one of the following policy identifiers: as defined in clause 5.3 item f); and/or an OID allocated by the TSP\" — the clause 5.3 item f) identifier alone, with no BRG OID, does not satisfy that conjunction.",
                nameof(policyOids));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            foreach(string policyOid in policyOids)
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(policyOid);
                }
            }
        }

        return EncodeExtension(WellKnownOids.CertificatePoliciesExtension, isCritical: false, writer, pool);
    }


    /// <summary>
    /// Mints a self-signed root Certification Authority certificate: <c>BasicConstraints{cA=TRUE,
    /// pathLenConstraint}</c> critical, <c>KeyUsage{keyCertSign, cRLSign}</c> critical, and a Subject Key
    /// Identifier, assembled with <see cref="AsnWriter"/> and signed through the registry.
    /// </summary>
    /// <param name="subjectName">The root's own name, also used as its issuer name (self-signed).</param>
    /// <param name="notBefore">The validity start.</param>
    /// <param name="notAfter">The validity end.</param>
    /// <param name="subjectPublicKey">The root's public key. The caller retains ownership.</param>
    /// <param name="issuerPrivateKey">The root's own signing key (self-signed).</param>
    /// <param name="pathLengthConstraint">The Basic Constraints path length budget.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="additionalExtensions">Extra certificate extensions appended after this profile's own, in order; the caller retains ownership of each entry. <see langword="null"/> or empty for none.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled, signed certificate. The caller owns and disposes it.</returns>
    public static async ValueTask<PkiCertificateMemory> MintRootCertificateAuthorityAsync(
        IReadOnlyList<IReadOnlyList<DirectoryNameAttribute>> subjectName,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        PublicKeyMemory subjectPublicKey,
        PrivateKeyMemory issuerPrivateKey,
        int pathLengthConstraint,
        BaseMemoryPool pool,
        IReadOnlyList<CertificateExtensionContent>? additionalExtensions = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subjectPublicKey);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);
        ArgumentNullException.ThrowIfNull(pool);

        using PooledMemory name = WriteDirectoryName(subjectName, pool);
        List<CertificateExtensionContent> extensions = [];
        try
        {
            extensions.Add(WriteBasicConstraintsExtension(isCertificateAuthority: true, pathLengthConstraint, pool));
            extensions.Add(WriteKeyUsageExtension([KeyUsageBitName.KeyCertSign, KeyUsageBitName.CrlSign], pool));
            extensions.Add(await WriteSubjectKeyIdentifierExtensionAsync(subjectPublicKey, pool, cancellationToken).ConfigureAwait(false));

            var request = new CertificateMintRequest
            {
                IssuerName = name.AsReadOnlyMemory(),
                SubjectName = name.AsReadOnlyMemory(),
                NotBefore = notBefore,
                NotAfter = notAfter,
                SubjectPublicKey = subjectPublicKey,
                Extensions = CombineExtensions(extensions, additionalExtensions)
            };

            return await MintCertificateAsync(request, issuerPrivateKey, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            DisposeAll(extensions);
        }
    }


    /// <summary>
    /// Mints an intermediate Certification Authority certificate signed by <paramref name="issuerCertificate"/>'s
    /// key: <c>BasicConstraints{cA=TRUE, pathLenConstraint}</c> critical, <c>KeyUsage{keyCertSign, cRLSign}</c>
    /// critical, a Subject Key Identifier, and an Authority Key Identifier chained to the issuer's own key.
    /// </summary>
    /// <param name="issuerCertificate">The issuing CA's own certificate, read for its subject name and public key (for the Authority Key Identifier). The caller retains ownership.</param>
    /// <param name="subjectName">The intermediate's own name.</param>
    /// <param name="notBefore">The validity start.</param>
    /// <param name="notAfter">The validity end.</param>
    /// <param name="subjectPublicKey">The intermediate's public key. The caller retains ownership.</param>
    /// <param name="issuerPrivateKey">The issuing CA's signing key.</param>
    /// <param name="pathLengthConstraint">The Basic Constraints path length budget.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="additionalExtensions">Extra certificate extensions appended after this profile's own, in order; the caller retains ownership of each entry. <see langword="null"/> or empty for none.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled, signed certificate. The caller owns and disposes it.</returns>
    public static async ValueTask<PkiCertificateMemory> MintIntermediateCertificateAuthorityAsync(
        PkiCertificateMemory issuerCertificate,
        IReadOnlyList<IReadOnlyList<DirectoryNameAttribute>> subjectName,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        PublicKeyMemory subjectPublicKey,
        PrivateKeyMemory issuerPrivateKey,
        int pathLengthConstraint,
        BaseMemoryPool pool,
        IReadOnlyList<CertificateExtensionContent>? additionalExtensions = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(subjectPublicKey);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);
        ArgumentNullException.ThrowIfNull(pool);

        ManagedCertificate issuer = ManagedCertificate.Parse(issuerCertificate.AsReadOnlyMemory());
        using PooledMemory subject = WriteDirectoryName(subjectName, pool);
        List<CertificateExtensionContent> extensions = [];
        try
        {
            extensions.Add(WriteBasicConstraintsExtension(isCertificateAuthority: true, pathLengthConstraint, pool));
            extensions.Add(WriteKeyUsageExtension([KeyUsageBitName.KeyCertSign, KeyUsageBitName.CrlSign], pool));
            extensions.Add(await WriteSubjectKeyIdentifierExtensionAsync(subjectPublicKey, pool, cancellationToken).ConfigureAwait(false));
            extensions.Add(await WriteAuthorityKeyIdentifierExtensionAsync(issuer, pool, cancellationToken).ConfigureAwait(false));

            var request = new CertificateMintRequest
            {
                IssuerName = issuer.SubjectDer,
                SubjectName = subject.AsReadOnlyMemory(),
                NotBefore = notBefore,
                NotAfter = notAfter,
                SubjectPublicKey = subjectPublicKey,
                Extensions = CombineExtensions(extensions, additionalExtensions)
            };

            return await MintCertificateAsync(request, issuerPrivateKey, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            DisposeAll(extensions);
        }
    }


    /// <summary>
    /// Mints an EU-qualified certificate leaf (electronic signature, electronic seal, or website
    /// authentication) signed by <paramref name="issuerCertificate"/>'s key: the <c>qcStatements</c> and
    /// <c>CertificatePolicies</c> extensions <see cref="WriteQcStatementsExtension"/>/
    /// <see cref="WriteCertificatePoliciesExtension"/> write, <c>BasicConstraints{cA=FALSE}</c>,
    /// <c>KeyUsage{nonRepudiation}</c> critical, a Subject Key Identifier, and an Authority Key Identifier
    /// chained to the issuer's own key.
    /// </summary>
    /// <param name="issuerCertificate">The issuing CA's own certificate. The caller retains ownership.</param>
    /// <param name="subjectName">The subject's name.</param>
    /// <param name="notBefore">The validity start.</param>
    /// <param name="notAfter">The validity end.</param>
    /// <param name="subjectPublicKey">The subject's public key. The caller retains ownership.</param>
    /// <param name="issuerPrivateKey">The issuing CA's signing key.</param>
    /// <param name="certificateType">The declared <c>QcType</c> value.</param>
    /// <param name="requiresQualifiedSignatureCreationDevice">Whether the <c>QcSSCD</c> statement is written; see <see cref="WriteQcStatementsExtension"/>.</param>
    /// <param name="certificatePolicyOids">The certificate policy identifiers; see <see cref="WriteCertificatePoliciesExtension"/>.</param>
    /// <param name="additionalStatements">The clause 4.3 generic statements to include, or <see langword="null"/> for none.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="additionalExtensions">Extra certificate extensions appended after this profile's own, in order; the caller retains ownership of each entry. <see langword="null"/> or empty for none.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled, signed certificate. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">
    /// See <see cref="WriteQcStatementsExtension"/> and <see cref="WriteCertificatePoliciesExtension"/> for
    /// their own enforced issuance-profile refusals. This method additionally cross-checks
    /// <paramref name="certificatePolicyOids"/> against <paramref name="requiresQualifiedSignatureCreationDevice"/>:
    /// a clause 5.3 [QCP-n-qscd]/[QCP-l-qscd] policy identifier without the flag set violates GEN-6.6.1-03; the
    /// flag set alongside a clause 5.3 policy identifier that is not one of those two violates GEN-6.6.1-04. A
    /// policy set containing only a TSP-allocated identifier is unconstrained (GEN-6.6.1-07).
    /// </exception>
    public static async ValueTask<PkiCertificateMemory> MintQualifiedCertificateAsync(
        PkiCertificateMemory issuerCertificate,
        IReadOnlyList<IReadOnlyList<DirectoryNameAttribute>> subjectName,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        PublicKeyMemory subjectPublicKey,
        PrivateKeyMemory issuerPrivateKey,
        EuQualifiedCertificateType certificateType,
        bool requiresQualifiedSignatureCreationDevice,
        IReadOnlyList<string> certificatePolicyOids,
        QualifiedCertificateStatements? additionalStatements,
        BaseMemoryPool pool,
        IReadOnlyList<CertificateExtensionContent>? additionalExtensions = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(subjectPublicKey);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);
        ArgumentNullException.ThrowIfNull(certificatePolicyOids);
        ArgumentNullException.ThrowIfNull(pool);

        ValidateQscdPolicyConsistency(certificatePolicyOids, requiresQualifiedSignatureCreationDevice);

        ManagedCertificate issuer = ManagedCertificate.Parse(issuerCertificate.AsReadOnlyMemory());
        using PooledMemory subject = WriteDirectoryName(subjectName, pool);
        List<CertificateExtensionContent> extensions = [];
        try
        {
            extensions.Add(WriteQcStatementsExtension(certificateType, requiresQualifiedSignatureCreationDevice, additionalStatements, pool));
            extensions.Add(WriteCertificatePoliciesExtension(certificatePolicyOids, pool));
            extensions.Add(WriteBasicConstraintsExtension(isCertificateAuthority: false, pathLengthConstraint: null, pool));
            extensions.Add(WriteKeyUsageExtension([KeyUsageBitName.NonRepudiation], pool));
            extensions.Add(await WriteSubjectKeyIdentifierExtensionAsync(subjectPublicKey, pool, cancellationToken).ConfigureAwait(false));
            extensions.Add(await WriteAuthorityKeyIdentifierExtensionAsync(issuer, pool, cancellationToken).ConfigureAwait(false));

            var request = new CertificateMintRequest
            {
                IssuerName = issuer.SubjectDer,
                SubjectName = subject.AsReadOnlyMemory(),
                NotBefore = notBefore,
                NotAfter = notAfter,
                SubjectPublicKey = subjectPublicKey,
                Extensions = CombineExtensions(extensions, additionalExtensions)
            };

            return await MintCertificateAsync(request, issuerPrivateKey, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            DisposeAll(extensions);
        }
    }


    /// <summary>
    /// Mints a Time-Stamping Authority certificate signed by <paramref name="issuerCertificate"/>'s key:
    /// <c>BasicConstraints{cA=FALSE}</c>, <c>KeyUsage{digitalSignature, nonRepudiation}</c> critical, and a
    /// critical <c>ExtendedKeyUsage</c> carrying <em>only</em> <c>id-kp-timeStamping</c> — the single-critical-EKU
    /// shape RFC 3161 §2.3 requires of the certificate a time-stamp token's signature is verified with — plus
    /// a Subject Key Identifier and an Authority Key Identifier chained to the issuer's own key.
    /// </summary>
    /// <param name="issuerCertificate">The issuing CA's own certificate. The caller retains ownership.</param>
    /// <param name="subjectName">The authority's own name.</param>
    /// <param name="notBefore">The validity start.</param>
    /// <param name="notAfter">The validity end.</param>
    /// <param name="subjectPublicKey">The authority's public key. The caller retains ownership.</param>
    /// <param name="issuerPrivateKey">The issuing CA's signing key.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="additionalExtensions">Extra certificate extensions appended after this profile's own, in order; the caller retains ownership of each entry. <see langword="null"/> or empty for none.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The pooled, signed certificate. The caller owns and disposes it.</returns>
    public static async ValueTask<PkiCertificateMemory> MintTimeStampingAuthorityCertificateAsync(
        PkiCertificateMemory issuerCertificate,
        IReadOnlyList<IReadOnlyList<DirectoryNameAttribute>> subjectName,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        PublicKeyMemory subjectPublicKey,
        PrivateKeyMemory issuerPrivateKey,
        BaseMemoryPool pool,
        IReadOnlyList<CertificateExtensionContent>? additionalExtensions = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuerCertificate);
        ArgumentNullException.ThrowIfNull(subjectPublicKey);
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);
        ArgumentNullException.ThrowIfNull(pool);

        ManagedCertificate issuer = ManagedCertificate.Parse(issuerCertificate.AsReadOnlyMemory());
        using PooledMemory subject = WriteDirectoryName(subjectName, pool);
        List<CertificateExtensionContent> extensions = [];
        try
        {
            extensions.Add(WriteBasicConstraintsExtension(isCertificateAuthority: false, pathLengthConstraint: null, pool));
            extensions.Add(WriteKeyUsageExtension([KeyUsageBitName.DigitalSignature, KeyUsageBitName.NonRepudiation], pool));
            extensions.Add(WriteExtendedKeyUsageExtension([WellKnownOids.TimeStampingKeyPurpose], isCritical: true, pool));
            extensions.Add(await WriteSubjectKeyIdentifierExtensionAsync(subjectPublicKey, pool, cancellationToken).ConfigureAwait(false));
            extensions.Add(await WriteAuthorityKeyIdentifierExtensionAsync(issuer, pool, cancellationToken).ConfigureAwait(false));

            var request = new CertificateMintRequest
            {
                IssuerName = issuer.SubjectDer,
                SubjectName = subject.AsReadOnlyMemory(),
                NotBefore = notBefore,
                NotAfter = notAfter,
                SubjectPublicKey = subjectPublicKey,
                Extensions = CombineExtensions(extensions, additionalExtensions)
            };

            return await MintCertificateAsync(request, issuerPrivateKey, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            DisposeAll(extensions);
        }
    }


    /// <summary>Writes the <c>tbsCertificate</c> SEQUENCE — version, serial number, signature algorithm, names, validity, <c>subjectPublicKeyInfo</c>, and extensions — into pooled memory.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned PooledMemory, which the caller disposes.")]
    private static PooledMemory WriteTbsCertificate(CertificateMintRequest request, MintingSigningProfile profile, ReadOnlySpan<byte> serialNumberBytes, BaseMemoryPool pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence(VersionContextTag))
            {
                writer.WriteInteger(CertificateVersion3);
            }

            writer.WriteInteger(new BigInteger(serialNumberBytes, isUnsigned: true, isBigEndian: true));
            WriteSignatureAlgorithmIdentifier(writer, profile);
            writer.WriteEncodedValue(request.IssuerName.Span);

            using(writer.PushSequence())
            {
                WriteTime(writer, request.NotBefore);
                WriteTime(writer, request.NotAfter);
            }

            writer.WriteEncodedValue(request.SubjectName.Span);
            WriteSubjectPublicKeyInfo(writer, request.SubjectPublicKey, pool);
            WriteExtensionsField(writer, request.Extensions);
        }

        return Materialize(writer, pool);
    }


    /// <summary>Assembles the outer <c>Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }</c>, splicing the already-encoded <paramref name="tbsCertificate"/> verbatim.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned PkiCertificateMemory, which the caller disposes.")]
    private static PkiCertificateMemory AssembleCertificate(PooledMemory tbsCertificate, MintingSigningProfile profile, ReadOnlySpan<byte> signatureValue, BaseMemoryPool pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteEncodedValue(tbsCertificate.AsReadOnlySpan());
            WriteSignatureAlgorithmIdentifier(writer, profile);
            writer.WriteBitString(signatureValue);
        }

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out _);

            return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Writes <c>subjectPublicKeyInfo</c> from <paramref name="subjectPublicKey"/>'s bytes — the SEC1 point
    /// for an elliptic-curve key (normalized to uncompressed form; see
    /// <see cref="WriteEllipticCurvePublicKeyBitString"/>), the DER <c>RSAPublicKey</c> SEQUENCE for an RSA
    /// key verbatim, or the raw FIPS 204 key for an ML-DSA key verbatim, exactly as <c>ManagedCertificate</c>
    /// reads it back off a parsed certificate — with the <c>AlgorithmIdentifier</c> resolved from the key's
    /// <see cref="Tag"/>.
    /// </summary>
    private static void WriteSubjectPublicKeyInfo(AsnWriter writer, PublicKeyMemory subjectPublicKey, BaseMemoryPool pool)
    {
        CryptoAlgorithm algorithm = subjectPublicKey.Tag.Get<CryptoAlgorithm>();
        using(writer.PushSequence())
        {
            if(TryGetEllipticCurveOid(algorithm) is string curveOid)
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                    writer.WriteObjectIdentifier(curveOid);
                }

                WriteEllipticCurvePublicKeyBitString(writer, subjectPublicKey, algorithm, pool);
            }
            else if(IsRsaAlgorithm(algorithm))
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(WellKnownOids.RsaEncryption);
                    writer.WriteNull();
                }

                writer.WriteBitString(subjectPublicKey.AsReadOnlySpan());
            }
            else if(TryGetMlDsaOid(algorithm) is string mlDsaOid)
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(mlDsaOid);
                }

                writer.WriteBitString(subjectPublicKey.AsReadOnlySpan());
            }
            else
            {
                throw new NotSupportedException($"Certificate minting has no SubjectPublicKeyInfo encoding for the public-key algorithm '{algorithm}'.");
            }
        }
    }


    /// <summary>
    /// Writes an elliptic-curve <c>subjectPublicKey</c> BIT STRING: verbatim when
    /// <paramref name="subjectPublicKey"/>'s <see cref="EncodingScheme"/> is
    /// <see cref="EncodingScheme.EcUncompressed"/>; normalized to the uncompressed SEC1 point
    /// (<c>0x04 || X || Y</c>) through <see cref="EllipticCurveUtilities.NormalizeToUncompressed"/>, copied
    /// into a pooled buffer, when it is <see cref="EncodingScheme.EcCompressed"/> — the encoding this
    /// library's own EC key creators produce.
    /// </summary>
    private static void WriteEllipticCurvePublicKeyBitString(AsnWriter writer, PublicKeyMemory subjectPublicKey, CryptoAlgorithm algorithm, BaseMemoryPool pool)
    {
        if(subjectPublicKey.Tag.Get<EncodingScheme>() != EncodingScheme.EcCompressed)
        {
            writer.WriteBitString(subjectPublicKey.AsReadOnlySpan());

            return;
        }

        byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(subjectPublicKey.AsReadOnlySpan(), EllipticCurveUtilities.CurveTypeFor(algorithm));
        using IMemoryOwner<byte> pooledPoint = pool.Rent(uncompressedPoint.Length);
        uncompressedPoint.CopyTo(pooledPoint.Memory.Span);
        writer.WriteBitString(pooledPoint.Memory.Span[..uncompressedPoint.Length]);
    }


    /// <summary>Maps an elliptic-curve <see cref="CryptoAlgorithm"/> to its RFC 5480 named-curve object identifier, or <see langword="null"/> when <paramref name="algorithm"/> is not one of the curves this surface knows.</summary>
    private static string? TryGetEllipticCurveOid(CryptoAlgorithm algorithm) => algorithm switch
    {
        var a when a == CryptoAlgorithm.P256 => WellKnownOids.EcP256,
        var a when a == CryptoAlgorithm.P384 => WellKnownOids.EcP384,
        var a when a == CryptoAlgorithm.P521 => WellKnownOids.EcP521,
        var a when a == CryptoAlgorithm.Secp256k1 => WellKnownOids.EcSecp256k1,
        var a when a == CryptoAlgorithm.BrainpoolP224r1 => WellKnownOids.EcBrainpoolP224r1,
        var a when a == CryptoAlgorithm.BrainpoolP256r1 => WellKnownOids.EcBrainpoolP256r1,
        var a when a == CryptoAlgorithm.BrainpoolP320r1 => WellKnownOids.EcBrainpoolP320r1,
        var a when a == CryptoAlgorithm.BrainpoolP384r1 => WellKnownOids.EcBrainpoolP384r1,
        var a when a == CryptoAlgorithm.BrainpoolP512r1 => WellKnownOids.EcBrainpoolP512r1,
        _ => null
    };


    /// <summary>States whether <paramref name="algorithm"/> is one of the RSA key sizes this surface knows.</summary>
    private static bool IsRsaAlgorithm(CryptoAlgorithm algorithm) =>
        algorithm == CryptoAlgorithm.Rsa2048 || algorithm == CryptoAlgorithm.Rsa4096;


    /// <summary>Maps an ML-DSA <see cref="CryptoAlgorithm"/> to its NIST Computer Security Objects Register identifier, or <see langword="null"/> when <paramref name="algorithm"/> is not one of the three ML-DSA parameter sets.</summary>
    private static string? TryGetMlDsaOid(CryptoAlgorithm algorithm) => algorithm switch
    {
        var a when a == CryptoAlgorithm.MlDsa44 => WellKnownOids.MlDsa44,
        var a when a == CryptoAlgorithm.MlDsa65 => WellKnownOids.MlDsa65,
        var a when a == CryptoAlgorithm.MlDsa87 => WellKnownOids.MlDsa87,
        _ => null
    };


    /// <summary>
    /// Resolves the signing identity for <paramref name="signingAlgorithm"/>: ECDSA (P-256/P-384/P-521, paired
    /// with SHA-256/384/512 per RFC 5758 §3.2), RSASSA-PKCS1-v1.5 with SHA-256 (RSA-2048/4096, RFC 8017), or
    /// ML-DSA-44/65/87 (NIST FIPS 204; the one identifier names both the key and signature algorithm, absent
    /// parameters, per <see cref="WellKnownOids.MlDsa44"/>'s documented convention).
    /// </summary>
    /// <exception cref="NotSupportedException">When <paramref name="signingAlgorithm"/> is none of the above.</exception>
    private static MintingSigningProfile ResolveSigningProfile(CryptoAlgorithm signingAlgorithm) => signingAlgorithm switch
    {
        var a when a == CryptoAlgorithm.P256 => new MintingSigningProfile(WellKnownOids.EcdsaWithSha256, IsEllipticCurve: true),
        var a when a == CryptoAlgorithm.P384 => new MintingSigningProfile(WellKnownOids.EcdsaWithSha384, IsEllipticCurve: true),
        var a when a == CryptoAlgorithm.P521 => new MintingSigningProfile(WellKnownOids.EcdsaWithSha512, IsEllipticCurve: true),
        var a when a == CryptoAlgorithm.Rsa2048 => new MintingSigningProfile(WellKnownOids.Sha256WithRsaEncryption, IsEllipticCurve: false),
        var a when a == CryptoAlgorithm.Rsa4096 => new MintingSigningProfile(WellKnownOids.Sha256WithRsaEncryption, IsEllipticCurve: false),
        var a when a == CryptoAlgorithm.MlDsa44 => new MintingSigningProfile(WellKnownOids.MlDsa44, IsEllipticCurve: false),
        var a when a == CryptoAlgorithm.MlDsa65 => new MintingSigningProfile(WellKnownOids.MlDsa65, IsEllipticCurve: false),
        var a when a == CryptoAlgorithm.MlDsa87 => new MintingSigningProfile(WellKnownOids.MlDsa87, IsEllipticCurve: false),
        _ => throw new NotSupportedException($"Certificate minting does not sign with the algorithm '{signingAlgorithm}'.")
    };


    /// <summary>Writes an <c>AlgorithmIdentifier</c> for <paramref name="profile"/>: absent parameters for ECDSA (RFC 3279 §2.2.3) and ML-DSA (<see cref="WellKnownOids.MlDsa44"/>'s convention), explicit <c>NULL</c> parameters for the RSA <c>sha256WithRSAEncryption</c> form (RFC 8017 convention) — the same inline pattern <c>CAdESSignatureCreation</c> writes its own <c>SignerInfo.signatureAlgorithm</c> with.</summary>
    private static void WriteSignatureAlgorithmIdentifier(AsnWriter writer, MintingSigningProfile profile)
    {
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(profile.SignatureAlgorithmOid);
            if(string.Equals(profile.SignatureAlgorithmOid, WellKnownOids.Sha256WithRsaEncryption, StringComparison.Ordinal))
            {
                writer.WriteNull();
            }
        }
    }


    /// <summary>Writes a <c>Validity</c> time, pivoting on the UTC instant's year: <c>UTCTime</c> through 2049, <c>GeneralizedTime</c> from 2050 on (RFC 5280 §4.1.2.5).</summary>
    private static void WriteTime(AsnWriter writer, DateTimeOffset instant)
    {
        DateTimeOffset utc = instant.ToUniversalTime();
        if(utc.Year < GeneralizedTimePivotYear)
        {
            writer.WriteUtcTime(utc, twoDigitYearMax: 2049);
        }
        else
        {
            writer.WriteGeneralizedTime(utc, omitFractionalSeconds: true);
        }
    }


    /// <summary>Writes the <c>extensions [3] EXPLICIT Extensions</c> field when <paramref name="extensions"/> is non-empty (RFC 5280 §4.1.2.9); omitted entirely otherwise, since the field itself is OPTIONAL.</summary>
    private static void WriteExtensionsField(AsnWriter writer, IReadOnlyList<CertificateExtensionContent> extensions)
    {
        if(extensions.Count == 0)
        {
            return;
        }

        using(writer.PushSequence(ExtensionsContextTag))
        {
            using(writer.PushSequence())
            {
                foreach(CertificateExtensionContent extension in extensions)
                {
                    using(writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(extension.ExtensionOid);
                        if(extension.IsCritical)
                        {
                            writer.WriteBoolean(true);
                        }

                        writer.WriteOctetString(extension.Value.AsReadOnlySpan());
                    }
                }
            }
        }
    }


    /// <summary>Writes one <c>QCStatement ::= SEQUENCE { statementId OID, statementInfo ANY OPTIONAL }</c>.</summary>
    private static void WriteQcStatement(AsnWriter writer, string statementId, Action<AsnWriter> writeInfo)
    {
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(statementId);
            writeInfo(writer);
        }
    }


    /// <summary>Writes a clause 4.3.2 <c>MonetaryValue ::= SEQUENCE { currency Iso4217CurrencyCode, amount INTEGER, exponent INTEGER }</c>. QCS-4.3.2-02 recommends the alphabetic <c>Iso4217CurrencyCode</c> alternative; this writer takes whichever of <see cref="QcMonetaryValue.AlphabeticCurrencyCode"/>/<see cref="QcMonetaryValue.NumericCurrencyCode"/> the caller populated, exactly one of which is non-null by the time this is reached.</summary>
    private static void WriteMonetaryValue(AsnWriter writer, QcMonetaryValue limitValue)
    {
        using(writer.PushSequence())
        {
            if(limitValue.AlphabeticCurrencyCode is { } alphabetic)
            {
                writer.WriteCharacterString(UniversalTagNumber.PrintableString, alphabetic);
            }
            else
            {
                writer.WriteInteger(limitValue.NumericCurrencyCode!.Value);
            }

            writer.WriteInteger(limitValue.Amount);
            writer.WriteInteger(limitValue.Exponent);
        }
    }


    /// <summary>
    /// Validates a <c>QcLimitValue</c> statement's <c>MonetaryValue</c> against clause 4.3.2's Annex B syntax:
    /// <c>Iso4217CurrencyCode ::= CHOICE { alphabetic PrintableString (SIZE (3)), numeric INTEGER (1..999) }</c>
    /// (QCS-4.1-04 gives Annex B's ASN.1 precedence) — exactly one alternative populated, the alphabetic form
    /// exactly three characters, the numeric form in the range 1 to 999.
    /// </summary>
    private static void ValidateMonetaryValue(QcMonetaryValue limitValue, string parameterName)
    {
        if((limitValue.AlphabeticCurrencyCode is not null) == (limitValue.NumericCurrencyCode is not null))
        {
            throw new ArgumentException(
                "Clause 4.3.2: Iso4217CurrencyCode ::= CHOICE { alphabetic PrintableString (SIZE (3)), numeric INTEGER (1..999) } (QCS-4.1-04 gives Annex B's ASN.1 precedence): a QcLimitValue statement must populate exactly one alternative.",
                parameterName);
        }

        if(limitValue.AlphabeticCurrencyCode is { } alphabetic && alphabetic.Length != 3)
        {
            throw new ArgumentException(
                $"Clause 4.3.2: Iso4217CurrencyCode's alphabetic alternative is PrintableString (SIZE (3)); got '{alphabetic}' ({alphabetic.Length} characters).",
                parameterName);
        }

        if(limitValue.NumericCurrencyCode is { } numeric && (numeric < 1 || numeric > 999))
        {
            throw new ArgumentException(
                $"Clause 4.3.2: Iso4217CurrencyCode's numeric alternative is INTEGER (1..999); got {numeric}.",
                parameterName);
        }
    }


    /// <summary>Writes a clause 4.3.4 <c>PdsLocations ::= SEQUENCE SIZE (1..MAX) OF PdsLocation</c>.</summary>
    private static void WritePdsLocations(AsnWriter writer, IReadOnlyList<PdsLocation> locations)
    {
        using(writer.PushSequence())
        {
            foreach(PdsLocation location in locations)
            {
                using(writer.PushSequence())
                {
                    writer.WriteCharacterString(UniversalTagNumber.IA5String, location.Url);
                    writer.WriteCharacterString(UniversalTagNumber.PrintableString, location.Language);
                }
            }
        }
    }


    /// <summary>Writes a <c>SEQUENCE OF CountryName</c>, the shape shared by clause 4.2.5's <c>QcQSCDlegislation</c>.</summary>
    private static void WriteCountryCodes(AsnWriter writer, IReadOnlyList<string> countryCodes)
    {
        using(writer.PushSequence())
        {
            foreach(string countryCode in countryCodes)
            {
                writer.WriteCharacterString(UniversalTagNumber.PrintableString, countryCode);
            }
        }
    }


    /// <summary>
    /// Validates clause 4.3.4's PDS conditions, all of which apply only once the statement is present
    /// (<paramref name="locations"/> non-empty): QCS-4.3.4-01's two-character language code, QCS-4.3.4-03's
    /// <c>https</c> scheme, Table 2 condition a)'s at-least-one-English requirement, and condition b)'s
    /// at-most-one-per-language limit.
    /// </summary>
    private static void ValidatePdsLocations(IReadOnlyList<PdsLocation> locations, string parameterName)
    {
        if(locations.Count == 0)
        {
            return;
        }

        bool hasEnglish = false;
        var seenLanguages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(PdsLocation location in locations)
        {
            if(location.Language.Length != 2)
            {
                throw new ArgumentException($"QCS-4.3.4-01: a PDS location's language must be the two-character ISO 639 Set 1 code; got '{location.Language}'.", parameterName);
            }

            if(!location.Url.StartsWith("https://", StringComparison.Ordinal))
            {
                throw new ArgumentException($"QCS-4.3.4-03: a PDS location URL must use the https scheme; got '{location.Url}'.", parameterName);
            }

            if(!seenLanguages.Add(location.Language))
            {
                throw new ArgumentException($"Table 2 (QcPDS, condition b): no more than one PDS location per language is allowed; '{location.Language}' repeats.", parameterName);
            }

            hasEnglish |= string.Equals(location.Language, "en", StringComparison.OrdinalIgnoreCase);
        }

        if(!hasEnglish)
        {
            throw new ArgumentException("Table 2 (QcPDS, condition a): at least one PDS location must be in English ('en').", parameterName);
        }
    }


    /// <summary>
    /// Validates QCS-4.2.5-01: every <paramref name="countryCodes"/> entry is clause 4.2.5's Annex B
    /// <c>CountryName ::= PrintableString (SIZE (2))</c> shape, and none identifies an EU or EEA country, a
    /// group of EU or EEA countries, or the literal value <c>"EU"</c>.
    /// </summary>
    private static void ValidateQscdLegislationCountryCodes(IReadOnlyList<string> countryCodes, string parameterName)
    {
        foreach(string countryCode in countryCodes)
        {
            if(countryCode.Length != 2)
            {
                throw new ArgumentException($"Clause 4.2.5: CountryName ::= PrintableString (SIZE (2)); got '{countryCode}'.", parameterName);
            }

            if(EuAndEeaCountryCodes.Contains(countryCode) || string.Equals(countryCode, "EU", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException($"QCS-4.2.5-01: a QcQSCDlegislation country code must not identify an EU or EEA country, or the value 'EU'; got '{countryCode}'.", parameterName);
            }
        }
    }


    /// <summary>Writes a <c>BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }</c> extension, critical (RFC 5280 §4.2.1.9). The DEFAULT <c>cA = FALSE</c> is omitted per DER's minimal-encoding rule (X.690 §11.5) rather than written explicitly.</summary>
    private static CertificateExtensionContent WriteBasicConstraintsExtension(bool isCertificateAuthority, int? pathLengthConstraint, BaseMemoryPool pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            if(isCertificateAuthority)
            {
                writer.WriteBoolean(true);
                if(pathLengthConstraint is int pathLength)
                {
                    writer.WriteInteger(pathLength);
                }
            }
        }

        return EncodeExtension(WellKnownOids.BasicConstraintsExtension, isCritical: true, writer, pool);
    }


    /// <summary>Writes a <c>KeyUsage</c> named <c>BIT STRING</c> extension, critical (RFC 5280 §4.2.1.3), from the bits <paramref name="bits"/> asserts, in ascending bit order.</summary>
    private static CertificateExtensionContent WriteKeyUsageExtension(IReadOnlyList<KeyUsageBitName> bits, BaseMemoryPool pool)
    {
        int highestBit = -1;
        foreach(KeyUsageBitName bit in bits)
        {
            highestBit = Math.Max(highestBit, (int)bit);
        }

        int byteCount = highestBit < 0 ? 0 : (highestBit / 8) + 1;
        Span<byte> content = stackalloc byte[byteCount];
        foreach(KeyUsageBitName bit in bits)
        {
            int bitIndex = (int)bit;
            content[bitIndex / 8] |= (byte)(0x80 >> (bitIndex % 8));
        }

        int unusedBitCount = byteCount == 0 ? 0 : 7 - (highestBit % 8);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteBitString(content, unusedBitCount);

        return EncodeExtension(WellKnownOids.KeyUsageExtension, isCritical: true, writer, pool);
    }


    /// <summary>Writes an <c>ExtendedKeyUsage ::= SEQUENCE OF KeyPurposeId</c> extension (RFC 5280 §4.2.1.12).</summary>
    private static CertificateExtensionContent WriteExtendedKeyUsageExtension(IReadOnlyList<string> keyPurposeOids, bool isCritical, BaseMemoryPool pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            foreach(string keyPurposeOid in keyPurposeOids)
            {
                writer.WriteObjectIdentifier(keyPurposeOid);
            }
        }

        return EncodeExtension(WellKnownOids.ExtendedKeyUsageExtension, isCritical, writer, pool);
    }


    /// <summary>Writes a <c>SubjectKeyIdentifier ::= KeyIdentifier ::= OCTET STRING</c> extension (RFC 5280 §4.2.1.2), non-critical, as the SHA-256 digest of the subject's own <c>subjectPublicKey</c> BIT STRING content.</summary>
    private static async ValueTask<CertificateExtensionContent> WriteSubjectKeyIdentifierExtensionAsync(PublicKeyMemory subjectPublicKey, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using DigestValue hash = await CryptographicKeyEvents.ComputeDigestAsync(
            subjectPublicKey.AsReadOnlyMemory(), PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(hash.AsReadOnlySpan());

        return EncodeExtension(WellKnownOids.SubjectKeyIdentifierExtension, isCritical: false, writer, pool);
    }


    /// <summary>Writes an <c>AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT KeyIdentifier OPTIONAL, ... }</c> extension (RFC 5280 §4.2.1.1) carrying only <c>keyIdentifier</c>, non-critical, set to the SHA-256 digest of <paramref name="issuer"/>'s own <c>subjectPublicKey</c> BIT STRING content — chained to <see cref="WriteSubjectKeyIdentifierExtensionAsync"/>'s value for that same certificate.</summary>
    private static async ValueTask<CertificateExtensionContent> WriteAuthorityKeyIdentifierExtensionAsync(ManagedCertificate issuer, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using DigestValue hash = await CryptographicKeyEvents.ComputeDigestAsync(
            issuer.SubjectPublicKeyBitStringContent, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteOctetString(hash.AsReadOnlySpan(), AuthorityKeyIdentifierKeyIdTag);
        }

        return EncodeExtension(WellKnownOids.AuthorityKeyIdentifierExtension, isCritical: false, writer, pool);
    }


    /// <summary>Encodes <paramref name="valueWriter"/>'s completed value into pooled memory and wraps it as an extension content carrier.</summary>
    private static CertificateExtensionContent EncodeExtension(string extensionOid, bool isCritical, AsnWriter valueWriter, BaseMemoryPool pool) =>
        new(extensionOid, isCritical, Materialize(valueWriter, pool));


    /// <summary>Disposes every entry of <paramref name="extensions"/> — the partial-failure cleanup for a chain-profile builder that accumulates extensions before minting: whatever was successfully created before a later writer or the mint call itself throws is still returned to the pool.</summary>
    private static void DisposeAll(List<CertificateExtensionContent> extensions)
    {
        for(int i = 0; i < extensions.Count; ++i)
        {
            extensions[i].Dispose();
        }
    }


    /// <summary>
    /// Appends caller-supplied <paramref name="additionalExtensions"/>, if any, after
    /// <paramref name="profileExtensions"/> — the caller retains ownership of its own entries, so they never
    /// join the profile builder's own <see cref="DisposeAll"/> list.
    /// </summary>
    private static IReadOnlyList<CertificateExtensionContent> CombineExtensions(
        IReadOnlyList<CertificateExtensionContent> profileExtensions,
        IReadOnlyList<CertificateExtensionContent>? additionalExtensions) =>
        additionalExtensions is null or { Count: 0 }
            ? profileExtensions
            : [.. profileExtensions, .. additionalExtensions];


    /// <summary>
    /// Cross-checks a certificate's clause 5.3 QSCD-flavoured policy identifiers against
    /// <paramref name="requiresQualifiedSignatureCreationDevice"/>: EN 319 411-2 GEN-6.6.1-03 requires the
    /// <c>QcSSCD</c> statement under a [QCP-n-qscd]/[QCP-l-qscd] policy; GEN-6.6.1-04 forbids it under any
    /// other clause 5.3 policy. A policy identifier this library does not recognise (a TSP-allocated OID,
    /// GEN-6.6.1-07) is unconstrained.
    /// </summary>
    private static void ValidateQscdPolicyConsistency(IReadOnlyList<string> certificatePolicyOids, bool requiresQualifiedSignatureCreationDevice)
    {
        foreach(string policyOid in certificatePolicyOids)
        {
            bool? isQscdFlavouredPolicy = policyOid switch
            {
                WellKnownOids.QcpNaturalQscd or WellKnownOids.QcpLegalQscd => true,
                WellKnownOids.QcpNatural or WellKnownOids.QcpLegal or WellKnownOids.QcpWeb or WellKnownOids.QncpWeb or WellKnownOids.QncpWebGen => false,
                _ => null
            };

            if(isQscdFlavouredPolicy == true && !requiresQualifiedSignatureCreationDevice)
            {
                throw new ArgumentException(
                    $"GEN-6.6.1-03: \"The certificate shall include the qcStatement for QSCD (esi4-qcStatement-4)\" under [QCP-n-qscd]/[QCP-l-qscd]; policy '{policyOid}' requires it but requiresQualifiedSignatureCreationDevice is false.",
                    nameof(requiresQualifiedSignatureCreationDevice));
            }

            if(isQscdFlavouredPolicy == false && requiresQualifiedSignatureCreationDevice)
            {
                throw new ArgumentException(
                    $"GEN-6.6.1-04: \"The qcStatement for QSCD (esi4-qcStatement-4) shall not be included in certificates that are not issued according to [QCP-n-qscd] or [QCP-l-qscd] requirements\"; policy '{policyOid}' is not one of those two.",
                    nameof(requiresQualifiedSignatureCreationDevice));
            }
        }
    }


    /// <summary>Encodes <paramref name="writer"/>'s completed value into a freshly rented, exactly-sized pooled buffer.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned PooledMemory, which the caller disposes.")]
    private static PooledMemory Materialize(AsnWriter writer, BaseMemoryPool pool)
    {
        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out int written);

            return new PooledMemory(owner, written, DerFragmentTag);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>The signature identity <see cref="ResolveSigningProfile"/> resolves: the <c>SignerInfo</c>/<c>Certificate.signatureAlgorithm</c> object identifier, and whether the registered signing seam's fixed-width P1363 output needs DER conversion before it is a valid <c>Ecdsa-Sig-Value</c>.</summary>
    /// <param name="SignatureAlgorithmOid">The signature algorithm object identifier.</param>
    /// <param name="IsEllipticCurve">Whether the algorithm is ECDSA, requiring P1363-to-DER conversion of the registered seam's raw signature output.</param>
    private readonly record struct MintingSigningProfile(string SignatureAlgorithmOid, bool IsEllipticCurve);
}
