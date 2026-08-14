using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The signature-qualifying header parameter that identifies the signing certificate and the remainder of its
/// certification path by digest: CB-AdES's <c>x5ts</c> (label 261, clause 5.2.2 Table 1) of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, and JAdES's <c>sigX5ts</c> of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.2.2.3 (JA-5.2.2.3-01). Both are an ordered, minimum-length-2
/// collection of certificate-reference records.
/// </summary>
/// <remarks>
/// <para>
/// CB-AdES CDDL (clause 5.2.2): <c>x5ts = [2*x5t: COSE_CertHash]</c> — the CDDL <c>2*</c> occurrence operator
/// requires at least <see cref="MinimumThumbprintCount"/> entries. JAdES JSON Schema (clause 5.2.2.3, Annex B.1):
/// an array of <c>x5t#o</c>-shaped entries, <c>"minItems": 2"</c> (JA-5.2.2.3-05). Both specifications require
/// the same minimum, enforced here by one validating constructor.
/// </para>
/// <para>
/// <see cref="Thumbprints"/>[0] is always the signing certificate ("The first reference within the <c>x5ts</c>
/// header parameter shall be the reference of the signing certificate", clause 5.2.2; JA-5.2.2.3-03 states the
/// same for <c>sigX5ts</c>); the remaining entries reference the rest of the certification path, in path order.
/// Ordering is semantically load-bearing and must survive every codec round-trip unreordered — see
/// <see cref="SigningCertificateThumbprint"/>. Both clauses also state the parameter shall not contain any other
/// information beyond these entries (clause 5.2.2; JA-5.2.2.3-04), which this shape satisfies by construction.
/// </para>
/// <para>
/// <c>x5ts</c>/<c>sigX5ts</c> is one of four disjunctive signing-certificate-identification options a signature
/// carries at least one of: alongside <c>x5t</c>/<c>x5chain</c> (RFC 9360 §2, profiled by clause 5.1.7/5.1.8) in
/// CB-AdES, and alongside <c>x5t#S256</c>/<c>x5c</c> (JA-5.1.7-04) in JAdES. Composing that disjunction, and
/// placing this parameter in the protected headers map, is the signature builder's responsibility — this type
/// models only the parameter's own content.
/// </para>
/// <para>
/// <strong>Ownership:</strong> owns every <see cref="AdESCertificateThumbprint.Digest"/> reachable through
/// <see cref="Thumbprints"/>. Disposing this instance disposes all of them, mirroring the owned-carrier half of
/// <c>CoseSign1Message</c>'s ownership split (<c>CoseSign1Message.ProtectedHeader</c> and
/// <c>CoseSign1Message.Signature</c> are owned; <c>CoseSign1Message.Payload</c> is borrowed).
/// </para>
/// </remarks>
[DebuggerDisplay("AdESCertificateThumbprints: {Thumbprints.Count} thumbprints")]
public sealed class AdESCertificateThumbprints: IDisposable, IEquatable<AdESCertificateThumbprints>
{
    private bool disposed;

    /// <summary>
    /// The minimum number of entries both families' occurrence constraints require: CB-AdES's CDDL <c>2*x5t</c>
    /// operator (clause 5.2.2) and JAdES's schema <c>"minItems": 2</c> (clause 5.2.2.3, JA-5.2.2.3-05).
    /// </summary>
    public const int MinimumThumbprintCount = 2;

    /// <summary>
    /// Gets the entries, in wire order. Index 0 is the signing certificate; the remainder is the rest of the
    /// certification path, in path order.
    /// </summary>
    public IReadOnlyList<AdESCertificateThumbprint> Thumbprints { get; }

    /// <summary>
    /// Gets the signing certificate's thumbprint — <see cref="Thumbprints"/>[0], per clause 5.2.2's (CB-AdES)
    /// and JA-5.2.2.3-03's (JAdES) ordering requirement.
    /// </summary>
    public AdESCertificateThumbprint SigningCertificateThumbprint => Thumbprints[0];


    /// <summary>
    /// Initializes a new <see cref="AdESCertificateThumbprints"/>. Ownership of every entry in
    /// <paramref name="thumbprints"/> transfers to this instance.
    /// </summary>
    /// <param name="thumbprints">
    /// The entries in wire order, index 0 being the signing certificate. Must contain at least
    /// <see cref="MinimumThumbprintCount"/> entries.
    /// </param>
    /// <exception cref="ArgumentNullException">When <paramref name="thumbprints"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="thumbprints"/> has fewer than <see cref="MinimumThumbprintCount"/> entries.
    /// </exception>
    public AdESCertificateThumbprints(IReadOnlyList<AdESCertificateThumbprint> thumbprints)
    {
        ArgumentNullException.ThrowIfNull(thumbprints);
        if(thumbprints.Count < MinimumThumbprintCount)
        {
            throw new ArgumentException(
                $"The x5ts/sigX5ts header parameter requires at least {MinimumThumbprintCount} entries (ETSI TS "
                + $"119 152-1 V1.1.1, clause 5.2.2, CDDL '2*x5t'; ETSI TS 119 182-1 V1.2.1, clause 5.2.2.3, "
                + $"JA-5.2.2.3-05); got {thumbprints.Count}.",
                nameof(thumbprints));
        }

        Thumbprints = thumbprints;
    }


    /// <summary>
    /// Disposes every <see cref="AdESCertificateThumbprint"/> this instance owns.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            for(int i = 0; i < Thumbprints.Count; ++i)
            {
                Thumbprints[i].Dispose();
            }

            disposed = true;
        }
    }


    /// <summary>
    /// Determines whether two <see cref="AdESCertificateThumbprints"/> instances carry the same entries in the
    /// same order.
    /// </summary>
    /// <param name="other">The instance to compare with.</param>
    /// <returns><see langword="true"/> when both carry equal entries in the same order.</returns>
    public bool Equals(AdESCertificateThumbprints? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(Thumbprints.Count != other.Thumbprints.Count)
        {
            return false;
        }

        for(int i = 0; i < Thumbprints.Count; ++i)
        {
            if(!Thumbprints[i].Equals(other.Thumbprints[i]))
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as AdESCertificateThumbprints);


    /// <summary>Returns a hash code combining every entry's hash code, in order.</summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        for(int i = 0; i < Thumbprints.Count; ++i)
        {
            hash.Add(Thumbprints[i]);
        }

        return hash.ToHashCode();
    }


    /// <summary>Determines whether two <see cref="AdESCertificateThumbprints"/> instances carry the same entries in the same order.</summary>
    public static bool operator ==(AdESCertificateThumbprints? left, AdESCertificateThumbprints? right) => left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="AdESCertificateThumbprints"/> instances differ.</summary>
    public static bool operator !=(AdESCertificateThumbprints? left, AdESCertificateThumbprints? right) => !(left == right);
}


/// <summary>
/// One entry within <see cref="AdESCertificateThumbprints"/>: CB-AdES's <c>COSE_CertHash</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>, profiled by
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.1.7, or JAdES's <c>x5t#o</c> per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.2.2.2 (JA-5.2.2.2-01).
/// </summary>
/// <remarks>
/// <para>
/// CB-AdES CDDL (RFC 9360 §2, reproduced at clause 5.1.7): <c>COSE_CertHash = [ hashAlg: (int / tstr), hashValue:
/// bstr ]</c>. JAdES JSON Schema (clause 5.2.2.2, Annex B.1):
/// </para>
/// <code>
/// "x5t#o": {
///   "type": "object",
///   "properties": {
///     "digAlg": {"type": "string"},
///     "digVal": {"type": "string", "contentEncoding": "base64"}
///   },
///   "required": ["digAlg", "digVal"],
///   "additionalProperties": false
/// }
/// </code>
/// <para>
/// <see cref="HashAlgorithm"/> models both wire syntaxes faithfully as <see cref="AdESDigestAlgorithmIdentifier"/>
/// rather than narrowing to one shape: CB-AdES's clause 5.1.7 identifier-registry prose ("shall be one of the
/// identifiers for digest algorithms registered in IANA COSE Algorithms registry, or any future specification
/// that defines new identifiers for digest algorithms") constrains which registry an identifier comes from, not
/// which CDDL arm it must use, so a producer emitting the CDDL's <c>tstr</c> arm is not itself non-conformant;
/// JAdES's <c>digAlg</c> value space is the IANA "Named Information Hash Algorithm Registry" (JA-5.2.2.2-06), a
/// registry this library does not itself enumerate, so a JAdES carrier always rides
/// <see cref="AdESDigestAlgorithmTextIdentifier"/> and an identifier this library cannot map onto a
/// <see cref="System.Security.Cryptography.HashAlgorithmName"/> still round-trips faithfully. <c>hashValue</c>/
/// <c>digVal</c> is the digest of the referenced certificate's DER encoding, carried in <see cref="Digest"/> —
/// never a naked <c>byte[]</c>.
/// </para>
/// <para>
/// <strong>Ownership:</strong> owns <see cref="Digest"/>. Disposing this instance disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("AdESCertificateThumbprint: HashAlgorithm={HashAlgorithm}")]
public sealed class AdESCertificateThumbprint: IDisposable, IEquatable<AdESCertificateThumbprint>
{
    private bool disposed;

    /// <summary>
    /// Gets the digest algorithm identifier — a CB-AdES <c>COSE_CertHash.hashAlg</c> (clause 5.1.7, one of the
    /// <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms</see>
    /// registry entries, e.g. <c>WellKnownCoseAlgorithms.Sha256</c>) or a JAdES <c>x5t#o.digAlg</c>
    /// (JA-5.2.2.2-05, always the <see cref="AdESDigestAlgorithmTextIdentifier"/> arm). See
    /// <see cref="AdESDigestAlgorithmIdentifier"/> for the union this member models.
    /// </summary>
    public AdESDigestAlgorithmIdentifier HashAlgorithm { get; }

    /// <summary>
    /// Gets the digest of the referenced certificate's DER encoding — <c>COSE_CertHash.hashValue</c> or
    /// <c>x5t#o.digVal</c> (JA-5.2.2.2-07).
    /// </summary>
    public DigestValue Digest { get; }


    /// <summary>
    /// Initializes a new <see cref="AdESCertificateThumbprint"/>. Ownership of <paramref name="digest"/>
    /// transfers to this instance.
    /// </summary>
    /// <param name="hashAlgorithm">The digest algorithm identifier.</param>
    /// <param name="digest">The digest of the referenced certificate's DER encoding.</param>
    /// <exception cref="ArgumentNullException">
    /// When <paramref name="hashAlgorithm"/> or <paramref name="digest"/> is <see langword="null"/>.
    /// </exception>
    public AdESCertificateThumbprint(AdESDigestAlgorithmIdentifier hashAlgorithm, DigestValue digest)
    {
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(digest);

        HashAlgorithm = hashAlgorithm;
        Digest = digest;
    }


    /// <summary>
    /// Disposes <see cref="Digest"/>.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Digest.Dispose();
            disposed = true;
        }
    }


    /// <summary>
    /// Determines whether two <see cref="AdESCertificateThumbprint"/> instances carry the same algorithm and
    /// digest bytes. Algorithm comparison is <see cref="AdESDigestAlgorithmIdentifier"/>'s own structural
    /// equality — an integer identifier never compares equal to a textual one.
    /// </summary>
    /// <param name="other">The instance to compare with.</param>
    /// <returns><see langword="true"/> when both carry the same algorithm and digest bytes.</returns>
    public bool Equals(AdESCertificateThumbprint? other)
    {
        return other is not null
            && HashAlgorithm == other.HashAlgorithm
            && Digest.AsReadOnlySpan().SequenceEqual(other.Digest.AsReadOnlySpan());
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as AdESCertificateThumbprint);


    /// <summary>Returns a hash code derived from <see cref="HashAlgorithm"/> and the digest bytes.</summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(HashAlgorithm);
        foreach(byte b in Digest.AsReadOnlySpan())
        {
            hash.Add(b);
        }

        return hash.ToHashCode();
    }


    /// <summary>Determines whether two <see cref="AdESCertificateThumbprint"/> instances carry the same algorithm and digest bytes.</summary>
    public static bool operator ==(AdESCertificateThumbprint? left, AdESCertificateThumbprint? right) => left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="AdESCertificateThumbprint"/> instances differ.</summary>
    public static bool operator !=(AdESCertificateThumbprint? left, AdESCertificateThumbprint? right) => !(left == right);
}
