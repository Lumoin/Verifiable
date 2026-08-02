using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>x5ts</c> (label 261, clause 5.2.1 Table 1) signed header parameter: an ordered,
/// minimum-length-2 collection of certificate-reference records identifying the signing certificate and the
/// remainder of its certification path, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.2.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.2.2): <c>x5ts = [2*x5t: COSE_CertHash]</c> — the CDDL <c>2*</c> occurrence operator requires
/// at least <see cref="MinimumThumbprintCount"/> entries. <see cref="Thumbprints"/>[0] is always the signing
/// certificate ("The first reference within the <c>x5ts</c> header parameter shall be the reference of the
/// signing certificate", clause 5.2.2); the remaining entries reference the rest of the certification path, in
/// path order. Ordering is semantically load-bearing and must survive every codec round-trip unreordered — see
/// <see cref="SigningCertificateThumbprint"/>. Clause 5.2.2 also states the parameter "shall not contain any
/// other information" beyond these entries, which this shape satisfies by construction.
/// </para>
/// <para>
/// <c>x5ts</c> is a signature-qualifying header parameter (clause 5.2.2) and an alternative to <c>x5t</c>/
/// <c>x5chain</c> (<see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>, profiled by
/// clause 5.1.7/5.1.8 of the same specification); a CB-AdES signature carries at least one of the three in its
/// protected headers map (clause 5.2.2). Composing that three-way disjunction, and placing this parameter in the
/// protected headers map at the signer layer (clause 5.2.2, "In <c>COSE_Sign</c> ... this header parameter shall
/// be placed at the signer layer"), is the signature builder's responsibility — this type models only the
/// parameter's own content.
/// </para>
/// <para>
/// <strong>Ownership:</strong> owns every <see cref="CBAdESCertificateThumbprint.Digest"/> reachable through
/// <see cref="Thumbprints"/>. Disposing this instance disposes all of them, mirroring the owned-carrier half of
/// <c>CoseSign1Message</c>'s ownership split (<c>CoseSign1Message.ProtectedHeader</c> and
/// <c>CoseSign1Message.Signature</c> are owned; <c>CoseSign1Message.Payload</c> is borrowed).
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESCertificateThumbprints: {Thumbprints.Count} thumbprints")]
public sealed class CBAdESCertificateThumbprints: IDisposable, IEquatable<CBAdESCertificateThumbprints>
{
    private bool disposed;

    /// <summary>
    /// The minimum number of entries the CDDL <c>2*x5t</c> occurrence operator requires (clause 5.2.2).
    /// </summary>
    public const int MinimumThumbprintCount = 2;

    /// <summary>
    /// Gets the <c>x5t</c> entries, in wire order. Index 0 is the signing certificate; the remainder is the
    /// rest of the certification path, in path order.
    /// </summary>
    public IReadOnlyList<CBAdESCertificateThumbprint> Thumbprints { get; }

    /// <summary>
    /// Gets the signing certificate's thumbprint — <see cref="Thumbprints"/>[0], per clause 5.2.2's ordering
    /// requirement.
    /// </summary>
    public CBAdESCertificateThumbprint SigningCertificateThumbprint => Thumbprints[0];


    /// <summary>
    /// Initializes a new <see cref="CBAdESCertificateThumbprints"/>. Ownership of every entry in
    /// <paramref name="thumbprints"/> transfers to this instance.
    /// </summary>
    /// <param name="thumbprints">
    /// The <c>x5t</c> entries in wire order, index 0 being the signing certificate. Must contain at least
    /// <see cref="MinimumThumbprintCount"/> entries.
    /// </param>
    /// <exception cref="ArgumentNullException">When <paramref name="thumbprints"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="thumbprints"/> has fewer than <see cref="MinimumThumbprintCount"/> entries.
    /// </exception>
    public CBAdESCertificateThumbprints(IReadOnlyList<CBAdESCertificateThumbprint> thumbprints)
    {
        ArgumentNullException.ThrowIfNull(thumbprints);
        if(thumbprints.Count < MinimumThumbprintCount)
        {
            throw new ArgumentException(
                $"The x5ts header parameter requires at least {MinimumThumbprintCount} entries per the CDDL "
                + $"'2*x5t' occurrence operator (ETSI TS 119 152-1 V1.1.1, clause 5.2.2); got {thumbprints.Count}.",
                nameof(thumbprints));
        }

        Thumbprints = thumbprints;
    }


    /// <summary>
    /// Disposes every <see cref="CBAdESCertificateThumbprint"/> this instance owns.
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
    /// Determines whether two <see cref="CBAdESCertificateThumbprints"/> instances carry the same entries in the
    /// same order.
    /// </summary>
    /// <param name="other">The instance to compare with.</param>
    /// <returns><see langword="true"/> when both carry equal entries in the same order.</returns>
    public bool Equals(CBAdESCertificateThumbprints? other)
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
    public override bool Equals(object? obj) => Equals(obj as CBAdESCertificateThumbprints);


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


    /// <summary>Determines whether two <see cref="CBAdESCertificateThumbprints"/> instances carry the same entries in the same order.</summary>
    public static bool operator ==(CBAdESCertificateThumbprints? left, CBAdESCertificateThumbprints? right) => left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="CBAdESCertificateThumbprints"/> instances differ.</summary>
    public static bool operator !=(CBAdESCertificateThumbprints? left, CBAdESCertificateThumbprints? right) => !(left == right);
}


/// <summary>
/// One <c>x5t</c> entry within <see cref="CBAdESCertificateThumbprints"/>: a <c>COSE_CertHash</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>, profiled by
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.1.7.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (RFC 9360 §2, reproduced at clause 5.1.7): <c>COSE_CertHash = [ hashAlg: (int / tstr), hashValue: bstr ]</c>.
/// <see cref="HashAlgorithm"/> models the CDDL's <c>int / tstr</c> union faithfully as
/// <see cref="CBAdESDigestAlgorithmIdentifier"/> rather than narrowing it to <see langword="int"/> — clause
/// 5.1.7's identifier-registry prose ("shall be one of the identifiers for digest algorithms registered in
/// IANA COSE Algorithms registry, or any future specification that defines new identifiers for digest
/// algorithms") constrains which registry an identifier comes from, not which CDDL arm it must use, so a
/// producer emitting the CDDL's <c>tstr</c> arm is not itself non-conformant. <c>hashValue</c> is the digest
/// of the referenced certificate's DER encoding, carried in <see cref="Digest"/> — never a naked
/// <c>byte[]</c>.
/// </para>
/// <para>
/// <strong>Ownership:</strong> owns <see cref="Digest"/>. Disposing this instance disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESCertificateThumbprint: HashAlgorithm={HashAlgorithm}")]
public sealed class CBAdESCertificateThumbprint: IDisposable, IEquatable<CBAdESCertificateThumbprint>
{
    private bool disposed;

    /// <summary>
    /// Gets the digest algorithm identifier — one of the
    /// <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms</see>
    /// registry entries (e.g. <c>WellKnownCoseAlgorithms.Sha256</c>), per the clause 5.1.7 profiling of
    /// <c>COSE_CertHash</c>'s <c>hashAlg</c> member. See <see cref="CBAdESDigestAlgorithmIdentifier"/> for
    /// the CDDL's <c>int / tstr</c> union this member models.
    /// </summary>
    public CBAdESDigestAlgorithmIdentifier HashAlgorithm { get; }

    /// <summary>
    /// Gets the digest of the referenced certificate's DER encoding — <c>COSE_CertHash</c>'s <c>hashValue</c>
    /// member.
    /// </summary>
    public DigestValue Digest { get; }


    /// <summary>
    /// Initializes a new <see cref="CBAdESCertificateThumbprint"/>. Ownership of <paramref name="digest"/>
    /// transfers to this instance.
    /// </summary>
    /// <param name="hashAlgorithm">The digest algorithm identifier.</param>
    /// <param name="digest">The digest of the referenced certificate's DER encoding.</param>
    /// <exception cref="ArgumentNullException">
    /// When <paramref name="hashAlgorithm"/> or <paramref name="digest"/> is <see langword="null"/>.
    /// </exception>
    public CBAdESCertificateThumbprint(CBAdESDigestAlgorithmIdentifier hashAlgorithm, DigestValue digest)
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
    /// Determines whether two <see cref="CBAdESCertificateThumbprint"/> instances carry the same algorithm and
    /// digest bytes.
    /// </summary>
    /// <param name="other">The instance to compare with.</param>
    /// <returns><see langword="true"/> when both carry the same algorithm and digest bytes.</returns>
    public bool Equals(CBAdESCertificateThumbprint? other)
    {
        return other is not null
            && HashAlgorithm == other.HashAlgorithm
            && Digest.AsReadOnlySpan().SequenceEqual(other.Digest.AsReadOnlySpan());
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CBAdESCertificateThumbprint);


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


    /// <summary>Determines whether two <see cref="CBAdESCertificateThumbprint"/> instances carry the same algorithm and digest bytes.</summary>
    public static bool operator ==(CBAdESCertificateThumbprint? left, CBAdESCertificateThumbprint? right) => left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="CBAdESCertificateThumbprint"/> instances differ.</summary>
    public static bool operator !=(CBAdESCertificateThumbprint? left, CBAdESCertificateThumbprint? right) => !(left == right);
}
