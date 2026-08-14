using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A digest-algorithm identifier as it travels on the wire in either family: CB-AdES's <c>hashAlg: (int / tstr)</c>
/// CDDL union — <c>sigD.hashM</c>, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.8.1, reused identically at <c>sigPId.digAlgVal.hashAlg</c> (clause
/// 5.2.7.1) and <c>COSE_CertHash.hashAlg</c> (<see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC
/// 9360 §2</see>, reproduced at clause 5.1.7) — and JAdES's <c>digAlg</c> member, a textual identifier drawn from
/// the IANA "Named Information Hash Algorithm Registry", per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clauses 5.2.2.2/5.2.2.3. Modelled as a closed two-arm sum over CB-AdES's CDDL
/// choice rather than narrowed to <see langword="int"/>, so any identifier registered in the
/// <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms registry</see>,
/// present or future, round-trips byte-exactly through this library regardless of whether the registry ever
/// assigns a <c>tstr</c> identifier. A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// <para>
/// Which registry governs a given value is a property of the containing signature's format, not of this type:
/// a CB-AdES carrier's identifier is one of the IANA COSE Algorithms registry entries minted to date (every one
/// of which is an <see langword="int"/> — RFC 9053 and the documents that update it register only integer algorithm
/// identifiers, the same convention every other COSE algorithm identifier in this library already uses, e.g. the
/// well-known COSE algorithm identifier registry in the COSE layer, <c>WellKnownCoseAlgorithms</c>) or, since the
/// CDDL itself admits it, a future <c>tstr</c> identifier a conformant producer is free to emit
/// (<see cref="AdESDigestAlgorithmTextIdentifier"/>); a JAdES carrier's identifier always rides the
/// <see cref="AdESDigestAlgorithmTextIdentifier"/> arm, drawn from the IANA Named Information Hash Algorithm
/// Registry (JA-5.2.2.2-06). Each format's codec enforces which arm its own wire syntax permits; this carrier
/// preserves whichever identifier it is given verbatim either way.
/// </para>
/// <para>
/// Both sibling arms carry the record-generated structural <see cref="IEquatable{T}"/> implementation, so two
/// identifiers compare equal exactly when they are the same choice arm holding the same value — an integer
/// identifier never compares equal to a textual one, even when their printed forms coincide (e.g. <c>-16</c> vs
/// <c>"-16"</c>).
/// </para>
/// </remarks>
public abstract record AdESDigestAlgorithmIdentifier
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected AdESDigestAlgorithmIdentifier()
    {
    }
}


/// <summary>
/// The CB-AdES <c>int</c> arm of the <c>hashAlg: (int / tstr)</c> CDDL union (see
/// <see cref="AdESDigestAlgorithmIdentifier"/>) — every digest-algorithm identifier the IANA COSE Algorithms
/// registry currently assigns.
/// </summary>
/// <param name="Value">The integer digest-algorithm identifier.</param>
[DebuggerDisplay("AdESDigestAlgorithmIntegerIdentifier: {Value}")]
public sealed record AdESDigestAlgorithmIntegerIdentifier(int Value) : AdESDigestAlgorithmIdentifier;


/// <summary>
/// The CB-AdES <c>tstr</c> arm of the <c>hashAlg: (int / tstr)</c> CDDL union — and the only arm a JAdES
/// carrier's <c>digAlg</c> member ever uses, an IANA Named Information Hash Algorithm Registry identifier
/// (JA-5.2.2.2-06) — see <see cref="AdESDigestAlgorithmIdentifier"/>.
/// </summary>
[DebuggerDisplay("AdESDigestAlgorithmTextIdentifier: {Value}")]
public sealed record AdESDigestAlgorithmTextIdentifier : AdESDigestAlgorithmIdentifier
{
    /// <summary>
    /// Initializes the textual arm.
    /// </summary>
    /// <param name="value">The textual digest-algorithm identifier — see the remarks on <see cref="Value"/>.</param>
    /// <exception cref="ArgumentException"><paramref name="value"/> is <see langword="null"/> or empty.</exception>
    public AdESDigestAlgorithmTextIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);

        Value = value;
    }


    /// <summary>
    /// Gets the textual digest-algorithm identifier, verbatim. Never empty: an empty text identifies no
    /// registry entry in either governing registry (the IANA COSE Algorithms registry's <c>tstr</c> values and
    /// the IANA Named Information Hash Algorithm Registry's names are all non-empty), so an empty value is
    /// refused at construction.
    /// </summary>
    public string Value { get; }
}
