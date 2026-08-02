using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>hashAlg: (int / tstr)</c> CDDL union used throughout CB-AdES wherever a digest-algorithm identifier
/// travels on the wire — <c>sigD.hashM</c>, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.8.1, and reused identically at <c>sigPId.digAlgVal.hashAlg</c>
/// (clause 5.2.7.1, see <see cref="CBAdESSignaturePolicyIdentifier.HashAlgorithm"/>) and
/// <c>COSE_CertHash.hashAlg</c> (<see href="https://www.rfc-editor.org/rfc/rfc9360#section-2">RFC 9360 §2</see>,
/// reproduced at clause 5.1.7, see <see cref="CBAdESCertificateThumbprint.HashAlgorithm"/>) — modelled as a
/// closed two-arm sum over the CDDL choice rather than narrowed to <see langword="int"/>, so any identifier
/// registered in the
/// <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms registry</see>,
/// present or future, round-trips byte-exactly through this library regardless of whether the registry ever
/// assigns a <c>tstr</c> identifier. A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// <para>
/// Every IANA COSE Algorithms registry entry minted to date is an <see langword="int"/> (RFC 9053 and its
/// amendments register only integer algorithm identifiers — the <see langword="int"/> convention every other
/// COSE algorithm identifier in this library already uses, e.g. the well-known COSE algorithm identifier
/// registry in the COSE layer, <c>WellKnownCoseAlgorithms</c>); the <c>tstr</c> arm exists because the CDDL
/// itself admits it, and a conformant producer is free to use it, so this library's parse side accepts
/// whatever a producer emits (<see cref="CBAdESDigestAlgorithmTextIdentifier"/>) rather than narrowing the
/// wire contract to a subset the CDDL does not itself impose.
/// </para>
/// <para>
/// Both sibling arms carry the record-generated structural <see cref="IEquatable{T}"/> implementation, so two
/// identifiers compare equal exactly when they are the same CDDL choice arm holding the same value — an
/// integer identifier never compares equal to a textual one, even when their printed forms coincide (e.g.
/// <c>-16</c> vs <c>"-16"</c>).
/// </para>
/// </remarks>
public abstract record CBAdESDigestAlgorithmIdentifier
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESDigestAlgorithmIdentifier()
    {
    }
}


/// <summary>
/// The <c>int</c> arm of the <c>hashAlg: (int / tstr)</c> CDDL union (see <see cref="CBAdESDigestAlgorithmIdentifier"/>) —
/// every digest-algorithm identifier the IANA COSE Algorithms registry currently assigns.
/// </summary>
/// <param name="Value">The integer digest-algorithm identifier.</param>
[DebuggerDisplay("CBAdESDigestAlgorithmIntegerIdentifier: {Value}")]
public sealed record CBAdESDigestAlgorithmIntegerIdentifier(int Value) : CBAdESDigestAlgorithmIdentifier;


/// <summary>
/// The <c>tstr</c> arm of the <c>hashAlg: (int / tstr)</c> CDDL union (see <see cref="CBAdESDigestAlgorithmIdentifier"/>) —
/// a textual digest-algorithm identifier, for a future IANA COSE Algorithms registry entry or a private-use
/// extension the registry never assigns an integer to.
/// </summary>
/// <param name="Value">The textual digest-algorithm identifier.</param>
[DebuggerDisplay("CBAdESDigestAlgorithmTextIdentifier: {Value}")]
public sealed record CBAdESDigestAlgorithmTextIdentifier(string Value) : CBAdESDigestAlgorithmIdentifier;
