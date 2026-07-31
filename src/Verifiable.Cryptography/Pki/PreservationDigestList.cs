using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The names of the <c>DigestList</c> component (clause 5.6.1, Table 24 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>), the hash-only submission payload.
/// </summary>
/// <remarks>
/// <strong>The component is never a JSON object of its own.</strong> Clause 5.6.1.3 states it outright — "The
/// component <c>DigestList</c> is not used as JSON object directly" — so in the JSON syntax these three member
/// names occur only inside a preservation object's payload, never as members of a request. The names are
/// nonetheless the ones Table 24 states, which is why they are transcribed here like every other pair.
/// </remarks>
public static class PreservationDigestListParameterNames
{
    /// <summary>The mandatory <c>DigestMethod</c> element, JSON <c>digAlg</c> — the digest algorithm as a URI containing an object identifier.</summary>
    public static PreservationName DigestMethod { get; } = new("DigestMethod", "digAlg");

    /// <summary>The repeatable <c>DigestValue</c> element, JSON <c>digVal</c> — one digest value per submitted data object, an array in the JSON binding.</summary>
    public static PreservationName DigestValue { get; } = new("DigestValue", "digVal");

    /// <summary>The optional <c>Evidence</c> element, JSON <c>ev</c> — the preservation evidence to be augmented.</summary>
    public static PreservationName Evidence { get; } = new("Evidence", "ev");
}


/// <summary>
/// The digest algorithm a <c>DigestList</c> names, in the URI form clause 5.6.1.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> requires: "a URI, which contains an Object Identifier (OID) as specified in IETF
/// RFC 3061".
/// </summary>
/// <remarks>
/// <para>
/// <strong>The form is the object-identifier namespace of
/// <see href="https://www.rfc-editor.org/rfc/rfc3061">IETF RFC 3061</see></strong>: <c>urn:oid:</c> followed by
/// the dotted-decimal identifier, which the specification's own example spells
/// <c>urn:oid:2.16.840.1.101.3.4.2.1</c> for SHA-256. This class writes exactly that and reads it back through
/// <see cref="PkiDigestAlgorithm.FromOid"/>, so a digest list never names an algorithm this library cannot
/// compute and no second algorithm registry comes into being.
/// </para>
/// <para>
/// <strong>The namespace identifier is case-insensitive, the identifier itself is not.</strong> RFC 3061 states
/// the namespace-specific string as a dotted-decimal value with no case at all, while
/// <see href="https://www.rfc-editor.org/rfc/rfc8141#section-2">IETF RFC 8141 clause 2</see> makes the scheme and
/// the namespace identifier of a uniform resource name case-insensitive. Reading therefore folds case on the
/// prefix and compares the identifier exactly, and writing produces the lower-case prefix.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
    Justification = "The value is a uniform resource name compared and split as an exact character sequence; System.Uri normalises escaping and case, which would let two spellings of different object identifiers compare equal. Nothing here is dereferenced.")]
[SuppressMessage("Design", "CA1055:URI-like return values should not be strings",
    Justification = "The produced value is written into a wire element as an exact character sequence, for the reason given on the parameters.")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The prefix is a literal the value is built from and split on, never a locator; System.Uri cannot hold a namespace prefix without the namespace-specific string that follows it.")]
public static class PreservationDigestMethod
{
    /// <summary>The uniform resource name prefix of the object-identifier namespace, <c>urn:oid:</c>.</summary>
    public static string ObjectIdentifierUrnPrefix { get; } = "urn:oid:";

    /// <summary>
    /// The largest number of characters a digest method value is read with, 128 — an object identifier long
    /// enough for anything the registry resolves and short enough that a value built to exhaust a reader is
    /// refused before it is split.
    /// </summary>
    public static int MaximumLength { get; } = 128;


    /// <summary>
    /// Writes the digest method value naming an algorithm.
    /// </summary>
    /// <param name="algorithm">The algorithm to name.</param>
    /// <returns>The value, as <c>urn:oid:</c> followed by the algorithm's object identifier.</returns>
    public static string ToUrn(PkiDigestAlgorithm algorithm) =>
        string.Create(CultureInfo.InvariantCulture, $"{ObjectIdentifierUrnPrefix}{algorithm.Identifier.Oid}");


    /// <summary>
    /// Reads a digest method value into the algorithm it names.
    /// </summary>
    /// <param name="digestMethod">The value a <c>DigestMethod</c> element carried, or <see langword="null"/>.</param>
    /// <param name="algorithm">The algorithm named, when the value names one this library computes.</param>
    /// <returns><see langword="true"/> when the value is a well-formed object-identifier uniform resource name naming a resolvable algorithm.</returns>
    /// <remarks>
    /// A value that is not of the required form, and a value naming an algorithm the registry does not resolve,
    /// both answer <see langword="false"/>: a submission this library cannot compute the digests of is one it
    /// must not act on, and the two cases are the same refusal to a caller.
    /// </remarks>
    public static bool TryResolve(string? digestMethod, out PkiDigestAlgorithm algorithm)
    {
        algorithm = default;
        if(string.IsNullOrEmpty(digestMethod) || digestMethod.Length > MaximumLength)
        {
            return false;
        }

        if(!digestMethod.StartsWith(ObjectIdentifierUrnPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string oid = digestMethod[ObjectIdentifierUrnPrefix.Length..];
        if(oid.Length == 0)
        {
            return false;
        }

        if(PkiDigestAlgorithm.FromOid(oid) is not PkiDigestAlgorithm resolved)
        {
            return false;
        }

        algorithm = resolved;

        return true;
    }
}


/// <summary>
/// The <c>DigestList</c> component (clause 5.6.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>): digest values instead of the data objects themselves, and optionally the
/// preservation evidence they are to be carried forward into.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What it is for.</strong> The component is "conveyed as content of a single <c>PO</c> component within
/// the <c>PreservePO</c> call of the preservation scheme with temporary storage", and clause A.3.1.4.7 gives the
/// reason: sending a hash function identifier and a hash value rather than the file keeps "the preservation
/// service ignorant of both the semantics and the size of the object to be protected". The preservation object
/// carrying it states <see cref="PreservationFormatWellKnown.DigestListFormat"/> as its format identifier
/// (clause A.1.6).
/// </para>
/// <para>
/// <strong>The <c>Evidence</c> element is what turns a submission into a renewal.</strong> The clause's own NOTE
/// says it: a digest list carrying a digest method, a list of digest values and an evidence record according to
/// IETF RFC 4998 or IETF RFC 6283 "allows to perform a hash-tree renewal of the provided evidence record".
/// <see cref="PreservationDigestListRenewal"/> is where that composition with the shipped renewal procedures
/// lives; this record is the wire shape and performs nothing.
/// </para>
/// <para>
/// <strong>A cardinality that lives outside this component.</strong> Clause 5.6.1.1 states that "It is only
/// admissible to submit a single <c>PO</c> component with a single <c>DigestList</c> component within one
/// <c>PreservePO</c> call" — a rule about the request rather than about the digest list, which is why
/// <see cref="PreservationDigestListRenewal"/> and a service's own request handling are where it is enforced and
/// this type does not pretend to.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every digest value and the evidence, and disposing it disposes
/// them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The digest method is a uniform resource name carried and compared as an exact character sequence and resolved by PreservationDigestMethod; System.Uri normalises escaping and case, which would let two spellings of different object identifiers compare equal.")]
public sealed record PreservationDigestList: IDisposable
{
    /// <summary>
    /// The mandatory <c>DigestMethod</c> element — the digest algorithm, as the object-identifier uniform
    /// resource name <see cref="PreservationDigestMethod"/> writes and reads.
    /// </summary>
    public required string DigestMethod { get; init; }

    /// <summary>
    /// The <c>DigestValue</c> elements — one or more digest values, each computed with
    /// <see cref="DigestMethod"/>. Owned by this instance.
    /// </summary>
    public required IReadOnlyList<DigestValue> DigestValues { get; init; }

    /// <summary>
    /// The optional <c>Evidence</c> element — the preservation evidence the service is to augment, or
    /// <see langword="null"/> when the submission carries none. Owned by this instance.
    /// </summary>
    public PreservationEvidence? Evidence { get; init; }


    /// <summary>Disposes every digest value and the evidence.</summary>
    public void Dispose()
    {
        for(int i = 0; i < DigestValues.Count; ++i)
        {
            DigestValues[i].Dispose();
        }

        Evidence?.Dispose();
    }


    /// <summary>A short debugger string showing the algorithm, how many values and whether an evidence rides with them.</summary>
    private string DebuggerDisplay =>
        $"PreservationDigestList({DigestMethod}, {DigestValues.Count} values, {(Evidence is null ? "no evidence" : Evidence.FormatId)})";
}
