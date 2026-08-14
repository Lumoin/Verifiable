using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One element of <see cref="AdESSignerAttributes.SignedAssertions"/> or
/// <see cref="AdESSignerAttributes.Claimed"/> when produced by JAdES (<c>qArrays</c> item,
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.2.5): one signed assertion or claimed attribute, self-describing
/// its own media type and value encoding.
/// </summary>
/// <remarks>
/// <para>JSON Schema (clause 5.2.5, copied from Annex B.1):</para>
/// <code>
/// {
///   "type": "object",
///   "properties": {
///     "mediaType": {"type": "string"},
///     "encoding": {"type": "string"},
///     "qVals": {"type": "array", "minItems": 1}
///   },
///   "required": ["mediaType", "encoding", "qVals"],
///   "additionalProperties": false
/// }
/// </code>
/// <para>
/// All three members are required (JA-5.2.5-11/-12/-14/-16), unlike
/// <see cref="CBAdESSignerAttributeNotCertifiedItem"/>'s CDDL/prose contradiction — no
/// opaque-carrier escape hatch is needed here; this is why <see cref="AdESSignerAttributes"/> does not force
/// the two formats' item shapes into one type. <see cref="QualifyingValues"/>'s own elements carry no further
/// type constraint in the schema (<c>qVals</c>'s <c>items</c> sub-schema is unconstrained) beyond "the values
/// ... encoded as indicated within the encoding member" (JA-5.2.5-17); the definition of specific content
/// types is explicitly out of this document's scope (clause 5.2.5). Each element is therefore carried as an
/// opaque JSON value (<see langword="object"/>), matching <see cref="AdESCommitment.CommitmentQualifiers"/>'s
/// identical open-value convention; a caller that knows <see cref="MediaType"/>/<see cref="Encoding"/> decodes
/// accordingly.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESQualifyingAttribute: {MediaType}, {Encoding}, {QualifyingValues.Count} values")]
public sealed record JAdESQualifyingAttribute
{
    /// <summary>The <c>mediaType</c> member's JSON key name (clause 5.2.5, Annex B.1 schema).</summary>
    public const string MediaTypeMemberName = "mediaType";

    /// <summary>The <c>encoding</c> member's JSON key name (clause 5.2.5, Annex B.1 schema).</summary>
    public const string EncodingMemberName = "encoding";

    /// <summary>The <c>qVals</c> member's JSON key name (clause 5.2.5, Annex B.1 schema).</summary>
    public const string QualifyingValuesMemberName = "qVals";

    /// <summary>
    /// Initializes a new <see cref="JAdESQualifyingAttribute"/>.
    /// </summary>
    /// <param name="mediaType">
    /// The <c>mediaType</c> member (JA-5.2.5-12): a string identifying the type of the values in
    /// <paramref name="qualifyingValues"/>, per the IANA media-types registry.
    /// </param>
    /// <param name="encoding">
    /// The <c>encoding</c> member (JA-5.2.5-14): a string identifying the encoding of the values in
    /// <paramref name="qualifyingValues"/>.
    /// </param>
    /// <param name="qualifyingValues">
    /// The <c>qVals</c> member (JA-5.2.5-16/-17): the values of the signed assertions or claimed attributes,
    /// encoded as <paramref name="encoding"/> states. Must be non-empty (schema <c>"minItems": 1"</c>).
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="mediaType"/> or <paramref name="encoding"/> is <see langword="null"/> or empty.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="qualifyingValues"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="qualifyingValues"/> is empty.</exception>
    public JAdESQualifyingAttribute(string mediaType, string encoding, IReadOnlyList<object> qualifyingValues)
    {
        ArgumentException.ThrowIfNullOrEmpty(mediaType);
        ArgumentException.ThrowIfNullOrEmpty(encoding);
        ArgumentNullException.ThrowIfNull(qualifyingValues);
        if(qualifyingValues.Count == 0)
        {
            throw new ArgumentException(
                "qArrays's 'qVals' member shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, clause 5.2.5, " +
                "JA-5.2.5-16, Annex B.1 schema 'minItems: 1').",
                nameof(qualifyingValues));
        }

        MediaType = mediaType;
        Encoding = encoding;
        QualifyingValues = qualifyingValues;
    }


    /// <summary>
    /// Gets the media type identifying the type of the values in <see cref="QualifyingValues"/> (<c>mediaType</c>,
    /// JA-5.2.5-12), per the IANA media-types registry.
    /// </summary>
    public string MediaType { get; }

    /// <summary>
    /// Gets the encoding identifying how each element of <see cref="QualifyingValues"/> is encoded (<c>encoding</c>,
    /// JA-5.2.5-14).
    /// </summary>
    public string Encoding { get; }

    /// <summary>
    /// Gets the qualifying-values collection (<c>qVals</c>, JA-5.2.5-16/-17). Non-empty (constructor-enforced).
    /// See the type remarks for why each element is carried opaque.
    /// </summary>
    public IReadOnlyList<object> QualifyingValues { get; }
}
