namespace Verifiable.Xml;

/// <summary>
/// The clause 4.5 canonicalization-management resolution point: given a qualifying property's own optional
/// <c>ds:CanonicalizationMethod</c> child, resolves which of the six clause 6.3(d) canonicalization
/// algorithms it names, or refuses with a named disposition — never a silently assumed default. Every XAdES
/// qualifying property that "provides optional means for indicating the canonicalization algorithm"
/// (clause 4.5's framing; every <c>GenericTimeStampType</c>/<c>ReferenceInfoType</c>-family property clause
/// 5.1.4 declares) resolves its canonicalization method through this ONE place rather than a per-property
/// copy.
/// </summary>
/// <remarks>
/// The refusal fires at USE — when a caller actually needs the resolved algorithm to canonicalize something
/// — never at container read: a <c>ds:CanonicalizationMethod</c> child is schema-optional
/// (<c>minOccurs="0"</c> throughout clause 5.1.4's schemas) and its absence is a perfectly well-formed
/// document to READ; it only becomes a refusal once clause 4.5's "shall include the canonicalization
/// algorithm identifier" generation-mandatory rule is applied against it.
/// </remarks>
public static class XAdESCanonicalizationManagement
{
    /// <summary>
    /// Resolves a qualifying property's <c>ds:CanonicalizationMethod</c> against the six clause 6.3(d)
    /// algorithms.
    /// </summary>
    /// <param name="hasCanonicalizationMethod">Whether the <c>ds:CanonicalizationMethod</c> child is present.</param>
    /// <param name="canonicalizationMethod">The <c>ds:CanonicalizationMethod</c> child, meaningful only when
    /// <paramref name="hasCanonicalizationMethod"/> is <see langword="true"/>.</param>
    /// <param name="algorithm">The resolved algorithm on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESProcessingFailure.AbsentCanonicalizationMethod"/> when
    /// <paramref name="hasCanonicalizationMethod"/> is <see langword="false"/> — clause 4.5 makes the
    /// element generator-mandatory for every EN-conformant signature and augmentation, and legacy material is
    /// out of scope, so its absence at use time is a named refusal rather than an
    /// assumed default;
    /// <see cref="XAdESProcessingFailure.UnsupportedCanonicalizationMethod"/> when its <c>Algorithm</c> is not
    /// one of the six clause 6.3(d) URIs.</param>
    /// <returns><see langword="true"/> when the algorithm resolved.</returns>
    public static bool TryResolve(
        bool hasCanonicalizationMethod,
        XmlCanonicalizationMethodInfo canonicalizationMethod,
        out XmlCanonicalizationAlgorithm algorithm,
        out XAdESProcessingError error)
    {
        algorithm = default;
        if(!hasCanonicalizationMethod)
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.AbsentCanonicalizationMethod, 0);

            return false;
        }

        if(!XmlReferenceProcessing.TryMapCanonicalizationAlgorithm(canonicalizationMethod.Algorithm, out algorithm))
        {
            error = new XAdESProcessingError(XAdESProcessingFailure.UnsupportedCanonicalizationMethod, 0);

            return false;
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Letter e): tells whether <paramref name="algorithm"/> is one of the three "with comments" variants
    /// (<see cref="XmlCanonicalizationAlgorithm.CanonicalXml10WithComments"/>,
    /// <see cref="XmlCanonicalizationAlgorithm.CanonicalXml11WithComments"/>,
    /// <see cref="XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments"/>) — "the signer/signature
    /// generator SHOULD NOT use a canonicalization algorithm that provides comments" is a SHOULD-NOT observable
    /// on the algorithm a <c>ds:CanonicalizationMethod</c> already resolved to, never a read-time refusal.
    /// </summary>
    /// <param name="algorithm">The resolved canonicalization algorithm.</param>
    /// <returns><see langword="true"/> when <paramref name="algorithm"/> preserves comments.</returns>
    public static bool IsWithCommentsAlgorithm(XmlCanonicalizationAlgorithm algorithm) => algorithm switch
    {
        XmlCanonicalizationAlgorithm.CanonicalXml10WithComments => true,
        XmlCanonicalizationAlgorithm.CanonicalXml11WithComments => true,
        XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments => true,
        _ => false
    };


    /// <summary>
    /// Translates a canonicalization refusal a resolved clause-4.5 algorithm produced into a XAdES processing
    /// one. Only <see cref="XmlCanonicalizationFailure.InvalidPrefixList"/> is reachable from input content
    /// the message-imprint engines hand to <see cref="XmlCanonicalization"/>: every node-set those engines
    /// canonicalize is valid over its own table by construction, the same invariant
    /// <see cref="XmlReferenceProcessing"/>'s own identically-reasoned internal mapper relies on. This is the
    /// one shared site every clause-4.5 message-imprint engine in the leaf calls — among them
    /// <see cref="XAdESIncludeProcessing"/>, <see cref="XAdESSignatureTimeStampImprint"/>,
    /// <see cref="XAdESArchiveTimeStampImprint"/>, <see cref="XAdESSigAndRefsTimeStampV2Imprint"/>,
    /// <see cref="XAdESRefsOnlyTimeStampV2Imprint"/> and <see cref="XAdESRenewedDigestsV2Processing"/> — kept
    /// here at clause 4.5's own home rather than duplicated per caller.
    /// </summary>
    internal static XAdESProcessingError MapCanonicalizationFailure(XmlCanonicalizationError error)
    {
        if(error.Failure == XmlCanonicalizationFailure.InvalidPrefixList)
        {
            return new XAdESProcessingError(XAdESProcessingFailure.InvalidCanonicalizationParameter, error.ByteOffset);
        }

        throw new InvalidOperationException($"Canonicalizing a node-set an imprint engine constructed itself must not fail with {error.Failure}.");
    }
}
