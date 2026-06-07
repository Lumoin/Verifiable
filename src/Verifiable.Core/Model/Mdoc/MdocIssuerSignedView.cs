namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Non-owning view of an <see cref="MdocIssuerSigned"/> — the presentation-side
/// counterpart to the issuance-side owned shape, mirroring the
/// <see cref="Verifiable.Core.Model.DataIntegrity.BaseProofResult"/> vs
/// <see cref="Verifiable.Core.Model.DataIntegrity.EcdsaSdDerivedProof"/>
/// split in the codebase.
/// </summary>
/// <remarks>
/// <para>
/// A view holds the same two slots an <see cref="MdocIssuerSigned"/> exposes —
/// <see cref="NameSpaces"/> and <see cref="IssuerAuth"/> — but borrows the
/// item references rather than owning them. The class is deliberately
/// <strong>not</strong> <see cref="IDisposable"/>: every
/// <see cref="MdocIssuerSignedItem"/> reachable through this view is owned
/// by a separate <see cref="MdocIssuerSigned"/> whose lifetime brackets the
/// view's. Disposing the underlying owned shape disposes the items'
/// <see cref="MdocIssuerSignedItem.Random"/> salts; the view never tries to.
/// </para>
/// <para>
/// Construction sources:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <see cref="MdocIssuerSignedTrimmer.Trim"/> — wallet-side selective
///     disclosure produces a filtered NameSpaces dictionary referencing a
///     subset of the owned items.
///   </description></item>
///   <item><description>
///     <see cref="FromOwned"/> — full-disclosure presentation; the view
///     simply reuses the owned shape's namespaces map verbatim.
///   </description></item>
/// </list>
/// <para>
/// The same hydrate → use → dispose lifecycle the rest of the codebase uses
/// applies: an <see cref="MdocIssuerSigned"/> is hydrated from storage or
/// from issuance, used (zero or more views are derived during this phase),
/// then disposed. The view exists only during the use phase.
/// </para>
/// </remarks>
public sealed class MdocIssuerSignedView
{
    /// <summary>
    /// Initializes a view from caller-supplied <paramref name="nameSpaces"/>
    /// (typically a trimmed subset) and <paramref name="issuerAuth"/>
    /// (typically the originating owned shape's
    /// <see cref="MdocIssuerSigned.IssuerAuth"/>).
    /// </summary>
    /// <remarks>
    /// The view stores both references as-is; the caller is responsible for
    /// ensuring the referenced items outlive the view (which falls out
    /// naturally when the view is derived from an owned
    /// <see cref="MdocIssuerSigned"/> that the same scope holds).
    /// </remarks>
    public MdocIssuerSignedView(
        IReadOnlyDictionary<string, IReadOnlyList<MdocIssuerSignedItem>> nameSpaces,
        MdocIssuerAuth issuerAuth)
    {
        ArgumentNullException.ThrowIfNull(nameSpaces);
        ArgumentNullException.ThrowIfNull(issuerAuth);

        NameSpaces = nameSpaces;
        IssuerAuth = issuerAuth;
    }


    /// <summary>
    /// Wraps an existing owned <see cref="MdocIssuerSigned"/> as a view
    /// without filtering — every item under every namespace is referenced.
    /// Use this when the presentation flow does NOT need selective
    /// disclosure (full-claim presentation).
    /// </summary>
    /// <param name="issuerSigned">The owned shape to view.</param>
    /// <returns>
    /// A view that borrows <paramref name="issuerSigned"/>'s namespaces map
    /// and <c>IssuerAuth</c> reference. Disposing
    /// <paramref name="issuerSigned"/> after this call still releases the
    /// salts; the returned view becomes unusable at that point.
    /// </returns>
    public static MdocIssuerSignedView FromOwned(MdocIssuerSigned issuerSigned)
    {
        ArgumentNullException.ThrowIfNull(issuerSigned);

        return new MdocIssuerSignedView(issuerSigned.NameSpaces, issuerSigned.IssuerAuth);
    }


    /// <summary>
    /// The borrowed <c>IssuerNameSpaces</c> map. Each namespace maps to an
    /// ordered list of <see cref="MdocIssuerSignedItem"/> references whose
    /// <see cref="MdocIssuerSignedItem.Random"/> salts are owned by the
    /// originating <see cref="MdocIssuerSigned"/>.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<MdocIssuerSignedItem>> NameSpaces { get; }

    /// <summary>
    /// The borrowed <c>IssuerAuth</c> reference carried unchanged from the
    /// originating <see cref="MdocIssuerSigned"/>. Non-nullable because a
    /// view is only ever derived from a signed <see cref="MdocIssuerSigned"/>,
    /// whose <c>IssuerAuth</c> is also non-nullable. The MSO commits to ALL
    /// items the issuer signed; a trimmed view simply presents a subset of
    /// those items, and the verifier resolves each presented item against
    /// the same MSO map.
    /// </summary>
    public MdocIssuerAuth IssuerAuth { get; }
}
