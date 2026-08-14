namespace Verifiable.Cryptography;

/// <summary>
/// What a <see cref="Verified{T}"/> instance knows about how its value's authenticity was established.
/// </summary>
/// <remarks>
/// <para>
/// Every <see cref="Verified{T}"/> carries exactly one <see cref="VerificationProvenance"/>, minted alongside
/// the value it describes. Two shapes exist, each honest about what it proves: <see cref="AssertedProvenance"/>
/// records a label with no binding behind it (a genuine bring-your-own-key path has nothing to resolve
/// against), and <see cref="BoundProvenance"/> records an identity a typed gate actually checked against the
/// verified value (<see cref="BoundProvenance.Witnesses(object)"/>) and the crypto-verification outcome that
/// produced it. A caller distinguishes the two through <see cref="Verified{T}.IsIdentityBound"/> rather than
/// treating every recorded <see cref="Identity"/> as an authenticated principal.
/// </para>
/// <para>
/// The constructor is <see langword="private protected"/>: only the two sealed subclasses declared in this
/// assembly can derive from it, so no third shape of provenance can appear.
/// </para>
/// </remarks>
public abstract class VerificationProvenance
{
    /// <summary>
    /// The verification method / key identifier this provenance names, or <see langword="null"/> when none is
    /// known.
    /// </summary>
    public KeyId? Identity { get; }


    private protected VerificationProvenance(KeyId? identity)
    {
        Identity = identity;
    }
}
