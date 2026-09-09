using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Credentials;
using Verifiable.Foundation;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// A Verifiable Credential secured with one or more embedded Data Integrity proofs.
/// </summary>
/// <remarks>
/// <para>
/// In the embedded securing mechanism, the proof is an in-graph member sitting at the
/// same object level as the credential's claims and metadata. This type therefore IS a
/// <see cref="VerifiableCredential"/> with an added proof chain, not a wrapper around one:
/// on the wire it is a single JSON-LD object whose members are the credential's members
/// plus a "proof" member.
/// </para>
/// <para>
/// The unsecured <see cref="VerifiableCredential"/> is the input to securing; the
/// embedded-secured output is an instance of this type. Enveloping mechanisms (JOSE, COSE,
/// SD-JWT, SD-CWT) instead carry the credential as a payload inside a distinct container
/// type and do not use this type.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0
/// §2.1 Proofs</see> and proof chains
/// <see href="https://www.w3.org/TR/vc-data-integrity/#proof-chains">§2.1.2 Proof Chains</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("DataIntegritySecuredCredential(Id = {Id}, Proofs = {Proof?.Count})")]
public class DataIntegritySecuredCredential: VerifiableCredential, IEquatable<DataIntegritySecuredCredential>
{
    /// <summary>
    /// The ordered Data Integrity proof chain securing this credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A single-element list is an ordinary single proof. Multiple proofs form a chain,
    /// where each subsequent proof's <see cref="DataIntegrityProof.PreviousProof"/>
    /// references the <see cref="DataIntegrityProof.Id"/> of the proof it builds upon.
    /// Verification walks the chain in dependency order.
    /// </para>
    /// </remarks>
    public List<DataIntegrityProof>? Proof { get; set; }


    /// <summary>
    /// Equality folds <see cref="Proof"/> into the inherited
    /// <see cref="VerifiableCredential.Equals(VerifiableCredential?)"/> comparison (which
    /// already enforces the exact-type guard): a secured document's identity includes the proof
    /// that secures it, so two credentials sharing every other member but signed by different
    /// keys - an honest credential and one impersonating the same issuer - are two distinct
    /// signed artifacts, not the same artifact observed twice, and MUST compare unequal.
    /// </summary>
    /// <param name="other">The secured credential to compare against.</param>
    /// <returns><see langword="true"/> if the secured credentials are equal; otherwise <see langword="false"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(DataIntegritySecuredCredential? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return base.Equals(other) && StructuralEquality.SequenceEqual(Proof, other.Proof);
    }


    /// <summary>
    /// Overrides <see cref="VerifiableCredential.Equals(VerifiableCredential?)"/> so the
    /// <see cref="Proof"/> fold performed by <see cref="Equals(DataIntegritySecuredCredential?)"/>
    /// is reached even when this instance is compared through the base
    /// <see cref="VerifiableCredential"/> static type rather than this derived one: a plain
    /// <c>List&lt;VerifiableCredential&gt;</c>, an
    /// <c>IEquatable&lt;VerifiableCredential&gt;</c>-based comparer such as
    /// <c>EqualityComparer&lt;VerifiableCredential&gt;.Default</c>, and the inherited
    /// <c>operator ==</c> all dispatch this virtual method by the instance's runtime type, so an
    /// honest credential and one carrying a different or forged proof never compare equal
    /// regardless of which static type the caller holds them as.
    /// </summary>
    /// <param name="other">The credential to compare against.</param>
    /// <returns><see langword="true"/> if the credentials are equal; otherwise <see langword="false"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(VerifiableCredential? other) =>
        other is DataIntegritySecuredCredential secured && Equals(secured);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is DataIntegritySecuredCredential other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(base.GetHashCode());
        hash.Add(StructuralEquality.SequenceHashCode(Proof));

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(DataIntegritySecuredCredential? left, DataIntegritySecuredCredential? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(DataIntegritySecuredCredential? left, DataIntegritySecuredCredential? right) => !(left == right);
}
