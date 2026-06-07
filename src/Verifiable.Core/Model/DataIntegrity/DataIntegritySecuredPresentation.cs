using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Model.Credentials;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// A Verifiable Presentation secured with one or more embedded Data Integrity proofs.
/// </summary>
/// <remarks>
/// <para>
/// In the embedded securing mechanism, the proof is an in-graph member sitting at the
/// same object level as the presentation's members. This type therefore IS a
/// <see cref="VerifiablePresentation"/> with an added proof chain, not a wrapper around
/// one: on the wire it is a single JSON-LD object whose members are the presentation's
/// members plus a <c>proof</c> member.
/// </para>
/// <para>
/// The unsecured <see cref="VerifiablePresentation"/> is the input to securing; the
/// embedded-secured output is an instance of this type. Enveloping mechanisms (JOSE,
/// COSE) instead carry the presentation as a payload referenced from an
/// <see cref="EnvelopedVerifiablePresentation"/> and do not use this type.
/// </para>
/// <para>
/// A presentation proof uses the <c>authentication</c> proof purpose and binds the
/// proof to a verifier interaction through the <see cref="DataIntegrityProof.Challenge"/>
/// and <see cref="DataIntegrityProof.Domain"/> options — see
/// <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0
/// §2.1 Proofs</see> and
/// <see href="https://www.w3.org/TR/vc-data-integrity/#proof-chains">§2.1.2 Proof Chains</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("DataIntegritySecuredPresentation(Id = {Id}, Proofs = {Proof?.Count})")]
public class DataIntegritySecuredPresentation: VerifiablePresentation
{
    /// <summary>
    /// The ordered Data Integrity proof chain securing this presentation.
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
}
