using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Model.Credentials;

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
public class DataIntegritySecuredCredential: VerifiableCredential
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
}
