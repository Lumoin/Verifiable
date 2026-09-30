namespace Verifiable.Core.Relations;

/// <summary>
/// The relation a comparison asks to hold between a candidate value and a reference value, read
/// "candidate RELATION reference": the candidate is the value presented at this step, the reference is the
/// value it is judged against.
/// </summary>
/// <remarks>
/// <para>
/// The four relations are the four the example of
/// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier (pic-prover-verifier-02) Section 4.2</see>
/// writes between a current value and its predecessor: equality, subset inclusion, superset inclusion and
/// the not-later-than order of an expiry. The candidate plays the part of the current value and the reference
/// the part of the predecessor. A relation names what is asked; the value's own rule or the application's
/// comparison decides whether it holds, and <see cref="ComparisonOutcome"/> carries the answer.
/// </para>
/// <para>
/// The PIC Prover and Verifier specification describes itself as a "Public Draft" and states: "It is not an
/// RFC, an Internet Standard, or an official work item of any working group or standards body." This library
/// adopts the vocabulary of its comparisons and not its protocol: it builds and verifies no Proof of
/// Continuity and claims no conformance to the PIC Protocol.
/// </para>
/// </remarks>
public enum ComparisonRelation
{
    /// <summary>
    /// The candidate equals the reference under the equivalence the value defines. The example of
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier Section 4.2</see>
    /// writes it for a role: "role:               current == predecessor". In this library the ID-JAG
    /// <c>sub_id</c> claim is compared under it with the subject the grant's validated claims name.
    /// </summary>
    Equal,

    /// <summary>
    /// Every element of the candidate is an element of the reference. The example of
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier Section 4.2</see>
    /// writes the subset sign between the current and the predecessor <c>allowedRegions</c> and
    /// <c>executionModel</c>. In this library the narrowing of the requested resources to the granted ones
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 Section 2.2</see>, and the
    /// refresh rule of <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 Section 6</see>)
    /// can be expressed under it.
    /// </summary>
    SubsetOf,

    /// <summary>
    /// Every element of the reference is an element of the candidate. The example of
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier Section 4.2</see>
    /// writes the superset sign between the current and the predecessor <c>requiredCompliance</c>: a
    /// successor keeps every obligation its predecessor carried. No comparison in this library asks for it.
    /// </summary>
    SupersetOf,

    /// <summary>
    /// The candidate instant is the same as or earlier than the reference instant. The example of
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier Section 4.2</see>
    /// writes the less-than-or-equal sign between the current and the predecessor <c>expiresAt</c>. In this
    /// library an expiry clamp, a lifetime that ends no later than the lifetime it derives from, can be
    /// expressed under it.
    /// </summary>
    NotLaterThan
}
