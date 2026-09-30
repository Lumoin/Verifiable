namespace Verifiable.Core.Relations;

/// <summary>
/// What a comparison's <see cref="ComparisonOutcome"/> leads to: a permit, a deny, or an indeterminate-deny,
/// in the words of the PIC Protocol.
/// </summary>
/// <remarks>
/// <para>
/// Where the answer leaves the library, a <see cref="Deny"/> and an <see cref="IndeterminateDeny"/> read the
/// same: both refuse. Only the record of the comparison tells them apart, a relation decided not to hold
/// against a relation nothing could decide, so the refusal a party sees does not reveal which one it met
/// while the audit trail keeps the difference.
/// </para>
/// <para>
/// The enumeration has no value for a refusal that leaves no record: every refusal it names is a decision a
/// record of the comparison carries.
/// </para>
/// </remarks>
public enum ComparisonDecision
{
    /// <summary>
    /// The comparison lets the step continue.
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-lineage-guardrail-spec.txt">PIC Sandboxed Execution (pic-sandboxed-execution-02) Section 2.4</see>:
    /// "The decision is recorded in the profile-defined request/execution binding as permit or deny or as an
    /// equivalent profile-defined value."
    /// </summary>
    Permit,

    /// <summary>
    /// The relation was decided not to hold, and the step does not continue.
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-lineage-guardrail-spec.txt">PIC Sandboxed Execution (pic-sandboxed-execution-02) Section 2.4</see>:
    /// "A permit MAY appear in an authorizing outer advancement; a deny MUST NOT authorize continuation. A
    /// profile MAY record a denial for audit, but MUST NOT introduce a denial artifact that is interpreted as
    /// permission to cross the governed boundary."
    /// </summary>
    Deny,

    /// <summary>
    /// Nothing could decide the relation, and the step does not continue.
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-lineage-guardrail-spec.txt">PIC Sandboxed Execution (pic-sandboxed-execution-02) Section 2.6</see>:
    /// "An input required by policy that is unauthenticated, ambiguously bound, semantically unmapped,
    /// inconsistent with the presented continuity state, unavailable, or controlled only by the proposing
    /// executor MUST produce deny or indeterminate-deny."
    /// </summary>
    /// <remarks>
    /// Which decision an undecided comparison leads to belongs to the profile that compares: a profile may
    /// permit an undecided comparison of a value its specification makes optional, deciding
    /// <see cref="Permit"/> while the record keeps the <see cref="ComparisonOutcome.Indeterminate"/> outcome
    /// that shows nothing decided it.
    /// </remarks>
    IndeterminateDeny
}
