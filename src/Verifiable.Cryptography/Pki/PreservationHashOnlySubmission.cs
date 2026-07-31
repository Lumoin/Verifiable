using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which part of a hash-only submission a preservation-goal treatment is about.
/// </summary>
/// <remarks>
/// <see cref="NotStated"/> occupies zero so a default-initialised part names nothing.
/// </remarks>
public enum PreservationSubmissionPart
{
    /// <summary>No part has been stated. The value of an unset field, by design.</summary>
    NotStated = 0,

    /// <summary>The detached signature the submission carries.</summary>
    DetachedSignature = 1,

    /// <summary>One of the hash values submitted instead of the signed data.</summary>
    SubmittedHashValue = 2
}


/// <summary>
/// Which preservation goal one part of a hash-only submission is treated under — the per-part answer
/// <c>OVR-9.3-07</c> of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> forces.
/// </summary>
/// <remarks>
/// <c>OVR-9.3-07</c> obliges a service to "treat the hash value (associated with a hash function identifier) as a
/// general data linked somehow to the signature, since it has no way of knowing if the hash value really
/// corresponds to the signed data". One submission therefore carries two treatments at once: the signature keeps
/// the preservation of digital signatures, and every bare hash is treated under the preservation of general data.
/// A caller dispatching strictly per goal has to read this list rather than the profile's goal set.
/// </remarks>
/// <param name="Part">Which part of the submission the treatment is about.</param>
/// <param name="Index">Which one, where the part occurs more than once; zero for the detached signature.</param>
/// <param name="Goal">The preservation goal the part is treated under, as <see cref="PreservationWellKnown.IsPreservationGoal"/> names it.</param>
/// <param name="RequirementIdentifier">The requirement that decides the treatment, in the document's own grammar.</param>
[DebuggerDisplay("PreservationGoalTreatment: {Part} {Index} under {Goal}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The goal is compared as an exact character sequence against PreservationWellKnown's goal vocabulary; System.Uri normalises case and escaping, which would let two identifiers that name different goals compare equal.")]
public sealed record PreservationGoalTreatment(
    PreservationSubmissionPart Part,
    int Index,
    string Goal,
    string RequirementIdentifier);


/// <summary>
/// A submission that carries a detached signature and, instead of the signed data, hash values of it — the case
/// <c>OVR-9.3-05</c> of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> permits a preservation service to allow.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What makes this its own type.</strong> <c>OVR-9.3-05</c> is about a detached signature whose signed
/// data the submitter withholds; the signature itself is still submitted, which is why
/// <see cref="DetachedSignature"/> is required. That is a different case from the hash-only submission of the
/// companion protocol standard's clause 5.6.1, where digest values are submitted with no signature at all for the
/// preservation of general data — that case is <see cref="PreservationDigestList"/> and has its own type for the
/// same reason.
/// </para>
/// <para>
/// <strong>The hash function is named once for the whole submission.</strong> <c>OVR-9.3-08</c> speaks of "hash
/// function identifiers" and of "each hash value has a length in accordance with the associated hash function
/// identifier"; one identifier associated with the submitted values is what makes "the associated identifier"
/// well defined, and it is the shape the companion standard's digest list uses as well.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every submitted hash value and the detached signature, and
/// disposing it disposes them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The hash function identifier is the object-identifier uniform resource name PreservationDigestMethod writes and reads as an exact character sequence; System.Uri normalises escaping and case, which would let two spellings of different object identifiers compare equal.")]
public sealed record PreservationHashOnlySubmission: IDisposable
{
    /// <summary>
    /// The identifier of the hash function the submitted values were computed with, in the object-identifier
    /// uniform resource name form <see cref="PreservationDigestMethod"/> writes and reads.
    /// </summary>
    public required string HashFunctionIdentifier { get; init; }

    /// <summary>The hash values submitted instead of the signed data, one per signed data object. Owned by this instance.</summary>
    public required IReadOnlyList<DigestValue> SignedDataHashes { get; init; }

    /// <summary>The detached signature whose signed data the hashes stand in for. Owned by this instance.</summary>
    public required PreservationObject DetachedSignature { get; init; }


    /// <summary>Disposes every submitted hash value and the detached signature.</summary>
    public void Dispose()
    {
        for(int i = 0; i < SignedDataHashes.Count; ++i)
        {
            SignedDataHashes[i].Dispose();
        }

        DetachedSignature.Dispose();
    }


    /// <summary>A short debugger string showing the hash function and how many values ride under it.</summary>
    private string DebuggerDisplay =>
        $"PreservationHashOnlySubmission({HashFunctionIdentifier}, {SignedDataHashes.Count} hash values)";
}


/// <summary>
/// Whether a hash-only submission passes the two checks <c>OVR-9.3-08</c> of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> obliges a preservation service to make, and if not, which one it failed.
/// </summary>
/// <remarks>
/// <see cref="Accepted"/> is deliberately not zero: a submission whose acceptance has not been computed must not
/// read as one that was accepted.
/// </remarks>
public enum PreservationHashOnlySubmissionStatus
{
    /// <summary>No submission has been judged. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>Both checks passed; the submission is one the profile admits.</summary>
    Accepted = 1,

    /// <summary>
    /// The profile announces no preservation of digital signatures, and <c>OVR-9.3-05</c> to <c>OVR-9.3-08</c> are
    /// tagged for that goal alone, so this submission is not the case they govern.
    /// </summary>
    ProfileDoesNotPreserveDigitalSignatures = 2,

    /// <summary>
    /// The profile lists no accepted hash function, so it does not allow hash-only submission at all —
    /// <c>OVR-9.3-06</c>'s list is what a profile allowing it states.
    /// </summary>
    ProfileStatesNoAcceptedHashFunction = 3,

    /// <summary>The submitted identifier is not a well-formed object-identifier uniform resource name naming a hash function this library computes.</summary>
    HashFunctionNotResolvable = 4,

    /// <summary>The submitted identifier names a hash function the profile does not list — the first check of <c>OVR-9.3-08</c>.</summary>
    HashFunctionNotAcceptedByProfile = 5,

    /// <summary>The submission states no hash value, so there is nothing standing in for the signed data.</summary>
    NoHashValueStated = 6,

    /// <summary>A submitted hash value is not as long as the associated hash function produces — the second check of <c>OVR-9.3-08</c>.</summary>
    HashValueLengthMismatch = 7
}


/// <summary>
/// Everything one <see cref="PreservationHashOnlySubmissions.StateAcceptance"/> call reads: the submission and the
/// profile it was made under.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> The caller owns both and disposes them; the report owns nothing.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationHashOnlySubmissionContext
{
    /// <summary>The submission being judged.</summary>
    public required PreservationHashOnlySubmission Submission { get; init; }

    /// <summary>The profile it was made under, whose announced input formats state which hash functions are accepted.</summary>
    public required PreservationProfile Profile { get; init; }


    /// <summary>A short debugger string showing what is being judged against which profile.</summary>
    private string DebuggerDisplay =>
        $"PreservationHashOnlySubmissionContext({Submission.SignedDataHashes.Count} hash values, profile {Profile.ProfileIdentifier})";
}


/// <summary>
/// What <see cref="PreservationHashOnlySubmissions.StateAcceptance"/> answered: whether the submission is one the
/// profile admits, and under which preservation goal each of its parts is then treated.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PreservationHashOnlySubmissionReport
{
    /// <summary>The outcome; <see cref="PreservationHashOnlySubmissionStatus.Accepted"/> is the only acceptance.</summary>
    public required PreservationHashOnlySubmissionStatus Status { get; init; }

    /// <summary>The hash functions the profile lists as accepted, in the order it lists them and without repetition.</summary>
    public required IReadOnlyList<PkiDigestAlgorithm> AcceptedHashFunctions { get; init; }

    /// <summary>
    /// The per-part preservation-goal treatment <c>OVR-9.3-07</c> forces, produced only for an accepted
    /// submission; empty otherwise, because a refused submission is treated under no goal at all.
    /// </summary>
    public required IReadOnlyList<PreservationGoalTreatment> GoalTreatments { get; init; }

    /// <summary>The hash function the submitted identifier named, when it named one this library computes.</summary>
    public PkiDigestAlgorithm? HashFunction { get; init; }

    /// <summary>Which submitted hash value the outcome turns on, when one does.</summary>
    public int? OffendingHashValueIndex { get; init; }

    /// <summary>What the outcome turns on, in terms a report can present, or <see langword="null"/> on acceptance.</summary>
    public string? Reason { get; init; }


    /// <summary>Gets whether the submission passed both checks.</summary>
    public bool IsAccepted => Status == PreservationHashOnlySubmissionStatus.Accepted;


    /// <summary>A short debugger string showing the outcome and how many treatments came out of it.</summary>
    private string DebuggerDisplay =>
        $"PreservationHashOnlySubmissionReport({Status}, {GoalTreatments.Count} goal treatments)";
}


/// <summary>
/// The hash-only submission capability of clause 9.3 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see>: which hash functions a profile accepts (<c>OVR-9.3-06</c>), the two checks a
/// service makes on a submission (<c>OVR-9.3-08</c>) and the per-part goal treatment that follows
/// (<c>OVR-9.3-07</c>).
/// </summary>
/// <remarks>
/// <para>
/// <strong>A profile's accepted hash functions are its submission operation's input formats.</strong>
/// <c>OVR-9.3-06</c> requires the profile to "indicate ... the identifiers of the hash functions that can be used"
/// and names no element of its own; <c>OVR-6.4-04</c> b) EXAMPLE 1 is the element it means — "In case the hash of
/// data can be provided, the list of accepted hash functions" is a list of supported input formats. An accepted
/// hash function is therefore an input format of the submission operation whose identifier resolves through
/// <see cref="PreservationDigestMethod.TryResolve"/>, which composes the algorithm resolution this library already
/// ships rather than starting a second registry. Recorded as a documented interpretation, not as a reading the
/// document spells out.
/// </para>
/// <para>
/// <strong>Nothing here hashes anything.</strong> Both checks <c>OVR-9.3-08</c> states are about the submitted
/// identifier and the submitted lengths, and the clause explains why no third check is possible: the service "has
/// no way of knowing if the hash value really corresponds to the signed data". A caller that does hold the signed
/// data is not making a hash-only submission.
/// </para>
/// <para>
/// <strong>Every entry point is pure over its inputs</strong> — no clock, no ambient state, nothing opened.
/// </para>
/// </remarks>
public static class PreservationHashOnlySubmissions
{
    /// <summary>
    /// States the hash functions a profile accepts for hash-only submission.
    /// </summary>
    /// <param name="profile">The profile to read.</param>
    /// <returns>The accepted hash functions, in the order the profile lists them and without repetition; empty when the profile allows no hash-only submission.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="profile"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// Only the submission operation is read, because that is the operation whose input a hash stands in for. An
    /// input format that is not an object-identifier uniform resource name, and one naming an algorithm this
    /// library cannot compute, are both simply not accepted hash functions — a submission under either could not
    /// have its length checked, which is what <c>OVR-9.3-08</c> obliges.
    /// </remarks>
    public static IReadOnlyList<PkiDigestAlgorithm> AcceptedHashFunctions(PreservationProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        List<PkiDigestAlgorithm> accepted = [];
        for(int i = 0; i < profile.Operations.Count; ++i)
        {
            PreservationOperationDescriptor operation = profile.Operations[i];
            if(!string.Equals(operation.Name, PreservationWellKnown.PreservePreservationObjectOperation, StringComparison.Ordinal))
            {
                continue;
            }

            for(int j = 0; j < operation.InputFormats.Count; ++j)
            {
                if(PreservationDigestMethod.TryResolve(operation.InputFormats[j].FormatId, out PkiDigestAlgorithm algorithm)
                    && !accepted.Contains(algorithm))
                {
                    accepted.Add(algorithm);
                }
            }
        }

        return accepted;
    }


    /// <summary>
    /// Makes the two checks <c>OVR-9.3-08</c> obliges a preservation service to make on a hash-only submission,
    /// and states the per-part goal treatment <c>OVR-9.3-07</c> forces on an accepted one.
    /// </summary>
    /// <param name="context">The submission and the profile it was made under.</param>
    /// <returns>The report.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is <see langword="null"/>.</exception>
    public static PreservationHashOnlySubmissionReport StateAcceptance(PreservationHashOnlySubmissionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        IReadOnlyList<PkiDigestAlgorithm> accepted = AcceptedHashFunctions(context.Profile);

        if(!StatesDigitalSignatureGoal(context.Profile))
        {
            return Refused(
                PreservationHashOnlySubmissionStatus.ProfileDoesNotPreserveDigitalSignatures,
                accepted,
                "OVR-9.3-05 to OVR-9.3-08 are tagged for the preservation of digital signatures and this profile announces no such goal.");
        }

        if(accepted.Count == 0)
        {
            return Refused(
                PreservationHashOnlySubmissionStatus.ProfileStatesNoAcceptedHashFunction,
                accepted,
                "OVR-9.3-06: the profile lists no accepted hash function, so it does not allow a hash of the signed data to be submitted in its place.");
        }

        if(!PreservationDigestMethod.TryResolve(context.Submission.HashFunctionIdentifier, out PkiDigestAlgorithm submitted))
        {
            return Refused(
                PreservationHashOnlySubmissionStatus.HashFunctionNotResolvable,
                accepted,
                string.Create(CultureInfo.InvariantCulture, $"'{context.Submission.HashFunctionIdentifier}' does not name a hash function this library computes."));
        }

        if(!Contains(accepted, submitted))
        {
            return Refused(
                PreservationHashOnlySubmissionStatus.HashFunctionNotAcceptedByProfile,
                accepted,
                string.Create(CultureInfo.InvariantCulture, $"OVR-9.3-08: the profile does not list hash function '{submitted.Identifier.Oid}'."),
                submitted);
        }

        if(context.Submission.SignedDataHashes.Count == 0)
        {
            return Refused(
                PreservationHashOnlySubmissionStatus.NoHashValueStated,
                accepted,
                "The submission states no hash value, so nothing stands in for the signed data.",
                submitted);
        }

        for(int i = 0; i < context.Submission.SignedDataHashes.Count; ++i)
        {
            int length = context.Submission.SignedDataHashes[i].Length;
            if(length != submitted.OutputByteLength)
            {
                return Refused(
                    PreservationHashOnlySubmissionStatus.HashValueLengthMismatch,
                    accepted,
                    string.Create(CultureInfo.InvariantCulture, $"OVR-9.3-08: hash value {i} is {length} octets where '{submitted.Identifier.Oid}' produces {submitted.OutputByteLength}."),
                    submitted,
                    i);
            }
        }

        List<PreservationGoalTreatment> treatments =
        [
            new PreservationGoalTreatment(
                PreservationSubmissionPart.DetachedSignature,
                0,
                PreservationWellKnown.DigitalSignatureGoal,
                "OVR-9.3-03")
        ];

        for(int i = 0; i < context.Submission.SignedDataHashes.Count; ++i)
        {
            treatments.Add(new PreservationGoalTreatment(
                PreservationSubmissionPart.SubmittedHashValue,
                i,
                PreservationWellKnown.GeneralDataGoal,
                "OVR-9.3-07"));
        }

        return new PreservationHashOnlySubmissionReport
        {
            Status = PreservationHashOnlySubmissionStatus.Accepted,
            AcceptedHashFunctions = accepted,
            GoalTreatments = treatments,
            HashFunction = submitted
        };


        //States a refusal, which is the same five fields every time and carries no goal treatment at all.
        static PreservationHashOnlySubmissionReport Refused(
            PreservationHashOnlySubmissionStatus status,
            IReadOnlyList<PkiDigestAlgorithm> accepted,
            string reason,
            PkiDigestAlgorithm? hashFunction = null,
            int? offendingIndex = null) =>
            new()
            {
                Status = status,
                AcceptedHashFunctions = accepted,
                GoalTreatments = [],
                HashFunction = hashFunction,
                OffendingHashValueIndex = offendingIndex,
                Reason = reason
            };


        //Determines whether a profile announces the preservation of digital signatures, which is what the
        //[PDS]/[PDS+PGD] tags of these requirements select on.
        static bool StatesDigitalSignatureGoal(PreservationProfile profile)
        {
            for(int i = 0; i < profile.PreservationGoals.Count; ++i)
            {
                if(string.Equals(profile.PreservationGoals[i], PreservationWellKnown.DigitalSignatureGoal, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }


        //Determines whether a resolved algorithm is one of the accepted ones, comparing the identity rather than
        //the whole value so that a table row and a submission agree on the algorithm and nothing else.
        static bool Contains(IReadOnlyList<PkiDigestAlgorithm> accepted, PkiDigestAlgorithm algorithm)
        {
            for(int i = 0; i < accepted.Count; ++i)
            {
                if(accepted[i].Identifier.Equals(algorithm.Identifier))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
