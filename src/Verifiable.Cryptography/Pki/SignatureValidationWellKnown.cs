using System;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The wire values
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1 clause 4.3</see> assigns to the status vocabulary of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see>: the main status indication URIs of clause 4.3.4.2, the
/// sub-indication URI namespace of clause 4.3.4.3, and the validation process URIs of clause 4.3.11.1.
/// </summary>
/// <remarks>
/// <para>
/// Clause 4.3.4.2 assigns two different URI sets to the same <c>MainIndication</c> element depending on where
/// it appears: the <c>total-*</c> set in the validation report of a signature, and the <c>passed</c> /
/// <c>failed</c> set in an individual validation constraint report element or in the validation report of a
/// signature validation object. That is why <see cref="SignatureValidationIndication"/> and
/// <see cref="BuildingBlockIndication"/> are separate types with separate mappings.
/// </para>
/// <para>
/// Sub-indication URIs are built by prefixing <see cref="SubIndicationPrefix"/> to the specification's own
/// token, which is what Table 2 of clause 4.3.4.3 tabulates for every value. Two sub-indications EN 319 102-1
/// V1.4.1 defines — <c>NO_CERTIFICATE_CHAIN_FOUND_NO_POE</c> and <c>OUT_OF_BOUNDS_NOT_REVOKED</c> — have no row
/// in that table, which predates them; the same prefixing rule yields their URIs, and reporting them is
/// preferable to reporting nothing for a sub-indication the validation algorithm mandates.
/// </para>
/// </remarks>
public static class SignatureValidationWellKnown
{
    /// <summary>The URI representing <c>TOTAL-PASSED</c> in the validation report of a signature (clause 4.3.4.2).</summary>
    public static string MainIndicationTotalPassed { get; } = "urn:etsi:019102:mainindication:total-passed";

    /// <summary>The URI representing <c>TOTAL-FAILED</c> in the validation report of a signature (clause 4.3.4.2).</summary>
    public static string MainIndicationTotalFailed { get; } = "urn:etsi:019102:mainindication:total-failed";

    /// <summary>The URI representing <c>INDETERMINATE</c>, which clause 4.3.4.2 assigns to both contexts.</summary>
    public static string MainIndicationIndeterminate { get; } = "urn:etsi:019102:mainindication:indeterminate";

    /// <summary>The URI representing <c>PASSED</c> in an individual validation constraint report element or in the validation report of a signature validation object (clause 4.3.4.2).</summary>
    public static string MainIndicationPassed { get; } = "urn:etsi:019102:mainindication:passed";

    /// <summary>The URI representing <c>FAILED</c> in an individual validation constraint report element or in the validation report of a signature validation object (clause 4.3.4.2).</summary>
    public static string MainIndicationFailed { get; } = "urn:etsi:019102:mainindication:failed";

    /// <summary>The namespace every sub-indication URI of Table 2 of clause 4.3.4.3 is built on, to which the sub-indication's own token is appended.</summary>
    public static string SubIndicationPrefix { get; } = "urn:etsi:019102:subindication:";

    /// <summary>The URI for the validation process for Basic Signatures of EN 319 102-1 clause 5.3 (clause 4.3.11.1).</summary>
    public static string ValidationProcessBasic { get; } = "urn:etsi:019102:validationprocess:Basic";

    /// <summary>The URI for the validation process for Signatures with Time and Signatures with Long-Term Validation Material of EN 319 102-1 clause 5.5 (clause 4.3.11.1).</summary>
    public static string ValidationProcessLongTermValidationMaterial { get; } = "urn:etsi:019102:validationprocess:LTVM";

    /// <summary>The URI for the validation process for Signatures providing Long Term Availability and Integrity of Validation Material of EN 319 102-1 clause 5.6 (clause 4.3.11.1).</summary>
    public static string ValidationProcessLongTermAvailability { get; } = "urn:etsi:019102:validationprocess:LTA";


    /// <summary>
    /// Determines whether a value is one of the three main status indication URIs a validation report of a
    /// signature uses.
    /// </summary>
    /// <param name="value">The value to test.</param>
    /// <returns><see langword="true"/> when it is one of them.</returns>
    public static bool IsProcessMainIndication(string value) =>
        string.Equals(value, MainIndicationTotalPassed, StringComparison.Ordinal)
        || string.Equals(value, MainIndicationTotalFailed, StringComparison.Ordinal)
        || string.Equals(value, MainIndicationIndeterminate, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a value is one of the three main status indication URIs an individual validation
    /// constraint report element or the validation report of a signature validation object uses.
    /// </summary>
    /// <param name="value">The value to test.</param>
    /// <returns><see langword="true"/> when it is one of them.</returns>
    public static bool IsBuildingBlockMainIndication(string value) =>
        string.Equals(value, MainIndicationPassed, StringComparison.Ordinal)
        || string.Equals(value, MainIndicationFailed, StringComparison.Ordinal)
        || string.Equals(value, MainIndicationIndeterminate, StringComparison.Ordinal);


    /// <summary>Determines whether a value is a main status indication URI of either context.</summary>
    /// <param name="value">The value to test.</param>
    /// <returns><see langword="true"/> when it is one of the five URIs clause 4.3.4.2 assigns.</returns>
    public static bool IsMainIndication(string value) =>
        IsProcessMainIndication(value) || IsBuildingBlockMainIndication(value);


    /// <summary>
    /// Determines whether a value is a sub-indication URI — one built on <see cref="SubIndicationPrefix"/>
    /// with a non-empty token after it.
    /// </summary>
    /// <param name="value">The value to test.</param>
    /// <returns><see langword="true"/> when it is a sub-indication URI.</returns>
    public static bool IsSubIndication(string value) =>
        value is not null
        && value.StartsWith(SubIndicationPrefix, StringComparison.Ordinal)
        && value.Length > SubIndicationPrefix.Length;


    /// <summary>Determines whether a value is one of the three validation process URIs clause 4.3.11.1 names.</summary>
    /// <param name="value">The value to test.</param>
    /// <returns><see langword="true"/> when it is one of them. Clause 4.3.11.1 also admits "any other URI indicating the validation process when none of these processes has been applied", so a <see langword="false"/> result does not make a value invalid.</returns>
    public static bool IsSpecifiedValidationProcess(string value) =>
        string.Equals(value, ValidationProcessBasic, StringComparison.Ordinal)
        || string.Equals(value, ValidationProcessLongTermValidationMaterial, StringComparison.Ordinal)
        || string.Equals(value, ValidationProcessLongTermAvailability, StringComparison.Ordinal);
}


/// <summary>
/// Maps <see cref="SignatureValidationIndication"/> to the main status indication URI a validation report of a
/// signature carries, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1 clause 4.3.4.2</see>.
/// </summary>
public static class SignatureValidationIndicationMapping
{
    /// <summary>Maps a <see cref="SignatureValidationIndication"/> to its URI.</summary>
    /// <param name="indication">The indication to map.</param>
    /// <returns>The URI. An unrecognized value maps to the <c>INDETERMINATE</c> URI, never to a passing one.</returns>
    public static string ToWireValue(SignatureValidationIndication indication) => indication switch
    {
        SignatureValidationIndication.TotalPassed => SignatureValidationWellKnown.MainIndicationTotalPassed,
        SignatureValidationIndication.TotalFailed => SignatureValidationWellKnown.MainIndicationTotalFailed,
        SignatureValidationIndication.Indeterminate => SignatureValidationWellKnown.MainIndicationIndeterminate,
        _ => SignatureValidationWellKnown.MainIndicationIndeterminate
    };
}


/// <summary>
/// Maps <see cref="BuildingBlockIndication"/> to the main status indication URI an individual validation
/// constraint report element or the validation report of a signature validation object carries, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1 clause 4.3.4.2</see>, and to the process-level indication of Table 5 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see>.
/// </summary>
public static class BuildingBlockIndicationMapping
{
    /// <summary>Maps a <see cref="BuildingBlockIndication"/> to its URI.</summary>
    /// <param name="indication">The indication to map.</param>
    /// <returns>The URI. An unrecognized value maps to the <c>INDETERMINATE</c> URI, never to a passing one.</returns>
    public static string ToWireValue(BuildingBlockIndication indication) => indication switch
    {
        BuildingBlockIndication.Passed => SignatureValidationWellKnown.MainIndicationPassed,
        BuildingBlockIndication.Failed => SignatureValidationWellKnown.MainIndicationFailed,
        BuildingBlockIndication.Indeterminate => SignatureValidationWellKnown.MainIndicationIndeterminate,
        _ => SignatureValidationWellKnown.MainIndicationIndeterminate
    };


    /// <summary>
    /// Promotes a building block's indication to the process-level indication clause 5.1.3 requires the
    /// overall result to be: "when the validation process selected as in clause 5.1.2 returns <c>PASSED</c>
    /// ... the overall result of the validation shall be <c>TOTAL-PASSED</c>", and likewise <c>FAILED</c> to
    /// <c>TOTAL-FAILED</c> and <c>INDETERMINATE</c> to <c>INDETERMINATE</c>.
    /// </summary>
    /// <param name="indication">The indication the selected validation process returned.</param>
    /// <returns>The overall result. An unrecognized value maps to <see cref="SignatureValidationIndication.Indeterminate"/>, never to a passing one.</returns>
    public static SignatureValidationIndication ToProcessIndication(BuildingBlockIndication indication) => indication switch
    {
        BuildingBlockIndication.Passed => SignatureValidationIndication.TotalPassed,
        BuildingBlockIndication.Failed => SignatureValidationIndication.TotalFailed,
        BuildingBlockIndication.Indeterminate => SignatureValidationIndication.Indeterminate,
        _ => SignatureValidationIndication.Indeterminate
    };
}


/// <summary>
/// Maps <see cref="SignatureValidationSubIndication"/> to the sub-indication URI of Table 2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1 clause 4.3.4.3</see>.
/// </summary>
/// <remarks>
/// Every row of Table 2 is the sub-indication's own token appended to
/// <see cref="SignatureValidationWellKnown.SubIndicationPrefix"/>, so the mapping is that concatenation rather
/// than a per-value table. Building it that way also gives the two sub-indications EN 319 102-1 V1.4.1 adds
/// after Table 2 was written a URI, and gives one to a caller-minted custom sub-indication.
/// </remarks>
public static class SignatureValidationSubIndicationMapping
{
    /// <summary>Maps a <see cref="SignatureValidationSubIndication"/> to its URI.</summary>
    /// <param name="subIndication">The sub-indication to map.</param>
    /// <returns>The URI.</returns>
    public static string ToWireValue(SignatureValidationSubIndication subIndication) =>
        string.Concat(SignatureValidationWellKnown.SubIndicationPrefix, subIndication.Value);


    /// <summary>
    /// Reads a sub-indication back from its URI, for a caller consuming a validation report someone else
    /// produced.
    /// </summary>
    /// <param name="value">The URI to read.</param>
    /// <param name="subIndication">The sub-indication when this method returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when the value is a sub-indication URI with a non-empty token.</returns>
    public static bool TryFromWireValue(string value, out SignatureValidationSubIndication subIndication)
    {
        if(SignatureValidationWellKnown.IsSubIndication(value))
        {
            subIndication = new SignatureValidationSubIndication(value[SignatureValidationWellKnown.SubIndicationPrefix.Length..]);

            return true;
        }

        subIndication = default;

        return false;
    }
}
