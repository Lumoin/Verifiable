using System;
using Verifiable.Cryptography.Text;

namespace Verifiable.Keri;

/// <summary>
/// The well-known KERI count codes that frame an event's attachment groups — the wire codes an encoder writes,
/// named so encoding code (a signer framing an event's signatures, a test minting a stream) carries no bare
/// strings. Reading a code's meaning off the wire is the classifier <see cref="KeriCountCodeSemantics"/>'s job;
/// the <c>Is…</c> helpers here delegate to it so both the small (<c>-K</c>) and large (<c>--K</c>) forms of a
/// code are recognized.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR master code table, <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// genus/version <c>-_AAACAA</c></see> (KERI/ACDC protocol stack version 2.00). The named values are the
/// canonical small forms; the codes are case-sensitive, so the comparisons here are ordinal.
/// </para>
/// </remarks>
public static class WellKnownKeriCountCodes
{
    /// <summary>The UTF-8 source literal of <see cref="ControllerSignatureGroup"/>.</summary>
    public static ReadOnlySpan<byte> ControllerSignatureGroupUtf8 => "-K"u8;

    /// <summary>
    /// The indexed controller-signature group count code (<c>-K</c>): the group framing a KERI event's controller
    /// signatures, each indexed into the establishment event's current signing-key list (field <c>k</c>).
    /// </summary>
    public static string ControllerSignatureGroup { get; } = Utf8Constants.ToInternedString(ControllerSignatureGroupUtf8);

    /// <summary>The UTF-8 source literal of <see cref="WitnessSignatureGroup"/>.</summary>
    public static ReadOnlySpan<byte> WitnessSignatureGroupUtf8 => "-L"u8;

    /// <summary>
    /// The indexed witness-signature group count code (<c>-L</c>): the group framing a KERI event's witness
    /// signatures, each indexed into the event's witness (backer) list.
    /// </summary>
    public static string WitnessSignatureGroup { get; } = Utf8Constants.ToInternedString(WitnessSignatureGroupUtf8);


    /// <summary>
    /// Whether a count code frames an indexed CONTROLLER signature group (<c>-K</c> or the large form
    /// <c>--K</c>). Delegates to <see cref="KeriCountCodeSemantics.Classify"/> so both forms are recognized.
    /// </summary>
    /// <param name="code">The stable (hard) count code.</param>
    /// <returns><see langword="true"/> when the code frames a controller signature group.</returns>
    public static bool IsControllerSignatureGroup(string code) => KeriCountCodeSemantics.Classify(code) == KeriGroupContent.ControllerSignatures;


    /// <summary>
    /// Whether a count code frames an indexed WITNESS signature group (<c>-L</c> or the large form <c>--L</c>) —
    /// not the controller signature group. A witness signature's index refers to the event's witness (backer)
    /// list rather than its signing-key list. Delegates to <see cref="KeriCountCodeSemantics.Classify"/>.
    /// </summary>
    /// <param name="code">The stable (hard) count code.</param>
    /// <returns><see langword="true"/> when the code frames a witness signature group.</returns>
    public static bool IsWitnessSignatureGroup(string code) => KeriCountCodeSemantics.Classify(code) == KeriGroupContent.WitnessSignatures;


    /// <summary>
    /// Returns the equivalent interned instance for the given code, or the original instance if none match. This
    /// conversion is optional but allows reference-equality comparisons elsewhere.
    /// </summary>
    /// <param name="code">The code to canonicalize.</param>
    /// <returns>The equivalent interned instance of <paramref name="code"/>, or the original instance if none match.</returns>
    public static string GetCanonicalizedValue(string code) => code switch
    {
        string _ when Equals(code, ControllerSignatureGroup) => ControllerSignatureGroup,
        string _ when Equals(code, WitnessSignatureGroup) => WitnessSignatureGroup,
        string _ => code
    };


    /// <summary>
    /// Returns a value that indicates whether the two codes are the same, comparing ordinally (CESR codes are
    /// case-sensitive Base64URL).
    /// </summary>
    /// <param name="codeA">The first code to compare.</param>
    /// <param name="codeB">The second code to compare.</param>
    /// <returns><see langword="true"/> if the codes are the same; otherwise, <see langword="false"/>.</returns>
    public static bool Equals(string codeA, string codeB)
    {
        return ReferenceEquals(codeA, codeB) || StringComparer.Ordinal.Equals(codeA, codeB);
    }
}
