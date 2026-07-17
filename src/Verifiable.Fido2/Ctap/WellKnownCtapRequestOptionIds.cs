using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Option IDs of the <c>options</c> parameter shared by <c>authenticatorMakeCredential</c> and
/// <c>authenticatorGetAssertion</c> requests.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential</see> defines <see cref="Rk"/>, <see cref="Up"/>,
/// and <see cref="Uv"/> for its <c>options</c> parameter (<c>0x07</c>);
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// section 6.2: authenticatorGetAssertion</see> defines <see cref="Up"/> and <see cref="Uv"/> for its own
/// <c>options</c> parameter (<c>0x05</c>) and states "Platforms MUST NOT send the 'rk' option key" — the
/// <see cref="Rk"/> identifier is still registered here (not split into a separate class) because a
/// conformant reader must recognize the string to detect and reject its presence per that rule, and
/// because both commands' option maps share the identical wire vocabulary. This is distinct from
/// <see cref="WellKnownCtapGetInfoOptionIds"/>, which names the unrelated <c>rk</c>/<c>plat</c> option
/// IDs of the <c>authenticatorGetInfo</c> response's <c>options</c> member.
/// </para>
/// </remarks>
public static class WellKnownCtapRequestOptionIds
{
    /// <summary>The UTF-8 source literal of <see cref="Rk"/>.</summary>
    public static ReadOnlySpan<byte> RkUtf8 => "rk"u8;

    /// <summary>
    /// <c>rk</c>: whether the credential being created is to be discoverable. Legal only on
    /// <c>authenticatorMakeCredential</c>; default <see langword="false"/> when absent.
    /// </summary>
    public static readonly string Rk = Utf8Constants.ToInternedString(RkUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Up"/>.</summary>
    public static ReadOnlySpan<byte> UpUtf8 => "up"u8;

    /// <summary>
    /// <c>up</c>: user presence — whether the authenticator must obtain evidence of user
    /// interaction. Default <see langword="true"/> when absent.
    /// </summary>
    public static readonly string Up = Utf8Constants.ToInternedString(UpUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Uv"/>.</summary>
    public static ReadOnlySpan<byte> UvUtf8 => "uv"u8;

    /// <summary>
    /// <c>uv</c>: user verification — whether the authenticator must perform a user-verifying
    /// gesture. Default <see langword="false"/> when absent.
    /// </summary>
    public static readonly string Uv = Utf8Constants.ToInternedString(UvUtf8);


    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="Rk"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>rk</c>.</returns>
    public static bool IsRk(string optionId) => Equals(Rk, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="Up"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>up</c>.</returns>
    public static bool IsUp(string optionId) => Equals(Up, optionId);

    /// <summary>
    /// Gets a value indicating whether <paramref name="optionId"/> is <see cref="Uv"/>.
    /// </summary>
    /// <param name="optionId">The option ID string to check.</param>
    /// <returns><see langword="true"/> if <paramref name="optionId"/> is <c>uv</c>.</returns>
    public static bool IsUv(string optionId) => Equals(Uv, optionId);


    /// <summary>
    /// Returns a value that indicates if the option IDs are the same.
    /// </summary>
    /// <param name="optionIdA">The first option ID to compare.</param>
    /// <param name="optionIdB">The second option ID to compare.</param>
    /// <returns>
    /// <see langword="true" /> if <paramref name="optionIdA"/> and <paramref name="optionIdB"/> are the same; otherwise, <see langword="false" />.
    /// </returns>
    public static bool Equals(string optionIdA, string optionIdB)
    {
        return object.ReferenceEquals(optionIdA, optionIdB) || StringComparer.Ordinal.Equals(optionIdA, optionIdB);
    }
}
