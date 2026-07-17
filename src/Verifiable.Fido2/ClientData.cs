using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// Parsed view of <c>CollectedClientData</c>, the client-produced record of the parameters
/// of a WebAuthn registration or authentication ceremony.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3, section 5.8.1: Client Data Used in WebAuthn Signatures.</see>
/// </para>
/// <para>
/// This carrier is format-agnostic — the concrete JSON codec is supplied at the composition
/// edge through <see cref="ParseClientDataDelegate"/> and fills it from the on-wire
/// <c>clientDataJSON</c> bytes.
/// </para>
/// </remarks>
[DebuggerDisplay("ClientData(Type={Type,nq}, Origin={Origin,nq})")]
public sealed class ClientData
{
    /// <summary>
    /// Initializes a <see cref="ClientData"/> view from its parsed members.
    /// </summary>
    /// <param name="type">The ceremony type, per <see cref="Type"/>.</param>
    /// <param name="challenge">The base64url-encoded challenge, per <see cref="Challenge"/>.</param>
    /// <param name="origin">The relying party origin, per <see cref="Origin"/>.</param>
    /// <param name="crossOrigin">The optional cross-origin indicator, per <see cref="CrossOrigin"/>.</param>
    /// <param name="topOrigin">The optional top-level origin, per <see cref="TopOrigin"/>.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="type"/>, <paramref name="challenge"/> or <paramref name="origin"/> is <see langword="null"/>.
    /// </exception>
    public ClientData(string type, string challenge, string origin, bool? crossOrigin = null, string? topOrigin = null)
    {
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(origin);

        Type = type;
        Challenge = challenge;
        Origin = origin;
        CrossOrigin = crossOrigin;
        TopOrigin = topOrigin;
    }


    /// <summary>
    /// The ceremony type, either <see cref="WellKnownClientDataTypes.Create"/> or
    /// <see cref="WellKnownClientDataTypes.Get"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3, section 5.8.1: Client Data Used in WebAuthn Signatures.</see>
    /// </remarks>
    public string Type { get; }

    /// <summary>
    /// The base64url-encoded challenge exactly as received, with no re-encoding applied.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3, section 5.8.1: Client Data Used in WebAuthn Signatures.</see>
    /// </remarks>
    public string Challenge { get; }

    /// <summary>
    /// The serialized origin of the caller in which the ceremony occurred.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3, section 5.8.1: Client Data Used in WebAuthn Signatures.</see>
    /// </remarks>
    public string Origin { get; }

    /// <summary>
    /// Indicates whether the ceremony was performed from a cross-origin embedded context.
    /// <see langword="null"/> when the client omitted the member.
    /// </summary>
    /// <remarks>
    /// Feeds
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3, section 7.1: Registering a New Credential</see>, steps 10-11, and
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, steps 13-14.
    /// </remarks>
    public bool? CrossOrigin { get; }

    /// <summary>
    /// The serialized origin of the top-level browsing context, present only when the
    /// ceremony was cross-origin. <see langword="null"/> when the client omitted the member.
    /// </summary>
    /// <remarks>
    /// Feeds
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3, section 7.1: Registering a New Credential</see>, steps 10-11, and
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication Level 3, section 7.2: Verifying an Authentication Assertion</see>, steps 13-14.
    /// </remarks>
    public string? TopOrigin { get; }
}


/// <summary>
/// Parses the JSON-encoded <c>clientDataJSON</c> wire bytes into a <see cref="ClientData"/> view.
/// </summary>
/// <param name="clientDataJson">The UTF-8 JSON-encoded <c>clientDataJSON</c> bytes.</param>
/// <returns>The parsed <see cref="ClientData"/>.</returns>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3, section 5.8.1: Client Data Used in WebAuthn Signatures.</see>
/// </para>
/// <para>
/// The concrete JSON codec is supplied at the composition edge, keeping this library
/// serialization-agnostic.
/// </para>
/// </remarks>
public delegate ClientData ParseClientDataDelegate(ReadOnlyMemory<byte> clientDataJson);
