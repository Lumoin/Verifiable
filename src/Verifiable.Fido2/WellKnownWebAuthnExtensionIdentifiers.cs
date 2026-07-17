using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// WebAuthn extension identifiers — the member names under <c>clientExtensionResults</c> /
/// <c>extensions</c> that select which extension a value belongs to.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extension-id">W3C Web Authentication Level 3,
/// section 9.1: Extension Identifiers</see>: "Implementations MUST match WebAuthn extension
/// identifiers in a case-sensitive fashion" — the reason every comparer here is ordinal, mirroring
/// <see cref="WellKnownClientDataTypes"/>. A single shared source for these identifier strings keeps
/// a registration call site (<see cref="Fido2ExtensionSelectors.FromIdentifiers"/>) and an eventual
/// options-request writer's member name from drifting into two independent magic-string literals.
/// This type serves BOTH the WebAuthn client-input layer (<c>AuthenticationExtensionsClientInputs</c>/
/// <c>Results</c> member names) and the CTAP <c>authenticatorGetInfo</c>/<c>authenticatorMakeCredential</c>
/// wire layer: CTAP section 14.1 registers its own extensions into this SAME WebAuthn extension-identifier
/// registry, and <see cref="CredProtect"/>/<see cref="MinPinLength"/> are spelled identically across the
/// WebAuthn client-input member, the CTAP getInfo <c>extensions</c> array entry, and the
/// <c>authenticatorMakeCredential</c>/authData <c>extensions</c> CBOR map key — one shared source for
/// every layer that needs the wire string, rather than a second, CTAP-only vocabulary type duplicating
/// the same literals.
/// </remarks>
public static class WellKnownWebAuthnExtensionIdentifiers
{
    /// <summary>The UTF-8 source literal of <see cref="AppId"/>.</summary>
    public static ReadOnlySpan<byte> AppIdUtf8 => "appid"u8;

    /// <summary>
    /// The <c>appid</c> identifier.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-extension">W3C Web Authentication
    /// Level 3, section 10.1.1: FIDO AppID Extension (appid)</see>. This extension bypasses the
    /// <see cref="Fido2ExtensionSelectors"/> registry entirely — it changes which hash
    /// <see cref="Fido2AssertionChecks.CheckAssertionRpIdHash"/> compares against rather than adding
    /// an independent processor — so this getter exists for a caller decoding the wire identifier or
    /// an options writer emitting it, not for a registry registration.
    /// </remarks>
    public static readonly string AppId = Utf8Constants.ToInternedString(AppIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AppIdExclude"/>.</summary>
    public static ReadOnlySpan<byte> AppIdExcludeUtf8 => "appidExclude"u8;

    /// <summary>
    /// The <c>appidExclude</c> identifier.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension">W3C Web
    /// Authentication Level 3, section 10.1.2: FIDO AppID Exclusion Extension (appidExclude)</see>.
    /// </remarks>
    public static readonly string AppIdExclude = Utf8Constants.ToInternedString(AppIdExcludeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LargeBlob"/>.</summary>
    public static ReadOnlySpan<byte> LargeBlobUtf8 => "largeBlob"u8;

    /// <summary>
    /// The <c>largeBlob</c> identifier.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web
    /// Authentication Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see>.
    /// </remarks>
    public static readonly string LargeBlob = Utf8Constants.ToInternedString(LargeBlobUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LargeBlobKey"/>.</summary>
    public static ReadOnlySpan<byte> LargeBlobKeyUtf8 => "largeBlobKey"u8;

    /// <summary>
    /// The <c>largeBlobKey</c> identifier.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-large-blob-key-extension">
    /// CTAP 2.3, section 12.3: Large Blob Key (largeBlobKey)</see>. Distinct from <see cref="LargeBlob"/>
    /// (the UNRELATED §10.1.5 WebAuthn client extension) and from <c>authenticatorLargeBlobs</c> (the
    /// <c>0x0C</c> command byte itself) — three separate identifiers sharing a name family, trap 11.
    /// This CTAP-registered authenticator extension's feature detection requires BOTH this identifier's
    /// presence in <c>authenticatorGetInfo</c>'s <c>extensions</c> array AND <c>largeBlobs</c> mapped to
    /// <see langword="true"/> in <c>options</c> (lines 12832-12834) — the two ship together.
    /// </remarks>
    public static readonly string LargeBlobKey = Utf8Constants.ToInternedString(LargeBlobKeyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredProtect"/>.</summary>
    public static ReadOnlySpan<byte> CredProtectUtf8 => "credProtect"u8;

    /// <summary>
    /// The <c>credProtect</c> identifier.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credProtect-extension">
    /// CTAP 2.3, section 12.1: Credential Protection (credProtect)</see>. This spelling serves the
    /// WebAuthn client-input extension key, the CTAP <c>authenticatorGetInfo</c> <c>extensions</c>
    /// array entry, and the <c>authenticatorMakeCredential</c>/authData <c>extensions</c> CBOR map key
    /// alike — one shared string across all three, spelled identically in all nine of its sitewide
    /// occurrences in the CTAP 2.3 snapshot (unlike <see cref="MinPinLength"/>, it carries no
    /// editorial-casing inconsistency to reconcile).
    /// </remarks>
    public static readonly string CredProtect = Utf8Constants.ToInternedString(CredProtectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MinPinLength"/>.</summary>
    public static ReadOnlySpan<byte> MinPinLengthUtf8 => "minPinLength"u8;

    /// <summary>
    /// The <c>minPinLength</c> identifier.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-minpinlength-extension">
    /// CTAP 2.3, section 12.5: Minimum PIN Length Extension (minPinLength)</see>. The canonical
    /// mixed-case spelling: section 12.5's own "Extension identifier" definition (snapshot line 12958),
    /// the <c>authenticatorMakeCredential</c> extensions-map input example (<c>"minPinLength": true</c>,
    /// line 12994), the authData output CDDL (<c>"minPinLength": uint</c>, line 13011), and the WebAuthn
    /// client-input IDL member (line 12976) are all mixed-case — this is the wire string used
    /// EVERYWHERE, including the <c>authenticatorGetInfo</c> <c>extensions</c> array. Two of the spec's
    /// own conditional MUSTs that gate on this identifier's presence in that array (section 7.4.3 line
    /// 8414; section 9 item 6, line 9086) spell it <c>minpinlength</c> (all-lowercase) in their own
    /// prose, but both are hyperlinks to section 12.5 itself — an internal editorial-case artifact, not
    /// a distinct identifier. Emitting the lowercase spelling into the getInfo array while the mc/authData
    /// wire key stays mixed-case would desynchronize advertisement from the identifier actually on the
    /// wire, a real interop break, not a cosmetic one.
    /// </remarks>
    public static readonly string MinPinLength = Utf8Constants.ToInternedString(MinPinLengthUtf8);

    /// <summary>The UTF-8 source literal of <see cref="HmacSecret"/>.</summary>
    public static ReadOnlySpan<byte> HmacSecretUtf8 => "hmac-secret"u8;

    /// <summary>
    /// The <c>hmac-secret</c> identifier.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-extension">
    /// CTAP 2.3, section 12.7: HMAC Secret Extension (hmac-secret)</see>, snapshot line 13076. Registered
    /// in the section 14.1 WebAuthn Extension Identifier registry (snapshot lines 13493-13533, the
    /// <c>hmac-secret</c> entry itself at 13527-13533) alongside <see cref="CredProtect"/>/
    /// <see cref="LargeBlobKey"/>/<see cref="MinPinLength"/> — unlike <see cref="HmacSecretMc"/>, which
    /// that same registry omits.
    /// </remarks>
    public static readonly string HmacSecret = Utf8Constants.ToInternedString(HmacSecretUtf8);

    /// <summary>The UTF-8 source literal of <see cref="HmacSecretMc"/>.</summary>
    public static ReadOnlySpan<byte> HmacSecretMcUtf8 => "hmac-secret-mc"u8;

    /// <summary>
    /// The <c>hmac-secret-mc</c> identifier.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-make-cred-extension">
    /// CTAP 2.3, section 12.8: HMAC Secret MakeCredential Extension (hmac-secret-mc)</see>, snapshot line
    /// 13361. NOT a member of the section 14.1 WebAuthn Extension Identifier registry (snapshot lines
    /// 13493-13533 list only <c>credProtect</c>/<c>credBlob</c>/<c>largeBlobKey</c>/<c>minPinLength</c>/
    /// <see cref="HmacSecret"/>) — this identifier carries no registration of its own, matching its
    /// pure-delegation processing (section 12.8, snapshot lines 13391/13402/13408: input/processing/
    /// output are each declared "the same as the hmac secret extension's getAssertion" counterpart).
    /// </remarks>
    public static readonly string HmacSecretMc = Utf8Constants.ToInternedString(HmacSecretMcUtf8);


    /// <summary>
    /// Determines whether <paramref name="identifier"/> is <see cref="AppId"/>.
    /// </summary>
    /// <param name="identifier">The extension identifier to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> equals <see cref="AppId"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsAppId(string identifier) => Equals(AppId, identifier);

    /// <summary>
    /// Determines whether <paramref name="identifier"/> is <see cref="AppIdExclude"/>.
    /// </summary>
    /// <param name="identifier">The extension identifier to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> equals <see cref="AppIdExclude"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsAppIdExclude(string identifier) => Equals(AppIdExclude, identifier);

    /// <summary>
    /// Determines whether <paramref name="identifier"/> is <see cref="LargeBlob"/>.
    /// </summary>
    /// <param name="identifier">The extension identifier to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> equals <see cref="LargeBlob"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsLargeBlob(string identifier) => Equals(LargeBlob, identifier);

    /// <summary>
    /// Determines whether <paramref name="identifier"/> is <see cref="LargeBlobKey"/>.
    /// </summary>
    /// <param name="identifier">The extension identifier to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> equals <see cref="LargeBlobKey"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsLargeBlobKey(string identifier) => Equals(LargeBlobKey, identifier);

    /// <summary>
    /// Determines whether <paramref name="identifier"/> is <see cref="CredProtect"/>.
    /// </summary>
    /// <param name="identifier">The extension identifier to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> equals <see cref="CredProtect"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsCredProtect(string identifier) => Equals(CredProtect, identifier);

    /// <summary>
    /// Determines whether <paramref name="identifier"/> is <see cref="MinPinLength"/>.
    /// </summary>
    /// <param name="identifier">The extension identifier to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> equals <see cref="MinPinLength"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsMinPinLength(string identifier) => Equals(MinPinLength, identifier);

    /// <summary>
    /// Determines whether <paramref name="identifier"/> is <see cref="HmacSecret"/>.
    /// </summary>
    /// <param name="identifier">The extension identifier to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> equals <see cref="HmacSecret"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsHmacSecret(string identifier) => Equals(HmacSecret, identifier);

    /// <summary>
    /// Determines whether <paramref name="identifier"/> is <see cref="HmacSecretMc"/>.
    /// </summary>
    /// <param name="identifier">The extension identifier to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> equals <see cref="HmacSecretMc"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsHmacSecretMc(string identifier) => Equals(HmacSecretMc, identifier);


    /// <summary>
    /// Returns a value that indicates if the extension identifiers are the same.
    /// </summary>
    /// <param name="identifierA">The first identifier to compare.</param>
    /// <param name="identifierB">The second identifier to compare.</param>
    /// <returns>
    /// <see langword="true" /> if <paramref name="identifierA"/> and <paramref name="identifierB"/> are the same; otherwise, <see langword="false" />.
    /// </returns>
    public static bool Equals(string identifierA, string identifierB)
    {
        return object.ReferenceEquals(identifierA, identifierB) || StringComparer.Ordinal.Equals(identifierA, identifierB);
    }
}
