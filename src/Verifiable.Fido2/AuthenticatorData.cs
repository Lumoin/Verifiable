using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Fido2;

/// <summary>
/// Parsed view of the <c>authData</c> structure — the authenticator's assertion of the
/// state of an authentication event.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
/// The wire layout is <c>rpIdHash</c> (32 bytes) | <c>flags</c> (1 byte) |
/// <c>signCount</c> (4 bytes, big-endian) | [<c>attestedCredentialData</c>] | [<c>extensions</c>].
/// </para>
/// <para>
/// <strong>Lifetime.</strong> <see cref="RpIdHash"/> is a pooled carrier this instance owns —
/// <see cref="AuthenticatorDataReader.Read"/> copies the wire <c>rpIdHash</c> bytes into it, so it
/// remains valid after the source buffer is reused or discarded. <see cref="Extensions"/> remains a
/// slice over the buffer supplied to <see cref="AuthenticatorDataReader.Read"/> — no copy is made —
/// and is valid only for as long as the caller keeps that buffer alive and unmodified. When present,
/// <see cref="AttestedCredentialData"/> is owned transitively: disposing this instance disposes it,
/// which in turn disposes its own <see cref="Fido2.AttestedCredentialData.CredentialId"/>.
/// </para>
/// <para>
/// <strong>Equality.</strong> Two instances are equal when <see cref="RpIdHash"/>,
/// <see cref="Flags"/>, <see cref="SignCount"/>, <see cref="AttestedCredentialData"/> (null-aware),
/// and <see cref="Extensions"/> all compare equal — content equality over every parsed member,
/// matching how <see cref="Fido2.AttestedCredentialData"/> and <see cref="Cryptography.DigestValue"/>
/// (via <see cref="RpIdHash"/>) already compare.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthenticatorData(Flags={Flags}, SignCount={SignCount}, AttestedCredentialData={AttestedCredentialData is not null})")]
public sealed class AuthenticatorData: IDisposable, IEquatable<AuthenticatorData>
{
    /// <summary>Guards against redundant disposal.</summary>
    private bool disposed;


    /// <summary>
    /// Initializes an <see cref="AuthenticatorData"/> view from its parsed members. Ownership of
    /// <paramref name="rpIdHash"/> and <paramref name="attestedCredentialData"/> transfers to the
    /// new instance; disposing it disposes both.
    /// </summary>
    /// <param name="rpIdHash">The relying party ID hash, per <see cref="RpIdHash"/>.</param>
    /// <param name="flags">The flags byte, per <see cref="Flags"/>.</param>
    /// <param name="signCount">The signature counter, per <see cref="SignCount"/>.</param>
    /// <param name="attestedCredentialData">The optional attested credential data, per <see cref="AttestedCredentialData"/>.</param>
    /// <param name="extensions">The raw extension outputs, per <see cref="Extensions"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rpIdHash"/> is <see langword="null"/>.</exception>
    public AuthenticatorData(
        DigestValue rpIdHash,
        AuthenticatorDataFlags flags,
        uint signCount,
        AttestedCredentialData? attestedCredentialData,
        ReadOnlyMemory<byte> extensions)
    {
        ArgumentNullException.ThrowIfNull(rpIdHash);

        RpIdHash = rpIdHash;
        Flags = flags;
        SignCount = signCount;
        AttestedCredentialData = attestedCredentialData;
        Extensions = extensions;
    }


    /// <summary>
    /// The SHA-256 hash of the relying party ID, owned by this instance (see the type-level
    /// remarks on lifetime).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public DigestValue RpIdHash { get; }

    /// <summary>
    /// The flags byte, giving the user presence/verification and structure-presence bits.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public AuthenticatorDataFlags Flags { get; }

    /// <summary>
    /// The signature counter, incremented by the authenticator on each use.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public uint SignCount { get; }

    /// <summary>
    /// The attested credential data, present when <see cref="AuthenticatorDataFlags.AttestedCredentialDataIncluded"/>
    /// was set; otherwise <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication Level 3, section 6.5.1: Attested Credential Data.</see>
    /// </remarks>
    public AttestedCredentialData? AttestedCredentialData { get; }

    /// <summary>
    /// The raw CBOR-encoded extension outputs map, a slice over the buffer supplied to
    /// <see cref="AuthenticatorDataReader.Read"/> (see the type-level remarks on lifetime).
    /// Empty when <see cref="AuthenticatorDataFlags.ExtensionDataIncluded"/> is clear.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public ReadOnlyMemory<byte> Extensions { get; }


    /// <summary>
    /// Determines whether this instance and <paramref name="other"/> parsed to the same content:
    /// equal <see cref="RpIdHash"/>, <see cref="Flags"/>, <see cref="SignCount"/>,
    /// <see cref="AttestedCredentialData"/> (null-aware), and <see cref="Extensions"/> bytes.
    /// </summary>
    /// <param name="other">The other instance to compare against.</param>
    /// <returns><see langword="true"/> when every member matches; otherwise <see langword="false"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] AuthenticatorData? other)
    {
        return other is not null
            && RpIdHash.Equals(other.RpIdHash)
            && Flags.Equals(other.Flags)
            && SignCount == other.SignCount
            && AttestedCredentialDataEqual(AttestedCredentialData, other.AttestedCredentialData)
            && Extensions.Span.SequenceEqual(other.Extensions.Span);

        //Compares the optional attested credential data by content, treating "absent" as equal only to
        //"absent" — the same null-aware pattern CoseKey.Equals uses for its optional parameters.
        static bool AttestedCredentialDataEqual(AttestedCredentialData? left, AttestedCredentialData? right)
        {
            if(left is null || right is null)
            {
                return left is null && right is null;
            }

            return left.Equals(right);
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is AuthenticatorData other && Equals(other);
    }


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(AuthenticatorData?)"/>.
    /// <see cref="Extensions"/> contributes only its length rather than its bytes — two equal
    /// instances always have equal-length extensions, so this stays consistent with equality while
    /// avoiding hashing the (potentially large) raw CBOR extensions bytes on every hash computation.
    /// </summary>
    /// <returns>The hash code.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(RpIdHash);
        hash.Add(Flags);
        hash.Add(SignCount);
        hash.Add(AttestedCredentialData);
        hash.Add(Extensions.Length);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Determines whether two <see cref="AuthenticatorData"/> instances parsed to the same content.
    /// </summary>
    public static bool operator ==(AuthenticatorData? left, AuthenticatorData? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="AuthenticatorData"/> instances parsed to different content.
    /// </summary>
    public static bool operator !=(AuthenticatorData? left, AuthenticatorData? right) => !(left == right);


    /// <summary>
    /// Releases <see cref="RpIdHash"/> and, when present, <see cref="AttestedCredentialData"/>.
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        RpIdHash.Dispose();
        AttestedCredentialData?.Dispose();
        disposed = true;
    }
}
