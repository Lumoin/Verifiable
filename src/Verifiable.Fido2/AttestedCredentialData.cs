using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.JCose;

namespace Verifiable.Fido2;

/// <summary>
/// Parsed view of the attested credential data structure embedded in <c>authData</c> when
/// the <c>AT</c> flag is set.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication Level 3, section 6.5.1: Attested Credential Data.</see>
/// The wire layout is <c>aaguid</c> (16 bytes) | <c>credentialIdLength</c> (2 bytes, big-endian) |
/// <c>credentialId</c> | <c>credentialPublicKey</c> (a COSE_Key).
/// </para>
/// <para>
/// <strong>Lifetime.</strong> <see cref="CredentialId"/> is a pooled carrier this instance owns —
/// <see cref="AuthenticatorDataReader.Read"/> copies the wire <c>credentialId</c> bytes into it, so
/// it remains valid after the source buffer is reused or discarded. Disposing this instance
/// disposes it.
/// </para>
/// <para>
/// <strong>Equality.</strong> Two instances are equal when <see cref="Aaguid"/>,
/// <see cref="CredentialId"/>, and <see cref="CredentialPublicKey"/> all compare equal — content
/// equality over every parsed member, delegating to <see cref="Fido2.CredentialId"/>'s and
/// <see cref="JCose.CoseKey"/>'s own content equality.
/// </para>
/// </remarks>
[DebuggerDisplay("AttestedCredentialData(Aaguid={Aaguid}, CredentialId={CredentialId})")]
public sealed class AttestedCredentialData: IDisposable, IEquatable<AttestedCredentialData>
{
    /// <summary>
    /// Initializes an <see cref="AttestedCredentialData"/> view from its parsed members. Ownership
    /// of <paramref name="credentialId"/> transfers to the new instance; disposing it disposes
    /// <paramref name="credentialId"/>.
    /// </summary>
    /// <param name="aaguid">The authenticator AAGUID, per <see cref="Aaguid"/>.</param>
    /// <param name="credentialId">The credential identifier, per <see cref="CredentialId"/>.</param>
    /// <param name="credentialPublicKey">The credential public key, per <see cref="CredentialPublicKey"/>.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="credentialId"/> or <paramref name="credentialPublicKey"/> is <see langword="null"/>.
    /// </exception>
    public AttestedCredentialData(Guid aaguid, CredentialId credentialId, CoseKey credentialPublicKey)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        ArgumentNullException.ThrowIfNull(credentialPublicKey);

        Aaguid = aaguid;
        CredentialId = credentialId;
        CredentialPublicKey = credentialPublicKey;
    }


    /// <summary>
    /// The AAGUID identifying the authenticator model that generated the credential.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication Level 3, section 6.5.1: Attested Credential Data.</see>
    /// </remarks>
    public Guid Aaguid { get; }

    /// <summary>
    /// The credential identifier, owned by this instance (see the type-level remarks on lifetime).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication Level 3, section 6.5.1: Attested Credential Data.</see>
    /// </remarks>
    public CredentialId CredentialId { get; }

    /// <summary>
    /// The credential public key, parsed from its COSE_Key encoding.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication Level 3, section 6.5.1: Attested Credential Data.</see>
    /// </remarks>
    public CoseKey CredentialPublicKey { get; }


    /// <summary>
    /// Determines whether this instance and <paramref name="other"/> carry the same
    /// <see cref="Aaguid"/>, <see cref="CredentialId"/>, and <see cref="CredentialPublicKey"/>.
    /// </summary>
    /// <param name="other">The other instance to compare against.</param>
    /// <returns><see langword="true"/> when every member matches; otherwise <see langword="false"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] AttestedCredentialData? other)
    {
        return other is not null
            && Aaguid == other.Aaguid
            && CredentialId.Equals(other.CredentialId)
            && CredentialPublicKey.Equals(other.CredentialPublicKey);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is AttestedCredentialData other && Equals(other);
    }


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(AttestedCredentialData?)"/>, combining
    /// <see cref="Aaguid"/>, <see cref="CredentialId"/>, and <see cref="CredentialPublicKey"/>.
    /// </summary>
    /// <returns>The hash code.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(Aaguid, CredentialId, CredentialPublicKey);


    /// <summary>
    /// Determines whether two <see cref="AttestedCredentialData"/> instances carry the same content.
    /// </summary>
    public static bool operator ==(AttestedCredentialData? left, AttestedCredentialData? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="AttestedCredentialData"/> instances carry different content.
    /// </summary>
    public static bool operator !=(AttestedCredentialData? left, AttestedCredentialData? right) => !(left == right);


    /// <summary>
    /// Releases <see cref="CredentialId"/>.
    /// </summary>
    public void Dispose() => CredentialId.Dispose();
}
