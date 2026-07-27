using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Buffer-content discriminators and pre-built <see cref="Tag"/> instances for the CTAP authenticator
/// state-custody snapshot bytes this subfolder owns.
/// </summary>
/// <remarks>
/// Mirrors <see cref="Fido2BufferTags"/> exactly, but keeps its own numeric range (starting at 1200,
/// comfortably clear of every kind already registered under 1000-1101 across
/// <c>Verifiable.JCose.JoseBufferTags</c>, <see cref="Fido2BufferTags"/>, and
/// <c>Verifiable.Apdu.Ctap.CtapTags</c>) so this wave's custody addition never collides with a kind
/// registered by a file outside this package's touch scope.
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="BufferKind"/>
public static class CtapAuthenticatorCustodyBufferTags
{
    /// <summary>
    /// Buffer kind for a versioned, CBOR-encoded <see cref="CtapAuthenticatorSnapshot"/> payload — the
    /// bytes an <see cref="EncodeCtapAuthenticatorSnapshotDelegate"/> implementation produces and a
    /// <see cref="DecodeCtapAuthenticatorSnapshotDelegate"/> implementation parses back.
    /// </summary>
    public static BufferKind SnapshotKind { get; } = BufferKind.Create(1200);

    /// <summary>
    /// Tag for a versioned, CBOR-encoded <see cref="CtapAuthenticatorSnapshot"/> payload, carrying
    /// <see cref="SnapshotKind"/>.
    /// </summary>
    public static Tag SnapshotPayload { get; } = Tag.Create(SnapshotKind);

    /// <summary>
    /// Buffer kind for a credential's custody-exportable private-key-material copy
    /// (<see cref="CtapCredentialRecord.CredentialKeyCustodyExport"/>) — a raw scalar copy captured at
    /// mint time so a snapshot can later restore signing capability without a live <c>PrivateKey</c>
    /// export path (see the type doc on <see cref="CtapCredentialRecord.CredentialKeyCustodyExport"/>).
    /// </summary>
    public static BufferKind CredentialKeyCustodyExportKind { get; } = BufferKind.Create(1201);

    /// <summary>
    /// Tag for a credential's custody-exportable private-key-material copy, carrying
    /// <see cref="CredentialKeyCustodyExportKind"/>.
    /// </summary>
    public static Tag CredentialKeyCustodyExportPayload { get; } = Tag.Create(CredentialKeyCustodyExportKind);
}
