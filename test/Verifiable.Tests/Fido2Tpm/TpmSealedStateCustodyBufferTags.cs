using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Fido2.Tpm.Ctap.Authenticator.Custody;

/// <summary>
/// Buffer-content discriminator and pre-built <see cref="Tag"/> for the serialized, TPM-sealed snapshot
/// blob bytes <see cref="TpmSealedStateCustody"/> hands to a caller-supplied
/// <see cref="StoreSealedSnapshotBlobAsyncDelegate"/> and reads back via a
/// <see cref="TryFetchSealedSnapshotBlobAsyncDelegate"/>.
/// </summary>
/// <remarks>
/// Own numeric range (1202), clear of <see cref="CtapAuthenticatorCustodyBufferTags"/>'s own 1200-1201
/// pair and every other kind registered elsewhere in the solution, so this package's addition never
/// collides with a kind registered by a file outside its touch scope.
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="BufferKind"/>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code (layering-split-ledger.md): public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
public static class TpmSealedStateCustodyBufferTags
{
    /// <summary>
    /// Buffer kind for a serialized <see cref="Verifiable.Tpm.Extensions.Seal.TpmSealedBlob"/> — the opaque
    /// bytes <see cref="TpmSealedStateCustody"/>'s persist step hands to a
    /// <see cref="StoreSealedSnapshotBlobAsyncDelegate"/> and its load step reads back via a
    /// <see cref="TryFetchSealedSnapshotBlobAsyncDelegate"/>. Never the plaintext snapshot itself — that
    /// recovered carrier carries <see cref="CtapAuthenticatorCustodyBufferTags.SnapshotPayload"/> instead.
    /// </summary>
    public static BufferKind SealedSnapshotBlobKind { get; } = BufferKind.Create(1202);

    /// <summary>Tag for a serialized, TPM-sealed snapshot blob, carrying <see cref="SealedSnapshotBlobKind"/>.</summary>
    public static Tag SealedSnapshotBlobPayload { get; } = Tag.Create(SealedSnapshotBlobKind);
}
