using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Stores the opaque, TPM-sealed snapshot blob bytes <see cref="TpmSealedStateCustody"/> produced for
/// <paramref name="runId"/>, overwriting whatever was previously stored for the same identifier — the
/// caller-supplied I/O half of the adapter's persist step (contract R-7).
/// </summary>
/// <param name="runId">
/// The stable identifier of the authenticator instance this sealed blob belongs to — the explicit per-call
/// context parameter this delegate takes instead of closing over any caller state (contract R-3, house
/// rule: no closure capture).
/// </param>
/// <param name="sealedBlobBytes">
/// The sealed blob's serialized bytes (<see cref="Verifiable.Tpm.Extensions.Seal.TpmSealedBlob.WriteTo"/>'s
/// own wire form: the parent-wrapped private area then the reserialized public area), already copied into
/// an independent pooled carrier at the adapter's own boundary. Ownership stays with the caller: an
/// implementation that must retain the bytes beyond this call copies what it needs, mirroring
/// <see cref="PersistSnapshotAsyncDelegate"/>'s identical ownership contract.
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <remarks>
/// The bytes this delegate receives are opaque to every entity but the TPM that sealed them — persisting
/// them is safe even to storage this library itself does not trust, since recovering the plaintext
/// snapshot requires both the sealed blob AND the sealing TPM's own loaded parent key and <c>sealAuth</c>.
/// </remarks>
public delegate ValueTask StoreSealedSnapshotBlobAsyncDelegate(string runId, PooledMemory sealedBlobBytes, CancellationToken cancellationToken);
