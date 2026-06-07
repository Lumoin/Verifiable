using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Extracts the holder's public key from an SD-CWT's <c>cnf</c> claim
/// (CWT claim 8 = <c>WellKnownCwtClaimNames.Cnf</c>), which carries a COSE_Key
/// confirmation method per <see href="https://www.rfc-editor.org/rfc/rfc8747">RFC 8747</see>,
/// and reconstructs it as a tracked <see cref="PublicKeyMemory"/>.
/// </summary>
/// <remarks>
/// <para>
/// A pure CBOR parse/extraction seam — it reads the embedded COSE_Key parameters
/// (kty, crv, x, y) from the SD-CWT's issuer-signed payload and bridges them onto a
/// pool-routed <see cref="PublicKeyMemory"/> tagged for verification. It performs no
/// cryptographic validation. Wired by the application to a <c>Verifiable.Cbor</c>
/// implementation — typically <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ExtractHolderKey</c>,
/// which reuses the <c>MdocCborCoseKeyReader</c> COSE_Key reading approach.
/// </para>
/// </remarks>
/// <param name="sdCwt">The embedded presentation SD-CWT whose issuer-signed payload carries the <c>cnf</c> COSE_Key.</param>
/// <param name="pool">Memory pool the returned key's buffer is rented from.</param>
/// <returns>
/// The holder's public key as a <see cref="PublicKeyMemory"/> the caller owns and disposes,
/// or <see langword="null"/> when the SD-CWT carries no <c>cnf</c> COSE_Key.
/// </returns>
public delegate PublicKeyMemory? ExtractSdCwtHolderKeyDelegate(
    SdToken<System.ReadOnlyMemory<byte>> sdCwt,
    MemoryPool<byte> pool);
