using Lumoin.Base;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cesr;

/// <summary>
/// The crypto facts a CESR verification-key derivation code resolves to: the algorithm used to verify a
/// signature made by that key, and the <see cref="Tag"/>s that wrap its public key and signature bytes for
/// the crypto layer.
/// </summary>
/// <param name="Algorithm">The cryptographic algorithm the verification key uses.</param>
/// <param name="PublicKeyTag">The tag that wraps the key's raw public-key bytes.</param>
/// <param name="SignatureTag">The tag that wraps a signature made by this key.</param>
public sealed record CesrVerificationKeyInfo(CryptoAlgorithm Algorithm, Tag PublicKeyTag, Tag SignatureTag);
