using Verifiable.Cryptography;
using Verifiable.OAuth.Oid4Vp.Wallet;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Writes and signs the Key Binding JWT (RFC 9901 section 4.3) of a wallet's SD-JWT VC presentation: the test wallet's seam
/// where a row decides the KB-JWT's claims at the producer, so the bytes the verifier reads are the first and only bytes the
/// holder signed.
/// </summary>
/// <param name="sdJwtForHashing">The presentation's <c>sd_hash</c> input, as UTF-8.</param>
/// <param name="holderKey">The holder's key the KB-JWT is signed with.</param>
/// <param name="context">The request-derived presentation inputs: nonce, Client ID, transaction data and the instant.</param>
/// <param name="cancellationToken">Cancels the signing.</param>
/// <returns>The compact KB-JWT.</returns>
internal delegate ValueTask<string> IssueKeyBindingJwtDelegate(
    ReadOnlyMemory<byte> sdJwtForHashing,
    PrivateKeyMemory holderKey,
    Oid4VpPresentationContext context,
    CancellationToken cancellationToken);
