using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Resolves the verifiable credential that carries a W3C Bitstring Status List from the URL in a
/// credential's <c>BitstringStatusListEntry.statusListCredential</c>. This is the W3C analog of
/// <see cref="ResolveStatusListTokenDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// Per W3C Bitstring Status List §3.2, the verifier dereferences the <c>statusListCredential</c>
/// URL and ensures all proofs verify. The library is transport- and proof-agnostic: this delegate
/// performs only the fetch (returning the raw credential bytes); the caller verifies the
/// credential's proof via the existing credential surface, then decodes its <c>encodedList</c> with
/// <see cref="BitstringStatusListCodec.DecodeList"/> and reads the status with
/// <see cref="BitstringStatusListValidation.GetStatus"/>.
/// </para>
/// <para>
/// Content-type negotiation (for example <c>application/vc</c>, <c>application/vc+jwt</c>, or
/// <c>application/vc+cose</c>) and caching are the application's responsibility (§4). Verifiers
/// SHOULD cache the retrieved list and SHOULD use mechanisms such as Oblivious HTTP that hide
/// retrieval behavior from the issuer (§3.2).
/// </para>
/// </remarks>
/// <param name="statusListCredentialUrl">The <c>statusListCredential</c> URL to dereference.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The raw bytes of the status list verifiable credential.</returns>
public delegate ValueTask<byte[]> ResolveBitstringStatusListCredentialDelegate(string statusListCredentialUrl, CancellationToken cancellationToken = default);
