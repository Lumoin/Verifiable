namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Returns the number of decoy digests to add at a single <c>_sd</c> location during issuance.
/// </summary>
/// <remarks>
/// <para>
/// A <em>decoy digest</em> is a digest that corresponds to no disclosure. Per
/// <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-4.2.5">RFC 9901 §4.2.5</see>,
/// an Issuer MAY add decoy digests to make it harder for an adversarial Verifier to infer the
/// original number of selectively-disclosable claims (or array elements). A Holder receives no
/// disclosure for a decoy, and a Verifier ignores any digest that matches no disclosure, so
/// decoys are transparent to verification.
/// </para>
/// <para>
/// The pipeline invokes this delegate <strong>once per <c>_sd</c> location</strong>, passing a
/// <see cref="DecoyDigestContext"/> that names the location and how many real disclosures are there.
/// An implementation may therefore vary the count by structure (e.g. pad each location to a uniform
/// bucket) and, by closing over the call site, by what is being issued (the credential and the
/// disclosable paths the issuer chose). The count is the issuer's policy — it depends on the
/// credential schema and threat model — so it flows in through this seam rather than being baked into
/// the engine. See <see cref="DecoyDigestPolicy"/> for ready-made implementations.
/// </para>
/// </remarks>
/// <param name="context">The location being padded and the number of real disclosures already there.</param>
/// <returns>The number of decoy digests to add at the current location. Must be non-negative.</returns>
public delegate int DecoyDigestCountDelegate(DecoyDigestContext context);
