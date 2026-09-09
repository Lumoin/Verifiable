using System.Linq;
using Verifiable.OAuth.Server;
using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Proves <see cref="VerifierFlowRefusal"/> maps each <see cref="VerifierFlowRefusalKind"/> to the
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see> error code the
/// <c>direct_post</c> endpoint answers a refused OID4VP presentation with (HTTP 400), so a refusal never
/// surfaces as 500, and that its <c>error_description</c> character rule holds by construction.
/// </summary>
[TestClass]
internal sealed class VerifierFlowRefusalTests
{
    /// <summary>
    /// Proves <see cref="VerifierFlowRefusalKind.Malformed"/> maps to <c>invalid_request</c> — the code an
    /// Authorization Response no conformant Wallet would produce is refused with.
    /// </summary>
    [TestMethod]
    public void MalformedKindMapsToInvalidRequestErrorCode()
    {
        VerifierFlowRefusal refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed);

        Assert.AreEqual(OAuthErrors.InvalidRequest, refusal.ErrorCode,
            "RFC 6749 §4.1.2.1: a malformed Authorization Response is invalid_request.");
    }


    /// <summary>
    /// Proves <see cref="VerifierFlowRefusalKind.Unverifiable"/> maps to <c>invalid_request</c> — the code a
    /// presentation whose verification verdict is negative (signature, holder binding, or the DCQL query) is
    /// refused with.
    /// </summary>
    [TestMethod]
    public void UnverifiableKindMapsToInvalidRequestErrorCode()
    {
        VerifierFlowRefusal refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Unverifiable);

        Assert.AreEqual(OAuthErrors.InvalidRequest, refusal.ErrorCode,
            "RFC 6749 §4.1.2.1: a presentation that does not satisfy the request is invalid_request.");
    }


    /// <summary>
    /// Proves <see cref="VerifierFlowRefusalKind.StatusUndeterminable"/> maps to <c>invalid_request</c> — an
    /// undeterminable Token Status List status is an unverifiable presentation, not a pass.
    /// </summary>
    [TestMethod]
    public void StatusUndeterminableKindMapsToInvalidRequestErrorCode()
    {
        VerifierFlowRefusal refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.StatusUndeterminable);

        Assert.AreEqual(OAuthErrors.InvalidRequest, refusal.ErrorCode,
            "RFC 6749 §4.1.2.1: an undeterminable credential status is invalid_request.");
    }


    /// <summary>
    /// Proves <see cref="VerifierFlowRefusalKind.PolicyRefused"/> maps to <c>access_denied</c> — the code a
    /// well-formed, verifiable presentation is refused with on authorization grounds, such as a deployment
    /// status policy refusing a determinable revoked credential.
    /// </summary>
    [TestMethod]
    public void PolicyRefusedKindMapsToAccessDeniedErrorCode()
    {
        VerifierFlowRefusal refusal = VerifierFlowRefusal.For(VerifierFlowRefusalKind.PolicyRefused);

        Assert.AreEqual(OAuthErrors.AccessDenied, refusal.ErrorCode,
            "RFC 6749 §4.1.2.1: a presentation refused on authorization grounds is access_denied.");
    }


    /// <summary>
    /// Proves <see cref="VerifierFlowRefusal.For"/> answers the same fixed sentence for a kind every time —
    /// OID4VP 1.0 §15.9's "Error responses SHOULD avoid including sensitive or detailed contextual
    /// information" holds because the wire description never varies with the refused query or cause.
    /// </summary>
    [TestMethod]
    public void ForAnswersTheSameGenericDescriptionEveryCall()
    {
        VerifierFlowRefusal first = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Unverifiable);
        VerifierFlowRefusal second = VerifierFlowRefusal.For(VerifierFlowRefusalKind.Unverifiable);

        Assert.AreEqual(first.Description, second.Description,
            "OID4VP 1.0 §15.9: the wire description is one fixed, generic sentence per kind.");
    }


    /// <summary>
    /// Proves the constructor enforces RFC 6749 §4.1.2.1's <c>error_description</c> character rule ("MUST NOT
    /// include characters outside the set %x20-21 / %x23-5B / %x5D-7E") by construction: a description
    /// carrying the double-quote character (%x22, outside the allowed set) is refused.
    /// </summary>
    [TestMethod]
    public void ConstructorRejectsADescriptionOutsideTheRfc6749CharacterSet()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new VerifierFlowRefusal(VerifierFlowRefusalKind.Malformed, "bad \" description"),
            "RFC 6749 §4.1.2.1's error_description character rule must hold for any caller, not only VerifierFlowRefusal.For's canonical text.");
    }


    /// <summary>The one fixed, canonical wire sentence for <see cref="VerifierFlowRefusalKind.Malformed"/>.</summary>
    private const string MalformedDescription = "The Authorization Response could not be parsed.";

    /// <summary>The one fixed, canonical wire sentence for <see cref="VerifierFlowRefusalKind.Unverifiable"/>.</summary>
    private const string UnverifiableDescription = "The presentation could not be verified.";

    /// <summary>The one fixed, canonical wire sentence for <see cref="VerifierFlowRefusalKind.PolicyRefused"/>.</summary>
    private const string PolicyRefusedDescription = "The presentation was refused by relying-party policy.";

    /// <summary>The one fixed, canonical wire sentence for <see cref="VerifierFlowRefusalKind.StatusUndeterminable"/>.</summary>
    private const string StatusUndeterminableDescription = "The presentation's credential status could not be determined.";


    /// <summary>
    /// Proves <see cref="VerifierFlowRefusal.For"/> answers each <see cref="VerifierFlowRefusalKind"/>'s exact
    /// literal wire sentence, not merely a non-empty or kind-varying one — an implementation answering the
    /// same generic sentence for every kind would otherwise pass every other test in this class.
    /// </summary>
    /// <param name="kind">The refusal class.</param>
    /// <param name="expectedDescription">The kind's one fixed, canonical wire sentence.</param>
    [TestMethod]
    [DataRow(VerifierFlowRefusalKind.Malformed, MalformedDescription)]
    [DataRow(VerifierFlowRefusalKind.Unverifiable, UnverifiableDescription)]
    [DataRow(VerifierFlowRefusalKind.PolicyRefused, PolicyRefusedDescription)]
    [DataRow(VerifierFlowRefusalKind.StatusUndeterminable, StatusUndeterminableDescription)]
    public void ForAnswersTheKindsExactCanonicalSentence(VerifierFlowRefusalKind kind, string expectedDescription)
    {
        VerifierFlowRefusal refusal = VerifierFlowRefusal.For(kind);

        Assert.AreEqual(expectedDescription, refusal.Description,
            $"{kind} must answer its own fixed, literal wire sentence, not a generic or another kind's.");
    }


    /// <summary>
    /// Proves the four kinds' canonical sentences are pairwise distinct — a reader of the wire
    /// <c>error_description</c> can tell the refusal classes apart even without the <c>error</c> code beside it.
    /// </summary>
    [TestMethod]
    public void TheFourCanonicalSentencesArePairwiseDistinct()
    {
        string[] descriptions =
        [
            MalformedDescription,
            UnverifiableDescription,
            PolicyRefusedDescription,
            StatusUndeterminableDescription
        ];

        Assert.HasCount(descriptions.Length, descriptions.Distinct(StringComparer.Ordinal).ToArray(),
            "Every VerifierFlowRefusalKind's canonical wire sentence must be distinct from every other kind's.");
    }
}
