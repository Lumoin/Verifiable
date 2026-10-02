using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// Tests of the problem-type table <see cref="VcalmProblemTypes"/>: every problem type the VCALM endpoints answer
/// with stands beside the one title its problems carry.
/// </summary>
[TestClass]
internal sealed class VcalmProblemTypesTests
{
    /// <summary>
    /// Every type and title pair of <see cref="VcalmProblemTypes"/>, listed member by member, each with the literal code
    /// name the pair is written for.
    /// </summary>
    /// <returns>One entry per problem type: its type URL, its title member's value and the literal code name.</returns>
    public static IEnumerable<object[]> GetProblemTypeTitlePairs()
    {
        yield return new object[] { VcalmProblemTypes.UnknownOptionProvided, VcalmProblemTypes.UnknownOptionProvidedTitle, "UNKNOWN_OPTION_PROVIDED" };
        yield return new object[] { VcalmProblemTypes.CryptographicSecurityError, VcalmProblemTypes.CryptographicSecurityErrorTitle, "CRYPTOGRAPHIC_SECURITY_ERROR" };
        yield return new object[] { VcalmProblemTypes.MalformedValueError, VcalmProblemTypes.MalformedValueErrorTitle, "MALFORMED_VALUE_ERROR" };
        yield return new object[] { VcalmProblemTypes.StatusRetrievalError, VcalmProblemTypes.StatusRetrievalErrorTitle, "STATUS_RETRIEVAL_ERROR" };
        yield return new object[] { VcalmProblemTypes.StatusVerificationError, VcalmProblemTypes.StatusVerificationErrorTitle, "STATUS_VERIFICATION_ERROR" };
        yield return new object[] { VcalmProblemTypes.StatusListLengthError, VcalmProblemTypes.StatusListLengthErrorTitle, "STATUS_LIST_LENGTH_ERROR" };
        yield return new object[] { VcalmProblemTypes.RangeError, VcalmProblemTypes.RangeErrorTitle, "RANGE_ERROR" };
        yield return new object[] { VcalmProblemTypes.ParsingError, VcalmProblemTypes.ParsingErrorTitle, "PARSING_ERROR" };
        yield return new object[] { VcalmProblemTypes.ProofVerificationError, VcalmProblemTypes.ProofVerificationErrorTitle, "PROOF_VERIFICATION_ERROR" };
        yield return new object[] { VcalmProblemTypes.ProofTransformationError, VcalmProblemTypes.ProofTransformationErrorTitle, "PROOF_TRANSFORMATION_ERROR" };
        yield return new object[] { VcalmProblemTypes.InvalidDomainError, VcalmProblemTypes.InvalidDomainErrorTitle, "INVALID_DOMAIN_ERROR" };
        yield return new object[] { VcalmProblemTypes.InvalidChallengeError, VcalmProblemTypes.InvalidChallengeErrorTitle, "INVALID_CHALLENGE_ERROR" };
        yield return new object[] { VcalmProblemTypes.InvalidControlledIdentifierDocument, VcalmProblemTypes.InvalidControlledIdentifierDocumentTitle, "INVALID_CONTROLLED_IDENTIFIER_DOCUMENT" };
        yield return new object[] { VcalmProblemTypes.InvalidControlledIdentifierDocumentId, VcalmProblemTypes.InvalidControlledIdentifierDocumentIdTitle, "INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID" };
        yield return new object[] { VcalmProblemTypes.InvalidVerificationMethodUrl, VcalmProblemTypes.InvalidVerificationMethodUrlTitle, "INVALID_VERIFICATION_METHOD_URL" };
        yield return new object[] { VcalmProblemTypes.InvalidVerificationMethod, VcalmProblemTypes.InvalidVerificationMethodTitle, "INVALID_VERIFICATION_METHOD" };
        yield return new object[] { VcalmProblemTypes.InvalidRelationshipForVerificationMethod, VcalmProblemTypes.InvalidRelationshipForVerificationMethodTitle, "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD" };
        yield return new object[] { VcalmProblemTypes.UnsupportedSecuringMechanism, VcalmProblemTypes.UnsupportedSecuringMechanismTitle, "UNSUPPORTED_SECURING_MECHANISM" };
        yield return new object[] { VcalmProblemTypes.ContextValidationError, VcalmProblemTypes.ContextValidationErrorTitle, "CONTEXT_VALIDATION_ERROR" };
        yield return new object[] { VcalmProblemTypes.ValidityPeriodWarning, VcalmProblemTypes.ValidityPeriodWarningTitle, "VALIDITY_PERIOD_WARNING" };
        yield return new object[] { VcalmProblemTypes.StatusWarning, VcalmProblemTypes.StatusWarningTitle, "STATUS_WARNING" };
        yield return new object[] { VcalmProblemTypes.ChallengeNotIssued, VcalmProblemTypes.ChallengeNotIssuedTitle, "CHALLENGE_NOT_ISSUED" };
        yield return new object[] { VcalmProblemTypes.VerificationMethodControllerMismatch, VcalmProblemTypes.VerificationMethodControllerMismatchTitle, "VERIFICATION_METHOD_CONTROLLER_MISMATCH" };
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.3">RFC 9457 Section 3.1.3</see> says of the
    /// <c>title</c> member: "It SHOULD NOT change from occurrence to occurrence of the problem, except for localization
    /// (e.g., using proactive content negotiation; see [HTTP], Section 12.1)." Each problem type of
    /// <see cref="VcalmProblemTypes"/> therefore has one title beside it: the title is the literal code name, and the
    /// type URL ends with <c>#</c> followed by that same code name.
    /// </summary>
    /// <param name="type">The problem type URL.</param>
    /// <param name="title">The title member's value standing beside <paramref name="type"/>.</param>
    /// <param name="codeName">The literal code name the pair is written for.</param>
    [TestMethod]
    [DynamicData(nameof(GetProblemTypeTitlePairs))]
    public void EachProblemTypeStandsBesideItsCodeNameTitle(string type, string title, string codeName)
    {
        Assert.AreEqual(codeName, title, $"The title beside '{type}' is its code name.");
        Assert.EndsWith("#" + codeName, type, StringComparison.Ordinal, $"The type URL ends with the fragment of the code name '{codeName}'.");
    }
}
