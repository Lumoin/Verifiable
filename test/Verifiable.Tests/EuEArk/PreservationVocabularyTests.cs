using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the three value vocabularies of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> this stage ships — <see cref="PreservationWellKnown"/> for the goals, storage
/// models, enumerations, operation names and Annex F scheme identifiers, <see cref="PreservationResultWellKnown"/>
/// for the result codes, and <see cref="PreservationFormatWellKnown"/> for the Annex A format identifiers.
/// </summary>
/// <remarks>
/// Every value is either an XML enumeration facet or a URI the document prints literally, and both match by exact
/// character sequence. The tests below are therefore as much about what the helpers REFUSE as about what they
/// accept — and about the places where the document contradicts itself, each of which is asserted as the reading
/// the library states rather than quietly normalised.
/// </remarks>
[TestClass]
internal sealed class PreservationVocabularyTests
{
    /// <summary>The three preservation goals and the three storage models, recognised and nothing else with them.</summary>
    [TestMethod]
    public void TheGoalsAndStorageModelsRecogniseTheirOwnMembersOnly()
    {
        Assert.IsTrue(PreservationWellKnown.IsPreservationGoal("http://uri.etsi.org/19512/goal/pgd"));
        Assert.IsTrue(PreservationWellKnown.IsPreservationGoal("http://uri.etsi.org/19512/goal/pds"));
        Assert.IsTrue(PreservationWellKnown.IsPreservationGoal("http://uri.etsi.org/19512/goal/aug"));
        Assert.IsFalse(PreservationWellKnown.IsPreservationGoal("http://uri.etsi.org/19512/goal/PGD"), "A goal identifier matches by exact character sequence.");
        Assert.IsFalse(PreservationWellKnown.IsPreservationGoal("http://uri.etsi.org/19512/goal/pgd/"));
        Assert.IsFalse(PreservationWellKnown.IsPreservationGoal(null));

        Assert.IsTrue(PreservationWellKnown.IsStorageModel("WithStorage"));
        Assert.IsTrue(PreservationWellKnown.IsStorageModel("WithTemporaryStorage"));
        Assert.IsTrue(PreservationWellKnown.IsStorageModel("WithoutStorage"));
        Assert.IsFalse(PreservationWellKnown.IsStorageModel("withstorage"));
        Assert.IsFalse(PreservationWellKnown.IsStorageModel("WithStorage "));
        Assert.IsFalse(PreservationWellKnown.IsStorageModel(null));
    }


    /// <summary>
    /// The status vocabulary reads three values although the reproduced enumeration lists two, and the two
    /// readings are kept apart so a caller can tell a profile's status from a discovery filter.
    /// </summary>
    [TestMethod]
    public void TheStatusVocabularyCarriesTheProseOnlyThirdValueAndKeepsBothReadingsApart()
    {
        Assert.IsTrue(PreservationWellKnown.IsStatus("active"));
        Assert.IsTrue(PreservationWellKnown.IsStatus("inactive"));
        Assert.IsTrue(PreservationWellKnown.IsStatus("all"), "Clause 5.4.8.1 gives this value a defined meaning although the reproduced enumeration omits it.");
        Assert.IsFalse(PreservationWellKnown.IsStatus("Active"));
        Assert.IsFalse(PreservationWellKnown.IsStatus(null));

        Assert.IsTrue(PreservationWellKnown.IsProfileStatus("active"));
        Assert.IsTrue(PreservationWellKnown.IsProfileStatus("inactive"));
        Assert.IsFalse(PreservationWellKnown.IsProfileStatus("all"), "A profile is active or inactive; only a filter may ask for both.");
    }


    /// <summary>The two deletion modes, the four subjects of retrieval and the version sentinel.</summary>
    [TestMethod]
    public void TheDeletionModesSubjectsAndVersionSentinelRecogniseTheirOwnMembersOnly()
    {
        Assert.IsTrue(PreservationWellKnown.IsDeletionMode("OnlySubDOs"));
        Assert.IsTrue(PreservationWellKnown.IsDeletionMode("SubDOsAndEvidence"));
        Assert.IsFalse(PreservationWellKnown.IsDeletionMode("OnlySubDos"), "The facet carries a capital O in the last two characters.");
        Assert.IsFalse(PreservationWellKnown.IsDeletionMode(null));

        Assert.IsTrue(PreservationWellKnown.IsSubjectOfRetrieval("PO"));
        Assert.IsTrue(PreservationWellKnown.IsSubjectOfRetrieval("Evidence"));
        Assert.IsTrue(PreservationWellKnown.IsSubjectOfRetrieval("POwithEmbeddedEvidence"));
        Assert.IsTrue(PreservationWellKnown.IsSubjectOfRetrieval("POwithDetachedEvidence"));
        Assert.IsFalse(PreservationWellKnown.IsSubjectOfRetrieval("POWithEmbeddedEvidence"), "The facet's fourth character is a lower-case w.");
        Assert.IsFalse(PreservationWellKnown.IsSubjectOfRetrieval(null));

        Assert.IsTrue(PreservationWellKnown.IsAllVersionsIdentifier("all"));
        Assert.IsFalse(PreservationWellKnown.IsAllVersionsIdentifier("ALL"));
        Assert.IsFalse(PreservationWellKnown.IsAllVersionsIdentifier("v1"));
        Assert.IsFalse(PreservationWellKnown.IsAllVersionsIdentifier(null));
    }


    /// <summary>
    /// The three values an omitted optional element means, which are what makes the difference between a model
    /// that reads a conformant request the way its sender meant it and one that does not.
    /// </summary>
    [TestMethod]
    public void TheThreeStatedDefaultsAreTheOnesTheirClausesGive()
    {
        Assert.AreEqual("active", PreservationWellKnown.DefaultStatus, "Clause 5.3.2.1.1: an omitted status returns only active profiles.");
        Assert.AreEqual("POwithEmbeddedEvidence", PreservationWellKnown.DefaultSubjectOfRetrieval, "Clause 5.3.4.1.1.");
        Assert.AreEqual("SubDOsAndEvidence", PreservationWellKnown.DefaultDeletionMode, "Clause 5.3.5.1.1: the wider of the two modes.");
    }


    /// <summary>The eight operation names, and the two operations a storage model gates.</summary>
    [TestMethod]
    public void TheOperationNamesAreTheEightTheDocumentDefinesAndTwoOfThemAreGated()
    {
        string[] operations =
        [
            "RetrieveInfo", "PreservePO", "RetrievePO", "DeletePO", "UpdatePOC", "RetrieveTrace", "ValidateEvidence", "Search"
        ];
        foreach(string operation in operations)
        {
            Assert.IsTrue(PreservationWellKnown.IsOperationName(operation), operation);
        }

        Assert.IsFalse(PreservationWellKnown.IsOperationName("preservePO"));
        Assert.IsFalse(PreservationWellKnown.IsOperationName("ValidatePOC"), "The residue of an earlier name is not an operation of this document.");
        Assert.IsFalse(PreservationWellKnown.IsOperationName(null));

        Assert.IsTrue(PreservationWellKnown.IsOperationPermittedUnderStorageModel("RetrievePO", "WithStorage"));
        Assert.IsTrue(PreservationWellKnown.IsOperationPermittedUnderStorageModel("RetrievePO", "WithTemporaryStorage"));
        Assert.IsFalse(PreservationWellKnown.IsOperationPermittedUnderStorageModel("RetrievePO", "WithoutStorage"), "Clause 5.3.4.1.1 permits retrieval only where something is stored.");

        Assert.IsTrue(PreservationWellKnown.IsOperationPermittedUnderStorageModel("DeletePO", "WithStorage"));
        Assert.IsFalse(PreservationWellKnown.IsOperationPermittedUnderStorageModel("DeletePO", "WithTemporaryStorage"), "Clause 5.3.5.1.1 permits deletion only in a scheme with storage.");
        Assert.IsFalse(PreservationWellKnown.IsOperationPermittedUnderStorageModel("DeletePO", "WithoutStorage"));

        Assert.IsTrue(PreservationWellKnown.IsOperationPermittedUnderStorageModel("PreservePO", "WithoutStorage"), "Only two operations carry a gate of their own.");
    }


    /// <summary>
    /// Three of the four Annex F schemes state two different identifiers for themselves, and the one the library
    /// writes is in every case the one that agrees with the goals the same scheme's own clause lists.
    /// </summary>
    [TestMethod]
    public void ThreeOfTheFourSchemesStateTwoIdentifiersAndTheLibraryWritesTheConsistentOne()
    {
        Assert.AreEqual("http://uri.etsi.org/19512/scheme/pds+pgd+aug+wst+ers", PreservationWellKnown.StorageWithEvidenceRecordsScheme, "Clause F.1.1.");
        Assert.AreEqual("http://uri.etsi.org/19512/scheme/pgd+wts+ers", PreservationWellKnown.TemporaryStorageWithEvidenceRecordsScheme, "Clause F.2.1.");
        Assert.AreEqual("http://uri.etsi.org/19512/scheme/pds+wst+aug", PreservationWellKnown.StorageWithAugmentationScheme, "Clause F.3.1.");
        Assert.AreEqual("http://uri.etsi.org/19512/scheme/pds+wos+aug", PreservationWellKnown.NoStorageWithAugmentationScheme, "Clause F.4.1.");

        Assert.AreEqual("http://uri.etsi.org/19512/scheme/pds+pgd+wst+ers", PreservationWellKnown.StorageWithEvidenceRecordsSchemeAsRestated, "Clause F.1.7 drops the augmentation segment.");
        Assert.AreEqual("http://uri.etsi.org/19512/scheme/pgd+wst+aug", PreservationWellKnown.StorageWithAugmentationSchemeAsRestated, "Clause F.3.7 changes the goal segment.");
        Assert.AreEqual("http://uri.etsi.org/19512/scheme/pgd+wos+aug", PreservationWellKnown.NoStorageWithAugmentationSchemeAsRestated, "Clause F.4.7 changes the goal segment.");

        Assert.AreNotEqual(PreservationWellKnown.StorageWithEvidenceRecordsScheme, PreservationWellKnown.StorageWithEvidenceRecordsSchemeAsRestated);
        Assert.AreNotEqual(PreservationWellKnown.StorageWithAugmentationScheme, PreservationWellKnown.StorageWithAugmentationSchemeAsRestated);
        Assert.AreNotEqual(PreservationWellKnown.NoStorageWithAugmentationScheme, PreservationWellKnown.NoStorageWithAugmentationSchemeAsRestated);

        foreach(string identifier in new[]
        {
            PreservationWellKnown.StorageWithEvidenceRecordsScheme,
            PreservationWellKnown.TemporaryStorageWithEvidenceRecordsScheme,
            PreservationWellKnown.StorageWithAugmentationScheme,
            PreservationWellKnown.NoStorageWithAugmentationScheme,
            PreservationWellKnown.StorageWithEvidenceRecordsSchemeAsRestated,
            PreservationWellKnown.StorageWithAugmentationSchemeAsRestated,
            PreservationWellKnown.NoStorageWithAugmentationSchemeAsRestated
        })
        {
            Assert.IsTrue(PreservationWellKnown.IsSchemeIdentifier(identifier), identifier);
        }

        Assert.IsFalse(PreservationWellKnown.IsConsistentSchemeIdentifier(PreservationWellKnown.StorageWithEvidenceRecordsSchemeAsRestated));
        Assert.IsFalse(PreservationWellKnown.IsConsistentSchemeIdentifier(PreservationWellKnown.StorageWithAugmentationSchemeAsRestated));
        Assert.IsFalse(PreservationWellKnown.IsConsistentSchemeIdentifier(PreservationWellKnown.NoStorageWithAugmentationSchemeAsRestated));
        Assert.IsTrue(PreservationWellKnown.IsConsistentSchemeIdentifier(PreservationWellKnown.TemporaryStorageWithEvidenceRecordsScheme), "The one scheme whose two statements agree.");
        Assert.IsFalse(PreservationWellKnown.IsSchemeIdentifier("http://uri.etsi.org/19512/scheme/pds"), "A scheme the annex does not define.");
        Assert.IsFalse(PreservationWellKnown.IsSchemeIdentifier(null));
    }


    /// <summary>The two policy types, and the two namespaces the protocol's schemas target.</summary>
    [TestMethod]
    public void ThePolicyTypesAndNamespacesAreTheOnesTheDocumentStates()
    {
        Assert.IsTrue(PreservationWellKnown.IsPolicyType("http://uri.etsi.org/19512/policy/preservation-evidence"));
        Assert.IsTrue(PreservationWellKnown.IsPolicyType("http://uri.etsi.org/19512/policy/signature-validation"));
        Assert.IsFalse(PreservationWellKnown.IsPolicyType("http://uri.etsi.org/19512/policy/preservation"));
        Assert.IsFalse(PreservationWellKnown.IsPolicyType(null));

        Assert.AreEqual("http://uri.etsi.org/19512/v1.2.1#", PreservationWellKnown.PreservationNamespace, "Annex C.1.");
        Assert.AreEqual("http://uri.etsi.org/19512/exchange/v1.2.1#", PreservationWellKnown.PreservationExchangeNamespace, "Annex C.2.");
    }


    /// <summary>The seventeen result codes, their two namespaces and the partition between error and warning.</summary>
    [TestMethod]
    public void TheResultCodesAreSeventeenAndPartitionIntoErrorsAndWarnings()
    {
        IReadOnlyList<string> codes = EveryResultCode();
        Assert.HasCount(17, codes, "Fifteen error codes and two warning codes.");

        int errors = 0;
        int warnings = 0;
        foreach(string code in codes)
        {
            Assert.IsTrue(PreservationResultWellKnown.IsResultMinor(code), code);

            if(PreservationResultWellKnown.IsErrorCode(code))
            {
                ++errors;
                Assert.StartsWith(PreservationResultWellKnown.ErrorCodeNamespace, code);
                Assert.IsFalse(PreservationResultWellKnown.IsWarningCode(code), code);
            }
            else
            {
                ++warnings;
                Assert.IsTrue(PreservationResultWellKnown.IsWarningCode(code), code);
                Assert.StartsWith(PreservationResultWellKnown.WarningCodeNamespace, code);
            }
        }

        Assert.AreEqual(15, errors);
        Assert.AreEqual(2, warnings);

        Assert.IsFalse(PreservationResultWellKnown.IsResultMinor("http://uri.etsi.org/19512/error/nopermission"), "A code matches by exact character sequence.");
        Assert.IsFalse(PreservationResultWellKnown.IsResultMinor(null));
        Assert.IsTrue(PreservationResultWellKnown.IsErrorCode("http://uri.etsi.org/19512/error/POFormatError"), "One of the two codes whose last segment begins with capitals.");
        Assert.IsTrue(PreservationResultWellKnown.IsErrorCode("http://uri.etsi.org/19512/error/DeltaPOCInternalProblem"));
    }


    /// <summary>
    /// Every error code maps to an outcome and back, and nothing that is not an error code ever maps to a
    /// success — which is the fail-closed reading a peer depends on when it meets a code it does not know.
    /// </summary>
    [TestMethod]
    public void EveryErrorCodeRoundTripsThroughItsOutcomeAndNothingElseReadsAsSuccess()
    {
        int mapped = 0;
        foreach(PreservationOperationOutcome outcome in Enum.GetValues<PreservationOperationOutcome>())
        {
            string? code = PreservationResultWellKnown.ResultMinorFromOutcome(outcome);
            if(outcome is PreservationOperationOutcome.NotEvaluated or PreservationOperationOutcome.Succeeded)
            {
                Assert.IsNull(code, $"{outcome} has no minor code of its own.");
                continue;
            }

            Assert.IsNotNull(code, outcome.ToString());
            Assert.AreEqual(outcome, PreservationResultWellKnown.OutcomeFromResultMinor(code));
            ++mapped;
        }

        Assert.AreEqual(15, mapped, "One outcome per error code.");

        Assert.IsNull(PreservationResultWellKnown.OutcomeFromResultMinor(PreservationResultWellKnown.LowSpace), "A warning accompanies a call that succeeded; it is not an outcome.");
        Assert.IsNull(PreservationResultWellKnown.OutcomeFromResultMinor(PreservationResultWellKnown.RequestOnlyPartlySuccessful));
        Assert.IsNull(PreservationResultWellKnown.OutcomeFromResultMinor("http://uri.etsi.org/19512/error/somethingElse"));
        Assert.IsNull(PreservationResultWellKnown.OutcomeFromResultMinor(null));

        foreach(string code in EveryResultCode())
        {
            Assert.AreNotEqual(
                PreservationOperationOutcome.Succeeded,
                PreservationResultWellKnown.OutcomeFromResultMinor(code) ?? PreservationOperationOutcome.NotEvaluated,
                $"{code} must never read as a successful operation.");
        }
    }


    /// <summary>
    /// Each operation's response admits exactly the codes its own clause enumerates: the four common ones
    /// everywhere, the operation-specific ones only where they are stated.
    /// </summary>
    /// <param name="operationName">The operation whose list is checked.</param>
    /// <param name="expectedCount">How many of the seventeen codes that clause enumerates.</param>
    [TestMethod]
    [DataRow("RetrieveInfo", 4, DisplayName = "clause 5.3.2.2.1, the four common codes")]
    [DataRow("PreservePO", 10, DisplayName = "clause 5.3.3.2.1, five more errors and one warning")]
    [DataRow("RetrievePO", 9, DisplayName = "clause 5.3.4.2.1, four more errors and one warning")]
    [DataRow("DeletePO", 6, DisplayName = "clause 5.3.5.2, two more errors")]
    [DataRow("UpdatePOC", 10, DisplayName = "clause 5.3.6.2.1, five more errors and one warning")]
    [DataRow("RetrieveTrace", 5, DisplayName = "clause 5.3.7.2.1, one more error")]
    [DataRow("ValidateEvidence", 4, DisplayName = "clause 5.3.8.2.1, the four common codes")]
    [DataRow("Search", 4, DisplayName = "clause 5.3.9.2.1, the four common codes under a misattributed heading")]
    public void EachOperationAdmitsExactlyTheCodesItsOwnClauseEnumerates(string operationName, int expectedCount)
    {
        int admitted = EveryResultCode().Count(code => PreservationResultWellKnown.IsResultMinorStatedForOperation(operationName, code));
        Assert.AreEqual(expectedCount, admitted, operationName);

        Assert.IsTrue(PreservationResultWellKnown.IsResultMinorStatedForOperation(operationName, PreservationResultWellKnown.NoPermission), "Every operation states the four common codes.");
        Assert.IsFalse(PreservationResultWellKnown.IsResultMinorStatedForOperation(operationName, null));
        Assert.IsFalse(PreservationResultWellKnown.IsResultMinorStatedForOperation("ValidatePOC", PreservationResultWellKnown.NoPermission), "An operation the document does not define admits nothing.");
    }


    /// <summary>
    /// The codes each operation adds to the four common ones, asserted by name so a list that lost a member
    /// would fail here rather than only in the counts.
    /// </summary>
    [TestMethod]
    public void TheOperationSpecificCodesAreStatedWhereTheirClausesStateThem()
    {
        Assert.IsTrue(PreservationResultWellKnown.IsResultMinorStatedForOperation("PreservePO", PreservationResultWellKnown.ExternalServiceUnavailable));
        Assert.IsFalse(PreservationResultWellKnown.IsResultMinorStatedForOperation("RetrievePO", PreservationResultWellKnown.ExternalServiceUnavailable));

        Assert.IsTrue(PreservationResultWellKnown.IsResultMinorStatedForOperation("RetrievePO", PreservationResultWellKnown.RequestOnlyPartlySuccessful));
        Assert.IsFalse(PreservationResultWellKnown.IsResultMinorStatedForOperation("PreservePO", PreservationResultWellKnown.RequestOnlyPartlySuccessful));

        Assert.IsTrue(PreservationResultWellKnown.IsResultMinorStatedForOperation("DeletePO", PreservationResultWellKnown.UnknownDeletionMode));
        Assert.IsFalse(PreservationResultWellKnown.IsResultMinorStatedForOperation("UpdatePOC", PreservationResultWellKnown.UnknownDeletionMode));

        Assert.IsTrue(PreservationResultWellKnown.IsResultMinorStatedForOperation("UpdatePOC", PreservationResultWellKnown.DeltaContainerInternalProblem));
        Assert.IsTrue(PreservationResultWellKnown.IsResultMinorStatedForOperation("UpdatePOC", PreservationResultWellKnown.UnknownDeltaContainerType));
        Assert.IsFalse(PreservationResultWellKnown.IsResultMinorStatedForOperation("DeletePO", PreservationResultWellKnown.UnknownDeltaContainerType));

        Assert.IsTrue(PreservationResultWellKnown.IsResultMinorStatedForOperation("RetrieveTrace", PreservationResultWellKnown.UnknownPreservationObjectIdentifier));
        Assert.IsFalse(PreservationResultWellKnown.IsResultMinorStatedForOperation("RetrieveInfo", PreservationResultWellKnown.UnknownPreservationObjectIdentifier));
    }


    /// <summary>The Annex A format identifiers, and the case distinction that separates the two container profiles.</summary>
    [TestMethod]
    public void TheFormatIdentifiersAreTheOnesAnnexARegistersAndTheContainerProfilesDifferByCase()
    {
        Assert.IsTrue(PreservationFormatWellKnown.IsEvidenceFormat("urn:ietf:rfc:3161:TimeStampToken"));
        Assert.IsTrue(PreservationFormatWellKnown.IsEvidenceFormat("urn:ietf:rfc:4998:EvidenceRecord"));
        Assert.IsTrue(PreservationFormatWellKnown.IsEvidenceFormat("urn:ietf:rfc:6283:EvidenceRecord"));
        Assert.IsTrue(PreservationFormatWellKnown.IsEvidenceFormat("http://uri.etsi.org/ades/CAdES/archive-time-stamp-v3"));
        Assert.IsTrue(PreservationFormatWellKnown.IsEvidenceFormat("http://uri.etsi.org/ades/XAdES/ArchiveTimeStamp"));
        Assert.IsTrue(PreservationFormatWellKnown.IsEvidenceFormat("http://uri.etsi.org/ades/PAdES/document-time-stamp"));
        Assert.IsFalse(PreservationFormatWellKnown.IsEvidenceFormat("urn:ietf:rfc:4998"), "The evidence format identifier carries the structure's name after the document's.");
        Assert.IsFalse(PreservationFormatWellKnown.IsEvidenceFormat(null));

        Assert.IsTrue(PreservationFormatWellKnown.IsSubmissionFormat("http://uri.etsi.org/ades/CAdES"));
        Assert.IsTrue(PreservationFormatWellKnown.IsSubmissionFormat("http://uri.etsi.org/ades/XAdES"));
        Assert.IsTrue(PreservationFormatWellKnown.IsSubmissionFormat("http://uri.etsi.org/ades/PAdES"));
        Assert.IsTrue(PreservationFormatWellKnown.IsSubmissionFormat("http://uri.etsi.org/ades/ASiC/type/ASiC-E"));
        Assert.IsTrue(PreservationFormatWellKnown.IsSubmissionFormat("http://uri.etsi.org/19512/format/DigestList"));
        Assert.IsFalse(PreservationFormatWellKnown.IsSubmissionFormat("http://uri.etsi.org/ades/ASiC/type/ASiC-ERS"), "The preservation-specific container profile is a container format, not a submission format.");
        Assert.IsFalse(PreservationFormatWellKnown.IsSubmissionFormat(null));

        Assert.IsTrue(PreservationFormatWellKnown.IsContainerFormat("http://uri.etsi.org/ades/ASiC/type/ASiC-ERS"));
        Assert.IsFalse(PreservationFormatWellKnown.IsContainerFormat("http://uri.etsi.org/ades/ASiC/type/ASiC-E"));
        Assert.IsFalse(PreservationFormatWellKnown.IsContainerFormat("http://uri.etsi.org/ades/ASiC/type/asic-ers"), "The identifiers differ by the case-sensitive suffix of their last segment.");
    }


    /// <summary>
    /// The library's vocabulary and the wave's claim-identifier registry state the same seventeen result codes
    /// and the same eight operation names — two independently written lists that have to agree, since one is what
    /// a message carries and the other is what a requirements matrix and a consumer's graph key on.
    /// </summary>
    [TestMethod]
    public void TheVocabularyAndTheClaimIdentifierRegistryStateTheSameCodesAndOperations()
    {
        Assert.AreEqual(PreservationResultWellKnown.NoPermission, PreservationClaimIds.ResultNoPermission.ToString());
        Assert.AreEqual(PreservationResultWellKnown.InternalError, PreservationClaimIds.ResultInternalError.ToString());
        Assert.AreEqual(PreservationResultWellKnown.ParameterError, PreservationClaimIds.ResultParameterError.ToString());
        Assert.AreEqual(PreservationResultWellKnown.NotSupported, PreservationClaimIds.ResultNotSupported.ToString());
        Assert.AreEqual(PreservationResultWellKnown.TransferError, PreservationClaimIds.ResultTransferError.ToString());
        Assert.AreEqual(PreservationResultWellKnown.NoSpaceError, PreservationClaimIds.ResultNoSpaceError.ToString());
        Assert.AreEqual(PreservationResultWellKnown.UnknownPreservationObjectFormat, PreservationClaimIds.ResultUnknownPoFormat.ToString());
        Assert.AreEqual(PreservationResultWellKnown.PreservationObjectFormatError, PreservationClaimIds.ResultPoFormatError.ToString());
        Assert.AreEqual(PreservationResultWellKnown.ExternalServiceUnavailable, PreservationClaimIds.ResultExternalServiceUnavailable.ToString());
        Assert.AreEqual(PreservationResultWellKnown.LowSpace, PreservationClaimIds.ResultLowSpace.ToString());
        Assert.AreEqual(PreservationResultWellKnown.UnknownEvidenceFormat, PreservationClaimIds.ResultUnknownEvidenceFormat.ToString());
        Assert.AreEqual(PreservationResultWellKnown.UnknownPreservationObjectIdentifier, PreservationClaimIds.ResultUnknownPoId.ToString());
        Assert.AreEqual(PreservationResultWellKnown.UnknownVersionIdentifier, PreservationClaimIds.ResultUnknownVersionId.ToString());
        Assert.AreEqual(PreservationResultWellKnown.RequestOnlyPartlySuccessful, PreservationClaimIds.ResultRequestOnlyPartlySuccessful.ToString());
        Assert.AreEqual(PreservationResultWellKnown.UnknownDeletionMode, PreservationClaimIds.ResultUnknownMode.ToString());
        Assert.AreEqual(PreservationResultWellKnown.UnknownDeltaContainerType, PreservationClaimIds.ResultUnknownDeltaPocType.ToString());
        Assert.AreEqual(PreservationResultWellKnown.DeltaContainerInternalProblem, PreservationClaimIds.ResultDeltaPocInternalProblem.ToString());

        Assert.AreEqual(PreservationWellKnown.RetrieveInfoOperation, PreservationClaimIds.OperationRetrieveInfo.ToString());
        Assert.AreEqual(PreservationWellKnown.PreservePreservationObjectOperation, PreservationClaimIds.OperationPreservePo.ToString());
        Assert.AreEqual(PreservationWellKnown.RetrievePreservationObjectOperation, PreservationClaimIds.OperationRetrievePo.ToString());
        Assert.AreEqual(PreservationWellKnown.DeletePreservationObjectOperation, PreservationClaimIds.OperationDeletePo.ToString());
        Assert.AreEqual(PreservationWellKnown.UpdatePreservationObjectContainerOperation, PreservationClaimIds.OperationUpdatePoc.ToString());
        Assert.AreEqual(PreservationWellKnown.RetrieveTraceOperation, PreservationClaimIds.OperationRetrieveTrace.ToString());
        Assert.AreEqual(PreservationWellKnown.ValidateEvidenceOperation, PreservationClaimIds.OperationValidateEvidence.ToString());
        Assert.AreEqual(PreservationWellKnown.SearchOperation, PreservationClaimIds.OperationSearch.ToString());
    }


    /// <summary>
    /// No enumeration this stage declares reads as a success, an admission or a stated value when it has not been
    /// assigned: every zero is the "nothing has been decided" case.
    /// </summary>
    [TestMethod]
    public void NoDefaultInitialisedEnumerationOfThisStageReadsAsAStatedValue()
    {
        Assert.AreEqual("None", Enum.GetName(default(PreservationPayloadKind)));
        Assert.AreEqual("NotEvaluated", Enum.GetName(default(PreservationContentForm)));
        Assert.AreEqual("NotEvaluated", Enum.GetName(default(PreservationMessageKind)));
        Assert.AreEqual("NotEvaluated", Enum.GetName(default(PreservationMessageStatus)));
        Assert.AreEqual("NotEvaluated", Enum.GetName(default(PreservationOperationOutcome)));
        Assert.AreEqual("NotEvaluated", Enum.GetName(default(PreservationSyntax)));
        Assert.AreEqual("NotEvaluated", Enum.GetName(default(PreservationMessageEncodeStatus)));
        Assert.AreEqual("NotEvaluated", Enum.GetName(default(PreservationMessageParseStatus)));
    }


    /// <summary>
    /// Every result code the vocabulary declares, found by reflection so a code added without a test row still
    /// takes part in the counts and the partition.
    /// </summary>
    /// <returns>The seventeen code values.</returns>
    private static List<string> EveryResultCode()
    {
        List<string> codes = [];
        foreach(PropertyInfo property in typeof(PreservationResultWellKnown).GetProperties(BindingFlags.Public | BindingFlags.Static))
        {
            if(property.PropertyType != typeof(string) || property.Name.EndsWith("Namespace", StringComparison.Ordinal))
            {
                continue;
            }

            codes.Add((string)property.GetValue(null)!);
        }

        return codes;
    }
}
