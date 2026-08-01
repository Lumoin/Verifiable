using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using CsCheck;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Property-based tests (CsCheck) for the determinism rules of clause 5.1.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>: "any execution of an SVA with the same inputs shall return <c>TOTAL-PASSED</c>
/// or <c>TOTAL-FAILED</c>, respectively" (rule a), and "any execution of an SVA with the same inputs and
/// additional validation data ... shall return the same result" (rule b) — as opposed to rule c, which allows
/// additional proofs of existence to change a determinate result, and is exercised by the Annex A worked examples
/// rather than here.
/// </summary>
/// <remarks>
/// <para>
/// One real world — a genuine CAdES-B-T signature over a real three-level certificate chain, minted once by
/// <see cref="AnnexAValidationScenario"/> — is reused across every sample of both properties: what varies is the
/// number of reruns and the unrelated extra validation data, never the signature or the chain. This keeps the
/// properties fast while still exercising the composed engine (<see cref="SignatureValidation.ValidateAsync(SignatureValidationInputs,SignatureValidationSeams,SignatureValidationProcessSelection,SignatureValidationCapabilities,DateTimeOffset,BaseMemoryPool,System.Threading.CancellationToken)"/>)
/// end to end, not a stand-in.
/// </para>
/// <para>
/// CsCheck's <c>Sample</c> callback is synchronous; the asynchronous validation calls inside it are blocked on
/// with <c>AsTask().GetAwaiter().GetResult()</c>, the idiom already used by
/// <c>Fido2RegistrationVerifierPropertyTests</c> in this suite.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SignatureValidationDeterminismPropertyTests
{
    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Rule a) of clause 5.1.3: rerunning the validation process for Signatures with Time over the same signature,
    /// the same chain and the same current time — the same inputs, nothing else — always yields the same main
    /// status indication and the same set of sub-indications, for any number of reruns.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until validation fully completes, so the using declaration's dispose runs strictly after every call returns.")]
    public async Task RerunningValidationWithIdenticalInputsYieldsAnIdenticalConclusion()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Gen.Int[2, 6].Sample(repeatCount =>
        {
            SignatureValidationIndication? firstIndication = null;
            IReadOnlyList<SignatureValidationSubIndication>? firstSubIndications = null;
            for(int i = 0; i < repeatCount; ++i)
            {
                using SignatureValidationOutcome outcome = SignatureValidation.ValidateAsync(
                    scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime,
                    SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
                    TestContext.CancellationToken).AsTask().GetAwaiter().GetResult();

                if(firstIndication is null)
                {
                    firstIndication = outcome.Conclusion.Indication;
                    firstSubIndications = [.. outcome.Conclusion.SubIndications];

                    continue;
                }

                if(outcome.Conclusion.Indication != firstIndication)
                {
                    return false;
                }

                if(!SubIndicationsMatch(firstSubIndications!, outcome.Conclusion.SubIndications))
                {
                    return false;
                }
            }

            return true;
        });
    }


    /// <summary>
    /// Rule b) of clause 5.1.3: rerunning the validation process for Signatures with Time with the same inputs
    /// plus arbitrary additional, unrelated certificate validation data — never referenced by any revocation
    /// status information the run uses — must return the same determinate result (here <c>TOTAL-PASSED</c>) that
    /// the run without that extra data returned. Unlike rule c) (additional proofs of existence), plain additional
    /// validation data must never flip a determinate conclusion.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2025:Ensure tasks using 'IDisposable' instances complete before the instances are disposed",
        Justification = "CsCheck's Sample callback is synchronous and cannot await; GetAwaiter().GetResult() blocks until validation fully completes, so the using declarations' dispose runs strictly after every call returns.")]
    public async Task AddingUnrelatedValidationDataNeverFlipsADeterminateConclusion()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using(SignatureValidationOutcome baseline = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime, SignatureValidationCapabilities.All,
            scenario.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(SignatureValidationIndication.TotalPassed, baseline.Conclusion.Indication,
                "Precondition: clause A.3.3 makes this world's with-time result a determinate TOTAL-PASSED, which is exactly the kind of result rule b) protects.");
        }

        Gen.Byte.Array[1, 16].Sample(extraBytes =>
        {
            using PkiCertificateMemory extra = MintPlaceholder(PkiCertificateTags.X509Crl, extraBytes);
            SignatureValidationInputs withExtraData = scenario.Inputs with
            {
                CertificateValidationData = [.. scenario.Inputs.CertificateValidationData, extra]
            };

            using SignatureValidationOutcome outcome = SignatureValidation.ValidateAsync(
                withExtraData, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime, SignatureValidationCapabilities.All,
                scenario.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask().GetAwaiter().GetResult();

            return outcome.Conclusion.Indication == SignatureValidationIndication.TotalPassed;
        });
    }


    /// <summary>Compares two sub-indication lists for the same members regardless of order, since clause 5.1.3 does not mandate an order among them.</summary>
    /// <param name="expected">The first run's sub-indications.</param>
    /// <param name="actual">A later run's sub-indications.</param>
    /// <returns><see langword="true"/> when both lists carry the same sub-indications the same number of times.</returns>
    private static bool SubIndicationsMatch(
        IReadOnlyList<SignatureValidationSubIndication> expected,
        IReadOnlyList<SignatureValidationSubIndication> actual)
    {
        if(expected.Count != actual.Count)
        {
            return false;
        }

        List<SignatureValidationSubIndication> remaining = [.. actual];
        for(int i = 0; i < expected.Count; ++i)
        {
            int index = remaining.IndexOf(expected[i]);
            if(index < 0)
            {
                return false;
            }

            remaining.RemoveAt(index);
        }

        return remaining.Count == 0;
    }


    /// <summary>Wraps bytes in a PKI carrier tagged as an unrelated certificate revocation list — extra validation data no revocation status information in the world ever references.</summary>
    /// <param name="tag">The tag declaring the carrier's kind.</param>
    /// <param name="bytes">The bytes; may be empty.</param>
    /// <returns>The carrier, which the caller disposes.</returns>
    private static PkiCertificateMemory MintPlaceholder(Tag tag, byte[] bytes)
    {
        byte[] content = bytes.Length == 0 ? [0x00] : bytes;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(content.Length);
        content.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }
}
