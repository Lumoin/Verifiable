using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Verifiable.Core.Assessment;


namespace Verifiable.Tests.Assertion
{
    [TestClass]
    internal sealed class ClaimIdTests
    {
        //TODO:
        /// <summary>
        /// This collects the library defined, or pre-defined, static instances of <see cref="ClaimId"/>.
        /// </summary>
        private static IEnumerable<PropertyInfo> AllClaimIdProperties => typeof(ClaimId)
                .GetProperties(BindingFlags.Public | BindingFlags.Static)
                .Where(prop => prop.PropertyType == typeof(ClaimId));


        /// <summary>
        /// Ensures that each ClaimId static instance has a unique non-empty description.
        /// This test helps guard against potential copy-paste errors or inadvertent duplications
        /// which could arise during library development.
        [TestMethod]
        public void AllStaticInstancesHaveUniqueNonEmptyDescriptions()
        {
            //This hold the descriptions to detect duplicates in case there are any.
            var descriptions = new Dictionary<string, ClaimId>();

            foreach(var staticProperty in AllClaimIdProperties)
            {
                //1. Get the static instance of ClaimId.
                ClaimId claimId2Instance = (ClaimId)staticProperty.GetValue(null)!;

                //2. Get its description.
                var description = claimId2Instance.ToString();

                //3. Check if the description is unique.
                Assert.IsNotNull(description);
                Assert.IsFalse(descriptions.ContainsKey(description), $"Duplicate description found: {description} for {staticProperty.Name} and {claimId2Instance}");

                //Add the description to the dictionary indexed by the description so that
                //potential duplicates can be detected.
                descriptions.Add(description, claimId2Instance);
            }
        }


        /// <summary>
        /// Validates that the total count of static ClaimId instances matches the expected count
        /// and that identifiers are what is expected unless they are changed also in the tests.
        /// This test acts as a guard against accidental change, removal or addition of ClaimId instances,
        /// ensuring that the library's ClaimId definitions remain aligned with expectations.
        /// </summary>
        [TestMethod]
        public void AllStaticInstancesCountMatchesExpectedCount()
        {
            var expectedIds = new Dictionary<string, (int Code, string Description)>
            {
                { nameof(ClaimId.FailedClaim), (0, "FailedToGenerateClaims") },
                { nameof(ClaimId.EcMissingCurve), (1, "EcMissingCurve") },
                { nameof(ClaimId.EcMissingXCoordinate), (2, "EcMissingXCoordinate") },
                { nameof(ClaimId.EcMissingYCoordinate), (3, "EcMissingYCoordinate") },
                { nameof(ClaimId.EcValidAlgAndCrvCombination), (4, "EcValidAlgAndCrvCombination") },
                { nameof(ClaimId.EcAlgOptionalAndNotPresentOrEmpty), (6, "EcAlgOptionalAndNotPresentOrEmpty") },
                { nameof(ClaimId.AlgExists), (7, "AlgExists") },
                { nameof(ClaimId.AlgIsNone), (8, "AlgIsNone") },
                { nameof(ClaimId.AlgIsValid), (9, "AlgIsValid") },
                { nameof(ClaimId.KtyMissingOrEmpty), (10, "KtyMissingOrEmpty") },
                { nameof(ClaimId.EcKeyType), (11, "EcKeyType") },
                { nameof(ClaimId.RsaKeyType), (12, "RsaKeyType") },
                { nameof(ClaimId.OctKeyType), (13, "OctKeyType") },
                { nameof(ClaimId.OkpKeyType), (14, "OkpKeyType") },
                { nameof(ClaimId.UnsupportedKeyType), (15, "UnsupportedKeyType") },
                { nameof(ClaimId.RsaMissingExponent), (100, "RsaMissingExponent") },
                { nameof(ClaimId.RsaMissingModulus), (101, "RsaMissingModulus") },
                { nameof(ClaimId.RsaKeyValid), (102, "RsaKeyValid") },
                { nameof(ClaimId.RsaKeyInvalid), (103, "RsaKeyInvalid") },
                { nameof(ClaimId.OkpMissingCurve), (200, "OkpMissingCurve") },
                { nameof(ClaimId.OkpAlgShouldNotBePresentForX25519), (201, "OkpAlgShouldNotBePresentForX25519") },
                { nameof(ClaimId.OkpValidAlgAndCrvCombination), (202, "OkpValidAlgAndCrvCombination") },
                { nameof(ClaimId.OkpAlgOptionalOrNotPresent), (204, "OkpAlgOptionalOrNotPresent") },
                { nameof(ClaimId.DidCoreJsonLdUriAsFirst), (300, "DidCoreJsonLdUriAsFirst") },
                { nameof(ClaimId.DidDocumentPrefix), (400, "DidDocumentPrefix") },
                { nameof(ClaimId.KeyDidPrefix), (500, "KeyDidPrefix") },
                { nameof(ClaimId.KeyDidIdEncoding), (501, "KeyDidIdEncoding") },
                { nameof(ClaimId.KeyDidIdFormat), (502, "KeyDidIdFormat") },
                { nameof(ClaimId.KeyDidSingleVerificationMethod), (503, "KeyDidSingleVerificationMethod") },
                { nameof(ClaimId.KeyDidKeyFormat), (504, "KeyDidKeyFormat") },
                { nameof(ClaimId.KeyDidIdPrefixMatch), (505, "KeyDidIdPrefixMatch") },
                { nameof(ClaimId.KeyDidIdPrefixMismatch), (506, "KeyDidIdPrefixMismatch") },
                { nameof(ClaimId.KeyDidIdPrefixMissing), (507, "KeyDidIdPrefixMissing") },
                { nameof(ClaimId.KeyDidFragmentIdentifierRepetition), (508, "KeyDidFragmentIdentifierRepetition") },
                { nameof(ClaimId.WebDidIdEncoding), (600, "WebDidIdEncoding") },
                { nameof(ClaimId.WebDidIdFormat), (601, "WebDidIdFormat") },
                { nameof(ClaimId.WebDidKeyFormat), (602, "WebDidKeyFormat") }
            };

            var reflectedIds = AllClaimIdProperties.ToDictionary(
                prop => prop.Name,
                prop =>
                (
                    ReflectedCode: ((ClaimId)prop.GetValue(null)!).Code,
                    ReflectedDescription: ((ClaimId)prop.GetValue(null)!).ToString()
                )
            );

            Assert.HasCount(expectedIds.Count, reflectedIds);
            foreach(var expectedId in expectedIds)
            {
                Assert.IsTrue(reflectedIds.ContainsKey(expectedId.Key), $"Missing predefined ID: {expectedId.Key}");
                Assert.AreEqual(expectedId.Value.Code, reflectedIds[expectedId.Key].ReflectedCode);
                Assert.AreEqual(expectedId.Value.Description, reflectedIds[expectedId.Key].ReflectedDescription);
            }
        }


        [TestMethod]
        public void NotPossibleToSaveDuplicateId()
        {
            const int TestClaimCode = 100_001;
            const string TestDescription = "TestDescription";
            var customCode1 = ClaimId.Create(TestClaimCode, TestDescription);

            var exception = Assert.ThrowsExactly<ArgumentException>(() => ClaimId.Create(TestClaimCode, TestDescription));
        }


        /// <summary>
        /// The first code of the band this class races over. It sits far from every band the shipped registries
        /// allocate from and far from the band <see cref="CreateReturnsClaimIdForValidInput"/> draws in, so a
        /// code raced here can only collide with itself.
        /// </summary>
        private static int RaceBandStart { get; } = 1_500_000;

        /// <summary>How many fresh codes the concurrent-allocation test races over.</summary>
        private static int RaceRounds { get; } = 200;

        /// <summary>How many threads race for each of those codes.</summary>
        private static int RaceThreads { get; } = 4;


        /// <summary>
        /// Allocating one code from several threads at once lets exactly one through and refuses every other one
        /// the way the registry documents — which holds only while the duplicate check and the insertion are one
        /// atomic step.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <strong>What a check outside the lock costs.</strong> When the duplicate check reads the shared
        /// dictionary before the lock the insertion takes, two threads can both find the code absent and both go
        /// on to insert it. One inserts; the other is refused by the dictionary rather than by the registry, so
        /// the caller sees a different exception than the one the registry promises — the observable half of a
        /// check-then-act window whose other half is an unsynchronised read of a collection that is not
        /// thread-safe.
        /// </para>
        /// <para>
        /// The assertions are therefore about the refusal itself: exactly one winner per code, every loser
        /// refused with the registry's own message, and no thread reaching any exception type other than the one
        /// documented — which is what an unsynchronised read of a dictionary being resized or initialised would
        /// produce.
        /// </para>
        /// </remarks>
        [TestMethod]
        public void ConcurrentAllocationOfOneCodeLetsExactlyOneThroughAndRefusesTheRestTheDocumentedWay()
        {
            for(int round = 0; round < RaceRounds; ++round)
            {
                int code = RaceBandStart + round;
                var outcomes = new Exception?[RaceThreads];
                var attempted = new bool[RaceThreads];
                using var start = new Barrier(RaceThreads);
                var racers = new Thread[RaceThreads];
                for(int i = 0; i < RaceThreads; ++i)
                {
                    racers[i] = new Thread(Race) { IsBackground = true };
                    racers[i].Start(new RaceAttempt(code, i, start, outcomes, attempted));
                }

                for(int i = 0; i < RaceThreads; ++i)
                {
                    racers[i].Join();
                }

                int winners = 0;
                for(int i = 0; i < RaceThreads; ++i)
                {
                    Assert.IsTrue(attempted[i], $"Racer {i} of code {code} never reached the allocation.");

                    if(outcomes[i] is null)
                    {
                        ++winners;
                        continue;
                    }

                    var refusal = Assert.IsInstanceOfType<ArgumentException>(
                        outcomes[i],
                        $"Racer {i} of code {code} was refused with {outcomes[i]!.GetType().Name}: {outcomes[i]!.Message}");

                    Assert.Contains(
                        $"code {code} already exists",
                        refusal.Message,
                        StringComparison.Ordinal,
                        $"Racer {i} of code {code} was refused by the dictionary rather than by the registry: {refusal.Message}");
                }

                Assert.AreEqual(1, winners, $"Exactly one racer allocates code {code}.");

                //And the registry is consistent afterwards, whichever racer won.
                ArgumentException afterwards = Assert.ThrowsExactly<ArgumentException>(
                    () => ClaimId.Create(code, $"AFTERWARDS-{code}"));

                Assert.Contains($"code {code} already exists", afterwards.Message, StringComparison.Ordinal);
            }
        }


        /// <summary>
        /// What one racing thread needs: the code to allocate, which racer it is, the barrier releasing them
        /// together, and where to record what happened. Passed as the thread's own parameter rather than captured,
        /// so nothing is shared implicitly.
        /// </summary>
        /// <param name="Code">The code every racer of this round allocates.</param>
        /// <param name="Index">Which racer this is, and the slot it records into.</param>
        /// <param name="Start">The barrier releasing the racers of one round together.</param>
        /// <param name="Outcomes">One slot per racer: the exception it was refused with, or <see langword="null"/> when it allocated.</param>
        /// <param name="Attempted">One slot per racer, set once it has reached the allocation at all.</param>
        private sealed record RaceAttempt(
            int Code,
            int Index,
            Barrier Start,
            Exception?[] Outcomes,
            bool[] Attempted);


        /// <summary>
        /// One racing thread: waits for its siblings, allocates, and records what happened.
        /// </summary>
        /// <param name="state">The <see cref="RaceAttempt"/> the thread was started with.</param>
        private static void Race(object? state)
        {
            var attempt = (RaceAttempt)state!;
            attempt.Start.SignalAndWait();
            try
            {
                _ = ClaimId.Create(attempt.Code, $"RACE-{attempt.Code}-{attempt.Index}");
                attempt.Outcomes[attempt.Index] = null;
            }
            catch(Exception thrown)
            {
                attempt.Outcomes[attempt.Index] = thrown;
            }
            finally
            {
                attempt.Attempted[attempt.Index] = true;
            }
        }


        [TestMethod]
        public void NotPossibleToUseDefaultConstructor()
        {
            var exception = Assert.ThrowsExactly<InvalidOperationException>(() => new ClaimId());
            Assert.AreEqual("Use Create.", exception.Message);
        }


        [TestMethod]
        [DataRow(0)]
        [DataRow(-1)]
        [DataRow(-100)]
        public void CreateThrowsArgumentOutOfRangeExceptionForNonPositiveCode(int code)
        {
            var exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => ClaimId.Create(code, "Description"));
            Assert.AreEqual(nameof(code), exception.ParamName);
            Assert.AreEqual(code, exception.ActualValue);
            Assert.IsTrue(
                exception.Message.Contains("Value must be greater than zero.", StringComparison.InvariantCulture),
                $"Expected message to contain 'Value must be greater than zero.' but got: '{exception.Message}'");
        }


        [TestMethod]
        public void CreateThrowsArgumentExceptionForEmptyDescription()
        {
            var exception = Assert.ThrowsExactly<ArgumentException>(() => ClaimId.Create(1, string.Empty));
            Assert.AreEqual("description", exception.ParamName);
            Assert.IsTrue(
                exception.Message.Contains("The value cannot be an empty string. (Parameter 'description')", StringComparison.InvariantCulture),
                $"Expected message to contain 'Value must be greater than zero.' but got: '{exception.Message}'");
        }


        [TestMethod]
        [SuppressMessage("Security", "CA5394:Do not use insecure randomness", Justification = "This is some test data without needing cryptographic security.")]
        public void CreateReturnsClaimIdForValidInput()
        {
            //This genereates a unique claim ID for testing purposes. The values are held in a static dictionary
            //and the testing framework may (or even likely) retains a cache between test runs. Which means
            //that we need to test the ability to insert a unique value so that we're sure such a value is generated
            //per test run.
            const int MaxAttempts = 1000;
            var random = new Random();
            for(int attempt = 0; attempt < MaxAttempts; ++attempt)
            {
                int code = random.Next(100_005, 200_000);
                string description = Guid.NewGuid().ToString();
                try
                {
                    //Tries to create a ClaimId to validate code and description.
                    //If it succeeds, the values are valid and unique.
                    var claimId = ClaimId.Create(code, description);
                    Assert.AreEqual(code, claimId.Code);
                    Assert.AreEqual(description, claimId.ToString());
                }
                catch(ArgumentOutOfRangeException) { }
                catch(ArgumentException) { }
            }
        }


        [TestMethod]
        public void CanRetrieveLibraryDefinedClaimId()
        {
            //This is just some claim identifier that is
            //picked for testing.
            var claimId = ClaimId.OctKeyType;
            Assert.AreEqual(13, claimId.Code);
        }
    }
}
