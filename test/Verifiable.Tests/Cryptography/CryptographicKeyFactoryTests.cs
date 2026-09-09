using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Concurrency coverage for <see cref="CryptographicKeyFactory"/>'s custom-function table. Unlike
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>'s write-once-then-immutable matchers,
/// <see cref="CryptographicKeyFactory.RegisterFunction{TFunction}"/> is registered and re-registered during live
/// execution (mirroring, for example, <c>TpmEntropyProviderTests.FactoryPathEmitsTpmEntropyEvent</c>'s
/// qualifier-scoped registration), so the underlying table must tolerate a registration racing concurrent
/// <see cref="CryptographicKeyFactory.GetFunction{TFunction}"/> resolutions of other keys.
/// </summary>
/// <remarks>
/// Per the house race-test discipline, only wrong-code invariants are asserted: no assertion depends on which
/// thread "wins" a race, because every registrar here targets its own unique qualifier and no two threads ever
/// contend for the same key. The registrations this test adds are never removed — <see cref="CryptographicKeyFactory"/>
/// offers no unregistration — but each qualifier is unique to this test run, so the leftover entries are inert:
/// no other test's <see cref="CryptographicKeyFactory.GetFunction{TFunction}"/> call can name their qualifier.
/// </remarks>
[TestClass]
internal sealed class CryptographicKeyFactoryTests
{
    /// <summary>How many threads concurrently register their own, uniquely-qualified function.</summary>
    private const int RegistrarCount = 16;

    /// <summary>How many threads concurrently resolve the pre-registered, never-mutated control key.</summary>
    private const int ReaderCount = 16;

    /// <summary>How many resolutions each reader thread performs against the control key.</summary>
    private const int IterationsPerReader = 3000;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Races <see cref="RegistrarCount"/> registrars (each on its own unique qualifier) against
    /// <see cref="ReaderCount"/> readers of a separately pre-registered, never-mutated control key. Proves: (1)
    /// no exception escapes any participant — an unsynchronized <see cref="System.Collections.Generic.Dictionary{TKey, TValue}"/>
    /// under exactly this shape would risk "Collection was modified" or bucket-array corruption, which is why the
    /// table is a <see cref="System.Collections.Concurrent.ConcurrentDictionary{TKey, TValue}"/>; (2) after every thread joins, each registrar's own qualifier resolves to exactly the delegate that
    /// registrar registered, so no write was lost or overwritten by a different key's concurrent registration;
    /// (3) the control key's delegate is unchanged and every one of its <see cref="IterationsPerReader"/> reads
    /// per reader thread, taken during the race, returned that exact delegate — concurrent writes to other keys
    /// never disrupted a concurrent read.
    /// </summary>
    [TestMethod]
    public async Task RegistrarsOnDistinctQualifiersRaceReadersOfAnUnmutatedControlKeyWithNoLostWritesOrDisruptedReads()
    {
        string runId = $"{nameof(CryptographicKeyFactoryTests)}-{Guid.NewGuid():N}";
        Type functionType = typeof(Func<int, int>);

        string controlQualifier = $"{runId}-control";
        Func<int, int> controlDelegate = static value => value + 1;
        CryptographicKeyFactory.RegisterFunction(functionType, controlDelegate, controlQualifier);

        var registrarQualifiers = new string[RegistrarCount];
        var registrarDelegates = new Func<int, int>[RegistrarCount];
        for(int i = 0; i < RegistrarCount; i++)
        {
            registrarQualifiers[i] = $"{runId}-registrar-{i}";
            int captured = i;
            registrarDelegates[i] = value => value + captured;
        }

        var startGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int arrivedCount = 0;
        int participantCount = RegistrarCount + ReaderCount;
        var escapedExceptions = new ConcurrentBag<Exception>();

        async Task ArriveAndWaitAsync()
        {
            if(Interlocked.Increment(ref arrivedCount) == participantCount)
            {
                startGate.SetResult();
            }

            await startGate.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        }

        async Task RunRegistrarAsync(int index)
        {
            await ArriveAndWaitAsync().ConfigureAwait(false);
            try
            {
                CryptographicKeyFactory.RegisterFunction(functionType, registrarDelegates[index], registrarQualifiers[index]);
            }
            catch(Exception ex)
            {
                escapedExceptions.Add(ex);
            }
        }

        async Task RunReaderAsync()
        {
            await ArriveAndWaitAsync().ConfigureAwait(false);
            try
            {
                for(int i = 0; i < IterationsPerReader; i++)
                {
                    Func<int, int>? resolved = CryptographicKeyFactory.GetFunction<Func<int, int>>(functionType, controlQualifier);
                    if(!ReferenceEquals(resolved, controlDelegate))
                    {
                        throw new InvalidOperationException(
                            $"The control key resolved to an unexpected delegate (iteration {i}): expected the pre-registered control delegate.");
                    }
                }
            }
            catch(Exception ex)
            {
                escapedExceptions.Add(ex);
            }
        }

        var participants = new Task[participantCount];
        for(int i = 0; i < RegistrarCount; i++)
        {
            int captured = i;
            participants[i] = Task.Run(() => RunRegistrarAsync(captured), TestContext.CancellationToken);
        }

        for(int i = 0; i < ReaderCount; i++)
        {
            participants[RegistrarCount + i] = Task.Run(RunReaderAsync, TestContext.CancellationToken);
        }

        await Task.WhenAll(participants).WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(escapedExceptions.IsEmpty, $"No exception may escape concurrent registration/resolution; first: {(escapedExceptions.IsEmpty ? null : escapedExceptions.First())}");

        for(int i = 0; i < RegistrarCount; i++)
        {
            Func<int, int>? resolved = CryptographicKeyFactory.GetFunction<Func<int, int>>(functionType, registrarQualifiers[i]);
            Assert.IsNotNull(resolved, $"Registrar {i}'s own qualifier must resolve to a delegate after the race.");
            Assert.AreSame(registrarDelegates[i], resolved, $"Registrar {i}'s own qualifier must resolve to exactly the delegate it registered.");
        }

        Func<int, int>? controlResolved = CryptographicKeyFactory.GetFunction<Func<int, int>>(functionType, controlQualifier);
        Assert.AreSame(controlDelegate, controlResolved, "The control key's delegate must be unchanged by the race.");
    }
}
