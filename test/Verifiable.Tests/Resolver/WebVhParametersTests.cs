using System.Collections.Immutable;
using Verifiable.Core.Did.Methods.WebVh;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebVhParameters"/> folding — the did:webvh parameter state machine: the first-entry
/// MUSTs and defaults (<see cref="WebVhParameters.FoldGenesis"/>) and the retention and constraint rules for
/// subsequent entries (<see cref="WebVhParameters.Fold"/>).
/// </summary>
[TestClass]
internal sealed class WebVhParametersTests
{
    private const string UpdateKey = "z6MkgzBDcBFV3sk4ypPE5YXMZHmS213A3HpYY2LmcVKV15jr";
    private const string Scid = "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE";
    private const string NextHash = "QmZreDcjvWEpyRFznQeExWNCsvMLk5i59AcRJJuQC8UodJ";


    private static WebVhParameters Genesis(WebVhDeclaredParameters? overrides = null)
    {
        WebVhDeclaredParameters declared = overrides ?? new WebVhDeclaredParameters
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = [UpdateKey]
        };

        (WebVhParameters? parameters, string? error) = WebVhParameters.FoldGenesis(declared);
        Assert.IsNull(error, $"Genesis fold MUST succeed. Error: {error}.");
        Assert.IsNotNull(parameters);

        return parameters!;
    }


    /// <summary>A minimal genesis entry yields the specification defaults for the omitted parameters.</summary>
    [TestMethod]
    public void GenesisAppliesDefaultsForOmittedParameters()
    {
        WebVhParameters parameters = Genesis();

        Assert.AreEqual(WebVhParameters.SupportedMethod, parameters.Method);
        Assert.AreEqual(Scid, parameters.Scid);
        Assert.HasCount(1, parameters.UpdateKeys);
        Assert.AreEqual(UpdateKey, parameters.UpdateKeys[0]);
        Assert.IsEmpty(parameters.NextKeyHashes, "nextKeyHashes defaults to an empty array.");
        Assert.IsFalse(parameters.IsPreRotationActive);
        Assert.IsFalse(parameters.Portable, "portable defaults to false.");
        Assert.IsFalse(parameters.Deactivated, "deactivated defaults to false.");
        Assert.AreEqual(WebVhParameters.DefaultTtlSeconds, parameters.Ttl, "ttl defaults to 3600.");
    }


    /// <summary>A non-empty nextKeyHashes in the genesis entry activates pre-rotation.</summary>
    [TestMethod]
    public void GenesisWithNextKeyHashesActivatesPreRotation()
    {
        WebVhParameters parameters = Genesis(new WebVhDeclaredParameters
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = [UpdateKey],
            NextKeyHashes = [NextHash]
        });

        Assert.IsTrue(parameters.IsPreRotationActive);
        Assert.AreEqual(NextHash, parameters.NextKeyHashes[0]);
    }


    [TestMethod]
    public void GenesisRequiresMethod()
    {
        (WebVhParameters? parameters, string? error) = WebVhParameters.FoldGenesis(new WebVhDeclaredParameters { Scid = Scid, UpdateKeys = [UpdateKey] });

        Assert.IsNull(parameters);
        Assert.IsNotNull(error);
    }


    [TestMethod]
    public void GenesisRejectsUnsupportedMethod()
    {
        (WebVhParameters? parameters, string? error) = WebVhParameters.FoldGenesis(new WebVhDeclaredParameters { Method = "did:webvh:0.5", Scid = Scid, UpdateKeys = [UpdateKey] });

        Assert.IsNull(parameters);
        Assert.IsNotNull(error);
    }


    [TestMethod]
    public void GenesisRequiresScid()
    {
        (WebVhParameters? parameters, string? error) = WebVhParameters.FoldGenesis(new WebVhDeclaredParameters { Method = WebVhParameters.SupportedMethod, UpdateKeys = [UpdateKey] });

        Assert.IsNull(parameters);
        Assert.IsNotNull(error);
    }


    [TestMethod]
    public void GenesisRequiresNonEmptyUpdateKeys()
    {
        (WebVhParameters? withoutKeys, string? error1) = WebVhParameters.FoldGenesis(new WebVhDeclaredParameters { Method = WebVhParameters.SupportedMethod, Scid = Scid });
        Assert.IsNull(withoutKeys);
        Assert.IsNotNull(error1);

        (WebVhParameters? emptyKeys, string? error2) = WebVhParameters.FoldGenesis(new WebVhDeclaredParameters { Method = WebVhParameters.SupportedMethod, Scid = Scid, UpdateKeys = ImmutableArray<string>.Empty });
        Assert.IsNull(emptyKeys);
        Assert.IsNotNull(error2);
    }


    /// <summary>Parameters omitted in a subsequent entry retain their accumulated values.</summary>
    [TestMethod]
    public void SubsequentRetainsOmittedParameters()
    {
        WebVhParameters prior = Genesis(new WebVhDeclaredParameters
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = [UpdateKey],
            NextKeyHashes = [NextHash],
            Ttl = 60
        });

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters());

        Assert.IsNull(error);
        Assert.IsNotNull(next);
        Assert.AreEqual(prior.Method, next!.Method);
        Assert.AreEqual(prior.Scid, next.Scid);
        Assert.AreSequenceEqual(prior.UpdateKeys, next.UpdateKeys);
        Assert.AreSequenceEqual(prior.NextKeyHashes, next.NextKeyHashes);
        Assert.AreEqual(60, next.Ttl);
    }


    /// <summary>A present parameter overrides the accumulated value (here updateKeys rotate).</summary>
    [TestMethod]
    public void SubsequentOverridesPresentParameters()
    {
        const string rotatedKey = "z6MkrotateddKeyExampleValueXXXXXXXXXXXXXXXXXXXXXX";
        WebVhParameters prior = Genesis();

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters { UpdateKeys = [rotatedKey], Deactivated = true });

        Assert.IsNull(error);
        Assert.IsNotNull(next);
        Assert.HasCount(1, next!.UpdateKeys);
        Assert.AreEqual(rotatedKey, next.UpdateKeys[0]);
        Assert.IsTrue(next.Deactivated);
    }


    [TestMethod]
    public void SubsequentRejectsScid()
    {
        WebVhParameters prior = Genesis();

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters { Scid = Scid });

        Assert.IsNull(next);
        Assert.IsNotNull(error);
    }


    [TestMethod]
    public void SubsequentRejectsTurningPortableTrue()
    {
        WebVhParameters prior = Genesis();

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters { Portable = true });

        Assert.IsNull(next);
        Assert.IsNotNull(error);
    }


    /// <summary>A portable DID MAY be turned non-portable in a later entry.</summary>
    [TestMethod]
    public void SubsequentAllowsTurningPortableFalse()
    {
        WebVhParameters prior = Genesis(new WebVhDeclaredParameters
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = [UpdateKey],
            Portable = true
        });

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters { Portable = false });

        Assert.IsNull(error);
        Assert.IsNotNull(next);
        Assert.IsFalse(next!.Portable);
    }


    /// <summary>Setting nextKeyHashes to an empty array in a later entry deactivates pre-rotation.</summary>
    [TestMethod]
    public void SubsequentEmptyNextKeyHashesDeactivatesPreRotation()
    {
        WebVhParameters prior = Genesis(new WebVhDeclaredParameters
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = [UpdateKey],
            NextKeyHashes = [NextHash]
        });
        Assert.IsTrue(prior.IsPreRotationActive);

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters { NextKeyHashes = ImmutableArray<string>.Empty });

        Assert.IsNull(error);
        Assert.IsNotNull(next);
        Assert.IsFalse(next!.IsPreRotationActive);
    }


    private const string WitnessA = "did:key:z6MkgzBDcBFV3sk4ypPE5YXMZHmS213A3HpYY2LmcVKV15jr";
    private const string WitnessB = "did:key:z6Mkt7yChY5h3RcirHovaY8FQpapxJrDR8jBkLQwskewgmAB";


    /// <summary>The witness parameter defaults to no active rule in a genesis entry that omits it.</summary>
    [TestMethod]
    public void GenesisWithoutWitnessHasNoActiveRule()
    {
        WebVhParameters parameters = Genesis();

        Assert.IsNull(parameters.Witness);
        Assert.IsFalse(parameters.IsWitnessActive);
    }


    /// <summary>A genesis entry declaring a valid witness rule activates witnessing immediately.</summary>
    [TestMethod]
    public void GenesisWithWitnessRuleActivatesWitnessing()
    {
        WebVhParameters parameters = Genesis(WithWitness(new WebVhWitnessDeclaration(new WebVhWitnessRule(1, [WitnessA]))));

        Assert.IsNotNull(parameters.Witness);
        Assert.IsTrue(parameters.IsWitnessActive);
        Assert.AreEqual(1, parameters.Witness!.Threshold);
        Assert.AreEqual(WitnessA, parameters.Witness.Witnesses[0]);
    }


    /// <summary>The empty witness object {} in the genesis entry yields no active rule.</summary>
    [TestMethod]
    public void GenesisWithEmptyWitnessHasNoActiveRule()
    {
        WebVhParameters parameters = Genesis(WithWitness(new WebVhWitnessDeclaration(null)));

        Assert.IsNull(parameters.Witness);
    }


    [TestMethod]
    public void GenesisRejectsThresholdBelowOne()
    {
        (WebVhParameters? parameters, string? error) = WebVhParameters.FoldGenesis(WithWitness(new WebVhWitnessDeclaration(new WebVhWitnessRule(0, [WitnessA]))));

        Assert.IsNull(parameters);
        Assert.IsNotNull(error);
    }


    [TestMethod]
    public void GenesisRejectsThresholdAboveWitnessCount()
    {
        (WebVhParameters? parameters, string? error) = WebVhParameters.FoldGenesis(WithWitness(new WebVhWitnessDeclaration(new WebVhWitnessRule(2, [WitnessA]))));

        Assert.IsNull(parameters);
        Assert.IsNotNull(error);
    }


    [TestMethod]
    public void GenesisRejectsEmptyWitnessList()
    {
        (WebVhParameters? parameters, string? error) = WebVhParameters.FoldGenesis(WithWitness(new WebVhWitnessDeclaration(new WebVhWitnessRule(1, ImmutableArray<string>.Empty))));

        Assert.IsNull(parameters);
        Assert.IsNotNull(error);
    }


    [TestMethod]
    public void GenesisRejectsNonDidKeyWitness()
    {
        (WebVhParameters? parameters, string? error) = WebVhParameters.FoldGenesis(WithWitness(new WebVhWitnessDeclaration(new WebVhWitnessRule(1, ["did:web:example.com"]))));

        Assert.IsNull(parameters);
        Assert.IsNotNull(error);
    }


    [TestMethod]
    public void GenesisRejectsDuplicateWitness()
    {
        (WebVhParameters? parameters, string? error) = WebVhParameters.FoldGenesis(WithWitness(new WebVhWitnessDeclaration(new WebVhWitnessRule(1, [WitnessA, WitnessA]))));

        Assert.IsNull(parameters);
        Assert.IsNotNull(error);
    }


    /// <summary>An entry that omits the witness parameter retains the accumulated rule.</summary>
    [TestMethod]
    public void SubsequentRetainsWitnessWhenOmitted()
    {
        WebVhParameters prior = Genesis(WithWitness(new WebVhWitnessDeclaration(new WebVhWitnessRule(1, [WitnessA]))));

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters());

        Assert.IsNull(error);
        Assert.IsNotNull(next);
        Assert.IsNotNull(next!.Witness);
        Assert.AreEqual(WitnessA, next.Witness!.Witnesses[0]);
    }


    /// <summary>The empty witness object {} in a later entry disables witnessing going forward.</summary>
    [TestMethod]
    public void SubsequentEmptyWitnessDisablesWitnessing()
    {
        WebVhParameters prior = Genesis(WithWitness(new WebVhWitnessDeclaration(new WebVhWitnessRule(1, [WitnessA]))));

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters { Witness = new WebVhWitnessDeclaration(null) });

        Assert.IsNull(error);
        Assert.IsNotNull(next);
        Assert.IsNull(next!.Witness);
        Assert.IsFalse(next.IsWitnessActive);
    }


    /// <summary>A later entry MAY replace the active witness rule with a new one.</summary>
    [TestMethod]
    public void SubsequentReplacesWitnessRule()
    {
        WebVhParameters prior = Genesis(WithWitness(new WebVhWitnessDeclaration(new WebVhWitnessRule(1, [WitnessA]))));

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters { Witness = new WebVhWitnessDeclaration(new WebVhWitnessRule(2, [WitnessA, WitnessB])) });

        Assert.IsNull(error);
        Assert.IsNotNull(next);
        Assert.AreEqual(2, next!.Witness!.Threshold);
        Assert.HasCount(2, next.Witness.Witnesses);
    }


    private static WebVhDeclaredParameters WithWitness(WebVhWitnessDeclaration witness)
    {
        return new WebVhDeclaredParameters
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = [UpdateKey],
            Witness = witness
        };
    }


    private const string WatcherA = "https://watcher-a.example/watch";
    private const string WatcherB = "https://watcher-b.example/watch";


    /// <summary>The watchers parameter defaults to an empty list in a genesis entry that omits it.</summary>
    [TestMethod]
    public void GenesisWithoutWatchersDefaultsToEmpty()
    {
        WebVhParameters parameters = Genesis();

        Assert.IsEmpty(parameters.Watchers);
    }


    [TestMethod]
    public void GenesisWithWatchersSetsThem()
    {
        WebVhParameters parameters = Genesis(new WebVhDeclaredParameters
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = [UpdateKey],
            Watchers = [WatcherA]
        });

        Assert.HasCount(1, parameters.Watchers);
        Assert.AreEqual(WatcherA, parameters.Watchers[0]);
    }


    [TestMethod]
    public void SubsequentRetainsWatchersWhenOmitted()
    {
        WebVhParameters prior = Genesis(new WebVhDeclaredParameters
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = [UpdateKey],
            Watchers = [WatcherA]
        });

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters());

        Assert.IsNull(error);
        Assert.IsNotNull(next);
        Assert.AreSequenceEqual(prior.Watchers, next!.Watchers);
    }


    [TestMethod]
    public void SubsequentReplacesWatchers()
    {
        WebVhParameters prior = Genesis(new WebVhDeclaredParameters
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = [UpdateKey],
            Watchers = [WatcherA]
        });

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters { Watchers = [WatcherB] });

        Assert.IsNull(error);
        Assert.IsNotNull(next);
        Assert.HasCount(1, next!.Watchers);
        Assert.AreEqual(WatcherB, next.Watchers[0]);
    }


    /// <summary>An empty watchers array replaces (clears) the accumulated list.</summary>
    [TestMethod]
    public void SubsequentEmptyWatchersClears()
    {
        WebVhParameters prior = Genesis(new WebVhDeclaredParameters
        {
            Method = WebVhParameters.SupportedMethod,
            Scid = Scid,
            UpdateKeys = [UpdateKey],
            Watchers = [WatcherA]
        });

        (WebVhParameters? next, string? error) = WebVhParameters.Fold(prior, new WebVhDeclaredParameters { Watchers = ImmutableArray<string>.Empty });

        Assert.IsNull(error);
        Assert.IsNotNull(next);
        Assert.IsEmpty(next!.Watchers);
    }
}
