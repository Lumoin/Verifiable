using System.Diagnostics;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.Cryptography;

/// <summary>
/// Shared instrumentation helpers used by all provider backends to stamp
/// provenance into <see cref="Tag"/> instances and set standard attributes
/// on OpenTelemetry <see cref="Activity"/> spans.
/// </summary>
/// <remarks>
/// <para>
/// Backend libraries hold their own static <see cref="ProviderLibrary"/>,
/// <see cref="CryptoLibraryInfo"/>, and <see cref="ProviderClass"/> instances
/// resolved once at class initialization. They pass those instances to the
/// methods here, which perform the shared work — merging tags and setting
/// span attributes — without duplicating logic across backends.
/// </para>
/// <para>
/// Usage in a backend:
/// </para>
/// <code>
/// private static readonly ProviderLibrary ProviderLib = new(
///     typeof(MyEntropyFunctions).Assembly.GetName().Name ?? "Verifiable.My",
///     typeof(MyEntropyFunctions).Assembly.GetName().Version?.ToString() ?? "Unknown");
///
/// private static readonly CryptoLibraryInfo CryptoLib = new(
///     "My.CryptoLibraryInfo",
///     typeof(SomeType).Assembly.GetName().Version?.ToString() ?? "Unknown");
///
/// private static readonly ProviderClass ProviderCls =
///     new(nameof(MyEntropyFunctions));
///
/// //In GenerateNonce:
/// ProviderOperation operation = new(nameof(GenerateNonce));
/// Tag stamped = CryptoProviderInstrumentation.StampTag(
///     tag, ProviderLib, CryptoLib, ProviderCls, operation);
/// Activity? activity = CryptoActivitySource.Source.StartActivity(
///     CryptoTelemetry.ActivityNames.Nonce);
/// if(activity is not null)
/// {
///     CryptoProviderInstrumentation.SetProviderAttributes(
///         activity, ProviderLib, CryptoLib, ProviderCls, operation);
///     activity.SetTag(CryptoTelemetry.ByteLength, byteLength);
/// }
/// </code>
/// </remarks>
public static class CryptoProviderInstrumentation
{
    /// <summary>
    /// Returns a new <see cref="Tag"/> that merges all entries from
    /// <paramref name="tag"/> with the four provenance entries. Provenance
    /// entries win on key conflict so that backend identity is always present.
    /// </summary>
    /// <param name="tag">The original tag carrying algorithm, purpose, and entropy source.</param>
    /// <param name="providerLibrary">The Verifiable provider library identity.</param>
    /// <param name="cryptoLibrary">The underlying cryptographic library identity.</param>
    /// <param name="providerClass">The class within the provider library.</param>
    /// <param name="operation">The specific method that was called.</param>
    /// <returns>A merged <see cref="Tag"/> containing both original and provenance entries.</returns>
    public static Tag StampTag(
        Tag tag,
        ProviderLibrary providerLibrary,
        CryptoLibraryInfo cryptoLibrary,
        ProviderClass providerClass,
        ProviderOperation operation)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(providerLibrary);
        ArgumentNullException.ThrowIfNull(cryptoLibrary);
        ArgumentNullException.ThrowIfNull(providerClass);
        ArgumentNullException.ThrowIfNull(operation);

        //Collect original entries then append provenance — later entries overwrite
        //earlier ones on duplicate keys, so provenance always wins.
        var entries = new System.Collections.Generic.List<(System.Type, object)>(
            tag.Data.Count + 4);

        foreach(System.Collections.Generic.KeyValuePair<System.Type, object> kv in tag.Data)
        {
            entries.Add((kv.Key, kv.Value));
        }

        entries.Add((typeof(ProviderLibrary), providerLibrary));
        entries.Add((typeof(CryptoLibraryInfo), cryptoLibrary));
        entries.Add((typeof(ProviderClass), providerClass));
        entries.Add((typeof(ProviderOperation), operation));

        return Tag.Create([.. entries]);
    }


    /// <summary>
    /// Sets the six standard provider and library attributes on
    /// <paramref name="activity"/> using <see cref="CryptoTelemetry"/> constants.
    /// </summary>
    /// <param name="activity">The activity to annotate.</param>
    /// <param name="providerLibrary">The Verifiable provider library identity.</param>
    /// <param name="cryptoLibrary">The underlying cryptographic library identity.</param>
    /// <param name="providerClass">The class within the provider library.</param>
    /// <param name="operation">The specific method that was called.</param>
    public static void SetProviderAttributes(
        Activity activity,
        ProviderLibrary providerLibrary,
        CryptoLibraryInfo cryptoLibrary,
        ProviderClass providerClass,
        ProviderOperation operation)
    {
        ArgumentNullException.ThrowIfNull(activity);
        ArgumentNullException.ThrowIfNull(providerLibrary);
        ArgumentNullException.ThrowIfNull(cryptoLibrary);
        ArgumentNullException.ThrowIfNull(providerClass);
        ArgumentNullException.ThrowIfNull(operation);

        activity.SetTag(CryptoTelemetry.Provider.Library, providerLibrary.Name);
        activity.SetTag(CryptoTelemetry.Provider.Version, providerLibrary.Version);
        activity.SetTag(CryptoTelemetry.Provider.Class, providerClass.Name);
        activity.SetTag(CryptoTelemetry.Provider.Operation, operation.Name);
        activity.SetTag(CryptoTelemetry.Library.Name, cryptoLibrary.Name);
        activity.SetTag(CryptoTelemetry.Library.Version, cryptoLibrary.Version);
    }
}