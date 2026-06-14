using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// Attribute name constants and activity name constants for cryptographic
/// OpenTelemetry instrumentation.
/// </summary>
/// <remarks>
/// <para>
/// Use these constants when setting attributes on <see cref="System.Diagnostics.Activity"/>
/// instances or when querying collected spans in your observability backend. All
/// attribute names follow the <c>crypto.*</c> namespace convention.
/// </para>
/// <para>
/// Example — subscribing and reading attributes:
/// </para>
/// <code>
/// using var tracerProvider = Sdk.CreateTracerProviderBuilder()
///     .AddSource(CryptoActivitySource.Name)
///     .AddOtlpExporter()
///     .Build();
///
/// //In your telemetry sink:
/// string? library = span.GetTagItem(CryptoTelemetry.Library.Name) as string;
/// string? version = span.GetTagItem(CryptoTelemetry.Library.Version) as string;
/// </code>
/// </remarks>
public static class CryptoTelemetry
{
    /// <summary>
    /// Attribute names describing the Verifiable provider abstraction layer —
    /// the library within the Verifiable family that dispatched the operation.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "Intentional grouping of related constants — same pattern as WellKnownMediaTypes.")]
    public static class Provider
    {
        /// <summary>Name of the provider library, e.g. <c>Verifiable.Microsoft</c>.</summary>
        public const string Library = "crypto.provider.library";

        /// <summary>Version of the provider library assembly.</summary>
        public const string Version = "crypto.provider.version";

        /// <summary>Class within the provider library, e.g. <c>MicrosoftEntropyFunctions</c>.</summary>
        public const string Class = "crypto.provider.class";

        /// <summary>Method that was called, e.g. <c>GenerateNonce</c>.</summary>
        public const string Operation = "crypto.provider.operation";
    }


    /// <summary>
    /// Attribute names describing the underlying cryptographic library that
    /// performed the actual work — the primary CBOM identifier.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "Intentional grouping of related constants — same pattern as WellKnownMediaTypes.")]
    public static class Library
    {
        /// <summary>
        /// Name of the underlying crypto library, e.g.
        /// <c>System.Security.Cryptography</c> or <c>Org.BouncyCastle.Cryptography</c>.
        /// </summary>
        public const string Name = "crypto.library.name";

        /// <summary>Version of the underlying crypto library.</summary>
        public const string Version = "crypto.library.version";
    }


    /// <summary>
    /// Attribute names specific to <see cref="Nonce"/> lifetime spans.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "Intentional grouping of related constants — same pattern as WellKnownMediaTypes.")]
    public static class Nonce
    {
        /// <summary>
        /// The value of <see cref="Verifiable.Cryptography.Nonce.UseCount"/> at the
        /// time <see cref="Verifiable.Cryptography.Nonce.UseNonce"/> was called.
        /// Emitted on every call — a value greater than one is a replay signal.
        /// </summary>
        public const string UseCount = "crypto.nonce.use_count";

        /// <summary>
        /// The final value of <see cref="Verifiable.Cryptography.Nonce.UseCount"/>
        /// at disposal time.
        /// </summary>
        public const string FinalUseCount = "crypto.nonce.final_use_count";

        /// <summary>
        /// <see langword="true"/> if <see cref="Verifiable.Cryptography.Nonce.UseNonce"/>
        /// was called at least once before disposal; <see langword="false"/> otherwise.
        /// An unused nonce indicates a protocol error or early abandonment.
        /// </summary>
        public const string Used = "crypto.nonce.used";
    }


    /// <summary>
    /// Attribute names specific to <see cref="DigestValue"/> lifetime spans.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "Intentional grouping of related constants — same pattern as WellKnownMediaTypes.")]
    public static class Digest
    {
        /// <summary>Hash algorithm name, e.g. <c>SHA256</c>.</summary>
        public const string Algorithm = "crypto.algorithm";

        /// <summary>Length of the input in bytes.</summary>
        public const string InputLength = "crypto.input_length";

        /// <summary>Length of the output digest in bytes.</summary>
        public const string OutputLength = "crypto.output_byte_length";
    }


    /// <summary>
    /// Attribute names specific to <see cref="Verifiable.Cryptography.Aead.ContentEncryptionKey"/>
    /// lifetime spans.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "Intentional grouping of related constants — same pattern as WellKnownMediaTypes.")]
    public static class ContentEncryptionKey
    {
        /// <summary>
        /// The value of
        /// <see cref="Verifiable.Cryptography.Aead.ContentEncryptionKey.UseCount"/>
        /// at the time <see cref="Verifiable.Cryptography.Aead.ContentEncryptionKey.UseKey"/>
        /// was called. Emitted on every call — a value greater than one is a misuse
        /// signal (the wrapper enforces single-use atomically, so the second call
        /// throws; the counter reflects the attempt regardless).
        /// </summary>
        public const string UseCount = "crypto.cek.use_count";

        /// <summary>
        /// The final value of
        /// <see cref="Verifiable.Cryptography.Aead.ContentEncryptionKey.UseCount"/>
        /// at disposal time.
        /// </summary>
        public const string FinalUseCount = "crypto.cek.final_use_count";
    }


    /// <summary>
    /// Attribute names specific to <see cref="HmacValue"/> lifetime spans and
    /// HMAC compute / verify operations.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "Intentional grouping of related constants — same pattern as WellKnownMediaTypes.")]
    public static class Hmac
    {
        /// <summary>Hash algorithm name backing the HMAC, e.g. <c>SHA256</c>.</summary>
        public const string Algorithm = "crypto.hmac.algorithm";

        /// <summary>Length of the message being authenticated in bytes.</summary>
        public const string InputLength = "crypto.hmac.input_length";

        /// <summary>Length of the HMAC output in bytes.</summary>
        public const string OutputLength = "crypto.hmac.output_byte_length";

        /// <summary><see langword="true"/> when verification succeeded; <see langword="false"/> otherwise.</summary>
        public const string Valid = "crypto.hmac.valid";
    }


    /// <summary>
    /// Activity name constants used when starting spans on
    /// <see cref="CryptoActivitySource.Source"/>.
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "Intentional grouping of related constants — same pattern as WellKnownMediaTypes.")]
    public static class ActivityNames
    {
        /// <summary>Activity name for <see cref="Verifiable.Cryptography.Nonce"/> generation.</summary>
        public const string Nonce = "crypto.nonce";

        /// <summary>Activity name for <see cref="Verifiable.Cryptography.Salt"/> generation.</summary>
        public const string Salt = "crypto.salt";

        /// <summary>Activity name for <see cref="DigestValue"/> computation.</summary>
        public const string Digest = "crypto.digest";

        /// <summary>Activity name for HMAC compute operations.</summary>
        public const string HmacCompute = "crypto.hmac.compute";

        /// <summary>Activity name for HMAC verify operations.</summary>
        public const string HmacVerify = "crypto.hmac.verify";
    }



    /// <summary>
    /// <c>crypto.purpose</c> — the <see cref="Verifiable.Cryptography.Context.Purpose"/>
    /// for which the value was generated.
    /// </summary>
    public const string Purpose = "crypto.purpose";

    /// <summary>
    /// <c>crypto.byte_length</c> — the number of bytes generated or processed.
    /// </summary>
    public const string ByteLength = "crypto.byte_length";
}