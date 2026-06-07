using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;

namespace Verifiable.Core;

/// <summary>
/// Cross-cutting typed accessors for well-known entries on an
/// <see cref="ExchangeContext"/>. These are the values that span every
/// channel and protocol a credential exchange can run over (issuance,
/// presentation, verification), so they live in <see cref="Verifiable.Core"/>
/// rather than in any one transport or protocol layer.
/// </summary>
/// <remarks>
/// <para>
/// Layer-specific accessors (OAuth, a given transport channel) live as
/// extensions in their own assemblies over the same <see cref="ExchangeContext"/>
/// so a non-OAuth channel never drags OAuth or HTTP in. Library users add their
/// own accessors the same way using C# extension syntax — the methods appear
/// alongside the library-provided ones in IntelliSense.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class ExchangeContextExtensions
{
    //The instant at which trust material is evaluated for validity during this
    //operation — certificate notBefore/notAfter, trust-statement iat/exp, and
    //any other time-bounded check a key resolver performs. Stamped by the
    //operation driver (for example the wallet client from its TimeProvider)
    //before invoking application hooks so the evaluation time is consistent
    //and deterministic across every hook in the same operation.
    private const string ValidationTimeKey = "exchange.validationTime";

    //The tenant whose configuration/key inventory this operation runs against.
    //Cross-cutting: tenancy spans the Authorization Server, the wallet, and any
    //channel adapter, so the accessor lives in Core over the neutral context.
    private const string TenantIdKey = "exchange.tenantId";


    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets the resolved <see cref="TenantId"/> for this operation, or
        /// <see langword="null"/> when no tenant has been resolved. Set by the
        /// application (or, on the server side, by the dispatcher's tenant
        /// extraction) before tenant-scoped work runs.
        /// </summary>
        public TenantId? TenantId =>
            context.TryGetValue(TenantIdKey, out object? value)
                && value is TenantId tenantId ? tenantId : default(TenantId?);

        /// <summary>
        /// Sets the resolved <see cref="TenantId"/> for this operation.
        /// </summary>
        /// <param name="tenantId">The tenant identifier.</param>
        public void SetTenantId(TenantId tenantId)
        {
            context[TenantIdKey] = tenantId;
        }


        /// <summary>
        /// Gets the UTC instant at which trust material is evaluated for
        /// validity during this operation, or <see langword="null"/> when the
        /// operation driver has not stamped one.
        /// </summary>
        public DateTimeOffset? ValidationTime =>
            context.TryGetValue(ValidationTimeKey, out object? value)
                && value is DateTimeOffset instant ? instant : default(DateTimeOffset?);

        /// <summary>
        /// Sets the UTC instant at which trust material is evaluated for
        /// validity during this operation. Called by the operation driver once
        /// per operation before application hooks run.
        /// </summary>
        /// <param name="validationTime">The UTC evaluation instant.</param>
        public void SetValidationTime(DateTimeOffset validationTime)
        {
            context[ValidationTimeKey] = validationTime;
        }
    }
}
