using System.Collections.Generic;
using Verifiable.Tpm.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// TPM command codes capability data (TPM_CAP_PP_COMMANDS, TPM_CAP_AUDIT_COMMANDS).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format (TPML_CC):</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                  //Number of command codes.
///     TPM_CC commandCodes[count];    //Array of command codes.
/// } TPML_CC;
/// </code>
/// <para>
/// <b>Usage:</b> This type is used for two capability queries:
/// </para>
/// <list type="bullet">
///   <item><description><b>TPM_CAP_PP_COMMANDS:</b> Commands requiring physical presence.</description></item>
///   <item><description><b>TPM_CAP_AUDIT_COMMANDS:</b> Commands being audited.</description></item>
/// </list>
/// <para>
/// The <see cref="CommandCodeCategory"/> property indicates which category this list represents.
/// </para>
/// </remarks>
/// <seealso cref="TpmCapabilityData"/>
public sealed record TpmCommandCodesData: TpmCapabilityData
{
    /// <inheritdoc/>
    public override TpmCapConstants Capability { get; }

    /// <summary>
    /// Gets the category of command codes in this list.
    /// </summary>
    public CommandCodeCategory CommandCodeCategory { get; }

    /// <summary>
    /// Gets the list of command codes.
    /// </summary>
    public required IReadOnlyList<TpmCcConstants> CommandCodes { get; init; }

    /// <summary>
    /// Initializes a new instance for physical presence commands.
    /// </summary>
    /// <param name="commandCodes">The command codes.</param>
    /// <returns>A new instance representing PP commands.</returns>
    public static TpmCommandCodesData ForPhysicalPresence(IReadOnlyList<TpmCcConstants> commandCodes)
    {
        return new TpmCommandCodesData(TpmCapConstants.TPM_CAP_PP_COMMANDS, CommandCodeCategory.PhysicalPresence)
        {
            CommandCodes = commandCodes
        };
    }

    /// <summary>
    /// Initializes a new instance for audit commands.
    /// </summary>
    /// <param name="commandCodes">The command codes.</param>
    /// <returns>A new instance representing audit commands.</returns>
    public static TpmCommandCodesData ForAudit(IReadOnlyList<TpmCcConstants> commandCodes)
    {
        return new TpmCommandCodesData(TpmCapConstants.TPM_CAP_AUDIT_COMMANDS, CommandCodeCategory.Audit)
        {
            CommandCodes = commandCodes
        };
    }

    private TpmCommandCodesData(TpmCapConstants capability, CommandCodeCategory category)
    {
        Capability = capability;
        CommandCodeCategory = category;
    }
}

/// <summary>
/// Categorizes command code lists.
/// </summary>
public enum CommandCodeCategory
{
    /// <summary>
    /// Commands requiring physical presence (TPM_CAP_PP_COMMANDS).
    /// </summary>
    PhysicalPresence,

    /// <summary>
    /// Commands being audited (TPM_CAP_AUDIT_COMMANDS).
    /// </summary>
    Audit
}