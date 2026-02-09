using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage(
    "Naming",
    "CA1707:Identifiers should not contain underscores",
    Justification = "Identifiers intentionally follow the TPM 2.0 specification naming to preserve one-to-one traceability with the standard.")]

[assembly: SuppressMessage(
    "Design",
    "CA1028:Enum Storage should be Int32",
    Justification = "The TPM 2.0 specification for types is for fixed-size integer types, not necessarily Int32.")]
