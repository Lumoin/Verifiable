using System;
using System.Collections.Generic;

namespace Verifiable.Core.Did.CryptographicSuites
{
    public class VerificationMethodTypeInfo
    {
        public required string TypeName { get; init; }
        public required Type DefaultKeyFormatType { get; init; }
        public required IReadOnlyCollection<string> Contexts { get; init; }

        public IReadOnlyCollection<Type>? CompatibleKeyFormats { get; init; } = null;
    }
}
