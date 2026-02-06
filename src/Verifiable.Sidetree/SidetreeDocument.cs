using System;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;

namespace Verifiable.Sidetree
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1067:Override Object.Equals(object) when implementing IEquatable<T>", Justification = "This project is likely removed.")]
    public class SideTreeDocument: IEquatable<SideTreeDocument>
    {
        public Context? Context { get; set; }

        public DidDocument? DidDocument { get; set; }


        /// <inheritdoc/>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1508:Avoid dead conditional code", Justification = "This project is likely removed.")]
        public bool Equals(SideTreeDocument? other)
        {
            if (other is null)
            {
                return false;
            }

            return Context == other.Context
                && DidDocument == other?.DidDocument;

        }


        /// <inheritdoc/>
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Context);
            hash.Add(DidDocument);

            return hash.ToHashCode();
        }
    }
}
