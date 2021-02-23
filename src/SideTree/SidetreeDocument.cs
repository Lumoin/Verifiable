using DotDecentralized.Core.Did;
using System;

namespace DotDecentralized.Sidetree
{
    public class SideTreeDocument: IEquatable<SideTreeDocument>
    {
        public Context? Context { get; set; }

        public DidDocument? DidDocument { get; set; }


        /// <inheritdoc/>
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
