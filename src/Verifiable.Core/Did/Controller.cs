using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// This is a temporary structure for the wrapped ID.
    /// </summary>
    [DebuggerDisplay("Controller({Id})")]
    public class Controller
    {
        public Controller(string did)
        {
            Did = did;
        }


        public string? Did { get; set; }

        public static implicit operator string(Controller controller) => controller.Did!;
        public static explicit operator Controller(string did) => new(did);
    }
}
