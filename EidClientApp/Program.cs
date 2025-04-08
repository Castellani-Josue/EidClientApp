using EidClientApp.Services;

namespace EidClientApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var eidService = new EidService();
            eidService.ListAvailableSlots();
            eidService.ListSupportedMechanisms();
            eidService.ProcessEidCard();
        }
    }
}
