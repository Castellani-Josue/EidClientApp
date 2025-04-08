using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using Net.Pkcs11Interop.Common;

namespace EidClientApp.Services;

public class EidService
{
    private readonly string _pkcs11LibraryPath = @"C:\Windows\System32\beidpkcs11.dll";

    public void ListAvailableSlots()
    {
        // Création des factories
        var factories = new Pkcs11InteropFactories();

        try
        {
            // Chargement propre de la librairie PKCS#11
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory
                .LoadPkcs11Library(factories, _pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Récupération des slots avec carte présente
                List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);

                if (slots.Count == 0)
                {
                    Console.WriteLine(" Aucun lecteur avec carte eID insérée.");
                    return;
                }

                Console.WriteLine(" Lecteurs eID détectés :");
                foreach (var slot in slots)
                {
                    var info = slot.GetSlotInfo();
                    Console.WriteLine($"  - {info.SlotDescription.Trim()}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"💥 Erreur : {ex.Message}");
        }
    }
}
