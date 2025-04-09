using EidClientApp.Services;


namespace EidClientApp
{
    public class Program
    {
       static async Task Main(string[] args)
    {
            // Configuration du conteneur de dépendances
            using HttpClient httpClient = new HttpClient();

            // Instanciation directe de ton service en passant le HttpClient
            var eidService = new EidService(httpClient);

            await eidService.ProcessEidCardAsync();

            Console.WriteLine("Fin du programme. Appuyez sur une touche pour quitter.");
            Console.ReadKey();
        }
    }
}
