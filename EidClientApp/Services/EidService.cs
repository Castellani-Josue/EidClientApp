using EidClientApp.Models;
using Net.Pkcs11Interop.Common;
using System.Net.Http.Json;
using System.Text;

namespace EidClientApp.Services
{
    public class EidService
    {

        private readonly Pkcs11Loader _loader;
        private readonly CertificateManager _certManager;
        private readonly SignatureManager _signManager;
        private readonly NissExtractor _nissExtractor;
        private readonly HttpClient _httpClient;

        // HttpClient est injecté via DI
        public EidService(HttpClient httpClient)
        {
            _loader = new Pkcs11Loader(@"C:\Windows\System32\beidpkcs11.dll");
            _certManager = new CertificateManager();
            _signManager = new SignatureManager();
            _nissExtractor = new NissExtractor();
            _httpClient = httpClient;
        }

        public async Task ProcessEidCardAsync()
        {
            using var pkcs11 = _loader.LoadLibrary();
            var slots = _loader.GetAvailableSlots(pkcs11);
            if (slots.Count == 0)
            {
                Console.WriteLine("Aucun lecteur eID détecté.");
                return;
            }

            using var session = slots[0].OpenSession(SessionType.ReadWrite);
            Console.WriteLine("Session ouverte avec succès.");

            // Récupérer les certificats "Authentication" et "Signature"
            var authCert = _certManager.FindCertificate(session, "Authentication");
            var signCert = _certManager.FindCertificate(session, "Signature");

            if (authCert == null)
            {
                Console.WriteLine("Certificat d'Authentication non trouvé.");
                return;
            }
            if (signCert == null)
            {
                Console.WriteLine("Certificat de Signature non trouvé.");
                return;
            }

            // Extraire la valeur brute du certificat d'Authentication
            var authValue = _certManager.GetRawCertificateValue(session, authCert);
            // Extraction du nationalId (NISS) depuis le certificat Authentication
            string nationalId = _nissExtractor.ExtractFromCertificate(authValue);
            Console.WriteLine($"National ID (NISS) extrait: {nationalId}");

            // Ici, nous définissons le challenge à signer. 
            // Pour un test rapide, on utilise une chaîne fixe.
            string challenge = "Hello from backend";
            var challengeBytes = Encoding.UTF8.GetBytes(challenge);

            // Signature du challenge avec la clé privée associée au certificat "Signature"
            //var signatureBytes = _signManager.SignMessage(session, "Signature", challengeBytes);
            //var signatureBytes = _signManager.SignMessageWithoutSignature(session,challengeBytes);
           /*if (signatureBytes == null)
            {
                Console.WriteLine("Erreur lors de la signature.");
                return;
            }*/
            //Console.WriteLine($"Signature (hex) : {BitConverter.ToString(signatureBytes)}");

            // Construction de la payload pour l'API
            var payload = new EidAuthRequest
            {
                nationalId = nationalId,
                certificate = Convert.ToBase64String(authValue),

            };

            // Envoi de la requête HTTP POST vers ton API Spring Boot
            try
            {
                // Remplace l’URL par celle de ton API (en local ou en prod)
                var response = await _httpClient.PostAsJsonAsync("http://localhost:8080/api/clients/eid/certificate", payload);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadFromJsonAsync<Dictionary<string, string>>();
                    if (json != null && json.ContainsKey("token"))
                    {
                        Console.WriteLine("Authentification réussie !");
                        Console.WriteLine("Token : " + json["token"]);
                    }
                    else
                    {
                        Console.WriteLine("Réponse API invalide.");
                    }
                }
                else
                {
                    var error = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Erreur HTTP : {response.StatusCode} - {error}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erreur lors de l'envoi HTTP : {ex.Message}");
            }
        }

    }
}
