using EidClientApp.Models;
using Net.Pkcs11Interop.Common;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

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
            //var signCert = _certManager.FindCertificate(session, "Signature");

            if (authCert == null)
            {
                Console.WriteLine("Certificat d'Authentication non trouvé.");
                return;
            }
            /*if (signCert == null)
            {
                Console.WriteLine("Certificat de Signature non trouvé.");
                return;
            }*/

            // Extraire la valeur brute du certificat d'Authentication
            var authValue = _certManager.GetRawCertificateValue(session, authCert);
            // Extraction du nationalId (NISS) depuis le certificat Authentication
            string nationalId = _nissExtractor.ExtractFromCertificate(authValue);
            Console.WriteLine($"National ID (NISS) extrait: {nationalId}");
            Console.WriteLine($"Valeur brute du certificat d'Authentication : {Convert.ToBase64String(authValue)}");

            // Construction de la payload pour l'API
            var payload = new EidAuthRequest
            {
                nationalId = nationalId,
                certificate = Convert.ToBase64String(authValue)
            };

            // 1. Sérialiser le payload en JSON
            string jsonString = JsonSerializer.Serialize(payload);
            byte[] jsonBytes = Encoding.UTF8.GetBytes(jsonString);

            // 2. Charger le certificat dans un objet .NET X509
            var x509Cert = new X509Certificate2("C:\\Users\\josue\\Desktop\\Projet_integre\\EidClientApp\\EidClientApp\\certificate.crt");

            using RSA rsa = x509Cert.GetRSAPublicKey();
            if (rsa == null)
            {
                Console.WriteLine("Clé publique RSA introuvable dans le certificat.");
                return;
            }

            // 3. Implémentation du chiffrement hybride
            byte[] encryptedData;
            byte[] encryptedKey;
            byte[] iv;

            // Générer une clé AES aléatoire
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256; // 256 bits pour AES
                aes.GenerateKey();
                aes.GenerateIV();
                iv = aes.IV;

                // Chiffrer les données avec AES
                using (var encryptor = aes.CreateEncryptor())
                using (var msEncrypt = new MemoryStream())
                {
                    // Optionnel: compression avant chiffrement
                    using (var compressedStream = new MemoryStream())
                    {
                        using (var gzipStream = new GZipStream(compressedStream, CompressionMode.Compress, true))
                        {
                            gzipStream.Write(jsonBytes, 0, jsonBytes.Length);
                        }
                        jsonBytes = compressedStream.ToArray();
                        Console.WriteLine($"Taille après compression: {jsonBytes.Length} octets");
                    }

                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(jsonBytes, 0, jsonBytes.Length);
                        csEncrypt.FlushFinalBlock();
                        encryptedData = msEncrypt.ToArray();
                    }
                }

                // Chiffrer la clé AES avec RSA
                encryptedKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.Pkcs1);
            }

            // Préparer le payload pour l'envoi
            var encryptedPayload = new
            {
                encryptedData = Convert.ToBase64String(encryptedData),
                encryptedKey = Convert.ToBase64String(encryptedKey),
                iv = Convert.ToBase64String(iv)
            };

            // Envoi de la requête HTTP POST vers ton API Spring Boot
            try
            {
                // Remplace l’URL par celle de ton API (en local ou en prod)
                var response = await _httpClient.PostAsJsonAsync("http://localhost:8080/api/clients/eid/certificate", encryptedPayload);

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
