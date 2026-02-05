using System.Text;
using Azure.Identity;
using System.Text.Json;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Renci.SshNet;

namespace fidelity.PgpEncryptAndSftp;

public class PgpEncryptAndSftp
{
    private readonly string _keyVaultUrl = Environment.GetEnvironmentVariable("KeyVaultUrl");
    private readonly string _pgpSecretName = "partner-pgp-public-key";

    private readonly string _sftpHost = Environment.GetEnvironmentVariable("SftpHost");
    private readonly string _sftpUser = Environment.GetEnvironmentVariable("SftpUser");
    private readonly string _sftpPassword = Environment.GetEnvironmentVariable("SftpPassword");

    [Function("EncryptAndUpload")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
    {
        var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
        JsonElement input = JsonSerializer.Deserialize<JsonElement>(requestBody);

        string fileName = input.GetProperty("fileName").GetString();
        string content  = input.GetProperty("content").GetString();
        string sftpPath = input.GetProperty("sftpPath").GetString();

        // Get PGP public key from Key Vault
        var client = new SecretClient(new Uri(_keyVaultUrl), new DefaultAzureCredential());
        KeyVaultSecret secret = await client.GetSecretAsync(_pgpSecretName);
        string publicKey = secret.Value;

        // Encrypt content
        byte[] encryptedBytes = EncryptPgp(content, publicKey);

        // Upload to SFTP
        using var sftp = new SftpClient(_sftpHost, _sftpUser, _sftpPassword);
        sftp.Connect();

        using var ms = new MemoryStream(encryptedBytes);
        sftp.UploadFile(ms, $"{sftpPath}/{fileName}.pgp");

        sftp.Disconnect();

        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        await response.WriteStringAsync("File encrypted and uploaded successfully");

        return response;
    }

    private static byte[] EncryptPgp(string data, string publicKey)
    {
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(data));
        using var output = new MemoryStream();

        using var keyStream = new MemoryStream(Encoding.ASCII.GetBytes(publicKey));
        var pubKeyRingBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyStream));

        PgpPublicKey encKey = pubKeyRingBundle.GetKeyRings()
            .Cast<PgpPublicKeyRing>()
            .SelectMany(r => r.GetPublicKeys().Cast<PgpPublicKey>())
            .First(k => k.IsEncryptionKey);

        var encryptedDataGenerator = new PgpEncryptedDataGenerator(
            Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag.Aes256, true);

        encryptedDataGenerator.AddMethod(encKey);

        using var encryptedOut = encryptedDataGenerator.Open(output, new byte[1 << 16]);
        input.CopyTo(encryptedOut);

        return output.ToArray();
    }
}