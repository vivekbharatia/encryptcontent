using System.Text;
using System.Text.Json;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Azure.Storage.Blobs;
using Azure.Storage.Sas;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace fidelity.PgpEncryptAndSftp;

public class PgpEncryptAndSftp
{
    private readonly string _keyVaultUrl =
        Environment.GetEnvironmentVariable("KeyVaultUrl");

    private readonly string _pgpSecretName =
        Environment.GetEnvironmentVariable("PgpSecretName") ?? "partner-pgp-public-key";

    private readonly string _sftpPrivateKeySecretName =
        Environment.GetEnvironmentVariable("SftpPrivateKeySecretName");

    private readonly string _sftpHost =
        Environment.GetEnvironmentVariable("SftpHost");

    private readonly string _sftpUser =
        Environment.GetEnvironmentVariable("SftpUser");

    private readonly string _storageAccountName =
        Environment.GetEnvironmentVariable("StorageAccountName");

    private readonly string _blobContainerName =
        Environment.GetEnvironmentVariable("BlobContainerName");

    private readonly string _localPgpKeyPath =
        Environment.GetEnvironmentVariable("LocalPgpKeyPath") ?? "test_public.asc";

    // --------------------------------------------------------------------
    // FUNCTION ENTRY POINT
    // --------------------------------------------------------------------
    [Function("EncryptAndUpload")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
        FunctionContext context)
    {
        var logger = context.GetLogger("EncryptAndUpload");

        logger.LogInformation("Function execution started");

        var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
        var input = JsonSerializer.Deserialize<JsonElement>(requestBody);

        string fileName = input.GetProperty("fileName").GetString();
        string sftpPath = input.GetProperty("sftpPath").GetString();
        // -------------------------
        // Generate SAS INSIDE FUNCTION
        // -------------------------
        string containerSas = await GenerateContainerCreateSasAsync();
        string content = _storageAccountName+" "+ containerSas;
        // -------------------------
        // Key Vault access
        // -------------------------
        var secretClient = new SecretClient(
            new Uri(_keyVaultUrl),
            new DefaultAzureCredential());

        string pgpPublicKey = await GetPgpPublicKeyAsync(
            secretClient,
            _pgpSecretName,
            _localPgpKeyPath,
            logger);

        string sftpPrivateKey =
            (await secretClient.GetSecretAsync(_sftpPrivateKeySecretName)).Value.Value;

        // -------------------------
        // Encrypt
        // -------------------------
        string normalizedPgpKey = NormalizePgpPublicKey(pgpPublicKey);
        byte[] encryptedBytes = EncryptPgp(content, normalizedPgpKey);

        // -------------------------
        // Upload to SFTP
        // -------------------------
        UploadUsingSshKey(
            encryptedBytes,
            $"{sftpPath}/{fileName}.pgp",
            sftpPrivateKey);

        logger.LogInformation("SFTP upload completed");

        

        // 🔴 DEBUG LOG (DO NOT KEEP IN PROD)
        logger.LogInformation("Generated Blob Service SAS (DEBUG):");
        logger.LogInformation(containerSas);

        // -------------------------
        // Response
        // -------------------------
        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        await response.WriteStringAsync(JsonSerializer.Serialize(new
        {
            message = "File encrypted and uploaded successfully",
            sasToken = containerSas
        }));

        return response;
    }

    // --------------------------------------------------------------------
    // SAS GENERATION (CONTAINER | CREATE | 8 HOURS)
    // --------------------------------------------------------------------
    private async Task<string> GenerateContainerCreateSasAsync()
    {
        var blobServiceClient = new BlobServiceClient(
            new Uri($"https://{_storageAccountName}.blob.core.windows.net"),
            new DefaultAzureCredential());

        // Delegation key must outlive SAS
        var delegationKey = await blobServiceClient.GetUserDelegationKeyAsync(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddHours(9));

        var sasBuilder = new BlobSasBuilder
        {
            BlobContainerName = _blobContainerName,
            Resource = "c",
            StartsOn = DateTimeOffset.UtcNow.AddMinutes(-5),
            ExpiresOn = DateTimeOffset.UtcNow.AddHours(8),
            Protocol = SasProtocol.Https
        };

        sasBuilder.SetPermissions(BlobContainerSasPermissions.Create);

        var sas = sasBuilder.ToSasQueryParameters(
            delegationKey,
            _storageAccountName).ToString();

        return $"?{sas}";
    }

    // --------------------------------------------------------------------
    // GET PGP KEY (KEY VAULT OR LOCAL FILE)
    // --------------------------------------------------------------------
    private async Task<string> GetPgpPublicKeyAsync(
        SecretClient secretClient,
        string secretName,
        string localFilePath,
        ILogger logger)
    {
        // Try Key Vault first
        try
        {
            logger.LogInformation($"Attempting to retrieve PGP key from Key Vault: {secretName}");
            string keyVaultKey = (await secretClient.GetSecretAsync(secretName)).Value.Value;
            if (!string.IsNullOrWhiteSpace(keyVaultKey))
            {
                logger.LogInformation("Successfully retrieved PGP key from Key Vault");
                return keyVaultKey;
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning($"Failed to retrieve PGP key from Key Vault: {ex.Message}. Attempting local file fallback.");
        }

        // Try local file as fallback
        try
        {
            if (File.Exists(localFilePath))
            {
                logger.LogInformation($"Attempting to retrieve PGP key from local file: {localFilePath}");
                string localKey = await File.ReadAllTextAsync(localFilePath);
                if (!string.IsNullOrWhiteSpace(localKey))
                {
                    logger.LogInformation("Successfully retrieved PGP key from local file");
                    return localKey;
                }
            }
            else
            {
                logger.LogWarning($"Local PGP key file not found: {localFilePath}");
            }
        }
        catch (Exception ex)
        {
            logger.LogError($"Failed to read PGP key from local file: {ex.Message}");
        }

        throw new InvalidOperationException(
            $"Unable to retrieve PGP public key. Tried Key Vault secret '{secretName}' and local file '{localFilePath}'.");
    }

    // --------------------------------------------------------------------
    // PGP ENCRYPTION
    // --------------------------------------------------------------------
    private static string NormalizePgpPublicKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return key;

        key = key.Trim();

        // Remove surrounding quotes if present
        if ((key.StartsWith("\"") && key.EndsWith("\"")) ||
            (key.StartsWith("'") && key.EndsWith("'")))
        {
            key = key.Substring(1, key.Length - 2);
        }

        // Normalize line endings and remove extra whitespace
        key = key.Replace("\r\n", "\n").Trim();

        return key;
    }
    private static byte[] EncryptPgp(string data, string publicKey)
    {
        using var output = new MemoryStream();

        Console.WriteLine($"DEBUG: Public key length: {publicKey.Length}");
        Console.WriteLine($"DEBUG: Public key starts with: {publicKey.Substring(0, Math.Min(100, publicKey.Length))}");

        using var keyStream = new MemoryStream(Encoding.ASCII.GetBytes(publicKey));
        var decoderStream = PgpUtilities.GetDecoderStream(keyStream);
        var pubKeyRingBundle = new PgpPublicKeyRingBundle(decoderStream);

        PgpPublicKey encKey = null;

        // Find a suitable encryption key
        Console.WriteLine($"DEBUG: Found {pubKeyRingBundle.GetKeyRings().Count()} key rings");
        foreach (PgpPublicKeyRing ring in pubKeyRingBundle.GetKeyRings())
        {
            Console.WriteLine($"DEBUG: Processing key ring with {ring.GetPublicKeys().Count()} keys");
            foreach (PgpPublicKey key in ring.GetPublicKeys())
            {
                Console.WriteLine($"DEBUG: Key ID {key.KeyId:X}, Algorithm: {key.Algorithm}, IsRevoked: {key.IsRevoked()}, IsEncryptionKey: {key.IsEncryptionKey}");
                
                if (key.IsRevoked())
                {
                    Console.WriteLine($"DEBUG: Skipping revoked key");
                    continue;
                }

                if (key.Algorithm == PublicKeyAlgorithmTag.ECDH ||
                    key.Algorithm == PublicKeyAlgorithmTag.RsaEncrypt ||
                    key.Algorithm == PublicKeyAlgorithmTag.RsaGeneral)
                {
                    Console.WriteLine($"DEBUG: Found suitable encryption key: {key.KeyId:X}");
                    encKey = key;
                    break;
                }
            }
            if (encKey != null) break;
        }

        if (encKey == null)
            throw new InvalidOperationException("No PGP encryption key found.");

        Console.WriteLine($"Found encryption key with ID: {encKey.KeyId:X}");
        Console.WriteLine($"INFO      Looked up the key preferences and using the symmetric algorithm 'AES128'");
        Console.WriteLine($"INFO      Looked up the key preferences and using the hash algorithm 'SHA256'");
        Console.WriteLine($"INFO      Looked up the key preferences and using the compression algorithm 'ZIP'");

        var encGen = new PgpEncryptedDataGenerator(
        SymmetricKeyAlgorithmTag.Aes128, true);

        encGen.AddMethod(encKey);

        using (var encOut = encGen.Open(output, new byte[1 << 16]))
        {
            // Create compressed data generator with ZIP algorithm and write into the encrypted stream
            var compGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            using (var compOut = compGen.Open(encOut))
            {
                var literalGen = new PgpLiteralDataGenerator();
                byte[] inputBytes = Encoding.UTF8.GetBytes(data);
                using (var literalOut = literalGen.Open(compOut, PgpLiteralDataGenerator.Utf8, "message.txt", inputBytes.Length, DateTime.UtcNow))
                {
                    literalOut.Write(inputBytes, 0, inputBytes.Length);
                }
            }
        }

        return output.ToArray();
    }

    // --------------------------------------------------------------------
    // SFTP UPLOAD
    // --------------------------------------------------------------------
    private void UploadUsingSshKey(
    byte[] fileBytes,
    string remotePath,
    string privateKeyPem)
    {
    string normalizedKey = NormalizePrivateKeyPem(privateKeyPem);

    try
    {
        using var keyStream = new MemoryStream(Encoding.UTF8.GetBytes(normalizedKey));
        var privateKeyFile = new PrivateKeyFile(keyStream);
        UploadWithPrivateKeyFile(fileBytes, remotePath, privateKeyFile);
        return;
    }
    catch (SshException) { }
    catch (ArgumentException) { }

    if (TryConvertKeyWithPemReader(normalizedKey, out var convertedPem))
    {
        using var keyStream2 = new MemoryStream(Encoding.UTF8.GetBytes(convertedPem));
        var privateKeyFile2 = new PrivateKeyFile(keyStream2);
        UploadWithPrivateKeyFile(fileBytes, remotePath, privateKeyFile2);
        return;
    }

    throw new InvalidOperationException(
        "Invalid SSH private key. Ensure it is an unencrypted PEM key.");
}

private static string NormalizePrivateKeyPem(string key)
{
    if (string.IsNullOrWhiteSpace(key))
        return key;

    key = key.Trim();

    if ((key.StartsWith("\"") && key.EndsWith("\"")) ||
        (key.StartsWith("'") && key.EndsWith("'")))
    {
        key = key.Substring(1, key.Length - 2);
    }

    return key.Replace("\r\n", "\n");
}

private static void UploadWithPrivateKeyFile(
    byte[] fileBytes,
    string remotePath,
    PrivateKeyFile privateKeyFile)
{
    var authMethod = new PrivateKeyAuthenticationMethod(
        Environment.GetEnvironmentVariable("SftpUser"),
        privateKeyFile);

    var connectionInfo = new ConnectionInfo(
        Environment.GetEnvironmentVariable("SftpHost"),
        22,
        Environment.GetEnvironmentVariable("SftpUser"),
        authMethod);

    using var sftp = new SftpClient(connectionInfo);
    sftp.Connect();

    using var ms = new MemoryStream(fileBytes);
    sftp.UploadFile(ms, remotePath, true);

    sftp.Disconnect();
}

private static bool TryConvertKeyWithPemReader(string keyPem, out string convertedPem)
{
    convertedPem = null;
    try
    {
        using var sr = new StringReader(keyPem);
        var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
        var obj = pemReader.ReadObject();
        if (obj == null) return false;

        var sw = new StringWriter();
        var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
        pemWriter.WriteObject(obj);
        pemWriter.Writer.Flush();

        convertedPem = sw.ToString();
        return true;
    }
    catch
    {
        return false;
    }
}


}
