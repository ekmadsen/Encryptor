using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using ErikTheCoder.Logging;
using ErikTheCoder.ServiceContract;
using Newtonsoft.Json;


namespace ErikTheCoder.Encryptor
{
    public static class Program
    {
        public static async Task Main(string[] Arguments)
        {
            try
            {
                await Run(Arguments);
                SafeConsole.WriteLine(null);
            }
            catch (Exception exception)
            {
                SafeConsole.WriteLine(exception.GetSummary(true, true), ConsoleColor.Red);
            }
        }


        private static async Task Run(IReadOnlyList<string> Arguments)
        {
            (string inputPath, Operation operation, DeriveBytes keyDerivation, int keyLength, byte[] salt, SymmetricAlgorithm cipher) = ParseCommandLine(Arguments);
            using (keyDerivation)
            using (cipher)
            {
                switch (operation)
                {
                    case Operation.Encrypt:
                        await Encrypt(inputPath, keyDerivation, keyLength, salt, cipher);
                        break;
                    case Operation.Decrypt:
                        await Decrypt(inputPath);
                        break;
                    default:
                        throw new ArgumentException($"{operation} operation not supported.");
                }
            }
            
        }


        // TODO: Add progress bar.
        private static async Task Encrypt(string InputPath, DeriveBytes KeyDerivation, int KeyLength, byte[] Salt, SymmetricAlgorithm Cipher)
        {
            const string encryptedFileExtension = ".encrypted";
            bool inputPathIsFile = File.Exists(InputPath);
            if (!inputPathIsFile && !Directory.Exists(InputPath)) throw new Exception($"{InputPath} input path does not exist.");
            // TODO: Support encrypting entire directories using System.IO.Compression.ZipFile class.
            if (!inputPathIsFile) throw new NotSupportedException("Encrypting directories is not supported.");
            string outputFilename = Path.ChangeExtension(InputPath, encryptedFileExtension);
            using (FileStream inputFileStream = File.Open(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (FileStream outputFileStream = File.Open(outputFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                // Generate new initialization vector for each encryption to prevent identical plaintexts from producing identical ciphertexts when encrypted using the same key.
                Cipher.GenerateIV();
                // Write integer length of encrypted file header (as four bytes) followed by the header bytes.
                byte[] encryptedFileHeader = GetEncryptedFileHeader(InputPath, KeyDerivation, KeyLength, Salt, Cipher, Cipher.IV);
                outputFileStream.Write(BitConverter.GetBytes(encryptedFileHeader.Length));
                outputFileStream.Write(encryptedFileHeader);
                byte[] key = KeyDerivation.GetBytes(KeyLength);
                byte[] buffer = new byte[Cipher.BlockSize];
                using (ICryptoTransform encryptor = Cipher.CreateEncryptor(key, Cipher.IV))
                using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                {
                    // Read from input stream and write to output stream.
                    int bytesRead;
                    while ((bytesRead = await inputFileStream.ReadAsync(buffer, 0, buffer.Length)) > 0) await cryptoStream.WriteAsync(buffer, 0, bytesRead);
                }
            }
            SafeConsole.WriteLine($"Wrote encrypted file to {outputFilename}.");
        }


        private static async Task Decrypt(string InputPath)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(1));
        }


        private static byte[] GetEncryptedFileHeader(string InputFilename, DeriveBytes KeyDerivation, int KeyLength, byte[] Salt, SymmetricAlgorithm Cipher, byte[] InitializationVector)
        {
            string keyDerivationAlgorithm = Encryptor.KeyDerivation.GetName(KeyDerivation);
            string cipherAlgorithm = Encryptor.Cipher.GetName(Cipher);
            EncryptedFileHeader encryptedFileHeader = new EncryptedFileHeader
            {
                Filename = InputFilename,
                KeyDerivationAlgorithm = keyDerivationAlgorithm,
                KeyLength = KeyLength,
                Salt = Salt,
                CipherAlgorithm = cipherAlgorithm,
                InitializationVector = InitializationVector
            };
            return Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(encryptedFileHeader));
        }


        private static (string InputPath, Operation Operation, DeriveBytes KeyDerivation, int KeyLength, byte[] Salt, SymmetricAlgorithm Cipher) ParseCommandLine(IReadOnlyList<string> Arguments)
        {
            if (Arguments.Count % 2 != 0) throw new ArgumentException("Invalid number of arguments.  Arguments must be passed in a pair: -argumentName argumentValue or /argumentName argumentValue.");
            string inputPath = null;
            Operation operation = Operation.Unknown;
            SymmetricAlgorithm cipher = null;
            string keyDerivationAlgorithm = null;
            int keyDerivationIterations = 0;
            int keyLength = 0;
            int saltLength = 0;
            for (int index = 0; index < Arguments.Count; index++)
            {
                string argumentName = Arguments[index];
                index++;
                string argumentValue = Arguments[index];
                switch (argumentName?.ToLower())
                {
                    case "-i":
                    case "/i":
                    case "-input":
                    case "/input":
                        inputPath = argumentValue;
                        break;
                    case "-o":
                    case "/o":
                    case "-operation":
                    case "/operation":
                        operation = Enum.Parse<Operation>(argumentValue, true);
                        break;
                    case "-c":
                    case "/c":
                    case "-cipher":
                    case "/cipher":
                        cipher = Cipher.Create(argumentValue);
                        break;
                    case "-kd":
                    case "/kd":
                    case "-keyderivation":
                    case "/keyderivation":
                        keyDerivationAlgorithm = argumentValue;
                        break;
                    case "-kdi":
                    case "/kdi":
                    case "-kditerations":
                    case "/kditerations":
                        int.TryParse(argumentValue, out keyDerivationIterations);
                        break;
                    case "-kl":
                    case "/kl":
                    case "-keylength":
                    case "/keylength":
                        int.TryParse(argumentValue, out keyLength);
                        break;
                    case "-sl":
                    case "/sl":
                    case "-saltlength":
                    case "/saltlength":
                        int.TryParse(argumentValue, out saltLength);
                        break;
                }
            }
            // Validate arguments.
            if (string.IsNullOrEmpty(inputPath)) throw new ArgumentException("Specify an input path via -i argument.");
            if (operation == Operation.Unknown) throw new ArgumentException("Specify an operation via -o argument.");
            if (cipher is null) throw new ArgumentException("Specify a cipher via -c argument.");
            if (keyDerivationAlgorithm is null) throw new ArgumentException("Specify a key derivation algorithm via -kd argument.");
            if (keyDerivationIterations <= 0) throw new ArgumentException("Specify key derivation iterations via -kdi argument");
            if (keyLength == 0) throw new ArgumentException("Specify a key length in bytes via -kl argument.");
            if (saltLength <= 0) throw new ArgumentException("Specify a salt length via -sl argument.");
            // Get password from user.
            // TODO: Hide password.
            // TODO: Confirm password.
            SafeConsole.Write("Enter password: ");
            string password = SafeConsole.ReadLine();
            // Create salt and key derivation.
            byte[] salt = new byte[saltLength];
            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider()) { random.GetBytes(salt); }
            DeriveBytes keyDerivation = KeyDerivation.Create(keyDerivationAlgorithm, password, salt, keyDerivationIterations);
            return (inputPath, operation, keyDerivation, keyLength, salt, cipher);
        }
    }
}
