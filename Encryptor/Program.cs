using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using ErikTheCoder.Logging;
using ErikTheCoder.ServiceContract;


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
            await Task.Delay(TimeSpan.FromMilliseconds(1));
        }


        private static (string InputPath, SymmetricAlgorithm Cipher) ParseCommandLine(string[] Arguments)
        {
            if (Arguments.Length % 2 != 0) throw new ArgumentException("Invalid number of arguments.  Arguments must be passed in a pair: -argumentName argumentValue or /argumentName argumentValue.");
            string inputPath = null;
            SymmetricAlgorithm cipher = null;
            string keyDerivationAlgorithm = null;
            int keyDerivationIterations = 0;
            int saltLength = 0;
            string password = null;
            for (int index = 0; index < Arguments.Length; index++)
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
                    case "-s":
                    case "/s":
                    case "-salt":
                    case "/salt":
                        int.TryParse(argumentValue, out saltLength);
                        break;
                    case "-p":
                    case "/p":
                    case "-password":
                    case "/password":
                        password = argumentValue;
                        break;
                }
            }
            // Validate arguments.
            if (string.IsNullOrEmpty(inputPath)) throw new ArgumentException("Specify an input path via -i argument.");
            if (cipher is null) throw new ArgumentException("Specify a cipher via -c argument.");
            if (keyDerivationAlgorithm is null) throw new ArgumentException("Specify a key derivation algorithm via -kd argument.");
            if (keyDerivationIterations <= 0) throw new ArgumentException("Specify key derivation iterations via -kdi argument");
            if (saltLength <= 0) throw new ArgumentException("Specify a salt length via -s argument.");
            // Create salt and key derivation.
            byte[] salt = new byte[saltLength];
            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider()) { random.GetBytes(salt); }
            DeriveBytes keyDerivation = KeyDerivation.Create(keyDerivationAlgorithm, password, salt, keyDerivationIterations);
            return (inputPath, cipher);
        }
    }
}
