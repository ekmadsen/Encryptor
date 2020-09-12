using System;
using System.Security.Cryptography;


namespace ErikTheCoder.Encryptor
{
    public static class Cipher
    {
        public static SymmetricAlgorithm Create(string Name)
        {
            return Name?.ToLower() switch
            {
                "aescsp" => new AesCryptoServiceProvider(),
                "aesmanaged" => new AesManaged(),
                "aescng" => new AesCng(),
                "tdescsp" => new TripleDESCryptoServiceProvider(),
                "tdescng" => new TripleDESCng(),
                _ => throw new ArgumentException($"{Name} cipher not supported.")
            };
        }
    }
}
