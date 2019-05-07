using System;
using System.Security.Cryptography;


namespace ErikTheCoder.Encryptor
{
    public static class Cipher
    {
        public static SymmetricAlgorithm Create(string Name)
        {
            switch (Name?.ToLower())
            {
                case "aescsp":
                    return new AesCryptoServiceProvider();
                case "aesmanaged":
                    return new AesManaged();
                case "aescng":
                    return new AesCng();
                default:
                    throw new ArgumentException($"{Name} cipher not supported.");
            }
        }
    }
}
