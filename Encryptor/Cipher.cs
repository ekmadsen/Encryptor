using System;
using System.Security.Cryptography;


namespace ErikTheCoder.Encryptor
{
    public static class Cipher
    {
        private const string _aesCsp = "aescsp";
        private const string _aesManaged = "aesmanaged";
        private const string _aesCng = "aescng";


        public static SymmetricAlgorithm Create(string Name)
        {
            switch (Name?.ToLower())
            {
                case _aesCsp:
                    return new AesCryptoServiceProvider();
                case _aesManaged:
                    return new AesManaged();
                case _aesCng:
                    return new AesCng();
                default:
                    throw new ArgumentException($"{Name} cipher not supported.");
            }
        }


        public static string GetName(SymmetricAlgorithm Algorithm)
        {
            string fullTypeName = Algorithm.GetType().FullName;
            switch (fullTypeName)
            {
                case "System.Security.Cryptography.AesCryptoServiceProvider":
                    return _aesCsp;
                case "System.Security.Cryptography.AesManaged":
                    return _aesManaged;
                case "System.Security.Cryptography.AesCng":
                    return _aesCng;
                default:
                    throw new ArgumentException($"{fullTypeName} class not supported.");
            }
        }
    }
}
