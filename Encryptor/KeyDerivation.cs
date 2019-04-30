using System;
using System.Security.Cryptography;


namespace ErikTheCoder.Encryptor
{
    public static class KeyDerivation
    {
        public static DeriveBytes Create(string Name, string Password, byte[] Salt, int Iterations)
        {
            switch (Name?.ToLower())
            {
                case "pdb":
                    return new PasswordDeriveBytes(Password, Salt) {IterationCount = Iterations};
                case "rfc2898":
                    return new Rfc2898DeriveBytes(Password, Salt, Iterations);
                default:
                    throw new ArgumentException($"{Name} key derivation not supported.");

            }
        }
    }
}
