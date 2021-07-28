using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int plSize = plainText.Length;
            cipherText = cipherText.ToLower();
            for (int i = 2; i < plSize; i++)
                if (findCipher(plainText, i).Equals(cipherText))
                    return i;
            return -1;
        }

        private string findCipher(string plainText, int key) 
        {
            string cipherText = "";
            int plSize = plainText.Length;
            for (int i = 0; i < key; i++)
                for (int j = i; j < plSize; j += key)
                    cipherText += plainText[j];
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            double ciSize = cipherText.Length;
            double depth = ciSize / key;
           int depth1 = Convert.ToInt32(Math.Round(depth));
            for (int i = 0; i < depth1; i++)
                for (int j = i; j < ciSize; j += depth1)
                    plainText += cipherText[j];
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            return findCipher(plainText, key);
        }
    }
}
