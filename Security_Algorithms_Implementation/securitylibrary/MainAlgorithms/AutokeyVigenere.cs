using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public static string realKey(string key, string pl)
        {
            string newKey = "";
            int plSize = pl.Length;
            string subString = "";
            string subString2 = "";
            for (int j = 0; j < 3; j++)
                subString += pl[j];
            int i = 0;
            for (i = 3; i < plSize; i++)
            {
                subString2 = "";
                for (int j = 0; j < 3; j++)
                    subString2 += key[i + j];
                if (subString == subString2)
                    break;
            }
            for (int j = 0; j < i; j++)
                newKey += key[j];

            return newKey;
        }

        public string Analyse(string plainText, string cipherText)
        {
            int ciSize = cipherText.Length;
            string key = "";
            for (int i = 0; i < ciSize; i++)
                for (int j = 0; j < 26; j++)
                {
                    if ((plainText[i] + j - 97) % 26 == cipherText[i] - 65)
                    {
                        key += Convert.ToChar(j + 97);
                        break;
                    }
                }
            return RepeatingkeyVigenere.realKey(key, plainText);
        }

        public string Decrypt(string cipherText, string key)
        {
            int ciSize = cipherText.Length;
            int kS = key.Length;
            string plainText = "";
            for (int i = 0; i < ciSize; i++)
                if (i < kS)
                {
                    for (int j = 0; j < 26; j++)
                        if ((key[i] + j - 97) % 26 == cipherText[i] - 65)
                        {
                            plainText += Convert.ToChar(j + 97);
                            break;
                        }
                }
                else
                {
                    for (int j = 0; j < 26; j++)
                        if ((plainText[i - kS] + j - 97) % 26 == cipherText[i] - 65)
                        {
                            plainText += Convert.ToChar(j + 97);
                            break;
                        }
                }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            int plSize = plainText.Length;
            key = RepeatingkeyVigenere.completeKey(key, plainText, plSize);
            string cipherText = "";
            for (int i = 0; i < plSize; i++)
                cipherText += Convert.ToChar((key[i] + plainText[i] - 194) % 26 + 97);
            return cipherText;
        }
    }
}
