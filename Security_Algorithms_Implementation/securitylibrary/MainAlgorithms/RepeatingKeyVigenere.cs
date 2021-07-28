using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public static string completeKey(string key, string comfrom, int sz)
        {
            int kSize = key.Length;
            int comfromSie = comfrom.Length;
            for(int i=0;kSize < sz ;)
            {
                key += comfrom[i++];
                kSize++;

                if (i == comfromSie)
                    i = 0;

            }
            return key;
        }

        public static string realKey(string key, string pl)
        {
            string newKey = "";
            int keySize = key.Length;
            string subString = "";
            string subString2 = "";
            for (int j = 0; j < 3; j++)
                subString += pl[j];
            int i = 0;
            for( i=3;i<keySize;i++)
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
            return realKey(key,key);
        }

        public string Decrypt(string cipherText, string key)
        {
            int ciSize = cipherText.Length;
            key = completeKey(key, key, ciSize);
            string plainText = "";
            for (int i = 0; i < ciSize; i++) 
              for (int j = 0; j < 26; j++)
              {
                    if ((key[i] + j - 97) % 26 == cipherText[i] - 65)
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
            key = completeKey(key, key, plSize);
            string cipherText = "";
            for (int i = 0; i < plSize; i++)
                cipherText += Convert.ToChar((key[i] + plainText[i] - 194)%26 + 97); 
                        return cipherText;
        }
    }
}