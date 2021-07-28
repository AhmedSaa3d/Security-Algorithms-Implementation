using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /*comments*/
    // a = 97  z = 122
    // A = 65  Z = 90
    // 0 = 48
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            int plSize = plainText.Length;
            key -= 97; 
          //  plainText.ToLower();
            string cipherText = "";
            for (int i = 0; i < plSize; i++)
                cipherText += Convert.ToChar((plainText[i] + key) % 26 + 97);
                    
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            int ciSize = cipherText.Length;
            cipherText = cipherText.ToLower();
            int conv;
            key += 97;
            string plainText = "";
            for (int i = 0; i < ciSize; i++)
            {
                conv = cipherText[i] - key;
                if (conv < 0)
                    plainText += Convert.ToChar(conv + 123);
                else
                    plainText += Convert.ToChar(conv + 97);
            }

            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            char pl = char.ToLower(plainText[0]);
            char ci = char.ToLower(cipherText[0]);
            int key = ci - pl;
            if (key < 0)
                return key + 26;
            return key;
        }
    }
}
