using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /*comments*/
    // a = 97  z = 122
    // A = 65  Z = 90
    // 0 = 48
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            char[] arr = new char[26];
            bool[] check = new bool[26];
            int plSize = plainText.Length;
            cipherText = cipherText.ToLower();

            for(int i=0; i<plSize; i++)
            {
                arr[plainText[i] - 97] = cipherText[i];
                check[cipherText[i] - 97] = true;
            }

            for(int i=0;i<26;i++)
                if(arr[i] < 'a' || arr[i] > 'z')
                {
                    for(int j=0;j<26;j++)
                        if(!check[j])
                        {
                            arr[i] = Convert.ToChar(j + 97);
                            check[j] = true;
                            break;
                        }

                }
            key = new string(arr);
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            int ciSize = cipherText.Length;
            cipherText = cipherText.ToLower();
            string plainText = "";
            char f;
            for (int i = 0; i < ciSize; i++)
                for (int j = 0; j < 26; j++)
                    if (cipherText[i] == key[j])
                    {
                        plainText += Convert.ToChar(j + 97); 
                        break;
                    }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            int plSize = plainText.Length;
            string cipherText = "";
            for(int i=0; i < plSize; i++)
                cipherText += key[plainText[i] - 97];
            
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string key = "";
            cipher = cipher.ToLower();
            char[] freq = {'e','t','a','o','i','n','s','r','h','l','d','c','u',
                          'm','f','p','g','w','y','b','v','k','x','j','q','z'};
            int[] count = new int[26];
            for (int i = 0; i < 26; i++)
                count[i] = 0;
            int ciSize = cipher.Length;
            for(int i=0;i<ciSize;i++)
                count[cipher[i]- 97 ]++;

            int mx,ti;
            char c;
            char[] newkey = new char[ciSize];

            for (int i = 0; i < 26; i++)
            {
                mx = 0; ti = 0;
                for (int j = 0; j < 26; j++)
                    if (count[j] > mx)
                    {
                        ti = j;
                        mx = count[j];
                    }
                count[ti] = -1;
                c = Convert.ToChar(ti + 97);
                for (int j = 0; j < ciSize; j++)
                    if (cipher[j].Equals(c))
                        newkey[j] = freq[i];
            }
            key = new string(newkey);

            return key;
        }
    }
}
