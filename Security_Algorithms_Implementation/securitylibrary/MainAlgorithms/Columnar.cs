using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<List<int>> lists = new List<List<int>>();
        private void permute(string str,int l, int r)
        {
            if (l == r)
            {
                List<int> list = new List<int>();
                for (int j = 0; j < str.Length; j++)
                    list.Add(str[j] - 48);
                lists.Add(list);    
            }
            else
            {
                for (int i = l; i <= r; i++)
                {
                    str = swap(str, l, i);
                    permute(str, l + 1, r);
                    str = swap(str, l, i);
                }
            }
        }
        public string swap(string a,int i, int j)
        {
            char temp;
            char[] charArray = a.ToCharArray();
            temp = charArray[i];
            charArray[i] = charArray[j];
            charArray[j] = temp;
            string s = new string(charArray);
            return s;
        }

        public List<int> Analyse(string plainText, string cipherText)
        {
            int plSize = plainText.Length;
            string s = "12";
            cipherText = cipherText.ToLower();
            for(int i = 3; i<plSize; i++)
            {
                s += i;
                permute(s, 0, s.Length - 1);
                for (int j = 0; j < lists.Count; j++)
                {
                    if (findCipher(plainText, lists[j]).Equals(cipherText))
                        return lists[j];
                }
                lists = new List<List<int>>();
            }

            return lists[0];
        }
        private string findCipher(string plainText, List<int> key) 
        {
            int keyLen = key.Count;
            string cipherText = "";
            int plSize = plainText.Length;

            for (int i = 1, j; i <= keyLen; i++)
            {
                for (j = 0; j < keyLen; j++)
                    if (key[j] == i)
                        break;
                for (; j < plSize; j += keyLen)
                    cipherText += plainText[j];
            }
            return cipherText;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string plainText = "";
            double ciSize = cipherText.Length;
            int keyCount = key.Count;
            double depth = ciSize / keyCount;
            int depth1 = Convert.ToInt32(Math.Round(depth));
            char[,] arr2d = new char[depth1,keyCount];
            int indx;
            try
            {
                for (int i = 1, j; i <= keyCount; i++)
                {
                    indx = 0;
                    for (j = 0; j < keyCount; j++)
                        if (i == key[j])
                            break;

                    for (int k = 0; k < depth1; k++)
                        arr2d[indx++, j] = cipherText[(depth1 * (i - 1)) + k];

                }
            }
            catch(Exception e)
            { return ""; }
            
            for (int i = 0,x=0,y=0; i<ciSize;i++)
            {
                plainText += arr2d[x,y++];
                if(y== keyCount)
                { y = 0;x++;}
            }

            return plainText;
                
        }

        public string Encrypt(string plainText, List<int> key)
        {
            return findCipher(plainText, key);
        }
    }
}
