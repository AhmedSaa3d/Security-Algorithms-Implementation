using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    /*comments*/
    // a = 97  z = 122
    // A = 65  Z = 90
    // 0 = 48
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        private void convertKey(string key, char[,] key2d, int[] x1, int[] y1)
        {
            bool[] usedChar = new bool[123];
            int keySize = key.Length;
            char c;
            int x = 0, y = 0;
            for (int i = 0; i < keySize; i++)
            {
                c = key[i];
                if (usedChar[c] != true)
                {
                    if (c == 'i' || c == 'j')
                    {
                        usedChar['i'] = true;
                        usedChar['j'] = true;
                        c = 'i';
                    }
                    else
                        usedChar[c] = true;
                    key2d[x, y] = c;
                    x1[c] = x;
                    y1[c] = y++;
                    if (y >= 5)
                    { y = 0; x++; }
                }
            }
            for (int i = 97; i < 123; i++)
            {
                if (usedChar[i] != true)
                {
                    key2d[x, y] = Convert.ToChar(i);
                    x1[i] = x;
                    y1[i] = y++;
                    usedChar[i] = true;
                    if (i == 105)
                        i++; // to avoid j
                    if (y >= 5)
                    { y = 0; x++; }
                }
            }
        }

        private int checkmins(int x) 
        {
            if (x - 1 < 0)
                return 4;
            else
                return x - 1;
        }
        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            int ciSize = cipherText.Length;
            char[,] key2d = new char[5, 5];
            int[] x = new int[123];
            int[] y = new int[123];
            convertKey(key, key2d, x, y);
            char c1, c2;
            int x1, x2, y1, y2;
            for (int i = 0; i < ciSize - 1;i+=2)
            {
                c1 = cipherText[i];
                c2 = cipherText[i + 1];
                
                x1 = x[c1];
                x2 = x[c2];
                y1 = y[c1];
                y2 = y[c2];

                if (x1 == x2)
                {
                    plainText += key2d[x1, checkmins(y1)];
                    plainText += key2d[x2, checkmins(y2)];
                }
                else if (y1 == y2)
                {
                    plainText += key2d[checkmins(x1), y1];
                    plainText += key2d[checkmins(x2), y2];
                }
                else 
                {
                    plainText += key2d[x1, y2];
                    plainText += key2d[x2, y1];
                }
            }


            for (int i = 1; i < ciSize - 1; i++)
            {
                if (plainText[i] == 'x' && plainText[i - 1] == plainText[i + 1])
                {
                   plainText = plainText.Remove(i,1);
                    ciSize--;
                }
                else
                    i++;
            }
            if (plainText[ciSize - 1] == 'x' )
               plainText = plainText.Remove(ciSize - 1, 1);
            
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            char[,] key2d = new char[5, 5];
            int[] x = new int[123];
            int[] y = new int[123];
            convertKey(key, key2d,x,y);
            int plSize = plainText.Length;
            char c1, c2;
            int x1, x2, y1, y2;
            for(int i=0;i<plSize;)
            {
                c1 = plainText[i];
                if (i < plSize - 1)
                    c2 = plainText[i + 1];
                else
                    c2 = 'x';
                
                if(c1 == c2)
                {
                    c2 = 'x';
                    i++;
                }
                else if( c1 != c2)
                    i += 2;
                x1 = x[c1];
                x2 = x[c2];
                y1 = y[c1];
                y2 = y[c2];

                if(x1 == x2) //same row
                {
                    cipherText += key2d[x1,(y1+1)%5];
                    cipherText += key2d[x2, (y2 + 1) % 5];
                }
                else if(y1 == y2)
                {
                    cipherText += key2d[(x1+1) % 5, y1];
                    cipherText += key2d[(x2 + 1) % 5, y2];
                }
                else
                {
                    cipherText += key2d[x1,y2];
                    cipherText += key2d[x2, y1];                
                }
            }

            return cipherText;
        }
    }
}
