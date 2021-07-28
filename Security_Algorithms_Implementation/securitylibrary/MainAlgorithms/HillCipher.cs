using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();

            int det = plainText[0] * plainText[3] - plainText[1] * plainText[2];
            if (det != 1 || det != -1)
                throw new InvalidAnlysisException();

            List<int> inversePlain = new List<int>();
            inversePlain.Add((plainText[3]*det) %26);
            inversePlain.Add((plainText[1]* -1 * det) %26);
            inversePlain.Add((plainText[2] * -1 * det) % 26);
            inversePlain.Add((plainText[0] * det) % 26);



            return key;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            throw new NotImplementedException();
        }

        private void convertKey(List<int> key, int[,] conKey)
        {
            int keysqr = Convert.ToInt16(Math.Sqrt(key.Count));
            for (int i = 0, x = 0, y = 0; i < key.Count; i++)
            {
                conKey[x, y++] = key[i];
                if (y == keysqr)
                { y = 0; x++; }
            }
        }
        private void mulData(int[,] conKey, int conKeySize, int[] data, int[] res) 
        {
            int dataSize = data.Length;
            int sum;
            for(int i=0; i<dataSize; i++)
            {
                sum = 0;
                for (int j = 0; j < dataSize; j++)
                    sum += data[j] * conKey[i, j];
                res[i] = sum%26;
            }        
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherText = new List<int>();
            int plSize = plainText.Count;
            int keysqr = Convert.ToInt16(Math.Sqrt(key.Count));
            int[,] conKey = new int[keysqr,keysqr];
            convertKey(key,conKey);
            int[] res = new int[keysqr];
            int[] data = new int[keysqr];
            int c = 0;
            for(int i=0;i<plSize;i++)
            {
                data[c++] = plainText[i];    
                if((i+1)%keysqr == 0) 
                {
                    mulData(conKey, keysqr, data, res);
                    c = 0;
                    for (int j = 0; j < keysqr; j++)
                        cipherText.Add(res[j]);
                }
            }

            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

    }
}
