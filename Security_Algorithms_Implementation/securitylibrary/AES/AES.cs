using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    /// /*comments*/
    // a = 97  z = 122
    // A = 65  Z = 90
    // 0 = 48

    public class AES : CryptographicTechnique
    {
        private string inverseBox = "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d";
        private string sBox = "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16";
        private string[,] sBox2d = new string[16, 16];
        string[,] pl2d;
        string[,] ci2d;
        string[,] key2d;
        int[,] mulTable = new int[,] { { 2, 3, 1, 1 }, { 1, 2, 3, 1 }, { 1, 1, 2, 3 }, { 3, 1, 1, 2 } };
        int[,] mulTable2 = new int[,] { { 14, 11, 13, 9 }, { 9, 14, 11, 13 }, { 13, 9, 14, 11 }, { 11, 13, 9, 14 } };
        string[] bina = {"0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111",
                            "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111",};
        char[] dig = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        string[] rcon = { "00", "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" };
        bool done1 = false;
        bool done2 = false;
        private void convertStringto2d(string text, int end, string[,] arr)
        {
            int count = 0;
            for (int i = 0; i < end; i++)
                for (int j = 0; j < end; j++)
                {
                    arr[i, j] = text.Substring(count, 2);
                    count += 2;
                }
        }
        private void convertStringto2d2(string text, int end, string[,] arr)
        {
            int count = 0;
            for (int i = 0; i < end; i++)
                for (int j = 0; j < end; j++)
                {
                    arr[j, i] = text.Substring(count, 2);
                    count += 2;
                }
        }
        private int getIndex(char c)
        {

            if (c >= '0' && c <= '9')
                return c - 48;
            return c - 87;   ///ab...yz --> sub 97 will get 0 then add 10
        }
        private void convertToSubByte(string[,] arr)
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    arr[i, j] = sBox2d[getIndex(arr[i, j][0]), getIndex(arr[i, j][1])];
        }
        private void shiftColumn(string[,] arr)
        {
            string temp;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < i; j++)
                    for (int k = 0; k < 3; k++) // 4 - 1 = 3
                    {
                        temp = arr[i, k];
                        arr[i, k] = arr[i, k + 1];
                        arr[i, k + 1] = temp;
                    }
        }
        private void shiftColumn2(string[,] arr)
        {
            string temp;
            for (int i = 1; i < 4; i++)
                for (int j = 0; j < 4 - i; j++)
                    for (int k = 0; k < 3; k++) // 4 - 1 = 3
                    {
                        temp = arr[i, k];
                        arr[i, k] = arr[i, k + 1];
                        arr[i, k + 1] = temp;
                    }
        }
        private string getBinary(string s)
        {
            string ans = "";
            ans += bina[getIndex(s[0])] + bina[getIndex(s[1])];
            return ans;
        }
        private string XoR(string x, string y)
        {
            string ans = "";
            for (int i = 0; i < 8; i++)
                if (x[i] != y[i])
                    ans += '1';
                else
                    ans += '0';
            return ans;
        }
        private string getHexa(string x)
        {
            string ans = "";
            string temp1 = x.Substring(0, 4);
            string temp2 = x.Substring(4, 4);
            for (int i = 0; i < 16; i++)
                if (temp1 == bina[i])
                    ans += dig[i];
            for (int i = 0; i < 16; i++)
                if (temp2 == bina[i])
                    ans += dig[i];
            return ans;
        }
        private string makeMix(int i, int j)
        {
            string ans;
            string temp;
            string[] data = new string[4];

            for (int k = 0; k < 4; k++)
            {
                temp = getBinary(pl2d[k, j]);
                if (mulTable[i, k] == 1)
                    data[k] = temp;
                else if (mulTable[i, k] == 2)
                    data[k] = its2(temp);
                else
                    data[k] = XoR(its2(temp), temp);
            }
            ans = XoR(XoR(XoR(data[0], data[1]), data[2]), data[3]);

            ans = getHexa(ans);
            return ans;
        }
        private string[,] mixCol()
        {
            string[,] mixed = new string[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    mixed[i, j] = makeMix(i, j);
            return mixed;
        }
        private string its2(string temp) 
        {
            string temp2 = temp;
            if (temp2[0] == '0')
            {
                temp2 = temp2.Remove(0, 1);
                temp2 += '0';
            }
            else
            {
                temp2 = temp2.Remove(0, 1);
                temp2 += '0';
                temp2 = XoR(temp2, "00011011"); ////////00010001
            }
            return temp2;
        }
        private string makeMix2(int i, int j)
        {
            string ans = "";
            string temp;
            string temp2;
            string[] data = new string[4];

            for (int k = 0; k < 4; k++)
            {
                temp = "";
                temp += getBinary(pl2d[k, j]);
                temp2 = temp;
               if (mulTable2[i, k] == 9)
                {
                    temp = its2(temp);
                    temp = its2(temp);
                    temp = its2(temp);
                    data[k] = XoR(temp,temp2);
                }
                else if (mulTable2[i, k] == 11)
                {
                    temp = its2(temp);
                    temp = its2(temp);
                    temp = XoR(temp, temp2);
                    temp = its2(temp);
                    data[k] = XoR(temp, temp2);
                }
                else if (mulTable2[i, k] == 13)
                {
                    temp = its2(temp);
                    temp = XoR(temp, temp2);
                    temp = its2(temp);
                    temp = its2(temp);
                    data[k] = XoR(temp, temp2);
                }
                else if (mulTable2[i, k] == 14)
                {
                    temp = its2(temp);
                    temp = XoR(temp, temp2);
                    temp = its2(temp);
                    temp = XoR(temp, temp2);
                    data[k] = its2(temp);
                }
            }
            ans = XoR(XoR(XoR(data[0], data[1]), data[2]), data[3]);
            ans = getHexa(ans);
            return ans;
        }
        private string[,] mixCol2()
        {
            string[,] mixed = new string[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    mixed[i, j] = makeMix2(i, j);
            return mixed;
        }
        private void plainMulKey()
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    pl2d[i, j] = getHexa(XoR(getBinary(pl2d[i,j]),getBinary(key2d[i,j])));
        }
        private string[,] genrateNewkey(int round)
        {
            string[,] tempKey = new string[4, 4];
            for(int i=0;i<4;i++)
                tempKey[i, 0] = sBox2d[getIndex(key2d[(i+1)%4, 3][0]), getIndex(key2d[(i+1)%4, 3][1])];
             
            for(int i=0;i<4;i++)
            {
                 tempKey[i,0] = getHexa(XoR(getBinary(tempKey[i, 0]), getBinary(key2d[i, 0])));
                if(i==0)
                    tempKey[i,0] = getHexa(XoR(getBinary(tempKey[i, 0]), getBinary(rcon[round])));
            }
            
            for(int j=1;j<4;j++)
                for(int i = 0; i<4;i++)
                    tempKey[i, j] = getHexa(XoR(getBinary(key2d[i, j]), getBinary(tempKey[i, j-1])));

            return tempKey;
        }

        private string[,,] AllKeys() 
        {
            string[,,] keys = new string[11,4,4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    keys[0, i, j] = key2d[i, j];

            for (int k = 1; k <= 10; k++)
            {
                key2d = genrateNewkey(k);
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < 4; j++)
                        keys[k, i, j] = key2d[i, j];
            }
                return keys;
        }
        string[,,] keys;
        private void genrateNewkey2(int round) 
        {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    key2d[i, j] = keys[round, i, j];
        }

        public override string Encrypt(string plainText, string key)
        {
            if(done1 == false)
            {
                convertStringto2d(sBox, 16, sBox2d);
                done1 = true;
            }
            string cipherText = "0x";
             // key = "0x2b28ab097eaef7cf15d2154f16a6883c";
             // plainText = "0x328831e0435a3137f6309807a88da234";
            plainText = plainText.ToLower();
            key = key.ToLower();
            pl2d = new string[4, 4];
            key2d = new string[4, 4];
            convertStringto2d2(plainText.Remove(0, 2), 4 , pl2d);
            convertStringto2d2(key.Remove(0,2),4, key2d);
            

            for(int i= 0;i<=10;i++)
            {
                if(i==0) // initial round
                    plainMulKey();           
                
                else if(i>0&&i<10) // rounds
                {
                    convertToSubByte(pl2d);
                    shiftColumn(pl2d);
                    pl2d = mixCol();
                    key2d = genrateNewkey(i);
                    plainMulKey();
                }
                else if(i==10)//final round
                {
                    convertToSubByte(pl2d);
                    shiftColumn(pl2d);
                    key2d = genrateNewkey(i);
                    plainMulKey();
                }
            }
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    cipherText += pl2d[j,i];

            return cipherText;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string plinText = "0x";
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            pl2d = new string[4, 4];
            key2d = new string[4, 4];
            // key = "0x2b28ab097eaef7cf15d2154f16a6883c";
            // plainText = "0x328831e0435a3137f6309807a88da234";
            //cipherText = "0x3902dc1925dc116a8409850b1dfb9732"; 


            convertStringto2d2(cipherText.Remove(0, 2), 4, pl2d);
            convertStringto2d2(key.Remove(0, 2), 4, key2d);

            convertStringto2d(sBox, 16, sBox2d);
         
            keys = new string[11, 4, 4];
            keys = AllKeys();
            
            convertStringto2d(inverseBox, 16, sBox2d);

            for (int i = 0; i <=10; i++)
            {
                if (i == 0) // initial round
                {
                    genrateNewkey2(10- i);  ///
                    plainMulKey();
                }
                else if (i > 0 && i < 10) // rounds
                {
                    shiftColumn2(pl2d);
                    convertToSubByte(pl2d);
                    genrateNewkey2(10 - i);  ///
                    plainMulKey();
                    pl2d = mixCol2();
                }
                else if (i == 10)//final round
                {
                    shiftColumn2(pl2d);
                    convertToSubByte(pl2d);
                    genrateNewkey2(10 - i);  ///
                    plainMulKey();
                }
            }
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    plinText += pl2d[j, i];
            return plinText;
        }
    }
}
