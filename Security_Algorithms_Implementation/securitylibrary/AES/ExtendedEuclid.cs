using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        // Function to find modulo inverse of a
        // Function for extended Euclidean Algorithm

        private long GCD(long A,long B)
        {
            if (B == 0)
                return A;
           return GCD(B, A%B);
        }
        private int EE(int b, int m)
        {
            int A1 = 1, A2 = 0, A3 = m;
            int B1 = 0, B2 = 1, B3 = b;
            while (true)
            {
                if (B3 == 0)
                    return -1;
                else if (B3 == 1)
                    return (B2 + m) % m;
                int Q = A3 / B3;
                int T1 = A1 - Q*B1, T2 = A2 - Q*B2, T3 = A3 - Q*B3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = T1;
                B2 = T2;
                B3 = T3;
            }
        }
        private int iterativeMethod(int number, int baseN) 
        {
            for (long i = 1; i < number; i++)
                  if (((number%baseN) * (i%baseN)) % baseN == 1)
                      return (int)i;
              return -1;
        }
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            if (GCD(number, baseN) != 1)
                return -1;
            return EE(number, baseN);
        }
    }
}
