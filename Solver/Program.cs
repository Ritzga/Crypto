using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using Microsoft.VisualBasic;

namespace Solver
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            //OneTimePad.Encrypt(new[] {1,0,0,0,0,1,1,0,0,0,0}, new[] { 0, 0, 0, 1, 1, 0, 1, 0, 1 });
            //OneTimePad.Decrypt(new[] {0,1,1,1,0,1,0,1,0,1,1,0,1}, new[] {0,0,0,1,0,0,1,0,0});
            //
            //RSA.TryModInverse(27, 37, out var test);
            //
            //BlockCipher.ECB(0b011, "000	100	010	110	001	101	011	111", 0b110, 0b110, 0b011);
            //BlockCipher.CBC(0b011, "000	100	010	110	001	101	011	111", 0b110, 0b110, 0b110, 0b011);
            //BlockCipher.CFB(0b011, "101	110	010	011	001	111	100	000", 0b001, 0b000, 0b111, 0b111);
            //BlockCipher.CTR(0b101, "100	000	110	010	101	001	111	011", 0b010, 0b111, 0b010, 0b010);
            //BlockCipher.OFB(0b100, "001	100	010	101	000	011	110	111", 0b011, 0b000, 0b000, 0b011);
            //
            //Hash.MerkleDamgardConstruction(new[,]
            //{
            //    { 1, 1, 0, 0, 0, 1, 1 },
            //    { 1, 1, 1, 0, 0, 0, 1 },
            //    { 1, 1, 1, 1, 0, 0, 0 },
            //    { 0, 1, 1, 1, 1, 0, 0 }
            //}, "10010", "0000", 2);
            //
            //RSA.Encrypt("HTML", 23, 29, 9, 2);
            //RSA.Decrypt(new[] { 468,286,121,302,521 }, 19, 29, 101, 2);
            //RSA.EncryptDecrypt(new[] { 16,13,12,16 }, 3, 7, 5, 2);
            //RSA.MultiplyAndSquare(16, 5, 21);
            RSA.PollardsRho(2279, 5, i => i*i + 1); //like y = f(x)= x^2 + 1
            //
            //DiscreteLogarithm.DiffieHellman(3457, 7, 990);
            //DiscreteLogarithm.ElGamalEncrypt(71, 19, 8, 30, 11);
            //DiscreteLogarithm.ElGamalDecrypt(71, 16, 40, 20);
            //DiscreteLogarithm.ElGamalSignSystem(79,12,16,10, 33, 17);
            //
            //EllipticCurve.IsPointInFunction(1, 263, 2, 3, true);
            //EllipticCurve.PointPlusPoint((4, 148), (5, 140), 263, 2, 3, true);
            //EllipticCurve.NumberMultPoint(4, (4, 148), 263, 2, 3, true);
            //EllipticCurve.Encrypt(11, (2, 10), (2, 1), 1, 2, 2, 7);
            //EllipticCurve.Decrypt(19, 2, (10, 0), 3, 1, 6);
        }
    }

    public static class OneTimePad
    {
        /// <summary>
        /// Returns cipher text
        /// </summary>
        /// <param name="k">key</param>
        /// <param name="m">message</param>
        public static void Encrypt(int[] k, int[] m)
        {
            Console.WriteLine("----OnetimePad Encrypt----");
            Console.WriteLine("K= " + string.Join("", k));
            Console.WriteLine("m= " + string.Join("", m));
            for (var i = 0; i < m.Length; i++)
            {
                m[i] ^= k[i];
            }
            Console.WriteLine("c= " + string.Join("", m));
            Console.WriteLine("Informationstheoretisch gegen Kryptanalyse sicher und kann nicht entziffert werden, " +
                              "wenn der Schlüssel genauso lang ist wie die Nachricht und aus Zeichen besteht, die " +
                              "zufällig und unabhängig sind, und wenn er nur einmal zur Verschlüsselung verwendet wird.");
            Console.WriteLine("Der Schlüssel muss aus echten Zufallsziffern bestehen; keine Mehrfachnutzung des " +
                              "Schlüssels, kein Preisgeben des Schlüssels");
        }

        /// <summary>
        /// Returns message
        /// </summary>
        /// <param name="k">key</param>
        /// <param name="c">cipher text</param>
        public static void Decrypt(int[] k, int[] c)
        {
            Console.WriteLine("----OnetimePad Decrypt----");
            Console.WriteLine("K= " + string.Join("", k));
            Console.WriteLine("c= " + string.Join("", c));
            for (var i = 0; i < c.Length; i++)
            {
                c[i] ^= k[i];
            }
            Console.WriteLine("m= " + string.Join("", c));
            Console.WriteLine("Eine Known-Plaintext-Attacke bedeutet, dass ein Angreifer Zugang sowohl zum Klartext " +
                              "m als auch zum Geheimtext c hat.");
            Console.WriteLine("Wenn Oskar sowohl einen Klartext m als auch einen Geheimtext c kennt, dann kann er " +
                              "durch K:=m xor c den benutzten Schlüssel K berechnen. Begehen Alice und Bob den Fehler, " +
                              "den gleichen Schlüssel K mehrfach zu verwenden, dann kann Oskar alle diese Chiffren c " +
                              "durch c xor K entschlüsseln.");
        }
    }

    public static class BlockCipher
    {
        /// <summary>
        /// parse strings to binary number
        /// </summary>
        /// <param name="s">string</param>
        /// <returns>binary numbers</returns>
        public static int[] StringToNumbers(string s)
        {
            var split = s.Replace("\t", " ").Split(" ".ToCharArray());
            var le = new int[split.Length];
            for (var i = 0; i < split.Length; i++)
            {
                le[i] = Convert.ToInt32(split[i], 2);
            }
            return le;
        }

        /// <summary>
        /// shuffle binary numbers (pi of x)
        /// </summary>
        /// <param name="x">number to shuffle</param>
        /// <param name="f">array of numbers to shuffle with</param>
        /// <returns></returns>
        public static int PiK(int x, int[] f)
        {
            return f[x];
        }
        
        /// <summary>
        /// Represents the Electronic-Codebook-Mode
        /// </summary>
        /// <param name="xor">number to xor with on e_k</param>
        /// <param name="ps">string to shuffle</param>
        /// <param name="m">message to decrypt</param>
        public static void ECB(int xor, string ps, params int[] m)
        {
            Console.WriteLine("----BlockCipher ECB----");
            Console.WriteLine(
                "Effizient berechenbar, aber Reihenfolge der chiffrierten Blöcke kann unbemerkt verändert werden; " +
                "gleiche Klartextblöcke werden durch gleiche Codeblöche chiffriert");
            var numbers = StringToNumbers(ps);
            
            for (var i = 0; i < m.Length; i++)
            {
                Console.WriteLine("c" + i + "= " + Convert.ToString(PiK(m[i], numbers)^xor, 2).PadLeft(3, '0'));
            }
        }
        
        /// <summary>
        /// Represents the Block-Chaining-Mode
        /// </summary>
        /// <param name="xor">number to xor with on e_k</param>
        /// <param name="ps">string to shuffle</param>
        /// <param name="c0">first c to start with</param>
        /// <param name="m">message to decrypt</param>
        public static void CBC(int xor, string ps, int c0, params int[] m)
        {
            Console.WriteLine("----BlockCipher CBC----");
            Console.WriteLine(
                "Reihenfolge der chiffrierten Blöcke kann nicht unbemerkt verändert werden; gleiche Klartextblöcke " +
                "werden durch verschiedene Codeblöche chiffriert");
            var numbers = StringToNumbers(ps);
            var ci = c0;
            Console.WriteLine("c0= " + Convert.ToString(ci, 2).PadLeft(3, '0'));
            for (var i = 0; i < m.Length; i++)
            {
                //ci+1
                ci = PiK(m[i]^ ci, numbers)^xor;
                Console.WriteLine("c" + (i + 1) + "= " + Convert.ToString(ci, 2).PadLeft(3, '0'));
            }
        }
        
        /// <summary>
        /// Represents the Cipher-Feedback-Mode
        /// </summary>
        /// <param name="xor">number to xor with on e_k</param>
        /// <param name="ps">string to shuffle</param>
        /// <param name="c0">first c to start with</param>
        /// <param name="m">message to decrypt</param>   
        public static void CFB(int xor, string ps, int c0, params int[] m)
        {
            Console.WriteLine("----BlockCipher CFB----");
            Console.WriteLine(
                "Reihenfolge der chiffrierten Blöcke kann nicht unbemerkt verändert werden; gleiche Klartextblöcke" +
                " werden durch verschiedene Codeblöcke chiffriert; Effiziente Implementierung, da Ver- und " +
                "Entschlüsseln gleich sind");
            var numbers = StringToNumbers(ps);
            var ci = c0;
            var cString = Convert.ToString(ci, 2).PadLeft(3, '0');
            var zString = "";
            for (var i = 0; i < m.Length; i++)
            {
                //zi
                var zi = PiK(ci, numbers)^xor;
                zString += ", " + Convert.ToString(zi, 2).PadLeft(3, '0');
                //ci
                ci = zi ^ m[i];
                cString += ", " + Convert.ToString(ci, 2).PadLeft(3, '0');
            }

            Console.WriteLine("c= " + cString);
            Console.WriteLine("z= " + zString);
        }

        /// <summary>
        /// Represents the Counter-Mode
        /// </summary>
        /// <param name="xor">number to xor with on e_k</param>
        /// <param name="ps">string to shuffle</param>
        /// <param name="c0">first c to start with</param>
        /// <param name="m">message to decrypt</param>
        public static void CTR(int xor, string ps, int c0, params int[] m)
        {
            Console.WriteLine("----BlockCipher CTR----");
            Console.WriteLine(
                "Reihenfolge der chiffrierten Blöcke kann nicht unbemerkt verändert werden; gleiche Klartextblöcke " +
                "werden durch verschiedene Codeblöcke chiffriert, leichte Parallelisierbarkeit");
            var numbers = StringToNumbers(ps);
            var ci = c0;
            var cString = Convert.ToString(ci, 2).PadLeft(3, '0');
            var zString = "";
            for (var i = 1; i < m.Length + 1; i++)
            {
                //TODO modulo 8 to dynamic 2^m.length
                //zi
                var zi = PiK((c0 + i) % 8, numbers)^xor;
                zString += ", " + Convert.ToString(zi, 2).PadLeft(3, '0');
                //ci
                ci = zi ^ m[i - 1];
                cString += ", " + Convert.ToString(ci, 2).PadLeft(3, '0');
            }

            Console.WriteLine("c= " + cString);
            Console.WriteLine("z= " + zString);
        }

        /// <summary>
        /// Represents the Output-Feedback-Mode
        /// </summary>
        /// <param name="xor">number to xor with on e_k</param>
        /// <param name="ps">string to shuffle</param>
        /// <param name="c0">first c to start with</param>
        /// <param name="m">message to decrypt</param>
        public static void OFB(int xor, string ps, int c0, params int[] m)
        {
            Console.WriteLine("----BlockCipher OFB----");
            Console.WriteLine(
                "Reihenfolge der chiffrierten Blöcke kann nicht unbemerkt verändert werden; gleiche Klartextblöcke " +
                "werden durch verschiedene Codeblöcke chiffriert; Effiziente Implementierung, da Ver- und " +
                "Entschlüsseln gleich sind; Schlüsselstrom kann vorab berechnet werden bei bekanntem c0");
            var numbers = StringToNumbers(ps);
            var ci = c0;
            var cString = Convert.ToString(ci, 2).PadLeft(3, '0');
            var zString = "";
            var zi = c0;
            for (var i = 1; i < m.Length + 1; i++)
            {
                //zi
                zi = PiK(zi, numbers)^xor;
                zString += ", " + Convert.ToString(zi, 2).PadLeft(3, '0');
                //ci
                ci = zi ^ m[i - 1];
                cString += ", " + Convert.ToString(ci, 2).PadLeft(3, '0');
            }

            Console.WriteLine("c= " + cString);
            Console.WriteLine("z= " + zString);
        }
    }

    public static class Hash
    {
        /// <summary>
        /// Do the Merkle Damgard
        /// </summary>
        /// <param name="a">matrix for encryption</param>
        /// <param name="h">message to encrypt</param>
        /// <param name="z0">z to start with e.g. 0</param>
        /// <param name="blockLength">block length</param>
        public static void MerkleDamgardConstruction(int[,] a, string h, string z0, int blockLength)
        {
            Console.WriteLine("----Hash function MerkleDamgard Construction----");
            var zeroAdd = h.Length % blockLength;
            var padding = h;
            for (var i = 0; i <= zeroAdd; i++)
            {
                padding += "0";
            }

            padding += Convert.ToInt32(zeroAdd.ToString(), 2).ToString();
            Console.WriteLine("Padding: " + padding);
            var next = z0;
            Console.WriteLine("z0 = " + next);
            for (var i = 0; i * blockLength < padding.Length; i++)
            {
                string zi;
                if (i == 0)
                {
                    zi = next + "0" + padding[..2];
                }
                else
                {
                    zi = next + "1" + padding[(i * blockLength)..(i * blockLength + blockLength)];
                }

                var matZi = new int[7, 1];
                for (var j = 0; j < a.GetLength(1); j++)
                {
                    matZi[j, 0] = int.Parse(zi[j] + "");
                }

                var test = Mult(a, matZi);
                next = "";
                next = test.Cast<int>().Aggregate(next, (current, x) => current + x);
                Console.WriteLine("z" + (i + 1) + "= h*(" +
                                  matZi.Cast<int>().Aggregate("", (current, x) => current + x) + ") = " + next);
            }

            Console.WriteLine("h(" + h + ")= " + next);
        }

        /// <summary>
        /// matrix multiply
        /// </summary>
        /// <param name="matrix1">matrix 1</param>
        /// <param name="matrix2">matrix 2</param>
        /// <returns>multiply of matrices</returns>
        /// <exception cref="InvalidOperationException"></exception>
        private static int[,] Mult(int[,] matrix1, int[,] matrix2)
        {
            // caching matrix lengths for better performance  
            var matrix1Rows = matrix1.GetLength(0);
            var matrix1Cols = matrix1.GetLength(1);
            var matrix2Rows = matrix2.GetLength(0);
            var matrix2Cols = matrix2.GetLength(1);

            // checking if product is defined  
            if (matrix1Cols != matrix2Rows)
                throw new InvalidOperationException(
                    "Product is undefined. n columns of first matrix must equal to n rows of second matrix");

            // creating the final product matrix  
            var product = new int[matrix1Rows, matrix2Cols];

            for (var matrix1Row = 0; matrix1Row < matrix1Rows; matrix1Row++)
            {
                for (var matrix2Col = 0; matrix2Col < matrix2Cols; matrix2Col++)
                {
                    for (var matrix1Col = 0; matrix1Col < matrix1Cols; matrix1Col++)
                    {
                        product[matrix1Row, matrix2Col] +=
                            matrix1[matrix1Row, matrix1Col] * matrix2[matrix1Col, matrix2Col];
                        product[matrix1Row, matrix2Col] %= 2; //to make it 1 or 0
                    }
                }
            }

            return product;
        }
    }

    // ReSharper disable once InconsistentNaming
    public static class RSA
    {
        /// <summary>
        /// A-Z to 1-26
        /// </summary>
        /// <param name="i">char to cast</param>
        /// <returns>cast int</returns>
        /// <exception cref="ArgumentOutOfRangeException">Char not defined</exception>
        private static int CharToInt(char i)
        {
            return i switch
            {
                'A' => 1, 'B' => 2,'C' => 3,'D' => 4,'E' => 5,'F' => 6,'G' => 7,'H' => 8,'I' => 9,'J' => 10,'K' => 11,
                'L' => 12,'M' => 13,'N' => 14,'O' => 15,'P' => 16,'Q' => 17,'R' => 18,'S' => 19,'T' => 20,'U' => 21,
                'V' => 22,'W' => 23,'X' => 24,'Y' => 25,'Z' => 26,
                _ => throw new ArgumentOutOfRangeException("", $"{i}not supported value"),
            };
        }
        /// <summary>
        /// 1-26 to A-Z
        /// </summary>
        /// <param name="i">int to cast</param>
        /// <returns>cast char</returns>
        /// <exception cref="ArgumentOutOfRangeException">Number is not between 1-26</exception>
        private static char IntToChar_1_26(int i)
        {
            return i switch
            {
                1 => 'A',2 => 'B',3 => 'C',4 => 'D',5 => 'E',6 => 'F',7 => 'G',8 => 'H',9 => 'I',10 => 'J',11 => 'K',
                12 => 'L',13 => 'M',14 => 'N',15 => 'O',16 => 'P',17 => 'Q',18 => 'R',19 => 'S',20 => 'T',21 => 'U',
                22 => 'V',23 => 'W',24 => 'X',25 => 'Y',26 => 'Z',
                _ => throw new ArgumentOutOfRangeException("", $"{i}not supported value"),
            };
        }
        /// <summary>
        /// 0-25 to A-Z
        /// </summary>
        /// <param name="i">int to cast</param>
        /// <returns>cast char</returns>
        /// <exception cref="ArgumentOutOfRangeException">Number is not between 0-25</exception>
        private static char IntToChar_0_25(int i)
        {
            return i switch
            {
                0 => 'A', 1 => 'B', 2 => 'C', 3 => 'D', 4 => 'E', 5 => 'F', 6 => 'G', 7 => 'H', 8 => 'I', 9 => 'J', 
                10 => 'K', 11 => 'L', 12 => 'M', 13 => 'N', 14 => 'O', 15 => 'P', 16 => 'Q', 17 => 'R', 18 => 'S',
                19 => 'T', 20 => 'U', 21 => 'V', 22 => 'W', 23 => 'X', 24 => 'Y', 25 => 'Z',
                _ => throw new ArgumentOutOfRangeException("", $"{i}not supported value"),
            };
        }
        /// <summary>
        /// inverse modulo of a number 
        /// </summary>
        /// <param name="number">number operator</param>
        /// <param name="modulo">modulo operator</param>
        /// <param name="result">inverse modulo</param>
        /// <returns>if there is a inverse modulo</returns>
        /// <exception cref="ArgumentOutOfRangeException">is negative or below 2</exception>
        public static bool TryModInverse(int number, int modulo, out int result)
        {
            if (number < 1) throw new ArgumentOutOfRangeException(nameof(number));
            if (modulo < 2) throw new ArgumentOutOfRangeException(nameof(modulo));
            var n = number;
            int m = modulo, v = 0, d = 1;
            while (n > 0)
            {
                int t = m / n, x = n;
                n = m % x;
                m = x;
                x = d;
                d = checked(v - t * x); // Just in case
                v = x;
            }

            result = v % modulo;
            if (result < 0) result += modulo;
            if ((long)number * result % modulo == 1L) return true;
            result = default;
            return false;
        }

        /// <summary>
        /// Encrypt the message with RSA
        /// </summary>
        /// <param name="m">message to encrypt</param>
        /// <param name="p">first prime number</param>
        /// <param name="q">second prime number</param>
        /// <param name="e">cyclic group (exponent)</param>
        /// <param name="blockSize">block size</param>
        public static void Encrypt(string m, int p, int q, int e, int blockSize)
        {
            Console.WriteLine("----RSA Encrypt----");
            var n = p * q;
            var phi = (p - 1) * (q - 1);
            if (!TryModInverse(e, phi, out var d))
            {
                Console.WriteLine("nope!");
                return;
            }

            var charNumbers = new int[m.Length];
            for (var i = 0; i < m.Length; i++)
            {
                charNumbers[i] = CharToInt(m[i]);
            }

            Console.Write("char to int: ");
            foreach (var i in charNumbers)
            {
                Console.Write(i + ", ");
            }

            Console.WriteLine();

            var pair = new int[m.Length / blockSize];
            for (var i = 0; i < charNumbers.Length / blockSize; i++)
            {
                pair[i] = (charNumbers[i * 2] - 1) * 26 + charNumbers[i * 2 + 1];
            }

            Console.Write("new pair: ");
            foreach (var i in pair)
            {
                Console.Write(i + ", ");
            }

            Console.WriteLine();

            Console.Write("encrypted pair: ");
            foreach (var i in pair)
            {
                Console.Write(BigInteger.ModPow(i, e, n) + ", ");
            }

            Console.WriteLine();
            Console.WriteLine("d= " + d);
        }
        
        /// <summary>
        /// Decrypt the message with RSA
        /// </summary>
        /// <param name="m">cipher text to decrypt</param>
        /// <param name="p">first prime number</param>
        /// <param name="q">second prime number</param>
        /// <param name="e">cyclic group (exponent) of x^e mod (p*q)</param>
        /// <param name="blockSize">block size</param>
        public static void Decrypt(int[] m, int p, int q, int e, int blockSize)
        {
            Console.WriteLine("----RSA Decrypt----");
            var n = p * q;
            var phi = (p - 1) * (q - 1);
            TryModInverse(e, phi, out var d);
            Console.WriteLine("d=" + d);
            Console.Write("Zahlenpaarfolge: ");
            var numberChars = new int[m.Length];
            for (var i = 0; i < m.Length; i++)
            {
                numberChars[i] = (int)BigInteger.ModPow(m[i], d, n);
                Console.Write(numberChars[i] + ", ");
            }

            Console.WriteLine();

            Console.Write("Zeichenfolge in Nummern:");
            var chars = "";
            for (var i = 0; i < m.Length; i++)
            {
                var v = ((numberChars[i] - 1) % 26) + 1;
                var u = (numberChars[i] - v) / 26 + 1;
                Console.Write(u + ", ");
                Console.Write(v + ", ");
                chars += IntToChar_1_26(u);
                chars += IntToChar_1_26(v);
            }

            Console.WriteLine();

            Console.WriteLine("Zeichenfolge in Zeichen: " + chars);
        }

        /// <summary>
        /// De- and encrypt with RSA
        /// </summary>
        /// <param name="m">message to encrypt</param>
        /// <param name="p">first prime number</param>
        /// <param name="q">second prime number</param>
        /// <param name="e">cyclic group</param>
        /// <param name="blockSize">block size</param>
        public static void EncryptDecrypt(int[] m, int p, int q, int e, int blockSize)
        {
            Console.WriteLine("----RSA Encrypt/Decrypt----");
            var n = p * q;
            var phi = (p - 1) * (q - 1);
            if (!TryModInverse(e, phi, out var d))
            {
                Console.WriteLine("nope!");
                return;
            }

            Console.WriteLine("Ke= (n,e) = (" + n + ", " + e + ")");
            Console.WriteLine("Ke= (n,d) = (" + n + ", " + d + ")");

            Console.Write("Zeichenfolge in Nummern:");
            var numberChars = new int[m.Length];
            for (var i = 0; i < m.Length; i++)
            {
                numberChars[i] = (int)BigInteger.ModPow(m[i], d, n);
                Console.Write(numberChars[i] + ", ");
            }

            Console.WriteLine();

            var chars = "";
            for (var i = 0; i < m.Length; i++)
            {
                chars += IntToChar_0_25(numberChars[i]);
            }

            Console.Write("Zeichenfolge in Zeichen: " + chars + "\n");
            Console.WriteLine("Jeden Buchstaben direkt durch eine Zahl kodieren und diese verschlüsseln.");
            Console.WriteLine("p,q oder verschlüsselte Nachricht mit d,n oder φ(n) veröffentlichen.");
        }
        
        /// <summary>
        /// Test of multiply and square to calculate big numbers
        /// </summary>
        /// <param name="m1">message</param>
        /// <param name="d">second part of public key</param>
        /// <param name="n">modulo number (p*q)</param>
        /// <returns></returns>
        public static int MultiplyAndSquare(int m1, int d, int n)
        {
            Console.WriteLine("----RSA MultiplyAndSquare----");
            var r = 1;
            Console.WriteLine("r= " + r);
            Console.WriteLine("a= " + m1);
            var bbin = new string(Convert.ToString(d, 2).ToCharArray().Reverse().ToArray());
            for (int i = 0; i < bbin.Length; i++)
            {
                if (bbin[i] == '1')
                {
                    r = (r * m1) % n;
                }

                m1 = ((int)BigInteger.Pow(m1, 2)) % n;
                Console.Write(bbin[i] + ", ");
                Console.Write(r + ", ");
                Console.Write(m1 + ", ");
                Console.WriteLine();
            }

            return r; //a^b mod n
        }

        /// <summary>
        /// Get the greatest common divisor
        /// </summary>
        /// <param name="p">number one</param>
        /// <param name="q">number two</param>
        /// <returns>greatest common divisor</returns>
        private static int GCD(int p, int q)
        {
            if (q == 0)
            {
                return p;
            }

            var r = p % q;
            return GCD(q, r);
        }

        /// <summary>
        /// Modulo with negative numbers
        /// </summary>
        /// <param name="x">number</param>
        /// <param name="m">modulo</param>
        /// <returns>positive modulo number</returns>
        public static int Mod(int x, int m)
        {
            return (x % m + m) % m;
        }

        /// <summary>
        /// Represent the pollards rho
        /// </summary>
        /// <param name="n">number</param>
        /// <param name="x0">x to start with</param>
        /// <param name="f">function to use</param>
        /// <returns>returns int pair</returns>
        public static (int, int) PollardsRho(int n, int x0, Func<int, int> f)
        {
            Console.WriteLine("----PollardsRho----");
            var xi = f(x0) % n;
            var x2i = f(xi) % n;
            var di = Mod(x2i - xi, n);
            var r = GCD(di, n);
            Console.WriteLine();
            Console.Write(xi + ", ");
            Console.Write(x2i + ", ");
            Console.Write(di + ", ");
            Console.Write(r);
            while (xi != x2i && r == 1)
            {
                xi = f(xi) % n;
                x2i = f(f(x2i) % n) % n;
                di = Mod(x2i - xi, n);
                r = GCD(di, n);
                Console.WriteLine();
                Console.Write(xi + ", ");
                Console.Write(x2i + ", ");
                Console.Write(di + ", ");
                Console.Write(r);
                if (r > 1)
                {
                    //proof (but very stupid!)
                    var proof = r;
                    var a = n;
                    for (var b = 2; a > 1; b++)
                    {
                        if (a % b != 0) continue;
                        while (a % b == 0)
                        {
                            a /= b;
                        }
                        proof = b;
                        break;
                    }
                    if (proof != r && proof != n / r)
                    {
                        Console.WriteLine("\nwarning there is an error in calc!");
                        Console.WriteLine("proof says: p=" + proof + ", q=" + n / proof);
                    }
                    else
                    {
                        Console.WriteLine();
                        Console.WriteLine("p=" + r);
                        Console.WriteLine("q=" + n / r);
                    }
                    Console.WriteLine("Ja, das Verfahren bricht immer ab, da es nur endlich viele Zustände gibt. " +
                                      "Der Abbruch erfolgt, wenn der r=ggt(,) einen Wert > 1 ergibt. Dies ist ein Teiler " +
                                      "wenn r<n ist, sonst ist r=n und es muss ein Neustart mit anderer Initialisierung " +
                                      "erfolgen.");
                    return (r, n / r);
                }
            }
            return (n, 1);
        }
    }

    public static class DiscreteLogarithm
    {
        /// <summary>
        /// Represents the Diffie Hellman algorithm
        /// </summary>
        /// <param name="p">prime number</param>
        /// <param name="alpha">random alpha</param>
        /// <param name="a">random a</param>
        public static void DiffieHellman(int p, int alpha, int a)
        {
            Console.WriteLine("----DiffieHellman----");
            var la = (int)BigInteger.ModPow(alpha, a, p);
            var b = a - 1;
            var lb = (int)BigInteger.ModPow(alpha, b, p);
            Console.WriteLine("la= " + la);
            Console.WriteLine("b= " + b);
            Console.WriteLine("lb= " + lb);
            Console.WriteLine("K=" + BigInteger.ModPow(lb, a, p));
            Console.WriteLine("Man-in-the-Middle Angriff um lb und la zu zu empfangen oder die Schlüssel selbst zu bestimmen.");
            Console.WriteLine("Eine Kombination aus Schlüsselvereinbarung und Digitaler Unterschrift kann einen Man-in-the-Middle Angriff erkennen.");
        }

        /// <summary>
        /// Encryption of El Gamal system
        /// </summary>
        /// <param name="p">selected p (modulo)</param>
        /// <param name="alpha">alpha parameter</param>
        /// <param name="beta">beta parameter</param>
        /// <param name="m">message</param>
        /// <param name="k">chosen number (secret key)</param>
        public static void ElGamalEncrypt(int p, int alpha, int beta, int m, int k = 0)
        {
            if (k == 0 || k > p - 1)
            {
                k = p - 2;
            }
            Console.WriteLine("----ElGamal Encrypt----");
            Console.WriteLine("k= " + k);
            Console.WriteLine("c1= " + (int)BigInteger.ModPow(alpha, k, p));
            Console.WriteLine("c2= " + (m * BigInteger.ModPow(beta, k, p)) % p);
        }

        /// <summary>
        /// Decryption of El Gamal system
        /// </summary>
        /// <param name="p">selected p (modulo)</param>
        /// <param name="a">random a</param>
        /// <param name="c1">cipher 1</param>
        /// <param name="c2">cipher 2</param>
        public static void ElGamalDecrypt(int p, int a, int c1, int c2)
        {
            Console.WriteLine("----ElGamal Decrypt----");
            RSA.TryModInverse((int)BigInteger.ModPow(c1, a, p), p, out var mod1);
            Console.WriteLine("m'= " + (c2 * mod1) % p);
            Console.WriteLine("k mehrfach verwenden, weil damit versucht werden kann k zu ermitteln. " +
                              "Da k = log_alpha(c1) = log_alpha(alpha^k)\nc2 = m * p^k mod p => m = c2 * (p^k)^-1 mod p");
        }

        /// <summary>
        /// Function to implement the sign schema of el gamal
        /// </summary>
        /// <param name="p">selected p</param>
        /// <param name="alpha">alpha parameter</param>
        /// <param name="a">random a</param>
        /// <param name="beta">beta parameter</param>
        /// <param name="m">message</param>
        /// <param name="k">chosen k between 0 and p-1 if greater then p or below 0 its p-1</param>
        public static void ElGamalSignSystem(int p, int alpha, int a, int beta, int m, int k = 0)
        {
            Console.WriteLine("----ElGamal Signature schema----");
            Console.WriteLine("Abschlusseigenschaft; Berechnen Hashwert der ganzen Nachricht und signieren " +
                              "diese mit El-Gamal");
            Console.WriteLine("Identitätseigenschaft; nur Alice kennt das Geheminis a um zu signieren, ihre " +
                              "Identität wird durch ein vertrauenswürdiges Zertifikat bestätigt");
            Console.WriteLine("Echtheit: Diese stellt sicher, dass das Dokument/die Nachricht wirklich vom " +
                              "Unterschreibenden stammt. Hier wird gefordert, dass ein enger Zusammenhang " +
                              "zwischen Dokument und Unterschrift besteht.");
            Console.WriteLine("Warneigenschaft: Diese soll den Unterzeichnenden vor einer Übereilung " +
                              "bewahren. Die handschriftliche Unterschrift ist hinreichend komplex, und " +
                              "besteht zum Beispiel nicht nur aus einem Kreuz");
            Console.WriteLine("Verifikationseigenschaft: Jeder Empfänger kann die Unterschrift, durch die Privat/Publik " +
                              "Schlüssel verifizieren.");
            Console.WriteLine("Nachteile/Fehler: keine überprüfung der Sinnhaftigkeit der Nachricht, akzeptanz von " +
                              "unterschriebenen Nachrichten");
            Console.WriteLine("k mehrfach verwenden, weil damit versucht werden kann k zu ermitteln. " +
                              "Da k = log_alpha(c1) = log_alpha(alpha^k)\nc2 = m * p^k mod p => m = c2 * (p^k)^-1 mod p");
            if (k == 0 || k > p - 1)
            {
                k = p - 2;
            }
            RSA.TryModInverse(k, p-1, out var modK);
            Console.WriteLine("k= " + k);
            Console.WriteLine("k^-1= " + modK);
            var gamma = (int)BigInteger.ModPow(alpha, k, p);
            Console.WriteLine("gamma= " + gamma);
            var delta = RSA.Mod((m - a * gamma) * modK, p-1);
            Console.WriteLine("delta= " + delta);
            Console.WriteLine("Verification is " +  "mod(" + beta + "^" + gamma  + " * " + gamma + "^" + delta + " , " + p + ") = " + (int)BigInteger.ModPow(alpha, m, p));
        }
    }
    
    public static class EllipticCurve
    {
        /// <summary>
        /// Modulo to calculate negative numbers too
        /// </summary>
        /// <param name="x">number to modulo</param>
        /// <param name="m">modulo</param>
        /// <returns>positive modulo number</returns>
        public static int Mod(int x, int m) 
        {
            var r = x % m;
            return r < 0 ? r + m : r;
        }

        /// <summary>
        /// Check if the point is on the function
        /// </summary>
        /// <param name="x">x position of the point</param>
        /// <param name="m">modulo number (Z-space) alias f</param>
        /// <param name="a">a of function parameter f(x) = y² = x³ ax + b</param>
        /// <param name="b">b of function parameter f(x) = y² = x³ ax + b</param>
        /// <param name="single"></param>
        /// <returns>y if it exists</returns>
        public static int IsPointInFunction(int x, int m, int a, int b, bool single = false)
        {
            if (single)
            {
                Console.WriteLine("----Elliptic Curve Point ----");
            }
            int F(int i) => i * i * i + a * i + b; //f(x) = y = x^3 + 2x + 1
            var z = F(x) % m;
            var y2 = ModularSqrt(F(x) % m, m);
            var y2Minus = Mod(-y2, m);

            if (single)
            {
                Console.WriteLine("Point (" + x + ",y) => y = " + (y2 * y2 % m != z ? "n": y2));
                Console.WriteLine("Point (" + x + ",-y) => y = " + (y2Minus * y2Minus % m != z ? "n": y2Minus));
            }
            return y2;
        }

        /// <summary>
        /// Calculate the modular square of a number
        /// </summary>
        /// <param name="a">number</param>
        /// <param name="m">modulo</param>
        /// <returns>modular square of a number, -1 if nor possible</returns>
        private static int ModularSqrt(int a, int m)
        {
            var sym = LegrendeSymbol(a, m);
            if (sym is not (0 or 1)) //no result
            {
                return -1;
            }
            if (sym is 0) //one result
            {
                return 0;
            }
            if (a == 0) 
            {
                return 0;
            }
            if (m == 2) 
            {
                return m;
            }
            if (m % 4 == 3)
            {
                return (int)BigInteger.ModPow(a, (m + 1) / 4, m);
            }
            switch (m % 8)
            {
                case 5:
                {
                    var v = (int)BigInteger.ModPow(2*a, (m-5) / 8, m);
                    var i = 2 * a * (int)BigInteger.Pow(v, 2) % m;
                    return a * v * (i - 1) % m;
                }
                case 1:
                    // Partition p-1 to s * 2^e for an odd s (i.e. reduce all the powers of 2 from p-1)
                    var s = m - 1;
                    var e = 0;
                    while (s % 2 == 0) 
                    {
                        s /= 2;
                        e += 1;
                    }
                    // Find some 'n' with a legendre symbol n|p = -1.
                    var n = 2;
                    while (LegrendeSymbol(n, m) != -1) 
                    {
                        n += 1;
                    }
                    // x is a guess of the square root that gets better
                    // with each iteration.
                    // b is the "fudge factor" - by how much we're off
                    // with the guess. The invariant x^2 = ab (mod p)
                    // is maintained throughout the loop.
                    // g is used for successive powers of n to update
                    // both a and b
                    // r is the exponent - decreases with each update
                    var x = (int)BigInteger.ModPow(a, (s + 1) / 2, m);
                    var b = (int)BigInteger.ModPow(a, s, m);
                    var g = (int)BigInteger.ModPow(n, s, m);
                    var r = e;
                    while (true) 
                    {
                        var t = b;
                        var range = 0;
                        foreach (var i in Enumerable.Range(0, r))
                        {
                            range = i;
                            if (t == 1) 
                            {
                                break;
                            }
                            t = (int)BigInteger.ModPow(t, 2, m);
                        }
                        if (range == 0) 
                        {
                            return x;
                        }
                        var gs = (int)BigInteger.ModPow(g, BigInteger.Pow(2, r - range - 1), m);
                        g = gs * gs % m;
                        x = x * gs % m;
                        b = b * g % m;
                        r = range;
                    }
                default:
                    return -1; //no result
            }
        }
        
        /// <summary>
        /// Implements the legrende symbol to perform the modular square
        /// </summary>
        /// <param name="a">number</param>
        /// <param name="p">modulo</param>
        /// <returns></returns>
        private static int LegrendeSymbol(int a, int p) 
        {
            var ls = (int)BigInteger.ModPow(a, (p - 1) / 2, p);
            return ls == p - 1 ? -1 : ls;
        }
        
        /// <summary>
        /// Calculate point plus point operation on elliptic curves
        /// </summary>
        /// <param name="p1">point 1</param>
        /// <param name="p2">point 2</param>
        /// <param name="m">modulo (Z-space)</param>
        /// <param name="a">a of function parameter f(x) = y = ax + b</param>
        /// <param name="b">b of function parameter f(x) = y = ax + b</param>
        /// <returns>sum on the two points</returns>
        public static (int, int) PointPlusPoint((int, int) p1, (int, int) p2, int m, int a, int b, bool single = false)
        {
            if (single)
            {
                Console.WriteLine("----Elliptic Curves - point plus point ----");
            }
            int F(int i) => (i * i * i + a * i + b) % m; //f(x) = y = x^3 + 2x + 1

            int x3 = 0, y3 = 0, lambda = 0;

            //case 3
            if (p1.Item1 == p2.Item1 && p1.Item2 == -p2.Item2)
            {
                Console.WriteLine("lambda = ?");
                Console.WriteLine("p3(x,y) = O");
                return (-1, -1);
            }
            //case 2
            if (p1.Item1 != p2.Item1)
            {
                RSA.TryModInverse(Mod(p2.Item1 - p1.Item1, m), m, out var mod);
                lambda = Mod(Mod(p2.Item2 - p1.Item2, m) * mod, m);
                x3 = Mod(lambda * lambda - p1.Item1 - p2.Item1, m);
                y3 = Mod(lambda * (p1.Item1 - x3) - p1.Item2, m);

                Console.WriteLine($"lambda = mod(mod({p2.Item2} - {p1.Item2}, {m}) * inv_mod(mod({p2.Item1} - {p1.Item1}, {m}), {m}) , {m})");
                Console.WriteLine($"x3 = mod({lambda} * {lambda} - {p1.Item1} - {p2.Item1}, {m})");
                Console.WriteLine($"y3 = mod({lambda} * ({p1.Item1} - {x3}) - {p1.Item2}, {m})");
            }
            //case 4
            else if (p1.Item1 == p2.Item1 && p1.Item2 != -p2.Item2)
            {
                RSA.TryModInverse((2 * p1.Item2 % m), m, out var mod);
                lambda = Mod((3 * p1.Item1 * p1.Item1 + a) % m * mod, m);
                x3 = Mod(lambda * lambda - p1.Item1 - p2.Item1, m);
                y3 = Mod(lambda * (p1.Item1 - x3) - p1.Item2, m);

                Console.WriteLine($"lambda = mod(mod(3 * {p1.Item1} * {p1.Item1} + {a} , {m}) * inv_mod(mod(2 * {p1.Item2}, {m} ) , {m}), {m})");
                Console.WriteLine($"x3 = mod({lambda} * {lambda} - {p1.Item1} - {p2.Item1}, {m})");
                Console.WriteLine($"y3 = mod({lambda} * ({p1.Item1} - {x3}) - {p1.Item2}, {m})");
            }

            var z = F(x3);
            var y3minus = Mod(-y3, m);
            var test = IsPointInFunction(x3, m, a, b);
            if (z != y3*y3 % m && y3minus*y3minus % m != z)
            {
                Console.WriteLine("lambda = ?");
                Console.WriteLine("p3(x,y) = O");
                return (-1, -1);
            }
            
            Console.WriteLine("lambda = " + lambda);
            if (single)
            {
                Console.WriteLine("p3(x,y) = (" + x3 + ", " + Mod(y3, m) + ")");
            }
            
            return (x3, Mod(y3, m));
        }
        

        /// <summary>
        /// Calculate point multiply by number on elliptic curves
        /// </summary>
        /// <param name="number">multiply the point by number</param>
        /// <param name="p">point to multiply with</param>
        /// <param name="m">modulo (Z-space)</param>
        /// <param name="a">a of function parameter f(x) = y^2 = x^3 ax + b</param>
        /// <param name="b">b of function parameter f(x) = y^2 = x^3 ax + b</param>
        /// <returns></returns>
        public static (int, int) NumberMultPoint(int number, (int, int) p, int m, int a, int b, bool single = false)
        {
            if (single)
            {
                Console.WriteLine("----Elliptic Curves - point multiply by number ----");
            }
            var newPoint = p;
            for (var i = 1; i < number; i++)
            {
                //point + point + point + point
                //1 + 1 + 1 + 1
                newPoint = PointPlusPoint(p, newPoint, m, a, b);
                if (newPoint == (-1, -1))
                {
                    Console.WriteLine(i+"P("+p.Item1+", "+p.Item2+")=O");
                }
                Console.WriteLine(i+"P=("+newPoint.Item1 + ", "+newPoint.Item2 + ")");
            }
            return newPoint;
        }

        /// <summary>
        /// Perform encryption on elliptic curves
        /// </summary>
        /// <param name="p">modulo (Z-space)</param>
        /// <param name="P">point 1 (x,y)</param>
        /// <param name="Q">point 2 (x,y)</param>
        /// <param name="a">a of function parameter f(x) = y^2 = x^3 ax + b</param>
        /// <param name="b">b of function parameter f(x) = y^2 = x^3 ax + b</param>
        /// <param name="m">message to encrypt</param>
        /// <param name="k">chosen k (secret key)</param>
        public static void Encrypt(int p, (int, int) P, (int, int) Q, int a, int b, int m, int k)
        {
            Console.WriteLine("----Elliptic Curves - El gamal encrypt ----");
            
            var kP = NumberMultPoint(k, P, p, a, b);
            var c1 = (kP.Item1, kP.Item2 % 2);
            Console.WriteLine(k  + "P(" + P.Item1 + ", " + P.Item2 + ")=(" +kP.Item1 + ", " + kP.Item2 + ")\n");
            var kQ = NumberMultPoint(k, Q, p, a, b);
            Console.WriteLine(k  + "Q(" + Q.Item1 + ", " + Q.Item2 + ")=(" +kQ.Item1 + ", " + kQ.Item2 + ")\n");
            var c2 = (m + (kQ.Item1 + kQ.Item2 ) % p ) % p;
            Console.WriteLine("c1 = ["+ c1.Item1 + ", "+ c1.Item2 + "]");
            Console.WriteLine("c2 = " + c2);
        }
   
        /// <summary>
        /// Perform decryption on elliptic curves
        /// </summary>
        /// <param name="p">modulo (Z-space)</param>
        /// <param name="r">chosen r (secret key)</param>
        /// <param name="c1">cipher key 1 (point)</param>
        /// <param name="c2">cipher key</param>
        /// <param name="a">a of function parameter f(x) = y^2 = x^3 ax + b</param>
        /// <param name="b">b of function parameter f(x) = y^2 = x^3 ax + b</param>
        public static void Decrypt(int p, int r, (int, int) c1, int c2, int a, int b)
        {
            Console.WriteLine("----Elliptic Curves - El gamal decrypt ----");
            var c1Square = IsPointInFunction(c1.Item1, p, a, b);
            if (c1Square != -1)
            {
                var newPoint = (c1.Item1, c1Square);
                var point = NumberMultPoint(r, newPoint, p, a, b);
                var m = Mod(c2 - point.Item1 - point.Item2, p);
                Console.WriteLine("m = " + m);
                return;
            }
            Console.WriteLine("Error!");
        }
    }
}