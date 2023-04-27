using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Numerics;

namespace InterfaceMain
{
    interface Program
    {
        private static readonly int ElementCount512 = Unsafe.SizeOf<Vector512<Int32>>() / sizeof(Int32);
        private static readonly int ElementCount256 = Unsafe.SizeOf<Vector256<Int32>>() / sizeof(Int32);
        public static unsafe int Main()
        {


             

            /*Console.WriteLine("\n Vector512EqualsAllConst Begin \n");
            bool resultElements512EqualsAllConst = Vector512EqualsAllConst();
            Console.WriteLine("\n Vector512EqualsAllConst Deepak val = " + resultElements512EqualsAllConst + "\n"); */

            /* bool Vector256Supp = vector256Supported();
             Console.Write("]\n Vector256Supp : " + Vector256Supp + " \n");

             bool Vector512Supp = vector512Supported();
             Console.Write("]\n Vector512Supp : " + Vector512Supp + " \n");



             Vector256<int> dot1 = Vector256.Create(100, 101, 102, 103, 104, 105, 106, 107);
             Vector256<int> dot2 = Vector256.Create(100, 101, 102, 103, 104, 105, 106, 107);
             ///Vector256<int> v256Shuffle2 = Vector256.Create(3, 3, 3, 3, 3, 3, 3, 3);
             int resultElements256Dot = Vector256Shuffle(v256Shuffle1);
             Console.Write("\n Vector256Suffle Deepak [ ");
             for (int index = 0; index < Vector256<int>.Count; index++)
             {
                 Console.Write(resultElements256Shuffle[index] + ", ");
             }
             Console.Write("]\n Vector256Shuffle Done \n");

             //Vector512<short> v512Shuffle1 = Vector512.Create(100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131);
             Vector512<int> v512Shuffle1 = Vector512.Create(100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115);
             //Vector512<Int64> v512Shuffle1 = Vector512.Create(100, 101, 102, 103, 104, 105, 106, 107);
             //Vector512<int> v512Shuffle2 = Vector512.Create(3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3);
             Vector512<int> resultElements512Shuffle = Vector512Shuffle(v512Shuffle1);
             Console.Write("\n Vector512Suffle Deepak [ ");
             for (int index = 0; index < Vector512<int>.Count; index++)
             {
                 Console.Write(resultElements512Shuffle[index] + ", ");
             }
             Console.Write("]\n Vector512Shuffle Done \n");*/

            /* Vector256<int> resultElements256Shift = Vector256Shift(v256Shuffle1, 3);
             Console.Write("\n Vector256Shift Deepak [ ");
             for (int index = 0; index < Vector256<int>.Count; index++)
             {
                 Console.Write(resultElements256Shift[index] + ", ");
             }
             Console.Write("]\n Vector256Shift Done \n");

             Vector512<int> resultElements512Shift = Vector512Shift(v512Shuffle1, 3);
             Console.Write("\n Vector512Shift Deepak [ ");
             for (int index = 0; index < Vector512<int>.Count; index++)
             {
                 Console.Write(resultElements512Shift[index] + ", ");
             }
             Console.Write("]\n Vector512Shift Done \n");*/

            Vector256<int> v256Eq1 = Vector256.Create(100, 101, 102, 103, 104, 105, 106, 107);
            Vector256<int> v256Eq2 = Vector256.Create(100, 101, 102, 103, 104, 105, 106, 107);           

            Vector512<int> v512Eq1 = Vector512.Create(100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115);
            Vector512<int> v512Eq2 = Vector512.Create(100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115);

            Vector256<int> resultElements256Eq = Vector256Eq(v256Eq1, v256Eq2);
            Console.Write("\n Vector256Eq Deepak [ ");
            for (int index = 0; index < Vector256<int>.Count; index++)
            {
                Console.Write(resultElements256Eq[index] + ", ");
            }
            Console.Write("]\n Vector256Eq Done \n");

            Vector512<int> resultElements512Eq = Vector512Eq(v512Eq1, v512Eq2);       
            Console.Write("\n Vector512Eq Deepak [ ");
            for (int index = 0; index < Vector512<int>.Count; index++)
            {
                Console.Write(resultElements512Eq[index] + ", ");
            }
            Console.Write("]\n Vector512Eq Done \n");

            Console.WriteLine("\n Vector256EqualsAll Begin \n");
            bool resultElements256EqualsAll = Vector256EqualsAll(v256Eq1, v256Eq2);
            Console.WriteLine("\n Vector256EqualsAll Deepak val = " + resultElements256EqualsAll + "\n");

            Console.WriteLine("\n Vector512EqualsAll Begin \n");
            bool resultElements512EqualsAll = Vector512EqualsAll(v512Eq1, v512Eq2);
            Console.WriteLine("\n Vector512EqualsAll Deepak val = " + resultElements512EqualsAll + "\n");



            return 100;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe bool Vector256EqualsAll(Vector256<int> v1, Vector256<int> v2)
        {
            return Vector256.EqualsAny(v1, v2);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe bool Vector512EqualsAll(Vector512<int> v1, Vector512<int> v2)
        {
            return Vector512.EqualsAny(v1, v2);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe Vector256<int> Vector256Eq(Vector256<int> v1, Vector256<int> v2)
        {
            return Vector256.LessThan(v1, v2);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe Vector512<int> Vector512Eq(Vector512<int> v1, Vector512<int> v2)
        {
            return Vector512.LessThan(v1, v2);
        }



        [MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe Vector256<int> Vector256Shuffle(Vector256<int> v1)
        {
            return Vector256.Shuffle(v1, Vector256.Create(7, 5, 132, 1, 6, 4, -3, 0));
            //Vector256<int> v2 = Vector256.Create(3, 3, 3, 3, 3, 3, 3, 3);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe Vector512<int> Vector512Shuffle(Vector512<int> v1)
        {
            return Vector512.Shuffle(v1, Vector512.Create(15, 13, 11, 99, 7, 5, 3, 1, 14, 12, 10, 8, -11, 4, 2, 0));
            //return Vector512.Shuffle(v1, Vector512.Create(31, 29, 27, 25, 23, 221, 19, 17, 15, 13, 11, 9, 7, 5, 3, 1, 30, 28, 26, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 0));
           // return Vector512.Shuffle(v1, Vector512.Create(15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0));
           // return Vector512.Shuffle(v1, Vector512.Create(7, 5, 3, 1, 6, 4, 2, 0));
        }


        /*[MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe Vector512<float> Vector512Shuffle(Vector512<float> v1)
        {
            //return Vector512.Shuffle(v1, Vector512.Create(31, 29, 27, 25, 23, 221, 19, 17, 15, 13, 11, 9, 7, 5, 3, 1, 30, 28, 26, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 0));
            return Vector512.Shuffle(v1, Vector512.Create(15, 100, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0));
            // return Vector512.Shuffle(v1, Vector512.Create(7, 5, 3, 1, 6, 4, 2, 0));
        }*/

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe Vector512<Int64> Vector512Shuffle(Vector512<Int64> v1)
        {
            //return Vector512.Shuffle(v1, Vector512.Create(31, 29, 27, 25, 23, 221, 19, 17, 15, 13, 11, 9, 7, 5, 3, 1, 30, 28, 26, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 0));
            // return Vector512.Shuffle(v1, Vector512.Create(15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0));
            return Vector512.Shuffle(v1, Vector512.Create(7, 5, 3, 1000, 6, 4, 2, 0));
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe Vector256<int> Vector256Shift(Vector256<int> v1, int a)
        {
            return Vector256.ShiftRightLogical(v1, a);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe Vector512<int> Vector512Shift(Vector512<int> v1, int a)
        {
            return Vector512.ShiftRightLogical(v1, a);
        }

        
    }
}
