// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using Xunit;

namespace BoxTest_enum_cs
{
    internal enum ToPrintOrNotToPrint
    {
        Print,
        DoNotPrint
    }

    public class Test
    {
        protected object Fibonacci(object num, object flag)
        {
            if ((ToPrintOrNotToPrint)flag == ToPrintOrNotToPrint.DoNotPrint)
                return Fibonacci2(num, flag);
            if (((int)num % 2) == 0)
                return Fibonacci2(num, flag);
            return Fibonacci2(num, flag);
        }

        protected object Fibonacci2(object num, object flag)
        {
            int N;
            if ((int)num <= 1)
                N = (int)num;
            else
                N = (int)Fibonacci((int)num - 2,
                        ToPrintOrNotToPrint.DoNotPrint) + (int)Fibonacci((int)num - 1, flag);
            if ((ToPrintOrNotToPrint)flag == ToPrintOrNotToPrint.Print)
                Console.Write(N.ToString() + " ");
            return N;
        }

        [Fact]
        [OuterLoop]
        public static void TestEntryPoint()
        {
            new Test().Fibonacci(20, ToPrintOrNotToPrint.Print);
            Console.WriteLine();
            Console.WriteLine("*** PASSED ***");
        }
    }
}
