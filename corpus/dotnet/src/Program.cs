// Tiny deterministic .NET program for the KRAKEN managed-code spike. No I/O beyond stdout.
using System;
using System.Collections.Generic;

namespace KrakenCorpus
{
    public enum Color
    {
        Red = 1,
        Green = 2,
        Blue = 4,
    }

    public struct Point
    {
        public int X;
        public int Y;

        public Point(int x, int y)
        {
            X = x;
            Y = y;
        }

        public int Manhattan() => Math.Abs(X) + Math.Abs(Y);
    }

    public interface IShape
    {
        double Area();
    }

    public sealed class Circle : IShape
    {
        private readonly double _radius;

        public Circle(double radius)
        {
            _radius = radius;
        }

        public double Area() => Math.PI * _radius * _radius;
    }

    public sealed class Square : IShape
    {
        public double Side { get; }

        public Square(double side)
        {
            Side = side;
        }

        public double Area() => Side * Side;
    }

    public static class Calc
    {
        public static int Add(int a, int b)
        {
            return a + b;
        }

        public static int Fib(int n)
        {
            if (n < 2)
            {
                return n;
            }
            return Fib(n - 1) + Fib(n - 2);
        }

        public static string Describe(Color c, int n)
        {
            string name = c switch
            {
                Color.Red => "red",
                Color.Green => "green",
                _ => "other",
            };
            return $"{name}:{Fib(n)}";
        }

        public static double TotalArea(IEnumerable<IShape> shapes)
        {
            double total = 0;
            foreach (IShape s in shapes)
            {
                total += s.Area();
            }
            return total;
        }
    }

    public static class Program
    {
        public static int Main()
        {
            Console.WriteLine(Calc.Describe(Color.Green, 10));
            var shapes = new List<IShape> { new Circle(1.0), new Square(2.0) };
            Console.WriteLine(Calc.TotalArea(shapes) > 7.0 ? "big" : "small");
            Console.WriteLine(new Point(3, -4).Manhattan());
            return Calc.Add(1, 2) == 3 ? 0 : 1;
        }
    }
}
