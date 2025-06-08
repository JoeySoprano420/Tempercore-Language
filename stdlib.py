import math

class TempercoreStdLib:
    @staticmethod
    def factorial(n):
        return math.factorial(n)

    @staticmethod
    def prime(n):
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    @staticmethod
    def primes_up_to(n):
        return [x for x in range(2, n + 1) if TempercoreStdLib.prime(x)]

    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def lcm(a, b):
        return abs(a * b) // TempercoreStdLib.gcd(a, b)

    @staticmethod
    def reverse_string(s):
        return s[::-1]

    @staticmethod
    def count_words(s):
        return len(s.split())

    @staticmethod
    def frequency_map(s):
        freq = {}
        for char in s:
            freq[char] = freq.get(char, 0) + 1
        return freq

    @staticmethod
    def to_upper(s):
        return s.upper()

    @staticmethod
    def to_lower(s):
        return s.lower()

    @staticmethod
    def remove_whitespace(s):
        return "".join(s.split())

    @staticmethod
    def extract_numbers(s):
        return [int(x) for x in s.split() if x.isdigit()]
