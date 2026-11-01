
import secrets


class RSA:
        COLORS: dict[str, str] = {
                "RED": "\033[91m",
                "GREEN": "\033[92m",
                "YELLOW": "\033[93m",
                "PURPLE": "\033[95m",
                "CYAN": "\033[96m",
                "WHITE": "\033[m"
        }

        def __init__(self, p: int = 0, q: int = 0, e: int = 0, d: int = 0):
                self.p = p
                self.q = q
                self.e = e
                self.n = p * q
                self.d = d
        def calculate_n(self):
                if self.is_empty(self.p, self.q):
                        raise ValueError("p and q must be non-zero integers.")
                if self.p == self.q:
                        raise ValueError("p and q must be distinct prime numbers.")
                if not self.is_prime(self.p) or not self.is_prime(self.q):
                        raise ValueError("Both p and q must be prime numbers.")

                self.n = self.p * self.q
                return self.n

        def set_p(self, p: int):
                if type(p) is not int or p <= 0:
                        raise ValueError("p must be a positive integer.")
                if not self.is_prime(p):
                        raise ValueError("p must be a prime number.")
                if p == self.q:
                        raise ValueError("p and q must be distinct prime numbers.")

                self.p = p

        def set_q(self, q: int):
                if type(q) is not int or q <= 0:
                        raise ValueError("q must be a positive integer.")
                if not self.is_prime(q):
                        raise ValueError("q must be a prime number.")
                if q == self.p:
                        raise ValueError("p and q must be distinct prime numbers.")

                self.q = q

        @staticmethod
        def is_empty(*nums):
                return any(num is None or num == 0 for num in nums)

        @staticmethod
        def is_prime(*nums: int, rounds: int = 40):
                small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

                if rounds < 1:
                        raise ValueError("Rounds must be positive.")

                for num in nums:
                        if type(num) is not int or num < 2:
                                return False

                        if num in small_primes:
                                continue

                        if any(num % prime == 0 for prime in small_primes):
                                return False

                        # n - 1 = 2^s * d
                        d = num - 1
                        s = 0

                        while d % 2 == 0:
                                d //= 2
                                s += 1

                        # Miller-Rabin test
                        for _ in range(rounds):
                                a = secrets.randbelow(num - 3) + 2
                                x = pow(a, d, num)

                                if x == 1 or x == num - 1:
                                        continue

                                for _ in range(s - 1):
                                        x = pow(x, 2, num)

                                        if x == num - 1:
                                                break
                                else:
                                        return False

                return True

        def get_input(self, prompt: str, check_prime: bool = False):
                while True:
                        try:
                                value = int(input(prompt))

                                if value <= 0:
                                        raise ValueError("Input must be a positive integer.")

                                if check_prime and not self.is_prime(value):
                                        raise ValueError("Input must be a prime number.")

                                return value

                        except ValueError as e:
                                self.print_message(str(e), "RED")

        def euler_totient(self):
                if self.is_empty(self.p, self.q):
                        raise ValueError("p and q must be non-zero integers.")
                if self.p == self.q:
                        raise ValueError("p and q must be distinct prime numbers.")
                if not self.is_prime(self.p) or not self.is_prime(self.q):
                        raise ValueError("Both p and q must be prime numbers.")

                return (self.p - 1) * (self.q - 1)

        def extended_gcd(self, a: int, b: int):
                if a == 0:
                        return b, 0, 1

                gcd_value, x1, y1 = self.extended_gcd(b % a, a)
                x = y1 - (b // a) * x1
                y = x1

                return gcd_value, x, y

        def modular_inverse(self, a: int, m: int):
                gcd_value, x, _ = self.extended_gcd(a, m)

                if gcd_value != 1:
                        raise ValueError(
                                f"Modular inverse does not exist for a={a} and m={m}."
                        )

                return x % m

        def public_exponent(self):
                phi_n = self.euler_totient()

                if self.e != 0:
                        if type(self.e) is not int or not 1 < self.e < phi_n:
                                raise ValueError("Invalid public exponent.")

                        if self.extended_gcd(self.e, phi_n)[0] != 1:
                                raise ValueError("e and φ(n) must be coprime.")

                        return self.e

                for e in range(2, phi_n):
                        if self.extended_gcd(e, phi_n)[0] == 1:
                                self.e = e
                                return e

                raise ValueError("No valid public exponent found.")

        def private_exponent(self):
                phi_n = self.euler_totient()
                self.d = self.modular_inverse(self.e, phi_n)
                return self.d

        def encrypt(self, message: int):
                if self.is_empty(self.e, self.n):
                        raise ValueError("Public key (e, n) must be set before encryption.")
                if type(message) is not int:
                        raise ValueError("Message must be an integer.")
                if not (0 <= message < self.n):
                        raise ValueError("Message must be in the range [0, n).")
                return pow(message, self.e, self.n)

        def decrypt(self, ciphertext: int):
                if self.is_empty(self.d, self.n):
                        raise ValueError("Private key (d, n) must be set before decryption.")
                if type(ciphertext) is not int:
                        raise ValueError("Ciphertext must be an integer.")
                if not (0 <= ciphertext < self.n):
                        raise ValueError("Ciphertext must be in the range [0, n).")

                return pow(ciphertext, self.d, self.n)

        def print_message(self, message: str, color: str = "WHITE"):
                color_code = self.COLORS.get(color.upper(), self.COLORS["WHITE"])
                print(f"{color_code}{message}{self.COLORS['WHITE']}")

        def main(self):
                try:
                        self.set_p(self.get_input("Enter a prime number p: ", check_prime=True))
                        self.set_q(self.get_input("Enter a prime number q: ", check_prime=True))
                        message = self.get_input(f"Enter a message (integer) to encrypt (0 <= message < {self.n}): ")

                        self.calculate_n()

                        self.print_message(f"Calculated n: {self.n}")
                        self.print_message(f"Calculated φ(n): {self.euler_totient()}")
                        self.print_message(f"Extended GCD of p and q: {self.extended_gcd(self.p, self.q)}")
                        self.print_message(f"Modular inverse of p modulo q: {self.modular_inverse(self.p, self.q)}")

                        self.public_exponent()
                        self.print_message(f"Public exponent e: {self.e}", "GREEN")

                        self.private_exponent()
                        self.print_message(f"Private exponent d: {self.d}", "GREEN")

                        ciphertext = self.encrypt(message)
                        self.print_message(f"Encrypted message: {ciphertext}", "CYAN")

                        decrypted_message = self.decrypt(ciphertext)
                        self.print_message(f"Decrypted message: {decrypted_message}", "PURPLE")

                except ValueError as e:
                        self.print_message(str(e), "RED")


if __name__ == "__main__":
        rsa = RSA()
        rsa.main()