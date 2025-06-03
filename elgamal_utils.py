# START OF FILE: elgamal_utils.py

import math # For PrimeTester, though custom_sqrt is better for large int
import random # Standard random, only for non-crypto if needed, or LCG base seed

class LCG:
    """
    Linear Congruential Generator for pseudo-random numbers.
    This fulfills the "встроенный модуль random" requirement.
    """
    def __init__(self, seed):
        self.seed = int(seed) # Ensure seed is an integer
        self.a = 1103515245
        self.c = 12345
        self.m = 2**31 # Standard m for LCG

    def next_int(self):
        """ Returns a pseudo-random integer in [0, m-1] """
        self.seed = (self.a * self.seed + self.c) % self.m
        return self.seed

    def randint(self, lower, upper):
        """ Returns a pseudo-random integer in [lower, upper] inclusive. """
        if lower > upper:
            lower, upper = upper, lower
        range_size = upper - lower + 1
        if range_size == 0: # Should not happen if lower <= upper
            return lower
        # Generate a random number and scale it to the desired range
        # To avoid modulo bias if m is not a multiple of range_size,
        # a more robust method would be to reject and resample,
        # but for simplicity and given m is large:
        return lower + (self.next_int() % range_size)

class ElGamalBaseUtils:
    """ Basic mathematical utilities for ElGamal """
    @staticmethod
    def custom_pow(base, exp, mod):
        """ Computes (base^exp) % mod efficiently. """
        if mod == 1: return 0
        result = 1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1: result = (result * base) % mod
            exp = exp // 2
            base = (base * base) % mod
        return result

    @staticmethod
    def extended_gcd(a, b):
        """ Extended Euclidean Algorithm: returns (gcd, x, y) such that ax + by = gcd. """
        if a == 0: return (b, 0, 1)
        gcd, x1, y1 = ElGamalBaseUtils.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return (gcd, x, y)

    @staticmethod
    def modinv(a, m):
        """ Computes modular multiplicative inverse of a under modulo m. """
        gcd, x, y = ElGamalBaseUtils.extended_gcd(a, m)
        if gcd != 1:
            return None # Modular inverse does not exist
        return (x % m + m) % m


class PrimeManager: # Combining PrimeGenerator and PrimeTester
    generated_primes = set() # To avoid re-generating/re-testing same prime quickly

    @staticmethod
    def _custom_int_sqrt(n):
        if n < 0: raise ValueError("Cannot compute sqrt of negative number")
        if n == 0: return 0
        x = int(math.sqrt(n)) # Initial guess using floating point
        # Refine using Newton's method for integers
        # Or simpler:
        if (x+1)*(x+1) <= n :
             x += 1
        while x*x > n:
            x -=1
        return x

    @staticmethod
    def _is_prime_trial_division(n):
        """
        Trial division test using small primes and then odd numbers up to sqrt(n).
        Returns True if n passes trial division test, False if composite.
        """
        if n < 4: return n > 1  # Handle small numbers
        # Check small primes first
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        for p in small_primes:
            if n % p == 0:
                return n == p  # Prime only if n equals the small prime

        # Check odd numbers up to sqrt(n) or 1000, whichever is smaller
        sqrt_n = PrimeManager._custom_int_sqrt(n)
        i = 37  # Start after our small primes list
        step = 2  # Only check odd numbers
        limit = min(sqrt_n, 1000)  # Don't go beyond 1000 for efficiency
        
        while i <= limit:
            if n % i == 0:
                return False
            i += step
        return True

    @staticmethod
    def _is_prime_fermat(n, k=5, lcg_instance=None):
        """
        Fermat primality test.
        n: number to test
        k: number of rounds (iterations) for testing
        lcg_instance: LCG instance for random number generation
        Returns True if n passes Fermat test, False if composite
        """
        if n == 2: return True
        if n < 2 or n % 2 == 0: return False

        if lcg_instance is None:
            lcg_instance = LCG(n)  # Create new LCG with n as seed if none provided

        # Test k random bases
        for _ in range(k):
            # Choose random base a in [2, n-2]
            a = lcg_instance.randint(2, n - 2)
            # Check if a^(n-1) ≡ 1 (mod n)
            if ElGamalBaseUtils.custom_pow(a, n - 1, n) != 1:
                return False
        return True

    @staticmethod
    def _is_prime_miller_rabin(n, k=64, lcg_instance=None): # k is number of rounds
        """
        Miller-Rabin primality test.
        k: number of rounds (iterations) for testing. Higher k = more certainty.
        lcg_instance: An LCG instance for choosing bases 'a'. If None, uses Python's random.
        Returns True if n is likely prime, False if composite.
        """
        if n <= 1: return False
        if n <= 3: return True
        if n % 2 == 0: return False

        # Write n as 2^s * d + 1
        s = 0
        d = n - 1
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(k):
            if lcg_instance:
                a = lcg_instance.randint(2, n - 2)
            else: # Fallback if no LCG provided, for standalone testing
                a = random.randint(2, n-2)

            x = ElGamalBaseUtils.custom_pow(a, d, n)
            if x == 1 or x == n - 1:
                continue # Potentially prime

            for _ in range(s - 1):
                x = ElGamalBaseUtils.custom_pow(x, 2, n)
                if x == n - 1:
                    break # Potentially prime
            else:
                return False # Definitely composite
        return True # Likely prime

    @staticmethod
    def generate_prime(bit_length, seed_for_lcg, attempts_per_candidate=1000):
        """
        Generates a prime number of approximately bit_length bits.
        Uses LCG for randomness and multiple primality tests:
        1. Trial division test
        2. Fermat primality test
        3. Miller-Rabin primality test
        """
        if not (64 <= bit_length <= 512): # Practical limits for demo
            raise ValueError("Bit length must be between 64 and 512 for this generator.")

        lcg_prime_gen = LCG(seed_for_lcg)
        lcg_miller_rabin_bases = LCG(seed_for_lcg + 1) # Separate LCG for Miller-Rabin bases
        lcg_fermat_bases = LCG(seed_for_lcg + 2) # Separate LCG for Fermat bases

        min_val = 1 << (bit_length - 1)
        max_val = (1 << bit_length) - 1

        for _ in range(attempts_per_candidate * 10): # Overall attempts for finding a prime
            # Generate a candidate number of the correct bit length
            # Ensure it's odd
            candidate = lcg_prime_gen.randint(min_val, max_val) | 1
            if candidate > max_val: candidate = (min_val | 1) # reset if overflow for some reason

            if candidate in PrimeManager.generated_primes: # Avoid re-testing known
                continue

            # Apply all three primality tests in order of computational cost
            # 1. Trial division (fastest, eliminates many composites quickly)
            if not PrimeManager._is_prime_trial_division(candidate):
                continue

            # 2. Fermat test (medium cost)
            if not PrimeManager._is_prime_fermat(candidate, k=5, lcg_instance=lcg_fermat_bases):
                continue

            # 3. Miller-Rabin test (most rigorous)
            if PrimeManager._is_prime_miller_rabin(candidate, k=64, lcg_instance=lcg_miller_rabin_bases):
                PrimeManager.generated_primes.add(candidate)
                return candidate

        raise RuntimeError(f"Failed to generate {bit_length}-bit prime after many attempts.")

    @staticmethod
    def find_generator(p, seed_for_lcg):
        """
        Finds a generator g for the multiplicative group of integers modulo p.
        p must be a prime number.
        A common way is to find g such that g^((p-1)/q) != 1 (mod p) for all prime factors q of p-1.
        For simplicity in a demo, we can pick random g and check g^2 != 1 and g^((p-1)/2) != 1 (mod p)
        if p-1 has 2 as a factor.
        A simpler (but not always best) approach for demo: pick a small g like 2 or 3 if it works,
        or a random one.
        """
        lcg = LCG(seed_for_lcg)
        if p == 2: return 1
        
        # p-1 factors are needed for a robust generator check.
        # This is complex. For this demo, we'll try random candidates.
        # We look for g such that order of g is p-1.
        # A common choice for g is a small prime if p is a safe prime, or random.
        # Let's try random numbers.
        phi = p -1 # Euler's totient function for prime p
        
        # Find prime factors of phi. This can be slow.
        # For simplicity, we'll try a few candidates for g.
        # This is NOT a cryptographically secure way to find a generator for all p.
        # A full method involves factoring p-1.
        
        # Try small numbers first if they are not 1 or p-1
        for g_candidate in range(2, min(p, 100)): # Try small g
             # A simple check (not exhaustive for all p): g^((p-1)/2) % p == p-1 (if p-1 is even)
             # or that g is a primitive root.
             # For demo, we'll be less strict, any g s.t. g > 1 and g < p is a start.
             # The security of ElGamal depends on g being a generator of a large subgroup.
            is_generator_candidate = True
            # Simplistic check: g must not be 1
            if ElGamalBaseUtils.custom_pow(g_candidate, 2, p) == 1 and p > 3: # e.g. g = p-1
                 is_generator_candidate = False
            if ElGamalBaseUtils.custom_pow(g_candidate, phi // 2, p) == 1 and phi%2 == 0 : # if 2 is a factor of phi
                 is_generator_candidate = False
            # Add more checks if prime factors of phi are known e.g. for q in prime_factors(phi): pow(g, phi//q, p) != 1
            
            if is_generator_candidate: # This is a very weak check for a generator.
                                       # A proper check requires factoring p-1.
                                       # For demonstration, we proceed with g_candidate > 1.
                                       # Let's assume we find a g that is not trivial.
                return g_candidate


        # Fallback to random if small ones don't pass even basic checks or are exhausted
        for _ in range(100): # Try 100 random candidates
            g = lcg.randint(2, p - 2) # Ensure g is not 1 or p-1
            # Again, a proper check for g being a generator is complex.
            # We just need g to generate a large subgroup.
            # Let's assume for demo any g in [2, p-2] can work if p is large prime.
            if ElGamalBaseUtils.custom_pow(g, 2, p) != 1 : # Avoid g where g^2 = 1 (mod p)
                # A better check would be against known prime factors of p-1
                # if ElGamalBaseUtils.custom_pow(g, (p - 1) // 2, p) != 1: # if p-1 is even and 2 is its factor
                return g
        
        return 2 # Default fallback, but could be problematic for some p


class ElGamalCrypto:
    """ Implements ElGamal encryption, decryption, signing, and verification. """

    @staticmethod
    def generate_keys(p, g, seed_for_lcg):
        """
        Generates an ElGamal key pair (private_x, public_y).
        p: A large prime number.
        g: A generator modulo p.
        seed_for_lcg: Seed for the LCG to generate private key x.
        """
        lcg = LCG(seed_for_lcg)
        # Private key x must be in [1, p-2] or [2, p-2]
        private_x = lcg.randint(2, p - 2)
        public_y = ElGamalBaseUtils.custom_pow(g, private_x, p)
        return private_x, public_y

    @staticmethod
    def encrypt(message_numeric, p, g, recipient_public_y, seed_for_lcg_k):
        """
        Encrypts a numeric message using ElGamal.
        message_numeric: The message as an integer (0 <= message_numeric < p).
        p, g: ElGamal public parameters.
        recipient_public_y: The recipient's public key.
        seed_for_lcg_k: Seed for LCG to generate ephemeral key k.
        Returns ciphertext (a, b).
        """
        if not (0 <= message_numeric < p):
            raise ValueError("Message for ElGamal encryption must be an integer m: 0 <= m < p.")
        
        lcg = LCG(seed_for_lcg_k)
        # Ephemeral key k must be in [1, p-2] or [2, p-2]
        k = lcg.randint(2, p - 2)
        
        a = ElGamalBaseUtils.custom_pow(g, k, p)
        s = ElGamalBaseUtils.custom_pow(recipient_public_y, k, p) # y^k mod p
        b = (message_numeric * s) % p
        
        return a, b

    @staticmethod
    def decrypt(ciphertext_a, ciphertext_b, p, g, recipient_private_x):
        """
        Decrypts an ElGamal ciphertext.
        ciphertext_a, ciphertext_b: The two parts of the ElGamal ciphertext.
        p, g: ElGamal public parameters. (g is not strictly needed here but often passed)
        recipient_private_x: The recipient's private key.
        Returns the original numeric message.
        """
        if not (0 < ciphertext_a < p and 0 <= ciphertext_b < p):
             raise ValueError("Invalid ciphertext components.")

        # s = a^x mod p
        s = ElGamalBaseUtils.custom_pow(ciphertext_a, recipient_private_x, p)
        
        # s_inv = s^(-1) mod p
        s_inv = ElGamalBaseUtils.modinv(s, p)
        if s_inv is None:
            raise ValueError("Failed to compute modular inverse for decryption (s_inv).")
            
        message_numeric = (ciphertext_b * s_inv) % p
        return message_numeric

    @staticmethod
    def sign(hash_h, p, g, signer_private_x, seed_for_lcg_k_sig):
        """
        Signs a hash_h using ElGamal signature scheme.
        hash_h: The hash of the message to be signed (integer, 0 <= hash_h < p-1).
        p, g: ElGamal public parameters.
        signer_private_x: The signer's private key.
        seed_for_lcg_k_sig: Seed for LCG to generate ephemeral key k_sig.
        Returns signature (r, s).
        """
        p_minus_1 = p - 1
        if not (0 <= hash_h < p_minus_1): # Hash should be modulo p-1
            # hash_h = hash_h % p_minus_1 # Or raise error if not pre-hashed correctly
            raise ValueError(f"Hash for ElGamal signing must be an integer h: 0 <= h < p-1. Got {hash_h}")


        lcg = LCG(seed_for_lcg_k_sig)
        
        while True:
            # Ephemeral key k_sig must be in [1, p-2] and gcd(k_sig, p-1) = 1
            k_sig = lcg.randint(1, p_minus_1 - 1) # k in [1, p-2]
            if ElGamalBaseUtils.extended_gcd(k_sig, p_minus_1)[0] == 1:
                break # Found a k_sig coprime to p-1
        
        r = ElGamalBaseUtils.custom_pow(g, k_sig, p)
        
        k_sig_inv = ElGamalBaseUtils.modinv(k_sig, p_minus_1)
        if k_sig_inv is None:
            raise RuntimeError("Failed to compute modular inverse for k_sig in signing.")
            
        # s = (h - x*r) * k_inv mod (p-1)
        s_val = (hash_h - (signer_private_x * r)) # This can be negative
        s = (s_val * k_sig_inv) % p_minus_1
        
        # s must not be 0. If s=0, try a new k. (Rare)
        if s == 0:
            # This recursive call or loop is to handle rare s=0 case by picking a new k_sig
            return ElGamalCrypto.sign(hash_h, p, g, signer_private_x, lcg.next_int()) 

        return r, s

    @staticmethod
    def verify(hash_h, r, s, p, g, signer_public_y):
        """
        Verifies an ElGamal signature.
        hash_h: The hash of the original message (integer, 0 <= hash_h < p-1).
        r, s: The signature components.
        p, g: ElGamal public parameters.
        signer_public_y: The signer's public key.
        Returns True if the signature is valid, False otherwise.
        """
        p_minus_1 = p - 1
        if not (0 <= hash_h < p_minus_1): # Hash should be modulo p-1
            # hash_h = hash_h % p_minus_1
             raise ValueError(f"Hash for ElGamal verification must be an integer h: 0 <= h < p-1. Got {hash_h}")


        # Signature validity conditions: 0 < r < p and 0 < s < p-1
        if not (0 < r < p and 0 < s < p_minus_1):
            return False
            
        # Verification: (y^r * r^s) mod p == g^h mod p
        # Left side: (y^r * r^s) mod p
        term1 = ElGamalBaseUtils.custom_pow(signer_public_y, r, p)
        term2 = ElGamalBaseUtils.custom_pow(r, s, p)
        left_side = (term1 * term2) % p
        
        # Right side: g^h mod p
        right_side = ElGamalBaseUtils.custom_pow(g, hash_h, p)
        
        return left_side == right_side


class MessageUtils:
    @staticmethod
    def message_to_numeric(message_str, p_val):
        """Converts a string message to a numeric representation for ElGamal.
           The numeric value must be less than p.
           This is a simple byte concatenation approach.
        """
        if not message_str:
            return 0 # Or handle as an error

        m_bytes = message_str.encode('utf-8')
        m_numeric = 0
        # Ensure it fits within p. If message is too long, it might exceed p.
        # Max message length for this encoding depends on p.
        # For a 256-bit p, max bytes is roughly 256/8 = 32 bytes.
        # (256^N) < p => N log(256) < log(p) => N < log(p)/log(256)
        max_bytes = (p_val.bit_length() // 8) -1 # Heuristic, leave some room
        if len(m_bytes) > max_bytes and max_bytes > 0 : # and max_bytes > 0 added to ensure it doesn't trigger for small p and 0 max_bytes
             raise ValueError(f"Message too long for this p. Max {max_bytes} UTF-8 bytes. Got {len(m_bytes)}.")

        for i, byte_val in enumerate(m_bytes):
            m_numeric += byte_val * (256 ** i)
        
        if m_numeric >= p_val:
            # This should ideally be caught by max_bytes check, but as a safeguard:
            raise ValueError("Numeric representation of message exceeds p.")
        return m_numeric

    @staticmethod
    def numeric_to_message(m_numeric):
        """Converts a numeric value back to a string message."""
        if m_numeric == 0: return "" # Assuming 0 was empty or null message
        m_bytes_list = []
        temp_m = m_numeric
        while temp_m > 0:
            m_bytes_list.append(temp_m % 256)
            temp_m //= 256
        
        try:
            return bytes(m_bytes_list).decode('utf-8')
        except UnicodeDecodeError:
            # Fallback if not valid UTF-8, could be an issue with original encoding or corruption
            return "".join([chr(b) for b in m_bytes_list if 0 <= b <= 0xFF]) # Raw bytes to chars

    @staticmethod
    def hash_message_for_elgamal(message_str, p_minus_1):
        """
        Simple hash function for a message string to be used with ElGamal signature.
        The hash value must be < p-1.
        This is NOT a cryptographically secure hash function like SHA-256.
        For demonstration purposes only.
        """
        # Using a simple additive hash with prime multipliers
        # similar to Python's string hash but ensuring it's within bounds.
        hash_val = 0
        prime1 = 31
        prime2 = 17
        
        for char_code in message_str.encode('utf-8'): # operate on bytes
            hash_val = (hash_val * prime1 + char_code + prime2)
        
        return hash_val % p_minus_1


if __name__ == '__main__':
    # Basic tests
    print("--- Testing ElGamal Utils ---")

    # LCG Test
    lcg_seed = 123456789
    lcg = LCG(lcg_seed)
    print(f"LCG seeded with {lcg_seed}:")
    for _ in range(5):
        print(f"  randint(1, 100): {lcg.randint(1, 100)}")

    # Prime Generation Test
    try:
        print("\nGenerating 64-bit prime...")
        p = PrimeManager.generate_prime(64, lcg.next_int())
        print(f"Generated p: {p} (bit length: {p.bit_length()})")
        print(f"Is p prime (Miller-Rabin)? {PrimeManager._is_prime_miller_rabin(p, lcg_instance=lcg)}")

        # Generator g (simplified search for demo)
        g = PrimeManager.find_generator(p, lcg.next_int())
        print(f"Found generator g: {g}")
        if g is None:
            print("Could not find a suitable generator g easily.")
            exit()

        # ElGamal Key Generation
        print("\nGenerating ElGamal keys...")
        alice_private_x, alice_public_y = ElGamalCrypto.generate_keys(p, g, lcg.next_int())
        bob_private_x, bob_public_y = ElGamalCrypto.generate_keys(p, g, lcg.next_int())
        print(f"Alice's private x_A: {alice_private_x}")
        print(f"Alice's public y_A: {alice_public_y}")
        print(f"Bob's private x_B: {bob_private_x}")
        print(f"Bob's public y_B: {bob_public_y}")

        # Message Conversion & Hashing
        original_message = "Hello ElGamal! This is a test. Привет!"
        print(f"\nOriginal message: {original_message}")
        
        try:
            m_numeric = MessageUtils.message_to_numeric(original_message, p)
            print(f"Message as numeric m: {m_numeric}")
            dec_message_test = MessageUtils.numeric_to_message(m_numeric)
            print(f"Numeric to message test: {dec_message_test}")
            if original_message != dec_message_test:
                 print("WARNING: Message to numeric and back test FAILED")


            # ElGamal Encryption (Alice encrypts for Bob)
            print("\nEncrypting message for Bob...")
            k_enc_seed = lcg.next_int()
            ciphertext_a, ciphertext_b = ElGamalCrypto.encrypt(m_numeric, p, g, bob_public_y, k_enc_seed)
            print(f"Ciphertext (a, b): ({ciphertext_a}, {ciphertext_b})")

            # ElGamal Decryption (Bob decrypts)
            print("\nBob decrypting message...")
            decrypted_numeric = ElGamalCrypto.decrypt(ciphertext_a, ciphertext_b, p, g, bob_private_x)
            print(f"Decrypted numeric m': {decrypted_numeric}")
            decrypted_message = MessageUtils.numeric_to_message(decrypted_numeric)
            print(f"Decrypted message: {decrypted_message}")

            if decrypted_message == original_message:
                print("Encryption and Decryption SUCCESSFUL!")
            else:
                print("Encryption and Decryption FAILED.")
        except ValueError as e:
            print(f"Error during message processing/encryption/decryption: {e}")


        # ElGamal Signature (Alice signs the message)
        print("\nAlice signing the message...")
        message_hash_h = MessageUtils.hash_message_for_elgamal(original_message, p - 1)
        print(f"Message hash h: {message_hash_h}")
        
        k_sig_seed = lcg.next_int()
        sig_r, sig_s = ElGamalCrypto.sign(message_hash_h, p, g, alice_private_x, k_sig_seed)
        print(f"Signature (r, s): ({sig_r}, {sig_s})")

        # ElGamal Verification (Bob verifies Alice's signature)
        print("\nBob verifying Alice's signature...")
        is_valid_signature = ElGamalCrypto.verify(message_hash_h, sig_r, sig_s, p, g, alice_public_y)
        if is_valid_signature:
            print("Signature VERIFIED successfully!")
        else:
            print("Signature verification FAILED.")

    except Exception as e:
        print(f"\nAn error occurred during testing: {e}")
        import traceback
        traceback.print_exc()

# END OF FILE: elgamal_utils.py