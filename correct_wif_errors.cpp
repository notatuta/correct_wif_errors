// correct_wif_errors.cpp
//
// Correct transcription errors in Wallet Import Format (WIF) strings
//
// Usage:
//
//     correct_wif_errors WIF
//
// Returns 0 on success
//
#include <iostream>
#include <stdexcept> // To use runtime_error
#include <cstring>
#include <gmpxx.h>
#include "libbase58.h"
#include "sha-256.h"

extern "C" {
  void ripemd160(const uint8_t* msg, uint32_t msg_len, uint8_t* hash);
}

class Secp256k1
{
  private:
    const mpz_class p_;
    const mpz_class x_;
    const mpz_class y_;

    // Modular division that returns nonnegative results
    mpz_class remainder(mpz_class x) const
    {
      return ((x % p_) + p_) % p_;
    }

  public:  
    Secp256k1(): 
      p_("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
      x_("55066263022277343669578718895168534326250603453777594175500187360389116729240", 10),
      y_("32670510020758816978083085130507043184471273380659243275938904335757337482424", 10) {}

    // Modular inverse
    // Returns x such that (x * k) % p_ == 1.
    mpz_class modinv(mpz_class k)
    {
      if (k == 0) {
        throw std::runtime_error("modinv(0) is undefined\n"); 
      }

      if (k < 0) { // k ** -1 = p - (-k) ** -1  (mod p)
        return p_ - modinv(-k);
      }

      // Extended Euclidean algorithm
      mpz_class s = 0; mpz_class old_s = 1;
      mpz_class t = 1; mpz_class old_t = 0;
      mpz_class r = p_; mpz_class old_r = k;

      while (r != 0) {
        mpz_class quotient = old_r / r;
        mpz_class tmp_r = r; r = old_r - quotient * r; old_r = tmp_r;
        mpz_class tmp_s = s; s = old_s - quotient * s; old_s = tmp_s;
        mpz_class tmp_t = t; t = old_t - quotient * t; old_t = tmp_t;
      }

      if (old_r != 1) {
        throw std::runtime_error("old_r != 1 in modinv()\n"); 
      }
      mpz_class x(remainder(old_s));
      mpz_class kxp(remainder(k * x));
      if (kxp != 1) {
        throw std::runtime_error("(k * x) % p_ != 1 in modinv()\n"); 
      }
      return x;
    }

    // Add a point on the curve to itself
    void add(mpz_class& x1, mpz_class& y1) {
      mpz_class slope(remainder((x1 * x1 * 3) * modinv((y1 * 2))));
      mpz_class x(remainder(slope * slope - x1 - x1));
      mpz_class y(remainder(slope * (x1 - x) - y1));
      x1 = x;
      y1 = y;
    }

    // Add point 2 to point 1
    void add(mpz_class& x1, mpz_class& y1, const mpz_class& x2, const mpz_class& y2)
    {
      // Add (x1,y1) to itself if both points are the same
      if ((x1 == x2) && (y1 == y2)) {
        add(x1, y1);
      } else {
        mpz_class slope(remainder((y2 - y1) * modinv(x2 - x1)));
        mpz_class x(remainder(slope * slope - x1 - x2));
        mpz_class y(remainder((slope * (x1 - x)) - y1));
        x1 = x;
        y1 = y;
      }
    }

    // Multiply a point by the private key
    void multiply(mpz_class& x, mpz_class& y, const mpz_class& k) {
      x = x_;
      y = y_;
      for (int i = mpz_sizeinbase(k.get_mpz_t(), 2) - 2; i >= 0; i--)
      {
        add(x, y);
        if (mpz_tstbit(k.get_mpz_t(), i)) {
          add(x, y, x_, y_);
        }
      }
    }
};

int print_public_key(mpz_class private_key, bool compressed)
{
  std::cout << (compressed ? "Compressed" : "Uncompressed") << " private key (hex) " << std::hex << private_key << std::endl;
  Secp256k1 curve;
  mpz_class x, y;
  curve.multiply(x, y, private_key);
  std::string str_x = x.get_str(16);
  int leading_x_zeroes = 64 - str_x.length();
  if (leading_x_zeroes < 0) {
    std::cerr << "Too many leading x zeroes" << std::endl;
    return -9;
  }
  if (leading_x_zeroes) {
    str_x.insert(0, leading_x_zeroes, '0');
  }
  std::string public_key;
  if (compressed) {
    public_key = ((y % 2) == 0) ? "02" : "03";
    public_key.append(str_x);
    std::cout << "Compressed public key (hex) " << public_key << std::endl;
  } else {
    std::string str_y = y.get_str(16);
    int leading_y_zeroes = 64 - str_y.length();
    if (leading_y_zeroes < 0) {
      std::cerr << "Too many leading y zeroes" << std::endl;
      return -8;
    }
    if (leading_y_zeroes) {
      str_y.insert(0, leading_y_zeroes, '0');
    }
    public_key = "04";
    public_key.append(str_x);
    public_key.append(str_y);
    std::cout << "Uncompressed public key (hex) " << public_key << std::endl;
  }
  mpz_class pk(public_key, 16);
  uint8_t bpk[33] = {0};
  size_t bpk_length;
  mpz_export(bpk, &bpk_length, 1, 1, -1, 0, pk.get_mpz_t()); 
  uint8_t sha256digest[32];
  calc_sha_256(sha256digest, bpk, bpk_length);
  uint8_t hash160[20];
  ripemd160(sha256digest, 32, hash160);
  char b58c[35];
  size_t b58c_length;
  if (!b58check_enc(b58c, &b58c_length, 0, hash160, 20)) {
    std::cerr << "b58check_enc() failed" << std::endl;
    return -7;
  } else {
    std::cout << "P2PKH address " << b58c << std::endl;
    return 0;
  }
}

bool my_sha256(void *digest, const void *data, size_t datasz)
{
  calc_sha_256((uint8_t*)digest, (const uint8_t*)data, datasz);
  return true;
}

int main(int argc, char* argv[])
{
  { // Self-test of elliptic curve math
    Secp256k1 curve;
    mpz_class x, y;
    mpz_class private_key("78ef4f361a057925361d94bca1407f98f98212188908835e5ebb0f70c08222ea", 16);
    mpz_class expected_x("111804461173250924701704772694496721445972174145506234673056158605240503164660", 10);
    mpz_class expected_y("19953983276126322186066606289277086253696929554717627225101578397073718403512", 10);
    curve.multiply(x, y, private_key);
    if (x != expected_x || y != expected_y) {
      std::cerr << "Self-test failed" << std::endl;
      std::cerr << "Expected x=" << expected_x << std::endl;
      std::cerr << "got        " << x << std::endl;
      std::cerr << "Expected y=" << expected_y << std::endl;  
      std::cerr << "got        " << y << std::endl;
      return -3;
    }
  }
  if (argc != 2) {
    std::cerr << "Usage:\n\tcorrect_wif_errors WIF\n";
    return -1;
  }
  char* wif = argv[1];
  unsigned char x[43]; // max value assigned to xsz in switch below
  int wif_length = strlen(argv[1]);
  size_t xsz = sizeof(x);
  switch (argv[1][0]) {
    case '1':
    case '3':
      if (wif[0] == '1') {
        std::cerr << "Starts with 1, probably Bitcoin address in Legacy (P2PKH) format\n";
      } else {
        std::cerr << "Starts with 3, probably Bitcoin address in Nested SegWit (P2SH) format\n";
      }
      if (wif_length != 34) {
        std::cerr << "Expected 34 characters, got " << wif_length << "instead\n";
        return -2;
      }
      xsz = 1 + 20 + 4; // 1 network byte + 32 byte public key hash + 4 byte checksum
      break;
    case '5':
      std::cerr << "Starts with 5, probably uncompressed private key\n";
      if (wif_length != 51) {
        std::cerr << "Expected 51 characters, got " << wif_length << "instead\n";
        return -2;
      }
      xsz = 37; // 1 version byte + 32 byte key + 4 byte checksum
      break;
    case 'K':
    case 'L': 
      std::cerr << "Starts with " << argv[1][0] << ", probably compressed private key\n";
      if (wif_length != 52) {
        std::cerr << "Expected 52 characters, got " << wif_length << " instead\n";
        return -2;
      }
      xsz = 38; // 1 version byte + 32 byte key + 1 byte flag + 4 byte checksum
      break;
    case '6':
      std::cerr << "Starts with a 6, probably BIP38 encrypted private key\n";
      if (wif_length != 58) {
        std::cerr << "Expected 58 characters, got " << wif_length << "instead\n";
        return -2;
      }
      if (argv[1][1] != 'P') {
        std::cerr << "Expected BIP38 encrypted private key to begin with 6P\n";
        return -2;
      }
      xsz = 43; // 2 bytes prefix, 37 bytes payload, 4 bytes checksum
      // payload is 1 flag byte + 4 byte salt + 16 bytes encrypted half one + 16 bytes encrypted half two
      break;
    case 'b': // example: bc1qy7m6d8mh5em8drkurgu6m46p6xmlqar63kl4vv
      if (wif[1] == 'c') {
        std::cerr << "Starts with bc, probably Bech32 address\n";
        return 0;
      } else {
        std::cerr << "Starts with unknown prefix\n";
        return -2;
      } 
    default:
      std::cerr << "Starts with unknown prefix " << argv[1][0] << "\n";
      break;
  }
  if (!b58tobin(&x[0], &xsz, wif, 0)) {
    std::cerr << "This does not look like a Base58 string\n";
  	return -2;
  }
  b58_sha256_impl = my_sha256;
  if (b58check(&x[0], xsz, wif, 0) >= 0) {
    std::cerr << "Checksum match, no correction is needed\n";
    if (  (argv[1][0] == '5' && wif_length == 51)
       || ((argv[1][0] == 'K' || argv[1][0] == 'L') && wif_length == 52)
       ) {
      mpz_class private_key;
      mpz_import(private_key.get_mpz_t(), 32, 1, 1, -1, 0, &x[1]);
      // 1 version byte + 32 byte key + 4 byte checksum (uncompressed) or
      // 1 version byte + 32 byte key + 1 byte flag + 4 byte checksum (compressed)
      return print_public_key(private_key, wif_length == 52);
    }
    return 0;
  }
  std::cerr << "Checksum does not match, trying all possible one-character transcription errors\n";
  int maxpos = strlen(wif);
  const char base58[59] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  for (int pos = 0; pos < maxpos; pos++) {
    const char orig = wif[pos];
    for (int i = 0; i < 58; i++) {
      if (orig == base58[i]) {
      	continue;
      }
      wif[pos] = base58[i];
      size_t xsz2 = xsz; // tweaking can change length
      if (!b58tobin(&x[0], &xsz2, wif, 0)) {
  	    continue;
      }
      if (b58check(&x[0], xsz2, wif, 0) >= 0) {
      	std::cout << "Changed " << orig << " to " << base58[i] << " at position " << pos << ":\n";
      	std::cout << wif << "\n";
      	for (int k = 0; k < pos; k++) {
      	  std::cout << " ";
      	}
      	std::cout << "^\n";
        return 0;
      }
    }
    wif[pos] = orig;
  }
  std::cerr << "Trying all possible two-character transcription errors\n";
  for (int pos_a = 0; pos_a < maxpos; pos_a++) {
    const char orig_a = wif[pos_a];
    for (int i = 0; i < 58; i++) {
      if (orig_a == base58[i]) {
        continue;
      }
      wif[pos_a] = base58[i];
      for (int pos_b = pos_a + 1; pos_b < maxpos; pos_b++) {
        const char orig_b = wif[pos_b];
        for (int j = 0; j < 58; j++) {
          if (orig_b == base58[j]) {
        	  continue;
          }
          wif[pos_b] = base58[j];
          size_t xsz2 = xsz; // tweaking can change length
          if (!b58tobin(&x[0], &xsz2, wif, 0)) {
  	        continue;
          }
          if (b58check(&x[0], xsz2, wif, 0) >= 0) {
      	    std::cout << "Changed " << orig_a << " to " << base58[i] << " at position " << pos_a << ",\n";
      	    std::cout << "changed " << orig_b << " to " << base58[j] << " at position " << pos_b << ":\n";
      	    std::cout << wif << "\n";
      	    for (int k = 0; k < pos_a; k++) {
      	      std::cout << " ";
      	    }
      	    std::cout << "^";
      	    for (int k = 0; k < pos_b - pos_a - 1; k++) {
      	      std::cout << " ";
      	    }
      	    std::cout << "^\n";
            return 0;
          }
        }
        wif[pos_b] = orig_b;
      }
    }
    wif[pos_a] = orig_a;
  }
  std::cerr << "Cannot find correction\n";
  return -5;
}
