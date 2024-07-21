// correct_wif_errors.cpp
//
// Correct transcription errors in Wallet Import Format (WIF) or check seed phrase
//
// Usage:
//
//     correct_wif_errors {WIF | seed phrase}
//
// Returns 0 on success
//
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept> // To use runtime_error
#include <unordered_map>
#include <gmpxx.h>
#include "libbase58.h"
#include "sha-256.h"
#include "bip39words.h"
#include "sha-2/sha-256.h"
#include "hmac-cpp/hmac.hpp"
#include "bech32/ref/c++/segwit_addr.h"

extern "C" {
  void ripemd160(const uint8_t* msg, uint32_t msg_len, uint8_t* hash);
}

class Secp256k1
{
  public:  
    const mpz_class p_;
    const mpz_class n_;
    const mpz_class x_;
    const mpz_class y_;

    Secp256k1(): 
      p_("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
      n_("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",16),
      x_("55066263022277343669578718895168534326250603453777594175500187360389116729240", 10),
      y_("32670510020758816978083085130507043184471273380659243275938904335757337482424", 10) {}

    // Modular division that returns nonnegative results
    mpz_class remainder(mpz_class x) const
    {
      return ((x % p_) + p_) % p_;
    }

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

static Secp256k1 g_curve;

bool my_sha256(void *digest, const void *data, size_t datasz)
{
  calc_sha_256((uint8_t*)digest, (const uint8_t*)data, datasz);
  return true;
}

mpz_class private_to_public(mpz_class private_key, bool compressed = true)
{
  mpz_class x, y;
  g_curve.multiply(x, y, private_key);
  std::string str_x = x.get_str(16);
  int leading_x_zeroes = 64 - str_x.length();
  if (leading_x_zeroes < 0) {
    throw std::runtime_error("Too many leading x zeroes\n"); 
  }
  if (leading_x_zeroes) {
    str_x.insert(0, leading_x_zeroes, '0');
  }
  std::string public_key;
  if (compressed) {
    public_key = ((y % 2) == 0) ? "02" : "03";
    public_key.append(str_x);
  } else {
    std::string str_y = y.get_str(16);
    int leading_y_zeroes = 64 - str_y.length();
    if (leading_y_zeroes < 0) {
      throw std::runtime_error("Too many leading y zeroes\n"); 
    }
    if (leading_y_zeroes) {
      str_y.insert(0, leading_y_zeroes, '0');
    }
    public_key = "04";
    public_key.append(str_x);
    public_key.append(str_y);
  }
  mpz_class mpk(public_key, 16);
  return mpk;
}

std::string serialize_public_key(mpz_class private_key, bool compressed)
{
  mpz_class pk(private_to_public(private_key, compressed));
  uint8_t bpk[33] = {0};
  size_t bpk_length;
  mpz_export(bpk, &bpk_length, 1, 1, -1, 0, pk.get_mpz_t()); 
  uint8_t sha256digest[32];
  calc_sha_256(sha256digest, bpk, bpk_length);
  uint8_t hash160[20];
  ripemd160(sha256digest, 32, hash160);
  char b58c[35];
  size_t b58c_length = 35;
  if (!b58check_enc(b58c, &b58c_length, 0, hash160, 20)) {
    throw std::runtime_error("b58check_enc() failed");
  }
  return std::string(b58c);
}

std::string serialize_extended_key(uint8_t* key, uint8_t* chaincode, bool is_private, 
  uint8_t depth = 0, uint8_t* fingerprint = NULL, uint32_t child_number = 0) {
  //                Length Offset
  // Version             4      0 Prefix
  //                                 0488ade4 = xprv, 0488b21e = xpub (BIP 44)
  //                                 049d7878 = yprv, 049d7cb2 = ypub (BIP 49)
  //                                 04b2430c = zprv, 04b24746 = zpub (BIP 84)
  // Depth               1      4 How many derivations deep this extended key is from the master key.
  // Parent Fingerprint  4      5 The first 4 bytes of the HASH160 of the parent's public key.
  // Child Number        4      9 The index number of this child from the parent.
  // Chain Code         32     13 The extra 32 byte secret, preventing others from deriving child keys without it.
  // Key                33     45 The private key (prepended with 00) or public key.
  //                           78
  uint8_t x[78] = {0};
  if (false) { // BIP 44
    x[0] = 0x04;
    x[1] = 0x88;
    if (is_private) {
      x[2] = 0xad;
      x[3] = 0xe4;
    } else {
      x[2] = 0xb2;
      x[3] = 0x1e;
    }
  } else { // BIP 84
    x[0] = 0x04;
    x[1] = 0xb2;
    if (is_private) {
      x[2] = 0x43;
      x[3] = 0x0c;
    } else {
      x[2] = 0x47;
      x[3] = 0x46;
    }
  }
  x[4] = depth;
  if (fingerprint) {
    memcpy(&x[5], fingerprint, 4);
  }
  x[ 9] = (uint8_t)(child_number >> 24);
  x[10] = (uint8_t)(child_number >> 16);
  x[11] = (uint8_t)(child_number >> 8);
  x[12] = (uint8_t)(child_number);
  memcpy(&x[13], chaincode, 32);
  if (is_private) {
    memcpy(&x[46], key, 32); // 46 because prepended with 0
  } else {
    memcpy(&x[45], key, 33);
  }
  if (false) {
    printf("Prefix:       %02x %02x %02x %02x\n", x[0], x[1], x[2], x[3]);
    printf("Depth:        %02x\n", x[4]);
    printf("Fingerprint:  %02x %02x %02x %02x\n", x[5], x[6], x[7], x[8]);
    printf("Child number: %02x %02x %02x %02x\n", x[9], x[10], x[11], x[12]);
    printf("Chain code:   ");
    for (int i = 0; i < 32; i++) {
      printf("%02x", x[i + 13]);
    }
    printf("\n");
    printf(is_private ? "Private key:  "
                      : "Public key:   "
          );
    for (int i = 0; i < 33; i++) {
      printf("%02x", x[i + 45]);
    }
    printf("\n");
  }
  char b58c[113]; // up to 112 characters
  size_t b58c_length = 113;
  if (!b58check_enc(b58c, &b58c_length, x[0], &x[1], 77)) {
    throw std::runtime_error("b58check_enc() failed\n"); 
  }
  if (b58c_length > 112) {
    throw std::runtime_error("b58c_length > 112\n"); 
  }
  return std::string(b58c);
}

std::string serialize_compressed_private_key(const std::string& compressed_private_key_s)
{
  std::string address_s(compressed_private_key_s);
  address_s.append(std::string("\1", 1)); // compression byte
  char b58c[53]; // 52 characters plus terminating zero
  size_t b58c_length = 53;
  if (!b58check_enc(&b58c[0], &b58c_length, 0x80, address_s.c_str(), address_s.length())) {
    throw std::runtime_error("b58enc() failed");
  }
  if (b58c_length != 53) {
    throw std::runtime_error("b58c_length != 53\n"); 
  }
  return std::string(b58c);
}

std::string serialize_bech32_address(const std::string& private_key_s)
{
  mpz_class cpriv_m;
  mpz_import(cpriv_m.get_mpz_t(), 32, 1, 1, -1, 0, private_key_s.c_str());
  mpz_class cpub_m(private_to_public(cpriv_m));
  uint8_t cpub[33];
  size_t cpub_length;
  mpz_export(cpub, &cpub_length, 1, 1, -1, 0, cpub_m.get_mpz_t()); 
  if (cpub_length > 33) {
    throw std::runtime_error("cpub_length > 33\n"); 
  }
  uint8_t sha256digest[32];
  calc_sha_256(sha256digest, cpub, cpub_length);
  uint8_t hash160[20];
  ripemd160(sha256digest, 32, hash160);
  std::vector<uint8_t> v(20);
  for (int i = 0; i < 20; i++) {
    v[i] = hash160[i];
  }
  return segwit_addr::encode(std::string("bc"), 0, v);
}

// On success updates key_s and chain_code_s, returns true
bool derive_child_key(std::string& key_s, std::string& chain_code_s, uint32_t index, uint8_t depth, bool is_master=false)
{
  mpz_class parent_private_key_m;
  mpz_import(parent_private_key_m.get_mpz_t(), 32, 1, 1, -1, 0, key_s.c_str());
  mpz_class parent_public_key_m(private_to_public(parent_private_key_m));
  uint8_t x[33 + 4] = {0};
  size_t x_length;
  mpz_export(x, &x_length, 1, 1, -1, 0, parent_public_key_m.get_mpz_t()); 
  if (x_length > 33) {
    throw std::runtime_error("x_length > 33\n"); 
  }
  // Parent fingerprint is the first 4 bytes of the HASH160 of the parent's public key
  uint8_t sha256digest[32];
  calc_sha_256(sha256digest, x, x_length);
  uint8_t hash160[20] = {0};
  ripemd160(sha256digest, 32, hash160);
  if (depth == 1) {
    printf("Root fingerprint=");
    for (int i = 0; i < 4; i++) {
      printf("%02x", hash160[i]);
    }
    printf("\n");
  }
  if (index >= (1u << 31)) { // Hardened child
    x[0] = 0;
    memcpy(&x[1], key_s.c_str(), 32);
  }
  x[33 + 0] = (index >> 24) & 0xff;
  x[33 + 1] = (index >> 16) & 0xff;
  x[33 + 2] = (index >>  8) & 0xff;
  x[33 + 3] = (index      ) & 0xff;
  std::string x_s(std::string((const char*)x, 33 + 4));
  std::string hmac(get_hmac(chain_code_s, x_s, hmac::TypeHash::SHA512, false));

  // The child private key is the first 32 bytes of the result from the HMAC added to the parent private key
  mpz_class offset_m;
  mpz_import(offset_m.get_mpz_t(), 32, 1, 1, -1, 0, hmac.c_str());
  if (offset_m >= g_curve.n_) {
    return false; // Invalid key, get next index
  }
  mpz_class child_private_m = parent_private_key_m + offset_m; 
  if (child_private_m >= g_curve.n_) {
    child_private_m -= g_curve.n_;
  }
  if (child_private_m == 0) {
    return false; // Invalid key, get next index
  }
  uint8_t cpriv[32];
  size_t cpriv_length;
  mpz_export(cpriv, &cpriv_length, 1, 1, -1, 0, child_private_m.get_mpz_t()); 
  if (cpriv_length > 32) {
    throw std::runtime_error("cpriv_length > 32\n"); 
  }
  key_s = std::string((const char*)cpriv, cpriv_length);
  size_t leading_zeroes = 32 - cpriv_length;
  while (leading_zeroes --> 0) {
    key_s.insert(0, std::string("\0", 1));
  }
  chain_code_s = hmac.substr(32, 32);
  if (is_master) {
    std::string xpriv(serialize_extended_key((uint8_t*)key_s.c_str(), 
      (uint8_t*)chain_code_s.c_str(), true, depth, hash160, index));
    mpz_class cpriv_m;
    mpz_import(cpriv_m.get_mpz_t(), 32, 1, 1, -1, 0, key_s.c_str());
    mpz_class cpub_m(private_to_public(cpriv_m));
    uint8_t cpub[33];
    size_t cpub_length;
    mpz_export(cpub, &cpub_length, 1, 1, -1, 0, cpub_m.get_mpz_t()); 
    if (cpub_length > 33) {
      throw std::runtime_error("cpub_length > 33\n"); 
    }
    std::string cpub_s(serialize_extended_key(cpub, 
      (uint8_t*)chain_code_s.c_str(), false, depth, hash160, index));
    std::cout << "Master public key " << cpub_s << std::endl;
  }
  return true;
}

int main(int argc, char* argv[])
{
  b58_sha256_impl = my_sha256;

  { // Self-test of elliptic curve math
    mpz_class x, y;
    mpz_class private_key("78ef4f361a057925361d94bca1407f98f98212188908835e5ebb0f70c08222ea", 16);
    mpz_class expected_x("111804461173250924701704772694496721445972174145506234673056158605240503164660", 10);
    mpz_class expected_y("19953983276126322186066606289277086253696929554717627225101578397073718403512", 10);
    g_curve.multiply(x, y, private_key);
    if (x != expected_x || y != expected_y) {
      std::cerr << "Self-test failed" << std::endl;
      std::cerr << "Expected x=" << expected_x << std::endl;
      std::cerr << "got        " << x << std::endl;
      std::cerr << "Expected y=" << expected_y << std::endl;  
      std::cerr << "got        " << y << std::endl;
      return -1;
    }
  }
  if (argc >= 3) {
    bool electrum = false;
    std::string seed_phrase; 
    for (int i = 0; i < argc - 1; i++) {
      std::string word(argv[i + 1]);
      std::transform(word.begin(), word.end(), word.begin(), ::tolower);
      if (i) {
        seed_phrase.append(" ");
      }
      seed_phrase.append(word);
    }
    std::string hash = get_hmac("Seed version", seed_phrase, hmac::TypeHash::SHA512, true);
    if (hash.substr(0,2) == "01") {
      std::cout << "Standard Electrum wallet seed phrase (P2PKH and Multisig P2SH wallets)" << std::endl;
      return 0;
    } else if (hash.substr(0,3) == "100") {
      std::cout << "Segwit Electrum wallet seed phrase (P2WPKH and P2WSH wallets)" << std::endl;
      electrum = true;
    } else if (hash.substr(0,3) == "101") {
      std::cout << "2FA Electrum wallet seed phrase (two-factor authenticated wallets)" << std::endl;
      return 0;
    } else if (argc == 13) {
      // Not Electrum, maybe BIP39?
      std::unordered_map<std::string, unsigned> wordlist;
      for (unsigned w = 0; w < 2048; w++) {
        wordlist[bip39words[w]] = w;
      }
      uint8_t entropy[17] = {0}; // 128 bit, initially all zero. Top 4 bits of last byte are checksum
      uint8_t entropy_mask = 0x80;
      int entropy_pos = 0;
      for (int i = 0; i < 12; i++) {
        std::string word(argv[i+1]);
        std::transform(word.begin(), word.end(), word.begin(), ::tolower); 
        auto it = wordlist.find(word);
        if (it == wordlist.end()) {
          std::cerr << word << " is not in BIP39 word list" << std::endl;
          return -2;
        }
        for (unsigned word_mask = (1 << 10); word_mask; word_mask >>= 1) {
          if (it->second & word_mask) { // raise corresponding bit in entropy
            if (entropy_pos >= 17) {
              std::cerr << "More bits than expected" << std::endl;
              return -3;
            }
            entropy[entropy_pos] |= entropy_mask;
          }
          entropy_mask >>= 1;
          if (!entropy_mask) {
            entropy_mask = 0x80;
            entropy_pos++;
          }
        }
      }
      uint8_t sha256digest[32];
      calc_sha_256(sha256digest, entropy, 16);
      if ((entropy[16] >> 4) != (sha256digest[0] >> 4)) {
        std::cerr << "BIP39 checksum mismatch" << std::endl;
        return -4;
      }
      std::cout << "BIP39 12 word checksum match" << std::endl;
    } else if (argc == 26 || argc == 14) {
      unsigned monero_words = argc - 2;
      std::string prefixes;
      for (unsigned i = 0; i < monero_words; i++) {
        std::string word(argv[i + 1]);
        prefixes.append(word.substr(0,3));
      }
      uint32_t crc32 = ~0U;
      {
        unsigned crc32_table[256] = {};
        for (uint32_t i = 0; i < 256; i++) {
          uint32_t j = i;
          for (int k = 0; k < 8; k++) {
            j = j & 1 ? (j >> 1) ^ 0xEDB88320 : j >> 1;
          }
          crc32_table[i] = j;
        }
        for (size_t i = 0; i < prefixes.length(); i++) {
          crc32 = crc32_table[(crc32 ^ prefixes.at(i)) & 0xff] ^ (crc32 >> 8);
        }
        crc32 = ~crc32;
      }
      unsigned checksum_word_position = crc32 % monero_words;
      std::string checksum_word(argv[checksum_word_position + 1]);
      std::string last_word(argv[monero_words + 1]); 
      if (last_word == checksum_word) {
        if (monero_words == 24) {
          std::cout << "Monero mnemonic seed (25 words)" << std::endl;
        } else {
          std::cout << "MyMonero mnemonic seed (13 words)" << std::endl;
        }
        return 0;
      } else {
        std::cout << "May be a Monero mnemonic seed, but last word (" << last_word 
                  << ") is different from checksum word " 
                  << (checksum_word_position + 1) << " (" 
                  << checksum_word << ")" << std::endl;
        return -5;
      }
    } else {
      std::cout << "Unknown seed phrase type" << std::endl;
      return -5;
    }

    // PBKDF2
    // 2048 iterations of HMAC-SHA512, dkLen = 64 bytes, hLen = 64 bytes
    // salt starts with prefix "mnemonic", concatenated with INT_32_BE(i).
    // Electrum uses its own prefix.
    std::string salt(electrum ? "electrum\0\0\0\1" : "mnemonic\0\0\0\1", 12);
    std::string u = get_hmac(seed_phrase, salt, hmac::TypeHash::SHA512, false);
    std::string seed = u;
    for (int iteration = 2; iteration <= 2048; iteration++) {
      u = get_hmac(seed_phrase, u, hmac::TypeHash::SHA512, false);
      for (int i = 0; i < 64; i++) {
        seed.at(i) ^= u.at(i);
      }
    }

    std::string master_hmac = get_hmac("Bitcoin seed", seed, hmac::TypeHash::SHA512, false);
    std::string master_private_key_s(master_hmac.substr(0, 32));
    std::string master_chain_code_s(master_hmac.substr(32, 32));

    // m/84h Purpose
    std::string purpose_private_key_s(master_private_key_s), purpose_chain_code_s(master_chain_code_s);
    for ( uint32_t index = (1u << 31) + (electrum ? 0u : 84u)
        ; !derive_child_key(purpose_private_key_s, purpose_chain_code_s, index, 1, electrum)
        ; index++
        ) { // Reset before trying again with the next index
      purpose_private_key_s = master_private_key_s;
      purpose_chain_code_s = master_chain_code_s;
    }

    // m/84h/0h Coin type
    std::string coin_type_private_key_s(purpose_private_key_s), coin_type_chain_code_s(purpose_chain_code_s);
    for ( uint32_t index = (1u << 31)
        ; !derive_child_key(coin_type_private_key_s, coin_type_chain_code_s, index, 2)
        ; index++
        ) { // Reset before trying again with the next index
      coin_type_private_key_s = purpose_private_key_s;
      coin_type_chain_code_s = purpose_chain_code_s;
    }

    // m/84h/0h/0h Account
    std::string account_private_key_s(coin_type_private_key_s), account_chain_code_s(coin_type_chain_code_s);
    for ( uint32_t index = (1u << 31)
        ; !derive_child_key(account_private_key_s, account_chain_code_s, index, 3, !electrum)
        ; index++
        ) { // Reset before trying again with the next index
      account_private_key_s = coin_type_private_key_s;
      account_chain_code_s = coin_type_chain_code_s;
    }

    // m/84h/0h/0h/0 Receiving
    std::string receiving_private_key_s(electrum ? purpose_private_key_s : account_private_key_s);
    std::string receiving_chain_code_s(electrum ? purpose_chain_code_s : account_chain_code_s);
    std::string change_private_key_s(receiving_private_key_s), change_chain_code_s(receiving_chain_code_s);
    for ( uint32_t index = 0u
        ; !derive_child_key(receiving_private_key_s, receiving_chain_code_s, index, 4)
        ; index++
        ) {
      receiving_private_key_s = electrum ? purpose_private_key_s : account_private_key_s;
      receiving_chain_code_s = electrum ? purpose_chain_code_s : account_chain_code_s;
    }

    // m/84h/0h/0h/1 Change
    for ( uint32_t index = 1u
        ; !derive_child_key(change_private_key_s, change_chain_code_s, index, 4)
        ; index++
        ) {
      change_private_key_s = account_private_key_s;
      change_chain_code_s = account_chain_code_s;
    }

    std::cout << "First 20 addresses for " << (electrum ? "Electrum derivation path m/0h" : "BIP84 derivation path m/84h/0h/0h") << std::endl;
    std::cout << "index,type,private_key,address" << std::endl;
    for (int is_change = 0; is_change < 2; is_change++) {
      for (uint32_t index = 0; index < 20u; ) {
        std::string private_key2_s(is_change ? change_private_key_s : receiving_private_key_s); 
        std::string chain_code2_s(is_change ? change_chain_code_s : receiving_chain_code_s);
        while (!derive_child_key(private_key2_s, chain_code2_s, index++, 5)) {
          private_key2_s = is_change ? change_private_key_s : receiving_private_key_s;
          chain_code2_s = is_change ? change_chain_code_s : receiving_chain_code_s;
        }
        std::string private_key_b58(serialize_compressed_private_key(private_key2_s));
        std::string bech32_address(serialize_bech32_address(private_key2_s));
        std::cout << (index - 1) << "," << (is_change ? "change" : "receiving") << "," 
                  << private_key_b58 << "," << bech32_address << std::endl;
      }
    }
    return 0;
  } else if (argc != 2) {
    std::cerr << "Usage:\n\tcorrect_wif_errors {WIF | seed phrase}\n";
    return -6;
  }
  char* wif = argv[1];
  unsigned char x[82]; // max value assigned to xsz in switch below
  int wif_length = strlen(argv[1]);
  if (wif_length < 25) { // min value assigned to xsz in switch below
    std::cerr << "Expected 25 or more characters, got only " << wif_length << "\n";
    return -7;
  }
  size_t xsz = sizeof(x);
  switch (wif[0]) {
    case '1':
    case '3':
      if (wif[0] == '1') {
        std::cerr << "Starts with 1, probably Bitcoin address in Legacy (P2PKH) format\n";
      } else {
        std::cerr << "Starts with 3, probably Bitcoin address in Nested SegWit (P2SH) format\n";
      }
      if (wif_length != 33 && wif_length != 34) {
        std::cerr << "Expected 33 or 34 characters, got " << wif_length << " instead\n";
        return -8;
      }
      xsz = 1 + 20 + 4; // 1 network byte + 20 byte public key hash + 4 byte checksum
      break;
    case '5':
      std::cerr << "Starts with 5, probably uncompressed private key\n";
      if (wif_length != 51) {
        std::cerr << "Expected 51 characters, got " << wif_length << " instead\n";
        return -9;
      }
      xsz = 1 + 32 + 4; // 1 version byte + 32 byte key + 4 byte checksum
      break;
    case 'K':
    case 'L': 
      std::cerr << "Starts with " << wif[0] << ", probably compressed private key\n";
      if (wif_length != 52) {
        std::cerr << "Expected 52 characters, got " << wif_length << " instead\n";
        return -10;
      }
      xsz = 1 + 32 + 1 + 4; // 1 version byte + 32 byte key + 1 byte flag + 4 byte checksum
      break;
    case '6':
      std::cerr << "Starts with a 6, probably BIP38 encrypted private key\n";
      if (wif_length != 58) {
        std::cerr << "Expected 58 characters, got " << wif_length << " instead\n";
        return -11;
      }
      if (wif[1] != 'P') {
        std::cerr << "Expected BIP38 encrypted private key to begin with 6P\n";
        return -12;
      }
      xsz = 43; // 2 bytes prefix, 37 bytes payload, 4 bytes checksum
      // payload is 1 flag byte + 4 byte salt + 16 bytes encrypted half one + 16 bytes encrypted half two
      break;
    case 'b': // example: bc1qy7m6d8mh5em8drkurgu6m46p6xmlqar63kl4vv
      if (wif[1] == 'c') {
        // Returns (witver, witprog). witver = -1 means failure.
        std::pair<int, std::vector<uint8_t> > decoded_beck32_addr = 
          segwit_addr::decode(std::string("bc"), std::string(wif));
        if (decoded_beck32_addr.first == 0) {
          std::cerr << "Valid Bech32 address\n";
          return 0;
        } else {
          std::cerr << "Starts with bc, but not a valid Bech32 address\n";
          return -13;          
        }
      } else {
        std::cerr << "Starts with unknown prefix\n";
        return -14;
      } 
    case 'x':
    case 'y':
    case 'z':
      if (wif[1] == 'p') { 
        if (wif[2] == 'r' && wif[3] == 'v') {
          std::cerr << "Starts with " << wif[0] << "prv, probably extended private key\n";
        } else if (wif[2] == 'u' && wif[3] == 'b') {
          std::cerr << "Starts with " << wif[0] << "pub, probably extended public key\n";
        }
      }
      // 4 byte prefix + 1 byte depth + 4 byte fingerprint + 4 byte child number + 32 byte chain code + 33 byte key + 4 byte checksum
      xsz = 82;
      break;
    default:
      std::cerr << "Starts with unknown prefix " << argv[1][0] << "\n";
      break;
  }
  if (!b58tobin(&x[0], &xsz, wif, 0)) {
    std::cerr << "This does not look like a Base58 string\n";
  	return -15;
  }
  if (b58check(&x[0], xsz, wif, 0) >= 0) {
    std::cerr << "Checksum match, no correction is needed\n";
    if (  (wif[0] == '5' && wif_length == 51)
       || ((wif[0] == 'K' || wif[0] == 'L') && wif_length == 52)
       ) {
      mpz_class private_key;
      mpz_import(private_key.get_mpz_t(), 32, 1, 1, -1, 0, &x[1]);
      // 1 version byte + 32 byte key + 4 byte checksum (uncompressed) or
      // 1 version byte + 32 byte key + 1 byte flag + 4 byte checksum (compressed)
      std::cout << "P2PKH address " << serialize_public_key(private_key, wif_length == 52) << "\n";
      if ((wif[0] == 'K' || wif[0] == 'L') && wif_length == 52) {
        std::cout << "SegWit address " << serialize_bech32_address(std::string((const char*)(&x[1]), 32)) << "\n";
      }
    } else if (wif[1] == 'p') {
      // 4 byte prefix + 1 byte depth + 4 byte fingerprint + 4 byte child number + 32 byte chain code + 33 byte key + 4 byte checksum
      printf("Prefix:       %02x %02x %02x %02x\n", x[0], x[1], x[2], x[3]);
      printf("Depth:        %02x\n", x[4]);
      printf("Fingerprint:  %02x %02x %02x %02x\n", x[5], x[6], x[7], x[8]);
      printf("Child number: %02x %02x %02x %02x\n", x[9], x[10], x[11], x[12]);
      printf("Chain code:   ");
      for (int i = 0; i < 32; i++) {
        printf("%02x", x[i + 13]);
      }
      printf("\n");
      printf((wif[2] == 'u') ? "Public key:   " 
                             : "Private key:  ");
      for (int i = 0; i < 33; i++) {
        printf("%02x", x[i + 45]);
      }
      printf("\n");
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
  return -16;
}
