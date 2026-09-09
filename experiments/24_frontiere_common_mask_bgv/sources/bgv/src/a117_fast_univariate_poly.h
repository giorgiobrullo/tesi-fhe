// Exact setup-only coefficient generation for A117.
//
// The polynomial and online homomorphic evaluation are due to Iliashenko and
// Zucca. This header only replaces their nested coefficient-construction loop
// with exact interpolation over the quadratic-residue subgroup of F_p.

#ifndef A117_FAST_UNIVARIATE_POLY_H
#define A117_FAST_UNIVARIATE_POLY_H

#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace a117 {

using Word = std::uint64_t;

inline Word add_mod(Word lhs, Word rhs, Word modulus)
{
  const Word sum = lhs + rhs;
  return sum >= modulus ? sum - modulus : sum;
}

inline Word mul_mod(Word lhs, Word rhs, Word modulus)
{
  return (lhs * rhs) % modulus;
}

inline Word pow_mod(Word base, Word exponent, Word modulus)
{
  Word result = 1;
  while (exponent != 0) {
    if ((exponent & 1U) != 0)
      result = mul_mod(result, base, modulus);
    base = mul_mod(base, base, modulus);
    exponent >>= 1U;
  }
  return result;
}

inline std::vector<Word> distinct_prime_factors(Word value)
{
  std::vector<Word> result;
  for (Word factor = 2; factor * factor <= value; ++factor) {
    if (value % factor != 0)
      continue;
    result.push_back(factor);
    while (value % factor == 0)
      value /= factor;
  }
  if (value > 1)
    result.push_back(value);
  return result;
}

inline Word primitive_root(Word prime)
{
  const Word order = prime - 1;
  const auto factors = distinct_prime_factors(order);
  for (Word candidate = 2; candidate < prime; ++candidate) {
    bool generator = true;
    for (const Word factor : factors) {
      if (pow_mod(candidate, order / factor, prime) == 1) {
        generator = false;
        break;
      }
    }
    if (generator)
      return candidate;
  }
  throw std::logic_error("A117 could not find a primitive root");
}

// Exact mixed-radix DFT. For A117, n=4095=3^2*5*7*13, so the work is
// O(n*(3+3+5+7+13)) rather than a dense O(n^2) transform.
inline std::vector<Word> dft(const std::vector<Word>& input,
                             Word root,
                             Word prime)
{
  const std::size_t n = input.size();
  if (n == 1)
    return input;

  std::size_t radix = 2;
  while (radix < n && n % radix != 0)
    ++radix;
  if (radix == n) {
    std::vector<Word> output(n, 0);
    for (std::size_t k = 0; k < n; ++k) {
      const Word step = pow_mod(root, k, prime);
      Word power = 1;
      for (std::size_t j = 0; j < n; ++j) {
        output[k] = add_mod(output[k], mul_mod(input[j], power, prime), prime);
        power = mul_mod(power, step, prime);
      }
    }
    return output;
  }

  const std::size_t sub_size = n / radix;
  const Word sub_root = pow_mod(root, radix, prime);
  const Word radix_root = pow_mod(root, sub_size, prime);
  std::vector<std::vector<Word>> sub_transforms(
      radix, std::vector<Word>(sub_size));

  for (std::size_t residue = 0; residue < radix; ++residue) {
    std::vector<Word> sub_input(sub_size);
    for (std::size_t index = 0; index < sub_size; ++index)
      sub_input[index] = input[radix * index + residue];
    sub_transforms[residue] = dft(sub_input, sub_root, prime);
  }

  std::vector<Word> output(n, 0);
  for (std::size_t low_frequency = 0; low_frequency < sub_size;
       ++low_frequency) {
    const Word twist = pow_mod(root, low_frequency, prime);
    std::vector<Word> twisted(radix);
    Word twist_power = 1;
    for (std::size_t residue = 0; residue < radix; ++residue) {
      twisted[residue] = mul_mod(
          sub_transforms[residue][low_frequency], twist_power, prime);
      twist_power = mul_mod(twist_power, twist, prime);
    }

    for (std::size_t high_frequency = 0; high_frequency < radix;
         ++high_frequency) {
      const Word step = pow_mod(radix_root, high_frequency, prime);
      Word step_power = 1;
      Word value = 0;
      for (std::size_t residue = 0; residue < radix; ++residue) {
        value = add_mod(
            value, mul_mod(twisted[residue], step_power, prime), prime);
        step_power = mul_mod(step_power, step, prime);
      }
      output[low_frequency + sub_size * high_frequency] = value;
    }
  }
  return output;
}

inline std::vector<long> univariate_less_coefficients(Word prime)
{
  if (prime < 3 || (prime & 1U) == 0)
    throw std::invalid_argument("A117 requires an odd prime");

  const Word half = (prime - 1) / 2;
  const Word generator = primitive_root(prime);
  const Word root = mul_mod(generator, generator, prime);
  if (pow_mod(root, half, prime) != 1)
    throw std::logic_error("A117 quadratic-residue root has wrong order");
  for (const Word factor : distinct_prime_factors(half)) {
    if (pow_mod(root, half / factor, prime) == 1)
      throw std::logic_error("A117 quadratic-residue root is not primitive");
  }

  // The upstream coefficient c_j is sum_a a^(-1)*(a^(-2))^j.
  // Reindex a^(-2)=root^t. Exactly one of +/-g^(-t) lies in [1,half],
  // and its inverse is the signed weight below. Thus the coefficient vector
  // is the positive-exponent forward DFT of these weights.
  std::vector<Word> weights(half);
  const Word generator_inverse = pow_mod(generator, prime - 2, prime);
  Word generator_power = 1;
  Word inverse_power = 1;
  for (Word index = 0; index < half; ++index) {
    weights[index] =
        inverse_power <= half ? generator_power : prime - generator_power;
    generator_power = mul_mod(generator_power, generator, prime);
    inverse_power = mul_mod(inverse_power, generator_inverse, prime);
  }

  const auto residues = dft(weights, root, prime);
  if (prime == 8191) {
    const std::vector<std::pair<std::size_t, Word>> expected_spots = {
        {0, 6931},    {1, 4955},    {2, 4275},    {3, 2441},
        {7, 4033},    {31, 1241},   {63, 2532},   {127, 3183},
        {255, 0},     {511, 6805},  {1023, 5658}, {2047, 55},
        {3071, 3376}, {4093, 128},  {4094, 7167},
    };
    for (const auto& [index, expected] : expected_spots) {
      if (residues[index] != expected)
        throw std::logic_error("A117 p=8191 coefficient witness mismatch");
    }
    Word coefficient_sum = 0;
    for (const Word residue : residues)
      coefficient_sum = add_mod(coefficient_sum, residue, prime);
    if (coefficient_sum != 4095 || residues.back() != 7167)
      throw std::logic_error("A117 p=8191 coefficient invariant mismatch");
  }

  std::vector<long> result;
  result.reserve(residues.size());
  for (const Word residue : residues)
    result.push_back(static_cast<long>(residue));
  return result;
}

} // namespace a117

#endif // A117_FAST_UNIVARIATE_POLY_H
