#include "comparator.h"

#include <helib/debugging.h>
#include <helib/helib.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr long kPlaintextPrime = 8191;
constexpr long kCyclotomicOrder = 81920;
constexpr long kRequestedBits = 600;
constexpr long kColumns = 3;
constexpr long kScale = 6;
constexpr long kScoreMaximum = 4095;
constexpr double kHardLoadCeiling = 24.0;
constexpr double kExpectedActualBits = 603.824751602;
constexpr double kExpectedSecurityBits = 135.301317068;

struct Options
{
  bool run = false;
  bool ack_keygen = false;
  bool ack_encryption = false;
  bool ack_fhe = false;
  bool ack_timing = false;
  bool ack_security_is_not_capacity = false;
  double max_load = -1.0;
  std::string result_path;
  std::string timers_path;
};

struct Pair
{
  long x;
  long y;
};

double seconds_since(const std::chrono::steady_clock::time_point& start)
{
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - start)
      .count();
}

double one_minute_load()
{
  double value = 0.0;
  if (getloadavg(&value, 1) != 1)
    throw std::runtime_error("A117 cannot read the one-minute host load");
  return value;
}

Options parse_options(int argc, char** argv)
{
  Options options;
  for (int index = 1; index < argc; ++index) {
    const std::string argument(argv[index]);
    if (argument == "--run")
      options.run = true;
    else if (argument == "--ack-keygen")
      options.ack_keygen = true;
    else if (argument == "--ack-encryption")
      options.ack_encryption = true;
    else if (argument == "--ack-fhe")
      options.ack_fhe = true;
    else if (argument == "--ack-timing")
      options.ack_timing = true;
    else if (argument == "--ack-security-is-not-capacity")
      options.ack_security_is_not_capacity = true;
    else if (argument == "--max-load" && index + 1 < argc)
      options.max_load = std::stod(argv[++index]);
    else if (argument == "--result" && index + 1 < argc)
      options.result_path = argv[++index];
    else if (argument == "--timers" && index + 1 < argc)
      options.timers_path = argv[++index];
    else
      throw std::invalid_argument("A117 unknown or incomplete argument: " + argument);
  }
  return options;
}

void validate_options(const Options& options)
{
  if (!options.run || !options.ack_keygen || !options.ack_encryption ||
      !options.ack_fhe || !options.ack_timing ||
      !options.ack_security_is_not_capacity)
    throw std::runtime_error(
        "A117 run refused: all explicit run acknowledgements are required");
  if (!(options.max_load > 0.0) || options.max_load > kHardLoadCeiling)
    throw std::runtime_error("A117 max-load must be in (0,24]");
  if (options.result_path.empty() || options.timers_path.empty())
    throw std::runtime_error("A117 requires distinct --result and --timers paths");
  if (options.result_path == options.timers_path)
    throw std::runtime_error("A117 result and timer paths must differ");
}

std::uint32_t next_lcg(std::uint32_t& state)
{
  state = state * UINT32_C(1664525) + UINT32_C(1013904223);
  return state;
}

std::vector<Pair> make_fixture(std::size_t slots)
{
  const std::vector<Pair> mandatory = {
      {0, 4095},    // difference -4095
      {0, 1},       // difference -1
      {0, 0},       // difference 0 at the lower boundary
      {4095, 4095}, // difference 0 at the upper boundary
      {1, 0},       // difference +1
      {4095, 0},    // difference +4095
      {4094, 4095},
      {4095, 4094},
      {2047, 2048},
      {2048, 2047},
  };
  if (slots < mandatory.size() + 8192)
    throw std::runtime_error("A117 requires enough slots for the frozen fixture");

  std::vector<Pair> pairs = mandatory;
  pairs.reserve(slots);

  // Two complete permutations ensure that every score in [0,4095] occurs on
  // both the x and y sides, independently of the pseudorandom tail.
  for (long value = 0; value <= kScoreMaximum; ++value)
    pairs.push_back({value, (4051 * value + 2047) & kScoreMaximum});
  for (long value = 0; value <= kScoreMaximum; ++value)
    pairs.push_back({(109 * value + 37) & kScoreMaximum, value});

  std::uint32_t state = UINT32_C(0xA1172026);
  while (pairs.size() < slots) {
    const long x = static_cast<long>((next_lcg(state) >> 8U) & kScoreMaximum);
    const long y = static_cast<long>((next_lcg(state) >> 8U) & kScoreMaximum);
    pairs.push_back({x, y});
  }
  return pairs;
}

std::uint64_t fixture_hash(const std::vector<Pair>& pairs)
{
  std::uint64_t hash = UINT64_C(14695981039346656037);
  for (const Pair& pair : pairs) {
    for (const long value : {pair.x, pair.y}) {
      for (unsigned shift = 0; shift < 16; shift += 8) {
        hash ^= static_cast<std::uint8_t>((value >> shift) & 0xff);
        hash *= UINT64_C(1099511628211);
      }
    }
  }
  return hash;
}

long timer_calls(const char* name)
{
  const helib::FHEtimer* timer = helib::getTimerByName(name);
  return timer == nullptr ? 0 : timer->getNumCalls();
}

double timer_seconds(const char* name)
{
  const helib::FHEtimer* timer = helib::getTimerByName(name);
  return timer == nullptr ? 0.0 : timer->getTime();
}

int run_gate(const Options& options)
{
  validate_options(options);
  const double observed_load = one_minute_load();
  if (observed_load > options.max_load)
    throw std::runtime_error("A117 load gate refused the FHE run");

  auto phase_start = std::chrono::steady_clock::now();
  const auto context = helib::ContextBuilder<helib::BGV>()
                           .m(kCyclotomicOrder)
                           .p(kPlaintextPrime)
                           .r(1)
                           .bits(kRequestedBits)
                           .c(kColumns)
                           .scale(kScale)
                           .build();
  const double context_seconds = seconds_since(phase_start);
  const double actual_bits =
      context.logOfProduct(context.getCtxtPrimes()) / std::log(2.0);
  const double security_bits = context.securityLevel();
  const long slots = context.getNSlots();
  if (context.getP() != kPlaintextPrime || context.getPhiM() != 32768 ||
      context.getOrdP() != 2 || slots != 16384)
    throw std::runtime_error("A117 context geometry drift");
  if (std::abs(actual_bits - kExpectedActualBits) > 1e-6 ||
      std::abs(security_bits - kExpectedSecurityBits) > 1e-6)
    throw std::runtime_error("A117 context no longer matches the A115 Q=600 row");

  phase_start = std::chrono::steady_clock::now();
  helib::SecKey secret_key(context);
  secret_key.GenSecKey();
  const helib::PubKey& public_key = secret_key;
  const double keygen_seconds = seconds_since(phase_start);

  phase_start = std::chrono::steady_clock::now();
  he_cmp::Comparator comparator(
      context, he_cmp::UNI, 1, 1, secret_key, false);
  const double comparator_setup_seconds = seconds_since(phase_start);

  const auto pairs = make_fixture(static_cast<std::size_t>(slots));
  std::vector<NTL::ZZX> plaintext_x(slots);
  std::vector<NTL::ZZX> plaintext_y(slots);
  long negative_differences = 0;
  long zero_differences = 0;
  long positive_differences = 0;
  for (long slot = 0; slot < slots; ++slot) {
    NTL::SetCoeff(plaintext_x[slot], 0, pairs[slot].x);
    NTL::SetCoeff(plaintext_y[slot], 0, pairs[slot].y);
    const long difference = pairs[slot].x - pairs[slot].y;
    negative_differences += difference < 0;
    zero_differences += difference == 0;
    positive_differences += difference > 0;
  }

  phase_start = std::chrono::steady_clock::now();
  helib::Ctxt ciphertext_x(public_key);
  helib::Ctxt ciphertext_y(public_key);
  context.getEA().encrypt(ciphertext_x, public_key, plaintext_x);
  context.getEA().encrypt(ciphertext_y, public_key, plaintext_y);
  const double encryption_seconds = seconds_since(phase_start);
  const long capacity_before =
      std::min(ciphertext_x.bitCapacity(), ciphertext_y.bitCapacity());

  helib::resetAllTimers();
  helib::Ctxt ciphertext_result(public_key);
  phase_start = std::chrono::steady_clock::now();
  comparator.compare(ciphertext_result, ciphertext_x, ciphertext_y);
  const double comparison_seconds = seconds_since(phase_start);
  const long capacity_after_before_cleanup = ciphertext_result.bitCapacity();
  ciphertext_result.cleanUp();
  const long capacity_after_cleanup = ciphertext_result.bitCapacity();

  phase_start = std::chrono::steady_clock::now();
  std::vector<NTL::ZZX> decrypted(slots);
  context.getEA().decrypt(ciphertext_result, secret_key, decrypted);
  const double decryption_seconds = seconds_since(phase_start);

  long mismatches = 0;
  long first_mismatch = -1;
  for (long slot = 0; slot < slots; ++slot) {
    const NTL::ZZX expected(
        NTL::INIT_MONO, 0, pairs[slot].x < pairs[slot].y ? 1 : 0);
    if (decrypted[slot] != expected) {
      ++mismatches;
      if (first_mismatch < 0)
        first_mismatch = slot;
    }
  }

  std::ofstream timers(options.timers_path);
  if (!timers)
    throw std::runtime_error("A117 could not open the timer output");
  helib::printAllTimers(timers);
  timers.close();

  const long multiply_calls = timer_calls("multiplyBy");
  const long automorph_calls = timer_calls("automorph");
  const long smart_automorph_calls = timer_calls("smartAutomorph");
  const long frobenius_calls = timer_calls("frobeniusAutomorph");

  const bool gate_pass =
      security_bits >= 128.0 && capacity_after_cleanup > 0 && mismatches == 0;

  std::ofstream result(options.result_path);
  if (!result)
    throw std::runtime_error("A117 could not open the result output");
  result << std::fixed << std::setprecision(12);
  result << "{\n"
         << "  \"artifact\": \"A117\",\n"
         << "  \"status\": \"" << (gate_pass ? "PASS" : "FAIL") << "\",\n"
         << "  \"requested_q_bits\": " << kRequestedBits << ",\n"
         << "  \"actual_ctxt_prime_bits\": " << actual_bits << ",\n"
         << "  \"security_bits_helib\": " << security_bits << ",\n"
         << "  \"observed_load_1m\": " << observed_load << ",\n"
         << "  \"slots\": " << slots << ",\n"
         << "  \"fixture_fnv1a64\": \"0x" << std::hex
         << fixture_hash(pairs) << std::dec << "\",\n"
         << "  \"negative_differences\": " << negative_differences << ",\n"
         << "  \"zero_differences\": " << zero_differences << ",\n"
         << "  \"positive_differences\": " << positive_differences << ",\n"
         << "  \"mismatches\": " << mismatches << ",\n"
         << "  \"first_mismatch_slot\": " << first_mismatch << ",\n"
         << "  \"capacity_before_bits\": " << capacity_before << ",\n"
         << "  \"capacity_after_before_cleanup_bits\": "
         << capacity_after_before_cleanup << ",\n"
         << "  \"capacity_after_cleanup_bits\": "
         << capacity_after_cleanup << ",\n"
         << "  \"multiplyBy_calls_during_comparison\": " << multiply_calls
         << ",\n"
         << "  \"automorph_calls_during_comparison\": " << automorph_calls
         << ",\n"
         << "  \"smartAutomorph_calls_during_comparison\": "
         << smart_automorph_calls << ",\n"
         << "  \"frobeniusAutomorph_calls_during_comparison\": "
         << frobenius_calls << ",\n"
         << "  \"multiplyBy_timer_seconds\": "
         << timer_seconds("multiplyBy") << ",\n"
         << "  \"context_seconds\": " << context_seconds << ",\n"
         << "  \"keygen_seconds\": " << keygen_seconds << ",\n"
         << "  \"comparator_setup_seconds\": "
         << comparator_setup_seconds << ",\n"
         << "  \"encryption_seconds\": " << encryption_seconds << ",\n"
         << "  \"comparison_seconds\": " << comparison_seconds << ",\n"
         << "  \"decryption_seconds\": " << decryption_seconds << "\n"
         << "}\n";
  result.close();

  std::cout << "A117_RESULT_PATH=" << options.result_path << '\n';
  std::cout << "A117_TIMERS_PATH=" << options.timers_path << '\n';
  return gate_pass ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
  try {
    return run_gate(parse_options(argc, argv));
  } catch (const std::exception& error) {
    std::cerr << "A117_REFUSED_OR_FAILED: " << error.what() << '\n';
    return 2;
  }
}
