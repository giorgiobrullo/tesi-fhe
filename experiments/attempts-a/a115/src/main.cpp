#include <helib/helib.h>

#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

constexpr long kPlaintextPrime = 8191;
constexpr long kCyclotomicOrder = 81920;
constexpr long kHenselLifting = 1;
constexpr long kScale = 6;
constexpr long kExpectedPhiM = 32768;
constexpr long kExpectedOrdP = 2;
constexpr long kExpectedSlots = 16384;
constexpr double kHardLoadCeiling = 24.0;
constexpr const char* kAck = "A115_CONTEXT_ONLY_NO_KEYGEN_NO_FHE";

struct Options
{
  bool run = false;
  bool ack = false;
  long bits = 0;
  long columns = 0;
  double max_load = 0.0;
};

long parse_long(const std::string& value, const char* label)
{
  std::size_t consumed = 0;
  const long parsed = std::stol(value, &consumed);
  if (consumed != value.size())
    throw std::invalid_argument(std::string(label) + " is not an integer");
  return parsed;
}

double parse_double(const std::string& value, const char* label)
{
  std::size_t consumed = 0;
  const double parsed = std::stod(value, &consumed);
  if (consumed != value.size() || !std::isfinite(parsed))
    throw std::invalid_argument(std::string(label) + " is not finite");
  return parsed;
}

Options parse_options(int argc, char** argv)
{
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string argument(argv[i]);
    if (argument == "--run") {
      if (options.run)
        throw std::invalid_argument("duplicate --run");
      options.run = true;
    } else if (argument == "--ack-context-only") {
      if (options.ack)
        throw std::invalid_argument("duplicate --ack-context-only");
      options.ack = true;
    } else if (argument == "--bits") {
      if (++i >= argc || options.bits != 0)
        throw std::invalid_argument("--bits requires one value");
      options.bits = parse_long(argv[i], "bits");
    } else if (argument == "--columns") {
      if (++i >= argc || options.columns != 0)
        throw std::invalid_argument("--columns requires one value");
      options.columns = parse_long(argv[i], "columns");
    } else if (argument == "--max-load") {
      if (++i >= argc || options.max_load != 0.0)
        throw std::invalid_argument("--max-load requires one value");
      options.max_load = parse_double(argv[i], "max-load");
    } else {
      throw std::invalid_argument("unknown argument: " + argument);
    }
  }
  return options;
}

double one_minute_load()
{
  double averages[3] = {0.0, 0.0, 0.0};
  if (getloadavg(averages, 3) != 3)
    throw std::runtime_error("getloadavg failed");
  return averages[0];
}

void validate_options(const Options& options)
{
  if (!options.run || !options.ack)
    throw std::invalid_argument(
        "execution requires --run --ack-context-only");
  if (options.bits < 100 || options.bits > 2400)
    throw std::invalid_argument("bits must be in [100,2400]");
  if (options.columns < 2 || options.columns > 4)
    throw std::invalid_argument("columns must be in [2,4]");
  if (options.max_load <= 0.0 || options.max_load > kHardLoadCeiling)
    throw std::invalid_argument("max-load must be in (0,24]");
}

} // namespace

int main(int argc, char** argv)
{
  try {
    const Options options = parse_options(argc, argv);
    validate_options(options);

    const double observed_load = one_minute_load();
    if (observed_load > options.max_load) {
      std::cerr << "A115 load gate refused context construction: observed="
                << observed_load << " limit=" << options.max_load << '\n';
      return 75;
    }

    const auto context = helib::ContextBuilder<helib::BGV>()
                             .m(kCyclotomicOrder)
                             .p(kPlaintextPrime)
                             .r(kHenselLifting)
                             .bits(options.bits)
                             .c(options.columns)
                             .scale(kScale)
                             .build();

    if (context.getPhiM() != kExpectedPhiM ||
        context.getOrdP() != kExpectedOrdP ||
        context.getNSlots() != kExpectedSlots) {
      throw std::runtime_error("HElib context geometry differs from A109");
    }

    const double log_two = std::log(2.0);
    const double ctxt_bits =
        context.logOfProduct(context.getCtxtPrimes()) / log_two;
    const double full_bits = context.logOfProduct(context.fullPrimes()) / log_two;

    std::cout << std::fixed << std::setprecision(9)
              << "{\"record\":\"a115_context\","
              << "\"ack\":\"" << kAck << "\","
              << "\"p\":" << kPlaintextPrime << ','
              << "\"m\":" << kCyclotomicOrder << ','
              << "\"r\":" << kHenselLifting << ','
              << "\"scale\":" << kScale << ','
              << "\"requested_bits\":" << options.bits << ','
              << "\"columns\":" << options.columns << ','
              << "\"phi_m\":" << context.getPhiM() << ','
              << "\"ord_p\":" << context.getOrdP() << ','
              << "\"slots\":" << context.getNSlots() << ','
              << "\"ctxt_prime_bits\":" << ctxt_bits << ','
              << "\"full_prime_bits\":" << full_bits << ','
              << "\"security_bits_helib\":" << context.securityLevel() << ','
              << "\"observed_load_1m\":" << observed_load << ','
              << "\"keygen\":false,\"fhe_eval\":false}"
              << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "A115 error: " << error.what() << '\n';
    return 2;
  }
}
