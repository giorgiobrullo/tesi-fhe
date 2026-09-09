// Exact observer helpers from the frozen compiled context probe.
namespace larger_context {
constexpr long kM=245760,kP=8191;
const std::vector<long> kGenerators{163843,86017,163841},kOrders{4096,4,2};
double finite_number(double value)
{
  need(std::isfinite(value) && value >= 0, "nonfinite or negative public observation");
  return value;
}

long power(long base, long exponent)
{
  long result = 1;
  for (; exponent; exponent >>= 1, base = base * base % kM)
    if (exponent & 1) result = result * base % kM;
  return result;
}

std::vector<long> expected_representatives()
{
  std::vector<long> result;
  result.reserve(32768);
  for (long a = 0; a < 4096; ++a)
    for (long b = 0; b < 4; ++b)
      for (long c = 0; c < 2; ++c)
        result.push_back(power(kGenerators[0], a) * power(kGenerators[1], b) % kM *
                         power(kGenerators[2], c) % kM);
  return result;
}

NativeJson geometry(const helib::Context& context)
{
  const auto& algebra = context.getZMStar();
  const auto& array = context.getEA();
  std::vector<long> generators, orders, array_sizes, representatives;
  std::vector<bool> native, array_native;
  need(algebra.numOfGens() >= 0 && algebra.numOfGens() <= 64 &&
       array.dimension() >= 0 && array.dimension() <= 64 &&
       context.getNSlots() >= 0 && context.getNSlots() <= 1048576,
       "public geometry exceeds observation bounds");
  for (long i = 0; i < algebra.numOfGens(); ++i) {
    generators.push_back(algebra.ZmStarGen(i));
    orders.push_back(algebra.OrderOf(i));
    native.push_back(algebra.SameOrd(i));
  }
  for (long i = 0; i < array.dimension(); ++i) {
    array_sizes.push_back(array.sizeOfDimension(i));
    array_native.push_back(array.nativeDimension(i));
  }
  for (long i = 0; i < context.getNSlots(); ++i) representatives.push_back(algebra.ith_rep(i));
  const auto expected = expected_representatives();
  const bool reps_pass = representatives == expected;
  const bool pass = context.getM() == kM && context.getP() == kP && context.getR() == 1 &&
      context.getPhiM() == 65536 && context.getOrdP() == 2 && context.getNSlots() == 32768 &&
      generators == kGenerators && orders == kOrders && native == std::vector<bool>(3, true) &&
      array.dimension() == 3 && array_sizes == kOrders && array_native == std::vector<bool>(3, true) &&
      reps_pass;
  return NativeJson{{"m", context.getM()}, {"p", context.getP()}, {"r", context.getR()},
              {"phi_m", context.getPhiM()}, {"ord_p", context.getOrdP()},
              {"slots", context.getNSlots()}, {"num_generators", algebra.numOfGens()},
              {"generators", generators}, {"orders", orders}, {"native_dimensions", native},
              {"ea_dimensions", array.dimension()}, {"ea_dimension_sizes", array_sizes},
              {"ea_native_dimensions", array_native}, {"representatives", representatives},
              {"representatives_pass", reps_pass}, {"geometry_pass", pass}};
}

struct PrimeSet {
  std::vector<long> indices;
  std::vector<long> values;
  double bits;
};

PrimeSet read_primes(const helib::Context& context, const helib::IndexSet& set)
{
  PrimeSet result;
  for (long index : set) {
    result.indices.push_back(index);
    result.values.push_back(context.ithPrime(index));
  }
  result.bits = finite_number(context.logOfProduct(set) / std::log(2.0));
  return result;
}

NativeJson prime_json(const PrimeSet& set)
{
  std::vector<std::string> values;
  for (long prime : set.values) values.push_back(std::to_string(prime));
  return NativeJson{{"indices", set.indices}, {"prime_values_decimal", values}, {"log2_product", set.bits}};
}

bool prime_set_valid(const PrimeSet& set)
{
  const std::set<long> indices(set.indices.begin(), set.indices.end());
  const std::set<long> values(set.values.begin(), set.values.end());
  if (indices.size() != set.indices.size() || values.size() != set.values.size() ||
      !std::is_sorted(set.indices.begin(), set.indices.end())) return false;
  double independently_summed_bits = 0;
  for (size_t i = 0; i < set.indices.size(); ++i) {
    if (set.indices[i] < 0 || set.values[i] <= 1) return false;
    independently_summed_bits += std::log2(double(set.values[i]));
  }
  return std::abs(set.bits - independently_summed_bits) <= 1e-8;
}

bool disjoint(const PrimeSet& a, const PrimeSet& b)
{
  std::set<long> indices(a.indices.begin(), a.indices.end());
  std::set<long> values(a.values.begin(), a.values.end());
  for (long i : b.indices) if (indices.count(i)) return false;
  for (long value : b.values) if (values.count(value)) return false;
  return true;
}

NativeJson moduli(const helib::Context& context)
{
  const auto small = read_primes(context, context.getSmallPrimes());
  const auto ctxt = read_primes(context, context.getCtxtPrimes());
  const auto special = read_primes(context, context.getSpecialPrimes());
  const auto full = read_primes(context, context.fullPrimes());
  std::set<std::pair<long, long>> expected, observed;
  for (const auto* set : {&ctxt, &special})
    for (size_t i = 0; i < set->indices.size(); ++i) expected.emplace(set->indices[i], set->values[i]);
  for (size_t i = 0; i < full.indices.size(); ++i) observed.emplace(full.indices[i], full.values[i]);
  const bool pass = prime_set_valid(small) && prime_set_valid(ctxt) && prime_set_valid(special) &&
      prime_set_valid(full) && !ctxt.indices.empty() && !special.indices.empty() &&
      disjoint(small, ctxt) && disjoint(small, special) && disjoint(ctxt, special) && expected == observed;
  return NativeJson{{"small", prime_json(small)}, {"ciphertext", prime_json(ctxt)},
              {"special", prime_json(special)}, {"full", prime_json(full)},
              {"modulus_ledger_pass", pass}};
}
}
