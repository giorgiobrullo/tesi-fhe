#include "openfhe.h"
#include "balanced_odd7.h"
#include "balanced_shared_rescale.h"
#include "balanced_shared_powers.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <vector>
#ifdef _OPENMP
#include <omp.h>
#endif

using namespace lbcrypto;
using Clock = std::chrono::steady_clock;
using Ct = Ciphertext<DCRTPoly>;
using Context = CryptoContext<DCRTPoly>;

namespace {

double seconds(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now() - start).count();
}

uint64_t peakRss() {
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0) return 0;
#ifdef __APPLE__
    return static_cast<uint64_t>(usage.ru_maxrss);
#else
    return static_cast<uint64_t>(usage.ru_maxrss) * 1024;
#endif
}

std::string jsonQuote(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') out << '\\' << static_cast<char>(c);
        else if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c) << std::dec;
        else out << static_cast<char>(c);
    }
    out << '"';
    return out.str();
}

std::string number(double value) {
    if (!std::isfinite(value)) return "null";
    std::ostringstream out;
    out << std::setprecision(17) << value;
    return out.str();
}

void emit(const std::string& fields) {
    std::cout << '{' << fields << ",\"peak_rss_bytes\":" << peakRss() << '}' << std::endl;
}

size_t log2Exact(size_t n) {
    if (n == 0 || (n & (n - 1))) throw std::runtime_error("Expected a positive power of two");
    size_t result = 0;
    while (n > 1) { n >>= 1; ++result; }
    return result;
}

int64_t checkedI64(__int128 value) {
    if (value < std::numeric_limits<int64_t>::min() || value > std::numeric_limits<int64_t>::max())
        throw std::runtime_error("Integer arithmetic overflow in public fixture");
    return static_cast<int64_t>(value);
}

uint64_t ceilSqrt(unsigned __int128 value) {
    uint64_t lo = 0, hi = std::numeric_limits<uint64_t>::max();
    while (lo < hi) {
        uint64_t mid = lo + (hi - lo) / 2;
        if (static_cast<unsigned __int128>(mid) * mid >= value) hi = mid;
        else lo = mid + 1;
    }
    return lo;
}

struct Options {
    std::vector<std::string> paths;
    size_t dg = 6, df = 2, depth = 0, scaleBits = 50, firstBits = 60, largeDigits = 3;
    size_t threads = 16, warmups = 0, repeats = 1, queryLimit = 0;
    int64_t qMax = 3, norm2Max = 1024;
    bool diagnostics = false, progress = false, cachePublic = false, pairedCache = false;
    bool pairedRuntime = false;
    std::string caseFilter, poly = "stock", runtime = "baseline";
    std::string runtimeReference = "baseline";
};

Options parseOptions(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--diagnostics") { options.diagnostics = true; continue; }
        if (arg == "--progress") { options.progress = true; continue; }
        if (arg == "--cache-public") { options.cachePublic = true; continue; }
        if (arg == "--paired-cache") { options.pairedCache = true; options.cachePublic = true; continue; }
        if (arg == "--paired-runtime") { options.pairedRuntime = true; continue; }
        if (arg == "--help") {
            std::cout << "ckks_identify --input FILE [--input FILE ...] [--poly stock|balanced --dg 6 --df 2 --depth D] "
                         "[--scale-bits 50 --first-bits 60 --large-digits 3 --threads 16 --warmups 0 --repeats 1] "
                         "[--q-max 3 --norm2-max 1024 --case LABEL --limit-queries N --diagnostics --progress --cache-public --paired-cache] "
                         "[--runtime baseline|shared-rescale|shared-powers|hoisted-score|combined|combined-powers --paired-runtime] "
                         "[--runtime-reference baseline|shared-rescale]\n";
            std::exit(0);
        }
        if (arg.rfind("--", 0) != 0) { options.paths.push_back(arg); continue; }
        if (i + 1 >= argc) throw std::runtime_error("Missing value for " + arg);
        std::string value = argv[++i];
        if (arg == "--input") options.paths.push_back(value);
        else if (arg == "--case") options.caseFilter = value;
        else if (arg == "--poly") options.poly = value;
        else if (arg == "--runtime") options.runtime = value;
        else if (arg == "--runtime-reference") options.runtimeReference = value;
        else {
            size_t consumed = 0;
            if (value.empty() || value[0] == '-') throw std::runtime_error("Expected nonnegative number for " + arg);
            uint64_t numeric = std::stoull(value, &consumed);
            if (consumed != value.size() || numeric > 1000000) throw std::runtime_error("Invalid number for " + arg);
            if (arg == "--dg") options.dg = numeric;
            else if (arg == "--df") options.df = numeric;
            else if (arg == "--depth") options.depth = numeric;
            else if (arg == "--scale-bits") options.scaleBits = numeric;
            else if (arg == "--first-bits") options.firstBits = numeric;
            else if (arg == "--large-digits") options.largeDigits = numeric;
            else if (arg == "--threads") options.threads = numeric;
            else if (arg == "--warmups") options.warmups = numeric;
            else if (arg == "--repeats") options.repeats = numeric;
            else if (arg == "--q-max") options.qMax = numeric;
            else if (arg == "--norm2-max") options.norm2Max = numeric;
            else if (arg == "--limit-queries") options.queryLimit = numeric;
            else throw std::runtime_error("Unknown option " + arg);
        }
    }
    if ((options.pairedCache || options.pairedRuntime) && options.progress)
        throw std::runtime_error("Paired evaluation cannot be combined with --progress");
    if (options.pairedCache && options.pairedRuntime)
        throw std::runtime_error("Select either cache or runtime pairing");
    if (options.runtime != "baseline" && options.runtime != "shared-rescale" &&
        options.runtime != "shared-powers" && options.runtime != "hoisted-score" &&
        options.runtime != "combined" && options.runtime != "combined-powers")
        throw std::runtime_error("Unknown runtime variant");
    if (options.runtimeReference != "baseline" && options.runtimeReference != "shared-rescale")
        throw std::runtime_error("Unknown runtime reference");
    if (options.pairedRuntime && options.runtime == options.runtimeReference)
        throw std::runtime_error("Runtime pairing requires a candidate variant");
    if ((options.runtime == "shared-rescale" || options.runtime == "combined" ||
         options.runtime == "shared-powers" || options.runtime == "combined-powers" ||
         options.runtimeReference == "shared-rescale") && options.poly != "balanced")
        throw std::runtime_error("Shared rescale applies only to the balanced polynomial");
    if (options.paths.empty() || options.df < 1 || options.dg > 32 || options.df > 32 ||
        options.threads < 1 || options.threads > 128 || options.repeats < 1 ||
        options.scaleBits < 30 || options.scaleBits > 59 || options.firstBits > 60 ||
        options.firstBits < options.scaleBits || options.depth > 256 || options.largeDigits < 1 || options.largeDigits > 256 ||
        (options.poly != "stock" && options.poly != "balanced"))
        throw std::runtime_error("Invalid configuration; use --help");
    return options;
}

struct Query {
    std::string label;
    size_t expected = 0;
    std::vector<int64_t> q;
    std::vector<int64_t> scores;
};

struct Fixture {
    std::string path;
    size_t n = 0, dim = 0;
    std::vector<std::vector<int64_t>> gallery;
    std::vector<int64_t> thresholds, norms;
    std::vector<Query> queries;
    int64_t publicLower = 0, publicUpper = 0;
    double publicComparisonBound = 0;
    double range = 1;
};

Fixture loadFixture(const std::string& path, const Options& options) {
    std::ifstream input(path);
    if (!input) throw std::runtime_error("Cannot open fixture: " + path);
    Fixture f;
    f.path = path;
    size_t count = 0;
    if (!(input >> f.n >> f.dim >> count) || (f.n != 4 && f.n != 64 && f.n != 128) ||
        f.dim != 512 || count == 0 || count > 100000)
        throw std::runtime_error("Invalid fixture header (supported N: 4,64,128; DIM:512): " + path);
    f.gallery.resize(f.n, std::vector<int64_t>(f.dim));
    f.norms.resize(f.n);
    for (size_t i = 0; i < f.n; ++i) {
        __int128 norm = 0;
        for (auto& value : f.gallery[i]) {
            if (!(input >> value) || value < -3 || value > 3)
                throw std::runtime_error("Gallery coefficient outside [-3,3]");
            norm += static_cast<__int128>(value) * value;
        }
        f.norms[i] = checkedI64(norm);
    }
    f.thresholds.resize(f.n);
    for (auto& t : f.thresholds)
        if (!(input >> t) || t < -1000000000 || t > 1000000000)
            throw std::runtime_error("Invalid threshold");
    f.publicLower = std::numeric_limits<int64_t>::max();
    f.publicUpper = std::numeric_limits<int64_t>::min();
    for (size_t i = 0; i < f.n; ++i) {
        uint64_t radius = ceilSqrt(static_cast<unsigned __int128>(f.norms[i]) * options.norm2Max);
        int64_t low = checkedI64(static_cast<__int128>(f.norms[i]) - 2 * static_cast<__int128>(radius));
        int64_t high = checkedI64(static_cast<__int128>(f.norms[i]) + 2 * static_cast<__int128>(radius));
        f.publicLower = std::min(f.publicLower, low);
        f.publicUpper = std::max(f.publicUpper, high);
        f.publicComparisonBound = std::max(f.publicComparisonBound,
            std::abs(static_cast<double>(f.norms[i]) - static_cast<double>(f.thresholds[i])) + 2.0 * radius);
    }
    // Bound each score difference directly: the shared probe makes the union-of-score
    // interval unnecessarily loose. No observed query value enters this normalization.
    for (size_t i = 0; i < f.n; ++i) {
        for (size_t j = i + 1; j < f.n; ++j) {
            unsigned __int128 differenceNorm = 0;
            for (size_t k = 0; k < f.dim; ++k) {
                __int128 difference = static_cast<__int128>(f.gallery[j][k]) - f.gallery[i][k];
                differenceNorm += static_cast<unsigned __int128>(difference * difference);
            }
            uint64_t radius = ceilSqrt(differenceNorm * options.norm2Max);
            double bound = std::abs(static_cast<double>(f.norms[j]) - static_cast<double>(f.norms[i])) + 2.0 * radius;
            f.publicComparisonBound = std::max(f.publicComparisonBound, bound);
        }
    }
    while (f.range < f.publicComparisonBound + 0.5 + 1.0) f.range *= 2.0;
    for (size_t a = 0; a < count; ++a) {
        Query query;
        if (!(input >> query.label >> query.expected) || query.expected > f.n)
            throw std::runtime_error("Invalid query header");
        query.q.resize(f.dim);
        __int128 norm = 0;
        for (auto& value : query.q) {
            if (!(input >> value) || value < -options.qMax || value > options.qMax)
                throw std::runtime_error("Probe coordinate outside declared public domain");
            norm += static_cast<__int128>(value) * value;
        }
        if (norm > options.norm2Max) throw std::runtime_error("Probe norm exceeds declared public bound");
        query.scores.resize(f.n);
        size_t winner = 0;
        for (size_t i = 0; i < f.n; ++i) {
            __int128 score = f.norms[i];
            for (size_t j = 0; j < f.dim; ++j) score -= 2 * static_cast<__int128>(f.gallery[i][j]) * query.q[j];
            query.scores[i] = checkedI64(score);
            if (query.scores[i] < f.publicLower || query.scores[i] > f.publicUpper)
                throw std::runtime_error("Public Cauchy bound implementation mismatch");
            if (query.scores[i] < query.scores[winner]) winner = i;
        }
        size_t expected = query.scores[winner] <= f.thresholds[winner] ? winner + 1 : 0;
        if (expected != query.expected) throw std::runtime_error("Fixture expected-ID disagrees with exact oracle: " + query.label);
        if (options.caseFilter.empty() || options.caseFilter == query.label) f.queries.push_back(std::move(query));
    }
    std::string extra;
    if (input >> extra) throw std::runtime_error("Unexpected trailing fixture token: " + extra);
    return f;
}

struct PublicPlan {
    size_t n, dim, batch, width, rho;
    double range;
    std::vector<std::vector<double>> scoreCoefficients;
    std::vector<double> scoreMask, normConstants, firstRowMask, nonDiagonal, bias, idMask, outputMask;
    PublicPlan(const Fixture& f, size_t slots)
        : n(f.n), dim(f.dim), batch(slots), width(slots / n), rho(n * dim / slots), range(f.range),
          scoreCoefficients(rho, std::vector<double>(slots)), scoreMask(slots), normConstants(slots),
          firstRowMask(slots), nonDiagonal(slots), bias(slots), idMask(slots), outputMask(slots) {
        if (batch % dim || batch % n || n * dim % batch || rho == 0 || width > dim)
            throw std::runtime_error("Unsupported Halevi-Shoup layout");
        for (size_t j = 0; j < rho; ++j)
            for (size_t slot = 0; slot < batch; ++slot) {
                size_t row = slot / width;
                size_t col = width * ((row + j) % rho) + slot % width;
                scoreCoefficients[j][slot] = -2.0 * static_cast<double>(f.gallery[row][col]);
            }
        for (size_t i = 0; i < n; ++i) {
            scoreMask[i * width] = 1;
            normConstants[i * width] = static_cast<double>(f.norms[i]);
            firstRowMask[i] = 1;
            idMask[i * n] = static_cast<double>(i + 1);
            for (size_t j = 0; j < n; ++j) {
                size_t slot = i * n + j;
                nonDiagonal[slot] = i != j ? 1 : 0;
                bias[slot] = i == j ? static_cast<double>(f.thresholds[i]) + 0.5 : (i < j ? 0.5 : -0.5);
            }
        }
        outputMask[0] = 1;
    }
};

std::vector<int32_t> rotations(const PublicPlan& p) {
    std::set<int32_t> values;
    for (size_t j = 1; j < p.rho; ++j) values.insert(static_cast<int32_t>(p.width * j));
    for (size_t s = 1; s < p.width; s *= 2) values.insert(static_cast<int32_t>(s));
    for (size_t s = 1; s < p.n; s *= 2) {
        values.insert(-static_cast<int32_t>(s));
        values.insert(-static_cast<int32_t>(p.n * s));
    }
    for (size_t k = 1; k <= log2Exact(p.n); ++k)
        values.insert(static_cast<int32_t>(p.n * (p.n - 1) / (size_t(1) << k)));
    if (p.width != p.n)
        for (size_t i = 1; i < p.n; ++i) values.insert(static_cast<int32_t>(i * (p.width - p.n)));
    for (size_t s = 1; s < p.batch; s *= 2) values.insert(static_cast<int32_t>(s));
    values.erase(0);
    return {values.begin(), values.end()};
}

// One immutable cache per context and public fixture. The fixed circuit's input
// levels are checked at every lookup; an unexpected level never triggers a
// silent re-encoding or reuse of a plaintext from another level.
class PublicPlaintexts {
    struct Entry {
        std::vector<double> values;
        size_t level;
        Plaintext plaintext;
    };
    Context context;
    size_t slots;
    std::vector<Entry> entries;

    void prepare(const std::vector<double>& values, size_t level) {
        for (const auto& entry : entries)
            if (entry.level == level && entry.values == values) return;
        auto plaintext = context->MakeCKKSPackedPlaintext(values, 1, static_cast<uint32_t>(level),
                                                         nullptr, static_cast<uint32_t>(slots));
        // EvalAdd requests this format. OpenFHE 1.5.1's MorphPlaintext copies the
        // encoded polynomial before changing levels/scales, so cached data stays fixed.
        plaintext->SetFormat(EVALUATION);
        entries.push_back({values, level, std::move(plaintext)});
    }

public:
    PublicPlaintexts(const Context& cc, const PublicPlan& p, const Options& options)
        : context(cc), slots(p.batch) {
        for (const auto& coefficients : p.scoreCoefficients) prepare(coefficients, 0);
        prepare(p.scoreMask, 0);
        prepare(p.normConstants, 1);
        size_t columnLevel = 1;
        if (p.width != p.n) {
            for (size_t i = 0; i < p.n; ++i) {
                std::vector<double> mask(slots);
                mask[i * p.width] = 1;
                prepare(mask, 1);
            }
            ++columnLevel;
        }
        prepare(p.firstRowMask, columnLevel);
        prepare(p.nonDiagonal, columnLevel + 1);
        prepare(p.bias, columnLevel + 2);
        const size_t polynomialDepth = options.poly == "stock" ? 4 : 3;
        const size_t productLevel = columnLevel + 3 +
            polynomialDepth * (options.dg + options.df) + log2Exact(p.n);
        prepare(p.idMask, productLevel);
        prepare(p.outputMask, productLevel + 1);
    }

    size_t size() const { return entries.size(); }

    Plaintext get(const Context& cc, const std::vector<double>& values, size_t level,
                  size_t requestedSlots) const {
        if (cc != context || requestedSlots != slots)
            throw std::runtime_error("Public plaintext cache context or slot mismatch");
        for (const auto& entry : entries)
            if (entry.level == level && entry.values == values) return entry.plaintext;
        throw std::runtime_error("Public plaintext cache miss at level " + std::to_string(level));
    }
};

Plaintext encodeFor(const Context& cc, const std::vector<double>& values, const Ct& ct, size_t slots,
                    const PublicPlaintexts* cache) {
    if (cache) return cache->get(cc, values, ct->GetLevel(), slots);
    return cc->MakeCKKSPackedPlaintext(values, 1, ct->GetLevel(), nullptr, static_cast<uint32_t>(slots));
}

Ct multiplyPlain(const Context& cc, const Ct& ct, const std::vector<double>& values, size_t slots,
                 const PublicPlaintexts* cache) {
    auto plaintext = encodeFor(cc, values, ct, slots, cache);
    return cc->EvalMult(ct, plaintext);
}

Ct addPlain(const Context& cc, const Ct& ct, const std::vector<double>& values, size_t slots,
            const PublicPlaintexts* cache) {
    auto plaintext = encodeFor(cc, values, ct, slots, cache);
    return cc->EvalAdd(ct, plaintext);
}

struct StageMetrics {
    std::string name;
    double seconds;
    size_t level, noiseScaleDegree;
};

void emitStage(const StageMetrics& stage, const std::string& fields, bool afterTimer) {
    emit("\"record\":\"stage\"," + fields + ",\"stage\":" + jsonQuote(stage.name) +
         ",\"seconds\":" + number(stage.seconds) + ",\"level\":" + std::to_string(stage.level) +
         ",\"noise_scale_degree\":" + std::to_string(stage.noiseScaleDegree) +
         ",\"effective_depth\":" + std::to_string(stage.level + stage.noiseScaleDegree - 1) +
         ",\"after_query_timer\":" + (afterTimer ? "true" : "false"));
}

struct Evaluation {
    Ct output, score, normalized, indicators, products;
    std::vector<StageMetrics> stages;
    double total = 0;
};

size_t effectiveDepth(const Ct& ciphertext) {
    return ciphertext->GetLevel() + ciphertext->GetNoiseScaleDeg() - 1;
}

bool sameCiphertext(const Ct& first, const Ct& second) {
    // The pinned library checks every element and the context/key tag, slots,
    // level/hops, scale degree/factors, encoding type, and metadata values.
    return first && second && *first == *second;
}

Ct evaluatePolynomial(const Context& cc, const Ct& input, const std::vector<double>& coefficients,
                      const std::string& method, bool sharedRescale, bool sharedPowers) {
    if (method == "stock") return cc->EvalPolyLinear(input, coefficients);
    if (sharedPowers) return ckks_polynomial_micro::EvaluateOdd7SharedPowers(
        cc, input, {coefficients[1], coefficients[3], coefficients[5], coefficients[7]}, coefficients[0]);
    if (sharedRescale) return ckks_polynomial_micro::EvaluateOdd7SharedRescale(
        cc, input, {coefficients[1], coefficients[3], coefficients[5], coefficients[7]}, coefficients[0]);
    return ckks_polynomial_micro::EvaluateOdd7Balanced(
        cc, input, {coefficients[1], coefficients[3], coefficients[5], coefficients[7]}, coefficients[0]);
}

Evaluation evaluate(const Context& cc, const Ct& encryptedQuery, const PublicPlan& p,
                    const Options& options, const std::string& queryFields,
                    const PublicPlaintexts* cache) {
    Evaluation result;
    result.stages.reserve(5);
    auto begin = Clock::now();
    auto stageBegin = begin;
    auto finishStage = [&](const std::string& stage, const Ct& current) {
        double elapsed = seconds(stageBegin);
        result.stages.push_back({stage, elapsed, current->GetLevel(), current->GetNoiseScaleDeg()});
        if (options.progress) emitStage(result.stages.back(), queryFields, false);
        stageBegin = Clock::now();
    };

    const bool sharedRescale = options.runtime == "shared-rescale" || options.runtime == "combined";
    const bool sharedPowers = options.runtime == "shared-powers" || options.runtime == "combined-powers";
    const bool hoistedScore = options.runtime == "hoisted-score" || options.runtime == "combined" ||
                              options.runtime == "combined-powers";
    // This decomposition depends on this encrypted query and belongs inside
    // the query timer. Only the score rotations share an unmodified input.
    std::shared_ptr<std::vector<DCRTPoly>> scoreDigits;
    if (hoistedScore && p.rho > 1) scoreDigits = cc->EvalFastRotationPrecompute(encryptedQuery);
    Ct score;
    for (size_t j = 0; j < p.rho; ++j) {
        Ct rotated = encryptedQuery;
        if (j) {
            const auto shift = static_cast<uint32_t>(p.width * j);
            rotated = scoreDigits ? cc->EvalFastRotation(encryptedQuery, shift, scoreDigits) :
                cc->EvalRotate(encryptedQuery, static_cast<int32_t>(shift));
        }
        auto term = multiplyPlain(cc, rotated, p.scoreCoefficients[j], p.batch, cache);
        score = score ? cc->EvalAdd(score, term) : term;
    }
    for (size_t s = 1; s < p.width; s *= 2) score = cc->EvalAdd(score, cc->EvalRotate(score, static_cast<int32_t>(s)));
    score = multiplyPlain(cc, score, p.scoreMask, p.batch, cache);
    score = addPlain(cc, score, p.normConstants, p.batch, cache);
    if (options.diagnostics) result.score = score;
    finishStage("score", score);

    Ct firstColumn = score;
    if (p.width != p.n) {
        // Only N=4 uses this small diagnostic compaction; N=64/128 already have W=N.
        firstColumn = nullptr;
        for (size_t i = 0; i < p.n; ++i) {
            std::vector<double> mask(p.batch);
            mask[i * p.width] = 1;
            auto term = multiplyPlain(cc, score, mask, p.batch, cache);
            if (i) term = cc->EvalRotate(term, static_cast<int32_t>(i * (p.width - p.n)));
            firstColumn = firstColumn ? cc->EvalAdd(firstColumn, term) : term;
        }
    }
    auto rows = firstColumn;
    for (size_t s = 1; s < p.n; s *= 2) rows = cc->EvalAdd(rows, cc->EvalRotate(rows, -static_cast<int32_t>(s)));

    // transposeColumn from openfhe-statistics: only the first row is retained afterward.
    auto columns = firstColumn;
    for (size_t k = 1; k <= log2Exact(p.n); ++k) {
        int32_t shift = static_cast<int32_t>(p.n * (p.n - 1) / (size_t(1) << k));
        columns = cc->EvalAdd(columns, cc->EvalRotate(columns, shift));
    }
    columns = multiplyPlain(cc, columns, p.firstRowMask, p.batch, cache);
    for (size_t s = 1; s < p.n; s *= 2)
        columns = cc->EvalAdd(columns, cc->EvalRotate(columns, -static_cast<int32_t>(p.n * s)));
    columns = multiplyPlain(cc, columns, p.nonDiagonal, p.batch, cache);
    auto normalized = cc->EvalSub(columns, rows);
    normalized = addPlain(cc, normalized, p.bias, p.batch, cache);
    normalized = cc->EvalMult(normalized, 1.0 / p.range);
    if (options.diagnostics) result.normalized = normalized;
    finishStage("layout", normalized);

    const std::vector<double> g3{0, 4589.0/1024, 0, -16577.0/1024, 0, 25614.0/1024, 0, -12860.0/1024};
    const std::vector<double> f3{0, 35.0/16, 0, -35.0/16, 0, 21.0/16, 0, -5.0/16};
    const std::vector<double> f3Final{0.5, 35.0/32, 0, -35.0/32, 0, 21.0/32, 0, -5.0/32};
    auto indicators = normalized;
    for (size_t k = 0; k < options.dg + options.df; ++k) {
        if (k < options.dg) indicators = evaluatePolynomial(cc, indicators, g3, options.poly, sharedRescale, sharedPowers);
        else if (k + 1 == options.dg + options.df) indicators = evaluatePolynomial(cc, indicators, f3Final, options.poly, sharedRescale, sharedPowers);
        else indicators = evaluatePolynomial(cc, indicators, f3, options.poly, sharedRescale, sharedPowers);
        if (options.progress)
            emit("\"record\":\"progress\"," + queryFields + ",\"stage\":\"comparison\",\"composition\":" +
                 std::to_string(k + 1) + ",\"level\":" + std::to_string(indicators->GetLevel()) +
                 ",\"noise_scale_degree\":" + std::to_string(indicators->GetNoiseScaleDeg()) +
                 ",\"effective_depth\":" + std::to_string(effectiveDepth(indicators)));
    }
    if (options.diagnostics) result.indicators = indicators;
    finishStage("comparison", indicators);

    auto products = indicators;
    for (size_t s = 1; s < p.n; s *= 2)
        products = cc->EvalMult(products, cc->EvalRotate(products, static_cast<int32_t>(s)));
    if (options.diagnostics) result.products = products;
    finishStage("product", products);

    auto output = multiplyPlain(cc, products, p.idMask, p.batch, cache);
    // Sum the whole declared batch so every slot first contains the same scalar.
    for (size_t s = 1; s < p.batch; s *= 2)
        output = cc->EvalAdd(output, cc->EvalRotate(output, static_cast<int32_t>(s)));
    output = multiplyPlain(cc, output, p.outputMask, p.batch, cache);
    result.output = output;
    finishStage("output", output);
    result.total = seconds(begin);
    return result;
}

std::vector<std::complex<double>> decryptSlots(const Context& cc, const PrivateKey<DCRTPoly>& key,
                                             const Ct& ct, size_t count) {
    Plaintext plaintext;
    cc->Decrypt(key, ct, &plaintext);
    plaintext->SetLength(count);
    return plaintext->GetCKKSPackedValue();
}

void diagnostic(const Context& cc, const PrivateKey<DCRTPoly>& key, const Evaluation& eval,
                const PublicPlan& p, const Fixture& f, const Query& q, const std::string& fields) {
    auto score = decryptSlots(cc, key, eval.score, p.batch);
    auto normalized = decryptSlots(cc, key, eval.normalized, p.batch);
    auto indicators = decryptSlots(cc, key, eval.indicators, p.batch);
    auto products = decryptSlots(cc, key, eval.products, p.batch);
    double scoreError = 0, layoutError = 0, indicatorError = 0, productError = 0;
    double scoreImag = 0, layoutImag = 0, indicatorImag = 0, productImag = 0;
    double argumentAbs = 0, expectedArgumentAbs = 0;
    bool finite = true;
    auto observe = [&](std::complex<double> value, double expected, double& maxError, double& maxImag) {
        bool valueFinite = std::isfinite(value.real()) && std::isfinite(value.imag());
        finite = finite && valueFinite;
        if (valueFinite) {
            maxError = std::max(maxError, std::abs(value - expected));
            maxImag = std::max(maxImag, std::abs(value.imag()));
        } else {
            maxError = std::numeric_limits<double>::infinity();
            maxImag = std::numeric_limits<double>::infinity();
        }
    };
    for (size_t i = 0; i < p.n; ++i) {
        observe(score[i * p.width], static_cast<double>(q.scores[i]), scoreError, scoreImag);
        bool rowPass = true;
        for (size_t j = 0; j < p.n; ++j) {
            double difference = i == j ? f.thresholds[i] + 0.5 - q.scores[i] :
                static_cast<double>(q.scores[j] - q.scores[i]) + (i < j ? 0.5 : -0.5);
            double expected = difference > 0 ? 1 : 0;
            rowPass = rowPass && expected == 1;
            size_t slot = i * p.n + j;
            observe(normalized[slot], difference / p.range, layoutError, layoutImag);
            observe(indicators[slot], expected, indicatorError, indicatorImag);
            double magnitude = std::abs(normalized[slot]);
            argumentAbs = std::isfinite(magnitude) ? std::max(argumentAbs, magnitude) : std::numeric_limits<double>::infinity();
            expectedArgumentAbs = std::max(expectedArgumentAbs, std::abs(difference / p.range));
        }
        observe(products[i * p.n], rowPass ? 1.0 : 0.0, productError, productImag);
    }
    emit("\"record\":\"diagnostic\"," + fields + ",\"after_query_timer\":true,\"all_finite\":" +
         (finite ? "true" : "false") + ",\"decoder_type\":\"REAL\",\"raw_complex_errors_observed\":false" +
         ",\"epsilon_conditional_bound_certified\":false" +
         ",\"error_metric\":\"complex_absolute_on_REAL_decoder_output\",\"max_score_error\":" + number(scoreError) +
         ",\"max_normalized_layout_error\":" + number(layoutError) + ",\"max_indicator_error\":" +
         number(indicatorError) + ",\"max_product_error\":" + number(productError) +
         ",\"max_score_imaginary\":" + number(scoreImag) + ",\"max_normalized_imaginary\":" + number(layoutImag) +
         ",\"max_indicator_imaginary\":" + number(indicatorImag) + ",\"max_product_imaginary\":" + number(productImag) +
         ",\"max_normalized_argument_abs\":" + number(argumentAbs) +
         ",\"max_expected_normalized_argument_abs\":" + number(expectedArgumentAbs) +
         ",\"max_layout_error_score_units\":" + number(layoutError * p.range) +
         ",\"public_normalized_argument_bound\":" + number((f.publicComparisonBound + 0.5) / p.range) +
         ",\"normalized_arguments_within_unit_disk\":" + (argumentAbs <= 1.0 ? "true" : "false"));
}

} // namespace

int main(int argc, char** argv) {
    try {
        Options options = parseOptions(argc, argv);
        std::vector<Fixture> fixtures;
        for (const auto& path : options.paths) fixtures.push_back(loadFixture(path, options));
        size_t n = fixtures.front().n;
        for (const auto& fixture : fixtures) if (fixture.n != n) throw std::runtime_error("All fixtures in one key process must have the same N");
        size_t batch = std::max(size_t(512), n * n);
        size_t totalQueries = 0;
        for (const auto& fixture : fixtures) totalQueries += fixture.queries.size();
        if (!totalQueries) throw std::runtime_error("No queries selected");
        if (!options.depth) {
            size_t polynomialDepth = options.poly == "stock" ? 4 : 3;
            options.depth = polynomialDepth * (options.dg + options.df) + log2Exact(n) + 9;
        }
#ifdef _OPENMP
        omp_set_dynamic(0);
        omp_set_num_threads(static_cast<int>(options.threads));
        int actualThreads = omp_get_max_threads();
#else
        int actualThreads = 1;
        if (options.threads != 1) throw std::runtime_error("Requested multiple threads but this harness has no OpenMP");
#endif
        emit("\"record\":\"begin\",\"n\":" + std::to_string(n) + ",\"batch\":" + std::to_string(batch) +
             ",\"dg\":" + std::to_string(options.dg) + ",\"df\":" + std::to_string(options.df) +
             ",\"depth\":" + std::to_string(options.depth) + ",\"threads\":" + std::to_string(actualThreads) +
             ",\"poly\":" + jsonQuote(options.poly) +
             ",\"runtime\":" + jsonQuote(options.runtime) +
             ",\"runtime_reference\":" + jsonQuote(options.runtimeReference) +
             ",\"paired_runtime\":" + (options.pairedRuntime ? "true" : "false") +
             ",\"cache_public\":" + (options.cachePublic ? "true" : "false") +
             ",\"large_digits\":" + std::to_string(options.largeDigits) +
             ",\"progress_during_query\":" + (options.progress ? "true" : "false"));
        auto start = Clock::now();
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecurityLevel(HEStd_128_classic);
        parameters.SetSecretKeyDist(UNIFORM_TERNARY);
        parameters.SetMultiplicativeDepth(static_cast<uint32_t>(options.depth));
        parameters.SetScalingModSize(static_cast<uint32_t>(options.scaleBits));
        parameters.SetFirstModSize(static_cast<uint32_t>(options.firstBits));
        parameters.SetScalingTechnique(FLEXIBLEAUTO);
        parameters.SetKeySwitchTechnique(HYBRID);
        parameters.SetNumLargeDigits(static_cast<uint32_t>(options.largeDigits));
        // Preserve the stock decoder policy. REAL decoding projects away imaginary
        // components, so decoded-imaginary diagnostics are not raw CKKS noise probes.
        parameters.SetCKKSDataType(REAL);
        parameters.SetBatchSize(static_cast<uint32_t>(batch));
        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE); cc->Enable(ADVANCEDSHE);
        auto cryptoParameters = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
        if (!cryptoParameters || !cryptoParameters->GetParamsP() || !cryptoParameters->GetParamsQP())
            throw std::runtime_error("Expected CKKS HYBRID Q/P parameter tables");
        if (cryptoParameters->GetStdLevel() != HEStd_128_classic)
            throw std::runtime_error("Effective security level is not HEStd_128_classic");
        emit("\"record\":\"setup\",\"phase\":\"context\",\"seconds\":" + number(seconds(start)) +
             ",\"security\":\"HEStd_128_classic\",\"ring_dimension\":" + std::to_string(cc->GetRingDimension()) +
             ",\"total_q_bits\":" + std::to_string(cc->GetModulus().GetLengthForBase(2)) +
             ",\"q_bits\":" + std::to_string(cryptoParameters->GetElementParams()->GetModulus().GetMSB()) +
             ",\"p_bits\":" + std::to_string(cryptoParameters->GetParamsP()->GetModulus().GetMSB()) +
             ",\"qp_bits\":" + std::to_string(cryptoParameters->GetParamsQP()->GetModulus().GetMSB()) +
             ",\"q_limb_count\":" + std::to_string(cryptoParameters->GetElementParams()->GetParams().size()) +
             ",\"p_limb_count\":" + std::to_string(cryptoParameters->GetParamsP()->GetParams().size()) +
             ",\"num_part_q\":" + std::to_string(cryptoParameters->GetNumPartQ()) +
             ",\"num_per_part_q\":" + std::to_string(cryptoParameters->GetNumPerPartQ()) +
             ",\"large_digits\":" + std::to_string(options.largeDigits) +
             ",\"poly\":" + jsonQuote(options.poly) + ",\"key_switch\":\"HYBRID\",\"ring_auto\":true" +
             ",\"batch\":" + std::to_string(batch) + ",\"scale_bits\":" + std::to_string(options.scaleBits) +
             ",\"first_bits\":" + std::to_string(options.firstBits) +
             ",\"decoder_type\":\"REAL\",\"raw_complex_errors_observed\":false" +
             ",\"epsilon_conditional_bound_certified\":false,\"bootstrap\":false");
        start = Clock::now();
        auto keys = cc->KeyGen();
        emit("\"record\":\"setup\",\"phase\":\"keygen\",\"seconds\":" + number(seconds(start)));
        start = Clock::now();
        cc->EvalMultKeyGen(keys.secretKey);
        emit("\"record\":\"setup\",\"phase\":\"multiplication_keys\",\"seconds\":" + number(seconds(start)));
        std::vector<PublicPlan> plans;
        for (const auto& fixture : fixtures) plans.emplace_back(fixture, batch);
        std::vector<std::unique_ptr<const PublicPlaintexts>> publicPlaintexts(fixtures.size());
        if (options.cachePublic) {
            for (size_t f = 0; f < fixtures.size(); ++f) {
                start = Clock::now();
                publicPlaintexts[f] = std::make_unique<const PublicPlaintexts>(cc, plans[f], options);
                emit("\"record\":\"setup\",\"phase\":\"public_plaintexts\",\"fixture\":" +
                     jsonQuote(fixtures[f].path) + ",\"seconds\":" + number(seconds(start)) +
                     ",\"plaintext_count\":" + std::to_string(publicPlaintexts[f]->size()) +
                     ",\"cache_public\":true");
            }
        }
        auto rotationList = rotations(plans.front());
        start = Clock::now();
        cc->EvalRotateKeyGen(keys.secretKey, rotationList);
        emit("\"record\":\"setup\",\"phase\":\"rotation_keys\",\"seconds\":" + number(seconds(start)) +
             ",\"rotation_key_count\":" + std::to_string(rotationList.size()));
        for (const auto& fixture : fixtures)
            emit("\"record\":\"fixture\",\"path\":" + jsonQuote(fixture.path) + ",\"n\":" + std::to_string(n) +
                 ",\"public_score_lower\":" + std::to_string(fixture.publicLower) + ",\"public_score_upper\":" +
                 std::to_string(fixture.publicUpper) + ",\"normalization_range\":" + number(fixture.range) +
                 ",\"public_comparison_bound\":" + number(fixture.publicComparisonBound) +
                 ",\"q_max\":" + std::to_string(options.qMax) + ",\"norm2_max\":" + std::to_string(options.norm2Max));

        size_t sequence = 0, failures = 0;
        for (size_t round = 0; round < options.warmups + options.repeats; ++round) {
            bool warmup = round < options.warmups;
            size_t selected = 0;
            for (size_t f = 0; f < fixtures.size(); ++f) {
                for (const auto& query : fixtures[f].queries) {
                    if (options.queryLimit && selected >= options.queryLimit) break;
                    ++selected;
                    std::string baseFields = "\"sequence\":" + std::to_string(sequence++) + ",\"fixture\":" + jsonQuote(fixtures[f].path) +
                        ",\"label\":" + jsonQuote(query.label) + ",\"n\":" + std::to_string(n) +
                        ",\"poly\":" + jsonQuote(options.poly) +
                        ",\"round\":" + std::to_string(round) + ",\"warmup\":" + (warmup ? "true" : "false");
                    std::vector<double> packedQuery(batch);
                    for (size_t j = 0; j < batch; ++j) packedQuery[j] = static_cast<double>(query.q[j % 512]);
                    start = Clock::now();
                    auto plaintext = cc->MakeCKKSPackedPlaintext(packedQuery, 1, 0, nullptr, static_cast<uint32_t>(batch));
                    auto encryptedQuery = cc->Encrypt(keys.publicKey, plaintext);
                    double encryptionSeconds = seconds(start);
                    const bool paired = options.pairedCache || options.pairedRuntime;
                    // Snapshot and all equality checks are outside both query clocks.
                    auto originalQuery = paired ? encryptedQuery->Clone() : nullptr;
                    struct Arm { bool cache; std::string runtime; };
                    std::vector<Arm> arms{{options.cachePublic, options.runtime}};
                    if (options.pairedCache) {
                        bool cachedFirst = (round + f) % 2 == 1;
                        arms = {{cachedFirst, options.runtime}, {!cachedFirst, options.runtime}};
                    } else if (options.pairedRuntime) {
                        const Arm baseline{options.cachePublic, options.runtimeReference};
                        const Arm candidate{options.cachePublic, options.runtime};
                        arms = {baseline, candidate};
                        if ((round + f) % 2 == 1) std::reverse(arms.begin(), arms.end());
                    }
                    std::vector<Evaluation> evaluations;
                    std::vector<std::string> armFields;
                    evaluations.reserve(arms.size());
                    armFields.reserve(arms.size());
                    for (const auto& arm : arms) {
                        armFields.push_back(baseFields + ",\"cache_public\":" + (arm.cache ? "true" : "false") +
                            ",\"paired_cache\":" + (options.pairedCache ? "true" : "false") +
                            ",\"runtime\":" + jsonQuote(arm.runtime) +
                            ",\"paired_runtime\":" + (options.pairedRuntime ? "true" : "false"));
                        if (!paired)
                            emit("\"record\":\"query_start\"," + armFields.back() + ",\"expected_id\":" +
                                 std::to_string(query.expected) + ",\"encryption_seconds\":" + number(encryptionSeconds));
                        Options armOptions = options;
                        armOptions.runtime = arm.runtime;
                        evaluations.push_back(evaluate(cc, encryptedQuery, plans[f], armOptions, armFields.back(),
                                                       arm.cache ? publicPlaintexts[f].get() : nullptr));
                        if (paired && !sameCiphertext(encryptedQuery, originalQuery))
                            throw std::runtime_error("Paired evaluation mutated the encrypted query");
                    }
                    if (paired) {
                        auto requireEqual = [&](const Ct& first, const Ct& second, const std::string& stage) {
                            const bool equal = sameCiphertext(first, second);
                            emit("\"record\":\"equality\"," + baseFields + ",\"stage\":" + jsonQuote(stage) +
                                 ",\"runtime_first\":" + jsonQuote(arms[0].runtime) +
                                 ",\"runtime_second\":" + jsonQuote(arms[1].runtime) +
                                 ",\"after_query_timer\":true,\"input_unchanged\":true,\"ciphertext_equal\":" +
                                 (equal ? "true" : "false"));
                            if (!equal) throw std::runtime_error("Paired ciphertext differs at " + stage);
                        };
                        if (options.diagnostics) {
                            requireEqual(evaluations[0].score, evaluations[1].score, "score");
                            requireEqual(evaluations[0].normalized, evaluations[1].normalized, "layout");
                            requireEqual(evaluations[0].indicators, evaluations[1].indicators, "comparison");
                            requireEqual(evaluations[0].products, evaluations[1].products, "product");
                        }
                        requireEqual(evaluations[0].output, evaluations[1].output, "output");
                    }
                    for (size_t arm = 0; arm < evaluations.size(); ++arm) {
                        const auto& fields = armFields[arm];
                        const auto& evaluated = evaluations[arm];
                        if (paired)
                            emit("\"record\":\"query_start\"," + fields + ",\"expected_id\":" + std::to_string(query.expected) +
                                 ",\"encryption_seconds\":" + number(encryptionSeconds) + ",\"after_query_timer\":true");
                        if (!options.progress)
                            for (const auto& stage : evaluated.stages) emitStage(stage, fields, true);
                        start = Clock::now();
                        auto output = decryptSlots(cc, keys.secretKey, evaluated.output, batch);
                        double decryptionSeconds = seconds(start);
                        if (output.size() != batch) throw std::runtime_error("Unexpected decoded slot count");
                        double scalar = output[0].real(), maxOther = 0, maxImag = 0;
                        bool finite = true;
                        for (size_t j = 0; j < batch; ++j) {
                            finite = finite && std::isfinite(output[j].real()) && std::isfinite(output[j].imag());
                            if (j) maxOther = std::max(maxOther, std::abs(output[j].real()));
                            maxImag = std::max(maxImag, std::abs(output[j].imag()));
                        }
                        double error = std::abs(scalar - static_cast<double>(query.expected));
                        bool inRange = std::isfinite(scalar) && scalar > -0.5 && scalar < static_cast<double>(n) + 0.5;
                        long decoded = inRange ? std::lround(scalar) : -1;
                        bool pass = finite && inRange && decoded >= 0 && decoded <= static_cast<long>(n) &&
                            decoded == static_cast<long>(query.expected) && error < 0.5 && maxOther < 0.5 && maxImag < 0.5;
                        if (!pass) ++failures;
                        emit("\"record\":\"query\"," + fields + ",\"expected_id\":" + std::to_string(query.expected) +
                             ",\"decoded_id\":" + std::to_string(decoded) + ",\"scalar\":" + number(scalar) +
                             ",\"absolute_error\":" + number(error) + ",\"max_other_slots\":" + number(maxOther) +
                             ",\"max_imaginary\":" + number(maxImag) + ",\"all_slots_finite\":" + (finite ? "true" : "false") +
                             ",\"decoder_type\":\"REAL\",\"raw_complex_errors_observed\":false" +
                             ",\"epsilon_conditional_bound_certified\":false" +
                             ",\"paired_ciphertext_equal_so_far\":" + (paired ? "true" : "null") +
                             ",\"query_seconds\":" + number(evaluated.total) + ",\"decryption_seconds\":" + number(decryptionSeconds) +
                             ",\"pass\":" + (pass ? "true" : "false"));
                        if (options.diagnostics) diagnostic(cc, keys.secretKey, evaluated, plans[f], fixtures[f], query, fields);
                    }
                }
            }
        }
        emit("\"record\":\"complete\",\"queries\":" + std::to_string(sequence) +
             ",\"evaluations\":" + std::to_string(sequence * ((options.pairedCache || options.pairedRuntime) ? 2 : 1)) + ",\"failures\":" +
             std::to_string(failures) + ",\"pass\":" + (failures ? "false" : "true"));
        return failures ? 2 : 0;
    } catch (const std::exception& error) {
        emit("\"record\":\"error\",\"message\":" + jsonQuote(error.what()));
        return 1;
    }
}
