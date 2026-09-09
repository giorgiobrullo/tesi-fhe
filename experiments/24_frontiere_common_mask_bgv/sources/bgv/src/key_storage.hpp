// Included after common.hpp and identity.hpp in the translation unit's namespace.
// Inspect public matrix shapes and stream the public-key serialization once.
class PublicKeyDigestBuffer final : public std::streambuf {
  CC_SHA256_CTX sha_{};
  std::uint64_t fnv_ = UINT64_C(14695981039346656037);
  std::uint64_t bytes_ = 0;
  bool finished_ = false;

  void append(const char* data, std::size_t count) {
    need(!finished_, "public key digest already finalized");
    need(count <= std::numeric_limits<std::uint64_t>::max() - bytes_,
         "public key serialized byte count overflow");
    const std::size_t limit = std::numeric_limits<CC_LONG>::max();
    std::size_t offset = 0;
    while (offset < count) {
      const std::size_t remaining = count - offset;
      const std::size_t chunk = remaining < limit ? remaining : limit;
      need(CC_SHA256_Update(&sha_, data + offset, static_cast<CC_LONG>(chunk)) == 1,
           "public key SHA256 update failed");
      offset += chunk;
    }
    for (std::size_t index = 0; index < count; ++index) {
      fnv_ ^= static_cast<unsigned char>(data[index]);
      fnv_ *= UINT64_C(1099511628211);
    }
    bytes_ += static_cast<std::uint64_t>(count);
  }

protected:
  int_type overflow(int_type value) override {
    if (traits_type::eq_int_type(value, traits_type::eof()))
      return traits_type::not_eof(value);
    const char byte = traits_type::to_char_type(value);
    append(&byte, 1);
    return value;
  }

  std::streamsize xsputn(const char* data, std::streamsize count) override {
    need(count >= 0, "negative public key serialization length");
    append(data, static_cast<std::size_t>(count));
    return count;
  }

public:
  PublicKeyDigestBuffer() {
    need(CC_SHA256_Init(&sha_) == 1, "public key SHA256 initialization failed");
  }
  PublicKeyDigestBuffer(const PublicKeyDigestBuffer&) = delete;
  PublicKeyDigestBuffer& operator=(const PublicKeyDigestBuffer&) = delete;

  NativeJson finish() {
    need(!finished_, "public key digest already finalized");
    need(bytes_ > 0, "empty public key serialization");
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    need(CC_SHA256_Final(digest, &sha_) == 1, "public key SHA256 finalization failed");
    finished_ = true;
    std::ostringstream encoded;
    encoded << std::hex << std::setfill('0');
    for (unsigned char byte : digest)
      encoded << std::setw(2) << static_cast<unsigned>(byte);
    return NativeJson{{"public_key_fnv1a64", hex(fnv_)},
                      {"public_key_sha256", encoded.str()},
                      {"public_key_serialized_bytes", bytes_}};
  }
};

NativeJson observe_public_key_storage(
    const helib::PubKey& public_key,
    const helib::Context& context,
    const std::vector<long>& expected_exponents) {
  need(&public_key.getContext() == &context, "public key context identity");
  need(context.getPhiM() == 65536 && sizeof(long) == 8, "public key residue geometry");
  need(expected_exponents.size() == 69, "public key direct exponent count");
  for (std::size_t index = 0; index < expected_exponents.size(); ++index) {
    need(expected_exponents[index] > 1 && expected_exponents[index] < context.getM(),
         "public key nonidentity exponent range");
    if (index > 0)
      need(expected_exponents[index - 1] < expected_exponents[index],
           "public key sorted distinct exponents");
  }

  const auto indices = [](const helib::IndexSet& set) {
    std::vector<long> result;
    for (long index : set) result.push_back(index);
    return result;
  };
  const auto ciphertext_indices = indices(context.getCtxtPrimes());
  const auto special_indices = indices(context.getSpecialPrimes());
  const auto full_indices = indices(context.fullPrimes());
  std::vector<long> expected_ciphertext, expected_special, expected_full;
  for (long index = 6; index <= 26; ++index) expected_ciphertext.push_back(index);
  for (long index = 27; index <= 33; ++index) expected_special.push_back(index);
  for (long index = 6; index <= 33; ++index) expected_full.push_back(index);
  need(ciphertext_indices == expected_ciphertext && special_indices == expected_special
           && full_indices == expected_full,
       "public key selected context prime sets");
  const auto& digits = context.getDigits();
  need(digits.size() == 3, "public key digit count");
  NativeJson digit_indices = NativeJson::array();
  for (std::size_t digit = 0; digit < digits.size(); ++digit) {
    const auto actual = indices(digits[digit]);
    std::vector<long> expected;
    for (long offset = 0; offset < 7; ++offset)
      expected.push_back(6 + 7 * static_cast<long>(digit) + offset);
    need(actual == expected, "public key exact seven-prime digit");
    digit_indices.push_back(actual);
  }

  const auto& matrices = public_key.keySWlist();
  need(matrices.size() == 71, "public key matrix count");
  NativeJson observed_matrices = NativeJson::array();
  std::uint64_t total_columns = 0, total_rows = 0, total_words = 0;
  for (std::size_t index = 0; index < matrices.size(); ++index) {
    const auto& matrix = matrices[index];
    const long power_s = matrix.fromKey.getPowerOfS();
    const long power_x = matrix.fromKey.getPowerOfX();
    const long from_id = matrix.fromKey.getSecretKeyID();
    const long wanted_s = index < 2 ? 2 + static_cast<long>(index) : 1;
    const long wanted_x = index < 2 ? 1 : expected_exponents[index - 2];
    need(power_s == wanted_s && power_x == wanted_x && from_id == 0
             && matrix.toKeyID == 0 && matrix.ptxtSpace == 8191,
         "public key exact ordered matrix handle");
    need(matrix.NumCols() == 3 && matrix.b.size() == 3, "public key matrix column count");
    NativeJson columns = NativeJson::array();
    for (std::size_t column = 0; column < matrix.b.size(); ++column) {
      const auto& b = matrix.b[column];
      need(&b.getContext() == &context, "public key column context identity");
      const auto actual_indices = indices(b.getIndexSet());
      need(actual_indices == full_indices, "public key column full prime set");
      std::vector<long> row_lengths;
      std::uint64_t column_words = 0;
      for (long prime : actual_indices) {
        const long length = b.getMap()[prime].length();
        need(length == 65536, "public key actual residue row length");
        row_lengths.push_back(length);
        column_words += static_cast<std::uint64_t>(length);
      }
      columns.push_back(NativeJson{{"index", column},
          {"prime_indices", actual_indices}, {"row_lengths", row_lengths},
          {"residue_rows", actual_indices.size()}, {"residue_words", column_words},
          {"residue_payload_bytes", column_words * sizeof(long)}});
      ++total_columns;
      total_rows += static_cast<std::uint64_t>(actual_indices.size());
      total_words += column_words;
    }
    observed_matrices.push_back(NativeJson{{"index", index}, {"from_s_power", power_s},
        {"from_x_power", power_x}, {"from_key_id", from_id}, {"to_key_id", matrix.toKeyID},
        {"plaintext_space", matrix.ptxtSpace}, {"num_columns_api", matrix.NumCols()},
        {"columns", columns}});
  }
  const std::uint64_t payload_bytes = total_words * sizeof(long);
  need(total_columns == 213 && total_rows == 5964 && total_words == 390856704
           && payload_bytes == UINT64_C(3126853632),
       "public key actual b residue totals");

  PublicKeyDigestBuffer buffer;
  std::ostream stream(&buffer);
  // This explicit base-class static type selects PubKey::writeTo, never SecKey's overload.
  const helib::PubKey& serializable = public_key;
  serializable.writeTo(stream);
  stream.flush();
  need(stream.good(), "public key streaming serialization failed");
  NativeJson result = buffer.finish();
  result["key_storage"] = NativeJson{
      {"schema", "bgv-larger-ring-public-key-storage.v1"},
      {"sizeof_long", sizeof(long)}, {"phi_m", context.getPhiM()},
      {"ciphertext_prime_indices", ciphertext_indices},
      {"special_prime_indices", special_indices}, {"full_prime_indices", full_indices},
      {"digit_prime_indices", digit_indices}, {"matrix_count", matrices.size()},
      {"matrices", observed_matrices}, {"stored_b_columns", total_columns},
      {"stored_b_residue_rows", total_rows}, {"stored_b_residue_words", total_words},
      {"stored_b_residue_payload_bytes", payload_bytes},
      {"residue_payload_is_serialized_size", false}, {"residue_payload_is_rss", false},
      {"peak_memory_bound", false}, {"secret_values_observed", false},
      {"secret_serialized", false}, {"public_encryption_key_residue_shape_observed", false},
      {"public_key_serialization_passes", 1}, {"full_serialization_buffered", false}};
  return result;
}
