// Public plaintext setup in the same later-used context, before any key or ciphertext.
// Included inside the caller's namespace after common, producer diagnostics and identity.
std::string public_encoding_integer_sha256(const std::vector<long>& values,unsigned bytes_per_word)
{
  static_assert(std::numeric_limits<unsigned char>::max()==255,"eight-bit public hash bytes");
  need(bytes_per_word==2||bytes_per_word==8,"public integer hash width");
  std::string bytes;bytes.reserve(values.size()*bytes_per_word);
  for(long value:values) {
    const auto word=static_cast<std::uint64_t>(value);
    for(unsigned byte=0;byte<bytes_per_word;++byte)
      bytes.push_back(static_cast<char>((word>>(8*byte))&255));
  }
  return sha256(bytes);
}

NativeJson prepare_public_encodings(Log& log,const helib::Context& context,
                                    const NativeJson& source_slots)
{
  constexpr long phi=65536,slot_count=32768,p=8191;
  const std::array<std::string,11> names{
      "producer/template_product","producer/periodic_scores",
      "producer/z_mask_0","producer/z_mask_1","producer/z_mask_2","producer/z_mask_3",
      "producer/z_mask_4","producer/z_mask_5","producer/z_mask_6","producer/z_mask_7",
      "producer/output_z"};
  need(source_slots.is_object()&&source_slots.size()==names.size(),"public setup closed vector map");
  for(const auto& name:names) {
    need(source_slots.contains(name),"public setup vector name");
    const auto& values=source_slots.at(name);
    need(values.is_array()&&values.size()==slot_count,"public setup source slot count");
    for(const auto& value:values)
      need(value.is_number_unsigned()&&value.get<std::uint64_t>()<p,"public setup unsigned scalar residue");
  }
  need(hex64(BGV_PUBLIC_SLOTS_SHA256),"public setup source hash");
  need(context.getM()==245760&&context.getP()==p&&context.getR()==1
       &&context.getPhiM()==phi&&kSlots==slot_count,"public setup fixed context");
  const auto& ea=context.getEA();
  need(ea.size()==slot_count,"public setup actual slot count");

  NativeJson entries=NativeJson::object(),pins=NativeJson::object();
  for(const auto& name:names) {
    const auto slots=source_slots.at(name).get<std::vector<long>>();
    const auto poly=producer::encode(ea,slots);
    const long degree=NTL::deg(poly);
    need(degree<phi,"public setup encoded polynomial degree");
    std::vector<long> coefficients(phi);
    long l1=0,max_abs=0;
    for(long i=0;i<phi;++i) {
      const auto& coefficient=NTL::coeff(poly,i);
      need(coefficient>=-4095&&coefficient<=4095,"public setup balanced coefficient");
      const long value=NTL::conv<long>(coefficient);
      coefficients[i]=value;l1+=std::abs(value);max_abs=std::max(max_abs,std::abs(value));
    }
    const double norm=NTL::conv<double>(helib::embeddingLargestCoeff(poly,context.getZMStar()));
    need(std::isfinite(norm)&&norm>0&&norm<=l1*(1+1e-8),"public setup embedding norm");

    // Decode a public polynomial only. Preserve both coordinates of every degree-two slot.
    std::vector<NTL::ZZX> decoded;ea.decode(decoded,poly);
    need(decoded.size()==slot_count,"public setup decoded slot count");
    std::vector<std::array<long,2>> decoded_polynomials;decoded_polynomials.reserve(slot_count);
    long nonconstant=0,mismatches=0;
    const NTL::ZZ modulus=NTL::to_ZZ(p);
    for(long i=0;i<slot_count;++i) {
      const long decoded_degree=NTL::deg(decoded[i]);
      need(decoded_degree<=1,"public setup extension degree");
      const long constant=producer::residue(NTL::conv<long>(NTL::coeff(decoded[i],0)%modulus));
      const long linear=producer::residue(NTL::conv<long>(NTL::coeff(decoded[i],1)%modulus));
      decoded_polynomials.push_back({constant,linear});
      const bool scalar=decoded_degree<=0;
      nonconstant+=!scalar;mismatches+=!scalar||constant!=slots[i];
    }
    need(nonconstant==0&&mismatches==0,"public setup exact scalar roundtrip");
    entries[name]={{"slots",slots},{"coefficients",coefficients},{"degree",degree},
        {"coefficient_l1",l1},{"coefficient_max_abs",max_abs},{"embedding_norm",norm},
        {"slots_u16le_sha256",public_encoding_integer_sha256(slots,2)},
        {"coefficients_i64le_sha256",public_encoding_integer_sha256(coefficients,8)},
        {"slots_fnv1a64",vector_hash(slots)},{"coefficients_fnv1a64",vector_hash(coefficients)},
        {"decoded_slot_polynomials",decoded_polynomials},
        {"public_roundtrip_nonconstant",nonconstant},{"public_roundtrip_mismatches",mismatches},
        {"public_roundtrip_pass",true}};
    pins[name]={{"slots",slots},{"coefficients",coefficients},{"embedding_norm",norm}};
  }

  // Emit only the completed bundle. A failure above leaves the caller's setup exception prefix.
  Json row;row.add("type","public_encoding_setup").add("source_public_slots_sha256",BGV_PUBLIC_SLOTS_SHA256)
      .add("vector_count",11).add("slots_per_vector",slot_count)
      .add("coefficient_words_per_vector",phi).add("decoded_scalar_slots",11*slot_count)
      .add("keygen_attempts",0).add("encryption_attempts",0).add("ciphertext_operations",0);
  field(row,"entries",entries);log.emit(row);
  return pins;
}
