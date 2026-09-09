// One client observation after the entire server graph. No copy returns to server code.
struct TerminalDiagnostic {std::string status;long decrypt_attempts=0,successful_decryptions=0;bool semantic_pass=false;};
TerminalDiagnostic observe_terminal(Log& log,const helib::Ctxt& original,
                                    const helib::SecKey& key,const std::vector<long>& expected) {
  TerminalDiagnostic result;bool copy_validated=false;
  const auto counters_before=timer_values();const auto before=binary(original);const auto before_sha=sha256(before);
  try {
    need(expected.size()==kSlots,"complete final oracle");
    const auto before_json=serialized_json(original);helib::Ctxt copy(original);
    need(binary(copy)==before,"observer initial full copy equality");
    need(original.getNoiseBound()>=0,"nonnegative final noise bound");
    const bool applied=original.getNoiseBound()>0,needed=!original.isCorrect();
    if(applied)copy.bumpNoiseBound(0.0); // Terminal copy only; original arithmetic is already finished.
    const auto copy_json=serialized_json(copy);auto protected_original=before_json,protected_copy=copy_json;
    const bool changed=protected_original.at("content").at("noiseBound")!=protected_copy.at("content").at("noiseBound");
    need(changed==applied,"exact copied bound change policy");
    need(protected_original.at("content").erase("noiseBound")==1
         &&protected_copy.at("content").erase("noiseBound")==1,"single exact noiseBound path");
    need(protected_original==protected_copy&&copy.getNoiseBound()==0,"all other JSON structure equal");
    if(!applied)need(binary(copy)==before&&copy_json==before_json,"zero-bound copy entirely unchanged");
    need(copy.isCorrect(),"diagnostic copy admission");copy_validated=true;
    const auto q=original.getContext().productOfPrimes(original.getPrimeSet());
    const long factor=int_factor(original),ptxt_space=original.getPtxtSpace();need(ptxt_space==kP,"fixed final plaintext space");
    const long denominator=NTL::MulMod(NTL::rem(q,kP),factor,kP);need(denominator!=0,"invertible BGV normalization");
    const long normalization=NTL::InvMod(denominator,kP);NTL::ZZX plaintext,f;
    ++result.decrypt_attempts;key.Decrypt(plaintext,copy,f);++result.successful_decryptions;
    need(NTL::deg(f)<65536&&NTL::deg(plaintext)<65536,"padded diagnostic polynomial geometry");
    std::vector<long> plaintext_coefficients;plaintext_coefficients.reserve(65536);bool normalized=true;
    for(long i=0;i<65536;++i) {
      const long actual=NTL::conv<long>(NTL::coeff(plaintext,i));
      long reduced=NTL::rem(NTL::coeff(f,i),kP);if(reduced<0)reduced+=kP;
      normalized &= actual==NTL::MulMod(reduced,normalization,kP);
      need(actual>=0&&actual<kP,"normalized plaintext coefficient range");plaintext_coefficients.push_back(actual);
    }
    need(normalized,"BGV f-to-plaintext normalization identity");
    std::vector<NTL::ZZX> slots;key.getContext().getEA().decode(slots,plaintext);need(slots.size()==kSlots,"full final decoded slots");
    Slots values;values.reserve(kSlots);long nonconstant=0,mismatches=0;NativeJson slot_polynomials=NativeJson::array();
    for(long slot=0;slot<kSlots;++slot) {
      need(NTL::deg(slots[slot])<2,"extension-degree slot geometry");
      const long constant=producer::residue(NTL::conv<long>(NTL::coeff(slots[slot],0)));
      const long linear=producer::residue(NTL::conv<long>(NTL::coeff(slots[slot],1)));
      const bool scalar=linear==0;nonconstant+=!scalar;
      const long value=scalar?constant:-1;values.push_back(value);mismatches+=value!=expected[slot];
      slot_polynomials.push_back(NativeJson::array({constant,linear}));
    }
    const auto norm=helib::embeddingLargestCoeff(f,key.getContext().getZMStar());
    need(norm>=0,"nonnegative reduced representative norm");
    const auto after=binary(original);const auto counters_after=timer_values();
    need(after==before&&sha256(after)==before_sha,"original full binary unchanged after observation");
    need(serialized_json(original)==before_json,"original full JSON unchanged after observation");
    need(counters_after==counters_before,"no server work during terminal observer");
    result.status="OBSERVED";result.semantic_pass=!mismatches&&!nonconstant;
    Json row;row.add("type","terminal_observation").add("stage","native/final").add("status",result.status)
        .add("decrypt_attempts",result.decrypt_attempts).add("successful_decryptions",result.successful_decryptions)
        .add("original_before_sha256",before_sha).add("original_after_sha256",sha256(after))
        .add("original_before_binary_hex",byte_hex(before)).add("original_after_binary_hex",byte_hex(after))
        .add("copy_invariants_validated",true).add("copy_initial_binary_equal",true).add("copy_only_noiseBound_changed",changed)
        .add("admission_bypass_applied",applied).add("admission_bypass_needed",needed).add("original_unchanged",true)
        .add("q_decimal",decimal(q)).add("intFactor",factor).add("ptxtSpace",ptxt_space)
        .add("normalization_factor",normalization).add("normalization_pass",normalized)
        .add("plaintext_coefficients",plaintext_coefficients).add("values",values).add("expected_slots",expected)
        .add("checked_slots",kSlots).add("nonconstant_slots",nonconstant).add("mismatches",mismatches)
        .add("terminal_semantic_pass",result.semantic_pass)
        .add("historical_unwrapped_noise",false).add("server_result_promoted",false);
    extended_number(row,"reduced_premodp_embedding_norm",norm);
    field(row,"original_json",before_json);field(row,"copy_json",copy_json);
    field(row,"premodp_coefficients_decimal",polynomial_decimal(f));field(row,"slot_polynomials",slot_polynomials);
    field(row,"server_counters_before",counters_before);field(row,"server_counters_after",counters_after);log.emit(row);
  } catch(const std::exception& error) {
    result.status="DIAGNOSTIC_INCOMPLETE";const auto after=binary(original);const auto counters_after=timer_values();
    Json row;row.add("type","terminal_observation").add("stage","native/final").add("status",result.status)
        .add("error",error.what()).add("copy_invariants_validated",copy_validated).add("decrypt_attempts",result.decrypt_attempts)
        .add("successful_decryptions",result.successful_decryptions).add("original_before_sha256",before_sha)
        .add("original_after_sha256",sha256(after)).add("original_before_binary_hex",byte_hex(before))
        .add("original_after_binary_hex",byte_hex(after)).add("original_unchanged",before==after).add("server_result_promoted",false);
    field(row,"terminal_semantic_pass",nullptr);field(row,"server_counters_before",counters_before);
    field(row,"server_counters_after",counters_after);log.emit(row);
  }
  return result;
}
