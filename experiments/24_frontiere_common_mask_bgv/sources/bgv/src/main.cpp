#include "producer.hpp"
#include "fixtures.hpp"
#include "consumer_fixtures.hpp"
#include <helib/polyEval.h>
#include "a117_fast_univariate_poly.h"
#include "source_identity.h"
#include "plan_literal.hpp"
#include <helib/debugging.h>
#include <CommonCrypto/CommonDigest.h>
#include "json.hpp"
#include <fstream>
#include <limits>
#include <map>
#include <gmp.h>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <streambuf>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <set>
#include <vector>

namespace {
namespace producer=bgv_n8_score_input;
constexpr long kP=8191,kSlots=32768,kWidth=4096,kBlocks=4;
constexpr const char* kAck="ROOT_EXCLUSIVE_BGV_LARGER_RING_DIRECT_N8";
#include "common.hpp"
#include "extended_observation.hpp"
#include "producer_diagnostics.hpp"
#include "identity.hpp"
#include "direct_polynomial.hpp"
#include "context_geometry.hpp"
#include "key_storage.hpp"
#include "public_encoding_setup.hpp"
#include "consumer.hpp"
#include "oracle.hpp"
#include "terminal_observer.hpp"
#include "stage_schedule.hpp"

struct Ledger {
  producer::Counts producer;
  long comparator_calls=0,comparator_products=0,selector_rotations=0,selector_products=0;
  long selector_support_subtractions=0,selector_scalar_products=0,selector_additions=0;
};
void ledger_fields(Json& row,const Ledger& l) {
  counts(row,l.producer);
  row.add("comparator_calls",l.comparator_calls).add("comparator_products",l.comparator_products)
      .add("selector_rotations",l.selector_rotations).add("selector_products",l.selector_products)
      .add("selector_support_subtractions",l.selector_support_subtractions)
      .add("selector_scalar_products",l.selector_scalar_products).add("selector_additions",l.selector_additions)
      .add("total_rotations",l.producer.rotations+l.selector_rotations)
      .add("total_ciphertext_products",l.comparator_products+l.selector_products)
      .add("total_plaintext_products",l.producer.plaintext_products)
      .add("total_explicit_encrypted_additions",l.producer.encrypted_additions+l.selector_additions)
      .add("total_explicit_public_additions",l.producer.public_additions+l.selector_support_subtractions)
      .add("total_selector_scalar_products",l.selector_scalar_products);
}
#include "trace.hpp"

struct SetupProgress {
  std::string phase="direct_polynomial_setup";
  long context_attempts=0,contexts_constructed=0,public_setup_records=0;
  long keygen_attempts=0,keysets_completed=0,encryption_attempts=0,encryptions_completed=0;
};
void emit_native(Log& log,const NativeJson& value) {
  Json record;
  for(auto it=value.begin();it!=value.end();++it)field(record,it.key().c_str(),it.value());
  log.emit(record);
}
NativeJson context_record(const helib::Context& context,const NativeJson& plan) {
  const auto geometry=larger_context::geometry(context),moduli=larger_context::moduli(context);
  const double actual_bits=larger_context::finite_number(context.logOfProduct(context.getCtxtPrimes())/std::log(2.0));
  const double full_bits=larger_context::finite_number(context.logOfProduct(context.fullPrimes())/std::log(2.0));
  const double security=larger_context::finite_number(context.securityLevel());
  const NativeJson distribution{{"stdev",larger_context::finite_number(NTL::to_double(context.getStdev()))},
      {"hwt",context.getHwt()},{"scale",larger_context::finite_number(context.getScale())}};
  const auto& expected=plan.at("context");
  bool selected=geometry.at("geometry_pass").get<bool>()&&moduli.at("modulus_ledger_pass").get<bool>()
      &&security>=128.0&&std::abs(security-expected.at("expected_security_bits_helib").get<double>())<1e-6
      &&distribution==expected.at("distribution_parameters");
  for(const std::string name:{"small","ciphertext","special","full"}) {
    const auto& actual=moduli.at(name);const auto& wanted=expected.at("exact_actual_modulus_ledgers").at(name);
    selected &= actual.at("indices")==wanted.at("indices")&&actual.at("prime_values_decimal")==wanted.at("prime_values_decimal")
        &&std::abs(actual.at("log2_product").get<double>()-wanted.at("log2_product").get<double>())<=1e-8;
  }
  std::vector<long> all_indices,all_values,ctxt_indices,full_indices,orders,native,generators;
  for(long index:context.allPrimes()){all_indices.push_back(index);all_values.push_back(context.ithPrime(index));}
  for(long index:context.getCtxtPrimes())ctxt_indices.push_back(index);
  for(long index:context.fullPrimes())full_indices.push_back(index);
  const auto& algebra=context.getZMStar();
  for(long i=0;i<algebra.numOfGens();++i){orders.push_back(algebra.OrderOf(i));native.push_back(algebra.SameOrd(i));generators.push_back(algebra.ZmStarGen(i));}
  return NativeJson{{"type","context"},{"p",context.getP()},{"m",context.getM()},{"phi_m",context.getPhiM()},
      {"ord_p",context.getOrdP()},{"requested_bits",1200},{"actual_bits",actual_bits},{"full_bits",full_bits},
      {"reported_security_floor",128},{"security_bits",security},{"orders",orders},{"native_dimensions",native},
      {"generators",generators},{"context_prime_indices",all_indices},{"context_prime_values",all_values},
      {"ctxt_prime_indices",ctxt_indices},{"full_prime_indices",full_indices},{"xdouble_exponent_unit_bits",2*NTL_XD_HBOUND_LOG},
      {"powerful_basis_norm_bound",context.getZMStar().getNormBnd()},
      {"polynomial_basis_norm_bound",context.getZMStar().getPolyNormBnd()},
      {"isCorrect_capacity_threshold",std::log2(context.getZMStar().getNormBnd()/0.48)},
      {"geometry",geometry},{"moduli",moduli},{"distribution_parameters",distribution},{"context_admitted",selected}};
}
void setup_exception(Log& log,const SetupProgress& progress,const std::string& binary,const char* error) {
  emit_native(log,NativeJson{{"type","setup_exception"},{"status","INCOMPLETE"},
      {"source",BGV_SOURCE_ID},{"binary_sha256_claim",binary},{"pid",static_cast<long>(getpid())},
      {"phase",progress.phase},{"error",error},{"context_construction_attempts",progress.context_attempts},
      {"contexts_constructed",progress.contexts_constructed},{"completed_public_setup_records",progress.public_setup_records},
      {"keygen_attempts",progress.keygen_attempts},{"keysets_completed",progress.keysets_completed},
      {"query_encryption_attempts",progress.encryption_attempts},{"query_encryptions_completed",progress.encryptions_completed},
      {"client_decryptions",0},{"terminal_decrypt_attempts",0},{"server_graph_started",false},
      {"terminal_semantic_pass",nullptr},{"server_result_promoted",false}});
}

int run(Log& log,const std::string& binary_claim,SetupProgress& progress) {
  const auto plan=NativeJson::parse(BGV_PLAN_JSON);
  const auto direct=direct_polynomial();
  progress.phase="meta_output";
  Json meta;meta.add("type","meta").add("schema","bgv-larger-ring-direct-n8.v1").add("source",BGV_SOURCE_ID)
      .add("binary_sha256_claim",binary_claim).add("binary_hash_requires_root_binding",true)
      .add("pid",static_cast<long>(getpid())).add("gmp_version",gmp_version)
      .add("slots",kSlots).add("scene_lanes",4).add("coordinates",512).add("candidate_cosets",8)
      .add("active_n",std::vector<long>{8,8,8,4}).add("fresh_keys",1).add("fixtures",4)
      .add("input_interface","one_gallery_independent_packed_query_ciphertext")
      .add("layout","slot=8*(8*k+i)+2*lane; new_dimension2=0").add("consumer_planned",true)
      .add("direct_score_encryptions",0).add("producer_ciphertexts_consumed_directly",true)
      .add("timing_claim",false).add("parameter_increase",true).add("balanced_precombined_z",true)
      .add("admission_rule","bitCapacity>0 AND isCorrect").add("poststop_observer",false).add("terminal_only_observer",true)
      .add("server_admission_policy","record_irreversible_loss_continue_ordinary_arithmetic")
      .add("plan_sha256",BGV_PLAN_SHA256).add("public_slots_sha256",BGV_PUBLIC_SLOTS_SHA256)
      .add("public_setup_before_keygen",true).add("public_setup_records",1)
      .add("terminal_anchor_slots",std::vector<long>{0,2,4,6}).add("inactive_odd_slots",16384);
  direct_fields(meta,direct);log.emit(meta);
  progress.phase="public_source_load";
  std::ifstream stream(env("BGV_LR_N8_SOURCE_DIR")+"/PUBLIC_SLOTS.json",std::ios::binary);
  need(stream.good(),"public slot source open");
  const std::string public_bytes((std::istreambuf_iterator<char>(stream)),std::istreambuf_iterator<char>());
  need(sha256(public_bytes)==BGV_PUBLIC_SLOTS_SHA256,"fixed public slot source hash");
  const auto source_slots=NativeJson::parse(public_bytes);
  progress.phase="context_build";progress.context_attempts=1;
  const auto context=helib::ContextBuilder<helib::BGV>().m(245760).p(kP).r(1).bits(1200).c(3).scale(6)
      .gens(std::vector<long>{163843,86017,163841}).ords(std::vector<long>{4096,4,2}).build();
  progress.contexts_constructed=1;progress.phase="context_observation";
  const auto context_row=context_record(context,plan);emit_native(log,context_row);
  progress.phase="context_validation";
  need(context_row.at("context_admitted").get<bool>(),"actual context differs from selected admissible context");
  progress.phase="public_encoding_setup";
  const auto public_pins=prepare_public_encodings(log,context,source_slots);
  progress.public_setup_records=1;progress.phase="key_object_setup";
  const auto exponents=producer::required_exponents(context.getZMStar());
  need(exponents.size()==69,"native rotation union drift");
  helib::SecKey key(context);progress.phase="key_generation";progress.keygen_attempts=1;
  key.GenSecKey();const long matrices_before=key.keySWlist().size();
  need(matrices_before==2,"initial key matrix count drift");
  for(long e:exponents)key.GenKeySWmatrix(1,e);
  key.setKeySwitchMap();need(key.keySWlist().size()==71,"native key matrix count drift");
  for(long e:exponents)need(key.haveKeySWmatrix(1,e)&&key.isReachable(e),"missing direct rotation key");
  progress.keysets_completed=1;progress.phase="key_storage_observation";
  const helib::PubKey& public_key=key;
  const auto key_observation=observe_public_key_storage(public_key,context,exponents);
  progress.phase="key_record_output";
  Json keys;keys.add("type","key").add("rotation_exponents",exponents).add("matrices_before",matrices_before)
      .add("matrices_after",static_cast<long>(key.keySWlist().size()))
      .add("public_key_fnv1a64",key_observation.at("public_key_fnv1a64").get<std::string>())
      .add("public_key_sha256",key_observation.at("public_key_sha256").get<std::string>())
      .add("public_key_serialized_bytes",key_observation.at("public_key_serialized_bytes").get<std::uint64_t>())
      .add("key_membership_attested",false).add("secret_serialized",false);
  field(keys,"key_storage",key_observation.at("key_storage"));log.emit(keys);
  progress.phase="input_setup";
  const auto e=expected();const auto l=layout();const auto& ea=context.getEA();
  const auto clear=oracle(e,l);
  need(e.x==l.x&&e.y==l.y,"producer and consumer exact operand contract");
  need(std::vector<long>(kSupport.begin(),kSupport.end())==producer::support(),"factor support contract");
  std::vector<NTL::ZZX> scalar_queries(kSlots);
  for(long i=0;i<kSlots;++i)NTL::SetCoeff(scalar_queries[i],0,e.query[i]);
  helib::Ctxt encrypted_query(public_key);progress.phase="input_encryption";progress.encryption_attempts=1;
  ea.encrypt(encrypted_query,public_key,scalar_queries);progress.encryptions_completed=1;
  progress.phase="input_observation";
  Json inputs;inputs.add("type","inputs").add("encryptions",1).add("query_fnv1a64",checksum(encrypted_query))
      .add("query_slots_fnv1a64",vector_hash(e.query));exact_capacity(inputs,encrypted_query);log.emit(inputs);
  helib::resetAllTimers();
  progress.phase="server_object_setup";
  Trace trace{log,ea,public_pins};producer::Result output(public_key);Consumer result;helib::Ctxt comparison(public_key);
  const auto begin=[&](const std::string& name) {trace.begin(name);};
  bool counts_pass=false;
  progress.phase="server_or_terminal";
  try {
  trace.phase("producer_setup");
  const auto capture_producer=[&](const std::string& name,const helib::Ctxt& ct,const producer::Counts& count,
                                  double norm,const NTL::ZZX* poly,const std::vector<long>* slots) {
    trace.ledger.producer=count;return trace.capture(name,ct,true,norm,poly,slots);
  };
  const auto validate_public=[&](const std::string& name,const NTL::ZZX& poly,const std::vector<long>& values,double norm) {
    trace.validate_public(name,poly,values,norm);
  };
  need(producer::produce(output,encrypted_query,fixture::input,capture_producer,validate_public,begin),"producer traversal incomplete");
  trace.phase("producer_complete_checks");
  need(trace.producer_snapshots==46&&trace.public_polynomials==11,"producer observation ledger");
  counts_pass=output.counts.rotations==16&&output.counts.plaintext_products==9
      &&output.counts.encrypted_additions==16&&output.counts.public_additions==2
      &&calls("multiplyBy")==0&&calls("automorph")==16&&calls("smartAutomorph")==16
      &&calls("frobeniusAutomorph")==0&&calls("multByConstant")==9;
  const auto produced_z=checksum(output.z),produced_z_sha=strong_hash(output.z);
  Json produced;produced.add("type","producer_complete").add("counts_pass",counts_pass)
      .add("encryptions",1).add("query_fnv1a64",checksum(encrypted_query))
      .add("scores_fnv1a64",checksum(output.scores)).add("z_fnv1a64",produced_z)
      .add("scores_sha256",strong_hash(output.scores)).add("z_sha256",produced_z_sha);
  trace.progress(produced);log.emit(produced);
  // An actual empty same-key ciphertext is the exact public zero; no Encrypt or DummyEncrypt call.
  const helib::Ctxt blank_zero(public_key);const auto zero_binary=binary(blank_zero);
  const auto zero_json=serialized_json(blank_zero);
  need(blank_zero.isEmpty()&&zero_json.at("content").at("parts").empty()
       &&blank_zero.getNoiseBound()==0&&int_factor(blank_zero)==1
       &&blank_zero.getPtxtSpace()==kP && &blank_zero.getPubKey()==&public_key,"exact empty same-key zero");
  Json binding;binding.add("type","comparator_input").add("z_fnv1a64",checksum(output.z))
      .add("z_sha256",strong_hash(output.z)).add("producer_z_fnv1a64",produced_z)
      .add("producer_z_sha256",produced_z_sha).add("fixture_fnv1a64",l.fingerprint)
      .add("reencryptions",0).add("client_decryptions",0)
      .add("zero_sha256",sha256(zero_binary)).add("zero_binary_hex",byte_hex(zero_binary))
      .add("zero_is_empty",true).add("zero_same_public_key",true);field(binding,"zero_json",zero_json);
  direct_fields(binding,direct);trace.progress(binding);log.emit(binding);
  begin("comparison");
  helib::polyEval(comparison,direct.polynomial,output.z,kDirectBabyStep);comparison.cleanUp();
  need(strong_hash(output.z)==produced_z_sha&&binary(blank_zero)==zero_binary,"comparator operands unchanged");
  trace.ledger.comparator_calls=1;trace.ledger.comparator_products=calls("multiplyBy");
  Json returned;returned.add("type","comparator_return").add("z_before_sha256",produced_z_sha)
      .add("z_after_sha256",strong_hash(output.z)).add("zero_before_sha256",sha256(zero_binary))
      .add("zero_after_sha256",strong_hash(blank_zero)).add("comparison_sha256",strong_hash(comparison))
      .add("operands_unchanged",true);trace.progress(returned);log.emit(returned);
  need(trace.capture("comparison",comparison,false),"comparison traversal incomplete");
  trace.phase("consumer_setup");
  const auto capture_consumer=[&](const std::string& name,const helib::Ctxt& ct,long rotations,long products,
                                  long weak,long scalar,long additions) {
    auto& c=trace.ledger;c.selector_rotations=rotations;c.selector_products=products;
    c.selector_support_subtractions=weak;c.selector_scalar_products=scalar;c.selector_additions=additions;
    return trace.capture(name,ct,false);
  };
  need(consume(log,"native",comparison,result,counts_pass,capture_consumer,begin),"consumer traversal incomplete");
  trace.phase("server_complete_checks");
  counts_pass &= trace.consumer_snapshots==164&&trace.snapshots==210
      &&trace.ledger.comparator_products==139&&calls("multiplyBy")==195
      &&calls("automorph")==79&&calls("smartAutomorph")==79
      &&calls("frobeniusAutomorph")==0&&calls("multByConstant")==9;
  need(strong_hash(output.z)==produced_z_sha&&binary(blank_zero)==zero_binary,"immutable comparator operands after consumer");
  need(counts_pass&&trace.public_roundtrips,"complete server structural checks");
  Json complete;complete.add("type","server_complete").add("counts_pass",counts_pass)
      .add("query_encryptions",1).add("direct_score_encryptions",0).add("client_decryptions",0)
      .add("query_fnv1a64",checksum(encrypted_query)).add("scores_fnv1a64",checksum(output.scores))
      .add("z_fnv1a64",checksum(output.z)).add("z_sha256",strong_hash(output.z))
      .add("comparison_fnv1a64",checksum(comparison)).add("final_fnv1a64",checksum(*result.selected))
      .add("consumer_executed",true).add("output_ciphertexts",1)
      .add("server_graph_complete",true).add("structural_checks_pass",true)
      .add("all_stages_admitted",trace.all_stages_admitted).add("final_original_isCorrect",result.selected->isCorrect());
  field(complete,"first_admission_loss",trace.first_loss);trace.progress(complete);log.emit(complete);
  } catch(const std::exception& error) {
    trace.exception(error.what());return 2;
  }
  // No server ciphertext operation occurs below this point.
  progress.phase="terminal_observation";
  const auto diagnostic=observe_terminal(log,*result.selected,key,clear.at("native/final"));
  progress.phase="terminal_summary";
  const bool usable=diagnostic.status=="OBSERVED";
  const bool passed=usable&&trace.all_stages_admitted&&diagnostic.semantic_pass;
  int code=1;std::string status="COMPLETE_NEGATIVE";
  if(!usable) {code=2;status="DIAGNOSTIC_INCOMPLETE";}
  else if(passed) {code=0;status="PASS";}
  Json summary;summary.add("type","summary").add("status",status)
      .add("gate_pass",passed).add("server_graph_complete",true).add("structural_checks_pass",true)
      .add("all_stages_admitted",trace.all_stages_admitted).add("final_original_isCorrect",result.selected->isCorrect())
      .add("terminal_observation_status",diagnostic.status).add("terminal_decrypt_attempts",diagnostic.decrypt_attempts)
      .add("client_decryptions",diagnostic.successful_decryptions).add("query_encryptions",1)
      .add("decoded_slots",usable?kSlots:0).add("server_result_promoted",false)
      .add("formal_failure_bound","unestablished").add("timing_claim",false);
  field(summary,"terminal_semantic_pass",usable?NativeJson(diagnostic.semantic_pass):NativeJson(nullptr));
  field(summary,"first_admission_loss",trace.first_loss);trace.progress(summary);log.emit(summary);
  return code;
}
} // namespace
int main(int argc,char** argv) {
  std::unique_ptr<Log> log;SetupProgress progress;
  try {
    need(sha256(BGV_PLAN_JSON)==BGV_PLAN_SHA256,"embedded exact PLAN hash");
    if(argc==1) {
      std::cout<<NativeJson{{"status","PLAN_NO_KEYGEN"},{"schema","bgv-larger-ring-direct-n8.v1"},
          {"source",BGV_SOURCE_ID},{"plan_sha256",BGV_PLAN_SHA256},{"plan",NativeJson::parse(BGV_PLAN_JSON)},
          {"context_construction_attempts",0},{"keygen_attempts",0},{"ciphertext_operations",0}}.dump()<<'\n';
      return 0;
    }
    need(argc==3&&std::string(argv[1])=="--run","expected --run ABS_NEW_JSONL");
    need(env("BGV_LR_N8_ACK")==kAck&&env("BGV_LR_N8_SOURCE")==BGV_SOURCE_ID,"source/authorization refusal");
    need(hex64(env("BGV_LR_N8_BINARY_SHA256")),"root binary SHA required");
    need(env("DYLD_LIBRARY_PATH")=="/opt/homebrew/Cellar/gmp/6.3.0/lib"&&std::string(gmp_version)=="6.3.0","GMP6.3 backend required");
    log=std::make_unique<Log>(argv[2]);return run(*log,env("BGV_LR_N8_BINARY_SHA256"),progress);
  }catch(const std::exception& error) {
    std::cerr<<"BGV_LR_N8_INVALID_OR_EXCEPTION: "<<error.what()<<'\n';
    if(log){try{
      if(progress.phase=="server_or_terminal"||progress.phase=="terminal_observation"||progress.phase=="terminal_summary"){
        Json actual;timers(actual);
        Json row;row.add("type","unhandled_exception").add("status","INCOMPLETE")
            .add("phase",progress.phase).add("error",error.what()).add("server_result_promoted",false);
        field(row,"actual_server_timers",NativeJson::parse(actual.str()));
        field(row,"client_decryptions",nullptr);field(row,"terminal_decrypt_attempts",nullptr);
        log->emit(row);
      } else setup_exception(*log,progress,env("BGV_LR_N8_BINARY_SHA256"),error.what());
    }catch(...){}}
    return 2;
  }
}
