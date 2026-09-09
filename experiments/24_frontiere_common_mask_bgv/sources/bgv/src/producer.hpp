#pragma once
// Balanced precombined X-Y producer; unchanged query scoring and full native key union.
#include <helib/helib.h>
#include <helib/norms.h>
#include <algorithm>
#include <array>
#include <functional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace bgv_n8_score_input {
constexpr long P=8191, D=512, G=8, LANES=4, WIDTH=4096, SLOTS=32768;
using Query=std::array<long,D>;
using Gallery=std::array<std::array<Query,G>,LANES>;
struct PublicInput {
  Gallery gallery;
  std::array<long,LANES> active_n;
  std::array<long,LANES> lower;
};
struct Counts {long rotations=0,plaintext_products=0,encrypted_additions=0,public_additions=0;};
struct Result {
  helib::Ctxt scores,z;
  Counts counts;
  explicit Result(const helib::PubKey& key):scores(key),z(key) {}
};
// A future gate should log capacity(), getNoiseBound(), logOfPrimeSet(), ciphertext hash,
// logical counts and the measured plaintext embedding norm before deciding whether to stop.
using Observe=std::function<bool(const std::string&,const helib::Ctxt&,const Counts&,double,const NTL::ZZX*,const std::vector<long>*)>;

inline void need(bool yes,const char* reason) {if(!yes) throw std::invalid_argument(reason);}
inline long residue(long x) {x%=P;return x<0?x+P:x;}
inline long ceil_sqrt(long value) {
  long lo=0,hi=value+1;
  while(lo+1<hi) {const long mid=(lo+hi)/2;if(mid*mid>=value)hi=mid;else lo=mid;}
  return value==0?0:hi;
}
inline std::vector<long> support() {
  std::vector<long> out;
  for(long j=0;j<32;++j) {out.push_back(j);out.push_back(1024+32*j);}
  return out;
}

// Client-side, gallery-independent replication. The server producer never receives these queries.
inline std::vector<long> pack_queries(const std::array<Query,LANES>& queries) {
  std::vector<long> packed(SLOTS);
  for(long lane=0;lane<LANES;++lane) {
    long norm=0;
    for(long value:queries[lane]) {need(value>=-3 && value<=3,"query coordinate");norm+=value*value;}
    need(norm<=1024,"query norm");
    for(long k=0;k<D;++k) for(long i=0;i<G;++i)
      packed[8*(8*k+i)+2*lane]=residue(queries[lane][k]);
  }
  return packed;
}

// Balanced coefficient lift preserves every scalar slot modulo8191. Its complex embedding
// norm, not the maximum slot value, determines HElib's multiply-by-plaintext noise factor.
inline NTL::ZZX encode(const helib::EncryptedArray& ea,const std::vector<long>& values) {
  NTL::ZZX poly;ea.encode(poly,values);
  for(long i=0;i<=NTL::deg(poly);++i) {
    long value=residue(NTL::conv<long>(NTL::coeff(poly,i)));
    if(value>P/2)value-=P;
    NTL::SetCoeff(poly,i,value);
  }
  return poly;
}

inline std::vector<long> required_exponents(const helib::PAlgebra& algebra) {
  need(algebra.numOfGens()==3 && algebra.OrderOf(0)==4096 && algebra.OrderOf(1)==4 && algebra.OrderOf(2)==2
       && algebra.SameOrd(0) && algebra.SameOrd(1) && algebra.SameOrd(2)
       && algebra.ZmStarGen(0)==163843 && algebra.ZmStarGen(1)==86017 && algebra.ZmStarGen(2)==163841,"native geometry");
  std::set<long> shifts;
  for(long j=0;j<9;++j)shifts.insert(8L<<j);
  for(long value=1;value<8;++value)shifts.insert(value);
  for(long value:support())if(value)shifts.insert(value);
  std::set<long> exponents;
  for(long shift:shifts)exponents.insert(algebra.genToPow(0,(4096-shift)%4096));
  need(exponents.size()==69,"exact producer/consumer key union");
  return {exponents.begin(),exponents.end()};
}

using ValidatePublic=std::function<void(const std::string&,const NTL::ZZX&,const std::vector<long>&,double)>;
using BeforeStage=std::function<void(const std::string&)>;
inline bool produce(Result& out,const helib::Ctxt& packed,
                    const PublicInput& input,const Observe& observe,const ValidatePublic& validate,const BeforeStage& begin) {
  const auto& context=packed.getContext();const auto& ea=context.getEA();
  need(context.getP()==P && context.getR()==1 && context.getM()==245760 && ea.size()==SLOTS,"fixed scalar context");
  required_exponents(context.getZMStar());
  std::vector<long> coefficients(SLOTS),offsets(SLOTS),threshold(SLOTS);
  for(long lane=0;lane<4;++lane) {
    need(input.lower[lane]==-1024,"fixed aligned threshold contract");
    need(input.active_n[lane]>=1 && input.active_n[lane]<=8,"active gallery");
    long upper=input.lower[lane];
    for(long i=0;i<8;++i) {
      const bool active=i<input.active_n[lane];long norm=0;
      if(active) {
        for(long value:input.gallery[lane][i]) {
          need(value>=-3 && value<=3,"template coordinate");norm+=value*value;
        }
        const long radius=2*ceil_sqrt(1024*norm);
        need(input.lower[lane]<=norm-radius,"gallery lower domain");
        upper=std::max(upper,norm+radius);
      }
      for(long k=0;k<512;++k) {
        const long slot=8*(8*k+i)+2*lane;
        coefficients[slot]=active?residue(-2*input.gallery[lane][i][k]):0;
        offsets[slot]=active?residue(norm-input.lower[lane]):4095;
      }
    }
    need(upper-input.lower[lane]+1<=4096,"gallery exceeds12bit domain");
  }
  std::array<std::vector<long>,8> xm,ym;
  for(long k=0;k<8;++k) {xm[k].assign(SLOTS,0);ym[k].assign(SLOTS,0);}
  const auto offsets_in_consumer=support();long factor=0;
  for(long i=0;i<8;++i) {
    for(long rival=-1;rival<8;++rival) {
      if(rival==i)continue;
      const long t=offsets_in_consumer[factor++];
      const bool is_threshold=rival<0,weak=rival>i;
      const long a=is_threshold?i:(weak?rival:i),b=is_threshold?-1:(weak?i:rival);
      for(long lane=0;lane<4;++lane) {
        const long slot=8*t+2*lane;xm[(a-t%8+8)%8][slot]=1;
        if(is_threshold)threshold[slot]=1024;
        else ym[(b-t%8+8)%8][slot]=1;
      }
    }
  }
  need(factor==64,"factor order");
  out.counts=Counts{};
  auto capture=[&](const std::string& name,const helib::Ctxt& ct,double norm=0.0,const NTL::ZZX* poly=nullptr,const std::vector<long>* values=nullptr) {
    const bool allowed=observe(name,ct,out.counts,norm,poly,values);
    return allowed; // Admission is recorded independently; ordinary arithmetic continues.
  };
  auto multiply=[&](helib::Ctxt& ct,const std::vector<long>& values,const std::string& name) {
    begin(name);
    const auto poly=encode(ea,values);
    const double norm=NTL::conv<double>(helib::embeddingLargestCoeff(poly,context.getZMStar()));
    validate(name,poly,values,norm);
    ct.multByConstant(poly,norm);++out.counts.plaintext_products;
    return capture(name,ct,norm,&poly,&values);
  };
  begin("producer/input");
  if(!capture("producer/input",packed))return false;
  out.scores=packed;
  if(!multiply(out.scores,coefficients,"producer/template_product"))return false;
  for(long j=0;j<9;++j) {
    begin("producer/sum_rotation_"+std::to_string(j));
    helib::Ctxt rotated(out.scores);ea.rotate1D(rotated,0,-(8L<<j));rotated.cleanUp();++out.counts.rotations;
    if(!capture("producer/sum_rotation_"+std::to_string(j),rotated))return false;
    begin("producer/sum_"+std::to_string(j));
    out.scores+=rotated;++out.counts.encrypted_additions;
    if(!capture("producer/sum_"+std::to_string(j),out.scores))return false;
  }
  begin("producer/periodic_scores");
  const auto offset_poly=encode(ea,offsets);
  const double offset_norm=NTL::conv<double>(helib::embeddingLargestCoeff(offset_poly,context.getZMStar()));
  validate("producer/periodic_scores",offset_poly,offsets,offset_norm);
  out.scores.addConstant(offset_poly);++out.counts.public_additions;
  if(!capture("producer/periodic_scores",out.scores,offset_norm,&offset_poly,&offsets))return false;
  for(long k=0;k<8;++k) {
    begin("producer/route_"+std::to_string(k));
    helib::Ctxt shifted(out.scores);
    if(k) {ea.rotate1D(shifted,0,-k);shifted.cleanUp();++out.counts.rotations;}
    if(!capture("producer/route_"+std::to_string(k),shifted))return false;
    std::vector<long> signed_mask(SLOTS);
    for(long slot=0;slot<SLOTS;++slot)signed_mask[slot]=residue(xm[k][slot]-ym[k][slot]);
    if(!multiply(shifted,signed_mask,"producer/z_mask_"+std::to_string(k)))return false;
    begin("producer/z_sum_"+std::to_string(k));
    if(k==0)out.z=shifted;
    else {out.z+=shifted;++out.counts.encrypted_additions;}
    if(!capture("producer/z_sum_"+std::to_string(k),out.z))return false;
  }
  begin("producer/output_z");
  for(long& value:threshold)value=residue(-value);
  const auto threshold_poly=encode(ea,threshold);
  const double threshold_norm=NTL::conv<double>(helib::embeddingLargestCoeff(threshold_poly,context.getZMStar()));
  validate("producer/output_z",threshold_poly,threshold,threshold_norm);
  out.z.addConstant(threshold_poly);++out.counts.public_additions;
  if(!capture("producer/output_z",out.z,threshold_norm,&threshold_poly,&threshold))return false;
  need(out.counts.rotations==16 && out.counts.plaintext_products==9
       && out.counts.encrypted_additions==16 && out.counts.public_additions==2,"producer ledger");
  return true;
}
} // namespace bgv_n8_score_input
