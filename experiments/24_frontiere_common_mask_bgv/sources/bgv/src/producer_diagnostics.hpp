// Byte-extracted passing producer observations and fixed query/gallery oracle.
std::string vector_hash(const std::vector<long>& values) {
  HashBuffer buffer;
  for(long value:values) {
    const auto word=static_cast<std::uint64_t>(value);
    for(unsigned shift=0;shift<64;shift+=8)buffer.overflow((word>>shift)&255);
  }
  return hex(buffer.value);
}
void counts(Json& row,const producer::Counts& count) {
  row.add("rotations",count.rotations).add("plaintext_products",count.plaintext_products)
      .add("encrypted_additions",count.encrypted_additions).add("public_additions",count.public_additions);
}
void timer_location(Json& row) {
  const auto* timer=helib::getTimerByName("multByConstant");
  row.add("selected_multByConstant_timer_location",timer?timer->loc:"")
      .add("timer_overloads_aggregated",false);
}
void capacity(Json& row,const helib::Ctxt& ct) {
  const double bits=ct.capacity(),prime_bits=ct.logOfPrimeSet()/std::log(2.0);
  need(std::isfinite(bits)&&std::isfinite(prime_bits)&&ct.getNoiseBound()>0,
       "finite capacity and positive extended noise required");
  row.add("capacity_bits",ct.bitCapacity()).add("capacity",bits).add("prime_set_bits",prime_bits);
  extended_number(row,"noise_bound",ct.getNoiseBound());
}
bool plaintext_record(Json& row,const helib::EncryptedArray& ea,
                      const NTL::ZZX& poly,const std::vector<long>& slots,double norm) {
  need(slots.size()==kSlots && NTL::deg(poly)<65536,"actual plaintext geometry");
  std::vector<long> coefficients(65536);long max_abs=0,l1=0;
  for(long i=0;i<65536;++i) {
    const long value=NTL::conv<long>(NTL::coeff(poly,i));
    need(value>=-4095&&value<=4095,"balanced coefficient drift");
    coefficients[i]=value;max_abs=std::max(max_abs,std::abs(value));l1+=std::abs(value);
  }
  need(std::isfinite(norm)&&norm>0&&norm<=l1*(1+1e-8),"plaintext embedding norm sanity");
  // This decodes a PUBLIC encoded polynomial, never a ciphertext or secret.
  std::vector<NTL::ZZX> decoded;ea.decode(decoded,poly);
  long mismatch=0,nonconstant=0;
  need(decoded.size()==kSlots,"public polynomial decoded size");
  for(long i=0;i<kSlots;++i) {
    const bool scalar=NTL::deg(decoded[i])<=0;nonconstant+=!scalar;
    const long value=scalar?producer::residue(NTL::conv<long>(NTL::coeff(decoded[i],0))):-1;
    mismatch+=value!=slots[i];
  }
  row.add("plaintext_present",true).add("plaintext_slots",slots)
      .add("plaintext_coefficients",coefficients).add("plaintext_degree",NTL::deg(poly))
      .add("plaintext_slots_fnv1a64",vector_hash(slots))
      .add("plaintext_coefficients_fnv1a64",vector_hash(coefficients))
      .add("plaintext_embedding_norm",norm).add("plaintext_coefficient_max_abs",max_abs)
      .add("plaintext_coefficient_l1",l1).add("public_roundtrip_nonconstant",nonconstant)
      .add("public_roundtrip_mismatches",mismatch).add("public_roundtrip_pass",!nonconstant&&!mismatch);
  return !nonconstant&&!mismatch;
}
struct Expected {std::vector<long> query,scores,x,y;};
Expected expected() {
  Expected out;out.query=producer::pack_queries(fixture::queries);
  out.scores.resize(kSlots);out.x.assign(kSlots,0);out.y.assign(kSlots,0);
  for(long lane=0;lane<4;++lane) for(long i=0;i<8;++i) {
    long score=4095;
    if(i<fixture::input.active_n[lane]) {
      long norm=0,dot=0;
      for(long k=0;k<512;++k) {const long g=fixture::input.gallery[lane][i][k];norm+=g*g;dot+=g*fixture::queries[lane][k];}
      score=norm-fixture::input.lower[lane]-2*dot;
    }
    need(score==fixture::scores[lane][i]&&score>=0&&score<4096,"actual query score fixture");
  }
  for(long s=0;s<kSlots;++s)out.scores[s]=(s%2)?0:fixture::scores[(s%8)/2][(s/8)%8];
  const auto offsets=producer::support();long factor=0;
  for(long i=0;i<8;++i)for(long rival=-1;rival<8;++rival) {
    if(rival==i)continue;
    const long t=offsets[factor++];
    for(long lane=0;lane<4;++lane) {
      const auto& scores=fixture::scores[lane];
      if(rival<0) {out.x[8*t+2*lane]=scores[i];out.y[8*t+2*lane]=1024;}
      else if(rival>i) {out.x[8*t+2*lane]=scores[rival];out.y[8*t+2*lane]=scores[i];}
      else {out.x[8*t+2*lane]=scores[i];out.y[8*t+2*lane]=scores[rival];}
    }
  }
  need(factor==64,"actual role layout");return out;
}
