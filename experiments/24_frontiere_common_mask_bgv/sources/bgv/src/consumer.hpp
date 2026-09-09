// Passed N8 arithmetic; only capacity callback and explicit charged counters adapted.
struct Factor { long candidate, rival; bool weak; };
std::array<Factor,64> factors() {
  std::array<Factor,64> result{}; long index=0;
  for (long i=0;i<8;++i) {
    result[index++]={i,-1,false};
    for (long j=0;j<8;++j) if (j!=i) result[index++]={i,j,j>i};
  }
  return result;
}
struct Layout {
  std::vector<long> x,y,comparison,output;
  std::array<std::vector<long>,8> winners;
  std::string fingerprint;
};
Layout layout() {
  Layout l;l.x.assign(kSlots,0);l.y.assign(kSlots,0);l.output.assign(kSlots,0);
  for (auto& w:l.winners) w.assign(kSlots,0);
  const auto spec=factors();
  for (long block=0;block<kBlocks;++block) {
    const auto& scores=kScores[block];
    for (long x:scores) need(x>=0 && x<=4095,"12-bit score domain");
    need(kActiveN[block]>=1 && kActiveN[block]<=8,"public active gallery size");
    for (long i=kActiveN[block];i<8;++i) need(scores[i]==4095,"padding score drift");
    const auto best=std::min_element(scores.begin(),scores.end());
    const long id=*best<1024?std::distance(scores.begin(),best)+1:0;
    const long anchor=2*block;
    l.output[anchor]=id;
    if (id) l.winners[id-1][anchor]=1;
    for (long j=0;j<64;++j) {
      const auto f=spec[j];
      const long index=anchor+8*kSupport[j];
      if (f.rival<0) {
        l.x[index]=scores[f.candidate];
        l.y[index]=1024;
      } else if (f.weak) {
        l.x[index]=scores[f.rival];
        l.y[index]=scores[f.candidate];
      } else {
        l.x[index]=scores[f.candidate];
        l.y[index]=scores[f.rival];
      }
    }
  }
  HashBuffer h;
  for (long i=0;i<kSlots;++i) {
    l.comparison.push_back(l.x[i]<l.y[i]);
    for (long value:{l.x[i],l.y[i]}) for (unsigned shift:{0U,8U}) h.overflow((value>>shift)&255);
  }
  l.fingerprint=hex(h.value);return l;
}
std::vector<long> shifted_support(long offset) {
  std::vector<long> output(kSlots,0);
  for (long i=0;i<kSlots;++i)
    output[i]=(i%2==0) && std::find(kSupport.begin(),kSupport.end(),(i/8+offset)%kWidth)!=kSupport.end();
  return output;
}
using ConsumerObserve=std::function<bool(const std::string&,const helib::Ctxt&,long,long,long,long,long)>;
struct Consumer {
  std::vector<helib::Ctxt> winners;
  std::unique_ptr<helib::Ctxt> selected;
};
std::array<long,5> timer_values() {
  return {{calls("multiplyBy"),calls("automorph"),calls("smartAutomorph"),
           calls("frobeniusAutomorph"),calls("multByConstant")}};
}
bool consume(Log& log,const char* arm,const helib::Ctxt& comparison,
             Consumer& result,bool& counts_pass,const ConsumerObserve& observe,const producer::BeforeStage& begin) {
  need(std::string(arm)=="native","single native consumer only");
  const auto& ea=comparison.getContext().getEA();
  helib::Ctxt input(comparison);
  const auto before=timer_values();
  const auto original_hash=checksum(comparison),clone_hash=checksum(input);
  need(original_hash==clone_hash,"comparison clone mismatch");
  Json start;start.add("type","arm_start").add("arm",arm)
      .add("comparison_fnv1a64",original_hash).add("input_clone_fnv1a64",clone_hash);
  timers(start);log.emit(start);
  const auto spec=factors();result.winners.reserve(8);
  long rotations=0,products=0,weak_factors=0,scalar_products=0,additions=0;
  auto capture=[&](const std::string& name,const helib::Ctxt& ct) {
    const std::string full=std::string(arm)+"/"+name;
    return observe(full,ct,rotations,products,weak_factors,scalar_products,additions);
  };
  for (long candidate=0;candidate<8;++candidate) {
    std::vector<helib::Ctxt> leaves;leaves.reserve(8);
    for (long lane=0;lane<8;++lane) {
      const long index=8*candidate+lane,offset=kSupport[index];
      begin(std::string(arm)+"/leaf_"+std::to_string(index));
      helib::Ctxt leaf(input);
      if (offset) {
        ea.rotate1D(leaf,0,-offset);
        leaf.cleanUp();++rotations;
      }
      if (!capture("leaf_"+std::to_string(index),leaf)) return false;
      if (spec[index].weak) {
        begin(std::string(arm)+"/weak_"+std::to_string(index));
        NTL::ZZX support;ea.encode(support,shifted_support(offset));
        leaf.negate();leaf.addConstant(support);++weak_factors;
        if (!capture("weak_"+std::to_string(index),leaf)) return false;
      }
      leaves.push_back(std::move(leaf));
    }
    for (long pair=0;pair<4;++pair) {
      begin(std::string(arm)+"/pair_"+std::to_string(4*candidate+pair));
      leaves[2*pair].multiplyBy(leaves[2*pair+1]);leaves[2*pair].cleanUp();++products;
      if (!capture("pair_"+std::to_string(4*candidate+pair),leaves[2*pair])) return false;
    }
    for (long quarter=0;quarter<2;++quarter) {
      begin(std::string(arm)+"/quarter_"+std::to_string(2*candidate+quarter));
      leaves[4*quarter].multiplyBy(leaves[4*quarter+2]);leaves[4*quarter].cleanUp();++products;
      if (!capture("quarter_"+std::to_string(2*candidate+quarter),leaves[4*quarter])) return false;
    }
    begin(std::string(arm)+"/winner_"+std::to_string(candidate));
    leaves[0].multiplyBy(leaves[4]);leaves[0].cleanUp();++products;
    if (!capture("winner_"+std::to_string(candidate),leaves[0])) return false;
    result.winners.push_back(std::move(leaves[0]));
  }
  result.selected=std::make_unique<helib::Ctxt>(result.winners[0]);
  for (long candidate=1;candidate<8;++candidate) {
    begin(std::string(arm)+"/weighted_"+std::to_string(candidate));
    helib::Ctxt weighted(result.winners[candidate]);weighted *= candidate+1;++scalar_products;
    if (!capture("weighted_"+std::to_string(candidate),weighted)) return false;
    begin(std::string(arm)+"/sum_"+std::to_string(candidate));
    *result.selected += weighted;++additions;
    if (!capture("sum_"+std::to_string(candidate),*result.selected)) return false;
  }
  begin(std::string(arm)+"/final");
  result.selected->cleanUp();if (!capture("final",*result.selected)) return false;
  const auto after=timer_values();std::vector<long> delta;
  for (long i=0;i<5;++i) delta.push_back(after[i]-before[i]);
  const bool counts=rotations==63 && products==56 && weak_factors==28
      && delta[0]==56 && delta[1]==63 && delta[2]==63 && delta[3]==0 && delta[4]==0;
  counts_pass &= counts;
  Json complete;complete.add("type","arm_complete").add("arm",arm)
      .add("rotate_calls",rotations).add("selector_ciphertext_multiplies",products)
      .add("selector_scalar_multiplies",7).add("selector_public_support_subtractions",weak_factors)
      .add("selector_ciphertext_additions",7).add("explicit_selector_plaintext_masks",0)
      .add("timer_delta",delta).add("counts_pass",counts)
      .add("capacity_bits",result.selected->bitCapacity())
      .add("final_fnv1a64",checksum(*result.selected));timers(complete);log.emit(complete);
  return true;
}
