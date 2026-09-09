// Client-only all-stage plaintext oracle. No output from this object enters server ciphertext arithmetic.
using Slots=std::vector<long>;
using Oracle=std::map<std::string,Slots>;
Slots shifted(const Slots& input,long offset) {
  need(input.size()==kSlots,"oracle slot geometry");Slots out(kSlots);
  for(long slot=0;slot<kSlots;++slot)out[slot]=input[8*((slot/8+offset)%4096)+slot%8];return out;
}
Slots product(const Slots& a,const Slots& b) {
  Slots out(kSlots);for(long s=0;s<kSlots;++s)out[s]=producer::residue(a[s]*b[s]);return out;
}
Slots sum(const Slots& a,const Slots& b) {
  Slots out(kSlots);for(long s=0;s<kSlots;++s)out[s]=producer::residue(a[s]+b[s]);return out;
}
Oracle oracle(const Expected& expected,const Layout& layout) {
  Oracle out;out["producer/input"]=expected.query;
  Slots coefficients(kSlots),offsets(kSlots),threshold(kSlots);
  for(long lane=0;lane<4;++lane)for(long candidate=0;candidate<8;++candidate) {
    bool active=candidate<fixture::input.active_n[lane];long norm=0;
    if(active)for(long g:fixture::input.gallery[lane][candidate])norm+=g*g;
    for(long coordinate=0;coordinate<512;++coordinate) {
      long s=8*(8*coordinate+candidate)+2*lane;
      coefficients[s]=active?producer::residue(-2*fixture::input.gallery[lane][candidate][coordinate]):0;
      offsets[s]=active?producer::residue(norm-fixture::input.lower[lane]):4095;
    }
  }
  Slots scores=product(expected.query,coefficients);out["producer/template_product"]=scores;
  for(long j=0;j<9;++j) {
    auto rotated=shifted(scores,8L<<j);out["producer/sum_rotation_"+std::to_string(j)]=rotated;
    scores=sum(scores,rotated);out["producer/sum_"+std::to_string(j)]=scores;
  }
  scores=sum(scores,offsets);out["producer/periodic_scores"]=scores;need(scores==expected.scores,"oracle actual scores");
  std::array<Slots,8> signed_masks;for(auto& mask:signed_masks)mask.assign(kSlots,0);
  const auto spec=factors();
  for(long i=0;i<64;++i) {
    long t=kSupport[i];auto f=spec[i];long a=f.weak?f.rival:f.candidate,b=f.weak?f.candidate:f.rival;
    for(long lane=0;lane<4;++lane) {
      long slot=8*t+2*lane;signed_masks[(a-t%8+8)%8][slot]+=1;
      if(b<0)threshold[slot]=8191-1024;else signed_masks[(b-t%8+8)%8][slot]-=1;
    }
  }
  Slots z(kSlots,0);
  for(long k=0;k<8;++k) {
    auto rotated=shifted(scores,k);out["producer/route_"+std::to_string(k)]=rotated;
    auto masked=product(rotated,signed_masks[k]);out["producer/z_mask_"+std::to_string(k)]=masked;
    z=sum(z,masked);out["producer/z_sum_"+std::to_string(k)]=z;
  }
  z=sum(z,threshold);out["producer/output_z"]=z;
  for(long slot=0;slot<kSlots;++slot)need(z[slot]==producer::residue(expected.x[slot]-expected.y[slot]),"oracle Z=X-Y");
  out["comparison"]=layout.comparison;
  Slots support=shifted_support(0);std::vector<Slots> winners;
  for(long candidate=0;candidate<8;++candidate) {
    std::vector<Slots> leaves;
    for(long lane=0;lane<8;++lane) {
      long index=8*candidate+lane;auto leaf=shifted(layout.comparison,kSupport[index]);
      out["native/leaf_"+std::to_string(index)]=leaf;
      if(spec[index].weak) {
        const auto mask=shifted(support,kSupport[index]);
        for(long s=0;s<kSlots;++s)leaf[s]=producer::residue(mask[s]-leaf[s]);
        out["native/weak_"+std::to_string(index)]=leaf;
      }
      leaves.push_back(std::move(leaf));
    }
    for(long pair=0;pair<4;++pair) {
      leaves[2*pair]=product(leaves[2*pair],leaves[2*pair+1]);
      out["native/pair_"+std::to_string(4*candidate+pair)]=leaves[2*pair];
    }
    for(long quarter=0;quarter<2;++quarter) {
      leaves[4*quarter]=product(leaves[4*quarter],leaves[4*quarter+2]);
      out["native/quarter_"+std::to_string(2*candidate+quarter)]=leaves[4*quarter];
    }
    auto winner=product(leaves[0],leaves[4]);out["native/winner_"+std::to_string(candidate)]=winner;
    need(winner==layout.winners[candidate],"oracle winner");winners.push_back(std::move(winner));
  }
  auto selected=winners[0];
  for(long i=1;i<8;++i) {
    auto weighted=winners[i];for(long& value:weighted)value=producer::residue((i+1)*value);
    out["native/weighted_"+std::to_string(i)]=weighted;selected=sum(selected,weighted);out["native/sum_"+std::to_string(i)]=selected;
  }
  out["native/final"]=selected;need(selected==layout.output&&out.size()==210,"all-stage oracle");return out;
}
