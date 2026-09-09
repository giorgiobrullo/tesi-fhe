// Stage admission recorder and exception evidence; never mutates a ciphertext.
struct Trace {
  Log& log;
  const helib::EncryptedArray& ea;
  const NativeJson& public_pins;
  Ledger ledger;
  long snapshots=0,producer_snapshots=0,consumer_snapshots=0,public_polynomials=0;
  bool public_roundtrips=true,all_stages_admitted=true;
  NativeJson first_loss=nullptr,last_snapshot=nullptr;
  std::string attempted_stage,attempted_phase="server_setup";

  void progress(Json& row) const {
    row.add("completed_snapshots",snapshots).add("producer_snapshots",producer_snapshots)
        .add("consumer_snapshots",consumer_snapshots).add("public_polynomials",public_polynomials);
    ledger_fields(row,ledger);timers(row);timer_location(row);
  }
  void phase(const std::string& name) {attempted_stage.clear();attempted_phase=name;}
  void begin(const std::string& name) {
    attempted_stage=name;attempted_phase="named_stage";
    need(snapshots<210&&name==kStageSchedule[snapshots],"attempted named stage order");
  }
  void validate_public(const std::string& name,const NTL::ZZX& poly,const std::vector<long>& slots,double norm) const {
    const auto& expected=public_pins.at(name);
    need(expected.at("slots")==slots,"actual public slot pin");
    need(expected.at("coefficients").size()==65536,"public coefficient pin geometry");
    for(long i=0;i<65536;++i)need(NTL::coeff(poly,i)==NTL::to_ZZ(expected.at("coefficients")[i].get<long>()),"actual public coefficient pin");
    const double expected_norm=expected.at("embedding_norm").get<double>();
    need(std::abs(norm-expected_norm)<=std::max(1e-6,1e-10*expected_norm),"actual public norm numerical screen");
  }
  bool capture(const std::string& name,const helib::Ctxt& ct,bool from_producer,
               double norm=0,const NTL::ZZX* poly=nullptr,const std::vector<long>* slots=nullptr) {
    need(attempted_stage==name&&snapshots<210&&name==kStageSchedule[snapshots],"captured named stage order");
    ++snapshots;if(from_producer)++producer_snapshots;else ++consumer_snapshots;
    Json row;row.add("type","stage").add("stage",name).add("ciphertext_fnv1a64",checksum(ct));
    exact_capacity(row,ct);need(bool(poly)==bool(slots),"public observation pair");
    if(poly) {
      validate_public(name,*poly,*slots,norm);
      public_roundtrips &= plaintext_record(row,ea,*poly,*slots,norm);++public_polynomials;
      need(public_roundtrips,"native public polynomial roundtrip");
    } else row.add("plaintext_present",false);
    progress(row);log.emit(row);last_snapshot=NativeJson::parse(row.str());
    const bool capacity_failed=ct.bitCapacity()<=0,library_failed=!ct.isCorrect();
    if(all_stages_admitted&&(capacity_failed||library_failed)) {
      all_stages_admitted=false;
      Json loss;loss.add("type","admission_loss").add("stage",name)
          .add("capacity_predicate_failed",capacity_failed).add("library_predicate_failed",library_failed)
          .add("all_stages_admitted",false).add("client_decryptions",0)
          .add("capacity_bits",ct.bitCapacity()).add("isCorrect",ct.isCorrect())
          .add("ciphertext_sha256",strong_hash(ct));progress(loss);
      first_loss=NativeJson::parse(loss.str());log.emit(loss);
    }
    phase("between_named_stages");return true;
  }
  void exception(const std::string& error) {
    Json current;timers(current);const auto actual=NativeJson::parse(current.str());
    Json row;row.add("type","server_exception").add("status","INCOMPLETE")
        .add("error",error).add("attempted_phase",attempted_phase)
        .add("server_graph_complete",false).add("all_stages_admitted",all_stages_admitted)
        .add("partial_work_may_exceed_completed_prefix",true).add("client_decryptions",0)
        .add("terminal_decrypt_attempts",0).add("server_result_promoted",false);
    field(row,"attempted_stage",attempted_stage.empty()?NativeJson(nullptr):NativeJson(attempted_stage));
    field(row,"last_completed_stage",last_snapshot.is_null()?NativeJson(nullptr):last_snapshot.at("stage"));
    field(row,"last_completed_snapshot_state",last_snapshot);field(row,"actual_server_timers",actual);
    field(row,"first_admission_loss",first_loss);field(row,"terminal_semantic_pass",nullptr);log.emit(row);
    Json summary;summary.add("type","summary").add("status","INCOMPLETE").add("gate_pass",false)
        .add("server_graph_complete",false).add("structural_checks_pass",false)
        .add("all_stages_admitted",all_stages_admitted).add("terminal_observation_status","NOT_ATTEMPTED")
        .add("terminal_decrypt_attempts",0).add("client_decryptions",0).add("server_result_promoted",false)
        .add("timing_claim",false);
    field(summary,"terminal_semantic_pass",nullptr);field(summary,"first_admission_loss",first_loss);
    field(summary,"last_completed_snapshot_state",last_snapshot);field(summary,"actual_server_timers",actual);log.emit(summary);
  }
};
