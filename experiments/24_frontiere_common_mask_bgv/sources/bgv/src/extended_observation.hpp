// Preserve an NTL xdouble without requiring a representable ordinary double.
// The original double field is nullable diagnostic data; exponent/log witnesses are explicit.
void extended_number(Json& row,const char* name,const NTL::xdouble& value) {
  static_assert(sizeof(double)==8&&std::numeric_limits<double>::is_iec559,"binary64 observation");
  need(value>=0&&std::isfinite(value.mantissa()),"finite nonnegative extended observation");
  const bool positive=value>0;
  std::uint64_t mantissa_bits=0;
  const double mantissa=value.mantissa();std::memcpy(&mantissa_bits,&mantissa,sizeof(mantissa_bits));
  std::ostringstream bits;bits<<std::hex<<std::setw(16)<<std::setfill('0')<<mantissa_bits;
  const nlohmann::json witness{{"mantissa",mantissa},{"mantissa_binary64_hex",bits.str()},
      {"exponent",value.exponent()},{"exponent_unit_bits",2*NTL_XD_HBOUND_LOG},
      {"sign_class",positive?"positive":"zero"}};
  row.key((std::string(name)+"_xdouble").c_str());row.out<<witness.dump();
  row.key(name);
  const double ordinary=NTL::conv<double>(value);
  if(std::isfinite(ordinary)&&(!positive||ordinary>0))row.out<<ordinary;
  else row.out<<"null";
  row.key((std::string(name)+"_log2").c_str());
  if(positive) {
    const double logarithm=NTL::log(value)/std::log(2.0);
    need(std::isfinite(logarithm),"finite extended logarithm");row.out<<logarithm;
  } else row.out<<"null";
}
