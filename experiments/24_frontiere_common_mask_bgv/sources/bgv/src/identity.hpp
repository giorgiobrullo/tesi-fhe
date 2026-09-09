// Public serialization witnesses. No secret-key serialization or ciphertext mutation.
using NativeJson=nlohmann::json;
void field(Json& row,const char* name,const NativeJson& value) {row.key(name);row.out<<value.dump();}
std::string binary(const helib::Ctxt& ct) {
  std::ostringstream out(std::ios::out|std::ios::binary);ct.writeTo(out);
  need(out.good(),"ciphertext binary serialization");return out.str();
}
std::string sha256(const std::string& data) {
  need(data.size()<=std::numeric_limits<CC_LONG>::max(),"SHA input size");
  unsigned char bytes[CC_SHA256_DIGEST_LENGTH];
  need(CC_SHA256(data.data(),static_cast<CC_LONG>(data.size()),bytes)!=nullptr,"SHA256");
  std::ostringstream out;out<<std::hex<<std::setfill('0');
  for(unsigned char byte:bytes)out<<std::setw(2)<<unsigned(byte);
  return out.str();
}
std::string strong_hash(const helib::Ctxt& ct) {return sha256(binary(ct));}
std::string byte_hex(const std::string& data) {
  constexpr char alphabet[]="0123456789abcdef";std::string result;result.reserve(data.size()*2);
  for(unsigned char value:data) {result+=alphabet[value>>4];result+=alphabet[value&15];}
  return result;
}
NativeJson serialized_json(const helib::Ctxt& ct) {
  std::ostringstream out;ct.writeToJSON(out);need(out.good(),"ciphertext JSON serialization");
  auto value=NativeJson::parse(out.str());
  need(value.is_object()&&value.size()==4&&value.at("type")=="Ctxt","typed ciphertext JSON");
  const auto& content=value.at("content");
  const std::set<std::string> wanted{"ptxtSpace","noiseBound","primeSet","intFactor","ptxtMag","ratFactor","parts"};
  std::set<std::string> actual;for(auto it=content.begin();it!=content.end();++it)actual.insert(it.key());
  need(content.is_object()&&actual==wanted,"complete Ctxt JSON field schema");return value;
}
std::vector<long> prime_indices(const helib::Ctxt& ct) {
  std::vector<long> result;for(long i:ct.getPrimeSet())result.push_back(i);return result;
}
std::vector<long> prime_values(const helib::Ctxt& ct) {
  std::vector<long> result;for(long i:ct.getPrimeSet())result.push_back(ct.getContext().ithPrime(i));return result;
}
std::string decimal(const NTL::ZZ& value) {std::ostringstream out;out<<value;return out.str();}
long int_factor(const helib::Ctxt& ct) {return serialized_json(ct).at("content").at("intFactor").get<long>();}
void exact_capacity(Json& row,const helib::Ctxt& ct) {
  capacity(row,ct);
  row.add("prime_indices",prime_indices(ct)).add("prime_values",prime_values(ct))
      .add("q_decimal",decimal(ct.getContext().productOfPrimes(ct.getPrimeSet())))
      .add("intFactor",int_factor(ct)).add("ptxtSpace",ct.getPtxtSpace())
      .add("isCorrect",ct.isCorrect()).add("ciphertext_sha256",strong_hash(ct));
}
std::vector<std::string> polynomial_decimal(const NTL::ZZX& poly) {
  need(NTL::deg(poly)<65536,"polynomial phi_m geometry");std::vector<std::string> result;
  result.reserve(65536);for(long i=0;i<65536;++i)result.push_back(decimal(NTL::coeff(poly,i)));return result;
}
