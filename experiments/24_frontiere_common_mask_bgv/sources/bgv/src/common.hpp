// Unchanged JSON, exclusive durable log, public hash and timer helpers from passed N8 gate.
std::string quote(const std::string& value)
{
  std::ostringstream out;
  out << '"';
  for (unsigned char c : value) {
    if (c == '"' || c == '\\') out << '\\' << c;
    else if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c);
    else out << c;
  }
  out << '"';
  return out.str();
}
struct Json {
  std::ostringstream out;
  bool first = true;
  Json() { out << '{' << std::setprecision(17); }
  void key(const char* name) { if (!first) out << ','; first = false; out << quote(name) << ':'; }
  template<class T> Json& add(const char* name, T value) { key(name); out << value; return *this; }
  Json& add(const char* name, const std::string& value) { key(name); out << quote(value); return *this; }
  Json& add(const char* name, const char* value) { return add(name, std::string(value)); }
  Json& add(const char* name, bool value) { key(name); out << (value ? "true" : "false"); return *this; }
  Json& add(const char* name, const std::vector<long>& values) {
    key(name); out << '[';
    for (std::size_t i = 0; i < values.size(); ++i) { if (i) out << ','; out << values[i]; }
    out << ']'; return *this;
  }
  std::string str() { return out.str() + "}\n"; }
};
class Log {
  int fd_ = -1;
public:
  explicit Log(const std::string& path) {
    if (path.empty() || path[0] != '/') throw std::runtime_error("absolute output path required");
    auto parent = path.substr(0, path.find_last_of('/'));
    struct stat st{};
    if (lstat(parent.c_str(), &st) || !S_ISDIR(st.st_mode) || (st.st_mode & 0777) != 0700)
      throw std::runtime_error("private real 0700 parent required");
    fd_ = open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd_ < 0) throw std::runtime_error("exclusive output creation failed");
    int dir = open(parent.c_str(), O_RDONLY | O_DIRECTORY);
    if (dir < 0) throw std::runtime_error("directory open failed");
    int sync = fsync(dir); close(dir);
    if (sync) throw std::runtime_error("directory sync failed");
  }
  ~Log() { if (fd_ >= 0) close(fd_); }
  void emit(Json& json) {
    auto bytes = json.str(); std::size_t done = 0;
    while (done < bytes.size()) {
      auto n = write(fd_, bytes.data() + done, bytes.size() - done);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) throw std::runtime_error("record write failed");
      done += static_cast<std::size_t>(n);
    }
    if (fsync(fd_)) throw std::runtime_error("record sync failed");
  }
};
void need(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::string env(const char* name) { const char* x = std::getenv(name); return x ? x : ""; }
bool hex64(const std::string& x) {
  return x.size() == 64 && x.find_first_not_of("0123456789abcdef") == std::string::npos;
}
struct HashBuffer : std::streambuf {
  std::uint64_t value = UINT64_C(14695981039346656037), bytes = 0;
  int_type overflow(int_type c) override {
    if (!traits_type::eq_int_type(c, traits_type::eof())) {
      value ^= static_cast<unsigned char>(c); value *= UINT64_C(1099511628211); ++bytes;
    }
    return traits_type::not_eof(c);
  }
  std::streamsize xsputn(const char* s, std::streamsize n) override {
    for (std::streamsize i = 0; i < n; ++i) overflow(static_cast<unsigned char>(s[i]));
    return n;
  }
};
std::string hex(std::uint64_t x) { std::ostringstream s; s << std::hex << std::setw(16) << std::setfill('0') << x; return s.str(); }
template<class T> std::string checksum(const T& object) {
  HashBuffer buffer; std::ostream stream(&buffer); object.writeTo(stream);
  need(stream.good(), "public object serialization failed"); return hex(buffer.value);
}
long calls(const char* name) { auto t = helib::getTimerByName(name); return t ? t->getNumCalls() : 0; }
void timers(Json& row) {
  row.add("multiplyBy_calls", calls("multiplyBy")).add("automorph_calls", calls("automorph"))
      .add("smartAutomorph_calls", calls("smartAutomorph")).add("frobenius_calls", calls("frobeniusAutomorph"))
      .add("multByConstant_calls",calls("multByConstant"));
}
