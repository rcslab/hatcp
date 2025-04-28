#pragma once

#include <cstdlib>
#include <string>
#include <unordered_map>
#include <random>
//#include <rocksdb/db.h>
#include "Generator.h"
#include "options.h"
#include <msg.pb.h>

#define DISABLE_EVIL_CONSTRUCTORS(name) \
	name(const name&) = delete; \
	void operator=(const name) = delete

class req_gen {
	protected:
		const int conn_id;
		char * send_buf;
		constexpr static int MAX_SEND_BUF_SIZE = 1024 * 1024;
	public:
		req_gen(const int id) : conn_id(id) { this->send_buf = new char[MAX_SEND_BUF_SIZE]; }; 
		virtual ~req_gen() { delete[] send_buf; };
		virtual int send_req(int fd) = 0;
		virtual int read_resp(int fd) = 0;
};

class touch_gen : public req_gen
{
	private:
		static constexpr const char* PARAM_GEN = "GEN";
		static constexpr const char* PARAM_GEN_DEFAULT = "fixed:64";
		static constexpr const char* PARAM_UPDATE = "UPDATE";
		static constexpr const int PARAM_UPDATE_DEFAULT = 0;
		Generator *wgen;
		Generator *ugen;
		int update_ratio;
	public:
		touch_gen(const int conn_id, std::unordered_map<std::string, std::string>* args);
		touch_gen() = delete;
		~touch_gen();
		DISABLE_EVIL_CONSTRUCTORS(touch_gen);
	 	int send_req(int fd);
		int read_resp(int fd);
};

class echo_gen : public req_gen
{
	private:
		static constexpr const char* PARAM_GEN = "GEN";
		static constexpr const char* PARAM_GEN_DEFAULT = "fixed:0";
		static constexpr const char* PARAM_CDELAY = "CDELAY";
		static constexpr const int PARAM_CDELAY_DEFAULT = 0;
		static constexpr const int DT_SZ = 100;
		static int delay_table[DT_SZ];
		static void populate_delay_table();
		static std::atomic<int> delay_table_populated;

		Generator *wgen;
		int cdelay;
		int get_delay();
	public:
		echo_gen(const int conn_id, std::unordered_map<std::string, std::string>* args);
		echo_gen() = delete;
		~echo_gen();
		DISABLE_EVIL_CONSTRUCTORS(echo_gen);
	 	int send_req(int fd);
		int read_resp(int fd);
};

#if 0
class http_gen : public req_gen
{
	private:
		std::string build_req();
		std::string method;
		std::unordered_map<std::string, std::string> headers;
		std::string uri;
		int major_ver;
		int minor_ver;
		static constexpr const int CONS_SZ = 1024 * 1024 * 4;
		static char cons_buf[CONS_SZ];
	public:
		http_gen(const int conn_id, const std::string& host, std::unordered_map<std::string, std::string>* args);
		http_gen() = delete;
		~http_gen();
		DISABLE_EVIL_CONSTRUCTORS(http_gen);
	 	int send_req(int fd);
		int read_resp(int fd);
};

class rdb_gen : public req_gen
{
	private:
		enum DistributionType : unsigned char {
			kFixed = 0,
			kUniform,
			kNormal
		};

		constexpr static int64_t TOTAL_KEYS = 50000000;
		constexpr static double GET_RATIO = 0.83;
		constexpr static double PUT_RATIO = 0.14;
		constexpr static double SEEK_RATIO = 0.03;
		constexpr static int KEYRANGE_NUM = 30;
		constexpr static double KEYRANGE_DIST_A = 14.18;
		constexpr static double KEYRANGE_DIST_B = -2.917;
		constexpr static double KEYRANGE_DIST_C = 0.0164;
		constexpr static double KEYRANGE_DIST_D = -0.08082;
		constexpr static double VALUE_THETA = 0;
		constexpr static double VALUE_K = 0.2615; 
		constexpr static double VALUE_SIGMA = 25.45;
		constexpr static int VALUESIZE_MIN = 100;
		constexpr static int VALUESIZE_MAX = 102400;
		constexpr static DistributionType VALUESIZE_DIST = kFixed;
		constexpr static int KEY_SIZE = 48;
		constexpr static double ITER_THETA = 0;
		constexpr static double ITER_K = 2.517;
		constexpr static double ITER_SIGMA = 14.236;
		constexpr static double READ_RANDOM_EXP_RANGE = 0.0;
		constexpr static bool IS_LITTLE_ENDIAN = true;
		constexpr static int FIXED_VALUE_SIZE = 100;
		// A good 64-bit random number generator based on std::mt19937_64
		class Random64 {
			private:
			std::mt19937_64 generator_;

			public:
			explicit Random64(uint64_t s) : generator_(s) { }

			// Generates the next random number
			uint64_t Next() { return generator_(); }

			// Returns a uniformly distributed value in the range [0..n-1]
			// REQUIRES: n > 0
			uint64_t Uniform(uint64_t n) {
				return std::uniform_int_distribution<uint64_t>(0, n - 1)(generator_);
			}

			// Randomly returns true ~"1/n" of the time, and false otherwise.
			// REQUIRES: n > 0
			bool OneIn(uint64_t n) { return Uniform(n) == 0; }

			// Skewed: pick "base" uniformly from range [0,max_log] and then
			// return "base" random bits.  The effect is to pick a number in the
			// range [0,2^max_log-1] with exponential bias towards smaller numbers.
			uint64_t Skewed(int max_log) {
				return Uniform(uint64_t(1) << Uniform(max_log + 1));
			}
		};

		struct KeyrangeUnit {
			int64_t keyrange_start;
			int64_t keyrange_access;
			int64_t keyrange_keys;
		};

		class GenerateTwoTermExpKeys {
			public:
				int64_t keyrange_rand_max_;
				int64_t keyrange_size_;
				int64_t keyrange_num_;
				bool initiated_;
				std::vector<KeyrangeUnit> keyrange_set_;

				GenerateTwoTermExpKeys() {
					keyrange_rand_max_ = TOTAL_KEYS;
					initiated_ = false;
				}

				~GenerateTwoTermExpKeys() {}

				// Initiate the KeyrangeUnit vector and calculate the size of each
				// KeyrangeUnit.
				rocksdb::Status InitiateExpDistribution(int64_t total_keys, double prefix_a,
												double prefix_b, double prefix_c,
												double prefix_d) {
					int64_t amplify = 0;
					int64_t keyrange_start = 0;
					initiated_ = true;
					if (KEYRANGE_NUM <= 0) {
						keyrange_num_ = 1;
					} else {
						keyrange_num_ = KEYRANGE_NUM;
					}
					keyrange_size_ = total_keys / keyrange_num_;

					// Calculate the key-range shares size based on the input parameters
					for (int64_t pfx = keyrange_num_; pfx >= 1; pfx--) {
					// Step 1. Calculate the probability that this key range will be
					// accessed in a query. It is based on the two-term expoential
					// distribution
					double keyrange_p = prefix_a * std::exp(prefix_b * pfx) +
										prefix_c * std::exp(prefix_d * pfx);
					if (keyrange_p < std::pow(10.0, -16.0)) {
						keyrange_p = 0.0;
					}
					// Step 2. Calculate the amplify
					// In order to allocate a query to a key-range based on the random
					// number generated for this query, we need to extend the probability
					// of each key range from [0,1] to [0, amplify]. Amplify is calculated
					// by 1/(smallest key-range probability). In this way, we ensure that
					// all key-ranges are assigned with an Integer that  >=0
					if (amplify == 0 && keyrange_p > 0) {
						amplify = static_cast<int64_t>(std::floor(1 / keyrange_p)) + 1;
					}

					// Step 3. For each key-range, we calculate its position in the
					// [0, amplify] range, including the start, the size (keyrange_access)
					KeyrangeUnit p_unit;
					p_unit.keyrange_start = keyrange_start;
					if (0.0 >= keyrange_p) {
						p_unit.keyrange_access = 0;
					} else {
						p_unit.keyrange_access =
							static_cast<int64_t>(std::floor(amplify * keyrange_p));
					}
					p_unit.keyrange_keys = keyrange_size_;
					keyrange_set_.push_back(p_unit);
					keyrange_start += p_unit.keyrange_access;
					}
					keyrange_rand_max_ = keyrange_start;

					// Step 4. Shuffle the key-ranges randomly
					// Since the access probability is calculated from small to large,
					// If we do not re-allocate them, hot key-ranges are always at the end
					// and cold key-ranges are at the begin of the key space. Therefore, the
					// key-ranges are shuffled and the rand seed is only decide by the
					// key-range hotness distribution. With the same distribution parameters
					// the shuffle results are the same.
					Random64 rand_loca(keyrange_rand_max_);
					for (int64_t i = 0; i < KEYRANGE_NUM; i++) {
					int64_t pos = rand_loca.Next() % KEYRANGE_NUM;
					assert(i >= 0 && i < static_cast<int64_t>(keyrange_set_.size()) &&
							pos >= 0 && pos < static_cast<int64_t>(keyrange_set_.size()));
					std::swap(keyrange_set_[i], keyrange_set_[pos]);
					}

					// Step 5. Recalculate the prefix start postion after shuffling
					int64_t offset = 0;
					for (auto& p_unit : keyrange_set_) {
					p_unit.keyrange_start = offset;
					offset += p_unit.keyrange_access;
					}

					return rocksdb::Status::OK();
				}

				// Generate the Key ID according to the input ini_rand and key distribution
				int64_t DistGetKeyID(int64_t ini_rand, double key_dist_a,
										double key_dist_b) {
					int64_t keyrange_rand = ini_rand % keyrange_rand_max_;

					// Calculate and select one key-range that contains the new key
					int64_t start = 0, end = static_cast<int64_t>(keyrange_set_.size());
					while (start + 1 < end) {
					int64_t mid = start + (end - start) / 2;
					assert(mid >= 0 && mid < static_cast<int64_t>(keyrange_set_.size()));
					if (keyrange_rand < keyrange_set_[mid].keyrange_start) {
						end = mid;
					} else {
						start = mid;
					}
					}
					int64_t keyrange_id = start;

					// Select one key in the key-range and compose the keyID
					int64_t key_offset = 0, key_seed;
					if (key_dist_a == 0.0 && key_dist_b == 0.0) {
					key_offset = ini_rand % keyrange_size_;
					} else {
					key_seed = static_cast<int64_t>(
						ceil(std::pow((ini_rand / key_dist_a), (1 / key_dist_b))));
					Random64 rand_key(key_seed);
					key_offset = static_cast<int64_t>(rand_key.Next()) % keyrange_size_;
					}
					return keyrange_size_ * keyrange_id + key_offset;
				}
		};

		// Decide the ratio of different query types
		// 0 Get, 1 Put, 2 Seek, 3 SeekForPrev, 4 Delete, 5 SingleDelete, 6 merge
		class QueryDecider {
			public:
				std::vector<int> type_;
				std::vector<double> ratio_;
				int range_;

				QueryDecider() {}
				~QueryDecider() {}

				rocksdb::Status Initiate(std::vector<double> ratio_input) {
					int range_max = 1000;
					double sum = 0.0;
					for (auto& ratio : ratio_input) {
						sum += ratio;
					}
						range_ = 0;
					for (auto& ratio : ratio_input) {
						range_ += static_cast<int>(ceil(range_max * (ratio / sum)));
						type_.push_back(range_);
						ratio_.push_back(ratio / sum);
					}
					return rocksdb::Status::OK();
				}

				int GetType(int64_t rand_num) {
					if (rand_num < 0) {
						rand_num = rand_num * (-1);
					}
					assert(range_ != 0);
					int pos = static_cast<int>(rand_num % range_);
					for (int i = 0; i < static_cast<int>(type_.size()); i++) {
						if (pos < type_[i]) {
							return i;
						}
					}
					return 0;
				}
		};

		class BaseDistribution {
		public:
		BaseDistribution(unsigned int _min, unsigned int _max)
			: min_value_size_(_min), max_value_size_(_max) {}
		virtual ~BaseDistribution() {}

		unsigned int Generate() {
			auto val = Get();
			if (NeedTruncate()) {
			val = std::max(min_value_size_, val);
			val = std::min(max_value_size_, val);
			}
			return val;
		}
		private:
		virtual unsigned int Get() = 0;
		virtual bool NeedTruncate() {
			return true;
		}
		unsigned int min_value_size_;
		unsigned int max_value_size_;
		};


		class FixedDistribution : public BaseDistribution
		{
		public:
		FixedDistribution(unsigned int size) :
			BaseDistribution(size, size),
			size_(size) {}
		private:
		virtual unsigned int Get() override {
			return size_;
		}
		virtual bool NeedTruncate() override {
			return false;
		}
		unsigned int size_;
		};

		class UniformDistribution
			: public BaseDistribution,
			public std::uniform_int_distribution<unsigned int> {
		public:
		UniformDistribution(unsigned int _min, unsigned int _max)
			: BaseDistribution(_min, _max),
				std::uniform_int_distribution<unsigned int>(_min, _max),
				gen_(rd_()) {}

		private:
		virtual unsigned int Get() override {
			return (*this)(gen_);
		}
		virtual bool NeedTruncate() override {
			return false;
		}
		std::random_device rd_;
		std::mt19937 gen_;
		};

		class NormalDistribution
			: public BaseDistribution, public std::normal_distribution<double> {
		public:
		NormalDistribution(unsigned int _min, unsigned int _max)
			: BaseDistribution(_min, _max),
				// 99.7% values within the range [min, max].
				std::normal_distribution<double>(
					(double)(_min + _max) / 2.0 /*mean*/,
					(double)(_max - _min) / 6.0 /*stddev*/),
				gen_(rd_()) {}

		private:
		virtual unsigned int Get() override {
			return static_cast<unsigned int>((*this)(gen_));
		}
		std::random_device rd_;
		std::mt19937 gen_;
		};


		class Random {
		private:
		enum : uint32_t {
			M = 2147483647L  // 2^31-1
		};
		enum : uint64_t {
			A = 16807  // bits 14, 8, 7, 5, 2, 1, 0
		};

		uint32_t seed_;

		static uint32_t GoodSeed(uint32_t s) { return (s & M) != 0 ? (s & M) : 1; }

		public:
		// This is the largest value that can be returned from Next()
		enum : uint32_t { kMaxNext = M };

		explicit Random(uint32_t s) : seed_(GoodSeed(s)) {}

		void Reset(uint32_t s) { seed_ = GoodSeed(s); }

		uint32_t Next() {
			// We are computing
			//       seed_ = (seed_ * A) % M,    where M = 2^31-1
			//
			// seed_ must not be zero or M, or else all subsequent computed values
			// will be zero or M respectively.  For all other values, seed_ will end
			// up cycling through every number in [1,M-1]
			uint64_t product = seed_ * A;

			// Compute (product % M) using the fact that ((x << 31) % M) == x.
			seed_ = static_cast<uint32_t>((product >> 31) + (product & M));
			// The first reduction may overflow by 1 bit, so we may need to
			// repeat.  mod == M is not possible; using > allows the faster
			// sign-bit-based test.
			if (seed_ > M) {
			seed_ -= M;
			}
			return seed_;
		}

		// Returns a uniformly distributed value in the range [0..n-1]
		// REQUIRES: n > 0
		uint32_t Uniform(int n) { return Next() % n; }

		// Randomly returns true ~"1/n" of the time, and false otherwise.
		// REQUIRES: n > 0
		bool OneIn(int n) { return Uniform(n) == 0; }

		// "Optional" one-in-n, where 0 or negative always returns false
		// (may or may not consume a random value)
		bool OneInOpt(int n) { return n > 0 && OneIn(n); }

		// Returns random bool that is true for the given percentage of
		// calls on average. Zero or less is always false and 100 or more
		// is always true (may or may not consume a random value)
		bool PercentTrue(int percentage) {
			return static_cast<int>(Uniform(100)) < percentage;
		}

		// Skewed: pick "base" uniformly from range [0,max_log] and then
		// return "base" random bits.  The effect is to pick a number in the
		// range [0,2^max_log-1] with exponential bias towards smaller numbers.
		uint32_t Skewed(int max_log) {
			return Uniform(1 << Uniform(max_log + 1));
		}

		// Returns a Random instance for use by the current thread without
		// additional locking
		static Random* GetTLSInstance();
		};

		static rocksdb::Slice RandomString(Random* rnd, int len, std::string* dst) {
		dst->resize(len);
		for (int i = 0; i < len; i++) {
			(*dst)[i] = static_cast<char>(' ' + rnd->Uniform(95));  // ' ' .. '~'
		}
		return rocksdb::Slice(*dst);
		}

		static rocksdb::Slice CompressibleString(Random* rnd, double compressed_fraction,
                                int len, std::string* dst) {
		int raw = static_cast<int>(len * compressed_fraction);
		if (raw < 1) raw = 1;
		std::string raw_data;
		RandomString(rnd, raw, &raw_data);

		// Duplicate the random data until we have filled "len" bytes
		dst->clear();
		while (dst->size() < (unsigned int)len) {
			dst->append(raw_data);
		}
		dst->resize(len);
		return rocksdb::Slice(*dst);
		}

		class RandomGenerator {
			private:
				std::string data_;
				unsigned int pos_;
				std::unique_ptr<BaseDistribution> dist_;

			public:

				RandomGenerator() {
					auto max_value_size = VALUESIZE_MAX;
					switch (VALUESIZE_DIST) {
					case kUniform:
						dist_.reset(new UniformDistribution(VALUESIZE_MIN,
															VALUESIZE_MAX));
						break;
					case kNormal:
						dist_.reset(new NormalDistribution(VALUESIZE_MIN,
														VALUESIZE_MAX));
						break;
					case kFixed:
					default:
						dist_.reset(new FixedDistribution(FIXED_VALUE_SIZE));
						max_value_size = FIXED_VALUE_SIZE;
					}
					// We use a limited amount of data over and over again and ensure
					// that it is larger than the compression window (32KB), and also
					// large enough to serve all typical value sizes we want to write.
					Random rnd(301);
					std::string piece;
					while (data_.size() < (unsigned)std::max(1048576, max_value_size)) {
					// Add a short fragment that is as compressible as specified
					// by FLAGS_compression_ratio.
					CompressibleString(&rnd, 0.5, 100, &piece);
					data_.append(piece);
					}
					pos_ = 0;
				}

				rocksdb::Slice Generate(unsigned int len) {
					assert(len <= data_.size());
					if (pos_ + len > data_.size()) {
					pos_ = 0;
					}
					pos_ += len;
					return rocksdb::Slice(data_.data() + pos_ - len, len);
				}

				rocksdb::Slice Generate() {
					auto len = dist_->Generate();
					return Generate(len);
				}
		};

		// The inverse function of Pareto distribution
		static int64_t ParetoCdfInversion(double u, double theta, double k, double sigma) {
			double ret;
			if (k == 0.0) {
				ret = theta - sigma * std::log(u);
			} else {
				ret = theta + sigma * (std::pow(u, -1 * k) - 1) / k;
			}
			return static_cast<int64_t>(ceil(ret));
		}


		static int64_t GetRandomKey(Random64* rand) {
			uint64_t rand_int = rand->Next();
			int64_t key_rand = 0;
			if (READ_RANDOM_EXP_RANGE == 0) {
				key_rand = rand_int % TOTAL_KEYS;
			}
			return key_rand;
		}

	  	static rocksdb::Slice AllocateKey(std::unique_ptr<const char[]>* key_guard, int key_size_) {
			char* data = new char[key_size_];
			const char* const_data = data;
			key_guard->reset(const_data);
			return rocksdb::Slice(key_guard->get(), key_size_);
		}

		static void GenerateKeyFromInt(uint64_t v, int64_t num_keys, int key_size_, rocksdb::Slice* key) {
			char* start = const_cast<char*>(key->data());
			char* pos = start;

			int bytes_to_fill = std::min(key_size_ - static_cast<int>(pos - start), 8);
			if (IS_LITTLE_ENDIAN) {
			for (int i = 0; i < bytes_to_fill; ++i) {
				pos[i] = (v >> ((bytes_to_fill - i - 1) << 3)) & 0xFF;
			}
			} else {
			memcpy(pos, static_cast<void*>(&v), bytes_to_fill);
			}
			pos += bytes_to_fill;
			if (key_size_ > pos - start) {
			memset(pos, '0', key_size_ - (pos - start));
			}
		}


	GenerateTwoTermExpKeys gen_exp;
	QueryDecider query;
	Random64 rand;
	RandomGenerator gen;
	rocksdb::Slice key;
	std::unique_ptr<const char[]> key_guard;

	public:
		rdb_gen(const int conn_id, std::unordered_map<std::string, std::string>* args);
		rdb_gen() = delete;
		~rdb_gen();
		DISABLE_EVIL_CONSTRUCTORS(rdb_gen);
	 	int send_req(int fd);
		int read_resp(int fd);
};
#endif
