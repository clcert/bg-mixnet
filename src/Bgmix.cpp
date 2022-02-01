#include "Bgmix.h"

#include "CipherTable.h"
#include "Globals.h"
#include "Functions.h"
#include <string.h>
#include "RemoteShuffler.h"
#include "FakeZZ.h"
#include "SchnorrProof.h"

#include <cmath>
#include <stdlib.h>
#include <time.h>
#include <map>
#include <stdio.h>
#include <mutex>
using namespace std;

mutex gInitMutex;

extern G_q H;
extern G_q G;

static bool kIsInit = false;

static vector<long> num(8);

void init_private_key(ElGammal* elgammal, int key_id) {
	ZZ secret;
        string private_key_file = string("config/keys/priv") + to_string(key_id);
#if USE_REAL_POINTS
        ZZFromBytes(secret, skeys[key_id], 32);
#else
	string line;
	ifstream sist;
	sist.open(private_key_file);
	getline(sist, line);

	getline(sist, line);
	istringstream secretstr(line);
	secretstr >> secret;
#endif
	elgammal->set_group(G);
	elgammal->set_sk(secret);
}

void* create_pub_key(int key_id) {
	Mod_p pk;
#if USE_REAL_POINTS
        // private key is
        // {0x50, 0x44, 0x4f, 0x53, 0x0, ...}
        CurvePoint pk_ = raw_curve_pt(pkeys[key_id]);
        // TODO this does not handle garbage collection
        pk = Mod_p(pk_, G.get_mod());
#else
	string fname = string("config/keys/pub") + to_string(key_id);
	ifstream ist;
	ist.open(fname);
	if (ist.fail()) {
		cout << "cannot open key file " << fname <<endl;
		exit(1); // TODO should probably raise an exception
	} 
	string line;
	getline(ist, line);
	istringstream pkstr(line);
	pkstr >> pk;
	ist.close();
#endif

	ElGammal* ret = new ElGammal();
	ret->set_group(G);
	ret->set_pk(pk);
	return ret;
}

void* create_decryption_key(int key_id) {
	ElGammal* elgammal = new ElGammal();
	init_private_key(elgammal, key_id);
	return (void*)elgammal;
}

void delete_key(void* elgammal) {
	ElGammal* tmp = (ElGammal*) elgammal;
	delete tmp;
}


void init() {
	lock_guard<mutex> guard(gInitMutex);

	if (kIsInit) return;
	Functions::read_config(kConfigFile, num, genq);

#if USE_REAL_POINTS
        CurvePoint gen = curve_basepoint();
        ZZ ord = ZZ(NTL::conv<NTL::ZZ>("7237005577332262213973186563042994240857116359379907606001950938285454250989"));
        // ZZ mod = ZZ(NTL::conv<NTL::ZZ>("2093940378184301311653365957372856779274958817946641127345598909177821235333110899157852449358735758089191470831461169154289110965924549400975552759536367817772197222736877807377880197200409316970791234520514702977005806082978079032920444679504632247059010175405894645810064101337094360118559702814823284408560044493630320638017495213077621340331881796467607713650957219938583"));
        ZZ mod = ZZ(NTL::conv<NTL::ZZ>("42"));
#else
        NTL::ZZ gen_sc = NTL::conv<NTL::ZZ>("1929181099559129674691211513194785872536670409492790905276619913671396722443243145931673445424440902236760877484211441680348197072495215150053603001343967365713940597148603897520835948403066356627154482171157913975934174689003578096019980791028264452409955094293631742810957258379488668086855090084223965396993821991583550151470397960480522495500106360092070361350077271147228");
		//NTL::ZZ gen_sc = NTL::conv<NTL::ZZ>("14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533");
        CurvePoint gen = zz_to_curve_pt(gen_sc);
        ZZ ord = ZZ(NTL::conv<NTL::ZZ>("1257206741114416297422800737364843764556936223541"));
		//ZZ ord = ZZ(NTL::conv<NTL::ZZ>("61329566248342901292543872769978950870633559608669337131139375508370458778917"));
        ZZ mod = ZZ(NTL::conv<NTL::ZZ>("2093940378184301311653365957372856779274958817946641127345598909177821235333110899157852449358735758089191470831461169154289110965924549400975552759536367817772197222736877807377880197200409316970791234520514702977005806082978079032920444679504632247059010175405894645810064101337094360118559702814823284408560044493630320638017495213077621340331881796467607713650957219938583"));
		//ZZ mod = ZZ(NTL::conv<NTL::ZZ>("16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071"));
#endif

        G = G_q(gen, ord, mod);
        H = G_q(gen, ord, mod);
	
	m = num[1];
	kIsInit = true;
}

string key_index_to_fname(int key_index) {
	return string("config/keys/pub") + to_string(key_index);
}


vector<vector<ZZ> >* buildSecretsVector(const unsigned char** secrects, int secretLen, int n) {
	vector<vector<ZZ> >* ret = new vector<vector<ZZ> >(m);
	for (int i = 0; i < m; i++)
		ret->at(i) = vector<ZZ>(n);

	#pragma omp parallel for collapse(2) num_threads(num_threads) if(parallel)
	for (int i = 0; i < m; i++)
		for (int j = 0; j < n; j++)
			ret->at(i).at(j) = ZZFromBytes(secrects[i*j], secretLen) % H.get_ord();
	return ret;
}

struct ciphertexts_and_proofs {
  CipherTable *ciphertexts;
  char *proofs;
  int proofs_size;
};

void* encrypt_with_proof(void** in_secrets, int secretLen, int arrayLen, int keyIndex) {
	init();
	const unsigned char** secrects = (const unsigned char**) in_secrets;
	ElGammal* elgammal = (ElGammal*)create_pub_key(keyIndex);
	int num_cols = Functions::get_num_cols(m, arrayLen);
	CipherTable* ret = new CipherTable();
	vector<vector<ZZ> >* my_secrets = buildSecretsVector(secrects, secretLen, num_cols);

        struct ciphertexts_and_proofs *s = (struct ciphertexts_and_proofs *) malloc(sizeof(struct ciphertexts_and_proofs));
        s->proofs_size = SchnorrProof::bytesize * m * num_cols;
        s->proofs = new char[s->proofs_size];
	Functions::createCipherWithProof(my_secrets, m, num_cols, arrayLen, ret->getCMatrix(), ret->getElementsMatrix(), s->proofs, elgammal);

	ret->set_dimensions(m, num_cols);
	delete my_secrets;
	delete_key(elgammal);
        s->ciphertexts = ret;
	return s;
}

void* encrypt_cipher_part(void* cipher_and_proof) {
  struct ciphertexts_and_proofs *s = (struct ciphertexts_and_proofs *) cipher_and_proof;
  return s->ciphertexts;
}

void* encrypt_proof_part(void* cipher_and_proof, int* proof_size) {
  struct ciphertexts_and_proofs *s = (struct ciphertexts_and_proofs *) cipher_and_proof;
  *proof_size = s->proofs_size;
  return s->proofs;
}

void delete_ciphers_with_proof(void* x) {
  struct ciphertexts_and_proofs *s = (struct ciphertexts_and_proofs *) x;
  delete_ciphers(s->ciphertexts);
  delete[] s->proofs;
  free(s);
}

int verify_encrypt(void* ciphertexts, int ciphertexts_size, void* pfs, int proofs_size) {
  init();
  int num_elems = proofs_size / SchnorrProof::bytesize;
  int num_cols = num_elems / m;
  CipherTable *ct = (CipherTable*) parse_ciphers(ciphertexts, ciphertexts_size, 0); // TODO check this doesn't segfault
  char *proofs = (char *) pfs;

  volatile int verified = 1;
  #pragma omp parallel for collapse(2) num_threads(num_threads) if(parallel)
  for (int i = 0; i < m; i++) {
    for (int j = 0; j < num_cols; j++) {
      char *proof = &proofs[(i*num_cols + j) * SchnorrProof::bytesize];
      SchnorrProof pf = SchnorrProof(proof);
      Cipher_elg c = ct->get_elg_cipher(i, j);
      CurvePoint x = c.get_u();

      if (pf.verify(x) == 0) {
        verified = 0;
      }
    }
  }
  delete ct;

  return verified;
}

void* elg_encrypt(void** in_secrets, int secretLen, ElGammal *elgammal, int keyIndex, long n) {
	init();
	const unsigned char** secrects = (const unsigned char**) in_secrets; 
	CipherTable* ret = new CipherTable();
	vector<vector<ZZ> >* my_secrets = buildSecretsVector(secrects, secretLen, n);
	Functions::createCipher(my_secrets, m, n, ret->getCMatrix(), ret->getElementsMatrix(), elgammal);
	ret->set_dimensions(m, n);
	delete my_secrets;
	return ret;
}

void* get_ciphertexts(void* in_table, void* in_len, void* in_elmenent_size) {
	int* elmenent_size = (int*) in_elmenent_size;
	int* len = (int*) in_len;
	CipherTable* cipher_table = (CipherTable*)in_table;
	string encoded(cipher_table->encode_all_ciphers());
	*len = encoded.size();
	*elmenent_size = (*len) / (cipher_table->rows() * cipher_table->cols());
	char* out = new char[*len];
	memcpy(out, encoded.c_str(), *len);
	return (void*) out;
}

void* get_element(void* in_table, int index, void* in_len) {
	int* len = (int*) in_len;
	CipherTable* cipher_table = (CipherTable*)in_table;
	int i = index / cipher_table->cols();
	int j = index % cipher_table->cols();

        // use canonical serialization
#if USE_REAL_POINTS
        CurvePoint pt = cipher_table->getElementsMatrix()->at(i)->at(j).get_val();
        *len = 32; // TODO is this correct?
        char* out = new char[*len];
        pt.serialize_canonical(out);
#else
	string encoded(cipher_table->getElement(i, j));
	*len = encoded.size();
	char* out = new char[*len];
	memcpy(out, encoded.c_str(), *len);
#endif
	return (void*)out;
}

void delete_ciphers(void* in_table) {
	CipherTable* cipher_table = (CipherTable*)in_table;
	delete cipher_table;
}

int rows(void* cipher_table) {
	return ((CipherTable*) cipher_table)->rows();
}

int cols(void* cipher_table) {
	return ((CipherTable*) cipher_table)->cols();
}

void* get_cipher(void* cipher_table, int i, int j, void* in_len) {
	int* len = (int*) in_len;
	CipherTable* ct = (CipherTable*) cipher_table;
	string cipher (ct->getCipher(i, j));
	*len = cipher.size();
	char* out = new char[*len];
	memcpy(out, cipher.c_str(), *len);
	return (void*) out;
}


void* parse_ciphers(void* in_ciphers, int len, void* elgammal) {
	unsigned char* ciphers = (unsigned char*) in_ciphers;
	long m = num[1];

	string c((char*)ciphers, len);
	return new CipherTable(c, m, (ElGammal*)elgammal);
}

void* decrypt_cipher(void* in_table, int i, int j, void* in_len, void* elgammal_in) {
	init();
	
	ElGammal* elgammal = (ElGammal*)elgammal_in;
	int* len = (int*) in_len;
	CipherTable* ciphers = (CipherTable*)in_table;
	Mod_p plain = elgammal->decrypt(ciphers->get_elg_cipher(i, j));

        // use canonical serialization
#if USE_REAL_POINTS
        CurvePoint pt = plain.get_val();
        *len = 32;
        char* out = new char[*len];
        pt.serialize_canonical(out);
#else
	stringstream elm_str;
	elm_str << plain;
	string encoded = elm_str.str();
	*len = encoded.size();
	char* out = new char[*len];
	memcpy(out, encoded.c_str(), *len);
#endif
	return (void*) out;
}

void delete_str(void* s) {
	delete [] (char*)s;
}


char**makeCharArray(int size) {
	return new char* [size];
}

void setArrayString(char **a, char *s, int index, int src_index, int size) {
	a[index] = new char [size];
	memcpy(a[index], s + src_index, size);
}

void freeCharArray(char **a, int size) {
	int i;
	for (i = 0; i < size; i++) {
		delete [] a[i];
	}
	delete [] a;
}

#ifdef LOG_CRYPTO_OUTPUT
void redirect_streams_to_log(ofstream &log, streambuf **saved_cout, streambuf **saved_cerr) {
	*saved_cout = cout.rdbuf();	// save cout buffer
	*saved_cerr = cerr.rdbuf();	// save cout buffer
	cout.rdbuf(log.rdbuf());		// redirect cout buffer to log file
	cerr.rdbuf(log.rdbuf());		// redirect cout buffer to log file
}

void redirect_log_to_streams(streambuf *saved_cout, streambuf *saved_cerr, ofstream &log) {
	cout.rdbuf(saved_cout);
	cerr.rdbuf(saved_cerr);
	log.close();
}
#endif

void usage(long m, long n) {
	cout << "Invalid number of rows (m): " << m << " or columns (n): " << n << endl;
	cout << "Requirements: 4^x = m for integer x > 2, n >= 4" <<endl;
	exit(1);
}

void check_usage(long m, long n) {
	if (m < 64 || n < 4)
		usage(m, n);
	// Check that m satisfies 4^x = m
	int i = 3;
	long pow_m = 64;
        while (pow_m < m)
		pow_m = pow(4, i++);
	if (pow_m > m)
		usage(m, n);
#if USE_REAL_POINTS
        cout << "Cryptosystem: ElGamal on elliptic curve (Curve25519) points" << endl;
#else
        cout << "Cryptosystem: ElGamal on big integers" << endl;
#endif
}

bool generate_ciphers(const char* ciphers_file, const char* publics_file, const char* proof_file, const long dim_m, const long dim_n,
					const char* g, const char* q, const char* p) {
#ifdef LOG_CRYPTO_OUTPUT
        // log file specified in config
	ofstream log(LOG_CRYPTO_OUTPUT, ofstream::out | ofstream::app);
	streambuf *saved_cout, *saved_cerr;
	redirect_streams_to_log(log, &saved_cout, &saved_cerr);
	cout << __func__ << "(): Log messages in file " << LOG_CRYPTO_OUTPUT << endl;
#endif
	init_specified(g, q, p);
	// Override config file's cipher matrix dimensions
	num[1] = dim_m;
	num[2] = dim_n;

	// m is global; see Globals.h
	m = num[1];
	long n = num[2];

	check_usage(m, n);

	const int SECRET_SIZE = 5;
	unsigned char** secrets = new unsigned char* [m * n];

	srand ((unsigned int) time (NULL));

	for (int i = 0; i < m * n; i++) {
		secrets[i] = new unsigned char[SECRET_SIZE];
		for (int j = 0; j < SECRET_SIZE; j++) {
			secrets[i][j] = (char)rand();
		}
	}

	ElGammal* elgammal = (ElGammal*)create_pub_key(1);

	time_t begin = time(NULL);
	CipherTable* ciphers = (CipherTable*) elg_encrypt((void**) secrets,
						SECRET_SIZE, elgammal, 1, n);
	time_t enc_time = time(NULL);
	cout << "encryption time: " << enc_time - begin << endl; 

	Functions::write_crypto_ciphers_to_file(ciphers_file, publics_file, proof_file, ciphers, NULL,
							elgammal, "", "", m, n);

	for (int i = 0; i < m * n; i++) {
		delete [] secrets[i];
	}
	delete [] secrets;
	delete ciphers;
	delete elgammal;

#ifdef LOG_CRYPTO_OUTPUT
	redirect_log_to_streams(saved_cout, saved_cerr, log);
#endif
	return true;
}

// requires shuffle_internal to be called first and cached data must be passed in
// on exit, deletes cached shuffle data
// TODO cache freeing function may be cleaner interface
void prove(void *cache_data, string &proof, string &pubv, const char* g, const char* q, const char* p) {
	init_specified(g, q, p);
	RemoteShuffler *P = (RemoteShuffler*) cache_data;

	proof = P->create_nizk();
	pubv = P->get_public_vector();

        delete P;
}

int verify(void *elgammal, string &proof, void* ciphers_in, void* post_shuffle_cipehrs, string &public_randoms,
			const char* g, const char* q, const char* p) {
	init_specified(g, q, p);
	CipherTable *c = (CipherTable *)ciphers_in;
	CipherTable *C = (CipherTable *)post_shuffle_cipehrs;
	
	if ((c->rows() != C->rows()) || (c->cols() != C->cols())) {
		return false;
	}

	istringstream respstream(public_randoms);
	// Replication of RemoteShuffler initialization's global effect
	extern long mu;
	extern long mu_h;
	mu = 4;
	mu_h = 2*mu-1;

	VerifierClient V(num, C->rows(), C->cols(), c->getCMatrix(), C->getCMatrix(), (ElGammal*)elgammal, false, true);
	V.set_public_vector(respstream, c->cols(), num[3], num[7], num[4]);
	if (V.process_nizk(proof)) {
		return 1;
	}
	return 0;
}

bool mix(const char* ciphers_file, const char* publics_file, const char* proof_file, const long dim_m, const long dim_n,
		const char* g, const char* q, const char* p) {
#ifdef LOG_CRYPTO_OUTPUT
        // log file specified in config
	ofstream log(LOG_CRYPTO_OUTPUT, ofstream::out | ofstream::app);
	streambuf *saved_cout, *saved_cerr;
        redirect_streams_to_log(log, &saved_cout, &saved_cerr);
	cout << __func__ << "(): Log messages in file " << LOG_CRYPTO_OUTPUT << endl;
#endif
	init_specified(g, q, p);
	// Override config file's cipher matrix dimensions
	num[1] = dim_m;
	num[2] = dim_n;

	// m is global; see Globals.h
	m = num[1];
	long n = num[2];

	check_usage(m, n);

	CipherTable* input_ciphers = new CipherTable();
	input_ciphers->set_dimensions(m, n);
	vector<vector<Cipher_elg>* >* cm = input_ciphers->getCMatrix();

	cout << "Load and parse ciphers...";
	ElGammal *elgammal = Functions::set_crypto_ciphers_from_json(ciphers_file,
									*cm, m, n);
	cout << "completed." << endl;
	cout << "Shuffling " << n * m << " messages (m: " << m << ", n: " << n << ")" << endl;

	string proof;
	int* permutation;
	int permutation_len;
	string public_randoms;
	
	time_t shuffle_time = time(NULL);
	void *cached_shuffle = shuffle_internal(elgammal, m*n, input_ciphers, &permutation, &permutation_len);
	CipherTable* shuffled_ciphers = new CipherTable(((RemoteShuffler*)cached_shuffle)->getC(), m, true);
	cout << "Shuffle is done! In " << time(NULL) - shuffle_time << endl;
        time_t prove_time = time(NULL);
	prove(cached_shuffle, proof, public_randoms, g, q, p);
	cout << "Proof is done! In " << time(NULL) - prove_time << endl;

	time_t verify_time = time(NULL);
	int ret = verify(elgammal, proof, input_ciphers, shuffled_ciphers, public_randoms, g, q, p);
	cout << "verification is done! In " << time(NULL) - verify_time << endl;
	cout << "Shuffle + prove + verify = " << time(NULL) - shuffle_time << endl;

	// Added public randoms, changes file output
	Functions::write_crypto_ciphers_to_file(ciphers_file, publics_file, proof_file, input_ciphers,
						shuffled_ciphers, elgammal, proof, public_randoms, m, n);
	delete elgammal;
	delete input_ciphers;
	delete shuffled_ciphers;
	delete [] permutation;

	if (ret) {
		cout << "everything passed!" <<endl;
	} else {
		cout << "shuffle failed!" <<endl;
	}

#ifdef LOG_CRYPTO_OUTPUT
	redirect_log_to_streams(saved_cout, saved_cerr, log);
#endif

	return ret;
}

void hello() {
	printf("hello world!\n");
}

// returns a pointer caching shuffle data
void *shuffle_internal(void* reenc_key, int number_of_elements, void *ciphers, int** permutation, int* permutation_len) {
	init();

	CipherTable *input_ciphers = (CipherTable *)ciphers;
	int number_of_cols = Functions::get_num_cols(m, number_of_elements);

	RemoteShuffler *P = new RemoteShuffler(num, input_ciphers->getCMatrix(), (ElGammal*)reenc_key, m, number_of_cols, false);
	
	vector<long> reversed;
	P->reverse_permutation(reversed);
	*permutation_len = reversed.size();
	int* out_perm = new int[*permutation_len];
	for (int i = 0; i < *permutation_len; i++) {
		out_perm[i] = reversed.at(i);
	}
	*permutation = out_perm;

        return P;
}

void delete_int_arr(int* x) {
	delete [] x;
}

int get_int_elem(int* arr, int i) {
	return arr[i];
}

/**
 * @brief Validation of mix's proof
 * 
 * @param ciphers_file Filename containing mix results
 * @param dim_m Number of rows in cipher matrix
 * @param dim_n Number of columns in cipher matrix
 * @return true The mix was validated correctly
 * @return false The mix could not be validated
 */
bool validate_mix(const char* ciphers_file, const char* publics_file, const char* proof_file,
					const long dim_m, const long dim_n, const char* g, const char* q, const char* p) {
	init_specified(g, q, p);
	
	num[1] = dim_m;
	num[2] = dim_n;

	m = num[1];
	long n = num[2];

	check_usage(m, n);

	// Pointers for cipher matrices
	CipherTable* input_ciphers = new CipherTable();
	CipherTable* shuffled_ciphers = new CipherTable();
	input_ciphers->set_dimensions(m, n);
	shuffled_ciphers->set_dimensions(m, n);
	vector<vector<Cipher_elg>*>* cm_in = input_ciphers->getCMatrix();
	vector<vector<Cipher_elg>*>* cm_sh = shuffled_ciphers->getCMatrix();

	string proof;
	string public_randoms;

	// Read from file
	ElGammal *elgammal = Functions::set_validation_vars_from_json(ciphers_file, publics_file, proof_file,
								*cm_in, *cm_sh, m, n, proof, public_randoms);

	// Run verification
	int ret = verify(elgammal, proof, input_ciphers, shuffled_ciphers, public_randoms, g, q, p);

	if (ret) {
		cout << "everything passed!" <<endl;
	} else {
		cout << "validation failed!" <<endl;
	}

	return ret;
}

/**
 * @brief Initializes the group
 * 
 * @param g group generator
 * @param q group order
 * @param p group modulus
 */
void init_specified(const char* g, const char* q, const char* p) {
	lock_guard<mutex> guard(gInitMutex);

	if (kIsInit) return;
	Functions::read_config(kConfigFile, num, genq);

	NTL::ZZ gen_sc = NTL::conv<NTL::ZZ>(g);
	CurvePoint gen = zz_to_curve_pt(gen_sc);
	ZZ ord = ZZ(NTL::conv<NTL::ZZ>(q));
	ZZ mod = ZZ(NTL::conv<NTL::ZZ>(p));

    G = G_q(gen, ord, mod);
    H = G_q(gen, ord, mod);
	
	m = num[1];
	kIsInit = true;
}

/**
 * @brief Initializes an ElGammal object with the public key as argument
 * 
 * @param y ElGamal's public key
 * @return ElGammal* 
 */
ElGammal* init_with_public_key(const char* y) {
	Mod_p pk;
	istringstream pkstr(y);
	pkstr >> pk;
	ElGammal* ret = new ElGammal();
	ret->set_group(G);
	ret->set_pk(pk);
	return ret;
}

/**
 * @brief Encrypts a single seccret into an ElGammal pair
 * 
 * @param secret secret to be encrypted
 * @return long* alpha, beta array
 */
char *encrypt_single_secret(char* secret, char* result, const char* g, const char* q, const char* p, const char* y) {
	init_specified(g, q, p);
	ElGammal* elgammal = (ElGammal*)init_with_public_key(y);
	Cipher_elg cipher = Functions::createSingleCipher(to_ZZ(secret), elgammal);
	stringstream cipher_str;
	cipher_str << cipher;
	string str = cipher_str.str();
	str = str.substr(1, str.size() -2);
	str.copy(result, str.size());
	return result;
}