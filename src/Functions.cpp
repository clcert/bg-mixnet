/*
 * Functions.cpp
 *
 *  Created on: 26.10.2010
 *      Author: stephaniebayer
 */

#include <string.h>
#include "Functions.h"
#include "G_q.h"
#include "Cipher_elg.h"
#include "FakeZZ.h"
#include "CurvePoint.h"
#include "SchnorrProof.h"
#include <mutex>
#include <iomanip>
#include <atomic>
NTL_CLIENT

#include <cmath>
#include <vector>
#include <iostream>
#include <time.h>
#include <fstream>
#include <sstream>
#include <random>
#include <unistd.h>
#include "sha256.h"

#include <string>
#include <map>
#include <algorithm> // erase()

using namespace std;

extern G_q G;
extern G_q H; 

//OpenMP config
extern bool parallel;
extern int num_threads;

static const int NR_JSON_KEYS = 8; // gen, ord, mod, public, proof, public_randoms, {original, mixed}_ciphers
static const int KEY_LENGTH = 50;
static const long SKIP_LENGTH = 1000000000000;
static const int VALUE_LENGTH = 10000;
static const int PROOF_LENGTH = 60000;	// Size of alternative buffer
static char raw_key[KEY_LENGTH];
static char value[VALUE_LENGTH];
static char p_value[PROOF_LENGTH];	// Alternative buffer to parse the proof
static char json_structure;
static string chars_clean(" :,\"[");


Functions::Functions() {}

Functions::~Functions() {}


void Functions::read_config(const string& name, vector<long> & num, ZZ & genq){
	ifstream ist, ist1;
	string line;
	vector<string> lines;
	long i;

	ist.open (name.c_str());
	if(!ist1) cout<<"Can't open "<< name.c_str();

	for(i=1; i<12; i++){
		getline(ist, line);
	}
	getline(ist, line);
	num[5]=tolong(line);

	for(i=1; i<=2; i++){
		getline(ist, line);
	}
	getline(ist, line);
	num[0]=tolong(line);

	for(i=1; i<=3; i++){
		getline(ist, line);
	}
	getline(ist, line);
	num[1]=tolong(line);
	getline(ist, line);
	num[2]=tolong(line);

	for(i=1; i<=2; i++){
		getline(ist, line);
	}
	getline(ist, line);
	num[4]=tolong(line);

	for(i=1; i<=2; i++){
		getline(ist, line);
	}
	getline(ist, line);
	num[7]=tolong(line);

	for(i=1; i<=2; i++){
		getline(ist, line);
	}
	getline(ist, line);
	num[3]=tolong(line);

	for(i=1; i<=4; i++){
		getline(ist, line);
	}
	getline(ist, line);
	num[6]=tolong(line);

	for(i=1; i<=5; i++){
		getline(ist, line);
	}
	getline(ist, line);
	if(line != "0"){
		ist.close();
	}
	else{
	}
}

// Added public_randoms
void Functions::write_crypto_ciphers_to_file(const char *ciphers_file, 
					const char *publics_file,
					const char *proof_file,
					CipherTable *ciphers,
					CipherTable *mixed_ciphers, ElGammal *elgammal,
					string proof, string public_randoms, long m, long n) {
	ofstream ofciphers;
	ofciphers.open(ciphers_file, ofstream::trunc);
	if (ofciphers.fail()) {
		cout << "cannot open ciphers file " << ciphers_file <<endl;
		exit(1); // TODO should probably raise an exception
	}
	G_q group = elgammal->get_group();

	ofciphers << "{";
	ofciphers << "\"g\": " << group.get_gen();
	ofciphers << ",\n";
	ofciphers << "\"q\": " << group.get_ord();
	ofciphers << ",\n";
	ofciphers << "\"p\": " << group.get_mod();
	ofciphers << ",\n";
	ofciphers << "\"y\": " << elgammal->get_pk();
	ofciphers << ",\n";
	ofciphers << "\"original_ciphers\": [";
	
	for (int i = 0; i < m; i++) {
		for (int j = 0; j < n; j++) {
			ofciphers << ciphers->getCipher(i, j);
			if (!(i == m-1 && j == n-1))
				ofciphers << ", ";
			//cout << "cipher " << i << " " << j << " : " << ciphers->getCipher(i, j) << endl;
		}
	}
    ofciphers << "],\n";

    ofciphers << "\"mixed_ciphers\": [";
	if (mixed_ciphers != NULL) {
		for (int i = 0; i < m; i++) {
			for (int j = 0; j < n; j++) {
				ofciphers << mixed_ciphers->getCipher(i, j);
				if (!(i == m-1 && j == n-1))
					ofciphers << ", ";
				//cout << "cipher " << i << " " << j << " : " << ciphers->getCipher(i, j) << endl;
			}
		}
	}
    ofciphers << "]\n";
    ofciphers << "}";
	ofciphers.close();

	// Pedersen commitment generators
	ofciphers.open(publics_file, ofstream::trunc);
	if (ofciphers.fail()) {
		cout << "cannot open publics file " << publics_file <<endl;
		exit(1);
	}
	ofciphers << public_randoms;
	ofciphers.close();

	// NIZK proof
	ofciphers.open(proof_file, ofstream::trunc);
	if (ofciphers.fail()) {
		cout << "cannot open proof file " << proof_file <<endl;
		exit(1);
	}
	ofciphers << proof;
	ofciphers.close();
}

void clean(string &s) {
	for (string::iterator it = chars_clean.begin(); it != chars_clean.end(); it++)
		s.erase(remove(s.begin(), s.end(), *it), s.end());
}

CurvePoint extract_set_cipher(const char *c_cipher) {
	CurvePoint cipher;
	string s_cipher(c_cipher);
	clean(s_cipher);
	istringstream is_cipher(s_cipher);
	is_cipher >> cipher;
	return cipher;
}

void parse_cipher_matrix(ifstream& ifciphers, vector<vector<Cipher_elg>* >& C,
				const long m, const long n) {
	CurvePoint alpha, beta;

	// Eat ":" and " " characters between the key and value
	ifciphers.ignore(VALUE_LENGTH, '[');
	// Get the '[' that is in front of us
	ifciphers.get(json_structure);
	json_structure = ifciphers.peek();
	if (json_structure == ']') {
		cerr << "Ciphers matrix is empty" << endl;
		exit(1);
	}

	for (int i = 0; i < m; i++) {
		C.push_back(new vector<Cipher_elg>());
		for (int j = 0; j < n; j++) {
			// Get alpha
			ifciphers.get(value, VALUE_LENGTH, ',');
			alpha = extract_set_cipher(value);

			// Get beta
			ifciphers.get(value, VALUE_LENGTH, ']');
			beta = extract_set_cipher(value);

			// H.get_mod(): see Cipher_elg.cpp::operator>>()
			C.at(i)->push_back(Cipher_elg(alpha, beta, H.get_mod()));
			ifciphers.get(json_structure); // get cipher's ']'
			ifciphers.get(json_structure);
			// Eat "," and " " characters between ciphers
			while (json_structure != '[' && json_structure != ']')
				ifciphers.get(json_structure);
			// Cipher matrix ended
			if (json_structure == ']')
				break;
		}
	}
}

void Functions::print_crypto(const map<string, string>& crypto) {
	cout << "generator: " << crypto.at("generator") << endl;
	cout << "modulus: " << crypto.at("modulus") << endl;
	cout << "order: " << crypto.at("order") << endl;
	cout << "public_key: " << crypto.at("public") << endl;
}

void Functions::print_cipher_matrix(const vector<vector<Cipher_elg>* >& C,
					const long m, const long n) {
	for (int i = 0; i < m; i++)
		for (int j = 0; j < n; j++)
		cout << "Cipher( " << i << ", " << j << "): " << C.at(i)->at(j) << endl;
}

string get_next_json_key(ifstream& ifciphers) {
	ifciphers.ignore(SKIP_LENGTH, '"');
	ifciphers.get(raw_key, KEY_LENGTH, ':');
	string json_key(raw_key);
	clean(json_key);
	return json_key;
}

bool find_json_key(ifstream& ifciphers, const string& json_key) {
	string current_key("");
	bool found = false;
	int i = 0;
	while (!found && !ifciphers.eof() && i < NR_JSON_KEYS) {
		i++;
		current_key = get_next_json_key(ifciphers);
		found = json_key == current_key;
	}
	return found;
}

void extract_fill_crypto(ifstream& ifciphers, map<string, string>& crypto,
				bool& passedby_ciphers) {
	string json_key;
	char value_delimiter;
	size_t iteration = 0;
	while (any_of(crypto.begin(), crypto.end(),
			[](map<string, string>::const_reference i){
				return i.second.empty();})) {
		iteration++;
		json_key = get_next_json_key(ifciphers);
		value_delimiter = iteration < NR_JSON_KEYS ? ',' : '}';

		try {
			crypto.at(json_key);
			ifciphers.get(value, VALUE_LENGTH, value_delimiter);
			string s_value(value);
			clean(s_value);
			crypto[json_key] = s_value;
		} catch (out_of_range e) {
			if (json_key == "original_ciphers") {
				passedby_ciphers = true;
			} else if (json_key == "mixed_ciphers") {
				;
			} else {
				cerr << "Unexpected json key " << json_key << endl;
				exit(1);
			}
		}
	}
}

void check_json_structure(ifstream &ifciphers) {
	ifciphers.get(json_structure);
	if (json_structure != '{') {
		cerr << "Unexpected structure" << endl;
		cerr << "Expected '{' found " << json_structure << endl;
		exit(1);
	}
}

ElGammal* Functions::set_crypto_ciphers_from_json(const char *ciphers_file,
			vector<vector<Cipher_elg>* >& C,
			const long m, const long n) {

	ifstream ifciphers;
	ifciphers.open(ciphers_file);
	if (ifciphers.fail()) {
		cerr << "cannot open ciphers file " << ciphers_file <<endl;
		exit(1);
	}

	check_json_structure(ifciphers);

	map<string, string> crypto {
		{"generator", ""},
		{"order", ""},
		{"modulus", ""},
		{"public", ""}
	};
	bool passedby_ciphers = false;
	extract_fill_crypto(ifciphers, crypto, passedby_ciphers);
	if (passedby_ciphers) {
		ifciphers.clear();
		ifciphers.seekg(0, ios::beg);
		check_json_structure(ifciphers);
	}

#if USE_REAL_POINTS
        // We should never be in here: Zeus works with ElGammal big ints
	CurvePoint generator = curve_basepoint();
        ZZ order = ZZ(NTL::conv<NTL::ZZ>("7237005577332262213973186563042994240857116359379907606001950938285454250989"));
        // ZZ mod = ZZ(NTL::conv<NTL::ZZ>("2093940378184301311653365957372856779274958817946641127345598909177821235333110899157852449358735758089191470831461169154289110965924549400975552759536367817772197222736877807377880197200409316970791234520514702977005806082978079032920444679504632247059010175405894645810064101337094360118559702814823284408560044493630320638017495213077621340331881796467607713650957219938583"));
        ZZ modulus = ZZ(NTL::conv<NTL::ZZ>("42"));
#else
	CurvePoint generator =
		zz_to_curve_pt(ZZ(NTL::conv<NTL::ZZ>(crypto["generator"].c_str())));
	ZZ order = NTL::conv<NTL::ZZ>(crypto["order"].c_str());
	ZZ modulus = NTL::conv<NTL::ZZ>(crypto["modulus"].c_str());
#endif
	// Override the init() setup
	G = G_q(generator, order, modulus);
	H = G_q(generator, order, modulus);

	ElGammal* elgammal = new ElGammal();
	elgammal->set_group(G);
	Mod_p pk;
	istringstream is_pk(crypto["public"]);
	is_pk >> pk;
	elgammal->set_pk(pk);

	string original_ciphers("original_ciphers");
	if (!find_json_key(ifciphers, original_ciphers)) {
		cerr << "Key 'original_ciphers' not found in JSON file" << endl;
		exit(1);
	}
	parse_cipher_matrix(ifciphers, C, m, n);
	ifciphers.close();

	return elgammal;
}


long Functions::tolong(string s){
	 //using namespace std;
	long n;
	stringstream ss(s); // Could of course also have done ss("1234") directly.


	 if( (ss >> n).fail() )
	 {
	    //error
	 }


	 return n;

}

string Functions::tostring(long n){

	stringstream ss;
	ss<<n;
	return ss.str();
}

//ygi:THIS IS IT PARAL
void Functions::createCipher(vector<vector<ZZ> >* secrets, int m, int n, vector<vector<Cipher_elg>* >* C, vector<vector<Mod_p>* >* elements, ElGammal* enc_key) {
	ZZ ord = H.get_ord();

	for (long i = 0; i < m; i++) {
		C->push_back(new vector<Cipher_elg>(n));
		elements->push_back(new vector<Mod_p>(n));
	}

	//PARALLELIZE
	#pragma omp parallel for collapse(2) num_threads(num_threads) if(parallel)
	for (long i=0; i<m; i++){
		for (long j = 0; j <n; j++){
			ZZ ran_2 = RandomBnd(ord);
			Cipher_elg temp;
			Mod_p ran_1;
			ran_1 = H.map_to_group_element(secrets->at(i).at(j));
			temp = enc_key->encrypt(ran_1, ran_2);
			C->at(i)->at(j)=temp;
			elements->at(i)->at(j) = ran_1;
		}
	}
}

void Functions::createCipherWithProof(vector<vector<ZZ> >* secrets, int m, int n, int N, vector<vector<Cipher_elg>* >* C, vector<vector<Mod_p>* >* elements, char* proofs, ElGammal* enc_key) {
	ZZ ord = H.get_ord();
	atomic<std::int32_t> count(1);

	for (long i = 0; i < m; i++) {
		C->push_back(new vector<Cipher_elg>(n));
		elements->push_back(new vector<Mod_p>(n));
	}

	//PARALLELIZE
	#pragma omp parallel for collapse(2) num_threads(num_threads) if(parallel)
	for (long i=0; i<m; i++){
		for (long j = 0; j <n; j++){
			ZZ ran_2 = RandomBnd(ord);
			Cipher_elg temp;
			Mod_p ran_1;
			if (count.fetch_add(1) <= N){
				ran_1 = H.map_to_group_element(secrets->at(i).at(j));
				temp = enc_key->encrypt(ran_1, ran_2);
			}
			else
			{
				ZZ x(RandomBnd(ord));
				ran_1 = H.map_to_group_element(x);
				temp = enc_key->encrypt(ran_1,ran_2);
			}
			C->at(i)->at(j)=temp;
			elements->at(i)->at(j) = ran_1;

                        SchnorrProof pf = SchnorrProof(ran_2);
                        int k = SchnorrProof::bytesize * (i*n + j);
                        pf.serialize(&proofs[k]);
		}
	}
}

void Functions::randomEl(vector<vector<ZZ>*>* R, int m, int n){
	vector<ZZ>* r = 0;
	ZZ ord;
	long i,j;
	ord= H.get_ord();
    
	for (i=0; i<m; i++){
		r = new vector<ZZ>(n);

		for (j = 0; j <n; j++){
			r->at(j) = RandomBnd(ord);
		}

		R->at(i)=r;
	}
}

vector<long> permutation2d_to_vector(vector<vector<vector<long>* >* >* pi, int m, int n) {
	vector<long> reversed_perm(m*n);
	int max = 0;
	for (long i = 0; i < m; i++) {
		for (long j = 0; j <n; j++){
			reversed_perm.at(n * i + j) = n * pi->at(i)->at(j)->at(0) + pi->at(i)->at(j)->at(1);
			if (reversed_perm.at(n * i + j) > max) {
				max = reversed_perm.at(n * i + j);
			} 
		}
	}
	
	cout << "The max: " << max <<endl;
	return reversed_perm;
}

bool test_perm(const vector<vector<vector<long>* >* >* pi, const vector<vector<vector<long> >* >* reversed, int m, int n) {
	cout << "testing the reverse" << endl;
	for (long i = 0; i < m; i++) {
		for (long j = 0; j <n; j++){
			int row = pi->at(i)->at(j)->at(0);
			int col = pi->at(i)->at(j)->at(1);
			
			int r_row = reversed->at(row)->at(col).at(0);
			int r_col = reversed->at(row)->at(col).at(1);
			if ((r_row != i) || (r_col != j)) {
				cout << "reversed permutation error! row " <<row << " -> " << r_row << endl;
				cout << "reversed permutation error! col " <<col << " -> " << r_col <<endl;
				return false;
			}
		}
	}
	return true;
}

vector<long> Functions::permutation2d_to_vector(vector<vector<vector<long>* >* >* pi, long m, long n) {
	vector<long> perm(m*n);
	for (long i = 0; i < m; i++) {
		for (long j = 0; j <n; j++){
			perm.at(n * i + j) = n * pi->at(i)->at(j)->at(0) + pi->at(i)->at(j)->at(1);
		}
	}
	return perm;	
}

void Functions::reencryptCipher( vector<vector<Cipher_elg>* >* C, vector<vector<Cipher_elg>* >* e, vector<vector<vector<long>* >* >* pi,vector<vector<ZZ>*>* R, int m, int n, ElGammal* reenc_pub_key){
	for (long i = 0; i < m; i++) {
		C->at(i) = new vector<Cipher_elg>(n);
	}

    //PARALLELIZE
    #pragma omp parallel for collapse(2) num_threads(num_threads) if(parallel)
	for (long i=0; i<m; i++){
		for (long j = 0; j <n; j++){
	        long row, col;
	        Cipher_elg temp = reenc_pub_key->encrypt(curve_zeropoint(),R->at(i)->at(j));
	        row = pi->at(i)->at(j)->at(0);
	        col = pi->at(i)->at(j)->at(1);
	        Cipher_elg::mult(C->at(i)->at(j), temp, e->at(row)->at(col));
		}
	}
}

//Returns the Hadamard product of x and y
void Functions::Hadamard(vector<ZZ>* ret, vector<ZZ>* x, vector<ZZ>* y){

	long n, m,i;
	ZZ ord=H.get_ord();
	n=x->size();
	m =y->size();

	if(m !=n){
		 cout<< "Not possible"<< endl;
	}
	else{
		 for (i = 0; i<n; i++){
			 MulMod(ret->at(i),x->at(i), y->at(i), ord);
		 }
	}
}

//returns the bilinear map of x and y, defined as x(y¡t)^T
ZZ Functions::bilinearMap(vector<ZZ>* x, vector<ZZ>* y, vector<ZZ>* t){
	long i, l;
	ZZ result,ord, tem;

	vector<ZZ>* temp = new vector<ZZ>(x->size());

	ord = H.get_ord();
	Hadamard(temp, y,t);
	l= x->size();
	result =0;
	for (i= 0; i<l; i++){
		MulMod(tem,x->at(i), temp->at(i), ord);
		AddMod(result, result, tem,ord);
	}
	delete temp;
	return result;
}

//help functions to delete matrices
void Functions::delete_vector(vector<vector<ZZ>* >* v){
	if (v == NULL) return;
	long i;
	long l = v->size();

	for(i=0; i<l; i++){
		delete v->at(i);
		v->at(i)=0;
	}
	delete v;
}


void Functions::delete_vector(vector<vector<long>* >* v){
	if (v == NULL) return;
	long i;
	long l = v->size();

	for(i=0; i<l; i++){
		delete v->at(i);
		v->at(i)=0;
	}
	delete v;
}
void Functions::delete_vector(vector<vector<Cipher_elg>* >* v){
	if (v == NULL) return;
	long i;
	long l = v->size();

	for(i=0; i<l; i++){
		delete v->at(i);
		v->at(i)=0;
	}
	delete v;
}


void Functions::delete_vector(vector<vector<vector<long>* >*>* v){
	if (v == NULL) return;
	long i;
	long l = v->size();

	for(i=0; i<l; i++){
		delete_vector(v->at(i));
	}
	delete v;
}

void Functions::delete_vector(vector<vector<vector<ZZ>* >*>* v){
	if (v == NULL) return;
	long i;
	long l = v->size();

	for(i=0; i<l; i++){
		delete_vector(v->at(i));
	}
	delete v;
}

//picks random value r and commits to the vector a,
void Functions::commit_op(vector<ZZ>* a, ZZ& r, Mod_p& com, Pedersen& ped){
	ZZ ord = H.get_ord();

	r = RandomBnd(ord);
	com = ped.commit_opt(a,r);
}


//picks random values r and commits to the rows of the matrix a, a,r,com are variables of Prover
void Functions::commit_op(vector<vector<ZZ>*>* a_in, vector<ZZ>* r, vector<Mod_p>* com, Pedersen& ped){
	long i,l;
	ZZ ord = H.get_ord();

	l=a_in->size();

	{
        //PARALLELIZE
        #pragma omp parallel for num_threads(num_threads) if(parallel)
		for(i=0; i<l; i++){
	        r->at(i) = RandomBnd(ord);
		}
	}
	
	{
        //PARALLELIZE
        #pragma omp parallel for num_threads(num_threads) if(parallel)
		for(i=0; i<l; i++){
	        com->at(i) = ped.commit_opt(a_in->at(i),r->at(i));
		}
	}
}


int Functions::get_num_cols(int m, int num_elements) {
	float converted = num_elements;
	float m_conv = m;
	
	int x = ceil(converted / m_conv);
	if (x < 4) x = 4;
	return x;
}

void Functions::parse_ciphers(string& s, long m, vector<vector<Cipher_elg>* >& C, ElGammal* elgammal) {
	string line;
	ZZ ran_2,ord;
	Cipher_elg temp;
	vector<Cipher_elg> parsed;
	ord=H.get_ord();
	//vector<vector<Cipher_elg>* >* C=new vector<vector<Cipher_elg>* >(m);

#if USE_REAL_POINTS
        for (unsigned int i = 0; i < s.size() / (CurvePoint::bytesize*2); i++) {
                CurvePoint u, v;
		u.deserialize(s.c_str() + i*CurvePoint::bytesize*2);
		v.deserialize(s.c_str() + i*CurvePoint::bytesize*2 + CurvePoint::bytesize);
                Cipher_elg ciph = Cipher_elg(u, v, H.get_mod());
		parsed.push_back(ciph);
        }
#else
        istringstream f(s);
	while (std::getline(f, line)) {
		if (line == "***") break;
		istringstream cipher_stream(line);
		Cipher_elg ciph;
		cipher_stream >> ciph;
		parsed.push_back(ciph);
    }
#endif

	unsigned long cols = get_num_cols(m, parsed.size());

	vector<Cipher_elg>* r = 0;
	int count = 0;
	for (unsigned int i=0; i<m; i++){
		r = new vector<Cipher_elg>(cols);
		for (unsigned int j = 0; j <cols; j++){
			if (cols * i + j < parsed.size()) {
				r->at(j) = parsed[cols * i + j];
			} else {
				ran_2 = RandomBnd(H.get_ord());
				r->at(j)=elgammal->encrypt(curve_zeropoint(),ran_2);
			}
			count ++;
		}
		
		
		C.push_back(r);
		//C->at(i)=r;
	}
}

unsigned int element_encode_size(vector<vector<Cipher_elg>* >* ciphers, unsigned int& total_ciphers) {
	unsigned int max = 0;
	total_ciphers = 0;
	for (unsigned int i=0; i< ciphers->size(); i++){
		for (unsigned int j = 0; j <ciphers->at(i)->size(); j++){
#if USE_REAL_POINTS
			max = 2 * CurvePoint::bytesize;
#else
			stringstream buffer;
			buffer << ciphers->at(i)->at(j);
			if (buffer.str().size() > max) {
				max = buffer.str().size();
			}
#endif
			total_ciphers++;
		}
	}
	return max;
}

void write_cipher_to_char_arr(char* outbuf, Cipher_elg& cipher, unsigned int len) {
#if USE_REAL_POINTS
        cipher.get_u().serialize(outbuf);
        cipher.get_v().serialize(outbuf + CurvePoint::bytesize);
#else
	stringstream buffer;
	buffer << cipher;
	memcpy(outbuf, buffer.str().c_str(), buffer.str().size());
	for (unsigned int i = buffer.str().size(); i < len; i++) {
		outbuf[i] = ' ';
	}
	outbuf[len] = '\n';
#endif
}

string Functions::ciphers_to_str(vector<vector<Cipher_elg>* >* ciphers) {
	unsigned int total_ciphers = 0;
	unsigned int pad_length = element_encode_size(ciphers, total_ciphers);
	if (ciphers->size() == 0) return string();
	
	unsigned int m = ciphers->size();
	unsigned int n = ciphers->at(0)->size();
	
	//cout << "number of ciphers " <<  total_ciphers << " and m*n = " << m*n <<endl;

#if USE_REAL_POINTS
	unsigned int total_length = total_ciphers * pad_length;
#else
	unsigned int total_length = total_ciphers + total_ciphers * pad_length;
#endif
	char* output = new char [total_length];
	
	//PARALLELIZE
	#pragma omp parallel for collapse(2) num_threads(num_threads) if(parallel)
	for (unsigned int i=0; i< m; i++){
		for (unsigned int j = 0; j <n; j++){
			unsigned int index = i * n + j;
#if USE_REAL_POINTS
			write_cipher_to_char_arr(output + index * pad_length, ciphers->at(i)->at(j), pad_length);
#else
			write_cipher_to_char_arr(output + index * (pad_length + 1), ciphers->at(i)->at(j), pad_length);
#endif
		}
	}
	
	//output[total_length - 1] = '\0';
	string ret(output, total_length);
	delete[] output;
	return ret;
}


string Functions::parse_response(std::basic_streambuf<char>* in) {
	std::ostringstream ss;
	ss << in;
	return ss.str();
}

void Functions::write_to_file(const string& filename, double output) {
	while (true) {
		ofstream myfile(filename, ios::app);
		if (myfile.is_open()) {
			myfile << output << "\n";
			myfile.close();
			break;
		}
		usleep(100*(rand() % 100));
	}
}

void Functions::sha256(string input, unsigned char* md) {
	SHA256_CTX context;
    sha256_init(&context);
    sha256_update(&context, (unsigned char*)input.c_str(), input.size());
    sha256_final(&context, md);
}

/**
 * @brief Parsing of NIZK proof from file
 * 
 * @param ifciphers string stream from JSON at key "proof"
 * @param proof pointer of destination string
 * @param m number of rows of the cipher matrix
 * @param n number of columns of the cipher matrix
 */
void parse_proof(ifstream& ifciphers, string& proof,
				const long m, const long n) {
	// Number of brakets batches
	int braket_size[3] = {7, 7, 8};

	// Ignores up to the first " within the next 10 characters
	ifciphers.ignore(10, '"');
	proof = "";

	for (int i = 0; i < 3; i++) {
		// Reads up to the first [ within the next PROOF_LENGTH characters and saves the char array in p_value
		ifciphers.get(p_value, PROOF_LENGTH, '[');
		string s_value(p_value);
		proof.append(s_value);
		ifciphers.ignore(2, '[');

		// Iterates over the 7 tuples 
		for (int j = 0; j < braket_size[i]; j++) {
			ifciphers.get(value, VALUE_LENGTH, ',');
			string s_value(value);
			proof.append("[").append(s_value).append(",\n");
			ifciphers.ignore(2, ',');
			ifciphers.get(value, VALUE_LENGTH, ']');
			string s_value_1(value);
			if (j != braket_size[i]-1) {
				proof.append(s_value_1).append("] \n");
			 	ifciphers.ignore(VALUE_LENGTH, '[');
			} else {
				proof.append(s_value_1).append("] ");
			}
		}
		ifciphers.ignore(2, ']');
	}

	// Reads up to the first "" within the next PROOF_LENGTH characters and saves the char array in p_value
	ifciphers.get(p_value, PROOF_LENGTH, '"');
	string s_value(p_value);
	proof.append(s_value);
}

/**
 * @brief Setting up of all the variables required for the validation of a mix process
 * 
 * @param ciphers_file source document after mixing
 * @param IC pointer to the matrix of original ciphers
 * @param SC pointer to the matrix of shuffled ciphers
 * @param m number of rows of the cipher matrix
 * @param n number of columns of the cipher matrix
 * @param proof NIZK proof of the mix
 * @param pubv generators used by Pedersen commitment
 * @return ** ElGammal* ElGammal object setted up to the specified configuration
 */
ElGammal* Functions::set_validation_vars_from_json(const char *ciphers_file,
			const char *publics_file,
			const char *proof_file,
			vector<vector<Cipher_elg>* >& IC,
			vector<vector<Cipher_elg>* >& SC,
			const long m, const long n, 
			string &proof, string &pubv) {

	ifstream ifciphers;
	ifciphers.open(ciphers_file);
	if (ifciphers.fail()) {
		cerr << "cannot open ciphers file " << ciphers_file <<endl;
		exit(1);
	}

	check_json_structure(ifciphers);

	map<string, string> crypto {
		{"g", ""},
		{"q", ""},
		{"p", ""},
		{"y", ""}
	};
	bool passedby_ciphers = false;
	extract_fill_crypto(ifciphers, crypto, passedby_ciphers);
	if (passedby_ciphers) {
		ifciphers.clear();
		ifciphers.seekg(0, ios::beg);
		check_json_structure(ifciphers);
	}

	CurvePoint generator =
		zz_to_curve_pt(ZZ(NTL::conv<NTL::ZZ>(crypto["g"].c_str())));
	ZZ order = NTL::conv<NTL::ZZ>(crypto["q"].c_str());
	ZZ modulus = NTL::conv<NTL::ZZ>(crypto["p"].c_str());

	// Override the init() setup
	G = G_q(generator, order, modulus);
	H = G_q(generator, order, modulus);

	ElGammal* elgammal = new ElGammal();
	elgammal->set_group(G);
	Mod_p pk;
	istringstream is_pk(crypto["y"]);
	is_pk >> pk;
	elgammal->set_pk(pk);

	string original_ciphers("original_ciphers");
	if (!find_json_key(ifciphers, original_ciphers)) {
		cerr << "Key 'original_ciphers' not found in JSON file" << endl;
		exit(1);
	}
	parse_cipher_matrix(ifciphers, IC, m, n);

	string mixed_ciphers("mixed_ciphers");
	if(!find_json_key(ifciphers, mixed_ciphers)) {
		cerr << "Key 'mixed_ciphers' not found in JSON file" << endl;
		exit(1);
	}
	parse_cipher_matrix(ifciphers, SC, m, n);

	ifciphers.close();

	ifciphers.open(publics_file);
	if (ifciphers.fail()) {
		cerr << "cannot open ciphers file " << publics_file <<endl;
		exit(1);
	}
	ostringstream pubvss;
	pubvss << ifciphers.rdbuf();
	pubv = pubvss.str();

	ifciphers.close();

	ifciphers.open(proof_file);
	if (ifciphers.fail()) {
		cerr << "cannot open ciphers file " << proof_file <<endl;
		exit(1);
	}
	ostringstream proofss;
	proofss << ifciphers.rdbuf();
	proof = proofss.str();

	ifciphers.close();

	return elgammal;
}

/**
 * @brief Parses ciphers from an election file
 * 
 * @param election_file election JSON file
 * @param C output CipherTable
 * @param m number of rows of the cipher matrix
 * @param n number of columns of the cipher matrix
 * @param votes number of votes casted in the election
 * @param options number of options per vote
 */
void parse_election(const char* election_file, vector<vector<Cipher_elg>*>* C,
							const long m, const long n,
							const long votes, const long options) {
	ifstream ifciphers;
	ifciphers.open(election_file);
	if (ifciphers.fail()) {
		cerr << "cannot open ciphers file " << election_file <<endl;
		exit(1);
	}

	check_json_structure(ifciphers);
	string answers("answers");
	if (!find_json_key(ifciphers, answers)) {
		cerr << "Key 'answers' not found in JSON file" << endl;
		exit(1);
	}

	vector<vector<string>> ciphers(votes*options);

	for (long i = 0; i < votes; i++) {
		// Ingnore up to the second [
		ifciphers.ignore(10, '[');
		ifciphers.ignore(30, '[');
		for (long j = 0; j < options; j++) {
			// Ingnore up to the first "
			ifciphers.ignore(30, '"');
			ifciphers.get(value, VALUE_LENGTH, '"');
			string alpha_value(value);

			ifciphers.ignore(30, '"');
			ifciphers.get(value, VALUE_LENGTH, '"');
			string beta_value(value);

			ciphers[i*options + j] = {alpha_value, beta_value};
		}
	}

	long alpha, beta;
	for (long i = 0; i < m; i++) {
		C->push_back(new vector<Cipher_elg>(n));
	}
	for (long i = 0; i < m; i++) {
		for (long j = 0; j < n; j++) {
			if (i*options + j < votes*options) {
				alpha = stol(ciphers[i*options + j][0]);
				beta = stol(ciphers[i*options + j][1]);
			} else {
				alpha = 0;
				beta = 0;
			}
			Mod_p mod_a = (Mod_p) alpha;
			Mod_p mod_b = (Mod_p) beta;
			C->at(i)->at(j) = Cipher_elg(mod_a, mod_b);
		}
	}
}

/**
 * @brief Set the election ciphers from file object
 * 
 * @param election_file file containing election data
 * @param m number of rows in the cipher matrix
 * @param n number of columns in the cipher matrix
 * @param votes number of votes casted in the election
 * @param options number of options available in each vote
 * @return CipherTable* mixnet input cipher matrix
 */
void Functions::set_election_ciphers_from_file(const char * election_file, 
						 CipherTable *ciphers,
						 const long m, const long n,
						 const long votes, const long options) {

	parse_election(election_file, ciphers->getCMatrix(), m, n, votes, options);
	ciphers->set_dimensions(m, n);
}

/**
 * @brief Create an ElGammal cipher for a single secret
 * 
 * @param secret secret to be encoded
 * @param enc_key ElGammal object
 * @return ElGammal encryption
 */
Cipher_elg Functions::createSingleCipher(ZZ secret, ElGammal* enc_key) {
	ZZ ord = H.get_ord();
	ZZ ran_2 = RandomBnd(ord);
	Cipher_elg temp;
	CurvePoint s;
	s.zz = secret;
	Mod_p ran_1;
	ran_1 = Mod_p(s, G.get_mod());
	temp = enc_key->encrypt(ran_1, ran_2);
	return temp;
}
