#include "Bgmix.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <stdlib.h>  // atol()

static int kNumTests = 1;

void test_mix(long dim_m, long dim_n) {
	char g[] = "1929181099559129674691211513194785872536670409492790905276619913671396722443243145931673445424440902236760877484211441680348197072495215150053603001343967365713940597148603897520835948403066356627154482171157913975934174689003578096019980791028264452409955094293631742810957258379488668086855090084223965396993821991583550151470397960480522495500106360092070361350077271147228";
	char q[] = "1257206741114416297422800737364843764556936223541";
	char p[] = "2093940378184301311653365957372856779274958817946641127345598909177821235333110899157852449358735758089191470831461169154289110965924549400975552759536367817772197222736877807377880197200409316970791234520514702977005806082978079032920444679504632247059010175405894645810064101337094360118559702814823284408560044493630320638017495213077621340331881796467607713650957219938583";
	char publics_file[] = "public_randoms.txt";
	char proof_file[] = "proof.txt";
	char ciphers_file[] = "ciphers.json";
	generate_ciphers(ciphers_file, publics_file, proof_file, dim_m, dim_n, g, q, p);
	mix(ciphers_file, publics_file, proof_file, dim_m, dim_n, g, q, p);
	validate_mix(ciphers_file, publics_file, proof_file, dim_m, dim_n, g, q, p);
}

int main(int argc, char *argv[]) {
	if (argc != 3) {
		std::cout << "Wrong number of arguments. Expected:" << std::endl;
		std::cout << "./bgmix <number of cipher matrix rows> <number of cipher matrix columns>" << std::endl;
		exit(1);
	}

	time_t begin = time(NULL);
	std::thread* th_arr[kNumTests];
	for (int i = 0; i < kNumTests; i++) {
		th_arr[i] = new std::thread(test_mix, atol(argv[1]), atol(argv[2]));
	}

	std::cout << "waiting for everyone..." <<std::endl;
	for (int i = 0; i < kNumTests; i++) {
		th_arr[i]->join();
	}

	std::cout << "stress test is done in " << time(NULL) - begin << " seconds" << std::endl;
	for (int i = 0; i < kNumTests; i++) {
		delete th_arr[i];
	}

	return 0;
}
