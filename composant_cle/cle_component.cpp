#include <iostream>
#include <pybind11/pybind11.h>
#include "micro-ecc/uECC.h"
#include "conv-string-bin/convert.cpp"

class Cle {

	private:
		// Clé privée
		uint8_t* private_key;
		size_t private_key_size;
		
		// Clé publique
		uint8_t* public_key;
		size_t public_key_size;

	public:
		void initialize(const char* x) {

			// Courbe secp256k1
			auto curve = uECC_secp256k1();

			// Récupérer la taille
			private_key_size = uECC_curve_private_key_size(curve);
			public_key_size = uECC_curve_public_key_size(curve);

			// Créer clé privée
			private_key = new uint8_t[private_key_size]();
			hexStringToBin(private_key, x);

			// Générer clé publique à partir de la clé privée
			public_key = new uint8_t[public_key_size]();
			uECC_compute_public_key(private_key, public_key, curve);
		}

		char* getPrivateKey() {
			return binToHexString(new char[private_key_size](), private_key, private_key_size);
		}
		
		char* getPublicKey() {
			return binToHexString(new char[public_key_size](), public_key, public_key_size);
		}

};

namespace py = pybind11;

PYBIND11_MODULE(cle_component, cle) {
	py::class_<Cle>(cle, "cle")
		.def(py::init<>())
		.def("initialize", &Cle::initialize)
		.def("getPrivateKey", &Cle::getPrivateKey)
		.def("getPublicKey", &Cle::getPublicKey);
}
