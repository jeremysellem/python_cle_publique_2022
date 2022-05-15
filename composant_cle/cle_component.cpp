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

		char* get_private_key() {
			return binToHexString(new char[private_key_size](), private_key, private_key_size);
		}
		
		char* get_public_key() {
			return binToHexString(new char[public_key_size](), public_key, public_key_size);
		}

};

namespace py = pybind11;

PYBIND11_MODULE(composant_cle, cle) {
	py::class_<Cle>(cle, "Cle")
		.def(py::init<>())
		.def("initialize", &Cle::initialize)
		.def("get_private_key", &Cle::get_private_key)
		.def("get_public_key", &Cle::get_public_key)
}
