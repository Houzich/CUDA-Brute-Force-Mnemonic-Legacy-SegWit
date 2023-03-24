/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V1.0.0
  * @date		20-March-2023
  * @mail		houzich_anton@mail.ru
  * discussion  https://t.me/BRUTE_FORCE_CRYPTO_WALLET
  ******************************************************************************
  */
#include "Config.hpp"
#include <tao/config.hpp>

int parse_gonfig(ConfigClass* config, std::string path)
{
	try {
		const tao::config::value v = tao::config::from_file(path);

		config->folder_database_legacy = access(v, tao::config::key("folder_database_legacy")).get_string();
		config->folder_database_segwit = access(v, tao::config::key("folder_database_segwit")).get_string();

		config->prefix_database_legacy = access(v, tao::config::key("prefix_database_legacy")).get_string();
		config->prefix_database_segwit = access(v, tao::config::key("prefix_database_segwit")).get_string();

		config->cuda_grid = access(v, tao::config::key("cuda_grid")).get_unsigned();
		config->cuda_block = access(v, tao::config::key("cuda_block")).get_unsigned();
	}
	catch (std::runtime_error& e) {
		std::cerr << "Error parse config file " << path << " : " << e.what() << '\n';
		throw;
	}
	catch (...) {
		std::cerr << "Error parse config file, unknown exception occured" << std::endl;
		throw;
	}
	return 0;
}


