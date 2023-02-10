#include <fstream>
#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <stdio.h>

extern "C" {
#include "util/jsmn.h"
}

#include "handler/alert_handler.hpp"
#include "util/json_util.hpp"

#include "ip2/hex.hpp"
#include "ip2/span.hpp"
#include "ip2/performance_counters.hpp"
#include "ip2/blockchain/constants.hpp"

namespace ip2 {

	alert_handler::alert_handler(tau_shell_sql* db)
	: m_db(db)	
	{
	}

	void alert_handler::alert_on_session_stats(alert* i){
        session_stats_alert* a = reinterpret_cast<session_stats_alert*>(i);
        span<std::int64_t const> sc = a -> counters();
        std::cout << "session nodes number: " << sc[counters::dht_nodes] << std::endl;
		return;
	}

}
