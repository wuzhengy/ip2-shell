#include <string>

#include "util/db_util.hpp"

#include "ip2/alert.hpp"
#include "ip2/alert_types.hpp"

#ifndef LIBTAU_SHELL_ALERT_HANDLER_HPP
#define LIBTAU_SHELL_ALERT_HANDLER_HPP

namespace ip2 {

	struct alert_handler
	{
		alert_handler(tau_shell_sql* db);

        void alert_on_session_stats(alert* i);

	private:
		tau_shell_sql* m_db;
	};

}
#endif
