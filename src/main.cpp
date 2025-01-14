#include <iostream>
#include <filesystem>
#include <sqlite3.h>

#include "rpc/webui.hpp"
#include "handler/alert_handler.hpp"
#include "handler/tau_handler.hpp"
#include "util/hex_util.hpp"
#include "util/db_util.hpp"
#include "util/tau_constants.hpp"

#include "ip2/aux_/ed25519.hpp"
#include "ip2/kademlia/ed25519.hpp"
#include "ip2/alert.hpp"
#include "ip2/alert_types.hpp"
#include "ip2/error_code.hpp"
#include "ip2/hex.hpp"
#include "ip2/session.hpp"
#include "ip2/session_params.hpp"
#include "ip2/session_handle.hpp"

#include <signal.h>
#include <unistd.h> // for getpid()
#include <getopt.h> // for getopt_long
#include <stdlib.h> // for daemon()

//#include "profiler.h"
//#include "heap-profiler.h"

const int FILE_LEN = 256;

bool quit = false;
bool force_quit = false;

void sighandler(int s)
{
    quit = true;
}

void sighandler_forcequit(int s)
{
    force_quit = true;
}

using namespace ip2;

struct option cmd_line_options[] =
{
    {"config",            required_argument,   NULL, 'c'},
    {"daemonize",         no_argument,         NULL, 'd'},
    {"initial",              no_argument,          NULL, 'i'},
    {"help",              no_argument,         NULL, 'h'},
};

void print_usage()
{
    fputs("ip2-daemon usage:\n\n"
        "-c, --config           <config filename>\n"
        "-d, --daemonize\n"
        "-i, --initial\n"
        "-h, --help\n"
        "\n"
        , stderr);
}

int main(int argc, char *const argv[])
{
    // general configuration of network ranges/peer-classes
    // and storage

    bool daemonize = false;
    bool initial = false;

    std::string config_file;
    int ch = 0;
    while ((ch = getopt_long(argc, argv, "c:d:i", cmd_line_options, NULL)) != -1)
    {
        switch (ch)
        {
            case 'c': config_file = optarg; break;
            case 'd': daemonize = true; break;
            case 'i': initial = true; break;
            default:
                print_usage();
                return 1;
        }
    }

    std::cout << "Configure from cmd line: " << std::endl;
    std::cout << "config file: " << config_file << std::endl;

    error_code ec;
    auth authorizer;
    ec.clear();
    authorizer.load_accounts("users.conf", ec);
    if (ec)
        authorizer.add_account("tau-shell", "tester", 0);
    ec.clear();

    //读取device_id, account_seed
    char device_id[KEY_LEN + 1]={}; //used for '\0'
    char account_seed[KEY_HEX_LEN + 1]={}; //used for '\0'
    char pubkey_hex[KEY_HEX_LEN + 1]={}; //used for '\0'
    char bootstrap_nodes[1024]={};

    char pid_file[FILE_LEN] = {0};
    char error_log[FILE_LEN] = {0};
    char debug_log[FILE_LEN] = {0};

    int listen_port = 6881;
    int rpc_port = 8080;

    char bind_ip_chars[FILE_LEN] = {0};
    char shell_save_path[FILE_LEN] = {};
    char tau_save_path[FILE_LEN] = {};

    if(!config_file.empty())
    {
        FILE* f = fopen(config_file.c_str(), "r");
        if(f)
        {
            fscanf(f, "%s\n %s\n %s\n", device_id, account_seed, bootstrap_nodes);
            fscanf(f, "%s\n %s\n %s\n", pid_file, error_log, debug_log);
            fscanf(f, "%d\n %d\n", &listen_port, &rpc_port);
            fscanf(f, "%s\n", bind_ip_chars);
            fscanf(f, "%s\n %s\n", shell_save_path, tau_save_path);
            fclose(f);
        }
        else
        {
            fprintf(stderr, "failed to open config file \"%s\": %s\n"
                , config_file.c_str(), strerror(errno));
            exit(1);
        }
    }

    std::cout << "pid file: " << pid_file << std::endl;
    std::cout << "listen port: " << listen_port << std::endl;
    std::cout << "rpc port: " << rpc_port << std::endl;
    std::cout << "shell save path: " << shell_save_path << std::endl;
    std::cout << "tau save path: " << tau_save_path << std::endl;
    std::cout << "error log file: " << error_log << std::endl;
    std::cout << "debug log file: " << debug_log << std::endl;
    std::cout << "Initial CMD Parameters Over" << std::endl;

    //处理seed
    std::array<char, KEY_LEN> array_seed;
    char* pubkey = new char[KEY_LEN];
    char* seckey = new char[KEY_HEX_LEN];
    if(!strcmp(account_seed, "null")){
        //产生随机数
        array_seed = dht::ed25519_create_seed();
        aux::to_hex(array_seed.data(), KEY_LEN, account_seed);
    } else {
        hex_char_to_bytes_char(account_seed, array_seed.data(), KEY_HEX_LEN);
    }
    
    dht::public_key m_pubkey;
    dht::secret_key m_seckey;
    std::tie(m_pubkey, m_seckey) = dht::ed25519_create_keypair(array_seed);

    if (daemonize)
    {
        //输出pid
        if (strlen(pid_file) > 0)
        {
            FILE* f = fopen(pid_file, "w+");
            if (f)
            {
                fprintf(f, "%d", getpid());
                fclose(f);
            }
            else
            {
                fprintf(stderr, "failed to open pid file \"%s\": %s\n"
                    , pid_file, strerror(errno));
            }
        }

        //as daemon process

        daemon(1, 0);
    }
    std::cout << "Initial File Parameters Over" << std::endl;

    // open db for message store
    std::string home_dir = std::filesystem::path(getenv("HOME")).string();
    std::string const& sqldb_dir = home_dir + shell_save_path;
    std::string const& sqldb_path = sqldb_dir + "/tau_sql.db";

    // create the directory for storing sqldb data
    if(!std::filesystem::is_directory(sqldb_dir)) {
        if(!std::filesystem::create_directories(sqldb_dir)){
            //报错退出-创建文件失败
            fprintf(stderr, "failed to create db file");
            exit(1);
        }
    }

    // open sqldb - sqlite3
    tau_shell_sql tau_sql(sqldb_path);

    // initial sqlite3
    if(initial) {
        tau_sql.sqlite_db_initial();
        std::cout << "Sqlite3 DB initial success" << std::endl;
    }

    std::cout << "DB File Open Over" << std::endl;

    // 输出debug日志
    FILE* debug_file = NULL;
    if (strlen(debug_log) > 0)
    {
        debug_file = fopen(debug_log, "w+");
        if (debug_file == NULL)
        {
            fprintf(stderr, "failed to debug log \"%s\": %s\n"
                , debug_log, strerror(errno));
            exit(1);
        }
    }

    std::cout << "Log File Open Over" << std::endl;

    //定义session_params
    settings_pack sp_set;

    //bootstrap nodes
    sp_set.set_str(settings_pack::dht_bootstrap_nodes, bootstrap_nodes);
    std::cout <<  "bootstrap nodes: " << bootstrap_nodes << std::endl;

    //device_id
    sp_set.set_str(settings_pack::device_id, device_id);
    std::cout <<  "device id: " << device_id << std::endl;

    //account seed
    sp_set.set_str(settings_pack::account_seed, account_seed);
    std::cout <<  "account_seed: " << account_seed << std::endl;

    //listen port
    std::string bind_ip(bind_ip_chars);
    std::stringstream listen_interfaces;
    listen_interfaces << bind_ip << ":" << listen_port;
    std::cout << "listen port: " << listen_interfaces.str() << std::endl;
    sp_set.set_str(settings_pack::listen_interfaces, listen_interfaces.str());

    //tau save path
    std::cout << "ip2 save path: " << tau_save_path << std::endl;
    sp_set.set_str(settings_pack::db_dir, tau_save_path);

    //alert mask
    alert_category_t atmask = alert::all_categories;
    //alert_category_t atmask = alert_category::session_log|alert_category::dht_log;
    sp_set.set_int(settings_pack::alert_mask, atmask);    

    //alert mask
    sp_set.set_int(settings_pack::dht_item_lifetime, 7200);    

    //reopen time when peer is 0
    sp_set.set_int(settings_pack::max_time_peers_zero, 7200000);    

    //referable
    sp_set.set_bool(settings_pack::dht_non_referrable, false);

    std::cout << "Session parameters' setting Over" << std::endl;

    session_params sp_param(sp_set) ;
    session ses(sp_param);
    //定义tau communication handle
    tau_handler t_handler(ses, &tau_sql, &authorizer, m_pubkey, m_seckey);
    alert_handler a_handler(&tau_sql);

    //定义启动webui
    webui_base webport;
    webport.add_handler(&t_handler);
    webport.start(rpc_port, 30);
    if (!webport.is_running())
    {
        fprintf(stderr, "failed to start web server\n");
        return 1;
    }
    std::cout << "Web UI RPC Start Over" << std::endl;

    signal(SIGTERM, &sighandler);
    signal(SIGINT, &sighandler);
    signal(SIGPIPE, SIG_IGN);

    //port
    std::uint16_t port = ses.get_port_from_pubkey(m_pubkey);
    aux::to_hex(m_pubkey.bytes.data(), KEY_LEN, pubkey_hex);
    std::cout <<  "public key: " << pubkey_hex << std::endl;
    std::cout << "port: "  << port << std::endl;

    std::vector<alert*> alert_queue;
    bool shutting_down = false;

    //profile analysis
    //ProfilerStart("./a.prof");
    //HeapProfilerStart("./mem.prof");

    while (!quit)
    {
        ses.pop_alerts(&alert_queue);

        for (std::vector<alert*>::iterator i = alert_queue.begin()
            , end(alert_queue.end()); i != end; ++i)
        {
            auto now = std::chrono::system_clock::now(); 
            auto now_c = std::chrono::system_clock::to_time_t(now); 
            std::cout << std::put_time(std::localtime(&now_c), "%c") << " " << (*i)->message().c_str() << std::endl;
            //fprintf(debug_file, "%s %s\n", std::put_time(std::localtime(&now_c), "%c"), (*i)->message().c_str());
            //std::cout << (*i)->type() <<  " " << log_alert::alert_type << std::endl;
            int alert_type = (*i)->type();
            switch(alert_type){
                case session_stats_alert::alert_type: 
                    a_handler.alert_on_session_stats(*i);
                    break;
                case log_alert::alert_type: 
                    //std::cout << ses.get_session_time()/1000 << " SESSION LOG: " << (*i)->message().c_str() << std::endl;
                    break;
                case dht_log_alert::alert_type:
                    //std::cout << ses.get_session_time()/1000 << " DHT LOG:  " << (*i)->message().c_str() << std::endl;
                    break;
				case transport_log_alert::alert_type:
					std::cout << ses.get_session_time()/1000 << " TRANSPORT LOG:  " << (*i)->message().c_str() << std::endl;
					break;
				case assemble_log_alert::alert_type:
					std::cout << ses.get_session_time()/1000 << " ASSEMBLE LOG:  " << (*i)->message().c_str() << std::endl;
					break;
                //ip2 alert
                case put_data_alert::alert_type:
                    break;
                case relay_data_uri_alert::alert_type:
                    break;
                case incoming_relay_data_uri_alert::alert_type:
                    break;
                case get_data_alert::alert_type:
                    break;
                case relay_message_alert::alert_type:
                    break;
                case incoming_relay_message_alert::alert_type:
                    break;
            }
        }

        if (quit && !shutting_down)
        {
            shutting_down = true;
            signal(SIGTERM, &sighandler_forcequit);
            signal(SIGINT, &sighandler_forcequit);
        }
        if (force_quit) break;
        ses.wait_for_alert(ip2::milliseconds(500));
    }

    //ProfilerStop();
    //HeapProfilerDump("exit");
    //HeapProfilerStop();

    ses.stop();

    std::cout << "Session Stop Over" << std::endl;

    if (debug_file) fclose(debug_file);

    std::cout << "Total Over" << std::endl;

    return 0;
}
