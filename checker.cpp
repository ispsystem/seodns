#include <ispbin.h>
#include <mgr/mgrclient.h>
#include <mgr/mgrdb_sbin.h>
#include <mgr/mgrproc.h>
#include <mgr/mgrlog.h>
#include <unistd.h>

MODULE("seodns_checker");

int ISP_MAIN(int argc, _TCHAR *argv[])
{
	mgr_log::Init("dnschecker");
        mgr_client::Local con("dnsmgr", "seodns_checker");

	auto db = mgr_db::Connect(con);
	ForEachQuery(db, "SELECT d.name, u.name, u.dnsns FROM domain d LEFT JOIN user u on d.user=u.id WHERE d.seodnsparked='on'", domain_list) {
		LogExt("check domain %s", domain_list->AsString(0).c_str());
		auto whois = mgr_proc::Execute("whois "+domain_list->AsString(0), mgr_proc::Execute::efOut);
		string out = str::Lower(whois.Str());
		Debug("result=%d out %s\n", whois.Result(), out.c_str());

		if (whois.Result() && out.find("no whois server") != string::npos) {
			// unknown tld
			con.Query("func=domain.delete&elid="+domain_list->AsString(0)+"&su="+domain_list->AsString(1));
		} else if (whois.Result() == 0) {
			// looking for nameservers
			StringSet WhoisNameServers, LocalNameServers;
			while (!out.empty()) {
				string line = str::GetWord(out, "\n");
				if (line.find("name server:") != string::npos 
				|| line.find("nserver:") != string::npos) {
					WhoisNameServers.insert(str::RGetWord(line));
				}
			}

			str::Split(domain_list->AsString(2), " ", LocalNameServers);

			// compare name servers
			bool found = false;
			ForEachI(WhoisNameServers, n) {
				LogExt("Check whois nameserver %s", n->c_str());
				if (LocalNameServers.find(*n) != LocalNameServers.end()) {
					found = true;
					break;
				}
			}
			if (!found)
				con.Query("func=domain.delete&elid="+domain_list->AsString(0)+"&su="+domain_list->AsString(1));
		}
		sleep(1); // for whois block system
	}

	return 0;
}
