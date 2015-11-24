#include <ispbin.h>
#include <mgr/mgrclient.h>
#include <mgr/mgrdb_sbin.h>
#include <mgr/mgrproc.h>
#include <mgr/mgrlog.h>

MODULE("seodns_checker");

int ISP_MAIN(int argc, _TCHAR* argv[])
{
    mgr_log::Init("dnschecker");
    mgr_client::Local con("dnsmgr", "seodns_checker");

    auto db = mgr_db::Connect(con);
    ForEachQuery(db, "SELECT d.name, u.name, u.dnsns FROM domain d LEFT JOIN user u on d.user=u.id WHERE d.seodnsparked='on'", domain_list)
    {
        LogExt("check domain %s", domain_list->AsString(0).c_str());
	mgr_file::Tmp tmp("tmp/out");
        mgr_proc::Execute whois("whois " + domain_list->AsString(0) + " > " + tmp.Str());
	whois.Run();
	// sometime whois hungs for long time, so we kill it after 10 seconds 
	for (int i = 100; i && whois.IsAlive(); --i)
		mgr_proc::Sleep(100);
	if (whois.IsAlive()) {
		whois.Terminate();
		continue;
	}
        //auto whois = mgr_proc::Execute("whois " + domain_list->AsString(0), mgr_proc::Execute::efOutErr);
        //string out = str::Lower(whois.Str());
        string out = str::Lower(mgr_file::Read(tmp));
        Debug("result=%d out '%s'\n", whois.Result(), out.c_str());

        if (whois.Result() == 0) {
            // looking for nameservers
	    StringSet LocalNameServers;
            str::Split(domain_list->AsString(2), " ", LocalNameServers);
            bool found = false;
	    ForEachI(LocalNameServers, srv) {
		string n = *srv;
		if (n[n.size()-1] == '.') {
			n.erase(n.size()-1);
			if (out.find(n) != string::npos) {
				found = true;
				break;
			}
		}
	    }

            if (!found)
                con.Query("func=domain.delete&elid=" + domain_list->AsString(0) + "&su=" + domain_list->AsString(1));
        }
        sleep(1); // for whois block system
    }

    return 0;
}
