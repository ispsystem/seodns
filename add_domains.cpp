#include <ispbin.h>
#include <mgr/mgrclient.h>
#include <mgr/mgrdb_sbin.h>
#include <mgr/mgrproc.h>
#include <mgr/mgrlog.h>
#include <unistd.h>

MODULE("seodns_add_domains");

int ISP_MAIN(int argc, _TCHAR* argv[]) {
	mgr_log::Init("dns_add_domains");
	mgr_proc::SingleInstance add_domains("add_domains");
	mgr_client::Local con("dnsmgr", "seodns_add_domains");
	string processed_ids;

	auto db = mgr_db::Connect(con);
	ForEachQuery(db, "SELECT id, name, reseller, seodnsip, namespace FROM domain_cache", domain_list) {
		try {
			const string domain = domain_list->AsString(1);
			con.Query("func=domain.edit&dtype=master&sok=ok&seodnsparked=on"
						"&namespace_id=" + str::url::Encode(domain_list->AsString("namespace")) +
						"&su=" + str::url::Encode(domain_list->AsString("reseller")) +
						"&name=" + str::url::Encode(domain) +
						"&ip=" + str::url::Encode(domain_list->AsString("seodnsip")));
		} catch (const std::exception &e) {
			Warning("Cant add domain '%s'. What: %s", domain_list->AsString(1).c_str(), e.what());
		}
		str::inpl::Append(processed_ids, domain_list->AsString(0), " ");
	}
	while (!processed_ids.empty()) {
		const string id = str::GetWord(processed_ids);
		try {
			db->Query("DELETE FROM domain_cache WHERE id=?", id);
		} catch (const std::exception &e) {
			Warning("Cant delete domain with id '%s'. What: %s", id.c_str(), e.what());
		}
	}
	return 0;
}
