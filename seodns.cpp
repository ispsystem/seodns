#include <api/module.h>
#include <mgr/mgrlog.h>
#include <mgr/mgrclient.h>
#include <mgr/mgrproc.h>
#include <api/action.h>
#include <mgr/mgrdb_struct.h>
#include <api/stddb.h>
#include <api/autotask.h>
#include <dnsmgr/db.h>

MODULE("seodns");

namespace {
DEFINE_FAIL("seodns");
using namespace isp_api;

mgr_db::JobCache* db;

class DomainCacheTable : public mgr_db::Table {
public:
	mgr_db::StringField Reseller;
	mgr_db::StringField SeodnsIp;
	mgr_db::IntField NameSpace;

	DomainCacheTable()
		: mgr_db::Table("domain_cache")
		, Reseller(this, "reseller")
		, SeodnsIp(this, "seodnsip")
		, NameSpace(this, "namespace")
	{ }
};

class EventUserDelete : public Event {
public:
    EventUserDelete()
        : Event("user.delete.one", "seodns")
    {
    }

    void BeforeExecute(Session& ses) const
    {
        auto user_table = db->Get<UserTable>();
        if (user_table->FindByName(ses.Param("elid")) && !user_table->Parent.IsNull()) {
            auto reseller_table = db->Get<UserTable>();
            if (reseller_table->Find(user_table->Parent) && (int)reseller_table->NameSpace == user_table->NameSpace) {
				auto domain_cache_table = db->Get<DomainCacheTable>();
                ForEachQuery(db, "SELECT name FROM domain WHERE user=" + user_table->Id, domain_list)
				{
					const string domain = domain_list->AsString(0);
					if (domain.find(".ispsystem") == string::npos) {
						domain_cache_table->New();
						domain_cache_table->Name = domain;
						domain_cache_table->Reseller = reseller_table->Name;
						domain_cache_table->SeodnsIp = reseller_table->FieldByName("seodnsip")->AsString();
						domain_cache_table->NameSpace = reseller_table->NameSpace;
						domain_cache_table->Post();
					}
                }
            }
        }
    }
};

class EventDomainCreate : public Event {
public:
    EventDomainCreate()
        : Event("domain.edit", "seodns")
    {
    }

    void BeforeExecute(Session& ses) const
    {
        if (!ses.Param("sok").empty() && ses.Param("elid").empty()) {
            auto domain_table = db->Get<DomainTable>();
            if (domain_table->FindByName(ses.Param("name")) && domain_table->FieldByName("seodnsparked")->AsString() == "on") {
                InternalCall("domain.delete", "elid=" + ses.Param("name"));
            }
        }
    }

	void AfterExecute(Session& ses) const {
		if (!ses.Param("sok").empty() && ses.Param("elid").empty()) {
			auto domain_table = db->Get<DomainTable>();
			if (ses.Checked("seodnsparked") && ses.conn.isAdmin()
				&& domain_table->DbFind("name=" + db->EscapeValue(ses.Param("name")) +
										"AND namespace_id=" + db->EscapeValue(ses.Param("namespace_id")))) {
					domain_table->FieldByName("seodnsparked")->Set("on");
					domain_table->Post();
			}
		}
	}
};

class EventDomainRefresh : public Event {
public:
    EventDomainRefresh()
        : Event("domain.refresh.one", "seodns")
    {
    }

    void BeforeExecute(Session& ses) const
    {
        if (ses.auth.level() > lvUser)
            return;

        auto domain_table = db->Get<DomainTable>();
        if (domain_table->DbFind("name=" + db->EscapeValue(ses.Param("elid")) + " AND seodnsparked='on'"))
            throw mgr_err::Missed("domain", ses.Param("elid"));
    }
};

class EventDomainDelete : public Event {
public:
    EventDomainDelete()
        : Event("domain.delete.one", "seodns")
    {
    }

    void BeforeExecute(Session& ses) const
    {
        auto domain_table = db->Get<DomainTable>();
        auto user_table = db->Get<UserTable>();

        ses.DelParam("new_domain_owner");
        string domain = ses.Param("elid");
        if (domain.find(".ispsystem") == string::npos
			&& domain_table->FindByName(domain)
			&& user_table->Find(domain_table->User)
			&& !user_table->Parent.IsNull()) {
				auto reseller_table = db->Get<UserTable>();
				if (reseller_table->Find(user_table->Parent) && (int)reseller_table->NameSpace == user_table->NameSpace)
					ses.SetParam("new_domain_owner", user_table->Parent);
		}
    }

    void AfterExecute(Session& ses) const
    {
        string domain = ses.Param("elid");
        string owner = ses.Param("new_domain_owner");
		Debug("delete domain '%s' reseller=%s", domain.c_str(), owner.c_str());

        if (!owner.empty()) {
            try {
                auto user_table = db->Get<UserTable>();
                user_table->Assert(owner);
                InternalCall("domain.edit", "su=" + user_table->Name + "&sok=ok&name=" + domain + "&dtype=master&ip=" + user_table->FieldByName("seodnsip")->AsString());

                auto domain_table = db->Get<DomainTable>();
                domain_table->AssertByName(domain);
                domain_table->FieldByName("seodnsparked")->Set("on");
                domain_table->Post();
            }
            catch (...) {
            }
        }
    }
};

class EventDnsParam : public Event {
public:
    EventDnsParam()
        : Event("dnsparam", "seodns")
    {
    }

    void AfterExecute(Session& ses) const
    {
        auto user_table = db->Get<UserTable>();
        user_table->Assert(ses.auth.ext("uid"));

        if (ses.Param("sok").empty()) {
            ses.NewNode("seodnsip", user_table->FieldByName("seodnsip")->AsString());
        } else {
            user_table->FieldByName("seodnsip")->Set(ses.Param("seodnsip"));
            user_table->Post();
        }
    }
};

MODULE_INIT(seodns, "")
{
    db = GetDb();
	db->Register<DomainCacheTable>();

    new EventDnsParam();

    new EventUserDelete();
    new EventDomainRefresh();

    new EventDomainCreate();
    new EventDomainDelete();

	const string cmd = mgr_file::ConcatPath(mgr_file::GetCurrentDir(), "sbin/seodns_checker");
	isp_api::task::Schedule(cmd, "0 2 * * *", "check redelegated domains");

	const string add_domains_cmd = mgr_file::ConcatPath(mgr_file::GetCurrentDir(), "sbin/seodns_add_domains");
	isp_api::task::Schedule(add_domains_cmd, "*/5 * * * *", "add removed domains");
}

} // end of private namespace
