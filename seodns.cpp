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
                ForEachQuery(db, "SELECT name FROM domain WHERE user=" + user_table->Id, domain_list)
                {
                    InternalCall("domain.delete", "elid=" + domain_list->AsString(0));
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
        if (domain_table->FindByName(ses.Param("elid"))
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

    new EventDnsParam();

    new EventUserDelete();
    new EventDomainRefresh();

    new EventDomainCreate();
    new EventDomainDelete();

    string cmd = mgr_file::ConcatPath(mgr_file::GetCurrentDir(), "sbin/seodns_checker");
    isp_api::task::Schedule(cmd, "0 2 * * *", "check redelegated domains");
}

} // end of private namespace
