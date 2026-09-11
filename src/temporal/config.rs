// SPDX-License-Identifier: MIT

use std::path::PathBuf;
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub struct TemporalRuleToml {
    pub id: String,
    pub sequence: Vec<String>,
    pub behavior: String,
    pub severity: String,
    pub observation: String,
    pub impact: String,
    pub improvement: String,
    pub tags: Vec<String>,
}

pub static BUILTIN_TEMPORAL_RULES: LazyLock<Vec<TemporalRuleToml>> = LazyLock::new(|| {
    vec![
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("fundWallet"),
                String::from("createLedgerEntry"),
            ],
            behavior: String::from(
                "Every wallet credit must be followed by a ledger entry in the same function",
            ),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("financial"),
                String::from("ledger"),
                String::from("consistency"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("debitWallet"),
                String::from("createLedgerEntry"),
            ],
            behavior: String::from(
                "Every wallet debit must be followed by a ledger entry in the same function",
            ),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("financial"),
                String::from("ledger"),
                String::from("consistency"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("chargeCard"),
                String::from("createPaymentRecord"),
            ],
            behavior: String::from("Every card charge must be followed by a payment record"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("financial"),
                String::from("payment"),
                String::from("idempotency"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("issueRefund"),
                String::from("createRefundRecord"),
            ],
            behavior: String::from("Every refund must be followed by a refund record"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("financial"),
                String::from("refund"),
                String::from("consistency"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("transferFunds"),
                String::from("createLedgerEntry"),
            ],
            behavior: String::from("Every fund transfer must produce a ledger entry"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![String::from("financial"), String::from("ledger")],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("awardPoints"),
                String::from("createPointsEntry"),
            ],
            behavior: String::from("Every points award must produce a points ledger entry"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![String::from("financial"), String::from("loyalty")],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("updateOrderStatus"),
                String::from("publishEvent"),
            ],
            behavior: String::from("Every order status change must publish a domain event"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("event-driven"),
                String::from("consistency"),
                String::from("order"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("updateSubscriptionStatus"),
                String::from("publishEvent"),
            ],
            behavior: String::from("Every subscription state change must publish an event"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("event-driven"),
                String::from("consistency"),
                String::from("subscription"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("updatePaymentStatus"),
                String::from("publishEvent"),
            ],
            behavior: String::from("Every payment state change must publish an event"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![String::from("event-driven"), String::from("payment")],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("cancelOrder"), String::from("releaseStock")],
            behavior: String::from("Every order cancellation must release reserved inventory"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("inventory"),
                String::from("consistency"),
                String::from("order"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("cancelOrder"), String::from("issueRefund")],
            behavior: String::from("Every cancellation of a paid order must trigger a refund"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("financial"),
                String::from("order"),
                String::from("refund"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("approveReturn"), String::from("issueRefund")],
            behavior: String::from("Every approved return must trigger a refund"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("financial"),
                String::from("return"),
                String::from("refund"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("approveReturn"),
                String::from("createLedgerEntry"),
            ],
            behavior: String::from(
                "Every approved return must produce a ledger debit for the seller",
            ),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("financial"),
                String::from("return"),
                String::from("ledger"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("fulfillOrder"), String::from("deductStock")],
            behavior: String::from("Every fulfilled order must deduct from stock"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![String::from("inventory"), String::from("order")],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("checkOwnership"),
                String::from("updateResource"),
            ],
            behavior: String::from("Ownership must be verified before any resource mutation"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![String::from("idor"), String::from("authorization")],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("checkOwnership"),
                String::from("deleteResource"),
            ],
            behavior: String::from("Ownership must be verified before resource deletion"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![String::from("idor"), String::from("authorization")],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("checkPermission"),
                String::from("performAdminAction"),
            ],
            behavior: String::from("Permission must be checked before any privileged action"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![String::from("authorization"), String::from("privilege")],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("verifySession"),
                String::from("accessSensitiveData"),
            ],
            behavior: String::from("Session must be verified before sensitive data access"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![String::from("authorization"), String::from("session")],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("checkCredits"), String::from("callLLM")],
            behavior: String::from("Credit balance must be checked before any LLM call"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("billing"),
                String::from("quota"),
                String::from("llm"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("deductCredits"), String::from("callLLM")],
            behavior: String::from("Credits must be deducted before the LLM call executes"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("billing"),
                String::from("quota"),
                String::from("llm"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("checkQuota"), String::from("spawnSandbox")],
            behavior: String::from("Quota must be verified before spawning a compute sandbox"),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("billing"),
                String::from("quota"),
                String::from("compute"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("checkPlan"),
                String::from("accessPremiumFeature"),
            ],
            behavior: String::from(
                "Subscription plan must be verified before accessing premium features",
            ),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("billing"),
                String::from("subscription"),
                String::from("feature"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("verifyWebhookSignature"),
                String::from("processWebhookEvent"),
            ],
            behavior: String::from(
                "Webhook signature must be verified before processing the event",
            ),
            severity: String::from("critical"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("webhook"),
                String::from("security"),
                String::from("authentication"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("deleteRecord"),
                String::from("createAuditEntry"),
            ],
            behavior: String::from("Every data deletion must create an audit trail entry"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("audit"),
                String::from("compliance"),
                String::from("gdpr"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("performAdminAction"),
                String::from("createAuditEntry"),
            ],
            behavior: String::from("Every admin action must produce an audit log entry"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("audit"),
                String::from("compliance"),
                String::from("admin"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("exportUserData"),
                String::from("createAuditEntry"),
            ],
            behavior: String::from("Every data export must be recorded in the audit log"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("audit"),
                String::from("compliance"),
                String::from("gdpr"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("changePermission"),
                String::from("createAuditEntry"),
            ],
            behavior: String::from("Every permission change must be audited"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![String::from("audit"), String::from("compliance")],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("acquireLock"), String::from("releaseLock")],
            behavior: String::from("Every lock acquisition must be followed by a release"),
            severity: String::from("error"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("resource"),
                String::from("lock"),
                String::from("deadlock"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("openConnection"),
                String::from("closeConnection"),
            ],
            behavior: String::from("Every opened connection must be closed"),
            severity: String::from("warning"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("resource"),
                String::from("connection"),
                String::from("leak"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("openFile"), String::from("closeFile")],
            behavior: String::from("Every opened file handle must be closed"),
            severity: String::from("warning"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("resource"),
                String::from("file"),
                String::from("leak"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("beginTransaction"),
                String::from("commitOrRollback"),
            ],
            behavior: String::from("Every started transaction must be committed or rolled back"),
            severity: String::from("error"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("resource"),
                String::from("transaction"),
                String::from("database"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("spawnSandbox"), String::from("destroySandbox")],
            behavior: String::from("Every spawned sandbox must be destroyed when done"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("resource"),
                String::from("compute"),
                String::from("cost"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("registerWebhook"),
                String::from("deregisterWebhookOnFailure"),
            ],
            behavior: String::from(
                "If post-registration steps fail, registered webhook must be removed",
            ),
            severity: String::from("medium"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("resource"),
                String::from("webhook"),
                String::from("cleanup"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("processRefund"), String::from("notifyUser")],
            behavior: String::from("Every processed refund must notify the user"),
            severity: String::from("medium"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("notification"),
                String::from("user-experience"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("chargeCard"), String::from("sendReceipt")],
            behavior: String::from("Every successful charge must send a receipt"),
            severity: String::from("medium"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![String::from("notification"), String::from("financial")],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![
                String::from("resetPassword"),
                String::from("invalidateOtherSessions"),
            ],
            behavior: String::from("Password reset must invalidate all other active sessions"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("security"),
                String::from("session"),
                String::from("password"),
            ],
        },
        TemporalRuleToml {
            id: String::new(),
            sequence: vec![String::from("changeEmail"), String::from("verifyNewEmail")],
            behavior: String::from("Email change must trigger verification of the new address"),
            severity: String::from("high"),
            observation: String::new(),
            impact: String::new(),
            improvement: String::new(),
            tags: vec![
                String::from("security"),
                String::from("identity"),
                String::from("email"),
            ],
        },
    ]
});

pub fn load_all_temporal_rules(_extra_dirs: &[PathBuf]) -> Vec<TemporalRuleToml> {
    BUILTIN_TEMPORAL_RULES.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_builtin_temporal_rules() {
        let rules = load_all_temporal_rules(&[]);
        assert_eq!(rules.len(), 37);
    }
}
