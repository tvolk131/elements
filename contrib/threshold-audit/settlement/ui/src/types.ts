export type Currency = "EUR" | "USD";
export type Kind =
  | "deposit"
  | "transfer"
  | "redemption"
  | "refund"
  | "receipt"
  | "quarantine";
export interface User {
  id: string;
  name: string;
  role: string;
  tenant: string;
  institution_id?: string;
  audit_member?: number;
}
export interface Session {
  user: User | null;
  csrf: string | null;
  permissions: string[];
}
export interface Account {
  id: string;
  name: string;
  tenant: string;
  currencies: Currency[];
  bank_id?: string;
  payment_reference?: string;
}
export interface Beneficiary {
  id: string;
  name: string;
  account_id: string;
  kind: string;
  currency?: Currency;
}
export interface Balance {
  account_id: string;
  currency: Currency;
  balance_minor: number;
  available_minor: number;
  chain_reconciles?: boolean;
}
export interface ApprovalRequest {
  id: string;
  kind: string;
  amount_minor?: number;
  currency?: Currency;
  asset_id?: string;
  destination_hash?: string;
  destination?: string;
  [key: string]: unknown;
}
export interface WorkflowActor {
  id: string;
  name: string;
  role: string;
}
export interface ApprovalWorkflow {
  maker: WorkflowActor;
  user_reviewers: WorkflowActor[];
  submitters: WorkflowActor[];
  institution_ids: string[];
  required_institutions: number;
  approved_institution_ids: string[];
}
export interface Operation {
  id: string;
  kind: Kind;
  currency: Currency;
  amount_minor: number;
  state: string;
  account_id: string;
  to_account_id?: string;
  beneficiary_id?: string;
  beneficiary_name?: string;
  destination_name?: string;
  destination_address?: string;
  beneficiary_verified?: boolean;
  incoming?: boolean;
  source_name?: string;
  destination?: string;
  tenant?: string;
  reference?: string;
  issuer?: string;
  created_at: number;
  expires_at?: number;
  maker?: string;
  approval_workflow?: ApprovalWorkflow;
  user_approved: boolean;
  /** Deposits under deposit_issuance "automatic": the bank's confirmation is
   * its approval and tokens issue once the institutions approve. */
  issues_automatically?: boolean;
  guardian_approvals: number;
  guardian_threshold: number;
  allowed_actions: string[];
  error?: string;
  /** "institutions" when their services refused to authorize it on the ledger. */
  declined_by?: string;
  txid?: string;
  stage?: string;
  destination_hash?: string;
  bank_account_ref_hash?: string;
  cash_receipt_id?: string;
  asset_id?: string;
  transaction_template_hash?: string;
  request_hash?: string;
  approval_request?: ApprovalRequest;
  /** Set when a regulator's order moved the funds (quarantine or return):
   * the order, the authority that signed it and its case. */
  recovery_order?: string;
  authority?: string;
  case_reference?: string;
}
/** One hash-chained evidence entry. */
export interface Activity {
  id: number;
  created_at: number;
  operation_id: string | null;
  actor: string;
  actor_name: string;
  event: string;
  entry_hash: string;
}
export interface Institution {
  id: string;
  institution_id: string;
  name: string;
  public_key: string;
  approval_url?: string;
}
export interface Network {
  connected: boolean;
  chain: string;
  genesis_hash: string;
  height: number;
  audit_version?: number;
  registry_version: number;
  audit_threshold: number;
  audit_guardians: number;
  disclosure_available: boolean;
}
export interface Reserve {
  currency: Currency;
  cash_minor: number;
  token_liability_minor: number;
  deposit_payable_minor: number;
  redemption_payable_minor: number;
  escrow_minor: number;
  frozen: boolean;
  cash_reconciles: boolean;
  liabilities_reconcile: boolean;
  supply_reconciles: boolean;
  journal_balances: boolean;
  payout_mode: string;
}
export interface Asset {
  currency: Currency;
  asset_id: string;
  registered: boolean;
  registry_version: number;
  issuer: string;
}
export interface Membership {
  threshold: number;
  count: number;
  members: string[];
  script?: string;
}
export interface FederationPolicy {
  label: string;
  epoch: number;
  policy_version: string;
  detail?: string;
  audit: Membership;
  block_signing: Membership;
  treasury: Membership;
  /** Must authorize every transaction; absent from older servers. */
  authorization?: Membership;
}
export interface RotationStep {
  id: string;
  label: string;
  state: "complete" | "active" | "pending";
}
export interface Readiness {
  id: string;
  label: string;
  state: string;
  detail: string;
}
export interface Migration {
  migration_id: string;
  kind: string;
  currency: Currency | "";
  txid: string | null;
  state: string;
}
export interface OutstandingCase {
  id: string;
  kind: Kind;
  state: string;
  currency: Currency;
  amount_minor: number;
}
export interface Rotation {
  id: string;
  state: string;
  stage: string;
  created_at: number;
  error: string | null;
  hold_reason: string | null;
  allowed_actions: string[];
  steps: RotationStep[];
  readiness: Readiness[];
  migrations: Migration[];
  outstanding_cases: OutstandingCase[];
  approval_count: number;
  approval_threshold: number;
  approvals: string[];
}
export interface Federation {
  id: string;
  genesis_hash: string;
  current: FederationPolicy;
  incoming: FederationPolicy | null;
  rotation: Rotation | null;
  allowed_actions: string[];
}
export interface FrozenFunds {
  account_id: string;
  currency: Currency;
  amount_minor: number;
  outpoint: string;
  order_id: string;
  authority: string;
  case_reference: string;
}
export interface Dashboard {
  directory_banks: { id: string; public_key: string }[];
  /** Funds on visible accounts under a regulator's freeze order. */
  frozen_funds?: FrozenFunds[];
  session: Session;
  accounts: Account[];
  balances: Balance[];
  operations: Operation[];
  beneficiaries: Beneficiary[];
  activity: Activity[];
  guardians: Institution[];
  network: Network;
  /** Whether payments between customers need institution approval. */
  transfer_institution_approval: "always" | "never" | { above_minor: number };
  deposit_issuance?: "manual" | "automatic";
  assets: Asset[];
  reserves: Reserve[];
  /** Only present for bank-tenant users who can view federation status. */
  federation: Federation | null;
}
export type Page =
  | "disclosures"
  | "overview"
  | "payments"
  | "banking"
  | "beneficiaries"
  | "activity"
  | "approvals"
  | "reserves"
  | "network"
  | "ledger"
  | "federation";
export type DialogState =
  | { type: "create"; kind: Exclude<Kind, "refund" | "receipt" | "quarantine"> }
  | { type: "receive" }
  | { type: "operation"; id: string }
  | { type: "review"; operation: Operation; action: string }
  | { type: "bank"; operation?: Operation }
  | { type: "rotation"; action: string }
  | null;
