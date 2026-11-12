export type Currency = "EUR" | "USD";
export type Kind = "deposit" | "transfer" | "redemption" | "refund";
export interface User {
  id: string;
  name: string;
  role: string;
  tenant: string;
  institution_id?: string;
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
  destination?: string;
  tenant?: string;
  reference?: string;
  issuer?: string;
  created_at: number;
  expires_at?: number;
  maker?: string;
  approval_workflow?: ApprovalWorkflow;
  user_approved: boolean;
  guardian_approvals: number;
  guardian_threshold: number;
  allowed_actions: string[];
  error?: string;
  txid?: string;
  stage?: string;
  chain_status?: string;
  bank_status?: string;
  bank_event_id?: string;
  destination_hash?: string;
  bank_account_ref_hash?: string;
  cash_receipt_id?: string;
  asset_id?: string;
  transaction_template_hash?: string;
  request_hash?: string;
  approval_request?: ApprovalRequest;
  history?: Activity[];
  events?: Activity[];
}
export interface Activity {
  id?: number;
  description?: string;
  action?: string;
  event?: string;
  state?: string;
  actor_name?: string;
  actor?: string;
  operation_id?: string;
  created_at?: number;
  timestamp?: number;
  detail?: string;
}
export interface Institution {
  id?: string;
  institution_id?: string;
  name?: string;
  status?: string;
  approval_url?: string;
  historical_ready?: boolean;
}
export interface Audit {
  threshold?: number;
  guardian_count?: number;
  roster_id?: string;
  historical_ready?: boolean;
}
export interface Network {
  connected?: boolean;
  chain?: string;
  height?: number;
  block_height?: number;
  genesis_hash?: string;
  registry_version?: number;
  audit_version?: number;
  audit_threshold?: number;
  audit_guardians?: number;
  error?: string;
  settlement_hold?: string;
  audit?: Audit;
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
  currency?: Currency;
  asset_id: string;
  registered?: boolean;
  registry_version?: number;
  issuer?: string;
}
export interface Membership {
  threshold?: number;
  count?: number;
  guardian_count?: number;
  members?: (string | { id?: string; name?: string; member?: string })[];
  script?: string;
  state?: string;
  status?: string;
  detail?: string;
}
export interface FederationPolicy {
  id?: string;
  label?: string;
  epoch?: number;
  state?: string;
  status?: string;
  audit?: Membership;
  block_signing?: Membership;
  treasury?: Membership;
}
export interface Stage {
  id?: string;
  label?: string;
  kind?: string;
  state?: string;
  status?: string;
  detail?: string;
  txid?: string;
  currency?: Currency;
  operation_id?: string;
  amount_minor?: number;
}
export interface Rotation {
  id: string;
  state: string;
  stage?: string;
  hold_reason?: string;
  error?: string;
  allowed_actions?: string[];
  steps?: Stage[];
  migrations?: Stage[];
  readiness?: Stage[];
  outstanding_cases?: Stage[];
  created_at?: number;
  activation_height?: number;
  approval_count?: number;
  guardian_approvals?: number;
  approvals?: unknown[];
  approval_threshold?: number;
  guardian_threshold?: number;
  threshold?: number;
  manifest_hash?: string;
  plan_hash?: string;
  payload_hash?: string;
  approval_request?: ApprovalRequest;
}
export interface Federation {
  chain?: string;
  genesis_hash?: string;
  current?: FederationPolicy;
  incoming?: FederationPolicy;
  rotation?: Rotation;
  allowed_actions?: string[];
  hold_reason?: string;
}
export interface Dashboard {
  session?: Session;
  accounts: Account[];
  balances: Balance[];
  operations: Operation[];
  beneficiaries: Beneficiary[];
  activity: Activity[];
  guardians: Institution[];
  network: Network;
  audit?: Audit;
  assets: Asset[];
  reserves: Reserve[];
  federation?: Federation;
}
export type Page =
  | "overview"
  | "payments"
  | "banking"
  | "beneficiaries"
  | "activity"
  | "approvals"
  | "reserves"
  | "network"
  | "federation";
export type DialogState =
  | { type: "create"; kind: Exclude<Kind, "refund"> }
  | { type: "receive" }
  | { type: "operation"; id: string }
  | { type: "review"; operation: Operation; action: string }
  | { type: "bank"; operation?: Operation }
  | { type: "rotation"; action: string }
  | null;
