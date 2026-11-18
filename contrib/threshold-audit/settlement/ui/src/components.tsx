import {
  cloneElement,
  useEffect,
  useId,
  useRef,
  type ButtonHTMLAttributes,
  type ReactElement,
  type ReactNode,
} from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpFromLine,
  Building2,
  Check,
  ChevronRight,
  Copy,
  Download,
  FileText,
  Info,
  LayoutGrid,
  LockKeyhole,
  LogOut,
  Network,
  Plus,
  RefreshCw,
  Search,
  Send,
  ShieldCheck,
  Users,
  Wallet,
  X,
} from "lucide-react";
import { human } from "./domain";
const icons = {
  activity: Activity,
  download: ArrowDownToLine,
  upload: ArrowUpFromLine,
  arrow: ArrowRight,
  bank: Building2,
  check: Check,
  chevron: ChevronRight,
  copy: Copy,
  document: FileText,
  info: Info,
  grid: LayoutGrid,
  lock: LockKeyhole,
  logout: LogOut,
  network: Network,
  plus: Plus,
  refresh: RefreshCw,
  search: Search,
  send: Send,
  shield: ShieldCheck,
  users: Users,
  wallet: Wallet,
  close: X,
  export: Download,
};
export function Icon({ name }: { name: string }) {
  const C = icons[name as keyof typeof icons] || Info;
  return <C size={19} aria-hidden="true" />;
}
export function Button({
  symbol,
  children,
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { symbol?: string }) {
  return (
    <button type="button" className={`button ${className}`} {...props}>
      {symbol && <Icon name={symbol} />} {children}
    </button>
  );
}
export function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark">C</span>
      <div>
        <div className="brand-name">CEND</div>
        <div className="brand-caption">Institutional settlement</div>
      </div>
    </div>
  );
}
export function Badge({
  status = "not_reported",
  children,
}: {
  status?: string;
  children?: ReactNode;
}) {
  const style = [
    "settled",
    "confirmed",
    "ready",
    "delivered",
    "configured",
    "healthy",
    "reconciled",
    "active",
    "success",
    "available",
    "complete",
    "completed",
  ].includes(status)
    ? "success"
    : [
          "rejected",
          "failed",
          "unavailable",
          "unreachable",
          "mismatch",
          "error",
          "blocked",
        ].includes(status)
      ? "error"
      : [
            "draft",
            "not_started",
            "not_applicable",
            "unconfigured",
            "neutral",
          ].includes(status)
        ? "neutral"
        : "pending";
  return (
    <span className={`badge ${style}`}>
      <span className="dot" />
      {children || human(status)}
    </span>
  );
}
export function Empty({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Icon name="document" />
      </span>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
export function Heading({
  title,
  children,
  actions,
}: {
  title: string;
  children?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <h1>{title}</h1>
        <p>{children}</p>
      </div>
      <div className="heading-right">{actions}</div>
    </div>
  );
}
export function Panel({
  title,
  count,
  subtitle,
  actions,
  children,
  className = "",
}: {
  title: string;
  count?: number;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-header">
        <div>
          <h2>
            {title}
            {count !== undefined && <span className="count">{count}</span>}
          </h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}
export function KV({
  label,
  children,
}: {
  label: string;
  children?: ReactNode;
}) {
  return (
    <div className="kv">
      <span>{label}</span>
      <strong>{children ?? "—"}</strong>
    </div>
  );
}
export function CopyField({ label, value }: { label: string; value?: string }) {
  const id = useId();
  if (!value) return null;
  return (
    <div className="copy-block">
      <span id={id} className="muted">
        {label}
      </span>
      <div className="copy-field">
        <code aria-labelledby={id}>{value}</code>
        <button
          type="button"
          className="icon-button"
          aria-label={`Copy ${label}`}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
            } catch {
              /* Text remains selectable on HTTP mesh origins. */
            }
          }}
        >
          <Icon name="copy" />
        </button>
      </div>
    </div>
  );
}
export function Field({
  label,
  children,
  detail,
}: {
  label: string;
  children: ReactElement<{ id?: string; "aria-describedby"?: string }>;
  detail?: string;
}) {
  const generated = useId();
  const id = children.props.id || generated;
  return (
    <div className="form-field">
      <label htmlFor={id}>{label}</label>
      {cloneElement(children, {
        id,
        "aria-describedby": detail ? `${id}-detail` : undefined,
      })}
      {detail && <small id={`${id}-detail`}>{detail}</small>}
    </div>
  );
}
export function Modal({
  title,
  description,
  children,
  close,
  drawer = false,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  close: () => void;
  drawer?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const prior = document.activeElement;
    const el = ref.current!;
    el.showModal();
    return () => {
      el.close();
      if (prior instanceof HTMLElement && prior.isConnected) prior.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className={drawer ? "drawer" : ""}
      aria-labelledby={titleId}
      onCancel={(event) => {
        event.preventDefault();
        close();
      }}
    >
      <div className="dialog-header">
        <div>
          <h2 id={titleId}>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        <button
          type="button"
          className="icon-button"
          aria-label="Close dialog"
          onClick={close}
        >
          <Icon name="close" />
        </button>
      </div>
      {children}
    </dialog>
  );
}
export function ErrorNote({ error }: { error: unknown }) {
  return error ? (
    <p className="field-error" role="alert">
      {error instanceof Error ? error.message : String(error)}
    </p>
  ) : null;
}
export function Metric({
  title,
  value,
  detail,
  symbol,
}: {
  title: string;
  value: ReactNode;
  detail: string;
  symbol: string;
}) {
  return (
    <article className="metric">
      <div className="metric-label">
        <span>{title}</span>
        <Icon name={symbol} />
      </div>
      <div className="metric-value number">{value}</div>
      <p className="metric-detail">{detail}</p>
    </article>
  );
}
