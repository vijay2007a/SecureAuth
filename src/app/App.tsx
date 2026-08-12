import React, { useState, useEffect, useRef, Component } from "react";
import {
  Shield, LayoutDashboard, Zap, Lock, Wrench, History,
  Activity, Bell, BarChart2, Brain, FileText, UserCheck,
  Network, Settings, Search, ChevronDown, TrendingUp,
  Play, Pause, Upload, RefreshCw, Download,
  AlertTriangle, CheckCircle, XCircle, Info, AlertCircle,
  Eye, Plus, Trash2, Check, X, ArrowUp, ArrowDown,
  Database, Globe, Filter, Calendar, Users,
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell,
} from "recharts";
import { onAuthStateChanged, signInWithEmailAndPassword, signOut, type User } from "firebase/auth";
import { getMessaging, getToken, isSupported as isMessagingSupported, onMessage } from "firebase/messaging";
import { app as firebaseApp, auth, isFirebaseConfigured } from "./firebase";
import { clearAccessToken, getAccessToken, setAccessToken } from "./session";
import { LoginScreen } from "./LoginScreen";
import { wsEvents } from "./events";


// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

type Screen =
  | "dashboard" | "password-spray" | "credential-stuffing"
  | "custom-attack" | "attack-history" | "live-monitoring"
  | "alerts" | "analytics" | "detection-models" | "reports"
  | "test-accounts" | "ip-controls" | "settings";

type Severity = "critical" | "high" | "medium" | "low" | "info";
type ModelStatus = "active" | "inactive" | "training" | "error";

// ─────────────────────────────────────────────────────────────────────────────
// Mock Data
// ─────────────────────────────────────────────────────────────────────────────

const attackTrendsData = [
  { time: "12AM", normal: 45, spray: 12, stuffing: 8, blocked: 18 },
  { time: "4AM",  normal: 28, spray: 15, stuffing: 12, blocked: 22 },
  { time: "8AM",  normal: 120, spray: 45, stuffing: 35, blocked: 65 },
  { time: "12PM", normal: 180, spray: 120, stuffing: 95, blocked: 180 },
  { time: "4PM",  normal: 165, spray: 110, stuffing: 88, blocked: 165 },
  { time: "8PM",  normal: 90, spray: 45, stuffing: 38, blocked: 75 },
];

const seedFeed = [
  { id: 1,  time: "19:42:31", username: "john.doe",  ip: "185.199.110.24", result: "failed",  riskScore: 92, type: "Credential Stuffing" },
  { id: 2,  time: "19:42:29", username: "alice",      ip: "185.199.110.24", result: "failed",  riskScore: 88, type: "Credential Stuffing" },
  { id: 3,  time: "19:42:26", username: "charlie",    ip: "185.199.110.24", result: "failed",  riskScore: 85, type: "Password Spray" },
  { id: 4,  time: "19:42:24", username: "bob",        ip: "185.199.110.24", result: "failed",  riskScore: 83, type: "Password Spray" },
  { id: 5,  time: "19:42:20", username: "admin",      ip: "203.0.113.45",   result: "success", riskScore: 12, type: "Normal" },
  { id: 6,  time: "19:42:18", username: "michael",    ip: "185.199.110.24", result: "failed",  riskScore: 87, type: "Credential Stuffing" },
  { id: 7,  time: "19:42:15", username: "emily",      ip: "198.51.100.23",  result: "failed",  riskScore: 78, type: "Password Spray" },
  { id: 8,  time: "19:42:12", username: "david",      ip: "198.51.100.23",  result: "failed",  riskScore: 76, type: "Password Spray" },
  { id: 9,  time: "19:42:08", username: "sarah",      ip: "192.168.1.100",  result: "blocked", riskScore: 95, type: "Credential Stuffing" },
  { id: 10, time: "19:42:05", username: "tom",        ip: "10.0.0.1",       result: "success", riskScore: 8,  type: "Normal" },
];

const seedAlerts = [
  { id: 1, severity: "high"     as Severity, title: "Credential Stuffing Attack Detected",  desc: "IP 185.199.110.24 • 42 failed attempts",          time: "5 min ago",  acked: false },
  { id: 2, severity: "medium"   as Severity, title: "Password Spray Pattern Detected",       desc: "IP 198.51.100.23 • 17 accounts targeted",          time: "8 min ago",  acked: false },
  { id: 3, severity: "high"     as Severity, title: "Multiple Failed Logins",                desc: "IP 203.0.113.45 • 10 attempts in 2 minutes",       time: "12 min ago", acked: false },
  { id: 4, severity: "low"      as Severity, title: "Unusual Login Time Detected",           desc: "user@example.com • Login at 3:42 AM",              time: "25 min ago", acked: true  },
  { id: 5, severity: "critical" as Severity, title: "Brute Force Attack Blocked",            desc: "IP 91.108.4.200 • 500+ attempts blocked",          time: "1 hr ago",   acked: true  },
  { id: 6, severity: "medium"   as Severity, title: "Geographic Anomaly Detected",           desc: "Admin login from CN blocked by geo-filter",        time: "2 hr ago",   acked: true  },
];

const attackHistoryRows = [
  { id: 1, type: "Credential Stuffing", status: "detected",  startTime: "2025-08-11 19:42:00", duration: "2m 31s",  attempts: 42,  sourceIP: "185.199.110.24", blocked: true  },
  { id: 2, type: "Password Spray",      status: "detected",  startTime: "2025-08-11 19:34:00", duration: "8m 15s",  attempts: 17,  sourceIP: "198.51.100.23",  blocked: false },
  { id: 3, type: "Password Spray",      status: "completed", startTime: "2025-08-11 18:00:00", duration: "5m 40s",  attempts: 100, sourceIP: "10.0.0.1",       blocked: true  },
  { id: 4, type: "Credential Stuffing", status: "completed", startTime: "2025-08-11 16:22:00", duration: "3m 10s",  attempts: 75,  sourceIP: "172.16.0.5",     blocked: true  },
  { id: 5, type: "Custom Attack",       status: "completed", startTime: "2025-08-11 14:15:00", duration: "12m 05s", attempts: 200, sourceIP: "192.168.1.50",   blocked: false },
  { id: 6, type: "Password Spray",      status: "detected",  startTime: "2025-08-10 20:00:00", duration: "4m 22s",  attempts: 60,  sourceIP: "91.108.4.200",   blocked: true  },
];

const testAccountRows = [
  { id: 1, username: "john.doe@lab.com",  role: "Standard User", status: "active",    lastLogin: "19:42:20", attempts: 45, locked: false },
  { id: 2, username: "alice@lab.com",     role: "Standard User", status: "active",    lastLogin: "19:42:18", attempts: 38, locked: false },
  { id: 3, username: "charlie@lab.com",   role: "Admin",         status: "locked",    lastLogin: "19:41:00", attempts: 15, locked: true  },
  { id: 4, username: "bob@lab.com",       role: "Standard User", status: "active",    lastLogin: "19:40:00", attempts: 22, locked: false },
  { id: 5, username: "admin@lab.com",     role: "Super Admin",   status: "active",    lastLogin: "19:42:20", attempts:  5, locked: false },
  { id: 6, username: "michael@lab.com",   role: "Standard User", status: "suspended", lastLogin: "Yesterday", attempts: 87, locked: true },
];

const ipRows = [
  { id: 1, ip: "185.199.110.24", type: "blocked",     reason: "Credential Stuffing",  added: "19:42:00", attempts: 42,  country: "US"  },
  { id: 2, ip: "198.51.100.23",  type: "blocked",     reason: "Password Spray",        added: "19:34:00", attempts: 17,  country: "RU"  },
  { id: 3, ip: "203.0.113.45",   type: "allowlisted", reason: "Lab server",            added: "09:00:00", attempts:  5,  country: "US"  },
  { id: 4, ip: "91.108.4.200",   type: "blocked",     reason: "Brute Force",           added: "18:00:00", attempts: 500, country: "CN"  },
  { id: 5, ip: "10.0.0.0/24",    type: "allowlisted", reason: "Internal network",      added: "—",        attempts:  0,  country: "N/A" },
];

const modelsData = [
  { id: 1, name: "Rule-Based Engine",         type: "Rule-Based",    accuracy: 94.2, status: "active"   as ModelStatus, version: "v2.1.0",      updated: "Aug 10", detections: 1420, fp: 18 },
  { id: 2, name: "Random Forest Classifier",  type: "ML Model",      accuracy: 96.8, status: "active"   as ModelStatus, version: "v3.0.1",      updated: "Aug 09", detections: 1580, fp: 12 },
  { id: 3, name: "Anomaly Detection Engine",  type: "Anomaly",       accuracy: 91.5, status: "active"   as ModelStatus, version: "v1.5.2",      updated: "Aug 08", detections:  890, fp: 24 },
  { id: 4, name: "LSTM Neural Network",       type: "Deep Learning", accuracy: 97.2, status: "training" as ModelStatus, version: "v1.0-beta",   updated: "Aug 11", detections:    0, fp:  0 },
];

const dailyData = [
  { date: "Mon", attacks: 85,  detected: 82,  blocked: 75  },
  { date: "Tue", attacks: 120, detected: 118, blocked: 110 },
  { date: "Wed", attacks: 95,  detected: 93,  blocked: 88  },
  { date: "Thu", attacks: 145, detected: 142, blocked: 130 },
  { date: "Fri", attacks: 180, detected: 176, blocked: 165 },
  { date: "Sat", attacks: 60,  detected: 58,  blocked: 55  },
  { date: "Sun", attacks: 42,  detected: 40,  blocked: 38  },
];

const typeDistribution = [
  { name: "Credential Stuffing", value: 42, color: "#ef4444" },
  { name: "Password Spray",      value: 35, color: "#f59e0b" },
  { name: "Brute Force",         value: 15, color: "#8b5cf6" },
  { name: "Other",               value: 8,  color: "#64748b" },
];

const reportRows = [
  { id: 1, name: "Weekly Attack Summary",            type: "Summary",       generated: "2025-08-11", size: "2.4 MB", status: "ready"      },
  { id: 2, name: "Detection Model Performance",      type: "Analytics",     generated: "2025-08-10", size: "1.8 MB", status: "ready"      },
  { id: 3, name: "Credential Stuffing Simulation",   type: "Simulation",    generated: "2025-08-09", size: "3.1 MB", status: "ready"      },
  { id: 4, name: "IP Threat Intelligence Report",    type: "Intelligence",  generated: "2025-08-08", size: "1.2 MB", status: "generating" },
];

const API_BASE_URL = import.meta.env.VITE_API_URL ?? import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
const WS_BASE_URL = import.meta.env.VITE_WS_URL ?? import.meta.env.VITE_WS_BASE_URL ?? "ws://127.0.0.1:8000";
const DEV_AUTH_TOKEN = import.meta.env.VITE_DEV_AUTH_TOKEN ?? "dev-admin-token";
const FIREBASE_VAPID_KEY = import.meta.env.VITE_FIREBASE_VAPID_KEY ?? "";

const authHeaders = () => ({
  Authorization: `Bearer ${getAccessToken() || DEV_AUTH_TOKEN}`,
});

const apiFetch = async (path: string, init: RequestInit = {}) => {
  const isFormData = init.body instanceof FormData;
  const headers: Record<string, string> = {
    ...authHeaders(),
    ...((init.headers as Record<string, string>) ?? {}),
  };
  if (!isFormData && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers,
  });

  if (!response.ok) {
    let errorMsg = `Request failed (${response.status})`;
    try {
      const text = await response.text();
      const parsed = JSON.parse(text);
      errorMsg = parsed.detail || parsed.message || text;
    } catch {
      // Use fallback errorMsg
    }
    throw new Error(errorMsg);
  }
  if (response.status === 204) return null;
  return response.json();
};

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("Uncaught UI Error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="bg-white rounded-xl border border-red-200 shadow-sm p-6 max-w-xl mx-auto my-8">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-lg bg-red-50 flex items-center justify-center text-red-600 font-bold shrink-0">
              <AlertTriangle size={20} />
            </div>
            <div>
              <h3 className="font-semibold text-slate-800 text-sm">Screen Render Error</h3>
              <p className="text-xs text-slate-500">An error occurred while rendering this view.</p>
            </div>
          </div>
          <div className="bg-slate-50 rounded-lg p-3 border border-slate-200 font-mono text-xs text-red-600 mb-4 overflow-x-auto">
            {this.state.error?.message || "Unknown error"}
          </div>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-semibold text-xs transition"
          >
            Try Reloading Screen
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}


const wsUrl = (path: string) => `${WS_BASE_URL}${path}`;

const buildMessagingWorkerUrl = () => {
  return "/firebase-messaging-sw.js";
};

const formatAttackType = (value: string) => {
  if (value === "password_spray") return "Password Spray";
  if (value === "credential_stuffing") return "Credential Stuffing";
  if (value === "normal") return "Normal";
  if (value === "custom") return "Custom Attack";
  return value.replace(/_/g, " ");
};

const formatEventRow = (event: any) => ({
  id: event.id,
  time: event.timestamp ? new Date(event.timestamp).toLocaleTimeString([], { hour12: false }) : "—",
  username: event.username,
  ip: event.source_ip,
  result: event.blocked ? "blocked" : event.success ? "success" : "failed",
  riskScore: event.risk_score ?? 0,
  type: formatAttackType(event.attack_type ?? event.attackClass ?? event.attack_class ?? "normal"),
});

// ─────────────────────────────────────────────────────────────────────────────
// Shared micro-components
// ─────────────────────────────────────────────────────────────────────────────

const SeverityBadge = ({ severity }: { severity: Severity }) => {
  const cls: Record<Severity, string> = {
    critical: "bg-red-100 text-red-700 border-red-200",
    high:     "bg-red-50  text-red-600  border-red-200",
    medium:   "bg-amber-50 text-amber-700 border-amber-200",
    low:      "bg-blue-50  text-blue-600  border-blue-200",
    info:     "bg-slate-50 text-slate-600 border-slate-200",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border capitalize ${cls[severity]}`}>
      {severity}
    </span>
  );
};

const TypeBadge = ({ type }: { type: string }) => {
  const cls: Record<string, string> = {
    "Credential Stuffing": "bg-red-100 text-red-700",
    "Password Spray":      "bg-amber-100 text-amber-700",
    "Normal":              "bg-emerald-100 text-emerald-700",
    "Brute Force":         "bg-purple-100 text-purple-700",
    "Custom Attack":       "bg-violet-100 text-violet-700",
  };
  return (
    <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-medium ${cls[type] ?? "bg-slate-100 text-slate-600"}`}>
      {type}
    </span>
  );
};

const ResultBadge = ({ result }: { result: string }) => {
  const cls: Record<string, string> = {
    failed:  "bg-red-100 text-red-600",
    success: "bg-emerald-100 text-emerald-700",
    blocked: "bg-slate-100 text-slate-600",
  };
  return (
    <span className={`px-2.5 py-0.5 rounded text-[11px] font-semibold capitalize ${cls[result] ?? "bg-slate-100 text-slate-600"}`}>
      {result.charAt(0).toUpperCase() + result.slice(1)}
    </span>
  );
};

const RiskScore = ({ score }: { score: number }) => {
  const color = score >= 70 ? "text-red-600" : score >= 30 ? "text-amber-600" : "text-emerald-600";
  return <span className={`font-mono font-semibold text-[13px] ${color}`}>{score} / 100</span>;
};

const StatusDot = ({ status }: { status: ModelStatus }) => {
  const c: Record<ModelStatus, string> = {
    active:   "bg-emerald-500",
    inactive: "bg-slate-400",
    training: "bg-blue-500 animate-pulse",
    error:    "bg-red-500",
  };
  return <span className={`inline-block w-2 h-2 rounded-full ${c[status]}`} />;
};

const CircularProgress = ({ value, size = 140 }: { value: number; size?: number }) => {
  const r = (size - 20) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (value / 100) * circ;
  return (
    <div className="relative flex items-center justify-center shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#e2e8f0" strokeWidth={10} />
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none" stroke="#10b981" strokeWidth={10}
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute text-center">
        <p className="text-2xl font-bold text-slate-800 leading-none">{value}%</p>
        <p className="text-[10px] text-slate-400 mt-1 leading-tight">Detection<br />Accuracy</p>
      </div>
    </div>
  );
};

const KPICard = ({
  title, value, trend, trendValue, icon: Icon, iconBg, sub,
}: {
  title: string; value: string; trend?: "up" | "down"; trendValue?: string;
  icon: React.ElementType; iconBg: string; sub?: string;
}) => (
  <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm hover:shadow-md transition-shadow">
    <div className="flex items-start justify-between mb-4">
      <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{title}</p>
      <div className={`p-2.5 rounded-lg ${iconBg}`}>
        <Icon size={16} className="text-white" />
      </div>
    </div>
    <p className="text-2xl font-bold text-slate-800 mb-1">{value}</p>
    {trendValue && trend ? (
      <div className={`flex items-center gap-1 text-xs font-medium ${trend === "up" ? "text-emerald-600" : "text-red-500"}`}>
        {trend === "up" ? <ArrowUp size={11} /> : <ArrowDown size={11} />}
        <span>{trendValue}</span>
        <span className="text-slate-400 font-normal ml-0.5">vs last 24h</span>
      </div>
    ) : (
      <p className="text-xs text-slate-400">{sub ?? ""}</p>
    )}
  </div>
);

const SectionHeader = ({
  title, subtitle, actions,
}: { title: string; subtitle?: string; actions?: React.ReactNode }) => (
  <div className="flex items-start justify-between mb-6">
    <div>
      <h1 className="text-lg font-bold text-slate-800">{title}</h1>
      {subtitle && <p className="text-sm text-slate-500 mt-0.5">{subtitle}</p>}
    </div>
    {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
  </div>
);

const Btn = ({
  children, variant = "primary", size = "md", onClick, disabled, className = "",
}: {
  children: React.ReactNode; variant?: "primary" | "secondary" | "danger" | "ghost" | "outline" | "violet";
  size?: "sm" | "md"; onClick?: () => void; disabled?: boolean; className?: string;
}) => {
  const base = "inline-flex items-center justify-center gap-1.5 font-medium rounded-lg transition-all select-none";
  const sz = { sm: "px-3 py-1.5 text-xs", md: "px-4 py-2 text-sm" };
  const v: Record<string, string> = {
    primary:   "bg-blue-600 text-white hover:bg-blue-700 shadow-sm",
    secondary: "bg-slate-100 text-slate-700 hover:bg-slate-200",
    danger:    "bg-red-600 text-white hover:bg-red-700",
    ghost:     "text-slate-600 hover:bg-slate-100",
    outline:   "border border-slate-300 text-slate-700 hover:bg-slate-50",
    violet:    "bg-violet-600 text-white hover:bg-violet-700",
  };
  return (
    <button
      onClick={onClick} disabled={disabled}
      className={`${base} ${sz[size]} ${v[variant]} ${disabled ? "opacity-50 cursor-not-allowed" : ""} ${className}`}
    >
      {children}
    </button>
  );
};

const FormInput = ({
  label, value, onChange, type = "text", placeholder, className = "",
}: {
  label?: string; value: string | number; onChange: (v: string) => void;
  type?: string; placeholder?: string; className?: string;
}) => (
  <div className={className}>
    {label && <label className="block text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wide">{label}</label>}
    <input
      type={type} value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full px-3 py-2 bg-[#f8fafc] border border-slate-200 rounded-lg text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 transition"
    />
  </div>
);

const Toast = ({ message, type, onClose }: { message: string; type: "success" | "error" | "info"; onClose: () => void }) => {
  const cls = { success: "bg-emerald-600", error: "bg-red-600", info: "bg-blue-600" };
  const Icon = type === "success" ? CheckCircle : type === "error" ? XCircle : Info;
  return (
    <div className={`fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl text-white shadow-2xl ${cls[type]} max-w-sm`}>
      <Icon size={15} className="shrink-0" />
      <span className="text-sm font-medium">{message}</span>
      <button onClick={onClose} className="ml-1 opacity-70 hover:opacity-100"><X size={13} /></button>
    </div>
  );
};

const ProgressBar = ({ value, color = "bg-blue-500" }: { value: number; color?: string }) => (
  <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
    <div className={`h-full rounded-full transition-all duration-200 ${color}`} style={{ width: `${value}%` }} />
  </div>
);

// ─────────────────────────────────────────────────────────────────────────────
// Sidebar
// ─────────────────────────────────────────────────────────────────────────────

type NavItem = { id: Screen; label: string; icon: React.ElementType; badge?: number };
type NavGroup = { label: string; items: NavItem[] };

const navGroups: NavGroup[] = [
  {
    label: "Overview",
    items: [{ id: "dashboard", label: "Dashboard", icon: LayoutDashboard }],
  },
  {
    label: "Attack Simulation",
    items: [
      { id: "password-spray",       label: "Password Spray",       icon: Zap      },
      { id: "credential-stuffing",  label: "Credential Stuffing",  icon: Lock     },
      { id: "custom-attack",        label: "Custom Attack",        icon: Wrench   },
      { id: "attack-history",       label: "Attack History",       icon: History  },
    ],
  },
  {
    label: "Detection & Monitoring",
    items: [
      { id: "live-monitoring",   label: "Live Monitor",      icon: Activity  },
      { id: "alerts",            label: "Alerts",            icon: Bell      },
      { id: "analytics",         label: "Analytics",         icon: BarChart2 },
      { id: "detection-models",  label: "Detection Models",  icon: Brain     },
      { id: "reports",           label: "Reports",           icon: FileText  },
    ],
  },
  {
    label: "Management",
    items: [
      { id: "test-accounts", label: "Test Accounts", icon: UserCheck },
      { id: "ip-controls",   label: "IP Controls",   icon: Network   },
      { id: "settings",      label: "Settings",      icon: Settings  },
    ],
  },
];

const Sidebar = ({ current, onChange, unreadAlertsCount }: { current: Screen; onChange: (s: Screen) => void; unreadAlertsCount: number }) => (
  <aside className="w-[218px] h-screen flex flex-col shrink-0 overflow-y-auto" style={{ background: "#0d1526" }}>
    {/* Logo */}
    <div className="px-4 py-5 border-b" style={{ borderColor: "rgba(255,255,255,0.06)" }}>
      <div className="flex items-center gap-2.5">
        <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center shrink-0 shadow-sm">
          <Shield size={15} className="text-white" />
        </div>
        <div>
          <p className="text-white font-bold text-sm leading-tight">SecureAuth</p>
          <p className="text-[10px] leading-tight" style={{ color: "#4a6585" }}>Simulate. Detect. Stay Secure.</p>
        </div>
      </div>
    </div>

    {/* Nav */}
    <nav className="flex-1 px-3 py-4 space-y-5 overflow-y-auto">
      {navGroups.map(group => (
        <div key={group.label}>
          <p className="text-[10px] font-bold uppercase tracking-widest px-2 mb-1.5" style={{ color: "#2d4060" }}>
            {group.label}
          </p>
          <ul className="space-y-0.5">
            {group.items.map(item => {
              const isActive = current === item.id;
              const badge = item.id === "alerts" && unreadAlertsCount > 0 ? unreadAlertsCount : item.badge;
              return (
                <li key={item.id}>
                  <button
                    onClick={() => onChange(item.id)}
                    className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[13px] font-medium transition-all ${
                      isActive ? "bg-blue-600 text-white shadow-sm" : "hover:bg-white/[0.05]"
                    }`}
                    style={{ color: isActive ? "#fff" : "#7a94b8" }}
                  >
                    <item.icon size={14} className="shrink-0" />
                    <span className="flex-1 text-left">{item.label}</span>
                    {Boolean(badge) && (
                      <span className="bg-red-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[18px] text-center leading-none">
                        {badge}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>

    {/* Footer */}
    <div className="px-4 py-4 border-t" style={{ borderColor: "rgba(255,255,255,0.06)" }}>
      <div className="flex items-center gap-2.5 mb-2">
        <div className="w-7 h-7 rounded-full bg-blue-700 flex items-center justify-center shrink-0">
          <Shield size={11} className="text-blue-200" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-white text-xs font-semibold truncate">Security Research</p>
          <p className="text-[10px] truncate" style={{ color: "#374f6b" }}>Controlled lab environment</p>
        </div>
      </div>
      <p className="text-[10px] font-mono ml-0.5" style={{ color: "#283d58" }}>v1.0.0</p>
    </div>
  </aside>
);

// ─────────────────────────────────────────────────────────────────────────────
// TopBar
// ─────────────────────────────────────────────────────────────────────────────

const TopBar = ({
  onNav,
  currentUser,
  onLogout,
  wsStatus,
  unreadAlertsCount,
}: {
  onNav: (s: Screen) => void;
  currentUser: User | null;
  onLogout: () => void;
  wsStatus: string;
  unreadAlertsCount: number;
}) => {
  const [notifOpen, setNotifOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  const statusConfig = {
    connected: { color: "bg-emerald-500", text: "text-emerald-700", bg: "bg-emerald-50", border: "border-emerald-200", label: "Connected" },
    connecting: { color: "bg-amber-500", text: "text-amber-700", bg: "bg-amber-50", border: "border-amber-200", label: "Reconnecting..." },
    disconnected: { color: "bg-red-500", text: "text-red-700", bg: "bg-red-50", border: "border-red-200", label: "Disconnected" },
  }[wsStatus] || { color: "bg-slate-400", text: "text-slate-700", bg: "bg-slate-50", border: "border-slate-200", label: "Offline" };

  return (
    <header className="h-[54px] bg-white border-b border-slate-200 flex items-center px-5 gap-3 shrink-0 z-20">
      {/* Search */}
      <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 w-64">
        <Search size={13} className="text-slate-400 shrink-0" />
        <input
          type="text"
          placeholder="Search logs, IPs, or attacks..."
          className="bg-transparent text-[13px] text-slate-600 placeholder-slate-400 outline-none flex-1 min-w-0"
        />
        <kbd className="text-[10px] text-slate-400 bg-white border border-slate-200 px-1.5 py-0.5 rounded font-mono shrink-0">⌘K</kbd>
      </div>

      <div className="flex-1" />

      {/* System Status */}
      <div className={`flex items-center gap-1.5 ${statusConfig.bg} border ${statusConfig.border} px-3 py-1.5 rounded-full`}>
        <span className={`w-1.5 h-1.5 rounded-full ${statusConfig.color} ${wsStatus === "connected" ? "animate-pulse" : ""}`} />
        <span className={`text-[11px] font-semibold ${statusConfig.text}`}>{statusConfig.label}</span>
      </div>

      {/* Notifications */}
      <div className="relative">
        <button
          onClick={() => { setNotifOpen(o => !o); setProfileOpen(false); }}
          className="relative w-9 h-9 flex items-center justify-center rounded-lg hover:bg-slate-100 transition text-slate-500"
        >
          <Bell size={17} />
          {unreadAlertsCount > 0 && (
            <span className="absolute top-1.5 right-1.5 w-4 h-4 bg-red-500 rounded-full text-[9px] text-white flex items-center justify-center font-bold border-2 border-white">
              {unreadAlertsCount}
            </span>
          )}
        </button>
        {notifOpen && (
          <div className="absolute right-0 top-11 w-72 bg-white rounded-xl shadow-xl border border-slate-200 z-50 overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-100 flex items-center justify-between">
              <p className="font-semibold text-slate-800 text-sm">Notifications</p>
              <span className="text-[11px] text-slate-400">{unreadAlertsCount} unread</span>
            </div>
            <div className="px-4 py-3 text-xs text-slate-500">
              {unreadAlertsCount > 0 ? `${unreadAlertsCount} unacknowledged alert(s) requiring attention.` : "No unread alerts."}
            </div>
            <div className="px-4 py-2.5 border-t border-slate-100">
              <button onClick={() => { onNav("alerts"); setNotifOpen(false); }} className="text-xs text-blue-600 font-medium hover:underline">
                View all alerts →
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Avatar */}
      <div className="relative">
        <button
          onClick={() => { setProfileOpen(o => !o); setNotifOpen(false); }}
          className="flex items-center gap-2.5 hover:bg-slate-50 rounded-lg px-2 py-1.5 transition"
        >
          <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold text-sm">
            {(currentUser?.displayName || currentUser?.email || "U").charAt(0).toUpperCase()}
          </div>
          <div className="text-left hidden sm:block">
            <p className="text-xs font-semibold text-slate-700 leading-tight truncate max-w-[120px]">{currentUser?.displayName || currentUser?.email || "Signed in"}</p>
            <p className="text-[10px] text-slate-400 leading-tight">{currentUser?.email ? "Firebase Auth" : "Dev Session"}</p>
          </div>
          <ChevronDown size={12} className="text-slate-400" />
        </button>
        {profileOpen && (
          <div className="absolute right-0 top-12 w-44 bg-white rounded-xl shadow-xl border border-slate-200 z-50 py-1.5 overflow-hidden">
            {[["Profile", null], ["Settings", "settings" as Screen], ["API Keys", "settings" as Screen]].map(([label, nav]) => (
              <button
                key={label}
                onClick={() => { if (nav) onNav(nav as Screen); setProfileOpen(false); }}
                className={`w-full text-left px-4 py-2 text-[13px] hover:bg-slate-50 ${label === "Sign Out" ? "text-red-600 border-t border-slate-100 mt-1" : "text-slate-700"}`}
              >
                {label}
              </button>
            ))}
            <button
              onClick={() => { setProfileOpen(false); onLogout(); }}
              className="w-full text-left px-4 py-2 text-[13px] text-red-600 border-t border-slate-100 mt-1 hover:bg-slate-50"
            >
              Sign Out
            </button>
          </div>
        )}
      </div>
    </header>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard Screen
// ─────────────────────────────────────────────────────────────────────────────

const DashboardScreen = ({ onNav, canSendTestAlert }: { onNav: (s: Screen) => void; canSendTestAlert: boolean }) => {
  const [sprayPass, setSprayPass] = useState("Spring2025!");
  const [sprayTargets, setSprayTargets] = useState("12");
  const [sprayDelay, setSprayDelay] = useState("0");
  const [maxAttempts, setMaxAttempts] = useState("12");
  const [sprayRunning, setSprayRunning] = useState(false);
  const [stuffRunning, setStuffRunning] = useState(false);
  const [testAlertRunning, setTestAlertRunning] = useState(false);
  const [sprayPct, setSprayPct] = useState(0);
  const [stuffPct, setStuffPct] = useState(0);
  const [feedFilter, setFeedFilter] = useState("All");
  const [feedPaused, setFeedPaused] = useState(false);
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);
  const [page, setPage] = useState(1);
  const [dashboard, setDashboard] = useState<any>(null);

  const showToast = (msg: string, type: "success" | "error" | "info") => {
    setToast({ msg, type });
    window.setTimeout(() => setToast(null), 4000);
  };

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const data = await apiFetch("/api/dashboard");
        if (active) setDashboard(data);
      } catch (error) {
        console.error(error);
      }
    };
    load();
    const iv = window.setInterval(() => {
      if (!feedPaused) load();
    }, 5000);
    return () => {
      active = false;
      window.clearInterval(iv);
    };
  }, [feedPaused]);

  const runSpray = async () => {
    setSprayRunning(true);
    setSprayPct(100);
    try {
      await apiFetch("/api/simulations/password-spray", {
        method: "POST",
        body: JSON.stringify({
          name: "Dashboard Password Spray",
          source_ip: "198.51.100.23",
          attempts: Number(sprayTargets) || 12,
          account_count: Number(sprayTargets) || 12,
          delay_seconds: Number(sprayDelay) || 0,
          password: sprayPass,
          attack_pattern: "password_spray",
        }),
      });
      showToast("Password Spray simulation completed", "success");
      setDashboard(await apiFetch("/api/dashboard"));
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Simulation failed", "error");
    } finally {
      setSprayRunning(false);
      setSprayPct(0);
    }
  };

  const runStuff = async () => {
    setStuffRunning(true);
    setStuffPct(100);
    try {
      await apiFetch("/api/simulations/credential-stuffing", {
        method: "POST",
        body: JSON.stringify({
          name: "Dashboard Credential Stuffing",
          source_ip: "185.199.110.24",
          attempts: Number(maxAttempts) || 12,
          account_count: Number(maxAttempts) || 12,
          delay_seconds: 0,
          attack_pattern: "credential_stuffing",
          credentials: Array.from({ length: Number(maxAttempts) || 12 }, (_, index) => ({
            username: `user${String(index + 1).padStart(3, "0")}@lab.local`,
            password: `Password${index + 1}!`,
          })),
        }),
      });
      showToast("Credential Stuffing simulation completed", "info");
      setDashboard(await apiFetch("/api/dashboard"));
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Simulation failed", "error");
    } finally {
      setStuffRunning(false);
      setStuffPct(0);
    }
  };

  const sendTestAlert = async () => {
    setTestAlertRunning(true);
    try {
      const result = await apiFetch("/api/notifications/test-alert", { method: "POST" });
      showToast(result?.skipped ? "Test alert skipped by cooldown" : "Test alert sent", "success");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Test alert failed", "error");
    } finally {
      setTestAlertRunning(false);
    }
  };

  const feedRows = (dashboard?.liveFeed ?? seedFeed).map(formatEventRow);
  const alerts = dashboard?.recentAlerts ?? seedAlerts;
  const attackTrendData = dashboard?.attackTrends ?? attackTrendsData;
  const filteredFeed = feedFilter === "All" ? feedRows : feedRows.filter((d: any) => d.type === feedFilter);
  const paged = filteredFeed.slice((page - 1) * 6, page * 6);
  const totals = dashboard?.totals ?? { loginAttempts: 12482, detectedAttacks: 27, uniqueIPs: 48, testAccounts: 100 };
  const models = dashboard?.models ?? [];

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-800 leading-tight">Password Attack Simulation &amp; Detection Framework</h1>
          <p className="text-sm text-slate-500 mt-0.5">Simulate controlled attacks. Detect malicious activity. Analyze patterns.</p>
        </div>
        <div className="flex items-center gap-2 shrink-0 mt-1">
          {canSendTestAlert && (
            <button
              onClick={sendTestAlert}
              disabled={testAlertRunning}
              className="px-3 py-1.5 rounded-lg text-[11px] font-semibold border border-amber-200 bg-amber-50 text-amber-700 hover:bg-amber-100 disabled:opacity-60 transition"
            >
              {testAlertRunning ? "Sending..." : "Send Test Security Alert"}
            </button>
          )}
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400 shrink-0 mt-1">
            <Calendar size={12} />
            <span>{new Date().toLocaleString()}</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <KPICard title="Total Login Attempts" value={String(totals.loginAttempts ?? 0)} trend="up" trendValue="real-time" icon={Users} iconBg="bg-blue-500" />
        <KPICard title="Detected Attacks" value={String(totals.detectedAttacks ?? 0)} trend="up" trendValue="live" icon={AlertTriangle} iconBg="bg-red-500" />
        <KPICard title="Unique IPs" value={String(totals.uniqueIPs ?? 0)} trend="up" trendValue="live" icon={Globe} iconBg="bg-violet-500" />
        <KPICard title="Test Accounts" value={String(totals.testAccounts ?? 0)} icon={UserCheck} iconBg="bg-emerald-500" sub="Active in lab" />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 bg-blue-50 rounded-lg flex items-center justify-center shrink-0">
              <Zap size={17} className="text-blue-600" />
            </div>
            <div>
              <p className="font-semibold text-slate-800 text-sm">Password Spray Attack</p>
              <p className="text-[11px] text-slate-400">Uses a single password across multiple accounts to avoid lockouts.</p>
            </div>
          </div>
          <div className="space-y-3 mb-4">
            <FormInput label="Password" value={sprayPass} onChange={setSprayPass} placeholder="Enter password" />
            <div className="grid grid-cols-2 gap-2">
              <FormInput label="Target Accounts" value={sprayTargets} onChange={setSprayTargets} type="number" />
              <FormInput label="Delay (seconds)" value={sprayDelay} onChange={setSprayDelay} type="number" />
            </div>
          </div>
          {sprayRunning && (
            <div className="mb-3">
              <div className="flex justify-between text-[11px] text-slate-500 mb-1">
                <span>Running spray...</span><span>{sprayPct}%</span>
              </div>
              <ProgressBar value={sprayPct} color="bg-blue-500" />
            </div>
          )}
          <button onClick={runSpray} disabled={sprayRunning} className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white rounded-lg text-sm font-semibold flex items-center justify-center gap-2 transition shadow-sm">
            <Play size={13} />
            {sprayRunning ? "Running..." : "Run Password Spray"}
          </button>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 bg-red-50 rounded-lg flex items-center justify-center shrink-0">
              <Database size={17} className="text-red-500" />
            </div>
            <div>
              <p className="font-semibold text-slate-800 text-sm">Credential Stuffing Attack</p>
              <p className="text-[11px] text-slate-400">Uses leaked credential lists to simulate real-world attacks.</p>
            </div>
          </div>
          <div className="space-y-3 mb-4">
            <div>
              <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Credential List</label>
              <div className="flex items-center gap-2 px-3 py-2 bg-[#f8fafc] border border-slate-200 rounded-lg hover:border-slate-300 transition cursor-pointer">
                <Upload size={12} className="text-slate-400 shrink-0" />
                <span className="text-[13px] text-slate-500 flex-1">Synthetic list</span>
                <span className="text-[11px] text-slate-400 bg-slate-100 px-2 py-0.5 rounded font-mono">lab-only</span>
              </div>
            </div>
            <FormInput label="Max Attempts" value={maxAttempts} onChange={setMaxAttempts} type="number" />
          </div>
          {stuffRunning && (
            <div className="mb-3">
              <div className="flex justify-between text-[11px] text-slate-500 mb-1">
                <span>Running stuffing...</span><span>{stuffPct}%</span>
              </div>
              <ProgressBar value={stuffPct} color="bg-red-500" />
            </div>
          )}
          <button onClick={runStuff} disabled={stuffRunning} className="w-full py-2.5 bg-red-600 hover:bg-red-700 disabled:bg-red-300 text-white rounded-lg text-sm font-semibold flex items-center justify-center gap-2 transition shadow-sm">
            <Play size={13} />
            {stuffRunning ? "Running..." : "Run Credential Stuffing"}
          </button>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Shield size={15} className="text-blue-600" />
              <p className="font-semibold text-slate-800 text-sm">Detection Engine Status</p>
            </div>
            <span className="text-[10px] font-bold text-emerald-600 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full">Active</span>
          </div>
          <div className="flex items-center gap-3">
            <CircularProgress value={Math.min(99, Math.max(80, totals.detectedAttacks ? 96 : 88))} size={130} />
            <div className="flex-1 space-y-3">
              {(models.length ? models : [
                { name: "Rule-based Engine", status: "active" },
                { name: "ML Model (Random Forest)", status: "inactive" },
                { name: "Anomaly Detection", status: "active" },
                { name: "Real-time Monitoring", status: "active" },
              ]).map((model: any) => (
                <div key={model.name} className="flex items-center justify-between gap-2">
                  <span className="text-[11px] text-slate-600 leading-tight">{model.name}</span>
                  <div className="flex items-center gap-1 shrink-0">
                    <StatusDot status={model.status === "active" || model.status === "training" ? "active" : "inactive"} />
                    <span className="text-[11px] text-emerald-600 font-semibold capitalize">{model.status ?? "active"}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <BarChart2 size={15} className="text-blue-600" />
              <p className="font-semibold text-slate-800 text-sm">Attack Trends</p>
            </div>
            <select className="text-[12px] text-slate-600 bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 outline-none">
              <option>Last 24 Hours</option>
              <option>Last 7 Days</option>
              <option>Last 30 Days</option>
            </select>
          </div>
          <div className="flex items-center gap-4 mb-3">
            {[{ label: "Normal", color: "#3b82f6" }, { label: "Spray", color: "#f59e0b" }, { label: "Stuffing", color: "#ef4444" }, { label: "Blocked", color: "#9ca3af" }].map(l => (
              <div key={l.label} className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ background: l.color }} />
                <span className="text-[11px] text-slate-500">{l.label}</span>
              </div>
            ))}
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={attackTrendData} margin={{ top: 4, right: 4, bottom: 0, left: -12 }}>
              <defs>
                {[["attacks", "#3b82f6"]].map(([id, color]) => (
                  <linearGradient key={id} id={`g-${id}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={color as string} stopOpacity={0.15} />
                    <stop offset="95%" stopColor={color as string} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: "1px solid #e2e8f0", boxShadow: "0 4px 12px rgba(0,0,0,0.08)" }} />
              <Area type="monotone" dataKey="attacks" stroke="#3b82f6" strokeWidth={2} fill="url(#g-attacks)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Bell size={15} className="text-red-500" />
              <p className="font-semibold text-slate-800 text-sm">Recent Alerts</p>
            </div>
            <button onClick={() => onNav("alerts")} className="text-[11px] text-blue-600 font-medium hover:underline">View All</button>
          </div>
          <div className="space-y-2.5">
            {alerts.slice(0, 3).map((alert: any) => (
              <div key={alert.id} className="p-3 rounded-lg border border-slate-100 hover:border-slate-200 hover:bg-slate-50/40 transition cursor-pointer group">
                <div className="flex items-start gap-2.5">
                  <div className={`mt-0.5 w-5 h-5 rounded-full flex items-center justify-center shrink-0 ${alert.severity === "high" || alert.severity === "critical" ? "bg-red-100" : alert.severity === "medium" ? "bg-amber-100" : "bg-blue-100"}`}>
                    <AlertCircle size={11} className={alert.severity === "high" || alert.severity === "critical" ? "text-red-600" : alert.severity === "medium" ? "text-amber-600" : "text-blue-600"} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] font-semibold text-slate-700 leading-tight">{alert.attack_type ?? alert.title ?? "Alert"}</p>
                    <p className="text-[10px] text-slate-400 mt-0.5 truncate">{alert.explanation ?? alert.desc ?? ""}</p>
                  </div>
                </div>
                <div className="flex items-center justify-between mt-1.5 ml-7">
                  <p className="text-[10px] text-slate-400">{alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : alert.time}</p>
                  <SeverityBadge severity={(alert.severity ?? "info") as Severity} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
        <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="font-semibold text-slate-800 text-sm">Live Activity Feed</span>
            </div>
            <span className="text-[11px] text-slate-400">Real-time login attempts</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => setFeedPaused(p => !p)} className="flex items-center gap-1.5 text-[12px] text-slate-600 bg-slate-50 border border-slate-200 px-3 py-1.5 rounded-lg hover:bg-slate-100 transition">
              {feedPaused ? <Play size={11} /> : <Pause size={11} />}
              {feedPaused ? "Resume" : "Pause"}
            </button>
            <div className="relative">
              <select value={feedFilter} onChange={e => { setFeedFilter(e.target.value); setPage(1); }} className="text-[12px] text-slate-600 bg-slate-50 border border-slate-200 rounded-lg pl-7 pr-3 py-1.5 outline-none appearance-none">
                <option>All</option>
                <option>Credential Stuffing</option>
                <option>Password Spray</option>
                <option>Normal</option>
              </select>
              <Filter size={10} className="absolute left-2 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
            </div>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[700px]">
            <thead>
              <tr className="border-b border-slate-100">
                {["Time", "Username", "IP Address", "Result", "Risk Score", "Attack Type"].map(h => (
                  <th key={h} className="text-left px-5 py-3 text-[10px] font-bold text-slate-400 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {paged.map((row: any) => (
                <tr key={row.id} className="hover:bg-slate-50/60 transition-colors">
                  <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.time}</td>
                  <td className="px-5 py-3 text-[13px] font-semibold text-slate-700">{row.username}</td>
                  <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.ip}</td>
                  <td className="px-5 py-3"><ResultBadge result={row.result} /></td>
                  <td className="px-5 py-3"><RiskScore score={row.riskScore} /></td>
                  <td className="px-5 py-3"><TypeBadge type={row.type} /></td>
                </tr>
              ))}
              {paged.length === 0 && <tr><td colSpan={6} className="px-5 py-12 text-center text-sm text-slate-400">No matching entries</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="px-5 py-3 border-t border-slate-100 flex items-center justify-between">
          <p className="text-[11px] text-slate-400">Showing {paged.length} of {filteredFeed.length} entries</p>
          <div className="flex items-center gap-1">
            {[1, 2].map(p => (
              <button key={p} onClick={() => setPage(p)} className={`w-7 h-7 rounded text-xs font-medium transition ${page === p ? "bg-blue-600 text-white" : "text-slate-500 hover:bg-slate-100"}`}>{p}</button>
            ))}
          </div>
        </div>
      </div>

      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Password Spray Screen
// ─────────────────────────────────────────────────────────────────────────────

const PasswordSprayScreen = () => {
  const [cfg, setCfg] = useState({ password: "Spring2025!", accounts: "50", delay: "2", rotateIPs: true, randomize: true });
  const [running, setRunning] = useState(false);
  const [pct, setPct] = useState(0);
  const [results, setResults] = useState<any[] | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);

  useEffect(() => {
    const unSubInit = wsEvents.on("simulation.initialized", () => {
      setPct(0);
    });
    const unSubProg = wsEvents.on("simulation.progress", (data) => {
      if (data.progress !== undefined) {
        setPct(data.progress);
      }
    });
    const unSubComp = wsEvents.on("simulation.completed", (data) => {
      setPct(100);
      setRunning(false);
      if (data.events) {
        const rows = data.events.map(formatEventRow);
        setResults(rows);
        setToast({ msg: `Password Spray completed — ${rows.length} events recorded`, type: "success" });
        window.setTimeout(() => setToast(null), 4000);
      }
    });
    const unSubFail = wsEvents.on("simulation.failed", (data) => {
      setRunning(false);
      setToast({ msg: data.error || "Simulation failed", type: "error" });
    });
    const unSubReset = wsEvents.on("simulations.reset", () => {
      setResults(null);
      setPct(0);
    });
    return () => {
      unSubInit();
      unSubProg();
      unSubComp();
      unSubFail();
      unSubReset();
    };
  }, []);

  const run = async () => {
    setRunning(true);
    setPct(0);
    setResults(null);
    try {
      const attempts = Number(cfg.accounts) || 50;
      await apiFetch("/api/simulations/password-spray", {
        method: "POST",
        body: JSON.stringify({
          name: "Password Spray Simulation",
          source_ip: "198.51.100.23",
          attempts,
          account_count: attempts,
          delay_seconds: Number(cfg.delay) || 0,
          password: cfg.password,
          attack_pattern: "password_spray",
          source_ips: cfg.rotateIPs ? ["198.51.100.23", "203.0.113.45", "10.0.0.5"] : ["198.51.100.23"],
        }),
      });
    } catch (error) {
      setToast({ msg: error instanceof Error ? error.message : "Simulation failed", type: "error" });
      setRunning(false);
    }
  };

  const handleReset = async () => {
    try {
      await apiFetch("/api/simulations/reset", { method: "DELETE" });
      setResults(null);
      setPct(0);
      setToast({ msg: "Simulation data reset successfully", type: "info" });
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : "Reset failed", type: "error" });
    }
  };

  return (
    <div className="space-y-5">
      <SectionHeader
        title="Password Spray Attack"
        subtitle="Simulate a single password across multiple target accounts to test lockout and detection policies"
        actions={<>
          <Btn variant="outline" size="sm" onClick={handleReset}><RefreshCw size={12} />Reset</Btn>
        </>}
      />
      <div className="grid grid-cols-3 gap-5">
        <div className="col-span-2 space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
            <h3 className="font-semibold text-slate-800 mb-4 flex items-center gap-2 text-sm">
              <Zap size={15} className="text-blue-600" />Attack Configuration
            </h3>
            <div className="grid grid-cols-2 gap-4 mb-4">
              <FormInput label="Password to Spray" value={cfg.password} onChange={v => setCfg(c => ({ ...c, password: v }))} />
              <FormInput label="Target Account Count" value={cfg.accounts} onChange={v => setCfg(c => ({ ...c, accounts: v }))} type="number" />
              <FormInput label="Delay Between Attempts (s)" value={cfg.delay} onChange={v => setCfg(c => ({ ...c, delay: v }))} type="number" />
              <div>
                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wide mb-2">Options</label>
                <div className="space-y-2">
                  {[{ key: "rotateIPs", label: "Rotate IP Addresses" }, { key: "randomize", label: "Randomize Account Order" }].map(opt => (
                    <label key={opt.key} className="flex items-center gap-2 cursor-pointer">
                      <input type="checkbox" checked={(cfg as any)[opt.key]} onChange={e => setCfg(c => ({ ...c, [opt.key]: e.target.checked }))} className="rounded border-slate-300 accent-blue-600" />
                      <span className="text-[12px] text-slate-600">{opt.label}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>

            {running && (
              <div className="mb-4 p-4 bg-blue-50 rounded-lg border border-blue-100">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
                    <span className="text-sm font-medium text-blue-700">Attack in progress...</span>
                  </div>
                  <span className="font-bold text-blue-700">{pct}%</span>
                </div>
                <ProgressBar value={pct} color="bg-blue-500" />
                <div className="flex justify-between text-[11px] text-blue-400 mt-1.5">
                  <span>Attempted {Math.round(parseInt(cfg.accounts) * pct / 100)} / {cfg.accounts} accounts</span>
                  <span>{pct === 100 ? "Completed" : "Processing real-time WebSocket events..."}</span>
                </div>
              </div>
            )}

            <button
              onClick={run} disabled={running}
              className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white rounded-lg font-semibold text-sm flex items-center justify-center gap-2 transition"
            >
              <Play size={13} />
              {running ? "Running Simulation..." : "Run Password Spray"}
            </button>
          </div>

          {results && (
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
              <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
                <p className="font-semibold text-slate-800 text-sm flex items-center gap-2">
                  <CheckCircle size={14} className="text-emerald-500" />Simulation Results ({results.length} events)
                </p>
                <Btn variant="outline" size="sm"><Download size={11} />Export CSV</Btn>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100">
                    {["Time", "Username", "IP Address", "Result", "Risk Score"].map(h => (
                      <th key={h} className="text-left px-5 py-3 text-[10px] font-bold text-slate-400 uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {results.map(row => (
                    <tr key={row.id} className="hover:bg-slate-50 transition-colors">
                      <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.time}</td>
                      <td className="px-5 py-3 font-semibold text-slate-700">{row.username}</td>
                      <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.ip}</td>
                      <td className="px-5 py-3"><ResultBadge result={row.result} /></td>
                      <td className="px-5 py-3"><RiskScore score={row.riskScore} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
            <p className="font-semibold text-slate-700 text-sm mb-3">Attack Preview</p>
            <div className="space-y-2.5">
              {[
                { label: "Target Accounts", value: `${cfg.accounts} accounts` },
                { label: "Sprayed Password", value: cfg.password ? "••••••••" : "Default" },
                { label: "IP Rotation", value: cfg.rotateIPs ? "Enabled (3 IPs)" : "Disabled" },
                { label: "Delay", value: `${cfg.delay}s per attempt` },
              ].map(s => (
                <div key={s.label} className="flex justify-between text-sm border-b border-slate-50 pb-2 last:border-0">
                  <span className="text-slate-500">{s.label}</span>
                  <span className="font-semibold text-slate-700 font-mono text-[12px] truncate max-w-[130px]">{s.value}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-1.5">
              <AlertTriangle size={13} className="text-amber-600" />
              <span className="text-[11px] font-bold text-amber-700">Research Mode Active</span>
            </div>
            <p className="text-[11px] text-amber-600 leading-relaxed">This simulation runs in a fully controlled lab environment. All attempts are logged and monitored by the detection engine.</p>
          </div>
        </div>
      </div>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Credential Stuffing Screen
// ─────────────────────────────────────────────────────────────────────────────

const CredentialStuffingScreen = () => {
  const [maxAttempts, setMaxAttempts] = useState("50");
  const [concurrency, setConcurrency] = useState("10");
  const [datasetId, setDatasetId] = useState<string | null>(null);
  const [datasetMeta, setDatasetMeta] = useState<{
    filename: string;
    total_rows: number;
    valid_credentials: number;
    invalid_rows: number;
    duplicate_rows: number;
  } | null>(null);
  const [uploading, setUploading] = useState(false);
  const [running, setRunning] = useState(false);
  const [pct, setPct] = useState(0);
  const [results, setResults] = useState<any[] | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const unSubInit = wsEvents.on("simulation.initialized", () => setPct(0));
    const unSubProg = wsEvents.on("simulation.progress", (data) => {
      if (data.progress !== undefined) setPct(data.progress);
    });
    const unSubComp = wsEvents.on("simulation.completed", (data) => {
      setPct(100);
      setRunning(false);
      if (data.events) {
        const rows = data.events.map(formatEventRow);
        setResults(rows);
        setToast({ msg: `Credential Stuffing completed — ${rows.length} events analyzed`, type: "info" });
        window.setTimeout(() => setToast(null), 4000);
      }
    });
    const unSubFail = wsEvents.on("simulation.failed", (data) => {
      setRunning(false);
      setToast({ msg: data.error || "Simulation failed", type: "error" });
    });
    const unSubReset = wsEvents.on("simulations.reset", () => {
      setResults(null);
      setPct(0);
    });
    return () => {
      unSubInit();
      unSubProg();
      unSubComp();
      unSubFail();
      unSubReset();
    };
  }, []);

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await apiFetch("/api/simulations/upload-credentials", {
        method: "POST",
        body: formData,
      });
      setDatasetId(res.dataset_id);
      setDatasetMeta(res);
      setMaxAttempts(String(res.valid_credentials));
      setToast({
        msg: `Uploaded ${res.filename}: ${res.valid_credentials} valid credentials ready`,
        type: "success",
      });
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : "Failed to upload CSV", type: "error" });
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const run = async () => {
    setRunning(true);
    setPct(0);
    setResults(null);
    try {
      const attempts = Number(maxAttempts) || 50;
      const payload: any = {
        name: "Credential Stuffing Attack",
        source_ip: "185.199.110.24",
        attempts,
        delay_seconds: Math.max(0, Number(concurrency) ? 0.05 : 0),
        attack_pattern: "credential_stuffing",
      };
      if (datasetId) {
        payload.dataset_id = datasetId;
      }
      await apiFetch("/api/simulations/credential-stuffing", {
        method: "POST",
        body: JSON.stringify(payload),
      });
    } catch (error) {
      setToast({ msg: error instanceof Error ? error.message : "Simulation failed", type: "error" });
      setRunning(false);
    }
  };

  return (
    <div className="space-y-5">
      <SectionHeader
        title="Credential Stuffing Attack"
        subtitle="Simulate attacks using leaked credential lists to test detection capabilities and response times"
      />
      <div className="grid grid-cols-3 gap-5">
        <div className="col-span-2 space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
            <h3 className="font-semibold text-slate-800 mb-4 flex items-center gap-2 text-sm">
              <Database size={15} className="text-red-500" />Simulation Configuration
            </h3>
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Credential List (CSV/TXT)</label>
                <input type="file" ref={fileInputRef} accept=".csv,.txt" className="hidden" onChange={handleFileSelect} />
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="border-2 border-dashed border-slate-200 rounded-lg p-5 text-center hover:border-blue-300 hover:bg-blue-50/20 transition cursor-pointer"
                >
                  <Upload size={18} className="text-slate-400 mx-auto mb-1.5" />
                  <p className="text-[13px] text-slate-700 font-semibold">
                    {uploading ? "Uploading & parsing CSV..." : datasetMeta ? datasetMeta.filename : "Select Credential List (CSV/TXT)"}
                  </p>
                  {datasetMeta ? (
                    <div className="text-[10px] text-slate-500 mt-1 space-y-0.5">
                      <span className="text-emerald-600 font-bold">{datasetMeta.valid_credentials} valid credentials</span> •{" "}
                      <span>{datasetMeta.invalid_rows} invalid</span> • <span>{datasetMeta.duplicate_rows} duplicates</span>
                    </div>
                  ) : (
                    <p className="text-[10px] text-slate-400 mt-0.5">Click to upload email,password dataset file</p>
                  )}
                </div>
              </div>
              <div className="space-y-3">
                <FormInput label="Max Attempts" value={maxAttempts} onChange={setMaxAttempts} type="number" />
                <FormInput label="Concurrency (threads)" value={concurrency} onChange={setConcurrency} type="number" />
              </div>
            </div>
            {running && (
              <div className="mb-4 p-4 bg-red-50 rounded-lg border border-red-100">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                    <span className="text-sm font-medium text-red-700">Stuffing in progress...</span>
                  </div>
                  <span className="font-bold text-red-700">{pct}%</span>
                </div>
                <ProgressBar value={pct} color="bg-red-500" />
              </div>
            )}
            <button onClick={run} disabled={running} className="w-full py-2.5 bg-red-600 hover:bg-red-700 disabled:bg-red-300 text-white rounded-lg font-semibold text-sm flex items-center justify-center gap-2 transition">
              <Play size={13} />
              {running ? "Running Credential Stuffing..." : "Run Credential Stuffing"}
            </button>
          </div>

          {results && (
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
              <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
                <p className="font-semibold text-slate-800 text-sm">Simulation Results ({results.length} events)</p>
                <Btn variant="outline" size="sm"><Download size={11} />Export</Btn>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100">
                    {["Time", "Username", "IP Address", "Result", "Risk Score"].map(h => (
                      <th key={h} className="text-left px-5 py-3 text-[10px] font-bold text-slate-400 uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {results.map(row => (
                    <tr key={row.id} className="hover:bg-slate-50 transition-colors">
                      <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.time}</td>
                      <td className="px-5 py-3 font-semibold text-slate-700">{row.username}</td>
                      <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.ip}</td>
                      <td className="px-5 py-3"><ResultBadge result={row.result} /></td>
                      <td className="px-5 py-3"><RiskScore score={row.riskScore} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
            <p className="font-semibold text-slate-700 text-sm mb-3">Configuration Summary</p>
            <div className="space-y-2.5">
              {[
                { label: "Credential Dataset", value: datasetMeta ? datasetMeta.filename : "Default Generator" },
                { label: "Max Attempts", value: maxAttempts },
                { label: "Concurrency", value: `${concurrency} threads` },
                { label: "Est. Duration", value: `~${Math.max(1, Math.round((parseInt(maxAttempts || "500", 10) / Math.max(1, parseInt(concurrency || "10", 10))) * 0.5 / 60))} min` },
              ].map(s => (
                <div key={s.label} className="flex justify-between text-sm border-b border-slate-50 pb-2 last:border-0">
                  <span className="text-slate-500">{s.label}</span>
                  <span className="font-semibold text-slate-700 font-mono text-[12px] truncate max-w-[130px]">{s.value}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="bg-red-50 border border-red-200 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-1.5">
              <AlertTriangle size={13} className="text-red-600" />
              <span className="text-[11px] font-bold text-red-700">Controlled Environment</span>
            </div>
            <p className="text-[11px] text-red-600 leading-relaxed">Simulation runs against isolated test accounts only. No real credentials are used or stored.</p>
          </div>
        </div>
      </div>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Custom Attack Screen
// ─────────────────────────────────────────────────────────────────────────────

const CustomAttackScreen = () => {
  const [cfg, setCfg] = useState({ name: "Custom Attack #1", type: "hybrid", passwords: "Spring2025!\nAdmin123!\nPassword1\nWelcome@2025", accounts: "50", delay: "1", rotateIP: true });
  const [running, setRunning] = useState(false);
  const [pct, setPct] = useState(0);
  const [results, setResults] = useState<any[] | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);

  const run = async () => {
    setRunning(true);
    setPct(15);
    setResults(null);
    try {
      const attackPattern = cfg.type === "spray" ? "password_spray" : cfg.type === "stuffing" ? "credential_stuffing" : cfg.type === "bruteforce" ? "normal" : "hybrid";
      const attempts = Number(cfg.accounts) || 50;
      const response = await apiFetch("/api/simulations/custom", {
        method: "POST",
        body: JSON.stringify({
          name: cfg.name,
          source_ip: "192.0.2.44",
          attempts,
          account_count: attempts,
          delay_seconds: Number(cfg.delay) || 1,
          attack_pattern: attackPattern,
          passwords: cfg.passwords.split("\n").map(v => v.trim()).filter(Boolean),
          rotate_ips: cfg.rotateIP,
          source_ips: cfg.rotateIP ? ["192.0.2.44", "198.51.100.23", "203.0.113.45"] : ["192.0.2.44"],
        }),
      });
      const rows = (response.events ?? []).map(formatEventRow);
      setResults(rows);
      setPct(100);
      setToast({ msg: `Custom attack simulation completed — ${rows.length} events recorded`, type: "success" });
      window.setTimeout(() => setToast(null), 4000);
    } catch (error) {
      setToast({ msg: error instanceof Error ? error.message : "Simulation failed", type: "error" });
    } finally {
      setRunning(false);
      window.setTimeout(() => setPct(0), 700);
    }
  };

  const pwList = cfg.passwords.split("\n").filter(Boolean);

  return (
    <div className="space-y-5">
      <SectionHeader title="Custom Attack Builder" subtitle="Design advanced multi-vector attack simulations with granular control" />
      <div className="grid grid-cols-3 gap-5">
        <div className="col-span-2 space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
            <h3 className="font-semibold text-slate-800 mb-4 flex items-center gap-2 text-sm">
              <Wrench size={15} className="text-violet-600" />Attack Builder
            </h3>
            <div className="grid grid-cols-2 gap-4 mb-4">
              <FormInput label="Attack Name" value={cfg.name} onChange={v => setCfg(c => ({ ...c, name: v }))} />
              <div>
                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Attack Type</label>
                <select value={cfg.type} onChange={e => setCfg(c => ({ ...c, type: e.target.value }))} className="w-full px-3 py-2 bg-[#f8fafc] border border-slate-200 rounded-lg text-sm text-slate-700 outline-none">
                  <option value="hybrid">Hybrid (Spray + Stuffing)</option>
                  <option value="spray">Password Spray</option>
                  <option value="stuffing">Credential Stuffing</option>
                  <option value="bruteforce">Brute Force</option>
                </select>
              </div>
              <FormInput label="Target Accounts" value={cfg.accounts} onChange={v => setCfg(c => ({ ...c, accounts: v }))} type="number" />
              <FormInput label="Delay (seconds)" value={cfg.delay} onChange={v => setCfg(c => ({ ...c, delay: v }))} type="number" />
            </div>
            <div className="mb-4">
              <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Password List (one per line)</label>
              <textarea
                value={cfg.passwords}
                onChange={e => setCfg(c => ({ ...c, passwords: e.target.value }))}
                rows={5}
                className="w-full px-3 py-2 bg-[#f8fafc] border border-slate-200 rounded-lg text-sm font-mono text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 transition resize-none"
              />
              <p className="text-[10px] text-slate-400 mt-1">{pwList.length} password{pwList.length !== 1 ? "s" : ""} in list</p>
            </div>
            <label className="flex items-center gap-2 cursor-pointer mb-4">
              <input type="checkbox" checked={cfg.rotateIP} onChange={e => setCfg(c => ({ ...c, rotateIP: e.target.checked }))} className="rounded border-slate-300 accent-blue-600" />
              <span className="text-[12px] text-slate-600">Rotate IP addresses during attack</span>
            </label>
            {running && (
              <div className="mb-4 p-4 bg-violet-50 rounded-lg border border-violet-100">
                <div className="flex justify-between mb-2">
                  <div className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-violet-500 animate-pulse" /><span className="text-sm font-medium text-violet-700">Custom Attack Running...</span></div>
                  <span className="font-bold text-violet-700">{pct}%</span>
                </div>
                <ProgressBar value={pct} color="bg-violet-500" />
              </div>
            )}
            <button onClick={run} disabled={running} className="w-full py-2.5 bg-violet-600 hover:bg-violet-700 disabled:bg-violet-300 text-white rounded-lg font-semibold text-sm flex items-center justify-center gap-2 transition">
              <Play size={13} />{running ? "Running Custom Attack..." : "Launch Custom Attack"}
            </button>
          </div>
          {results && (
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
              <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
                <p className="font-semibold text-slate-800 text-sm">Latest Run</p>
                <Btn variant="outline" size="sm"><Download size={11} />Export</Btn>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100">
                    {["Time", "Username", "IP Address", "Result", "Risk Score"].map(h => (
                      <th key={h} className="text-left px-5 py-3 text-[10px] font-bold text-slate-400 uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {results.map(row => (
                    <tr key={row.id} className="hover:bg-slate-50 transition-colors">
                      <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.time}</td>
                      <td className="px-5 py-3 font-semibold text-slate-700">{row.username}</td>
                      <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.ip}</td>
                      <td className="px-5 py-3"><ResultBadge result={row.result} /></td>
                      <td className="px-5 py-3"><RiskScore score={row.riskScore} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <div className="space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
            <p className="font-semibold text-slate-700 text-sm mb-3">Attack Preview</p>
            <div className="space-y-2.5">
              {[
                { label: "Name", value: cfg.name },
                { label: "Type", value: cfg.type },
                { label: "Passwords", value: `${pwList.length} entries` },
                { label: "Targets", value: `${cfg.accounts} accounts` },
                { label: "IP Rotation", value: cfg.rotateIP ? "Yes" : "No" },
              ].map(s => (
                <div key={s.label} className="flex justify-between text-sm border-b border-slate-50 pb-2 last:border-0">
                  <span className="text-slate-500">{s.label}</span>
                  <span className="font-semibold text-slate-700 text-[12px] truncate max-w-[120px]">{s.value}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="bg-violet-50 border border-violet-200 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-1.5">
              <AlertTriangle size={13} className="text-violet-600" />
              <span className="text-[11px] font-bold text-violet-700">Lab Environment Only</span>
            </div>
            <p className="text-[11px] text-violet-600 leading-relaxed">Custom attacks are isolated to test accounts and fully monitored by all detection engines.</p>
          </div>
        </div>
      </div>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Attack History Screen
// ─────────────────────────────────────────────────────────────────────────────

const AttackHistoryScreen = () => {
  const [filter, setFilter] = useState("All");
  const [search, setSearch] = useState("");
  const [rows, setRows] = useState<any[]>([]);

  const loadHistory = async () => {
    try {
      const simulations = await apiFetch("/api/simulations");
      const items = (simulations ?? []).map((sim: any) => ({
        id: sim.id,
        type: formatAttackType(sim.attack_type ?? "normal"),
        startTime: sim.created_at ? new Date(sim.created_at).toLocaleString() : "—",
        duration: sim.completed_at
          ? `${Math.max(1, Math.round((new Date(sim.completed_at).getTime() - new Date(sim.created_at).getTime()) / 1000))}s`
          : "In Progress",
        attempts: sim.attempts ?? 0,
        sourceIP: sim.source_ip,
        affectedCount: sim.affected_accounts?.length ?? 0,
        status: sim.status ?? "completed",
        blocked: sim.status === "completed",
      }));
      setRows(items);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    loadHistory();
    const unSubComp = wsEvents.on("simulation.completed", () => loadHistory());
    const unSubReset = wsEvents.on("simulations.reset", () => loadHistory());
    return () => {
      unSubComp();
      unSubReset();
    };
  }, []);

  const filtered = rows.filter((a) =>
    (filter === "All" || a.type === filter) &&
    (search === "" || a.type.toLowerCase().includes(search.toLowerCase()) || a.sourceIP.includes(search))
  );

  return (
    <div className="space-y-5">
      <SectionHeader
        title="Attack History"
        subtitle="Historical log of all simulated attacks, detections, and response actions"
        actions={<Btn variant="outline" size="sm"><Download size={12} />Export CSV</Btn>}
      />
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
        <div className="px-5 py-4 border-b border-slate-100 flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 flex-1 min-w-[180px] max-w-xs">
            <Search size={12} className="text-slate-400 shrink-0" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search type or IP..." className="bg-transparent text-[13px] text-slate-600 placeholder-slate-400 outline-none flex-1" />
          </div>
          <select value={filter} onChange={e => setFilter(e.target.value)} className="text-[13px] text-slate-600 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 outline-none">
            <option>All</option>
            <option>Password Spray</option>
            <option>Credential Stuffing</option>
            <option>Custom Attack</option>
          </select>
          <span className="text-[11px] text-slate-400 ml-auto">{filtered.length} records</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[750px]">
            <thead>
              <tr className="border-b border-slate-100">
                {["Attack Type", "Start Time", "Duration", "Attempts", "Source IP", "Status", "Blocked", "Actions"].map(h => (
                  <th key={h} className="text-left px-5 py-3 text-[10px] font-bold text-slate-400 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {filtered.map(row => (
                <tr key={row.id} className="hover:bg-slate-50/60 transition-colors">
                  <td className="px-5 py-3"><TypeBadge type={row.type} /></td>
                  <td className="px-5 py-3 font-mono text-[12px] text-slate-600">{row.startTime}</td>
                  <td className="px-5 py-3 text-slate-600 text-[13px]">{row.duration}</td>
                  <td className="px-5 py-3 font-semibold text-slate-700">{row.attempts}</td>
                  <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.sourceIP}</td>
                  <td className="px-5 py-3">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${row.status === "failed" ? "bg-red-50 text-red-600 border-red-200" : "bg-emerald-50 text-emerald-600 border-emerald-200"}`}>
                      {row.status.charAt(0).toUpperCase() + row.status.slice(1)}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    {row.blocked ? <CheckCircle size={15} className="text-emerald-500" /> : <XCircle size={15} className="text-slate-300" />}
                  </td>
                  <td className="px-5 py-3">
                    <button className="text-[12px] text-blue-600 hover:underline flex items-center gap-1">
                      <Eye size={11} />View
                    </button>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={8} className="px-5 py-12 text-center text-sm text-slate-400">No simulation history found</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Live Monitoring Screen
// ─────────────────────────────────────────────────────────────────────────────

const LiveMonitoringScreen = () => {
  const [paused, setPaused] = useState(false);
  const [feed, setFeed]     = useState<any[]>(seedFeed);
  const [filter, setFilter] = useState("All");

  useEffect(() => {
    const unSub = wsEvents.on("login_event", (data) => {
      if (data.event && !paused) {
        const row = formatEventRow(data.event);
        setFeed(prev => [row, ...prev.filter(r => r.id !== row.id)].slice(0, 100));
      }
    });
    return () => unSub();
  }, [paused]);

  useEffect(() => {
    if (paused) return;
    let active = true;
    const load = async () => {
      try {
        const data = await apiFetch("/api/dashboard");
        if (!active) return;
        const rows = (data.liveFeed ?? []).map(formatEventRow);
        if (rows.length) {
          setFeed(prev => {
            const map = new Map();
            rows.forEach((r: any) => map.set(r.id, r));
            prev.forEach(r => map.set(r.id, r));
            return Array.from(map.values()).slice(0, 100);
          });
        }
      } catch (error) {
        console.error(error);
      }
    };
    load();
    const iv = window.setInterval(load, 3000);
    return () => {
      active = false;
      window.clearInterval(iv);
    };
  }, [paused]);

  const filtered = filter === "All" ? feed : feed.filter(f => f.type === filter);

  return (
    <div className="space-y-5">
      <SectionHeader
        title="Live Monitoring"
        subtitle="Real-time authentication activity via WebSocket live stream"
        actions={
          <button
            onClick={() => setPaused(p => !p)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium border transition ${paused ? "bg-emerald-50 text-emerald-700 border-emerald-200" : "bg-slate-50 text-slate-700 border-slate-200 hover:bg-slate-100"}`}
          >
            {paused ? <><Play size={13} />Resume</> : <><Pause size={13} />Pause</>}
          </button>
        }
      />
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Events / min", value: "~30",  color: "text-blue-600"    },
          { label: "Active Threats", value: "3",  color: "text-red-600"     },
          { label: "Blocked IPs",   value: "4",   color: "text-amber-600"   },
          { label: "Uptime",        value: "99.9%", color: "text-emerald-600" },
        ].map(s => (
          <div key={s.label} className="bg-white rounded-xl border border-slate-200 shadow-sm px-4 py-3 flex items-center justify-between">
            <span className="text-[12px] text-slate-500">{s.label}</span>
            <span className={`font-bold text-xl ${s.color}`}>{s.value}</span>
          </div>
        ))}
      </div>
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
        <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${paused ? "bg-slate-400" : "bg-emerald-500 animate-pulse"}`} />
            <span className="font-semibold text-slate-800 text-sm">{paused ? "Feed Paused" : "Live Feed (WebSocket)"}</span>
            {!paused && <span className="text-[11px] text-slate-400">{feed.length} events captured</span>}
          </div>
          <select value={filter} onChange={e => setFilter(e.target.value)} className="text-[12px] text-slate-600 bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 outline-none">
            <option>All</option>
            <option>Credential Stuffing</option>
            <option>Password Spray</option>
            <option>Normal</option>
          </select>
        </div>
        <div className="overflow-x-auto max-h-[520px] overflow-y-auto">
          <table className="w-full text-sm min-w-[700px]">
            <thead className="sticky top-0 bg-white z-10 border-b border-slate-100">
              <tr>
                {["Time", "Username", "IP Address", "Result", "Risk Score", "Attack Type"].map(h => (
                  <th key={h} className="text-left px-5 py-3 text-[10px] font-bold text-slate-400 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {filtered.map((row, i) => (
                <tr key={row.id} className={`transition-colors ${i === 0 && !paused ? "bg-blue-50/40" : "hover:bg-slate-50/60"}`}>
                  <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.time}</td>
                  <td className="px-5 py-3 text-[13px] font-semibold text-slate-700">{row.username}</td>
                  <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{row.ip}</td>
                  <td className="px-5 py-3"><ResultBadge result={row.result} /></td>
                  <td className="px-5 py-3"><RiskScore score={row.riskScore} /></td>
                  <td className="px-5 py-3"><TypeBadge type={row.type} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Alerts Screen
// ─────────────────────────────────────────────────────────────────────────────

const AlertsScreen = () => {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [selected, setSelected] = useState<any | null>(null);

  const load = async () => {
    try {
      const data = await apiFetch("/api/alerts");
      setAlerts(data);
      if (selected) {
        const refreshed = data.find((alert: any) => alert.id === selected.id);
        if (refreshed) setSelected(refreshed);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    load();
    const unSub = wsEvents.on("alert_created", (data) => {
      if (data.alert) {
        setAlerts(prev => [data.alert, ...prev.filter(a => a.id !== data.alert.id)]);
      }
    });
    const unSubReset = wsEvents.on("simulations.reset", () => {
      setAlerts([]);
      setSelected(null);
    });
    return () => {
      unSub();
      unSubReset();
    };
  }, []);

  const ack = async (id: string) => {
    await apiFetch(`/api/alerts/${id}`, { method: "PUT", body: JSON.stringify({ status: "acknowledged" }) });
    await load();
  };

  const dismiss = (id: string) => {
    setAlerts(prev => prev.filter(alert => alert.id !== id));
    if (selected?.id === id) setSelected(null);
  };

  const unacked = alerts.filter(a => a.status === "open" || a.status === "pending");
  const acked = alerts.filter(a => a.status !== "open" && a.status !== "pending");

  const SevIcon = ({ sev }: { sev: Severity }) => {
    if (sev === "critical" || sev === "high") return <AlertCircle className="text-red-500 shrink-0" size={15} />;
    if (sev === "medium") return <AlertTriangle className="text-amber-500 shrink-0" size={15} />;
    return <Info className="text-blue-500 shrink-0" size={15} />;
  };

  return (
    <div className="space-y-5">
      <SectionHeader
        title="Security Alerts"
        subtitle={`${unacked.length} unacknowledged alert${unacked.length !== 1 ? "s" : ""} require attention`}
        actions={
          <Btn variant="outline" size="sm" onClick={async () => { await Promise.all(alerts.map(alert => ack(alert.id))); }}>
            <Check size={12} />Acknowledge All
          </Btn>
        }
      />
      <div className="grid grid-cols-3 gap-5">
        <div className="col-span-2 space-y-5">
          {unacked.length > 0 && (
            <div>
              <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-3">Unacknowledged ({unacked.length})</p>
              <div className="space-y-2">
                {unacked.map(alert => (
                  <div
                    key={alert.id}
                    onClick={() => setSelected(alert)}
                    className={`bg-white rounded-xl border shadow-sm p-4 cursor-pointer transition-all hover:shadow-md ${selected?.id === alert.id ? "border-blue-300 ring-2 ring-blue-100" : "border-slate-200"}`}
                  >
                    <div className="flex items-start gap-3">
                      <SevIcon sev={alert.severity} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                          <span className="font-semibold text-slate-800 text-sm">{alert.attack_type}</span>
                          <SeverityBadge severity={alert.severity} />
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-mono">Simulation Activity</span>
                        </div>
                        <p className="text-[12px] text-slate-500">{alert.explanation}</p>
                        <p className="text-[11px] text-slate-400 mt-1">{alert.timestamp ? new Date(alert.timestamp).toLocaleString() : ""}</p>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <button onClick={e => { e.stopPropagation(); ack(alert.id); }} className="text-[11px] text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-lg hover:bg-emerald-100 transition flex items-center gap-1">
                          <Check size={10} />Ack
                        </button>
                        <button onClick={e => { e.stopPropagation(); dismiss(alert.id); }} className="text-slate-400 hover:text-red-500 p-1 rounded hover:bg-red-50 transition">
                          <X size={13} />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {acked.length > 0 && (
            <div>
              <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-3">Acknowledged ({acked.length})</p>
              <div className="space-y-2 opacity-55">
                {acked.map(alert => (
                  <div key={alert.id} className="bg-white rounded-xl border border-slate-200 p-4 flex items-center gap-3">
                    <CheckCircle size={15} className="text-emerald-500 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <span className="text-[13px] font-medium text-slate-600 truncate block">{alert.attack_type}</span>
                      <p className="text-[11px] text-slate-400">{alert.timestamp ? new Date(alert.timestamp).toLocaleString() : ""}</p>
                    </div>
                    <SeverityBadge severity={alert.severity} />
                  </div>
                ))}
              </div>
            </div>
          )}
          {alerts.length === 0 && (
            <div className="bg-white rounded-xl border border-dashed border-slate-200 p-16 text-center">
              <CheckCircle size={32} className="text-emerald-400 mx-auto mb-3" />
              <p className="font-semibold text-slate-600">All clear!</p>
              <p className="text-sm text-slate-400 mt-1">No active alerts at this time</p>
            </div>
          )}
        </div>
        <div>
          {selected ? (
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 sticky top-6">
              <div className="flex items-center justify-between mb-4">
                <p className="font-semibold text-slate-800 text-sm">Alert Details</p>
                <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-slate-600 transition"><X size={15} /></button>
              </div>
              <div className="space-y-3">
                <SeverityBadge severity={selected.severity} />
                <p className="font-semibold text-slate-800 leading-snug">{selected.attack_type}</p>
                <p className="text-[13px] text-slate-600">{selected.explanation}</p>
                <div className="border-t border-slate-100 pt-3 space-y-2.5">
                  {[
                    { label: "Severity", value: selected.severity.toUpperCase() },
                    { label: "Detected", value: selected.timestamp ? new Date(selected.timestamp).toLocaleString() : "" },
                    { label: "Status",   value: selected.status === "open" ? "Pending Review" : "Acknowledged" },
                  ].map(d => (
                    <div key={d.label} className="flex justify-between text-sm">
                      <span className="text-slate-400">{d.label}</span>
                      <span className="font-semibold text-slate-700">{d.value}</span>
                    </div>
                  ))}
                </div>
                {selected.status === "open" && (
                  <button
                    onClick={() => { ack(selected.id); setSelected(null); }}
                    className="w-full mt-2 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-[13px] font-semibold flex items-center justify-center gap-2 transition"
                  >
                    <Check size={13} />Acknowledge Alert
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-slate-50 rounded-xl border border-dashed border-slate-200 p-8 text-center text-slate-400">
              <Bell size={24} className="mx-auto mb-2 opacity-30" />
              <p className="text-[13px]">Select an alert to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Analytics Screen
// ─────────────────────────────────────────────────────────────────────────────

const AnalyticsScreen = () => {
  const [timeRange, setTimeRange] = useState("7d");
  const [analytics, setAnalytics] = useState<any | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        setAnalytics(await apiFetch("/api/analytics"));
      } catch (error) {
        console.error(error);
      }
    };
    load();
  }, []);

  const totals = analytics?.totals ?? {
    loginAttempts: 0,
    detectedAttacks: 0,
    blockedAttempts: 0,
    uniqueIPs: 0,
    successCount: 0,
    failureCount: 0,
  };
  const dailyData = (analytics?.dailyTrends ?? []).map((item: any) => ({ date: item.date, attacks: item.count, detected: item.count, blocked: item.count }));
  const typeDistribution = analytics?.attackTypeDistribution ?? [];

  return (
    <div className="space-y-5">
      <SectionHeader
        title="Analytics"
        subtitle="Attack patterns, detection rates, and trend analysis over time"
        actions={
          <div className="flex gap-1.5">
            {["24h", "7d", "30d"].map(r => (
              <button key={r} onClick={() => setTimeRange(r)} className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${timeRange === r ? "bg-blue-600 text-white shadow-sm" : "bg-slate-100 text-slate-600 hover:bg-slate-200"}`}>{r}</button>
            ))}
          </div>
        }
      />

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Total Attacks",     value: String(totals.loginAttempts ?? 0), sub: "all recorded events", color: "text-slate-800"    },
          { label: "Detection Rate",    value: totals.loginAttempts ? `${Math.round(((totals.detectedAttacks ?? 0) / totals.loginAttempts) * 100)}%` : "0%", sub: "derived from live data", color: "text-emerald-600"  },
          { label: "Blocked",           value: String(totals.blockedAttempts ?? 0), sub: "events blocked by engine", color: "text-blue-600"   },
          { label: "Unique IPs",        value: String(totals.uniqueIPs ?? 0), sub: "active source addresses", color: "text-amber-600"    },
        ].map(s => (
          <div key={s.label} className="bg-white rounded-xl border border-slate-200 shadow-sm p-4">
            <p className="text-[11px] text-slate-500 mb-1 uppercase tracking-wide font-medium">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            <p className="text-[11px] text-slate-400 mt-0.5">{s.sub}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <p className="font-semibold text-slate-800 text-sm mb-4">Daily Attack Volume</p>
          <ResponsiveContainer width="100%" height={230}>
            <BarChart data={dailyData} barGap={4} margin={{ top: 4, right: 4, bottom: 0, left: -12 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: "1px solid #e2e8f0" }} />
              <Bar dataKey="attacks"  fill="#ef4444" radius={[3,3,0,0]} name="Total Attacks" />
              <Bar dataKey="detected" fill="#f59e0b" radius={[3,3,0,0]} name="Detected" />
              <Bar dataKey="blocked"  fill="#3b82f6" radius={[3,3,0,0]} name="Blocked" />
            </BarChart>
          </ResponsiveContainer>
          <div className="flex items-center gap-4 mt-3">
            {[{ label: "Attacks", color: "#ef4444" }, { label: "Detected", color: "#f59e0b" }, { label: "Blocked", color: "#3b82f6" }].map(l => (
              <div key={l.label} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded" style={{ background: l.color }} />
                <span className="text-[11px] text-slate-500">{l.label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <p className="font-semibold text-slate-800 text-sm mb-4">Attack Type Distribution</p>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={typeDistribution} cx="50%" cy="50%" innerRadius={48} outerRadius={72} paddingAngle={3} dataKey="value">
                {typeDistribution.map((entry: any, i: number) => <Cell key={i} fill={["#ef4444", "#f59e0b", "#8b5cf6", "#64748b", "#3b82f6"][i % 5]} />)}
              </Pie>
              <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-2 mt-3">
            {typeDistribution.map((t: any, index: number) => (
              <div key={t.name} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: ["#ef4444", "#f59e0b", "#8b5cf6", "#64748b", "#3b82f6"][index % 5] }} />
                  <span className="text-[11px] text-slate-600">{t.name}</span>
                </div>
                <span className="text-[12px] font-bold text-slate-700">{t.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Detection Models Screen
// ─────────────────────────────────────────────────────────────────────────────

const DetectionModelsScreen = () => {
  const [models, setModels] = useState<any[]>([]);
  const [retraining, setRetraining] = useState(false);
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);

  const load = async () => {
    try {
      setModels(await apiFetch("/api/models"));
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const retrain = async () => {
    setRetraining(true);
    try {
      const res = await apiFetch("/api/models/retrain", { method: "POST" });
      setModels(res.models || []);
      setToast({ msg: "Detection models re-evaluated against telemetry data", type: "success" });
      window.setTimeout(() => setToast(null), 3000);
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : "Retraining failed", type: "error" });
    } finally {
      setRetraining(false);
    }
  };

  return (
    <div className="space-y-5">
      <SectionHeader
        title="Detection Models"
        subtitle="Manage and monitor machine learning and rule-based detection engines"
        actions={
          <Btn size="sm" onClick={retrain} disabled={retraining}>
            <RefreshCw size={12} className={retraining ? "animate-spin" : ""} />
            {retraining ? "Re-evaluating..." : "Re-evaluate Models"}
          </Btn>
        }
      />
      <div className="grid grid-cols-2 gap-4">
        {models.map(model => (
          <div key={model.id} className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${model.status === "active" ? "bg-emerald-50" : "bg-slate-100"}`}>
                    <Brain size={17} className={model.status === "active" ? "text-emerald-600" : "text-slate-400"} />
                  </div>
                  <div>
                    <p className="font-semibold text-slate-800 text-sm">{model.name}</p>
                    <p className="text-[11px] text-slate-400">{model.type} • {model.version}</p>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <StatusDot status={model.status} />
                  <span className={`text-[11px] font-semibold capitalize ${model.status === "active" ? "text-emerald-600" : "text-slate-500"}`}>
                    {model.status}
                  </span>
                </div>
              </div>

              <div className="mb-4">
                <div className="flex justify-between text-[12px] mb-1.5">
                  <span className="text-slate-500">Benchmark Accuracy</span>
                  <span className="font-bold text-slate-700">
                    {model.accuracy !== null && model.accuracy !== undefined ? `${model.accuracy}%` : "Accuracy: N/A — no labeled evaluation dataset"}
                  </span>
                </div>
                {model.accuracy !== null && model.accuracy !== undefined ? (
                  <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-emerald-500" style={{ width: `${model.accuracy}%` }} />
                  </div>
                ) : (
                  <p className="text-[10px] text-slate-400 leading-tight">
                    {model.notes || "Model relies on heuristic signatures or unsupervised scoring; accuracy requires a benchmark dataset."}
                  </p>
                )}
              </div>
            </div>

            <div>
              <div className="grid grid-cols-3 gap-2 mb-4">
                {[
                  { label: "Detections", value: Number(model.detections ?? 0).toLocaleString() },
                  { label: "False Positives", value: String(model.false_positives ?? 0) },
                  { label: "Samples", value: String(model.training_samples ?? 0) },
                ].map(s => (
                  <div key={s.label} className="bg-slate-50 rounded-lg p-2.5">
                    <p className="text-[9px] text-slate-400 uppercase tracking-wide font-medium">{s.label}</p>
                    <p className="font-bold text-slate-700 text-sm mt-0.5">{s.value}</p>
                  </div>
                ))}
              </div>

              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-100">
                <span>Last Updated: {model.last_trained_at ? new Date(model.last_trained_at).toLocaleString() : "Initial state"}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Reports Screen
// ─────────────────────────────────────────────────────────────────────────────

const ReportsScreen = () => {
  const [reports, setReports] = useState<any[]>([]);
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);

  const load = async () => {
    try {
      setReports(await apiFetch("/api/reports"));
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const generate = async () => {
    try {
      await apiFetch("/api/reports/generate", { method: "POST" });
      await load();
      setToast({ msg: "Report generated successfully", type: "success" });
      window.setTimeout(() => setToast(null), 3000);
    } catch (error) {
      setToast({ msg: error instanceof Error ? error.message : "Unable to generate report", type: "error" });
    }
  };

  return (
    <div className="space-y-5">
      <SectionHeader
        title="Reports"
        subtitle="Generate, export, and review attack simulation and detection reports"
        actions={<Btn size="sm" onClick={generate}><Plus size={12} />Generate Report</Btn>}
      />
      <div className="grid grid-cols-3 gap-4 mb-2">
        {[
          { label: "Total Reports", value: String(reports.length), icon: FileText, bg: "bg-blue-500" },
          { label: "Generated This Week", value: String(reports.filter(r => new Date(r.generated_at).getTime() > Date.now() - 7 * 24 * 60 * 60 * 1000).length), icon: TrendingUp, bg: "bg-emerald-500" },
          { label: "Latest Status", value: reports[0]?.status ?? "idle", icon: RefreshCw, bg: "bg-amber-500" },
        ].map(s => (
          <div key={s.label} className="bg-white rounded-xl border border-slate-200 shadow-sm p-4 flex items-center gap-3">
            <div className={`w-10 h-10 ${s.bg} rounded-lg flex items-center justify-center shrink-0`}>
              <s.icon size={17} className="text-white" />
            </div>
            <div>
              <p className="text-2xl font-bold text-slate-800">{s.value}</p>
              <p className="text-[11px] text-slate-500">{s.label}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100">
              {["Report Name", "Type", "Generated", "Size", "Status", "Actions"].map(h => (
                <th key={h} className="text-left px-5 py-3 text-[10px] font-bold text-slate-400 uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-50">
            {reports.map(r => (
              <tr key={r.id} className="hover:bg-slate-50/60 transition-colors">
                <td className="px-5 py-3">
                  <div className="flex items-center gap-2">
                    <FileText size={13} className="text-blue-400 shrink-0" />
                    <span className="font-medium text-slate-700">{r.name}</span>
                  </div>
                </td>
                <td className="px-5 py-3">
                  <span className="px-2 py-0.5 bg-blue-50 text-blue-600 border border-blue-100 rounded text-[11px] font-medium">{r.type}</span>
                </td>
                <td className="px-5 py-3 text-slate-500 text-[12px]">{r.generated_at ? new Date(r.generated_at).toLocaleString() : "—"}</td>
                <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{r.size_bytes ? `${(r.size_bytes / 1024 / 1024).toFixed(1)} MB` : "—"}</td>
                <td className="px-5 py-3">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${r.status === "ready" ? "bg-emerald-50 text-emerald-600 border-emerald-200" : "bg-amber-50 text-amber-600 border-amber-200"}`}>
                    {r.status === "ready" ? "Ready" : "Generating..."}
                  </span>
                </td>
                <td className="px-5 py-3">
                  <div className="flex items-center gap-3">
                    <button className="text-[12px] text-blue-600 hover:underline flex items-center gap-1"><Eye size={11} />View</button>
                    <button className="text-[12px] text-slate-500 hover:text-slate-700 flex items-center gap-1"><Download size={11} />PDF</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Test Accounts Screen
// ─────────────────────────────────────────────────────────────────────────────

const TestAccountsScreen = () => {
  const [accounts, setAccounts] = useState<any[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [newUser, setNewUser] = useState({ username: "", role: "Standard User" });
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);

  const load = async () => {
    try {
      setAccounts(await apiFetch("/api/test-accounts"));
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const createAccount = async () => {
    if (!newUser.username.trim()) return;
    setLoading(true);
    try {
      await apiFetch("/api/test-accounts", {
        method: "POST",
        body: JSON.stringify({ username: newUser.username.trim(), role: newUser.role }),
      });
      setNewUser({ username: "", role: "Standard User" });
      setShowAdd(false);
      setToast({ msg: "Test account created successfully", type: "success" });
      await load();
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : "Failed to create account", type: "error" });
    } finally {
      setLoading(false);
    }
  };

  const generateAccounts = async () => {
    setLoading(true);
    try {
      const res = await apiFetch("/api/test-accounts/generate?count=10", { method: "POST" });
      await load();
      setToast({ msg: `Generated ${res.count || 10} new test accounts`, type: "success" });
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : "Failed to generate test accounts", type: "error" });
    } finally {
      setLoading(false);
    }
  };

  const toggleLock = async (account: any) => {
    try {
      await apiFetch(`/api/test-accounts/${account.id}`, {
        method: "PUT",
        body: JSON.stringify({
          locked: !account.locked,
          status: !account.locked ? "locked" : "active",
        }),
      });
      setToast({ msg: `Account ${account.username} ${account.locked ? "unlocked" : "locked"}`, type: "info" });
      await load();
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : "Update failed", type: "error" });
    }
  };

  const removeAccount = async (id: string) => {
    try {
      await apiFetch(`/api/test-accounts/${id}`, { method: "DELETE" });
      setToast({ msg: "Account removed", type: "info" });
      await load();
    } catch (err) {
      setToast({ msg: err instanceof Error ? err.message : "Delete failed", type: "error" });
    }
  };

  return (
    <div className="space-y-5">
      <SectionHeader
        title="Test Accounts"
        subtitle="Manage isolated lab accounts used in attack simulations and detection testing"
        actions={
          <div className="flex gap-2">
            <Btn variant="outline" size="sm" onClick={generateAccounts} disabled={loading}>
              <RefreshCw size={12} className={loading ? "animate-spin" : ""} />Generate Accounts (10)
            </Btn>
            <Btn size="sm" onClick={() => setShowAdd(true)}><Plus size={12} />Add Account</Btn>
          </div>
        }
      />

      {showAdd && (
        <div className="bg-white rounded-xl border border-blue-200 shadow-sm p-5">
          <p className="font-semibold text-slate-800 text-sm mb-4">Add New Test Account</p>
          <div className="grid grid-cols-3 gap-4 items-end">
            <FormInput label="Username" value={newUser.username} onChange={v => setNewUser(u => ({ ...u, username: v }))} placeholder="user@lab.com" />
            <div>
              <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Role</label>
              <select value={newUser.role} onChange={e => setNewUser(u => ({ ...u, role: e.target.value }))} className="w-full px-3 py-2 bg-[#f8fafc] border border-slate-200 rounded-lg text-sm text-slate-700 outline-none">
                <option>Standard User</option>
                <option>Admin</option>
                <option>Super Admin</option>
              </select>
            </div>
            <div className="flex gap-2">
              <Btn onClick={createAccount} disabled={loading}>
                Create Account
              </Btn>
              <Btn variant="ghost" onClick={() => setShowAdd(false)}>Cancel</Btn>
            </div>
          </div>
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100">
              {["Username", "Role", "Status", "Last Login", "Attempts", "Locked", "Actions"].map(h => (
                <th key={h} className="text-left px-5 py-3 text-[10px] font-bold text-slate-400 uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-50">
            {accounts.map(acc => (
              <tr key={acc.id} className="hover:bg-slate-50/60 transition-colors">
                <td className="px-5 py-3 font-mono text-[12px] font-medium text-slate-700">{acc.username}</td>
                <td className="px-5 py-3 text-[13px] text-slate-600">{acc.role}</td>
                <td className="px-5 py-3">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${acc.status === "active" ? "bg-emerald-50 text-emerald-600 border-emerald-200" : acc.status === "locked" ? "bg-red-50 text-red-600 border-red-200" : "bg-slate-50 text-slate-500 border-slate-200"}`}>
                    {String(acc.status ?? "active").charAt(0).toUpperCase() + String(acc.status ?? "active").slice(1)}
                  </span>
                </td>
                <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{acc.last_login ? new Date(acc.last_login).toLocaleString() : "Never"}</td>
                <td className="px-5 py-3 font-semibold text-slate-700">{acc.attempts ?? 0}</td>
                <td className="px-5 py-3">
                  {acc.locked ? <Lock size={14} className="text-red-500" /> : <span className="text-slate-300 text-xs">—</span>}
                </td>
                <td className="px-5 py-3">
                  <div className="flex items-center gap-3">
                    <button onClick={() => toggleLock(acc)} className="text-[12px] text-slate-500 hover:text-slate-700 flex items-center gap-1 transition">
                      <Lock size={11} />{acc.locked ? "Unlock" : "Lock"}
                    </button>
                    <button onClick={() => removeAccount(acc.id)} className="text-[12px] text-red-400 hover:text-red-600 transition">
                      <Trash2 size={12} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="px-5 py-3 border-t border-slate-100 flex items-center justify-between">
          <p className="text-[11px] text-slate-400">{accounts.length} accounts total • {accounts.filter(a => a.status === "active").length} active</p>
          <Btn variant="outline" size="sm"><Download size={11} />Export</Btn>
        </div>
      </div>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// IP Controls Screen
// ─────────────────────────────────────────────────────────────────────────────

const IPControlsScreen = () => {
  const [ips, setIps] = useState<any[]>([]);
  const [newIP, setNewIP] = useState("");
  const [newType, setNewType] = useState("blocked");

  const load = async () => {
    try {
      setIps(await apiFetch("/api/ip-controls"));
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const addIp = async () => {
    if (!newIP.trim()) return;
    await apiFetch("/api/ip-controls", {
      method: "POST",
      body: JSON.stringify({ ip: newIP.trim(), type: newType, reason: "Manual", country: "N/A" }),
    });
    setNewIP("");
    await load();
  };

  const removeIp = async (id: string) => {
    await apiFetch(`/api/ip-controls/${id}`, { method: "DELETE" });
    await load();
  };

  return (
    <div className="space-y-5">
      <SectionHeader title="IP Controls" subtitle="Manage blocked and allowlisted IP addresses and CIDR ranges" />

      <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
        <p className="font-semibold text-slate-800 text-sm mb-4">Add IP / CIDR Range</p>
        <div className="flex gap-3 flex-wrap">
          <FormInput value={newIP} onChange={setNewIP} placeholder="e.g. 192.168.1.1 or 10.0.0.0/24" className="flex-1 min-w-[220px]" />
          <div>
            <select value={newType} onChange={e => setNewType(e.target.value)} className="h-full px-3 py-2 bg-[#f8fafc] border border-slate-200 rounded-lg text-sm text-slate-700 outline-none">
              <option value="blocked">Block</option>
              <option value="allowlisted">Allowlist</option>
            </select>
          </div>
          <Btn onClick={addIp}>
            <Plus size={13} />Add
          </Btn>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-1">
        {[
          { label: "Blocked IPs", value: ips.filter(i => i.type === "blocked").length, color: "text-red-600" },
          { label: "Allowlisted IPs", value: ips.filter(i => i.type === "allowlisted").length, color: "text-emerald-600" },
        ].map(s => (
          <div key={s.label} className="bg-white rounded-xl border border-slate-200 shadow-sm p-4 flex items-center justify-between">
            <span className="text-[13px] text-slate-500">{s.label}</span>
            <span className={`text-2xl font-bold ${s.color}`}>{s.value}</span>
          </div>
        ))}
      </div>

      <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100">
              {["IP Address", "Type", "Reason", "Added", "Attempts", "Country", "Actions"].map(h => (
                <th key={h} className="text-left px-5 py-3 text-[10px] font-bold text-slate-400 uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-50">
            {ips.map(ip => (
              <tr key={ip.id} className="hover:bg-slate-50/60 transition-colors">
                <td className="px-5 py-3 font-mono text-[13px] font-semibold text-slate-700">{ip.ip}</td>
                <td className="px-5 py-3">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${ip.type === "blocked" ? "bg-red-50 text-red-600 border-red-200" : "bg-emerald-50 text-emerald-600 border-emerald-200"}`}>
                    {ip.type === "blocked" ? "Blocked" : "Allowlisted"}
                  </span>
                </td>
                <td className="px-5 py-3 text-slate-600 text-[13px]">{ip.reason}</td>
                <td className="px-5 py-3 font-mono text-[12px] text-slate-500">{ip.created_at ? new Date(ip.created_at).toLocaleTimeString() : "—"}</td>
                <td className="px-5 py-3 font-semibold text-slate-700">{ip.attempts ?? 0}</td>
                <td className="px-5 py-3 text-slate-500">{ip.country ?? "N/A"}</td>
                <td className="px-5 py-3">
                  <button onClick={() => removeIp(ip.id)} className="text-red-400 hover:text-red-600 transition">
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// Settings Screen
// ─────────────────────────────────────────────────────────────────────────────

const SettingsScreen = () => {
  const [tab, setTab] = useState("general");
  const tabs = ["general", "detection", "notifications", "api", "security"];
  const [cfg, setCfg] = useState({
    systemName: "SecureAuth Lab",
    timezone: "Asia/Kolkata",
    maxAttempts: "500",
    lockout: "5",
    riskThreshold: "70",
    emailAlerts: true,
    slackAlerts: false,
    autoBlock: true,
    realtimeMon: true,
  });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await apiFetch("/api/settings");
        setCfg(c => ({
          ...c,
          systemName: data.system_name ?? c.systemName,
          timezone: data.timezone ?? c.timezone,
          autoBlock: data.auto_block ?? c.autoBlock,
          realtimeMon: data.realtime_monitoring ?? c.realtimeMon,
          maxAttempts: String(data.thresholds?.time_window_attempts ?? c.maxAttempts),
          lockout: String(data.thresholds?.repeated_failures ?? c.lockout),
          riskThreshold: String(data.thresholds?.risk_alert_threshold ?? c.riskThreshold),
        }));
      } catch (error) {
        console.error(error);
      }
    };
    load();
  }, []);

  const save = async () => {
    await apiFetch("/api/settings", {
      method: "PUT",
      body: JSON.stringify({
        system_name: cfg.systemName,
        timezone: cfg.timezone,
        auto_block: cfg.autoBlock,
        realtime_monitoring: cfg.realtimeMon,
        thresholds: {
          time_window_attempts: Number(cfg.maxAttempts) || 20,
          repeated_failures: Number(cfg.lockout) || 5,
          risk_alert_threshold: Number(cfg.riskThreshold) || 70,
        },
      }),
    });
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-5">
      <SectionHeader title="Settings" subtitle="Configure system preferences, detection thresholds, and integrations" />
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
        <div className="border-b border-slate-100 px-5 flex gap-0.5 overflow-x-auto">
          {tabs.map(t => (
            <button
              key={t} onClick={() => setTab(t)}
              className={`px-4 py-3 text-[13px] font-medium capitalize transition whitespace-nowrap border-b-2 -mb-px ${tab === t ? "border-blue-600 text-blue-600" : "border-transparent text-slate-500 hover:text-slate-700"}`}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="p-6">
          {tab === "general" && (
            <div className="max-w-lg space-y-4">
              <h3 className="font-semibold text-slate-800 text-sm mb-4">General Settings</h3>
              <FormInput label="System Name" value={cfg.systemName} onChange={v => setCfg(c => ({ ...c, systemName: v }))} />
              <div>
                <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Timezone</label>
                <select value={cfg.timezone} onChange={e => setCfg(c => ({ ...c, timezone: e.target.value }))} className="w-full px-3 py-2 bg-[#f8fafc] border border-slate-200 rounded-lg text-sm text-slate-700 outline-none">
                  <option>Asia/Kolkata</option>
                  <option>UTC</option>
                  <option>America/New_York</option>
                  <option>Europe/London</option>
                </select>
              </div>
              <div className="pt-2">
                <Btn onClick={save}>{saved ? <><Check size={13} />Saved!</> : "Save Changes"}</Btn>
              </div>
            </div>
          )}

          {tab === "detection" && (
            <div className="max-w-lg space-y-4">
              <h3 className="font-semibold text-slate-800 text-sm mb-4">Detection Thresholds</h3>
              <FormInput label="Max Login Attempts Before Alert" value={cfg.maxAttempts} onChange={v => setCfg(c => ({ ...c, maxAttempts: v }))} type="number" />
              <FormInput label="Lockout Threshold (failed attempts)" value={cfg.lockout} onChange={v => setCfg(c => ({ ...c, lockout: v }))} type="number" />
              <FormInput label="Risk Score Alert Threshold (0–100)" value={cfg.riskThreshold} onChange={v => setCfg(c => ({ ...c, riskThreshold: v }))} type="number" />
              <div className="space-y-3 pt-3 border-t border-slate-100">
                {[
                  { key: "autoBlock", label: "Auto-block high-risk IPs", desc: "Automatically block IPs that exceed the risk score threshold" },
                  { key: "realtimeMon", label: "Real-time monitoring", desc: "Enable continuous feed monitoring (auto-refresh)" },
                ].map(opt => (
                  <label key={opt.key} className="flex items-start gap-3 cursor-pointer p-3 rounded-lg hover:bg-slate-50 transition">
                    <input type="checkbox" checked={(cfg as any)[opt.key]} onChange={e => setCfg(c => ({ ...c, [opt.key]: e.target.checked }))} className="mt-0.5 accent-blue-600" />
                    <div>
                      <p className="text-sm font-medium text-slate-700">{opt.label}</p>
                      <p className="text-[11px] text-slate-400">{opt.desc}</p>
                    </div>
                  </label>
                ))}
              </div>
              <Btn onClick={save}>{saved ? <><Check size={13} />Saved!</> : "Save Detection Settings"}</Btn>
            </div>
          )}

          {tab === "notifications" && (
            <div className="max-w-lg space-y-3">
              <h3 className="font-semibold text-slate-800 text-sm mb-4">Notification Preferences</h3>
              {[
                { key: "emailAlerts", label: "Email Alerts",        desc: "Receive critical alerts via email" },
                { key: "slackAlerts", label: "Slack Integration",   desc: "Post alerts to configured Slack channels" },
              ].map(opt => (
                <div key={opt.key} className="flex items-center justify-between p-4 bg-slate-50 rounded-lg border border-slate-200">
                  <div>
                    <p className="text-[13px] font-semibold text-slate-700">{opt.label}</p>
                    <p className="text-[11px] text-slate-400 mt-0.5">{opt.desc}</p>
                  </div>
                  <button
                    onClick={() => setCfg(c => ({ ...c, [opt.key]: !(c as any)[opt.key] }))}
                    className={`w-10 h-6 rounded-full transition-colors relative shrink-0 ${(cfg as any)[opt.key] ? "bg-blue-600" : "bg-slate-300"}`}
                  >
                    <span className={`absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-all ${(cfg as any)[opt.key] ? "left-4" : "left-0.5"}`} />
                  </button>
                </div>
              ))}
            </div>
          )}

          {tab === "api" && (
            <div className="max-w-lg space-y-4">
              <h3 className="font-semibold text-slate-800 text-sm mb-4">API Keys</h3>
              {[
                { label: "SecureAuth API Key",   value: "sa_prod_••••••••••••abcd1234" },
                { label: "Threat Intel API Key", value: "ti_••••••••••••efgh5678" },
              ].map(k => (
                <div key={k.label} className="p-4 bg-slate-50 rounded-lg border border-slate-200">
                  <p className="text-[11px] font-bold text-slate-500 uppercase tracking-wide mb-2">{k.label}</p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 font-mono text-[13px] text-slate-700 bg-white border border-slate-200 rounded px-3 py-2">{k.value}</code>
                    <button className="text-slate-400 hover:text-slate-600 p-1.5 rounded hover:bg-white transition"><Eye size={14} /></button>
                  </div>
                </div>
              ))}
              <Btn><Plus size={12} />Generate New Key</Btn>
            </div>
          )}

          {tab === "security" && (
            <div className="max-w-lg space-y-4">
              <h3 className="font-semibold text-slate-800 text-sm mb-4">Security Settings</h3>
              <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl">
                <div className="flex items-center gap-2 mb-1.5">
                  <AlertTriangle size={13} className="text-amber-600" />
                  <span className="text-[12px] font-bold text-amber-700">Research Lab Mode Active</span>
                </div>
                <p className="text-[11px] text-amber-600 leading-relaxed">This system is configured for controlled security research only. All attack simulations are isolated. Unauthorized use is strictly prohibited.</p>
              </div>
              <div className="space-y-2">
                {[
                  { label: "Two-Factor Authentication", value: "Enabled",   color: "text-emerald-600" },
                  { label: "Session Timeout",           value: "30 minutes", color: "text-slate-600"   },
                  { label: "Audit Logging",             value: "Enabled",   color: "text-emerald-600" },
                  { label: "Data Encryption",           value: "AES-256",   color: "text-emerald-600" },
                ].map(s => (
                  <div key={s.label} className="flex items-center justify-between px-4 py-3 bg-slate-50 rounded-lg border border-slate-200">
                    <span className="text-[13px] text-slate-700">{s.label}</span>
                    <span className={`text-[12px] font-bold ${s.color}`}>{s.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────────────────
// App
// ─────────────────────────────────────────────────────────────────────────────

export default function App() {
  const [screen, setScreen] = useState<Screen>("dashboard");
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [currentRole, setCurrentRole] = useState<string | null>(null);
  const [authReady, setAuthReady] = useState(!isFirebaseConfigured);
  const [authError, setAuthError] = useState<string | null>(null);
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);
  const [wsStatus, setWsStatus] = useState<string>("connecting");
  const [unreadAlertsCount, setUnreadAlertsCount] = useState<number>(0);
  const wsRef = useRef<WebSocket | null>(null);
  const pushTokenRef = useRef<string | null>(null);
  const pushCleanupRef = useRef<(() => void) | null>(null);

  const refreshAlertsCount = async () => {
    try {
      const data = await apiFetch("/api/alerts");
      const openCount = (data ?? []).filter((a: any) => a.status === "open" || a.status === "pending").length;
      setUnreadAlertsCount(openCount);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    refreshAlertsCount();
    const unSubWsStatus = wsEvents.on("ws_status", (data) => {
      if (data.status) setWsStatus(data.status);
    });
    const unSubAlert = wsEvents.on("alert_created", () => {
      refreshAlertsCount();
    });
    const unSubReset = wsEvents.on("simulations.reset", () => {
      setUnreadAlertsCount(0);
    });
    return () => {
      unSubWsStatus();
      unSubAlert();
      unSubReset();
    };
  }, []);

  useEffect(() => {
    if (!auth || !isFirebaseConfigured) {
      setAccessToken(DEV_AUTH_TOKEN);
      setCurrentRole("admin");
      setAuthReady(true);
      return;
    }
    const unsubscribe = onAuthStateChanged(auth, async user => {
      setCurrentUser(user);
      if (user) {
        // Force a fresh ID token so newly assigned Firebase custom claims
        // (for example `role: "admin"`) are included immediately after sign-in.
        const tokenResult = await user.getIdTokenResult(true).catch(() => null);
        if (tokenResult) {
          setAccessToken(tokenResult.token);
          setCurrentRole(typeof tokenResult.claims.role === "string" ? tokenResult.claims.role : null);
        } else {
          const token = await user.getIdToken(true).catch(() => "");
          setAccessToken(token);
          setCurrentRole(null);
        }
        try {
          const profile = await apiFetch("/api/me");
          setCurrentRole(typeof profile?.role === "string" ? profile.role : null);
        } catch {
          setCurrentRole(null);
        }
      } else {
        clearAccessToken();
        setCurrentRole(null);
      }
      setAuthReady(true);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    if (!currentUser || !isFirebaseConfigured || !firebaseApp || !FIREBASE_VAPID_KEY) return;
    if (typeof window === "undefined" || !("Notification" in window) || !("serviceWorker" in navigator)) return;
    let cancelled = false;

    const setupPushNotifications = async () => {
      const supported = await isMessagingSupported().catch(() => false);
      if (!supported || cancelled) return;
      if (Notification.permission === "default") {
        try {
          await Notification.requestPermission();
        } catch {
          return;
        }
      }
      if (Notification.permission !== "granted" || cancelled) return;

      try {
        const registration = await navigator.serviceWorker.register(buildMessagingWorkerUrl(), { scope: "/" });
        const messaging = getMessaging(firebaseApp);
        const token = await getToken(messaging, {
          vapidKey: FIREBASE_VAPID_KEY,
          serviceWorkerRegistration: registration,
        });
        if (!cancelled && token && token !== pushTokenRef.current) {
          pushTokenRef.current = token;
          await apiFetch("/api/notifications/register-token", {
            method: "POST",
            body: JSON.stringify({
              token,
              platform: "web",
              device_name: navigator.userAgent,
            }),
          });
        }
        pushCleanupRef.current?.();
        pushCleanupRef.current = onMessage(messaging, payload => {
          const title = payload.notification?.title || "SecureAuth Alert";
          const body = payload.notification?.body || "New security notification";
          const data = payload.data ?? {};
          if (Notification.permission === "granted") {
            void registration.showNotification(title, {
              body,
              data,
            });
          }
        });
      } catch (error) {
        console.error("Push notification setup failed", error);
      }
    };

    void setupPushNotifications();
    return () => {
      cancelled = true;
      pushCleanupRef.current?.();
      pushCleanupRef.current = null;
    };
  }, [currentUser?.uid, authReady]);

  useEffect(() => {
    const shouldConnect = isFirebaseConfigured ? Boolean(currentUser) : Boolean(getAccessToken());
    if (!shouldConnect) return;
    let reconnectTimer: number | null = null;
    let closed = false;
    const connect = async () => {
      let token: string;
      if (currentUser && isFirebaseConfigured) {
        token = await currentUser.getIdToken(false).catch(() => getAccessToken());
        setAccessToken(token); // keep session cache in sync
      } else {
        token = getAccessToken();
      }
      if (!token) return;
      setWsStatus("connecting");
      const socket = new WebSocket(wsUrl(`/ws/live?token=${encodeURIComponent(token)}`));
      wsRef.current = socket;
      socket.onopen = () => {
        setWsStatus("connected");
        wsEvents.emit("ws_status", { status: "connected" });
      };
      socket.onmessage = (evt) => {
        try {
          const message = JSON.parse(evt.data);
          if (message && message.type) {
            wsEvents.emit(message.type, message);
          }
        } catch (err) {
          console.error("Failed to parse WebSocket message:", err);
        }
      };
      socket.onerror = () => {
        setWsStatus("disconnected");
        wsEvents.emit("ws_status", { status: "disconnected" });
        socket.close();
      };
      socket.onclose = () => {
        setWsStatus("disconnected");
        wsEvents.emit("ws_status", { status: "disconnected" });
        if (!closed) reconnectTimer = window.setTimeout(connect, 2500);
      };
    };
    connect();
    return () => {
      closed = true;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [currentUser, isFirebaseConfigured]);


  const renderScreen = () => {
    switch (screen) {
      case "dashboard":          return <DashboardScreen onNav={setScreen} canSendTestAlert={currentRole === "admin"} />;
      case "password-spray":     return <PasswordSprayScreen />;
      case "credential-stuffing":return <CredentialStuffingScreen />;
      case "custom-attack":      return <CustomAttackScreen />;
      case "attack-history":     return <AttackHistoryScreen />;
      case "live-monitoring":    return <LiveMonitoringScreen />;
      case "alerts":             return <AlertsScreen />;
      case "analytics":          return <AnalyticsScreen />;
      case "detection-models":   return <DetectionModelsScreen />;
      case "reports":            return <ReportsScreen />;
      case "test-accounts":      return <TestAccountsScreen />;
      case "ip-controls":        return <IPControlsScreen />;
      case "settings":           return <SettingsScreen />;
      default:                   return <DashboardScreen onNav={setScreen} canSendTestAlert={currentRole === "admin"} />;
    }
  };

  const handleLogin = async () => {
    if (!auth || !isFirebaseConfigured) {
      setAccessToken(DEV_AUTH_TOKEN);
      setAuthReady(true);
      return;
    }
    setLoginBusy(true);
    setAuthError(null);
    try {
      await signInWithEmailAndPassword(auth, loginEmail.trim(), loginPassword);
    } catch (error: any) {
      setAuthError(error?.message || "Unable to sign in");
    } finally {
      setLoginBusy(false);
    }
  };

  const handleLogout = async () => {
    if (pushTokenRef.current) {
      try {
        await apiFetch("/api/notifications/token", {
          method: "DELETE",
          body: JSON.stringify({ token: pushTokenRef.current }),
        });
      } catch (error) {
        console.error("Failed to unregister push token", error);
      }
    }
    if (auth && isFirebaseConfigured) {
      await signOut(auth);
    }
    pushCleanupRef.current?.();
    pushCleanupRef.current = null;
    clearAccessToken();
    setCurrentUser(null);
    setCurrentRole(null);
    pushTokenRef.current = null;
  };

  if (!authReady) {
    return <LoginScreen email={loginEmail} password={loginPassword} error={authError} loading onEmailChange={setLoginEmail} onPasswordChange={setLoginPassword} onSubmit={handleLogin} />;
  }

  if (isFirebaseConfigured && !currentUser) {
    return <LoginScreen email={loginEmail} password={loginPassword} error={authError} loading={loginBusy} onEmailChange={setLoginEmail} onPasswordChange={setLoginPassword} onSubmit={handleLogin} />;
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "#f1f5f9", fontFamily: "'Inter', sans-serif" }}>
      <Sidebar current={screen} onChange={setScreen} unreadAlertsCount={unreadAlertsCount} />
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        <TopBar onNav={setScreen} currentUser={currentUser} onLogout={handleLogout} wsStatus={wsStatus} unreadAlertsCount={unreadAlertsCount} />
        <main className="flex-1 overflow-y-auto p-6 min-w-0">
          <ErrorBoundary key={screen}>
            {renderScreen()}
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

