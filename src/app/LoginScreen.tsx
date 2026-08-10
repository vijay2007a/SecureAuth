import { Shield } from "lucide-react";
import { isFirebaseConfigured } from "./firebase";

export const LoginScreen = ({
  email,
  password,
  error,
  loading,
  onEmailChange,
  onPasswordChange,
  onSubmit,
}: {
  email: string;
  password: string;
  error: string | null;
  loading: boolean;
  onEmailChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onSubmit: () => void;
}) => (
  <div className="min-h-screen flex items-center justify-center px-4" style={{ background: "linear-gradient(135deg, #eaf2ff 0%, #f8fbff 45%, #e9f4f4 100%)" }}>
    <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl shadow-2xl p-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-12 h-12 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-lg">
          <Shield size={20} />
        </div>
        <div>
          <h1 className="text-xl font-bold text-slate-800">SecureAuth Lab</h1>
          <p className="text-sm text-slate-500">Firebase authenticated access</p>
        </div>
      </div>
      <div className="space-y-4">
        <div>
          <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Email</label>
          <input value={email} onChange={e => onEmailChange(e.target.value)} placeholder="analyst@lab.local" className="w-full px-3 py-2 bg-[#f8fafc] border border-slate-200 rounded-lg text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 transition" />
        </div>
        <div>
          <label className="block text-[10px] font-bold text-slate-500 uppercase tracking-wide mb-1.5">Password</label>
          <input type="password" value={password} onChange={e => onPasswordChange(e.target.value)} placeholder="Your Firebase password" className="w-full px-3 py-2 bg-[#f8fafc] border border-slate-200 rounded-lg text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-400 transition" />
        </div>
        {error && <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</div>}
        <button onClick={onSubmit} disabled={loading} className="w-full py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white rounded-lg text-sm font-semibold transition">
          {loading ? "Signing in..." : "Sign in"}
        </button>
      </div>
      <p className="text-xs text-slate-400 mt-5 leading-relaxed">
        {isFirebaseConfigured ? "Your Firebase ID token will be attached to protected API requests." : "Firebase env vars are missing, so the app is currently using the local dev auth fallback."}
      </p>
    </div>
  </div>
);
