import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Clock, Shield, CheckCircle, RefreshCw, Lock } from "lucide-react";
import { getAuditEvents, AuditEvent } from "@/api/packages";

const EVENT_CONFIG: Record<string, { color: string; label: string; icon: string }> = {
  NAME_LIST_FETCHED: { color: "#00d4ff", label: "Name List Fetched", icon: "🔗" },
  NAME_CHECK: { color: "#a78bfa", label: "Name Verified", icon: "🔍" },
  RISK_SCORED: { color: "#ff9900", label: "Risk Scored", icon: "📊" },
  STATIC_SCAN: { color: "#ff3366", label: "Static Scan", icon: "🔬" },
  SBOM_SIGNED: { color: "#00ff88", label: "SBOM Signed", icon: "✍️" },
  LICENSE_ANALYSIS: { color: "#00d4ff", label: "License Analysis", icon: "⚖️" },
};

export default function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const res = await getAuditEvents();
      setEvents(res.events);
    } catch {
      /* backend may not be connected yet */
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <section id="audit" className="py-20 px-4 relative">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/20 mb-4">
            <Clock className="w-3.5 h-3.5 text-[#00ff88]" />
            <span className="text-xs text-[#00ff88] font-medium">Phase 4 — PQC Audit Log</span>
          </div>
          <h2 className="text-3xl font-bold text-white mb-3">
            Cryptographic <span className="gradient-text">Audit Timeline</span>
          </h2>
          <p className="text-gray-400 text-sm max-w-xl mx-auto">
            Every cryptographic event is independently signed with ML-DSA-65 + Ed25519 and
            appended to the immutable session audit log.
          </p>
        </div>

        <div className="glass-card rounded-2xl overflow-hidden">
          {/* Header */}
          <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-4 h-4 text-[#00ff88]" />
              <span className="text-sm font-semibold text-white">Audit Events</span>
              <span className="px-2 py-0.5 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/20 text-[#00ff88] text-xs">
                {events.length}
              </span>
            </div>
            <button
              onClick={fetchEvents}
              disabled={loading}
              className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>

          {/* Events */}
          <div className="divide-y divide-white/5 max-h-[520px] overflow-y-auto">
            {events.length === 0 ? (
              <div className="p-10 text-center">
                <Lock className="w-8 h-8 text-gray-700 mx-auto mb-3" />
                <p className="text-gray-600 text-sm">
                  No audit events yet. Start an analysis above to populate the log.
                </p>
              </div>
            ) : (
              <AnimatePresence>
                {[...events].reverse().map((ev, i) => {
                  const cfg = EVENT_CONFIG[ev.event_type] ?? {
                    color: "#888",
                    label: ev.event_type,
                    icon: "●",
                  };
                  const isOpen = expanded === ev.id;
                  return (
                    <motion.div
                      key={ev.id}
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.02 }}
                    >
                      <button
                        className="w-full px-5 py-3.5 flex items-start gap-4 hover:bg-white/3 transition-colors text-left"
                        onClick={() => setExpanded(isOpen ? null : ev.id)}
                      >
                        {/* Timeline dot */}
                        <div className="flex-shrink-0 mt-1 relative">
                          <div
                            className="w-2.5 h-2.5 rounded-full"
                            style={{ backgroundColor: cfg.color }}
                          />
                        </div>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="text-sm font-medium text-white">
                              {cfg.icon} {cfg.label}
                            </span>
                            <span
                              className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                              style={{
                                backgroundColor: `${cfg.color}15`,
                                color: cfg.color,
                              }}
                            >
                              {ev.event_type}
                            </span>
                          </div>
                          <p className="text-xs text-gray-400 truncate">{ev.description}</p>
                          <div className="flex items-center gap-3 mt-1">
                            <span className="text-[10px] text-gray-600 font-mono">
                              {new Date(ev.timestamp * 1000).toISOString()}
                            </span>
                            <span className="text-[10px] text-[#7c3aed] font-mono">
                              ML-DSA-65 · Ed25519 · {ev.signature_size_bytes}B
                            </span>
                          </div>
                        </div>

                        <CheckCircle className="w-4 h-4 text-[#00ff88] flex-shrink-0 mt-1" />
                      </button>

                      {/* Expanded detail */}
                      <AnimatePresence>
                        {isOpen && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="overflow-hidden"
                          >
                            <div className="px-5 pb-4 bg-black/20 space-y-2">
                              <div className="grid grid-cols-1 gap-2 pt-2">
                                <SigRow
                                  label="ML-DSA-65 Signature"
                                  value={ev.ml_dsa_signature}
                                  color="#a78bfa"
                                />
                                <SigRow
                                  label="Ed25519 Signature"
                                  value={ev.ed25519_signature}
                                  color="#00d4ff"
                                />
                                {Object.entries(ev.details).slice(0, 6).map(([k, v]) => (
                                  <div key={k} className="flex gap-3 text-xs">
                                    <span className="text-gray-600 font-mono w-40 flex-shrink-0">{k}:</span>
                                    <span className="text-gray-400 font-mono truncate">
                                      {typeof v === "object" ? JSON.stringify(v) : String(v)}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            )}
          </div>

          {/* Footer legend */}
          <div className="px-5 py-3 border-t border-white/5 flex flex-wrap gap-3">
            {Object.entries(EVENT_CONFIG).map(([type, cfg]) => (
              <span key={type} className="flex items-center gap-1.5 text-[10px] text-gray-600">
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: cfg.color }} />
                {cfg.label}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function SigRow({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="space-y-0.5">
      <p className="text-[10px] font-mono" style={{ color }}>
        {label}
      </p>
      <p className="text-[9px] font-mono text-gray-600 break-all leading-tight">
        {value.slice(0, 96)}…
      </p>
    </div>
  );
}
