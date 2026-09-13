import React, { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence, useReducedMotion } from "framer-motion";
import "./App.css";

// ---------------------------------------------------------------------------
// Backend config
// ---------------------------------------------------------------------------

// Override with a .env file: VITE_API_URL=http://localhost:8000
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// Fallbacks so the UI has sensible options even before /models and /tests
// resolve (or if the backend is briefly unreachable). Mirrors app/config.py.
const FALLBACK_PROVIDERS = {
  gemini: ["gemini-3.5-flash", "gemini-3.6-flash", "gemini-3.1-flash-lite"],
  groq: ["openai/gpt-oss-20b", "openai/gpt-oss-120b"],
};
const FALLBACK_CATEGORIES = [
  "Prompt Injection",
  "Jailbreak Resistance",
  "System Prompt Leakage",
  "Sensitive Information Disclosure",
];
const FALLBACK_TECHNIQUES = [
  "Standard English",
  "Roman Urdu",
  "Multilingual / Cross-Lingual",
  "Role-Play",
  "Creative Formatting",
  "Indirect Instruction",
  "System Prompt Extraction",
];
const DEFAULT_SYSTEM_PROMPT = "You are a helpful AI assistant.";

function timestamp() {
  return new Date().toTimeString().slice(0, 8);
}

function truncate(text, max = 260) {
  if (!text) return "";
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

// ---------------------------------------------------------------------------
// Intro
// ---------------------------------------------------------------------------

function IntroSequence() {
  return (
    <div className="intro-screen">
      <motion.div
        className="intro-line"
        initial={{ scaleX: 0, opacity: 0.4 }}
        animate={{ scaleX: 1, opacity: 1 }}
        transition={{ duration: 1.1, ease: [0.16, 1, 0.3, 1] }}
      />
      <motion.h1
        className="intro-title"
        initial={{ opacity: 0, letterSpacing: "0.7em" }}
        animate={{ opacity: 1, letterSpacing: "0.22em" }}
        transition={{ duration: 2.8, delay: 0.9, ease: "easeOut" }}
      >
        SENTINELLLM
      </motion.h1>
      <motion.p
        className="intro-subtitle"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 1, delay: 3.2 }}
      >
        Autonomous Red Team Console
      </motion.p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sidebar
// ---------------------------------------------------------------------------

function Sidebar({
  backendOnline,
  providers,
  provider,
  setProvider,
  model,
  setModel,
  categories,
  vulnerability,
  setVulnerability,
  techniques,
  technique,
  setTechnique,
  systemPrompt,
  setSystemPrompt,
  providerMode,
}) {
  const models = providers[provider] || [];

  return (
    <div className="glass-card sidebar-card">
      <div className="brand-block">
        <div className="brand-mark" />
        <h1 className="brand-title">SENTINELLLM</h1>
        <p className="brand-tagline">Autonomous Red Team Console</p>
      </div>

      <div className="field-group">
        <label className="field-label" htmlFor="provider-select">
          Target Provider
        </label>
        <div className="select-wrap">
          <select
            id="provider-select"
            className="field-select"
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
          >
            {Object.keys(providers).map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <span className="select-caret" aria-hidden="true">
            ▾
          </span>
        </div>
      </div>

      <div className="field-group">
        <label className="field-label" htmlFor="model-select">
          Target Model
        </label>
        <div className="select-wrap">
          <select
            id="model-select"
            className="field-select"
            value={model}
            onChange={(e) => setModel(e.target.value)}
          >
            {models.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <span className="select-caret" aria-hidden="true">
            ▾
          </span>
        </div>
        {providerMode && (
          <span
            className={`mode-chip mode-chip--${providerMode === "configured" ? "live" : "demo"}`}
          >
            {providerMode === "configured" ? "Live API key" : "Demo mode"}
          </span>
        )}
      </div>

      <div className="field-group">
        <label className="field-label" htmlFor="vulnerability-select">
          Vulnerability Category
        </label>
        <div className="select-wrap">
          <select
            id="vulnerability-select"
            className="field-select"
            value={vulnerability}
            onChange={(e) => setVulnerability(e.target.value)}
          >
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <span className="select-caret" aria-hidden="true">
            ▾
          </span>
        </div>
      </div>

      <div className="field-group">
        <label className="field-label" htmlFor="technique-select">
          Select Payload
        </label>
        <div className="select-wrap">
          <select
            id="technique-select"
            className="field-select"
            value={technique}
            onChange={(e) => setTechnique(e.target.value)}
          >
            {techniques.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <span className="select-caret" aria-hidden="true">
            ▾
          </span>
        </div>
      </div>

      <div className="field-group">
        <label className="field-label" htmlFor="system-prompt">
          Target System Prompt
        </label>
        <textarea
          id="system-prompt"
          className="field-textarea"
          rows={3}
          value={systemPrompt}
          onChange={(e) => setSystemPrompt(e.target.value)}
          spellCheck={false}
        />
      </div>

      <div className="sidebar-footer">
        <span
          className={`status-dot${backendOnline ? " status-dot--live" : " status-dot--dead"}`}
        />
        <span className="status-text">
          {backendOnline ? `Backend online · ${API_BASE}` : `Backend unreachable · ${API_BASE}`}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

// Rapid char-by-char reveal for evidence lines. FAIL renders in Neon Orange,
// PASS (or anything else) renders in Tactical Green, with a blocky pixel
// cursor trailing the text while it's still typing.
function TypedLine({ text, status }) {
  const [count, setCount] = useState(0);

  useEffect(() => {
    setCount(0);
    if (!text) return undefined;
    const id = setInterval(() => {
      setCount((c) => {
        if (c >= text.length) {
          clearInterval(id);
          return c;
        }
        return c + 1;
      });
    }, 12);
    return () => clearInterval(id);
  }, [text]);

  const done = count >= text.length;
  const colorClass = status === "FAIL" ? "typed-text--fail" : "typed-text--pass";

  return (
    <span className={`terminal-text typed-text ${colorClass}`}>
      {text.slice(0, count)}
      {!done && <span className="terminal-cursor terminal-cursor--inline" aria-hidden="true" />}
    </span>
  );
}

function Terminal({ lines, scanning }) {
  const bodyRef = useRef(null);

  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div className={`terminal${scanning ? " terminal--scanning" : ""}`} ref={bodyRef}>
      {lines.map((line, i) => (
        <div key={i} className={`terminal-line terminal-line--${line.type}`}>
          <span className="terminal-time">[{line.time}]</span>
          {line.type === "typewriter" ? (
            <TypedLine text={line.text} status={line.status} />
          ) : (
            <span className="terminal-text">{line.text}</span>
          )}
        </div>
      ))}
      <span className="terminal-cursor" aria-hidden="true" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pixel Avatar — 8-bit cyber-drone, state-reactive
// ---------------------------------------------------------------------------

// Purely CSS box-shadow pixel art (see .pixel-avatar__sprite in App.css) —
// no external image assets. `state` is one of idle | scanning | breach | blocked.
function PixelAvatar({ state }) {
  return (
    <div className={`pixel-avatar pixel-avatar--${state}`} aria-hidden="true" title={`Sentinel drone — ${state}`}>
      <span className="pixel-avatar__sprite" />
      <span className="pixel-avatar__sprite pixel-avatar__sprite--alt" />
      <span className="pixel-avatar__eye" />
      <span className="pixel-avatar__shield" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main stage
// ---------------------------------------------------------------------------

function MainStage({
  provider,
  model,
  vulnerability,
  technique,
  running,
  status,
  lines,
  onExecute,
  canExecute,
}) {
  // Drives the Pixel Avatar directly off the loading state and the last
  // scan's result status, so it stays in sync with the terminal/badge.
  const avatarState = running
    ? "scanning"
    : status.type === "breach"
    ? "breach"
    : status.type === "secure"
    ? "blocked"
    : "idle";

  return (
    <div className="glass-card main-card">
      <div className="main-header">
        <div>
          <h2 className="main-title">Live Security Scan</h2>
          <p className="main-subtitle">
            {provider}/{model} · {vulnerability} · {technique}
          </p>
        </div>
        <div className="main-header-right">
          <PixelAvatar state={avatarState} />
          <div className={`status-badge status-badge--${status.type}`}>{status.label}</div>
        </div>
      </div>

      <Terminal lines={lines} scanning={running} />

      <button
        className="execute-button"
        onClick={onExecute}
        disabled={running || !canExecute}
        title={!canExecute ? "Backend unreachable — start the FastAPI server first" : undefined}
      >
        {running ? "Scanning..." : "Execute Attack"}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

function Dashboard() {
  const [providers, setProviders] = useState(FALLBACK_PROVIDERS);
  const [categories, setCategories] = useState(FALLBACK_CATEGORIES);
  const [techniques, setTechniques] = useState(FALLBACK_TECHNIQUES);
  const [health, setHealth] = useState(null);
  const [backendOnline, setBackendOnline] = useState(false);

  const [provider, setProvider] = useState("gemini");
  const [model, setModel] = useState("gemini-3.5-flash");
  const [vulnerability, setVulnerability] = useState(FALLBACK_CATEGORIES[0]);
  const [technique, setTechnique] = useState(FALLBACK_TECHNIQUES[0]);
  const [systemPrompt, setSystemPrompt] = useState(DEFAULT_SYSTEM_PROMPT);

  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState({ type: "idle", label: "Idle" });
  const [lines, setLines] = useState([
    { type: "system", text: "SentinelLLM console ready.", time: timestamp() },
    { type: "system", text: "Connecting to backend...", time: timestamp() },
  ]);

  const appendLine = (type, text) =>
    setLines((prev) => [...prev, { type, text, time: timestamp() }]);

  // Evidence lines that should type out character-by-character, colored by
  // the scan's PASS/FAIL status.
  const appendTypedLine = (prefix, text, status) =>
    setLines((prev) => [
      ...prev,
      { type: "typewriter", text: `${prefix} → ${truncate(text)}`, status, time: timestamp() },
    ]);

  // Bootstrap: health, models, tests -------------------------------------
  useEffect(() => {
    let cancelled = false;

    async function bootstrap() {
      try {
        const [healthRes, modelsRes, testsRes] = await Promise.all([
          fetch(`${API_BASE}/health`),
          fetch(`${API_BASE}/models`),
          fetch(`${API_BASE}/tests`),
        ]);
        if (!healthRes.ok || !modelsRes.ok || !testsRes.ok) {
          throw new Error("Backend responded with an error");
        }
        const [healthData, modelsData, testsData] = await Promise.all([
          healthRes.json(),
          modelsRes.json(),
          testsRes.json(),
        ]);
        if (cancelled) return;

        const nextProviders = modelsData.target_providers || FALLBACK_PROVIDERS;
        const nextCategories = testsData.categories || FALLBACK_CATEGORIES;
        const nextTechniques = testsData.techniques || FALLBACK_TECHNIQUES;

        setHealth(healthData);
        setProviders(nextProviders);
        setProvider(modelsData.defaults?.provider || "gemini");
        setModel(modelsData.defaults?.model || "");
        setCategories(nextCategories);
        setTechniques(nextTechniques);
        setVulnerability(nextCategories[0]);
        setTechnique(nextTechniques[0]);
        setBackendOnline(true);
        appendLine("system", "Connected to SentinelLLM backend.");
      } catch (err) {
        if (cancelled) return;
        setBackendOnline(false);
        appendLine(
          "critical",
          `Could not reach backend at ${API_BASE}. Start it with "python run.py" and confirm CORS allows this origin.`
        );
      }
    }

    bootstrap();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep model valid whenever the provider (or provider list) changes ----
  useEffect(() => {
    const available = providers[provider];
    if (available && available.length && !available.includes(model)) {
      setModel(available[0]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider, providers]);

  const providerMode = health?.providers?.[provider];

  const handleExecute = async () => {
    if (running) return;

    setRunning(true);
    setStatus({ type: "scanning", label: "Scanning" });
    appendLine("system", `Connecting to ${provider}/${model}...`);
    appendLine("info", `Deploying test: ${vulnerability} via ${technique}`);

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider,
          model,
          vulnerability,
          attack_technique: technique,
          system_prompt: systemPrompt || DEFAULT_SYSTEM_PROMPT,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || `Scan request failed (HTTP ${res.status})`);
      }

      appendTypedLine("Test prompt", data.evidence.test_prompt, data.result.status);
      appendTypedLine("Target response", data.evidence.target_response, data.result.status);

      if (data.result.status === "FAIL") {
        appendLine("critical", `VULNERABILITY CONFIRMED — ${data.owasp.id} ${data.owasp.name}`);
        appendLine("critical", truncate(data.evidence.reasoning, 220));
        setStatus({ type: "breach", label: "Breach Detected" });
      } else if (data.result.status === "PASS") {
        appendLine("success", "Target resisted the attack. No vulnerability detected.");
        setStatus({ type: "secure", label: "Secure" });
      } else {
        appendLine("warning", "Result inconclusive — flagged for manual review.");
        setStatus({ type: "review", label: "Needs Review" });
      }

      appendLine(
        "system",
        `Risk score ${data.result.risk_score}/100 (${data.result.severity}) · confidence ${(
          data.result.confidence * 100
        ).toFixed(0)}% · mode ${data.mode} · attempts ${data.attempts}`
      );
    } catch (err) {
      setStatus({ type: "error", label: "Scan Failed" });
      appendLine("critical", `Scan failed: ${err.message}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="dashboard-grid">
      <Sidebar
        backendOnline={backendOnline}
        providers={providers}
        provider={provider}
        setProvider={setProvider}
        model={model}
        setModel={setModel}
        categories={categories}
        vulnerability={vulnerability}
        setVulnerability={setVulnerability}
        techniques={techniques}
        technique={technique}
        setTechnique={setTechnique}
        systemPrompt={systemPrompt}
        setSystemPrompt={setSystemPrompt}
        providerMode={providerMode}
      />
      <MainStage
        provider={provider}
        model={model}
        vulnerability={vulnerability}
        technique={technique}
        running={running}
        status={status}
        lines={lines}
        onExecute={handleExecute}
        canExecute={backendOnline}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

export default function App() {
  const prefersReducedMotion = useReducedMotion();
  const [booted, setBooted] = useState(false);

  useEffect(() => {
    if (prefersReducedMotion) {
      setBooted(true);
      return;
    }
    const timer = setTimeout(() => setBooted(true), 5000);
    return () => clearTimeout(timer);
  }, [prefersReducedMotion]);

  return (
    <div className="app-root">
      <div className="ambient-glow ambient-glow--purple" />
      <div className="ambient-glow ambient-glow--green" />

      <AnimatePresence mode="wait">
        {!booted ? (
          <motion.div
            key="intro"
            className="intro-wrapper"
            exit={{ opacity: 0 }}
            transition={{ duration: 0.8, ease: "easeInOut" }}
          >
            <IntroSequence />
          </motion.div>
        ) : (
          <motion.div
            key="dashboard"
            className="dashboard-wrapper"
            initial={{ opacity: 0, y: 60 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
          >
            <Dashboard />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
