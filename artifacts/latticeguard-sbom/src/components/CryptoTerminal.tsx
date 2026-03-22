import { useEffect, useRef } from "react";

export interface TerminalLine {
  text: string;
  type: "info" | "success" | "error" | "warn" | "dim";
  timestamp?: boolean;
}

interface CryptoTerminalProps {
  lines: TerminalLine[];
  height?: string;
}

const colors: Record<TerminalLine["type"], string> = {
  info: "text-[#00d4ff]",
  success: "text-[#00ff88]",
  error: "text-[#ff3366]",
  warn: "text-[#ffaa00]",
  dim: "text-gray-500",
};

export default function CryptoTerminal({
  lines,
  height = "h-72",
}: CryptoTerminalProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  return (
    <div
      className={`${height} bg-black/60 border border-[#00d4ff]/20 rounded-lg p-4 font-mono text-sm overflow-y-auto`}
    >
      {lines.length === 0 && (
        <p className="text-gray-600 select-none">
          {">"} Waiting for input...
        </p>
      )}
      {lines.map((line, i) => (
        <div key={i} className={`flex gap-2 leading-6 ${colors[line.type]}`}>
          <span className="shrink-0 text-gray-600 select-none text-xs pt-0.5">
            {String(i + 1).padStart(3, "0")}
          </span>
          <span className="break-all">{line.text}</span>
        </div>
      ))}
      <div ref={bottomRef} />
    </div>
  );
}
