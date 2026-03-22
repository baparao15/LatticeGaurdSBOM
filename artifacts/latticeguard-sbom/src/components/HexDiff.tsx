interface Props {
  original: string;
  tampered: string;
  label?: string;
}

function chunkHex(hex: string, chunkSize = 2): string[] {
  const chunks: string[] = [];
  for (let i = 0; i < hex.length; i += chunkSize) {
    chunks.push(hex.slice(i, i + chunkSize));
  }
  return chunks;
}

export default function HexDiff({
  original,
  tampered,
  label = "Hash Comparison",
}: Props) {
  const origChunks = chunkHex(original.slice(0, 64));
  const tampChunks = chunkHex(tampered.slice(0, 64));
  const maxLen = Math.max(origChunks.length, tampChunks.length);

  return (
    <div className="rounded-lg border border-[#ff3366]/30 overflow-hidden">
      <div className="px-3 py-2 bg-[#ff3366]/10 border-b border-[#ff3366]/20 flex items-center gap-2">
        <span className="text-[#ff3366] text-xs font-mono font-semibold">
          ⚠ {label}
        </span>
        <span className="text-gray-500 text-xs">
          (first 32 bytes shown)
        </span>
      </div>
      <div className="p-3 font-mono text-xs space-y-2">
        <div>
          <span className="text-gray-500 text-[10px] uppercase tracking-wider mr-2">
            Expected:
          </span>
          <div className="mt-1 flex flex-wrap gap-0.5">
            {origChunks.slice(0, 32).map((byte, i) => {
              const isDiff = byte !== (tampChunks[i] ?? "");
              return (
                <span
                  key={i}
                  className={isDiff ? "text-[#00ff88]" : "text-gray-400"}
                >
                  {byte}
                </span>
              );
            })}
          </div>
        </div>
        <div>
          <span className="text-gray-500 text-[10px] uppercase tracking-wider mr-2">
            Received:
          </span>
          <div className="mt-1 flex flex-wrap gap-0.5">
            {Array.from({ length: Math.min(maxLen, 32) }, (_, i) => {
              const byte = tampChunks[i] ?? "??";
              const isDiff = byte !== (origChunks[i] ?? "");
              return (
                <span
                  key={i}
                  className={
                    isDiff ? "text-[#ff3366] underline decoration-dotted" : "text-gray-400"
                  }
                >
                  {byte}
                </span>
              );
            })}
          </div>
        </div>
        <div className="pt-1 border-t border-white/5 text-gray-600 text-[10px]">
          <span className="text-[#00ff88]">█</span> original bytes &nbsp;
          <span className="text-[#ff3366]">█</span> tampered bytes
        </div>
      </div>
    </div>
  );
}
