// P2PSec mark: an open pea pod in engraving-style line art; only the peas carry color.
// Line work uses currentColor (black on paper, white on the banner); --logo-paper fills the pod.
const PEAS = [
  { cx: 62, cy: 61, r: 13.5 },
  { cx: 90, cy: 60, r: 14.5 },
  { cx: 119, cy: 58, r: 14.5 },
  { cx: 148, cy: 55.5, r: 13.5 },
  { cx: 175, cy: 52, r: 11.5 },
];

const FRONT = "M24 63 C 66 109, 168 104, 226 47 C 196 70, 150 80, 104 80 C 70 80, 42 74, 24 63 Z";
const BACK = "M24 59 C 64 22, 160 14, 226 44 C 186 36, 128 34, 86 40 C 58 44, 38 50, 24 59 Z";

function hatch(n, from, to) {
  // parallel contour lines that follow the front valve's belly
  return Array.from({ length: n }, (_, i) => {
    const t = from + ((to - from) * i) / (n - 1);
    const y1 = 63 + t * 0.35, y2 = 108 - t, y3 = 103 - t, y4 = 47 + t * 0.12;
    return `M${26 + t * 0.4} ${y1} C ${68} ${y2}, ${166} ${y3}, ${224 - t * 0.6} ${y4}`;
  });
}

export function PeaPod({ size = 160, title = "P2PSec", detail = true }) {
  const id = "pp";
  return (
    <svg viewBox="0 0 240 120" width={size} height={size / 2} role="img" aria-label={title} className="peapod">
      <title>{title}</title>
      <defs>
        <radialGradient id={`${id}-pea`} cx="38%" cy="34%" r="70%">
          <stop offset="0" stopColor="#B9E58A" />
          <stop offset="0.45" stopColor="#6DB443" />
          <stop offset="0.85" stopColor="#3E8A26" />
          <stop offset="1" stopColor="#2A6418" />
        </radialGradient>
        <clipPath id={`${id}-front`}><path d={FRONT} /></clipPath>
        <clipPath id={`${id}-back`}><path d={BACK} /></clipPath>
        <pattern id={`${id}-x`} width="3.2" height="3.2" patternUnits="userSpaceOnUse" patternTransform="rotate(32)">
          <line x1="0" y1="0" x2="0" y2="3.2" stroke="currentColor" strokeWidth="0.45" />
        </pattern>
      </defs>

      <g fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round">
        {/* tendril */}
        <path d="M14 52 C 4 40, 6 22, 20 18 C 32 15, 38 28, 30 34 C 24 38, 18 32, 22 27 C 25 24, 29 26, 28 29"
              strokeWidth="1.3" />
        <path d="M9 47 C 3 49, 1 56, 4 60" strokeWidth="0.9" />
        {/* stem */}
        <path d="M24 61 C 16 60, 10 57, 6 50" strokeWidth="2.2" />
        <path d="M24 61 C 16 61, 10 58, 6 51" strokeWidth="0.6" opacity="0.6" />
      </g>

      {/* back valve with cross-hatched inner wall */}
      <path d={BACK} fill="var(--logo-paper, #fff)" stroke="currentColor" strokeWidth="1.6" />
      {detail && (
        <g clipPath={`url(#${id}-back)`}>
          <rect x="20" y="10" width="210" height="60" fill={`url(#${id}-x)`} opacity="0.55" />
          <path d="M30 57 C 70 38, 150 32, 220 44" fill="none" stroke="currentColor" strokeWidth="0.6" />
        </g>
      )}

      {/* peas */}
      {PEAS.map((p, i) => (
        <g key={i}>
          <circle cx={p.cx} cy={p.cy} r={p.r} fill={`url(#${id}-pea)`} stroke="#1F4A12" strokeWidth="1.1" />
          <path d={`M${p.cx - p.r * 0.2} ${p.cy + p.r * 0.95} A ${p.r} ${p.r} 0 0 0 ${p.cx + p.r * 0.95} ${p.cy + p.r * 0.1}
                    A ${p.r * 0.85} ${p.r * 0.85} 0 0 1 ${p.cx - p.r * 0.2} ${p.cy + p.r * 0.95} Z`}
                fill="#24581A" opacity="0.55" />
          <ellipse cx={p.cx - p.r * 0.38} cy={p.cy - p.r * 0.42} rx={p.r * 0.28} ry={p.r * 0.16}
                   transform={`rotate(-30 ${p.cx - p.r * 0.38} ${p.cy - p.r * 0.42})`} fill="#F4FFE8" opacity="0.85" />
          {detail && <circle cx={p.cx + p.r * 0.45} cy={p.cy - p.r * 0.55} r="0.9" fill="#F4FFE8" opacity="0.7" />}
          {/* hilum: where the pea attaches to the pod */}
          <path d={`M${p.cx - 2} ${p.cy - p.r + 1.5} q 2 -1.8 4 0`} fill="none" stroke="#1F4A12" strokeWidth="0.8" />
        </g>
      ))}

      {/* front valve: engraved contour hatching + midrib */}
      <path d={FRONT} fill="var(--logo-paper, #fff)" stroke="currentColor" strokeWidth="1.8" />
      {detail && (
        <g clipPath={`url(#${id}-front)`} fill="none" stroke="currentColor">
          {hatch(9, 0, 22).map((d, i) => (
            <path key={i} d={d} strokeWidth={0.35 + i * 0.07} opacity={0.35 + i * 0.06} />
          ))}
          {Array.from({ length: 26 }, (_, i) => {
            const x = 40 + i * 7;
            const top = 78 - Math.sin((i / 25) * Math.PI) * 4 - i * 0.6;
            return <path key={`v${i}`} d={`M${x} ${top} q 3 6 2 12`} strokeWidth="0.35" opacity="0.5" />;
          })}
        </g>
      )}
      <path d="M28 64 C 74 96, 166 92, 222 49" fill="none" stroke="currentColor" strokeWidth="0.9" />

      {/* calyx: sepals cupping the stem end */}
      <g fill="var(--logo-paper, #fff)" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round">
        <path d="M24 61 C 30 50, 40 46, 46 48 C 40 52, 34 56, 24 61 Z" />
        <path d="M24 61 C 32 68, 42 72, 48 70 C 42 66, 34 62, 24 61 Z" />
        <path d="M24 61 C 28 56, 36 54, 41 58 C 35 59, 30 60, 24 61 Z" />
      </g>
      {detail && (
        <g fill="none" stroke="currentColor" strokeWidth="0.45" opacity="0.7">
          <path d="M27 58 C 33 52, 39 49, 44 48.5" />
          <path d="M27 63 C 34 67, 41 69.5, 46 70" />
        </g>
      )}
      {/* tip */}
      <path d="M224 46 C 229 43, 232 40, 234 36" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="wordmark">
      <PeaPod size={64} detail={false} />
      <span className="wordmark-text">P2PSec</span>
    </span>
  );
}
