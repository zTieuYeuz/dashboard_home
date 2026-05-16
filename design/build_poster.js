/* Wayfinding Lucidity — poster generator. Emits poster.html (embedded SVG). */
const fs = require('fs');

const W = 1600, H = 2240;
const INK = '#0a0d14';
const S = []; // svg fragments
const p = (s) => S.push(s);

/* deterministic pseudo-random for patient, repeatable texture */
let _s = 20260516;
function rnd() { _s = (_s * 1664525 + 1013904223) % 4294967296; return _s / 4294967296; }

p(`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" font-family="JBM">`);

/* ── ground + grain + vignette ── */
p(`<defs>
  <radialGradient id="vig" cx="50%" cy="42%" r="75%">
    <stop offset="0" stop-color="#0c1018"/>
    <stop offset="0.62" stop-color="${INK}"/>
    <stop offset="1" stop-color="#06080d"/>
  </radialGradient>
  <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
    <path d="M40 0H0V40" fill="none" stroke="#10151f" stroke-width="1"/>
  </pattern>
  <radialGradient id="halo" cx="50%" cy="50%" r="50%">
    <stop offset="0" stop-color="#5b8cff" stop-opacity="0.16"/>
    <stop offset="0.55" stop-color="#5b8cff" stop-opacity="0.04"/>
    <stop offset="1" stop-color="#5b8cff" stop-opacity="0"/>
  </radialGradient>
  <filter id="soft"><feGaussianBlur stdDeviation="0.4"/></filter>
</defs>`);
p(`<rect width="${W}" height="${H}" fill="${INK}"/>`);
p(`<rect width="${W}" height="${H}" fill="url(#grid)" opacity="0.55"/>`);
p(`<rect width="${W}" height="${H}" fill="url(#vig)" opacity="0.9"/>`);

/* ── faint accumulated polar field (the patient texture) ── */
const fcx = W/2, fcy = 980;
p(`<g opacity="0.5">`);
for (let ring = 7; ring <= 30; ring++) {
  const rad = ring * 27.5;
  const n = Math.floor(rad / 13);
  for (let i = 0; i < n; i++) {
    const a = (i / n) * Math.PI * 2 + ring * 0.18;
    const x = fcx + Math.cos(a) * rad;
    const y = fcy + Math.sin(a) * rad * 0.92;
    if (x < 90 || x > W-90 || y < 150 || y > H-200) continue;
    const op = (0.05 + rnd()*0.06).toFixed(3);
    p(`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="0.9" fill="#3a5dab" opacity="${op}"/>`);
  }
}
p(`</g>`);

/* ── outer frame with corner crops ── */
const M = 70;
p(`<rect x="${M}" y="${M}" width="${W-2*M}" height="${H-2*M}" fill="none" stroke="#222d46" stroke-width="1"/>`);
const cl = 26;
[[M,M,1,1],[W-M,M,-1,1],[M,H-M,1,-1],[W-M,H-M,-1,-1]].forEach(c=>{
  p(`<path d="M${c[0]} ${c[1]+c[3]*cl} V${c[1]} H${c[0]+c[2]*cl}" fill="none" stroke="#3a4a68" stroke-width="1.4"/>`);
});

/* ── side measurement ladders ── */
function ladder(x, dir){
  const y0=300, y1=1900;
  p(`<line x1="${x}" y1="${y0}" x2="${x}" y2="${y1}" stroke="#1c2740" stroke-width="1"/>`);
  let idx=0;
  for(let y=y0; y<=y1; y+=22){
    const major = idx%5===0;
    const len = major?14:7;
    p(`<line x1="${x}" y1="${y}" x2="${x+dir*len}" y2="${y}" stroke="#26334e" stroke-width="1"/>`);
    if(idx%10===0){
      p(`<text x="${x+dir*22}" y="${y+3}" font-size="9" fill="#2f3e5e" letter-spacing="1" text-anchor="${dir>0?'start':'end'}">${String(idx).padStart(3,'0')}</text>`);
    }
    idx++;
  }
}
ladder(112, 1);
ladder(W-112, -1);

/* ── header / instrument legend ── */
p(`<text x="${M+44}" y="116" font-size="12" fill="#8a9ac0" letter-spacing="5">WAYFINDING&#160;&#160;LUCIDITY</text>`);
p(`<text x="${M+44}" y="138" font-size="10.5" fill="#3f527a" letter-spacing="3">A CHART FOR FINDING THE WAY · ABSTRACT TOPOGRAPHY OF AN OPERATIONS FIELD</text>`);
p(`<text x="${W-M-44}" y="116" font-size="11" fill="#3f527a" letter-spacing="3" text-anchor="end">LAT 0x0C · LON 0x14</text>`);
p(`<text x="${W-M-44}" y="138" font-size="11" fill="#5b8cff" letter-spacing="4" text-anchor="end">ED. I — PLATE 01</text>`);
p(`<line x1="${M+44}" y1="160" x2="${W-M-44}" y2="160" stroke="#1b2540" stroke-width="1"/>`);

/* ── the route: five primary stations along a serpentine spine ── */
const stations = [
  { y: 360,  x: W*0.50, code:'S·01', name:'SEE'     },
  { y: 660,  x: W*0.62, code:'S·02', name:'MOVE'    },
  { y: 980,  x: W*0.42, code:'S·03', name:'FIND'    },
  { y: 1300, x: W*0.60, code:'S·04', name:'RESOLVE' },
  { y: 1600, x: W*0.50, code:'S·05', name:'CONNECT' },
];

/* halo behind the conceptual centre */
p(`<circle cx="${W/2}" cy="980" r="560" fill="url(#halo)"/>`);

/* large faint range rings (concentric, behind) */
p(`<g opacity="0.4">`);
[150,300,470,640].forEach((r,i)=>{
  p(`<circle cx="${W/2}" cy="980" r="${r}" fill="none" stroke="#22335c" stroke-width="1" stroke-dasharray="${i%2?'2 7':'1 9'}"/>`);
});
p(`</g>`);

/* connective route — double track, smooth */
function pathThrough(pts){
  let d=`M${pts[0].x.toFixed(1)} ${pts[0].y}`;
  for(let i=0;i<pts.length-1;i++){
    const a=pts[i], b=pts[i+1];
    const my=(a.y+b.y)/2;
    d+=` C ${a.x.toFixed(1)} ${my.toFixed(1)} ${b.x.toFixed(1)} ${my.toFixed(1)} ${b.x.toFixed(1)} ${b.y}`;
  }
  return d;
}
const route = pathThrough(stations);
p(`<path d="${route}" fill="none" stroke="#2f4a86" stroke-width="7" opacity="0.4" filter="url(#soft)"/>`);
p(`<path d="${route}" fill="none" stroke="#6f9bff" stroke-width="1.9"/>`);
p(`<path d="${route}" fill="none" stroke="#5b8cff" stroke-width="1" opacity="0.3" transform="translate(3.5,0)"/>`);

/* secondary branch nodes off each station — the interlinked field */
stations.forEach((st, si)=>{
  const branches = 3 + (si%2);
  for(let b=0;b<branches;b++){
    const ang = (-0.9 + b*(1.8/(branches-1))) + (si%2? Math.PI: 0) + (rnd()-0.5)*0.3;
    const L = 86 + rnd()*70;
    const ex = st.x + Math.cos(ang)*L;
    const ey = st.y + Math.sin(ang)*L*0.62;
    if(ex<150||ex>W-150){ continue; }
    p(`<line x1="${st.x.toFixed(1)}" y1="${st.y}" x2="${ex.toFixed(1)}" y2="${ey.toFixed(1)}" stroke="#22345c" stroke-width="1"/>`);
    p(`<circle cx="${ex.toFixed(1)}" cy="${ey.toFixed(1)}" r="3.2" fill="#0a0d14" stroke="#3f5f9e" stroke-width="1.2"/>`);
    /* tertiary whisper */
    if(rnd()>0.45){
      const ex2=ex+Math.cos(ang)*36, ey2=ey+Math.sin(ang)*22;
      if(ex2>150&&ex2<W-150){
        p(`<line x1="${ex.toFixed(1)}" y1="${ey.toFixed(1)}" x2="${ex2.toFixed(1)}" y2="${ey2.toFixed(1)}" stroke="#1b2842" stroke-width="1"/>`);
        p(`<circle cx="${ex2.toFixed(1)}" cy="${ey2.toFixed(1)}" r="1.8" fill="#2c4a6e"/>`);
      }
    }
  }
});

/* primary station glyphs — concentric precision */
const stateColor = ['#34d399','#5b8cff','#5b8cff','#fbbf24','#34d399'];
stations.forEach((st,i)=>{
  const c = stateColor[i];
  p(`<circle cx="${st.x.toFixed(1)}" cy="${st.y}" r="30" fill="none" stroke="#26345a" stroke-width="1"/>`);
  p(`<circle cx="${st.x.toFixed(1)}" cy="${st.y}" r="17" fill="#0b1018" stroke="${c}" stroke-width="1.5" opacity="0.85"/>`);
  p(`<circle cx="${st.x.toFixed(1)}" cy="${st.y}" r="6.5" fill="${c}"/>`);
  p(`<circle cx="${st.x.toFixed(1)}" cy="${st.y}" r="44" fill="none" stroke="${c}" stroke-width="1" opacity="0.18"/>`);
  /* label plate to the open side */
  const left = st.x > W/2;
  const lx = left ? st.x - 64 : st.x + 64;
  const anc = left ? 'end' : 'start';
  p(`<text x="${lx.toFixed(1)}" y="${st.y-4}" font-size="13" fill="#cdd6e6" letter-spacing="4" text-anchor="${anc}">${st.name}</text>`);
  p(`<text x="${lx.toFixed(1)}" y="${st.y+15}" font-size="10" fill="#425274" letter-spacing="3" text-anchor="${anc}">${st.code} · NODE</text>`);
  /* tiny connector tick from glyph to label */
  const tx0 = left ? st.x-30 : st.x+30;
  const tx1 = left ? st.x-52 : st.x+52;
  p(`<line x1="${tx0.toFixed(1)}" y1="${st.y}" x2="${tx1.toFixed(1)}" y2="${st.y}" stroke="#33486f" stroke-width="1"/>`);
});

/* ── anchor typography ── */
p(`<text x="${W/2}" y="1808" font-size="12.5" fill="#3f527a" letter-spacing="15" text-anchor="middle">PLATE 01 — THE WAY</text>`);
p(`<text x="${W/2}" y="1930" font-family="Jura" font-weight="300" font-size="150" fill="#eef2fa" letter-spacing="17" text-anchor="middle">LUCIDITY</text>`);
p(`<line x1="${W/2-44}" y1="1958" x2="${W/2+44}" y2="1958" stroke="#2b3a5c" stroke-width="1"/>`);
p(`<text x="${W/2}" y="2000" font-family="ISerif" font-style="italic" font-size="33" fill="#6f81a7" letter-spacing="1" text-anchor="middle">every place is one step away</text>`);

/* ── footer instrument legend ── */
const fy = 2118;
p(`<line x1="${M+44}" y1="${fy-34}" x2="${W-M-44}" y2="${fy-34}" stroke="#1b2540" stroke-width="1"/>`);
const leg=[['#34d399','NOMINAL'],['#fbbf24','WATCH'],['#f87171','FAULT']];
let lx=M+44;
leg.forEach(it=>{
  p(`<circle cx="${lx+4}" cy="${fy-4}" r="4" fill="${it[0]}"/>`);
  p(`<text x="${lx+18}" y="${fy}" font-size="10.5" fill="#4a5d83" letter-spacing="3">${it[1]}</text>`);
  lx += 150;
});
/* scale bar centre */
const sbx=W/2-90, sby=fy-6;
p(`<line x1="${sbx}" y1="${sby}" x2="${sbx+180}" y2="${sby}" stroke="#3a4a68" stroke-width="1"/>`);
[0,45,90,135,180].forEach(d=>p(`<line x1="${sbx+d}" y1="${sby-4}" x2="${sbx+d}" y2="${sby+4}" stroke="#3a4a68" stroke-width="1"/>`));
p(`<text x="${W/2}" y="${fy+16}" font-size="9" fill="#324164" letter-spacing="3" text-anchor="middle">SCALE — ARBITRARY UNITS</text>`);
p(`<text x="${W-M-44}" y="${fy}" font-size="10.5" fill="#4a5d83" letter-spacing="3" text-anchor="end">⌖  COMPOSED IN INK &amp; SIGNAL</text>`);

p(`</svg>`);

const html = `<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{font-family:'JBM';src:url('fonts/JetBrainsMono-Regular.ttf');}
@font-face{font-family:'JBMB';src:url('fonts/JetBrainsMono-Bold.ttf');}
@font-face{font-family:'Jura';src:url('fonts/Jura-Light.ttf');font-weight:300;}
@font-face{font-family:'Jura';src:url('fonts/Jura-Medium.ttf');font-weight:500;}
@font-face{font-family:'ISerif';src:url('fonts/InstrumentSerif-Regular.ttf');}
@font-face{font-family:'ISerif';src:url('fonts/InstrumentSerif-Italic.ttf');font-style:italic;}
*{margin:0;padding:0}html,body{width:${W}px;height:${H}px;background:${INK}}
svg{display:block}
</style></head><body>${S.join('\n')}</body></html>`;

fs.writeFileSync(__dirname + '/poster.html', html);
console.log('poster.html written', html.length, 'bytes');
