// VibeSnitch badge — returns an SVG grade badge for GitHub READMEs / site footers.
// Usage: /.netlify/functions/badge?g=A   (optionally &s=app.frigolog.fr)
const COLORS = { A: "#57D9A3", B: "#8FD14F", C: "#FFCF5C", D: "#FF9F45", F: "#FF5D5D" };

export default async (req) => {
  const u = new URL(req.url);
  const grade = (u.searchParams.get("g") || "?").toUpperCase().slice(0, 1);
  const color = COLORS[grade] || "#5A5F6E";
  const label = "VibeSnitch";
  const value = `Grade ${grade}`;
  const lw = 74, vw = 66, h = 20, w = lw + vw;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" role="img" aria-label="${label}: ${value}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${w}" height="${h}" rx="4" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lw}" height="${h}" fill="#101219"/>
    <rect x="${lw}" width="${vw}" height="${h}" fill="${color}"/>
    <rect width="${w}" height="${h}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${lw / 2}" y="14" fill="#FFD447" font-weight="bold">${label}</text>
    <text x="${lw + vw / 2}" y="14" fill="#181400" font-weight="bold">${value}</text>
  </g>
</svg>`;
  return new Response(svg, {
    status: 200,
    headers: { "content-type": "image/svg+xml", "cache-control": "public, max-age=3600" },
  });
};
