export function riskBadgeClass(level) {
  const v = (level || "").toLowerCase();
  if (v.includes("crít") || v.includes("crit") || v.includes("alto")) return "badge badge-bad";
  if (v.includes("medio")) return "badge badge-warn";
  if (v.includes("bajo")) return "badge badge-ok";
  return "badge badge-info";
}

export function deviceShortTag(type) {
  if (type === "router") return "RT";
  if (type === "mobile") return "MOV";
  if (type === "windows") return "WIN";
  if (type === "linux") return "LNX";
  if (type === "laptop") return "PC";
  return "DEV";
}