"use strict";
/**
 * APJ Threat Intelligence — standalone frontend.
 * Pulls pre-tagged, pre-aggregated data from /api/data (populated by the Worker's
 * scheduled collector — see src/worker.js). No client-side fetching, no API keys,
 * no MCP bridge: this runs anywhere as static files behind that one endpoint.
 */

const APP_VERSION = "standalone-v1";
const REFRESH_POLL_MS = 5 * 60 * 1000; // re-poll /api/data every 5 min to pick up the cron's updates

const APJ_CC = { IN:"India", JP:"Japan", CN:"China", KR:"South Korea", TW:"Taiwan", AU:"Australia", NZ:"New Zealand", SG:"Singapore", VN:"Vietnam", TH:"Thailand", ID:"Indonesia", MY:"Malaysia", PH:"Philippines", BD:"Bangladesh", LK:"Sri Lanka", NP:"Nepal", PK:"Pakistan", MM:"Myanmar", KH:"Cambodia", HK:"Hong Kong", MO:"Macau" };

const CENTROIDS = {
  IN:[20,78], JP:[36,138], CN:[35,105], KR:[36,128], TW:[23,121], AU:[-25,133], NZ:[-41,174],
  SG:[1.3,103.8], VN:[16,108], TH:[15,101], ID:[-5,120], MY:[4,102], PH:[13,122], BD:[24,90],
  LK:[7,81], NP:[28,84], PK:[30,70], MM:[21,96], KH:[12,105], HK:[22.3,114.2], MO:[22.2,113.5],
  US:[39,-98], CA:[56,-106], MX:[23,-102], BR:[-10,-55], AR:[-34,-64], CO:[4,-72], CL:[-30,-71],
  PE:[-10,-76], CR:[9.7,-83.7], GB:[54,-2], DE:[51,10], FR:[46,2], ES:[40,-4], PT:[39.5,-8],
  IT:[43,12], NL:[52,5], BE:[50.5,4.5], CH:[47,8], SE:[62,15], NO:[61,9], DK:[56,10], FI:[64,26],
  PL:[52,19], CZ:[49.8,15.5], AT:[47.5,14.5], IE:[53,-8], RU:[61,105], UA:[49,32], TR:[39,35],
  ZA:[-29,24], EG:[26,30], SA:[24,45], AE:[24,54], IL:[31,35], IR:[32,53], NG:[9,8]
};

const REGIONS = {
  world: { lon: null, countries: null },
  in:    { lon: 78,   countries: ["IN"] },
  na:    { lon: -100, countries: ["US","CA","MX"] },
  sa:    { lon: -60,  countries: ["BR","AR","CO","CL","PE","CR"] },
  eu:    { lon: 12,   countries: ["GB","DE","FR","ES","PT","IT","NL","BE","CH","SE","NO","DK","FI","PL","CZ","AT","IE","UA"] },
  me:    { lon: 45,   countries: ["TR","SA","AE","IL","IR","EG"] },
  apac:  { lon: 112,  countries: ["IN","JP","CN","KR","TW","AU","NZ","SG","VN","TH","ID","MY","PH","BD","LK","NP","PK","MM","KH","HK","MO","RU"] }
};

/* ---------------- Actor baseline (curated) ---------------- */
const ACTORS = [
  { name:"Transparent Tribe", aka:"APT36 · Earth Karkaddan", origin:"Pakistan-nexus", motive:"Espionage", p:"P1", conf:"Attributed with high confidence to a Pakistan-nexus threat actor.",
    overview:"Long-running espionage cluster focused on Indian government, defense, and education sectors. Extensive use of Crimson RAT and ElizaRAT delivered via spearphishing and cloned government portals.",
    targets:"Indian military/defense, government, education", ttps:[["T1566.001","Spearphishing attachment"],["T1204.002","User execution"],["T1105","Ingress tool transfer"],["T1071.001","Web protocols C2"]],
    mit:"App & API Protector for portal spoofing/web delivery; Akamai MFA against credential phishing; EAA to reduce exposed access surface." },
  { name:"SideCopy", aka:"—", origin:"Pakistan-nexus", motive:"Espionage", p:"P1", conf:"Assessed with medium-high confidence as Pakistan-nexus; overlaps with Transparent Tribe.",
    overview:"Targets Indian defense, government, Railways, and Oil & Gas entities, mimicking SideWinder TTPs (hence the name); shifted from HTA to MSI staging with reflective DLL loading. 'Operation XENOFISCAL' (mid-2026) extended targeting to Afghanistan's Ministry of Finance via XenoRAT.",
    targets:"Indian defense, government, Railways, Oil & Gas; Afghan MoF (XENOFISCAL)", ttps:[["T1566.002","Spearphishing link"],["T1218.005","Mshta abuse"],["T1036","Masquerading"]],
    mit:"App & API Protector WAF; Client-Side Protection & Compliance for injected script detection; Akamai MFA." },
  { name:"RedEcho", aka:"threat activity group linked to APT41 infra", origin:"China-nexus", motive:"Espionage / Pre-positioning", p:"P1", conf:"Attributed with medium confidence to a China-nexus actor (Recorded Future reporting).",
    overview:"Targeted Indian power sector and critical infrastructure with ShadowPad implants — assessed as strategic pre-positioning rather than immediate disruption.",
    targets:"Indian power grid, ports, critical infrastructure", ttps:[["T1133","External remote services"],["T1071","C2 over app-layer protocols"],["T1105","ShadowPad delivery"]],
    mit:"Guardicore Segmentation to contain lateral movement in OT-adjacent networks; EAA for third-party access; Security Services IR Retainer." },
  { name:"APT41", aka:"Winnti · Wicked Panda · Brass Typhoon", origin:"China-nexus", motive:"Espionage + Financial", p:"P2", conf:"Attributed with high confidence to a China-nexus threat actor.",
    overview:"Dual-mission group conducting state espionage and financially motivated intrusions. Known for software supply-chain compromises, web-facing app exploitation, and web shells across APJ.",
    targets:"Telecom, healthcare, software, gaming across APJ incl. India", ttps:[["T1195.002","Supply chain compromise"],["T1190","Exploit public-facing app"],["T1505.003","Web shell"]],
    mit:"App & API Protector against edge exploitation; Guardicore Segmentation; Client-Side Protection & Compliance for supply-chain script risk." },
  { name:"CL-STA-1062", aka:"UAT-7237", origin:"China-nexus", motive:"Espionage (possible IAB)", p:"P2", conf:"Attributed with high confidence to a China-nexus threat actor; initial-access-broker role assessed with low confidence.",
    overview:"State-sponsored espionage cluster active since at least March 2022. Uses the TinyRCT backdoor, web shells, and credential theft; expanded in 2026 from Taiwan web-hosting infrastructure into Southeast Asian electricity/water utilities and government/military targets via SoftEther VPN and Mimikatz.",
    targets:"Southeast Asian energy infrastructure, government", ttps:[["T1505.003","Web shell"],["T1003","Credential dumping"],["T1190","Exploit public-facing app"]],
    mit:"App & API Protector WAF; Guardicore Segmentation; Akamai MFA; Security Services IR Retainer." },
  { name:"Lazarus Group", aka:"Hidden Cobra · Diamond Sleet", origin:"DPRK", motive:"Financial + Espionage", p:"P2", conf:"Attributed with high confidence to the DPRK.",
    overview:"Prolific DPRK operator: cryptocurrency theft, bank intrusions (incl. 2018 Cosmos Bank ATM cashout in India), supply-chain attacks, and defense-sector espionage across APJ. 2026 watering-hole campaign exploited a South Korean banking-software zero-day (AnySign4PC) via 15 compromised legitimate sites, affecting 70+ organizations.",
    targets:"Financial services, crypto exchanges, defense — APJ-wide incl. India", ttps:[["T1195","Supply chain compromise"],["T1566","Phishing (job-lure)"],["T1621","MFA request abuse"]],
    mit:"Akamai MFA (phish-proof); App & API Protector for exchange/API abuse; Client-Side Protection & Compliance for skimming." },
  { name:"Kimsuky", aka:"Emerald Sleet · APT43", origin:"DPRK", motive:"Espionage", p:"P2", conf:"Attributed with high confidence to the DPRK.",
    overview:"Credential-harvesting and spearphishing specialist targeting think tanks, academia, and government policy circles in Korea, Japan, and wider APJ, incl. India-focused policy targets. 2026 campaign compromised South Korean groupware vendors' mail servers to pivot into customer credentials via new Gomir-family backdoor variants.",
    targets:"Think tanks, academia, government policy — KR/JP/APJ", ttps:[["T1598.003","Credential-harvest spearphishing"],["T1078","Valid accounts"],["T1114","Email collection"]],
    mit:"Akamai MFA; EAA for identity-aware access; App & API Protector." },
  { name:"Mustang Panda", aka:"Earth Preta · Stately Taurus", origin:"China-nexus", motive:"Espionage", p:"P2", conf:"Attributed with high confidence to a China-nexus threat actor.",
    overview:"Espionage operator heavily active against Southeast Asian governments; signature PlugX/Korplug delivery via phishing and infected USB media.",
    targets:"SEA governments, NGOs, shipping", ttps:[["T1566.002","Spearphishing link"],["T1091","Removable media replication"],["T1574.002","DLL side-loading"]],
    mit:"Guardicore Segmentation; EAA; App & API Protector." },
  { name:"Mysterious Team Bangladesh", aka:"MTB", origin:"Bangladesh (hacktivist)", motive:"Ideological — DDoS", p:"P1", conf:"Self-attributed hacktivist collective; claims assessed with medium confidence.",
    overview:"Hacktivist DDoS collective repeatedly targeting Indian government, financial, and airline web properties with Layer 7 floods and defacements, typically announced on Telegram.",
    targets:"Indian gov portals, BFSI, aviation", ttps:[["T1498","Network DoS"],["T1499.004","Application-layer DoS"],["T1491","Defacement"]],
    mit:"App & API Protector + rate controls for L7 floods; Prolexic-class network-layer defense; bot visibility." },
  { name:"NoName057(16)", aka:"—", origin:"Russia-aligned (hacktivist)", motive:"Ideological — DDoS", p:"P2", conf:"Self-attributed pro-Russia collective; high confidence in DDoS activity, low in membership claims.",
    overview:"Crowdsourced 'DDoSia' Layer 7 attack platform; the single most prolific hacktivist DDoS brand by claim volume, generating an estimated 40.5% of all recorded hacktivist DDoS claims in H1 2026. Primarily targets Europe (incl. a Feb 2026 campaign against Italian government sites tied to the Milano Cortina Winter Olympics) but launched a sustained #OpJapan campaign in Aug 2026 against Japanese transport, government, shipping, insurance, and media targets — a useful bellwether for hacktivist DDoS tradecraft reaching APJ.",
    targets:"Government, transport, BFSI web properties", ttps:[["T1498.002","Reflection amplification"],["T1499.004","Application-layer DoS"]],
    mit:"App & API Protector; edge rate controls; upstream network-layer scrubbing." },
  { name:"Keymous+", aka:"EliteStress (affiliated DDoS-for-hire platform)", origin:"Self-described North Africa-based; DDoS-as-a-service", motive:"Ideological (claimed) / commercial DDoS-for-hire", p:"P1", conf:"Self-attributed hacktivist brand; analysts assess a dual hacktivist/commercial-DaaS identity with medium confidence — claimed attack volumes are largely self-reported and unverified.",
    overview:"Emerged 2023, ramping sharply through 2025 with 700+ claimed DDoS attacks (249 independently confirmed). Became the most aggressive DDoS actor against Indian public healthcare during the 2025-26 India-Pakistan tension period, repeatedly flooding AIIMS and Safdarjung Hospital web infrastructure; no confirmed data breach.",
    targets:"Indian government and public healthcare portals (AIIMS, Safdarjung); opportunistic global targeting", ttps:[["T1498","Network DoS"],["T1499.004","Application-layer DoS"],["T1583.005","Botnet / DDoS-for-hire infrastructure"]],
    mit:"App & API Protector + rate controls for L7 floods; Prolexic-class network-layer defense; bot visibility." },
  { name:"RuskiNet", aka:"—", origin:"Russia-aligned hacktivist (Eastern Europe)", motive:"Ideological — geopolitical", p:"P2", conf:"Self-attributed pro-Russia hacktivist collective; not yet assessed as state-linked. Confidence in claimed scale/impact is low.",
    overview:"Blends DDoS, data leaks, and phishing against government and critical-infrastructure targets, opportunistically tying campaigns (incl. 'Operation Trinetara') to geopolitical flashpoints. India named among its targets alongside the US, Canada, Israel, UK, and Turkey; activity trend assessed as declining since mid-2026.",
    targets:"Government and critical infrastructure — US, Canada, Israel, UK, Turkey, India", ttps:[["T1498","Network DoS"],["T1566","Phishing"],["T1567","Exfiltration over web services"]],
    mit:"App & API Protector + rate controls; Akamai MFA against credential phishing; Guardicore Segmentation." }
];
const ACTOR_META = {
  "Transparent Tribe": ["2026-07-11"], "SideCopy": ["2026-06-30"], "RedEcho": ["2025-11-15"],
  "APT41": ["2026-06-10"], "CL-STA-1062": ["2026-07-15"], "Lazarus Group": ["2026-07-30"],
  "Kimsuky": ["2026-07-24"], "Mustang Panda": ["2026-05-28"], "Mysterious Team Bangladesh": ["2026-04-10"],
  "NoName057(16)": ["2026-08-20"], "Keymous+": ["2026-05-15"], "RuskiNet": ["2026-03-01"]
};
const GLOBAL_ACTORS = [
  { name:"Qilin", aka:"Agenda", origin:"Russia-aligned RaaS", motive:"Ransomware", p:"P2", region:"global", last:"2026-08-10",
    conf:"RaaS operation; affiliate attribution varies. Assessed with high confidence as the dominant ransomware brand by victim volume.",
    overview:"Ransomware-as-a-service operation leading leak-site victim counts (2,100+ claimed victims) amid ecosystem consolidation. Strong Linux/ESXi capability; actively exploiting Palo Alto PAN-OS auth-bypass flaws for initial access; recurring Indian victims.",
    targets:"Cross-sector, global — recurring Indian victims", ttps:[["T1486","Data encrypted for impact"],["T1567","Exfiltration over web services"],["T1078","Valid accounts"]],
    mit:"Guardicore Segmentation to limit blast radius; Akamai MFA against affiliate credential access; Security Services IR Retainer." },
  { name:"DragonForce", aka:"—", origin:"RaaS cartel", motive:"Ransomware", p:"P2", region:"global", last:"2026-07-14",
    conf:"Self-styled ransomware 'cartel'; affiliate structure assessed with medium confidence.",
    overview:"Aggressive RaaS/cartel model absorbing affiliates from disrupted brands. Active APJ + Indian manufacturing claims.",
    targets:"Cross-sector, global + APJ incl. India", ttps:[["T1486","Data encrypted for impact"],["T1133","External remote services"],["T1567.002","Exfil to cloud storage"]],
    mit:"Guardicore Segmentation; EAA to replace exposed remote access; IR Retainer." },
  { name:"Cl0p", aka:"TA505-linked", origin:"Russia-nexus eCrime", motive:"Extortion (mass exploitation)", p:"P2", region:"global", last:"2026-07-20",
    conf:"Attributed with high confidence to a Russia-nexus eCrime group.",
    overview:"Specialist in mass exploitation of managed file transfer and enterprise software zero-days (MOVEit, Oracle EBS, and a 2026 PTC Windchill/FlexPLM RCE campaign claiming 1,200+ victims across 54 countries) rather than individual intrusions — cumulative claimed victim count has passed 1,190 since the group's Aug 2020 emergence. Claimed Indian healthcare victims.",
    targets:"Enterprises via file-transfer/ERP zero-days — global incl. India", ttps:[["T1190","Exploit public-facing application"],["T1567","Exfiltration over web services"]],
    mit:"App & API Protector WAF with rapid virtual-patch rules on MFT/ERP CVEs; Guardicore Segmentation." },
  { name:"Scattered Spider", aka:"UNC3944 · Octo Tempest", origin:"eCrime (native-English)", motive:"Extortion", p:"P1", region:"global", last:"2026-07-02",
    conf:"High confidence in TTP cluster; loose membership (The Com) complicates attribution.",
    overview:"Social-engineering-led intrusions: helpdesk impersonation, MFA-reset abuse, SIM swap, then SaaS data theft and ESXi ransomware deployment with RaaS partners. Core UK/US members have faced arrests, extraditions, and guilty pleas through mid-2026 (incl. the TfL breach), though the loose 'The Com' membership model limits disruption impact.",
    targets:"Retail, insurance, aviation, SaaS-heavy enterprises", ttps:[["T1656","Impersonation (helpdesk)"],["T1621","MFA request generation"],["T1078.004","Cloud accounts"]],
    mit:"Akamai MFA (phish-proof FIDO2); EAA identity-aware access; helpdesk verification playbooks + IR Retainer." },
  { name:"ShinyHunters", aka:"UNC6040 overlap", origin:"eCrime collective", motive:"Data-theft extortion", p:"P1", region:"global", last:"2026-07-14",
    conf:"Cluster overlaps with Scattered Spider ecosystem; assessed with medium confidence.",
    overview:"Large-scale SaaS data-theft extortion via vishing, malicious connected apps, and OAuth token abuse; 2026 activity includes Oracle PeopleSoft PeopleTools zero-day exploitation and growing ecosystem overlap with Scattered Spider and Lapsus$ (tracked by some vendors as 'SLSH').",
    targets:"Salesforce/SaaS tenants of global enterprises", ttps:[["T1566.004","Voice phishing"],["T1528","Steal application access tokens"],["T1530","Data from cloud storage"]],
    mit:"Akamai MFA; Client-Side Protection & Compliance; SaaS OAuth-app governance." },
  { name:"Sandworm", aka:"APT44 · Seashell Blizzard", origin:"Russia (GRU)", motive:"Espionage + Disruption", p:"P1", region:"global", last:"2026-07-13",
    conf:"Attributed with high confidence to Russia's GRU.",
    overview:"Destructive and espionage operations against critical infrastructure; known for exploiting vulnerable and misconfigured edge routers.",
    targets:"Critical infrastructure, energy, government — primarily Europe/US, tradecraft globally relevant", ttps:[["T1190","Exploit public-facing application"],["T1542","Pre-OS/router implants"],["T1485","Data destruction"]],
    mit:"Guardicore Segmentation; hardened edge via App & API Protector; DNS posture review." },
  { name:"Salt Typhoon", aka:"Earth Estries · GhostEmperor overlap", origin:"China-nexus", motive:"Espionage", p:"P2", region:"global", last:"2026-05-15",
    conf:"Attributed with high confidence to a China-nexus threat actor.",
    overview:"Telecom-focused espionage penetrating carrier core networks and lawful-intercept systems across multiple countries, including APJ operators (Singapore's four national carriers confirmed compromised, per Feb 2026 national assessments). Suspected — not formally confirmed — in a Feb 2026 breach of the FBI's DCSNet wiretap system.",
    targets:"Telecom carriers and ISPs, global incl. APJ", ttps:[["T1190","Exploit public-facing application"],["T1078","Valid accounts"],["T1020","Automated exfiltration"]],
    mit:"Guardicore Segmentation of management planes; EAA for vendor access; App & API Protector." },
  { name:"TheGentlemen", aka:"—", origin:"eCrime (RaaS)", motive:"Ransomware", p:"P1", region:"global", last:"2026-08-10",
    conf:"Emerging group; assessed with medium confidence as an affiliate-driven RaaS with deliberate India targeting.",
    overview:"Newer leak-site operation (emerged Aug 2025 from a former Qilin affiliate), now the #2 most prolific ransomware brand globally by published victim count, with a striking India concentration across healthcare, manufacturing, and education victims spanning 60+ countries.",
    targets:"Indian healthcare, manufacturing, education; wider Asia", ttps:[["T1486","Data encrypted for impact"],["T1490","Inhibit system recovery"]],
    mit:"Guardicore Segmentation; Akamai MFA; Security Services IR Retainer; leak-site monitoring." }
];
/* ---------------- Top 10 rankings (curated, self-reported/leak-site claim volumes — not confirmed breach counts) ---------------- */
const RANSOMWARE_RANK = [
  { name:"Qilin", stat:"~1,300–2,100+ claimed victims all-time (source-dependent); 50+ countries", note:"Dominant RaaS brand by leak-site volume through most of 2026; recurring Indian victims." },
  { name:"Akira", stat:"1,400+ claimed victims all-time; $245M+ ransom collected", note:"Consistently top-2–3 on the leaderboard; strong Linux/ESXi capability." },
  { name:"Cl0p", stat:"1,190+ claimed victims since Aug 2020", note:"Mass-exploitation model (MOVEit, Oracle EBS, 2026 PTC Windchill/FlexPLM — 1,200+ victims/54 countries in that campaign alone) rather than individual intrusions." },
  { name:"TheGentlemen", stat:"~300 claimed victims across 66+ countries since Aug 2025", note:"Fastest-growing brand of 2026; by some trackers overtook Qilin for #1 activity by June 2026. Pronounced India concentration (healthcare, manufacturing, education)." },
  { name:"Play", stat:"~900+ claimed victims all-time", note:"Steady top-10 mainstay; exploits public-facing app and RDP/VPN access." },
  { name:"RansomHub", stat:"~840+ claimed victims all-time", note:"Rapid 2024–25 riser via ex-ALPHV/LockBit affiliates; activity reported thinning after the 2025 DragonForce/Scattered Spider affiliate dispute." },
  { name:"DragonForce", stat:"590+ claimed victims all-time", note:"RaaS 'cartel' model absorbing affiliates from disrupted brands; active APJ and Indian manufacturing claims." },
  { name:"SafePay", stat:"~570 claimed victims all-time", note:"SMB-heavy victim profile across almost any sector." },
  { name:"Medusa", stat:"~520 claimed victims since Feb 2023", note:"MedusaLocker-lineage RaaS; double-extortion with countdown leak timers." },
  { name:"INC Ransom", stat:"65 claimed victims in 2026 YTD (through Jul 2026)", note:"Smaller volume but a consistent top-5 2026 entrant by monthly claim rate." }
];
const DDOS_RANK = [
  { name:"NoName057(16)", stat:"~40.5% of all hacktivist DDoS claims, H1 2026", note:"Pro-Russia; crowdsourced 'DDoSia' L7 platform. Aug 2026 #OpJapan campaign vs transport/gov/shipping/insurance/media targets." },
  { name:"Keymous+", stat:"700+ claimed attacks since 2023 (249 independently confirmed); ~26.8% of global claims in the Feb–Mar 2026 surge window", note:"North Africa-based hacktivist/DDoS-for-hire hybrid; most aggressive actor vs Indian public healthcare (AIIMS, Safdarjung) in 2025–26." },
  { name:"DieNet", stat:"Paired with Keymous+ for ~70% of a 149-attack / 110-org / 16-country surge (late Feb 2026)", note:"Frequent joint campaigns with Keymous+ around geopolitical flashpoints." },
  { name:"Mysterious Team Bangladesh", stat:"Repeated L7 floods + defacements, Telegram-announced", note:"Consistent claims vs Indian gov portals, BFSI, and aviation web properties." },
  { name:"RuskiNet", stat:"Multi-country 'Operation Trinetara' claims (India, US, Canada, Israel, UK, Turkey)", note:"Pro-Russia hacktivist; activity trend assessed as declining since mid-2026." },
  { name:"ServerKillers", stat:"Joint campaigns with NoName057(16) vs Spain/EU government sites (Jan–Feb 2026)", note:"Frequent NoName057(16) coalition partner in DDoSia-linked operations." },
  { name:"Dark Storm Team", stat:"High-profile platform/service-outage claims", note:"Pro-Palestinian hacktivist brand; claims frequently disputed/unverified by targets." },
  { name:"Z-Pentest", stat:"OT/ICS-focused claims vs water and energy SCADA systems", note:"Part of the pro-Russia hacktivist cluster targeting critical infrastructure HMIs." },
  { name:"CyberArmyofRussia_Reborn (CARR)", stat:"Recurring claims vs water/energy control systems", note:"Overlaps with Sandworm-adjacent tradecraft narratives; claims not independently confirmed." },
  { name:"Arabian Ghosts", stat:"Part of the 12-group cluster behind 74.6% of a 149-attack Middle-East-conflict surge", note:"Regional hacktivist collective, Middle East-conflict-driven claims." }
];
function renderRankings(){
  const rEl = $("#rank-ransomware"), dEl = $("#rank-ddos");
  const rowHtml = (g, i) =>
    '<div class="claimrank-row" title="' + esc(g.note) + '"><span class="rank-n">' + (i+1) + "</span>" +
    '<span class="rank-body"><span class="rank-label">' + esc(g.name) + "</span>" +
    '<span class="rank-count">' + esc(g.stat) + "</span></span></div>";
  if (rEl) rEl.innerHTML = RANSOMWARE_RANK.map(rowHtml).join("");
  if (dEl) dEl.innerHTML = DDOS_RANK.map(rowHtml).join("");
}
function mergedActors(){
  return ACTORS.map(a => Object.assign({}, a, { region: "apj", last: (ACTOR_META[a.name] || ["2025-01-01"])[0] }))
    .concat(GLOBAL_ACTORS)
    .sort((a,b) => String(b.last).localeCompare(String(a.last)));
}

/* ---------------- State ---------------- */
let allItems = [];
let rwVictims = [];
let telegramItems = [];
let rwNewsItems = [];
let vulnItems = [];
let iocItems = [];
let DATA = { generated: null, vulnGenerated: null, infocon: "green", items: [], victims: [], telegram: [], ransomwareNews: [], iocs: [], vulnerabilities: [], ddosTelemetry: null, sourceStatus: {} };
let rwFilter = localStorage.getItem("apjti.rwFilter") || "apj";
let tgFilter = localStorage.getItem("apjti.tgFilter") || "all";
let sectorFilter = localStorage.getItem("apjti.sectorFilter") || "all";
let rangeDays = parseInt(localStorage.getItem("apjti.range") || "30", 10);
let actorFilter = localStorage.getItem("apjti.actorFilter") || "all";
let vulnFilter = localStorage.getItem("apjti.vulnFilter") || "all";
let vulnSearch = "";
let iocFilter = localStorage.getItem("apjti.iocFilter") || "all";
let iocTypeFilter = localStorage.getItem("apjti.iocTypeFilter") || "all";
let iocSearch = "";
let currentRegion = localStorage.getItem("apjti.region") || "world";
let CURRENT_ACTORS = [];

/* ---------------- Tab navigation (one section visible at a time) ---------------- */
const TAB_IDS = ["brief", "ransomware", "vulnerabilities", "telegram", "actors", "map", "iocs"];
let activeTab = "brief";
function showTab(id, opts){
  if (!TAB_IDS.includes(id)) id = "brief";
  activeTab = id;
  localStorage.setItem("apjti.tab", id);
  TAB_IDS.forEach(t => {
    const sec = document.getElementById(t);
    if (!sec) return;
    if (t === id){
      sec.hidden = false;
      sec.classList.remove("tab-enter");
      void sec.offsetWidth; // reflow so the enter animation restarts on repeat visits
      sec.classList.add("tab-enter");
    } else {
      sec.hidden = true;
    }
  });
  document.querySelectorAll(".nav-links a[href^='#']").forEach(a => {
    if (a.getAttribute("href").slice(1) === id) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  if (!(opts && opts.skipHash)) history.replaceState(null, "", "#" + id);
  if (id === "map"){
    // Chart.js sized these canvases while their container was display:none (0×0) on first load —
    // recompute now that the section actually has layout dimensions.
    [chartTrendInst, chartGroupsInst, chartSectorsInst].forEach(c => c && c.resize());
    if (typeof startMapLoop === "function" && typeof rwVictims !== "undefined" && rwVictims.length) startMapLoop();
  }
  // Header bits that only mean something on some tabs (e.g. the Brief's tagline and Markdown
  // export) carry data-only-tabs="brief ..." and are hidden everywhere else.
  document.querySelectorAll("[data-only-tabs]").forEach(el => { el.hidden = !el.dataset.onlyTabs.split(/\s+/).includes(id); });
  if (id === "actors") loadApt();
  document.body.classList.toggle("map-mode", id === "map");
  syncThemeToggle();
}
function wireTabs(){
  document.querySelectorAll(".nav-links a[href^='#']").forEach(a => {
    const id = a.getAttribute("href").slice(1);
    if (!TAB_IDS.includes(id)) return;
    a.addEventListener("click", e => { e.preventDefault(); showTab(id); });
  });
  window.addEventListener("hashchange", () => {
    const id = location.hash.slice(1);
    if (TAB_IDS.includes(id) && id !== activeTab) showTab(id, { skipHash: true });
  });
}

// Every caller treats the result as "the most recent real-world timestamp we have data for" and
// anchors a trend chart or a rolling window to it — a single future-dated item (e.g. a feed's
// [Virtual Event] listing whose pubDate is the event date, not a publish date) would otherwise drag
// the whole window into the future, past every item that actually has real data, making a chart look
// broken/flat rather than just skipping that one bad item. Clamped to "now" (+1 day of clock skew)
// as a defensive backstop; worker.js's parseItems() also rejects future dates at the source.
function maxDate(dates){
  const cap = Date.now() + 86400000;
  let m = null;
  for (const d of dates){ const t = d instanceof Date ? d : new Date(d); if (!isNaN(t) && t.getTime() <= cap && (!m || t > m)) m = t; }
  return m;
}
function inWindow(d, anchorMs){ return !d || (d instanceof Date ? d.getTime() : new Date(d).getTime()) >= (anchorMs - rangeDays * 86400000); }

/* ---------------- Helpers ---------------- */
const $ = s => document.querySelector(s);
function esc(s){ return String(s||"").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function showError(msg){
  const el = $("#err-banner");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
}
function regionTagClass(isIndia, isApj){ return isIndia ? "tag-accent" : (isApj ? "tag-outline" : "tag-neutral"); }
// ransomware.live partially redacts some victim names (e.g. "vi***in") — commonly done for an
// ongoing negotiation or a legal request on their end, not a data quality issue on ours. Flagged
// wherever a victim name renders, so it doesn't read as broken data.
function victimNameHtml(name){
  return /\*/.test(name)
    ? '<span title="Victim name partially redacted by the source (ransomware.live) — commonly done for an ongoing negotiation or a legal request, not a data error.">' + esc(name) + "</span>"
    : esc(name);
}

/* ---------------- Data loading ---------------- */
async function loadData(){
  const res = await fetch("/api/data");
  if (!res.ok) throw new Error("HTTP " + res.status);
  const json = await res.json();
  DATA = json;
  allItems = (json.items || []).map(i => Object.assign({}, i, { date: i.date ? new Date(i.date) : null }));
  rwVictims = (json.victims || []).slice().sort((a,b) => (b.cc==="IN")-(a.cc==="IN") || (b.apj-a.apj) || String(b.date||"").localeCompare(String(a.date||"")));
  telegramItems = (json.telegram || []).map(i => Object.assign({}, i, { date: i.date ? new Date(i.date) : null }));
  rwNewsItems = (json.ransomwareNews || []).map(i => Object.assign({}, i, { date: i.date ? new Date(i.date) : null }));
  vulnItems = (json.vulnerabilities || []).map(i => Object.assign({}, i, { date: i.date ? new Date(i.date) : null }));
  iocItems = (json.iocs || []).map(i => Object.assign({}, i, { firstSeen: i.firstSeen ? new Date(i.firstSeen) : null }));

  const statusEntries = Object.entries(json.sourceStatus || {});
  $("#srcbar").innerHTML = statusEntries.map(([name, s]) =>
    '<span class="srcpill ' + (s.ok ? "ok" : "fail") + '">' + esc(name) + " · " + (s.ok ? s.count + " items" : "unavailable") + "</span>"
  ).join("") + '<span class="srcpill ' + (rwVictims.length ? "ok" : "fail") + '">ransomware.live · ' + rwVictims.length + " claims</span>";
  const okCount = statusEntries.filter(([,s]) => s.ok).length + (rwVictims.length ? 1 : 0);
  const totalCount = statusEntries.length + 1;
  const srcSummary = $("#srcsummary");
  if (srcSummary) srcSummary.textContent = "Source health · " + okCount + "/" + totalCount + " ok";

  if (json.note) showError(json.note);
  else $("#err-banner").classList.remove("show");

  $("#lastload").textContent = json.generated
    ? "data as of " + new Date(json.generated).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) + " · " + APP_VERSION
    : "no data yet · " + APP_VERSION;

  const footAbusech = $("#foot-abusech");
  if (footAbusech) footAbusech.textContent = statusEntries.some(([name]) => name.startsWith("abuse.ch")) ? ", URLhaus, ThreatFox, MalwareBazaar" : "";
  const footRadar = $("#foot-radar");
  if (footRadar) footRadar.textContent = statusEntries.some(([name]) => name === "Cloudflare Radar") ? ", Cloudflare Radar" : "";
}

function fmtDate(d){ if (!d) return ""; return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }); }

/* ---------------- Rendering: ransomware panel ---------------- */
function populateSectorFilter(){
  const sel = $("#sector-filter");
  if (!sel) return;
  const sectors = [...new Set(rwVictims.map(v => v.sector).filter(Boolean))].sort();
  if (!sectors.includes(sectorFilter) && sectorFilter !== "all") sectorFilter = "all";
  sel.innerHTML = '<option value="all">All industries</option>' +
    sectors.map(s => '<option value="' + esc(s) + '"' + (s === sectorFilter ? " selected" : "") + ">" + esc(s) + "</option>").join("");
  sel.value = sectorFilter;
}
function renderRw(){
  const el = $("#rw");
  populateSectorFilter();
  document.querySelectorAll("[data-rwf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.rwf === rwFilter)));
  const oldestIn = rwVictims.filter(v => v.cc === "IN" && v.date).reduce((m,v) => (!m || v.date < m) ? v.date : m, "");
  $("#rw-cov").textContent = rwVictims.length
    ? "Coverage: " + rwVictims.length + " cached claims" + (oldestIn ? ", oldest India claim from " + String(oldestIn).slice(0,10) : "") + ". Archive grows with every collection cycle."
    : "";
  let list = rwVictims;
  if (rwFilter === "apj") list = list.filter(v => v.apj);
  else if (rwFilter === "global") list = list.filter(v => !v.apj);
  if (sectorFilter !== "all") list = list.filter(v => v.sector === sectorFilter);
  const rwAnchor = maxDate(rwVictims.map(v => v.date));
  if (rwAnchor) list = list.filter(v => inWindow(v.date, rwAnchor.getTime()));
  if (!list.length){
    el.innerHTML = '<tr><td colspan="6" class="empty">No ' + (rwFilter === "apj" ? "APJ-country" : rwFilter) + ' victims in the last ' + rangeDays + ' days — widen the time window or switch scope.</td></tr>';
    return;
  }
  el.innerHTML = list.slice(0, 30).map(v =>
    "<tr>" +
      '<td data-label="Organization">' + victimNameHtml(v.victim) + "</td>" +
      '<td data-label="Sector" class="text-muted">' + esc(v.sector || "—") + "</td>" +
      '<td data-label="Group">' + esc(v.group) + "</td>" +
      '<td data-label="Region"><span class="tag ' + regionTagClass(v.cc === "IN", v.apj) + '">' + esc(v.cc === "IN" ? "India" : v.country) + "</span></td>" +
      '<td data-label="Claimed" class="text-muted">' + (v.date ? esc(String(v.date).slice(0,10)) : "—") + "</td>" +
      '<td data-label="Status"><span class="tag tag-outline">Claimed</span></td>' +
    "</tr>"
  ).join("");
}

/* ---------------- Rendering: ransomware community/social signal (Mastodon) ---------------- */
function renderRansomwareNews(){
  const el = $("#rw-news-list");
  if (!el) return;
  const anchor = maxDate(rwNewsItems.map(i => i.date));
  let items = anchor ? rwNewsItems.filter(i => inWindow(i.date, anchor.getTime())) : rwNewsItems.slice();
  items.sort((a,b) => (b.date ? b.date.getTime() : 0) - (a.date ? a.date.getTime() : 0));
  if (!items.length){
    el.innerHTML = '<div class="empty">No community posts in the last ' + rangeDays + ' days.</div>';
    return;
  }
  el.innerHTML = items.slice(0, 20).map(i =>
    '<div class="card blueprint elev-sm feed-card">' +
      '<i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>' +
      '<div class="feed-card-tags">' +
        '<span class="tag tag-neutral">' + esc(i.src) + "</span>" +
        (i.india || i.apj ? '<span class="tag ' + regionTagClass(i.india, i.apj) + '">' + (i.india ? "India P1" : "APJ") + "</span>" : "") +
      "</div>" +
      '<div class="card-title"><a href="' + esc(i.link) + '" target="_blank" rel="noopener">' + esc(i.title) + "</a></div>" +
      (i.desc && i.desc !== i.title ? '<p class="card-body">' + esc(i.desc) + "</p>" : "") +
      '<div class="card-meta"><span>' + (i.date ? fmtDate(i.date) : "") + "</span></div>" +
    "</div>"
  ).join("");
}

/* ---------------- Rendering: Telegram bot feed ---------------- */
function visibleTelegram(){
  let items = telegramItems.slice();
  if (tgFilter === "claims") items = items.filter(i => i.claim);
  else if (tgFilter !== "all") items = items.filter(i => i.channel === tgFilter);
  const anchor = maxDate(telegramItems.map(i => i.date));
  if (anchor) items = items.filter(i => inWindow(i.date, anchor.getTime()));
  items.sort((a,b) => (b.date ? b.date.getTime() : 0) - (a.date ? a.date.getTime() : 0));
  return items;
}
function renderTelegram(){
  const el = $("#telegram-list");
  if (!el) return;
  document.querySelectorAll("[data-tgf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.tgf === tgFilter)));
  const channels = new Set(telegramItems.map(i => i.channel));
  $("#telegram-cov").textContent = telegramItems.length
    ? "Coverage: " + telegramItems.length + " posts across " + channels.size + " channel(s). Unmoderated public Telegram channels — treat as claimed, not confirmed."
    : "";
  const items = visibleTelegram();
  if (!items.length){
    el.innerHTML = '<div class="empty">No Telegram posts match this view in the last ' + rangeDays + ' days.</div>';
    return;
  }
  el.innerHTML = items.map(i =>
    '<div class="card blueprint elev-sm feed-card">' +
      '<i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>' +
      '<div class="feed-card-tags">' +
        '<span class="tag tag-neutral">' + esc(i.channel) + "</span>" +
        (i.india || i.apj ? '<span class="tag ' + regionTagClass(i.india, i.apj) + '">' + (i.india ? "India P1" : "APJ") + "</span>" : "") +
        (i.lens ? '<span class="tag tag-neutral">DDoS · AppSec</span>' : "") +
        (i.claim ? '<span class="tag tag-accent">Actor claim</span>' : "") +
      "</div>" +
      '<div class="card-title"><a href="' + esc(i.link) + '" target="_blank" rel="noopener">' + esc(i.title) + "</a></div>" +
      (i.desc ? '<p class="card-body">' + esc(i.desc) + "</p>" : "") +
      '<div class="card-meta"><span>' + esc(i.src) + (i.date ? " · " + fmtDate(i.date) : "") + "</span>" +
        (i.tgLink && i.tgLink !== i.link ? ' <a href="' + esc(i.tgLink) + '" target="_blank" rel="noopener">View on Telegram</a>' : "") +
      "</div>" +
    "</div>"
  ).join("");
}

/* ---------------- Rendering: actor tracker ---------------- */
function fmtLast(d){
  const dt = new Date(d + "T12:00:00Z");
  return isNaN(dt) ? d : dt.toLocaleDateString(undefined, { month: "short", year: "numeric" });
}
function originFlag(origin){
  const o = String(origin || "").toLowerCase();
  if (o.includes("pakistan")) return "🇵🇰";
  if (o.includes("china")) return "🇨🇳";
  if (o.includes("dprk") || o.includes("korea")) return "🇰🇵";
  if (o.includes("russia")) return "🇷🇺";
  if (o.includes("bangladesh")) return "🇧🇩";
  return "🌐";
}
function renderActors(){
  let list = mergedActors();
  if (actorFilter === "apj") list = list.filter(a => a.region === "apj");
  else if (actorFilter === "global") list = list.filter(a => a.region === "global");
  document.querySelectorAll("[data-af]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.af === actorFilter)));
  CURRENT_ACTORS = list;
  $("#actors-list").innerHTML = list.map((a, idx) =>
    '<div class="card blueprint elev-sm actor-card" data-i="' + idx + '">' +
      '<i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>' +
      '<div class="actor-hd">' +
        "<div><div class=\"card-title\">" + esc(a.name) + '</div><div class="aka">' + esc(a.aka) + "</div></div>" +
        '<span class="tag ' + (a.region === "global" ? "tag-neutral" : (a.p === "P1" ? "tag-accent" : "tag-outline")) + '">' + (a.region === "global" ? "Global" : (a.p || "APJ")) + "</span>" +
      "</div>" +
      '<div class="actor-tags">' +
        '<span class="tag tag-neutral">⏱ ' + fmtLast(a.last) + "</span>" +
        '<span class="tag tag-neutral">' + originFlag(a.origin) + " " + esc(a.origin) + "</span>" +
        '<span class="tag tag-neutral">' + esc(a.motive) + "</span>" +
      "</div>" +
      '<div class="card-meta">' + esc(a.overview) + "</div>" +
      '<div class="det">' +
        '<div class="row"><span class="lbl">Targets</span><br>' + esc(a.targets) + "</div>" +
        '<div class="row"><span class="lbl">Key TTPs (MITRE ATT&amp;CK)</span><br>' +
          a.ttps.map(t => '<span class="ttp" title="' + esc(t[1]) + '">' + esc(t[0]) + "</span> " + esc(t[1])).join("<br>") +
        "</div>" +
        '<div class="row"><span class="lbl">Mitigation</span><br>' + esc(a.mit) + "</div>" +
        aptCuratedRow(a) +
        '<div class="conf">' + esc(a.conf) + "</div>" +
      "</div>" +
    "</div>"
  ).join("");
  renderTopTtps();
  renderRankings();
}

/* ---------------- Actors: APT Groups & Operations community sheet (/api/actors) ---------------- */
// Loaded lazily the first time the Actors tab opens (~200KB, changes at most daily), not with
// /api/data. Also enriches the curated cards above with each group's vendor names from the sheet.
let aptGroups = null, aptChanges = [], aptMeta = null, aptBaseline = null, aptIndex = new Map(), aptLoading = false;
let aptFilter = localStorage.getItem("apjti.aptFilter") || "apj";
let aptTab = localStorage.getItem("apjti.aptTab") || "all";
let aptSearch = "", aptOpen = null;
const APT_ROW_CAP = 150;
async function loadApt(){
  if (aptGroups || aptLoading) return;
  aptLoading = true;
  try {
    const r = await fetch("/api/actors");
    if (!r.ok) throw new Error("HTTP " + r.status);
    const j = await r.json();
    const d = j.data || {};
    aptMeta = j.meta;
    aptBaseline = d.baselineAt || null;
    aptChanges = d.changes || [];
    aptGroups = (d.groups || []).map(g => Object.assign(g, {
      _hay: [g.name, g.label, g.mitre, g.malware, ...(g.aliases || []).map(a => a.n), ...(g.ops || [])].filter(Boolean).join(" ").toLowerCase()
    }));
    aptGroups.forEach(g => [g.name, ...(g.aliases || []).map(a => a.n)].forEach(n => {
      const k = n.toLowerCase(); if (!aptIndex.has(k)) aptIndex.set(k, g);
    }));
  } catch (e){
    aptGroups = [];
    aptMeta = { status: { ok: false, error: "could not load /api/actors (" + e.message + ")" } };
  }
  aptLoading = false;
  populateAptTabs();
  renderApt();
  renderActors(); // re-render curated cards now that sheet aliases are available
}
// Curated profile → sheet group, via its name or any "aka" token ("APT36 · Earth Karkaddan").
function aptMatch(a){
  if (!aptIndex.size) return null;
  const names = [a.name, ...String(a.aka || "").split(/[·,\/]/)].map(s => s.trim().toLowerCase()).filter(s => s && s !== "—");
  for (const n of names){ const g = aptIndex.get(n); if (g) return g; }
  return null;
}
function aptAliasText(g, max){
  const al = g.aliases || [];
  return al.slice(0, max).map(a => a.v ? a.n + " (" + a.v + ")" : a.n).join(", ") + (al.length > max ? " +" + (al.length - max) + " more" : "");
}
function aptMitreLink(id){
  return id ? '<a href="https://attack.mitre.org/groups/' + esc(id) + '/" target="_blank" rel="noopener">' + esc(id) + "</a>" : "—";
}
function aptLinksHtml(links, max){
  return (links || []).slice(0, max).map(u => {
    let host = u; try { host = new URL(u).hostname.replace(/^www\./, ""); } catch (_){}
    return '<a href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(host) + "</a>";
  }).join(" · ");
}
function aptCuratedRow(a){
  const g = aptMatch(a);
  if (!g) return "";
  // Say which sheet row this is when its name differs (e.g. the sheet files RedEcho under Winnti
  // Group) — that mapping is the sheet's attribution call, not this profile's.
  const same = g.name.toLowerCase() === a.name.toLowerCase();
  return '<div class="row"><span class="lbl">Vendor names · community sheet</span><br>' +
    (same ? "" : '<span class="text-muted">Sheet lists this under</span> <b>' + esc(g.name) + "</b> — ") + esc(aptAliasText(g, 10) || "—") +
    (g.mitre ? " · MITRE " + aptMitreLink(g.mitre) : "") +
    (g.links && g.links.length ? '<br><span class="text-muted">Sources:</span> ' + aptLinksHtml(g.links, 3) : "") + "</div>";
}
function populateAptTabs(){
  const sel = $("#apt-tab-filter");
  if (!sel || !aptGroups) return;
  const tabs = [...new Set(aptGroups.map(g => g.tab))];
  if (aptTab !== "all" && !tabs.includes(aptTab)) aptTab = "all";
  sel.innerHTML = '<option value="all">All countries</option>' + tabs.map(t => '<option value="' + esc(t) + '">' + esc(t) + "</option>").join("");
  sel.value = aptTab;
}
function visibleApt(){
  let list = aptGroups || [];
  // A search looks across every group — "Fancy Bear" shouldn't come back empty just because the
  // India / APJ toggle is on. The country-tab filter still applies.
  if (aptSearch) list = list.filter(g => g._hay.includes(aptSearch));
  else if (aptFilter === "apj") list = list.filter(g => g.apj || g.india);
  if (aptTab !== "all") list = list.filter(g => g.tab === aptTab);
  return list.slice().sort((a, b) => (!!b.india - !!a.india) || (a.label || a.name).localeCompare(b.label || b.name));
}
function fmtDay(iso){ return iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "—"; }
function renderApt(){
  const el = $("#apt-list");
  if (!el) return;
  document.querySelectorAll("[data-aptf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.aptf === aptFilter)));
  const metaEl = $("#apt-meta"), chEl = $("#apt-changes");
  if (!aptGroups){ return; }
  const st = (aptMeta && aptMeta.status) || {};
  if (metaEl) metaEl.textContent = aptGroups.length
    ? aptGroups.length + " groups · " + aptGroups.filter(g => g.apj || g.india).length + " India/APJ-linked · checked " + fmtDay(aptMeta && aptMeta.checkedAt) + (st.ok === false ? " · last check failed: " + st.error : "")
    : (st.error ? "Unavailable — " + st.error : "Not collected yet — runs daily at 03:17 UTC, or POST /api/refresh-actors.");
  if (chEl){
    chEl.innerHTML = aptChanges.length
      ? '<ul class="apt-changes-list">' + aptChanges.slice(0, 12).map(c =>
          "<li><b>" + esc(fmtDay(c.date)) + "</b> · " + '<span class="tag ' + (c.kind === "added" ? "tag-accent" : "tag-neutral") + '">' + esc(c.kind) + "</span> " +
          esc(c.name) + ' <span class="text-muted">[' + esc(c.tab) + "]</span>" + (c.detail && c.detail.length ? ' — <span class="text-muted">' + esc(c.detail.join("; ")) + "</span>" : "") + "</li>"
        ).join("") + "</ul>"
      : (aptBaseline ? "No edits to the sheet since monitoring began on " + esc(fmtDay(aptBaseline)) + "." : "Waiting for the first collection.");
  }
  const list = visibleApt();
  if (!list.length){ el.innerHTML = '<tr><td colspan="5" class="empty">' + (aptGroups.length ? "No groups match this view." : "No data yet.") + "</td></tr>"; return; }
  const rows = list.slice(0, APT_ROW_CAP).map(g => {
    const row = '<tr class="apt-row" data-id="' + esc(g.id) + '">' +
      '<td data-label="Group"><b>' + esc(g.label || g.name) + "</b>" + (g.label ? ' <span class="apt-alias">(' + esc(g.name) + ")</span>" : "") +
        (g.india ? ' <span class="tag tag-accent">India</span>' : "") + "</td>" +
      '<td data-label="Sheet tab" class="text-muted">' + esc(g.tab) + "</td>" +
      '<td data-label="Also known as">' + esc(aptAliasText(g, 8) || "—") + "</td>" +
      '<td data-label="MITRE">' + aptMitreLink(g.mitre) + "</td>" +
      '<td data-label="Targets" class="text-muted">' + esc((g.targets || g.origin || "—").slice(0, 160)) + ((g.targets || "").length > 160 ? "…" : "") + "</td></tr>";
    if (aptOpen !== g.id) return row;
    const f = (lbl, v) => v ? '<div class="row"><span class="lbl">' + lbl + "</span><br>" + v + "</div>" : "";
    return row + '<tr class="apt-det"><td colspan="5">' +
      f("All names", esc(aptAliasText(g, 60))) +
      f("Operations", esc((g.ops || []).join(", "))) +
      f("Toolset / malware", esc(g.malware)) +
      f("Targets", esc(g.targets)) +
      f("Modus operandi", esc(g.modus)) +
      f("Origin", esc(g.origin)) +
      f("Overlaps", esc(g.overlaps)) +
      f("Comment", esc(g.comment)) +
      f("Sources", aptLinksHtml(g.links, 12)) +
      "</td></tr>";
  }).join("");
  el.innerHTML = rows + (list.length > APT_ROW_CAP ? '<tr><td colspan="5" class="empty">Showing ' + APT_ROW_CAP + " of " + list.length + " — search or pick a country to narrow.</td></tr>" : "");
}
function wireApt(){
  document.querySelectorAll("[data-aptf]").forEach(c => c.addEventListener("click", () => {
    aptFilter = c.dataset.aptf;
    localStorage.setItem("apjti.aptFilter", aptFilter);
    renderApt();
  }));
  const sel = $("#apt-tab-filter");
  if (sel) sel.addEventListener("change", e => { aptTab = e.target.value; localStorage.setItem("apjti.aptTab", aptTab); renderApt(); });
  const search = $("#apt-search");
  let t = null;
  if (search) search.addEventListener("input", e => {
    clearTimeout(t);
    t = setTimeout(() => { aptSearch = e.target.value.trim().toLowerCase(); renderApt(); }, 120);
  });
  const list = $("#apt-list");
  if (list) list.addEventListener("click", e => {
    if (e.target.closest("a")) return;
    const tr = e.target.closest("tr.apt-row");
    if (!tr) return;
    aptOpen = aptOpen === tr.dataset.id ? null : tr.dataset.id;
    renderApt();
  });
}

/* ---------------- Rendering: signal snapshot ---------------- */
function renderSnapshot(){
  const el = $("#snapshot");
  if (!el) return;
  const anchor = maxDate(allItems.map(i => i.date));
  const items = anchor ? allItems.filter(i => inWindow(i.date, anchor.getTime())) : allItems;
  const rwAnchor = maxDate(rwVictims.map(v => v.date));
  const rw = rwAnchor ? rwVictims.filter(v => inWindow(v.date, rwAnchor.getTime())) : rwVictims;
  const stats = [
    { label: "India-tagged items", value: items.filter(i => i.india).length },
    { label: "APJ-tagged items", value: items.filter(i => i.apj).length },
    { label: "DDoS / AppSec lens", value: items.filter(i => i.lens).length },
    { label: "Ransomware claims", value: rw.length }
  ];
  const max = Math.max(1, ...stats.map(s => s.value));
  el.innerHTML = stats.map(s =>
    '<div class="snap-row"><div class="snap-hdr"><span>' + esc(s.label) + '</span><b>' + s.value + '</b></div>' +
    '<div class="apj-barcell"><div class="apj-barfill" style="width:' + Math.round((s.value / max) * 100) + '%"></div></div></div>'
  ).join("");
}

/* ---------------- Rendering: critical vulnerabilities (CISA KEV) ---------------- */
function daysAgo(dateStr){
  if (!dateStr) return null;
  const d = new Date(dateStr);
  if (isNaN(d)) return null;
  return Math.max(0, Math.round((Date.now() - d.getTime()) / 86400000));
}
function renderKev(){
  const el = $("#kev-list");
  if (!el) return;
  const list = (DATA.kev || []).slice(0, 6);
  if (!list.length){ el.innerHTML = '<div class="bempty">No new CISA KEV entries in this collection cycle.</div>'; return; }
  el.innerHTML = list.map(k => {
    const age = daysAgo(k.dateAdded);
    return '<div class="kev-item">' +
      '<div class="kev-top">' +
        '<span class="kev-name">' + esc(k.cveId) + (k.vendor ? " — " + esc(k.vendor) : "") + (k.product ? " " + esc(k.product) : "") + "</span>" +
        '<span class="tag ' + (k.ransomware ? "tag-accent" : "tag-outline") + '">' + (k.ransomware ? "Ransomware use" : "Exploited") + "</span>" +
      "</div>" +
      '<div class="card-meta">' + (age !== null ? "added " + age + (age === 1 ? " day ago" : " days ago") : "date unknown") + (k.dueDate ? " · CISA due " + esc(String(k.dueDate).slice(0,10)) : "") + "</div>" +
    "</div>";
  }).join("");
}

/* ---------------- Rendering: Critical Vulnerabilities tab (NVD + GHSA + KEV, merged by CVE) ---------------- */
function cvssClass(score){
  if (score == null) return "";
  if (score >= 9) return "cvss-critical";
  if (score >= 7) return "cvss-high";
  return "cvss-med";
}
// EPSS is a 0-1 probability, not a 0-10 score, so its own thresholds — reuses the cvss-badge color
// classes (they're generic severity colors, not CVSS-specific) rather than adding a parallel set.
// >=0.5 ("more likely than not" to be exploited in the next 30 days) and >=0.1 are FIRST.org's own
// rough breakpoints for "high" and "elevated" EPSS.
function epssClass(score){
  if (score == null) return "";
  if (score >= 0.5) return "cvss-critical";
  if (score >= 0.1) return "cvss-high";
  return "cvss-med";
}
function visibleVulns(){
  let list = vulnItems.slice();
  if (vulnFilter === "critical") list = list.filter(v => v.cvssScore != null && v.cvssScore >= 9);
  else if (vulnFilter === "kev") list = list.filter(v => v.kev);
  else if (vulnFilter === "waf") list = list.filter(v => v.waf);
  else if (vulnFilter === "epss") list = list.filter(v => v.epss != null && v.epss >= 0.5);
  if (vulnSearch) list = list.filter(v => (v.cveId + " " + (v.vendor||"") + " " + (v.product||"") + " " + (v.desc||"")).toLowerCase().includes(vulnSearch));
  list.sort((a,b) => ((b.cvssScore==null?-1:b.cvssScore) - (a.cvssScore==null?-1:a.cvssScore)) || ((b.date?b.date.getTime():0) - (a.date?a.date.getTime():0)));
  return list;
}
function renderVulnerabilities(){
  const el = $("#vuln-list");
  if (!el) return;
  document.querySelectorAll("[data-vf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.vf === vulnFilter)));
  const covEl = $("#vuln-cov");
  if (covEl) covEl.textContent = vulnItems.length
    ? "Coverage: " + vulnItems.length + " CVE(s) tracked · " + vulnItems.filter(v => v.kev).length + " actively exploited (CISA KEV) · " + vulnItems.filter(v => v.waf).length + " WAF-mitigable class(es) · " + vulnItems.filter(v => v.epss != null && v.epss >= 0.5).length + " with EPSS ≥ 50%."
      + (DATA.vulnGenerated ? " CVE sources last checked " + new Date(DATA.vulnGenerated).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) + " (refreshes every 10 min)." : "")
    : "";
  const list = visibleVulns();
  if (!list.length){ el.innerHTML = '<tr><td colspan="7" class="empty">No vulnerabilities match this view.</td></tr>'; return; }
  el.innerHTML = list.slice(0, 200).map(v => {
    const cls = cvssClass(v.cvssScore);
    const ecls = epssClass(v.epss);
    return "<tr" + (cls === "cvss-critical" ? ' class="row-critical"' : "") + ">" +
      '<td data-label="CVE"><a href="' + esc(v.link) + '" target="_blank" rel="noopener">' + esc(v.cveId) + "</a>" +
        (v.desc ? '<div class="text-muted" style="font-size:11.5px;margin-top:2px">' + esc(v.desc) + "</div>" : "") +
      "</td>" +
      '<td data-label="CVSS">' + (v.cvssScore != null ? '<span class="cvss-badge ' + cls + '">' + v.cvssScore.toFixed(1) + "</span>" : '<span class="text-muted">—</span>') + "</td>" +
      '<td data-label="EPSS">' + (v.epss != null ? '<span class="cvss-badge ' + ecls + '" title="' + (v.epssPercentile != null ? (v.epssPercentile*100).toFixed(0) + "th percentile" : "") + '">' + (v.epss*100).toFixed(1) + "%</span>" : '<span class="text-muted">—</span>') + "</td>" +
      '<td data-label="WAF">' + (v.waf ? '<span class="wafdot" title="WAF/virtual-patch mitigable class (SQLi, XSS, RCE, SSRF, path traversal, deserialization, etc.)">🛡</span>' : "") + "</td>" +
      '<td data-label="Vendor / Product" class="text-muted">' + esc([v.vendor, v.product].filter(Boolean).join(" ") || "—") + "</td>" +
      '<td data-label="Status">' + (v.kev ? '<span class="tag tag-accent">Exploited (KEV)</span>' : '<span class="tag tag-outline">Tracked</span>') + "</td>" +
      '<td data-label="Published / Added" class="text-muted">' + (v.date ? esc(v.date.toISOString().slice(0,10)) : "—") + "</td>" +
    "</tr>";
  }).join("");
}

/* ---------------- IP reputation lookup (AbuseIPDB via /api/ip-check) ---------------- */
function renderIpCheck(d){
  const cls = d.score >= 75 ? "abuse-high" : d.score >= 25 ? "abuse-mid" : "abuse-low";
  const verdict = d.score >= 75 ? "Very likely abusive" : d.score >= 25 ? "Some abuse reports" : d.reports ? "Low confidence of abuse" : "No abuse reports";
  const row = (k, v) => v ? "<dt>" + esc(k) + "</dt><dd>" + v + "</dd>" : "";
  return '<div class="ipc-head"><span class="ipc-ip">' + esc(d.ip) + '</span><span class="abuse-score ' + cls + '">' + esc(String(d.score)) + "%</span><b>" + esc(verdict) + "</b></div>" +
    "<dl>" +
      row("Reports", esc(d.reports + " from " + d.users + " user(s) in the last 90 days")) +
      row("Last reported", d.lastReportedAt ? esc(String(d.lastReportedAt).slice(0, 10)) : "") +
      row("Country", esc(d.country)) +
      row("ISP", esc(d.isp) + (d.domain ? ' <span class="text-muted">(' + esc(d.domain) + ")</span>" : "")) +
      row("Usage", esc(d.usageType)) +
      row("Hostnames", esc((d.hostnames || []).join(", "))) +
      row("Flags", esc([d.isTor ? "Tor exit node" : "", d.isWhitelisted ? "whitelisted by AbuseIPDB" : "", d.isPublic ? "" : "private/reserved address"].filter(Boolean).join(" · "))) +
    "</dl>" +
    '<div class="text-muted" style="margin-top:var(--space-2);font-size:12px">Community-reported, checked ' + esc(new Date(d.checkedAt).toLocaleString()) +
    ' · <a href="https://www.abuseipdb.com/check/' + encodeURIComponent(d.ip) + '" target="_blank" rel="noopener">Full report on AbuseIPDB ↗</a></div>';
}
function wireIpCheck(){
  const form = $("#ipcheck-form"), input = $("#ipcheck-input"), out = $("#ipcheck-result");
  if (!form) return;
  // Bumped on every new lookup and whenever the box is cleared, so a response that arrives after
  // the user has emptied the box (or started another lookup) is dropped instead of re-appearing.
  let seq = 0;
  input.addEventListener("input", () => {
    if (!input.value.trim()){ seq++; out.innerHTML = ""; }
  });
  form.addEventListener("submit", async e => {
    e.preventDefault();
    const ip = input.value.trim().replace(/^\[|\]$/g, "");
    if (!ip){ input.focus(); return; }
    const mine = ++seq;
    const btn = form.querySelector("button");
    btn.disabled = true;
    out.textContent = "Checking " + ip + "…";
    try {
      const r = await fetch("/api/ip-check?ip=" + encodeURIComponent(ip));
      const d = await r.json();
      if (mine !== seq) return;
      out.innerHTML = d.error ? '<span class="text-muted">' + esc(d.error) + "</span>" : renderIpCheck(d);
    } catch (err){
      if (mine === seq) out.innerHTML = '<span class="text-muted">Lookup failed (' + esc(err.message) + ").</span>";
    } finally {
      btn.disabled = false;
    }
  });
}

/* ---------------- Rendering: IOCs tab (abuse.ch URLhaus/ThreatFox/MalwareBazaar, raw) ---------------- */
function populateIocTypeFilter(){
  const sel = $("#ioc-type-filter");
  if (!sel) return;
  const types = [...new Set(iocItems.map(i => i.type).filter(Boolean))].sort();
  if (!types.includes(iocTypeFilter) && iocTypeFilter !== "all") iocTypeFilter = "all";
  sel.innerHTML = '<option value="all">All types</option>' +
    types.map(t => '<option value="' + esc(t) + '"' + (t === iocTypeFilter ? " selected" : "") + ">" + esc(t) + "</option>").join("");
  sel.value = iocTypeFilter;
}
function visibleIocs(){
  let list = iocItems.slice();
  if (iocFilter !== "all") list = list.filter(i => i.source === iocFilter);
  if (iocTypeFilter !== "all") list = list.filter(i => i.type === iocTypeFilter);
  if (iocSearch) list = list.filter(i => (i.value + " " + (i.threat||"") + " " + (i.tags||[]).join(" ")).toLowerCase().includes(iocSearch));
  list.sort((a,b) => ((b.firstSeen?b.firstSeen.getTime():0) - (a.firstSeen?a.firstSeen.getTime():0)));
  return list;
}
function renderIocs(){
  const el = $("#ioc-list");
  if (!el) return;
  populateIocTypeFilter();
  document.querySelectorAll("[data-iocf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.iocf === iocFilter)));
  const covEl = $("#ioc-cov");
  if (covEl) covEl.textContent = iocItems.length
    ? "Coverage: " + iocItems.length + " indicator(s) tracked across " + new Set(iocItems.map(i => i.source)).size + " abuse.ch feed(s)."
    : "No indicators cached yet — set ABUSECH_AUTH_KEY (free key at auth.abuse.ch) to enable URLhaus/ThreatFox/MalwareBazaar.";
  const list = visibleIocs();
  if (!list.length){ el.innerHTML = '<tr><td colspan="6" class="empty">No indicators match this view.</td></tr>'; return; }
  el.innerHTML = list.slice(0, 200).map(i =>
    "<tr>" +
      '<td data-label="Source"><span class="tag tag-neutral">' + esc(i.source) + "</span></td>" +
      '<td data-label="Indicator" style="word-break:break-all">' + esc(i.value) + "</td>" +
      '<td data-label="Type" class="text-muted">' + esc(i.type || "—") + "</td>" +
      '<td data-label="Threat / family" class="text-muted">' + esc(i.threat || "—") + "</td>" +
      '<td data-label="Tags" class="text-muted">' + esc((i.tags || []).slice(0, 4).join(", ") || "—") + "</td>" +
      '<td data-label="First seen" class="text-muted">' + (i.firstSeen ? esc(i.firstSeen.toISOString().slice(0,10)) : "—") + "</td>" +
    "</tr>"
  ).join("");
}

/* ---------------- Rendering: top TTPs observed (curated actor profiles) ---------------- */
function renderTopTtps(){
  const el = $("#top-ttps");
  if (!el) return;
  let list = mergedActors();
  if (actorFilter === "apj") list = list.filter(a => a.region === "apj");
  else if (actorFilter === "global") list = list.filter(a => a.region === "global");
  const counts = {};
  list.forEach(a => (a.ttps || []).forEach(([id, name]) => {
    if (!counts[id]) counts[id] = { id, name, count: 0 };
    counts[id].count++;
  }));
  const top = Object.values(counts).sort((a,b) => b.count - a.count).slice(0, 8);
  if (!top.length){ el.innerHTML = '<div class="bempty">No techniques in this view.</div>'; return; }
  el.innerHTML = top.map((t, i) =>
    '<div class="rank-row"><span class="rank-n">' + (i+1) + "</span>" +
    '<span class="ttp" style="margin:0">' + esc(t.id) + "</span>" +
    '<span class="rank-label">' + esc(t.name) + "</span>" +
    '<span class="rank-count">' + t.count + "×</span></div>"
  ).join("");
}

/* ---------------- Rendering: hero INFOCON ---------------- */
function renderHeroInfocon(){
  const level = String(DATA.infocon || "green").toLowerCase();
  const labelMap = { green: "LOW", yellow: "ELEVATED", orange: "HIGH", red: "SEVERE" };
  const tagEl = $("#hero-infocon");
  if (!tagEl) return;
  tagEl.className = "tag tag-outline infocon-tag lvl-" + level;
  $("#hero-infocon-text").textContent = "INFOCON: " + (labelMap[level] || level.toUpperCase());
}

/* ---------------- Rendering: daily brief ---------------- */
function srcLinks(items){
  const seen = new Set();
  let out = "";
  for (const i of items){
    if (!i.link) continue;
    let host;
    try { host = new URL(i.link).hostname.replace(/^www\./,""); } catch(_){ host = i.src; }
    if (seen.has(host)) continue;
    seen.add(host);
    out += '<a href="' + esc(i.link) + '" target="_blank" rel="noopener">' + esc(host) + "</a>";
    if (seen.size >= 3) break;
  }
  return out ? '<span class="bsrc">' + out + "</span>" : "";
}
function bulletLi(boldPart, rest, items){
  return "<li>" + (boldPart ? "<b>" + esc(boldPart) + ":</b> " : "") + esc(rest) + srcLinks(items || []) + "</li>";
}
function renderStructuredBrief(pool, victims){
  const india = pool.filter(i => i.india);
  const apjOnly = pool.filter(i => i.apj && !i.india);
  const lens = pool.filter(i => i.lens);
  const global = pool.filter(i => !i.apj);
  const rwIndia = victims.filter(v => v.cc === "IN").slice(0, 6);
  const rwOther = victims.filter(v => v.cc !== "IN").slice(0, 6);

  function newsBullets(list, max){
    if (!list.length) return '<div class="bempty">Nothing notable in this window.</div>';
    return '<ul class="blist">' + list.slice(0, max || 6).map(i => bulletLi(null, i.title + (i.desc ? " — " + i.desc.slice(0,140) : ""), [i])).join("") + "</ul>";
  }
  function rwBullets(list){
    if (!list.length) return '<div class="bempty">No claims in this window.</div>';
    return '<ul class="blist">' + list.map(v =>
      "<li><b>" + esc(v.group) + ":</b> claims " + esc(v.victim) + (v.sector ? " (" + esc(v.sector) + ")" : "") + " — " + esc(v.country) + (v.date ? ", " + esc(String(v.date).slice(0,10)) : "") + "</li>"
    ).join("") + "</ul>";
  }

  let html = "";
  html += '<div class="bsec pri"><div class="bhdr"><span class="n">1</span> India / APJ — Priority</div>' + newsBullets(india.concat(apjOnly), 8) + "</div>";
  html += '<div class="bsec"><div class="bhdr">Ransomware Watch — India first</div>' + rwBullets(rwIndia.concat(rwOther).slice(0,8)) + "</div>";
  html += '<div class="bsec"><div class="bhdr">DDoS &amp; AppSec Lens</div>' + newsBullets(lens, 6) + "</div>";
  html += '<div class="bsec"><div class="bhdr">Global — Key Developments</div>' + newsBullets(global, 6) + "</div>";
  return html;
}
function makeBrief(){
  const el = $("#brief-text");
  const dateEl = $("#brief-date");
  if (dateEl) dateEl.textContent = DATA.generated ? new Date(DATA.generated).toLocaleDateString(undefined, { weekday:"long", year:"numeric", month:"long", day:"numeric" }) : "No data yet";
  const pool = allItems.slice().sort((a,b) => (b.date?b.date.getTime():0) - (a.date?a.date.getTime():0));
  if (!pool.length && !rwVictims.length){ el.textContent = "No items collected yet — check source status above."; return; }
  el.classList.remove("placeholder");
  el.innerHTML = renderStructuredBrief(pool, rwVictims);
}

/* ---------------- Markdown export ---------------- */
function buildMarkdown(){
  const pool = allItems.slice().sort((a,b) => (b.date?b.date.getTime():0) - (a.date?a.date.getTime():0));
  const india = pool.filter(i => i.india), apjOnly = pool.filter(i => i.apj && !i.india);
  const lens = pool.filter(i => i.lens), global = pool.filter(i => !i.apj);
  const rwIndia = rwVictims.filter(v => v.cc === "IN").slice(0,8);
  const rwOther = rwVictims.filter(v => v.cc !== "IN").slice(0,8);
  const lines = [];
  lines.push("# Threat Intelligence Brief — " + new Date().toISOString().slice(0,10));
  lines.push("");
  lines.push("India first, then APJ, then global. INFOCON: " + (DATA.infocon || "green").toUpperCase() + " (SANS ISC).");
  lines.push("");
  lines.push("## India / APJ — Priority");
  india.concat(apjOnly).slice(0,10).forEach(i => lines.push("- **" + i.title + "** (" + i.src + (i.link ? ", " + i.link : "") + ")"));
  lines.push("");
  lines.push("## Ransomware Watch");
  rwIndia.concat(rwOther).slice(0,10).forEach(v => lines.push("- **" + v.group + "**: " + v.victim + (v.sector ? " (" + v.sector + ")" : "") + " — " + v.country + (v.date ? ", " + String(v.date).slice(0,10) : "")));
  lines.push("");
  lines.push("## DDoS / AppSec Lens");
  lens.slice(0,8).forEach(i => lines.push("- " + i.title + " (" + i.src + ")"));
  lines.push("");
  lines.push("## Global");
  global.slice(0,8).forEach(i => lines.push("- " + i.title + " (" + i.src + ")"));
  lines.push("");
  lines.push("_Generated " + new Date().toISOString() + " from open-source collection. Ransomware entries are leak-site claims, not confirmed breaches._");
  return lines.join("\n");
}
function downloadMarkdown(){
  const md = buildMarkdown();
  const blob = new Blob([md], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "apj-threat-brief-" + new Date().toISOString().slice(0,10) + ".md";
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ---------------- DarkGrid: dot-matrix claim map + live ticker + locate ---------------- */
let chartGroupsInst = null, chartTrendInst = null, chartSectorsInst = null;

function buildTrendSeries(){
  const anchor = maxDate(allItems.map(i => i.date)) || new Date();
  const days = Math.max(1, Math.min(rangeDays, 60)); // cap buckets so the chart stays readable at wide windows
  const buckets = [];
  for (let i = days - 1; i >= 0; i--){
    const d = new Date(anchor.getTime() - i * 86400000);
    buckets.push({ key: d.toISOString().slice(0,10), india: 0, apj: 0, global: 0 });
  }
  const byKey = Object.fromEntries(buckets.map(b => [b.key, b]));
  allItems.forEach(i => {
    if (!i.date) return;
    const b = byKey[i.date.toISOString().slice(0,10)];
    if (!b) return;
    if (i.india) b.india++; else if (i.apj) b.apj++; else b.global++;
  });
  return { buckets, capped: days < rangeDays };
}
function computeAgg(regionKey){
  const scope = REGIONS[regionKey] && REGIONS[regionKey].countries;
  const byCountry = {}, byGroup = {}, bySector = {};
  for (const v of rwVictims){
    const cc = v.cc || "??";
    if (scope && !scope.includes(cc)) continue;
    byCountry[cc] = (byCountry[cc] || 0) + 1;
    byGroup[v.group] = (byGroup[v.group] || 0) + 1;
    if (v.sector) bySector[v.sector] = (bySector[v.sector] || 0) + 1;
  }
  return { byCountry, byGroup, bySector };
}
/* ---------------- DarkGrid map: flat dot-matrix world, claim heat, same-group arcs ----------------
   Equirectangular projection over a land mask rasterised once from world-atlas (110m TopoJSON, via
   jsDelivr) — no mapping library beyond topojson-client for decoding. The mask stores a country
   index per 0.5° cell, so one lookup gives both "is this land" (dot rendering) and "which country"
   (hover/click hit-testing). If the atlas can't load, the map still renders pings/arcs over a bare
   graticule rather than failing. */
const WORLD_ATLAS_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json";
const MAP_LAT_MAX = 80, MAP_LAT_MIN = -58, MASK_RES = 0.5;
const MASK_W = 360 / MASK_RES, MASK_H = Math.round((MAP_LAT_MAX - MAP_LAT_MIN) / MASK_RES);
// ISO 3166 numeric (world-atlas feature ids) → alpha-2 for every country the victim feed commonly
// uses; anything else falls back to matching the atlas's English name via Intl.DisplayNames.
const ISO_NUM = {
  "356":"IN","392":"JP","156":"CN","410":"KR","158":"TW","036":"AU","554":"NZ","702":"SG","704":"VN","764":"TH",
  "360":"ID","458":"MY","608":"PH","050":"BD","144":"LK","524":"NP","586":"PK","104":"MM","116":"KH","344":"HK",
  "840":"US","124":"CA","484":"MX","076":"BR","032":"AR","170":"CO","152":"CL","604":"PE","188":"CR","826":"GB",
  "276":"DE","250":"FR","724":"ES","620":"PT","380":"IT","528":"NL","056":"BE","756":"CH","752":"SE","578":"NO",
  "208":"DK","246":"FI","616":"PL","203":"CZ","040":"AT","372":"IE","643":"RU","804":"UA","792":"TR","710":"ZA",
  "818":"EG","682":"SA","784":"AE","376":"IL","364":"IR","566":"NG","024":"AO","706":"SO","862":"VE","442":"LU",
  "780":"TT","600":"PY","404":"KE","504":"MA","300":"GR","642":"RO","348":"HU","218":"EC","858":"UY","398":"KZ",
  "634":"QA","414":"KW","400":"JO","422":"LB","368":"IQ","012":"DZ","788":"TN","288":"GH","231":"ET","100":"BG",
  "191":"HR","688":"RS","703":"SK","705":"SI","860":"UZ","496":"MN","112":"BY","512":"OM","048":"BH","008":"AL"
};
const REGION_VIEW = { // [lonMin, lonMax, latMin, latMax]
  world: [-160, 182, -56, 76], in: [62, 98, 5, 37], apac: [58, 182, -48, 52], na: [-168, -50, 8, 72],
  sa: [-95, -30, -56, 14], eu: [-25, 45, 34, 71], me: [22, 66, 10, 44]
};
const MAP_COLORS = { IN: [255, 91, 58], APJ: [255, 180, 84], OTHER: [122, 162, 214] };
const ARC_PALETTE = ["#ff5b3a", "#ffb454", "#e8d27a", "#7aa2d6", "#c58cf0", "#5fd3b0", "#f07fa8", "#9aa3b5"];
const REDUCED_MOTION = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const regionNames = (() => { try { return new Intl.DisplayNames(["en"], { type: "region" }); } catch (_){ return null; } })();
function ccName(cc){
  if (!cc) return "Unknown";
  if (APJ_CC[cc]) return APJ_CC[cc];
  try { return (regionNames && regionNames.of(cc)) || cc; } catch (_){ return cc; }
}
function ccCategory(cc){ return cc === "IN" ? "IN" : (APJ_CC[cc] ? "APJ" : "OTHER"); }
function rgba(c, a){ return "rgba(" + c[0] + "," + c[1] + "," + c[2] + "," + a + ")"; }

let landMask = null, maskCountries = [], maskCentroid = {}, mapAtlasState = "idle";
let mapView = null, mapTarget = null;               // { lon, lat, spanLon, spanLat }
let mapScene = { counts: {}, max: 1, pings: [], arcs: [], focus: null, pool: [] };
let mapHover = null, mapDirty = true, mapLoopOn = false, mapDrag = null;
let mapBursts = [], mapBurstIdx = 0, mapLastBurst = 0, mapRipples = [];
const dotLayer = document.createElement("canvas");

function viewFromBounds(b){ return { lon: (b[0] + b[1]) / 2, lat: (b[2] + b[3]) / 2, spanLon: b[1] - b[0], spanLat: b[3] - b[2] }; }
function mapGeom(){
  const canvas = document.getElementById("threatMap");
  const w = canvas.clientWidth, h = canvas.clientHeight, v = mapView;
  const s = Math.min(w / v.spanLon, h / v.spanLat);
  return { w, h, s, v };
}
function toXY(lat, lon, g){ return { x: g.w / 2 + (lon - g.v.lon) * g.s, y: g.h / 2 - (lat - g.v.lat) * g.s }; }
function toLatLon(x, y, g){ return { lon: g.v.lon + (x - g.w / 2) / g.s, lat: g.v.lat - (y - g.h / 2) / g.s }; }
function maskAt(lat, lon){
  if (!landMask || lat >= MAP_LAT_MAX || lat < MAP_LAT_MIN) return 0;
  const col = Math.floor((((lon + 180) % 360 + 360) % 360) / MASK_RES);
  const row = Math.floor((MAP_LAT_MAX - lat) / MASK_RES);
  return landMask[row * MASK_W + col];
}
function posOf(cc){
  const c = CENTROIDS[cc];
  if (c) return c;
  return maskCentroid[cc] || null;
}

async function loadAtlas(){
  if (mapAtlasState !== "idle") return;
  mapAtlasState = "loading";
  try {
    if (typeof topojson === "undefined") throw new Error("topojson-client not loaded");
    const topo = await (await fetch(WORLD_ATLAS_URL)).json();
    const features = topojson.feature(topo, topo.objects.countries).features;
    const byName = {};
    if (regionNames){
      for (let a = 65; a <= 90; a++) for (let b = 65; b <= 90; b++){
        const code = String.fromCharCode(a, b);
        try { const n = regionNames.of(code); if (n && n !== code) byName[n.toLowerCase()] = code; } catch (_){}
      }
    }
    maskCountries = features.map(f => {
      const num = f.id == null ? "" : String(f.id).padStart(3, "0");
      const name = (f.properties && f.properties.name) || "";
      return { cc: ISO_NUM[num] || byName[name.toLowerCase()] || null, name };
    });
    // Rasterise each country with its index encoded in R/G and a checksum in B: anti-aliased edge
    // pixels blend two countries' colours, fail the checksum, and are resolved to "land, unknown
    // country" instead of decoding to a bogus index.
    const off = document.createElement("canvas");
    off.width = MASK_W; off.height = MASK_H;
    const ctx = off.getContext("2d");
    features.forEach((f, i) => {
      const id = i + 1;
      ctx.fillStyle = "rgb(" + (id & 255) + "," + (id >> 8) + "," + ((id * 37) & 255) + ")";
      ctx.beginPath();
      const polys = f.geometry ? (f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates) : [];
      polys.forEach(poly => poly.forEach(ring => ring.forEach(([lon, lat], k) => {
        const x = (lon + 180) / MASK_RES, y = (MAP_LAT_MAX - lat) / MASK_RES;
        if (k === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      })));
      ctx.fill("evenodd");
    });
    const px = ctx.getImageData(0, 0, MASK_W, MASK_H).data;
    const mask = new Uint16Array(MASK_W * MASK_H);
    const sums = {};
    for (let i = 0; i < mask.length; i++){
      const r = px[i * 4], g = px[i * 4 + 1], b = px[i * 4 + 2], a = px[i * 4 + 3];
      if (a < 128) continue;
      const id = r | (g << 8);
      if (id >= 1 && id <= features.length && ((id * 37) & 255) === b){
        mask[i] = id;
        const cc = maskCountries[id - 1].cc;
        if (cc){
          const s = sums[cc] || (sums[cc] = { lat: 0, lon: 0, n: 0 });
          s.lat += MAP_LAT_MAX - (Math.floor(i / MASK_W) + 0.5) * MASK_RES;
          s.lon += (i % MASK_W + 0.5) * MASK_RES - 180;
          s.n++;
        }
      } else {
        mask[i] = 65535; // land, country unresolved (anti-aliased border)
      }
    }
    for (const [cc, s] of Object.entries(sums)) maskCentroid[cc] = [s.lat / s.n, s.lon / s.n];
    landMask = mask;
    mapAtlasState = "ready";
  } catch (e){
    mapAtlasState = "failed";
    console.warn("DarkGrid: world atlas unavailable, rendering without land", e);
  }
  buildMapScene(mapScene.focus, currentRegion);
}

function scopePool(regionKey, focusCC){
  if (focusCC) return rwVictims.filter(v => v.cc === focusCC);
  const scope = REGIONS[regionKey] && REGIONS[regionKey].countries;
  return scope ? rwVictims.filter(v => scope.includes(v.cc)) : rwVictims;
}
function buildMapScene(focusCC, regionKey){
  const pool = scopePool(regionKey || currentRegion, focusCC);
  const counts = {};
  pool.forEach(v => { if (v.cc) counts[v.cc] = (counts[v.cc] || 0) + 1; });
  const max = Math.max(1, ...Object.values(counts));
  const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const pings = ranked.map(([cc, n], i) => {
    const p = posOf(cc);
    return p ? { cc, n, lat: p[0], lon: p[1], phase: i * 0.83, label: i < 6 } : null;
  }).filter(Boolean);

  // Arcs connect countries claimed by the same group — the group's busiest in-scope country (or the
  // focused country) to the other countries it has claimed anywhere. Deliberately not "attack
  // origin": leak-site data carries no origin, and the actor tracker is careful about attribution.
  const byGroup = {};
  pool.forEach(v => { byGroup[v.group] = (byGroup[v.group] || 0) + 1; });
  const topGroups = Object.entries(byGroup).sort((a, b) => b[1] - a[1]).slice(0, 7).map(([g]) => g);
  const arcs = [];
  topGroups.forEach((g, gi) => {
    const inScope = {}, everywhere = {};
    pool.forEach(v => { if (v.group === g && v.cc) inScope[v.cc] = (inScope[v.cc] || 0) + 1; });
    rwVictims.forEach(v => { if (v.group === g && v.cc) everywhere[v.cc] = (everywhere[v.cc] || 0) + 1; });
    const hub = focusCC || (Object.entries(inScope).sort((a, b) => b[1] - a[1])[0] || [])[0];
    if (!hub || !posOf(hub)) return;
    Object.entries(everywhere).filter(([cc]) => cc !== hub && posOf(cc)).sort((a, b) => b[1] - a[1]).slice(0, 5)
      .forEach(([cc, n], k) => arcs.push({ from: hub, to: cc, n, group: g, color: ARC_PALETTE[gi % ARC_PALETTE.length],
        speed: 0.12 + ((gi * 7 + k * 3) % 10) / 70, off: ((gi * 13 + k * 29) % 100) / 100 }));
  });

  mapScene = { counts, max, pings, arcs, focus: focusCC || null, pool,
    groups: topGroups.map((g, i) => ({ g, n: byGroup[g], color: ARC_PALETTE[i % ARC_PALETTE.length] })) };
  mapBursts = pool.filter(v => v.cc && posOf(v.cc)).slice().sort((a, b) => String(b.date || "").localeCompare(String(a.date || ""))).slice(0, 30);
  mapBurstIdx = 0;
  const scopeEl = $("#dg-scope");
  if (scopeEl) scopeEl.textContent = "SCOPE · " + (focusCC ? ccName(focusCC) : (document.querySelector('.dg-rtab[data-region="' + (regionKey || currentRegion) + '"]') || {}).textContent || "World").toUpperCase();
  renderMapSide(ranked, pool.length);
  mapDirty = true;
}
function renderMapSide(ranked, total){
  const rankEl = $("#dg-rank");
  if (!rankEl) return;
  const top = ranked.slice(0, 10), max = Math.max(1, ...top.map(r => r[1]));
  $("#dg-rank-meta").textContent = total + " claims";
  rankEl.innerHTML = top.length ? top.map(([cc, n], i) => {
    const cat = ccCategory(cc).toLowerCase();
    return '<li><button type="button" class="dg-rank-row cat-' + cat + (mapScene.focus === cc ? " on" : "") + '" data-cc="' + esc(cc) + '">' +
      '<span class="rk">' + String(i + 1).padStart(2, "0") + '</span><span class="nm">' + esc(ccName(cc)) + '</span>' +
      '<span class="ct">' + n + '</span><span class="bar"><i style="width:' + (n / max * 100).toFixed(1) + '%"></i></span></button></li>';
  }).join("") : '<li class="dg-empty">No claims in this scope.</li>';
  const chips = $("#dg-gchips");
  if (chips) chips.innerHTML = (mapScene.groups || []).map(x =>
    '<span class="dg-gchip"><i style="background:' + x.color + '"></i>' + esc(x.g) + '<b>' + x.n + '</b></span>').join("") || '<span class="dg-empty">—</span>';
}

function resizeMap(){
  const canvas = document.getElementById("threatMap");
  if (!canvas) return;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return;
  canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
  dotLayer.width = canvas.width; dotLayer.height = canvas.height;
  mapDirty = true;
}
function renderDotLayer(g, dpr){
  const ctx = dotLayer.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, g.w, g.h);
  // graticule
  ctx.strokeStyle = "rgba(233,228,220,.045)"; ctx.lineWidth = 1;
  ctx.beginPath();
  for (let lon = -180; lon <= 360; lon += 30){ const x = toXY(0, lon, g).x; if (x >= 0 && x <= g.w){ ctx.moveTo(x, 0); ctx.lineTo(x, g.h); } }
  for (let lat = -60; lat <= 90; lat += 30){ const y = toXY(lat, 0, g).y; if (y >= 0 && y <= g.h){ ctx.moveTo(0, y); ctx.lineTo(g.w, y); } }
  ctx.stroke();
  if (!landMask) return;
  const styles = maskCountries.map(c => {
    const n = c.cc ? (mapScene.counts[c.cc] || 0) : 0;
    const hover = mapHover && c.cc === mapHover, focus = mapScene.focus && c.cc === mapScene.focus;
    if (!n) return hover ? "rgba(233,228,220,.5)" : "rgba(170,160,146,.24)";
    const t = Math.log1p(n) / Math.log1p(mapScene.max);
    return rgba(MAP_COLORS[ccCategory(c.cc)], (focus || hover) ? 1 : (0.34 + 0.6 * t).toFixed(2));
  });
  const gap = g.s > 9 ? 3.2 : 4.2, size = gap > 3.5 ? 2 : 1.7;
  let last = null;
  for (let y = gap / 2; y < g.h; y += gap){
    for (let x = gap / 2; x < g.w; x += gap){
      const ll = toLatLon(x, y, g);
      const id = maskAt(ll.lat, ll.lon);
      if (!id) continue;
      const st = id === 65535 ? "rgba(170,160,146,.24)" : styles[id - 1];
      if (st !== last){ ctx.fillStyle = st; last = st; }
      ctx.fillRect(x - size / 2, y - size / 2, size, size);
    }
  }
}
function arcPoint(a, b, c, t){
  const u = 1 - t;
  return { x: u * u * a.x + 2 * u * t * c.x + t * t * b.x, y: u * u * a.y + 2 * u * t * c.y + t * t * b.y };
}
function arcGeom(arc, g){
  const pa = posOf(arc.from), pb = posOf(arc.to);
  const a = toXY(pa[0], pa[1], g), b = toXY(pb[0], pb[1], g);
  const d = Math.hypot(b.x - a.x, b.y - a.y);
  const c = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - Math.min(d * 0.32, 180) };
  return { a, b, c };
}
function drawMap(ts){
  const canvas = document.getElementById("threatMap");
  if (!canvas || activeTab !== "map"){ mapLoopOn = false; return; }
  if (!canvas.width || canvas.width !== Math.round(canvas.clientWidth * Math.min(window.devicePixelRatio || 1, 2))) resizeMap();
  const dpr = canvas.width / Math.max(1, canvas.clientWidth);
  const t = (ts || 0) / 1000;

  if (!mapDrag){
    for (const k of ["lon", "lat", "spanLon", "spanLat"]){
      const diff = mapTarget[k] - mapView[k];
      if (Math.abs(diff) > 0.01){ mapView[k] += diff * (REDUCED_MOTION ? 1 : 0.085); mapDirty = true; }
    }
  }
  const g = mapGeom();
  if (mapDirty){ renderDotLayer(g, dpr); mapDirty = false; }

  const ctx = canvas.getContext("2d");
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(dotLayer, 0, 0);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  // arcs: faint base path + a comet-trail particle travelling hub → target
  ctx.lineCap = "round";
  for (const arc of mapScene.arcs){
    const { a, b, c } = arcGeom(arc, g);
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.quadraticCurveTo(c.x, c.y, b.x, b.y);
    ctx.strokeStyle = arc.color + "40"; ctx.lineWidth = 1; ctx.stroke();
    const p = REDUCED_MOTION ? 0.62 : (t * arc.speed + arc.off) % 1;
    for (let k = 14; k >= 0; k--){
      const tt = p - k * 0.011;
      if (tt < 0) continue;
      const q = arcPoint(a, b, c, tt);
      ctx.globalAlpha = (1 - k / 15) * 0.9;
      ctx.fillStyle = arc.color;
      ctx.beginPath(); ctx.arc(q.x, q.y, k === 0 ? 2.4 : 1.6 * (1 - k / 18), 0, Math.PI * 2); ctx.fill();
    }
    ctx.globalAlpha = 1;
    if (!REDUCED_MOTION && p < arc._lastP) mapRipples.push({ cc: arc.to, color: arc.color, start: t });
    arc._lastP = p;
  }

  // arrival ripples
  mapRipples = mapRipples.filter(r => t - r.start < 1.1);
  for (const r of mapRipples){
    const pos = posOf(r.cc); if (!pos) continue;
    const q = toXY(pos[0], pos[1], g), k = (t - r.start) / 1.1;
    ctx.beginPath(); ctx.arc(q.x, q.y, 3 + k * 14, 0, Math.PI * 2);
    ctx.strokeStyle = r.color; ctx.globalAlpha = 1 - k; ctx.lineWidth = 1.2; ctx.stroke(); ctx.globalAlpha = 1;
  }

  // pings: core dot + two sonar rings sized by claim volume
  ctx.font = "500 10px 'Martian Mono', ui-monospace, monospace";
  ctx.textBaseline = "middle";
  for (const pg of mapScene.pings){
    const q = toXY(pg.lat, pg.lon, g);
    if (q.x < -20 || q.x > g.w + 20 || q.y < -20 || q.y > g.h + 20) continue;
    const col = MAP_COLORS[ccCategory(pg.cc)];
    const r = 2.6 + Math.sqrt(pg.n / mapScene.max) * 9;
    for (let ring = 0; ring < 2; ring++){
      const k = REDUCED_MOTION ? 0.5 : ((t * 0.55 + pg.phase * 0.1 + ring * 0.5) % 1);
      ctx.beginPath(); ctx.arc(q.x, q.y, r + k * (r * 1.6 + 8), 0, Math.PI * 2);
      ctx.strokeStyle = rgba(col, ((1 - k) * 0.55).toFixed(2)); ctx.lineWidth = 1; ctx.stroke();
    }
    const grad = ctx.createRadialGradient(q.x, q.y, 0, q.x, q.y, r * 2.4);
    grad.addColorStop(0, rgba(col, 0.45)); grad.addColorStop(1, rgba(col, 0));
    ctx.fillStyle = grad; ctx.beginPath(); ctx.arc(q.x, q.y, r * 2.4, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = rgba(col, 1); ctx.beginPath(); ctx.arc(q.x, q.y, r, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "rgba(255,248,238,.9)"; ctx.beginPath(); ctx.arc(q.x, q.y, Math.max(1.2, r * 0.32), 0, Math.PI * 2); ctx.fill();
    if (pg.cc === mapScene.focus || pg.cc === mapHover){
      ctx.beginPath(); ctx.arc(q.x, q.y, r + 5, 0, Math.PI * 2); ctx.strokeStyle = "#fff8ee"; ctx.lineWidth = 1.3; ctx.stroke();
    }
    if (pg.label || pg.cc === mapHover){
      const label = ccName(pg.cc).toUpperCase() + "  " + pg.n;
      ctx.fillStyle = "rgba(10,11,13,.72)";
      const tw = ctx.measureText(label).width;
      ctx.fillRect(q.x + r + 6, q.y - 8, tw + 10, 16);
      ctx.fillStyle = rgba(col, 1); ctx.fillRect(q.x + r + 6, q.y - 8, 2, 16);
      ctx.fillStyle = "#e9e4dc"; ctx.fillText(label, q.x + r + 12, q.y + 0.5);
    }
  }

  // claim bursts: cycle through the newest claims in scope, one callout at a time
  if (!REDUCED_MOTION && mapBursts.length && t - mapLastBurst > 2.8){
    mapLastBurst = t;
    const v = mapBursts[mapBurstIdx++ % mapBursts.length];
    mapBurstActive = { v, start: t };
  }
  if (mapBurstActive && t - mapBurstActive.start < 2.6){
    const v = mapBurstActive.v, pos = posOf(v.cc);
    if (pos){
      const q = toXY(pos[0], pos[1], g), k = (t - mapBurstActive.start) / 2.6;
      const col = MAP_COLORS[ccCategory(v.cc)];
      for (let i = 0; i < 2; i++){
        const kk = Math.min(1, k * 1.8 - i * 0.25);
        if (kk <= 0) continue;
        ctx.beginPath(); ctx.arc(q.x, q.y, 4 + kk * 30, 0, Math.PI * 2);
        ctx.strokeStyle = rgba(col, (1 - kk).toFixed(2)); ctx.lineWidth = 1.5; ctx.stroke();
      }
      const alpha = k < 0.12 ? k / 0.12 : (k > 0.8 ? (1 - k) / 0.2 : 1);
      const l1 = String(v.group || "").toUpperCase() + "  ▸  " + String(v.victim || "").slice(0, 34);
      const l2 = ccName(v.cc) + (v.sector ? " · " + v.sector : "") + " · " + String(v.date || "").slice(0, 10);
      ctx.font = "600 10.5px 'Martian Mono', ui-monospace, monospace";
      const w1 = ctx.measureText(l1).width;
      ctx.font = "400 9.5px 'Martian Mono', ui-monospace, monospace";
      const bw = Math.max(w1, ctx.measureText(l2).width) + 20, bh = 38;
      let bx = q.x + 18, by = q.y - 46 - (1 - Math.min(1, k * 6)) * 6;
      if (bx + bw > g.w - 8) bx = q.x - 18 - bw;
      if (by < 8) by = q.y + 16;
      ctx.globalAlpha = alpha;
      ctx.strokeStyle = rgba(col, 0.7); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(q.x, q.y); ctx.lineTo(bx < q.x ? bx + bw : bx, by + bh / 2); ctx.stroke();
      ctx.fillStyle = "rgba(12,13,16,.92)"; ctx.fillRect(bx, by, bw, bh);
      ctx.strokeRect(bx + 0.5, by + 0.5, bw - 1, bh - 1);
      ctx.fillStyle = rgba(col, 1); ctx.fillRect(bx, by, 3, bh);
      ctx.font = "600 10.5px 'Martian Mono', ui-monospace, monospace"; ctx.fillStyle = "#fff8ee"; ctx.fillText(l1, bx + 11, by + 13);
      ctx.font = "400 9.5px 'Martian Mono', ui-monospace, monospace"; ctx.fillStyle = "#8b8680"; ctx.fillText(l2, bx + 11, by + 27);
      ctx.globalAlpha = 1;
    }
  }
  requestAnimationFrame(drawMap);
}
let mapBurstActive = null;
function startMapLoop(){
  if (mapLoopOn || !document.getElementById("threatMap")) return;
  mapLoopOn = true;
  resizeMap();
  requestAnimationFrame(drawMap);
}
function setMapTarget(bounds){ mapTarget = viewFromBounds(bounds); if (!mapView) mapView = Object.assign({}, mapTarget); }
function pickCountryAt(x, y, g){
  let best = null, bestD = 12;
  for (const pg of mapScene.pings){
    const q = toXY(pg.lat, pg.lon, g), d = Math.hypot(q.x - x, q.y - y);
    if (d < bestD){ bestD = d; best = pg.cc; }
  }
  if (best) return best;
  const ll = toLatLon(x, y, g), id = maskAt(ll.lat, ll.lon);
  return id && id !== 65535 ? maskCountries[id - 1].cc : null;
}
function showMapTip(cc, x, y){
  const tip = $("#dg-tip");
  if (!tip) return;
  if (!cc){ tip.hidden = true; return; }
  const all = rwVictims.filter(v => v.cc === cc);
  const groups = {};
  all.forEach(v => { groups[v.group] = (groups[v.group] || 0) + 1; });
  const topG = Object.entries(groups).sort((a, b) => b[1] - a[1]).slice(0, 3);
  const sectors = {};
  all.forEach(v => { if (v.sector) sectors[v.sector] = (sectors[v.sector] || 0) + 1; });
  const topS = Object.entries(sectors).sort((a, b) => b[1] - a[1])[0];
  tip.innerHTML = '<div class="tip-hd cat-' + ccCategory(cc).toLowerCase() + '"><span>' + esc(ccName(cc)) + '</span><b>' + all.length + '</b></div>' +
    (all.length ? '<div class="tip-row"><span>Top groups</span>' + topG.map(([g2, n]) => esc(g2) + " <i>" + n + "</i>").join(" · ") + '</div>' +
      (topS ? '<div class="tip-row"><span>Top sector</span>' + esc(topS[0]) + '</div>' : "") + '<div class="tip-foot">Click to focus</div>'
      : '<div class="tip-row"><span>No leak-site claims tracked</span></div>');
  tip.hidden = false;
  const wrap = $("#dg-map-wrap").getBoundingClientRect();
  const tw = tip.offsetWidth, th = tip.offsetHeight;
  tip.style.left = Math.min(wrap.width - tw - 8, x + 16) + "px";
  tip.style.top = Math.max(8, Math.min(wrap.height - th - 8, y - th - 12)) + "px";
}
function wireMap(){
  const canvas = document.getElementById("threatMap");
  if (!canvas || canvas._wired) return;
  canvas._wired = true;
  if (window.ResizeObserver) new ResizeObserver(() => resizeMap()).observe(canvas);
  const local = e => { const r = canvas.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; };
  canvas.addEventListener("pointerdown", e => {
    const p = local(e);
    mapDrag = { x: p.x, y: p.y, sx: p.x, sy: p.y, moved: false };
    try { canvas.setPointerCapture(e.pointerId); } catch (_){}
  });
  canvas.addEventListener("pointermove", e => {
    const p = local(e), g = mapGeom();
    if (mapDrag){
      const dx = p.x - mapDrag.x, dy = p.y - mapDrag.y;
      if (Math.hypot(p.x - mapDrag.sx, p.y - mapDrag.sy) > 4) mapDrag.moved = true;
      if (mapDrag.moved){
        mapView.lon -= dx / g.s; mapView.lat = Math.max(-40, Math.min(65, mapView.lat + dy / g.s));
        mapTarget.lon = mapView.lon; mapTarget.lat = mapView.lat;
        mapDirty = true; canvas.classList.add("dragging"); showMapTip(null);
      }
      mapDrag.x = p.x; mapDrag.y = p.y;
      if (mapDrag.moved) return;
    }
    const ll = toLatLon(p.x, p.y, g);
    const coords = $("#dg-coords");
    if (coords) coords.textContent = "LAT " + ll.lat.toFixed(1).padStart(5) + "  LON " + ll.lon.toFixed(1).padStart(6);
    const cc = pickCountryAt(p.x, p.y, g);
    if (cc !== mapHover){ mapHover = cc; mapDirty = true; }
    canvas.style.cursor = cc ? "pointer" : "grab";
    showMapTip(cc, p.x, p.y);
  });
  canvas.addEventListener("pointerleave", () => { if (mapHover){ mapHover = null; mapDirty = true; } showMapTip(null); });
  canvas.addEventListener("pointerup", e => {
    const drag = mapDrag; mapDrag = null; canvas.classList.remove("dragging");
    if (!drag || drag.moved) return;
    const p = local(e), cc = pickCountryAt(p.x, p.y, mapGeom());
    if (cc) focusCountry(cc);
  });
  const rank = $("#dg-rank");
  if (rank) rank.addEventListener("click", e => { const b = e.target.closest("[data-cc]"); if (b) focusCountry(b.dataset.cc); });
}
function tickClock(){
  const el = $("#dg-clock");
  if (el) el.textContent = new Date().toISOString().slice(11, 19);
}
// `singleCC` (set by focusCountry(), below) narrows to exactly one country — distinct from
// `regionKey`, which scopes to one of the named multi-country REGIONS groups.
function buildTicker(regionKey, singleCC){
  const track = $("#dg-ticker");
  if (!track) return;
  const pool = scopePool(regionKey || currentRegion, singleCC);
  const items = pool.slice(0, 24).map(v => {
    const cls = v.cc === "IN" ? "tk-in" : (v.apj ? "tk-apj" : "tk-other");
    const tag = v.cc || "??";
    return '<div class="tk-item"><span class="tk-tag ' + cls + '">' + esc(tag) + '</span><div class="tk-body"><b>' + esc(v.group.toUpperCase()) +
      '</b> <span class="tk-arrow">▸</span> ' + victimNameHtml(v.victim) + '<div class="tk-meta">' + (v.sector ? esc(v.sector) + " · " : "") +
      esc(String(v.date).slice(0,10)) + "</div></div></div>";
  });
  track.innerHTML = items.length ? (items.join("") + items.join("")) : '<div class="tk-item tk-none">No claims' + (singleCC ? " for this country." : " in this region.") + "</div>";
  track.classList.toggle("static", items.length < 6);
  $("#dg-feed-count").textContent = pool.length + " in scope";
}
// Shared by the map's click handler, the ranked list, and the locate box — zooms to one country and
// filters the Live Claim Feed, ranked list, stats and arcs to it.
function focusCountry(cc, opts){
  document.querySelectorAll(".dg-rtab").forEach(t => t.classList.remove("active"));
  buildMapScene(cc, "world");
  buildTicker("world", cc);
  renderDashStats("world", cc);
  const c = posOf(cc);
  if (c){
    const span = cc === "IN" ? 30 : (["US","CA","RU","CN","BR","AU"].includes(cc) ? 70 : 34);
    setMapTarget([c[1] - span, c[1] + span, c[0] - span * 0.42, c[0] + span * 0.42]);
  }
  // Skipped while the user is still typing in the locate box — setting input.value mid-keystroke
  // would fight their cursor.
  if (!opts || opts.setInput !== false){
    const input = $("#dg-locate");
    if (input) input.value = ccName(cc);
  }
}

function renderBanner(){
  const level = String(DATA.infocon || "green").toLowerCase();
  const el = $("#dg-banner");
  if (!el) return;
  el.className = "dg-banner lvl-" + level;
  const labelMap = { green: "LOW", yellow: "ELEVATED", orange: "HIGH", red: "SEVERE" };
  const cveSet = new Set();
  allItems.forEach(i => { const m = (i.title + " " + (i.desc||"")).match(/CVE-\d{4}-\d{4,7}/gi); if (m) m.forEach(c => cveSet.add(c.toUpperCase())); });
  const indiaSignals = allItems.filter(i => i.india).length + rwVictims.filter(v => v.cc === "IN").length;
  $("#dg-banner-text").innerHTML = "<b>INFOCON " + esc(level.toUpperCase()) + " · " + (labelMap[level]||"—") + "</b><span class=\"sep\"></span>SANS Internet Storm Center<span class=\"sep\"></span>" +
    indiaSignals + " India-priority signals · " + cveSet.size + " CVEs tracked <span class=\"dim\">(our own volume heuristic, not an official alert)</span>";
}
function selectRegion(key){
  if (!REGIONS[key]) key = "world";
  currentRegion = key;
  localStorage.setItem("apjti.region", key);
  document.querySelectorAll(".dg-rtab").forEach(t => { const on = t.dataset.region === key; t.classList.toggle("active", on); t.setAttribute("aria-selected", String(on)); });
  setMapTarget(REGION_VIEW[key] || REGION_VIEW.world);
  const input = $("#dg-locate");
  if (input) input.value = "";
  buildMapScene(null, key);
  buildTicker(key);
  renderDashStats(key);
}
function locateCandidates(){
  const set = new Set(Object.keys(CENTROIDS));
  rwVictims.forEach(v => v.cc && set.add(v.cc));
  maskCountries.forEach(c => c.cc && set.add(c.cc));
  return [...set].map(cc => [cc, ccName(cc)]);
}
function wireLocate(){
  const input = $("#dg-locate");
  if (!input || input._wired) return;
  input._wired = true;
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    if (!q){ selectRegion(currentRegion); return; }
    const cands = locateCandidates();
    const hit = cands.find(([cc]) => cc.toLowerCase() === q) ||
      cands.find(([, name]) => name.toLowerCase().startsWith(q)) ||
      (q.length > 2 && cands.find(([, name]) => name.toLowerCase().includes(q)));
    if (hit) focusCountry(hit[0], { setInput: false });
  });
}
function resetMapView(){ selectRegion("world"); }
function wireResetView(){
  const btn = $("#dg-reset");
  if (!btn || btn._wired) return;
  btn._wired = true;
  btn.addEventListener("click", resetMapView);
}
/* ---------------- Rendering: real (not claimed) DDoS attack traffic — Cloudflare Radar ---------------- */
function renderDdosTelemetry(){
  const el = $("#radar-ddos");
  if (!el) return;
  const dt = DATA.ddosTelemetry;
  if (!dt || (!dt.l3.india.length && !dt.l7.india.length)){
    el.innerHTML = '<div class="empty">No Cloudflare Radar data cached yet — set CF_RADAR_TOKEN (free Account &gt; Radar &gt; Read token) to enable real, measured DDoS attack-traffic telemetry alongside the claims above.</div>';
    return;
  }
  const rowHtml = r => '<div class="radar-row"><span class="radar-label">' + esc(r.label) + '</span>' +
    '<span class="radar-bar"><span class="radar-fill" style="width:' + Math.min(100, r.pct) + '%"></span></span>' +
    '<span class="radar-pct">' + r.pct.toFixed(1) + "%</span></div>";
  const colHtml = (list, empty) => list.length ? list.map(rowHtml).join("") : '<div class="empty">' + empty + "</div>";
  el.innerHTML =
    '<div><div class="radar-col-hd">L3/L4 attack vectors targeting India (7d)</div>' + colHtml(dt.l3.india, "No L3/L4 attack traffic recorded.") + "</div>" +
    '<div><div class="radar-col-hd">L7 HTTP methods targeting India (7d)</div>' + colHtml(dt.l7.india, "No L7 attack traffic recorded.") + "</div>";
}
function renderDashStats(regionKey, focusCC){
  const pool = scopePool(regionKey || currentRegion, focusCC);
  const countries = new Set(pool.map(v => v.cc).filter(Boolean));
  const groups = new Set(pool.map(v => v.group));
  const india = pool.filter(v => v.cc === "IN").length;
  const cutoff = Date.now() - 7 * 86400000;
  const last7 = pool.filter(v => v.date && new Date(v.date).getTime() >= cutoff).length;
  const cveSet = new Set();
  allItems.forEach(i => { const m = (i.title + " " + (i.desc||"")).match(/CVE-\d{4}-\d{4,7}/gi); if (m) m.forEach(c => cveSet.add(c.toUpperCase())); });
  const pct = pool.length ? Math.round(india / pool.length * 100) : 0;
  $("#dg-stats").innerHTML = [
    ["Claims in scope", pool.length, last7 + " in the last 7 days", ""],
    ["India", india, pct + "% of scope", "hot"],
    ["Countries hit", countries.size, "victim countries", ""],
    ["Active groups", groups.size, "posting to leak sites", ""],
    ["CVEs tracked", cveSet.size, "mentioned in the feed", ""]
  ].map(([l, v, sub, cls], i) => '<div class="dg-stat ' + cls + '" style="--i:' + i + '"><div class="l">' + esc(l) + '</div><div class="v">' + esc(String(v)) +
    '</div><div class="s">' + esc(sub) + "</div></div>").join("");
}
function wireRegionTabs(){
  document.querySelectorAll(".dg-rtab").forEach(t => {
    if (t._wired) return;
    t._wired = true;
    t.addEventListener("click", () => selectRegion(t.dataset.region));
  });
}
function buildDashboard(){
  const dates = rwVictims.map(v => v.date).filter(Boolean).sort();
  const focus = mapScene.focus;

  renderDashStats(currentRegion, focus);
  renderDdosTelemetry();
  renderBanner();
  renderHeroInfocon();
  document.querySelectorAll(".dg-rtab").forEach(t => t.classList.toggle("active", !focus && t.dataset.region === currentRegion));

  $("#dg-updated").textContent = rwVictims.length + " leak-site claims tracked · latest " + (dates.length ? String(dates[dates.length-1]).slice(0,10) : "n/a");
  $("#dash-cov").textContent = "Coverage " + (dates[0] ? String(dates[0]).slice(0,10) : "n/a") + " → " + (dates.length ? String(dates[dates.length-1]).slice(0,10) : "n/a") + " · leak-site claims, not confirmed breaches · refreshed every 30 min server-side";

  if (!mapTarget) setMapTarget(REGION_VIEW[currentRegion] || REGION_VIEW.world);
  buildMapScene(focus, currentRegion);
  buildTicker(currentRegion, focus);
  wireMap();
  wireLocate();
  wireResetView();
  wireRegionTabs();
  loadAtlas();
  if (activeTab === "map") startMapLoop();
  if (!tickClock._on){ tickClock._on = true; tickClock(); setInterval(tickClock, 1000); }

  const { byGroup, bySector } = computeAgg("world");
  const topGroups = Object.entries(byGroup).sort((a,b) => b[1]-a[1]).slice(0, 8);
  const topSectors = Object.entries(bySector).sort((a,b) => b[1]-a[1]).slice(0, 8);

  if (typeof Chart === "undefined") return;
  const mono = "'Martian Mono', ui-monospace, monospace";
  const gridColor = "rgba(233,228,220,.06)";
  const tick = { color: "#8b8680", font: { size: 10, family: mono } };
  const tooltip = { backgroundColor: "#0c0d10", borderColor: "#2a2f37", borderWidth: 1, titleColor: "#e9e4dc", bodyColor: "#c9c3b9",
    titleFont: { family: mono, size: 11 }, bodyFont: { family: mono, size: 10.5 }, padding: 10, cornerRadius: 0, boxPadding: 4 };
  const fade = (ctx, hex) => {
    const area = ctx.chart.chartArea;
    if (!area) return hex + "33";
    const g = ctx.chart.ctx.createLinearGradient(0, area.top, 0, area.bottom);
    g.addColorStop(0, hex + "55"); g.addColorStop(1, hex + "00");
    return g;
  };

  const ctxT = document.getElementById("chartTrend");
  if (ctxT){
    const { buckets, capped } = buildTrendSeries();
    if (chartTrendInst) chartTrendInst.destroy();
    const line = (label, key, hex) => ({ label, data: buckets.map(b => b[key]), borderColor: hex, backgroundColor: c => fade(c, hex),
      fill: true, pointRadius: 0, pointHoverRadius: 3, borderWidth: 1.6, tension: 0.35 });
    chartTrendInst = new Chart(ctxT, {
      type: "line",
      data: { labels: buckets.map(b => b.key.slice(5)), datasets: [line("India", "india", "#ff5b3a"), line("APJ", "apj", "#ffb454"), line("Global", "global", "#7aa2d6")] },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: { display: false }, tooltip },
        scales: {
          x: { ticks: { ...tick, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 }, grid: { display: false }, border: { color: "#2a2f37" } },
          y: { beginAtZero: true, ticks: { ...tick, precision: 0, maxTicksLimit: 5 }, grid: { color: gridColor }, border: { display: false } }
        }
      }
    });
    const note = ctxT.closest(".dg-achart").querySelector("h4");
    if (note) note.title = capped ? "Capped to the last 60 days for readability." : "";
  }

  const hbar = (el, inst, rows, colorFor) => {
    if (inst) inst.destroy();
    return new Chart(el, {
      type: "bar",
      data: { labels: rows.map(([k]) => k.length > 18 ? k.slice(0, 17) + "…" : k), datasets: [{ data: rows.map(([,n]) => n),
        backgroundColor: rows.map((r, i) => colorFor(i) + "cc"), hoverBackgroundColor: rows.map((r, i) => colorFor(i)),
        borderSkipped: false, borderRadius: 1, barPercentage: 0.62, categoryPercentage: 0.9 }] },
      options: {
        responsive: true, maintainAspectRatio: false, indexAxis: "y",
        plugins: { legend: { display: false }, tooltip },
        scales: {
          x: { beginAtZero: true, ticks: { ...tick, precision: 0, maxTicksLimit: 5 }, grid: { color: gridColor }, border: { display: false } },
          y: { ticks: { ...tick, color: "#c9c3b9" }, grid: { display: false }, border: { color: "#2a2f37" } }
        }
      }
    });
  };
  const ctxG = document.getElementById("chartGroups");
  if (ctxG) chartGroupsInst = hbar(ctxG, chartGroupsInst, topGroups, i => ARC_PALETTE[i % ARC_PALETTE.length]);
  const ctxS = document.getElementById("chartSectors");
  if (ctxS) chartSectorsInst = hbar(ctxS, chartSectorsInst, topSectors, i => i === 0 ? "#ff5b3a" : (i < 3 ? "#ffb454" : "#8a847a"));
  // Chart.js measures axis labels at creation; if Martian Mono arrives afterwards the wider glyphs
  // overflow the reserved gutter and get clipped — re-layout once web fonts are ready.
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => [chartTrendInst, chartGroupsInst, chartSectorsInst].forEach(c => c && c.update()));
}

function setCopyStatus(msg){
  document.querySelectorAll(".copy-status").forEach(el => { el.textContent = msg; });
  if (msg) setTimeout(() => document.querySelectorAll(".copy-status").forEach(el => { el.textContent = ""; }), 2500);
}

/* ---------------- Wiring ---------------- */
// Nav sun/moon toggle — flips html[data-theme] (initially set by the inline script in index.html's
// <head>) and remembers the explicit choice. The Map tab stays dark either way (body.map-mode).
function syncThemeToggle(){
  const btn = $("#theme-toggle");
  if (!btn) return;
  const dark = document.documentElement.getAttribute("data-theme") === "dark";
  const onMap = document.body.classList.contains("map-mode");
  const label = onMap ? "The map is always dark — theme applies to other tabs (currently " + (dark ? "dark" : "light") + ")"
    : "Switch to " + (dark ? "light" : "dark") + " theme";
  btn.setAttribute("aria-label", label);
  btn.title = label;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = (dark || onMap) ? "#0a0b0d" : "#f2f2f3";
}
function wireThemeToggle(){
  const btn = $("#theme-toggle");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("apjti.theme", next); } catch (_){}
    syncThemeToggle();
  });
  syncThemeToggle();
}
function wireNavToggle(){
  const toggle = $("#nav-toggle");
  const links = $("#nav-links");
  if (!toggle || !links) return;
  toggle.addEventListener("click", () => {
    const open = links.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
  });
  links.querySelectorAll("a").forEach(a => a.addEventListener("click", () => {
    links.classList.remove("open");
    toggle.setAttribute("aria-expanded", "false");
  }));
}

function wireActions(){
  document.querySelectorAll('[data-action="download-brief"]').forEach(b => b.addEventListener("click", () => {
    downloadMarkdown();
    setCopyStatus("✓ Downloaded.");
  }));
  document.addEventListener("click", e => {
    const card = e.target.closest(".actor-card");
    if (card && !e.target.closest("a")) card.classList.toggle("open");
  });
  document.querySelectorAll("[data-t]").forEach(c => c.addEventListener("click", () => {
    rangeDays = parseInt(c.dataset.t, 10);
    localStorage.setItem("apjti.range", String(rangeDays));
    document.querySelectorAll("[data-t]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.t === c.dataset.t)));
    renderRw(); renderRansomwareNews(); renderTelegram(); renderSnapshot(); buildDashboard();
  }));
  document.querySelectorAll("[data-af]").forEach(c => c.addEventListener("click", () => {
    actorFilter = c.dataset.af;
    localStorage.setItem("apjti.actorFilter", actorFilter);
    renderActors();
  }));
  document.querySelectorAll("[data-rwf]").forEach(c => c.addEventListener("click", () => {
    rwFilter = c.dataset.rwf;
    localStorage.setItem("apjti.rwFilter", rwFilter);
    renderRw();
  }));
  document.querySelectorAll("[data-tgf]").forEach(c => c.addEventListener("click", () => {
    tgFilter = c.dataset.tgf;
    localStorage.setItem("apjti.tgFilter", tgFilter);
    renderTelegram();
  }));
  document.querySelectorAll("[data-vf]").forEach(c => c.addEventListener("click", () => {
    vulnFilter = c.dataset.vf;
    localStorage.setItem("apjti.vulnFilter", vulnFilter);
    renderVulnerabilities();
  }));
  const vulnSearchEl = $("#vuln-search");
  if (vulnSearchEl) vulnSearchEl.addEventListener("input", e => { vulnSearch = e.target.value.toLowerCase(); renderVulnerabilities(); });
  document.querySelectorAll("[data-iocf]").forEach(c => c.addEventListener("click", () => {
    iocFilter = c.dataset.iocf;
    localStorage.setItem("apjti.iocFilter", iocFilter);
    renderIocs();
  }));
  const iocSearchEl = $("#ioc-search");
  if (iocSearchEl) iocSearchEl.addEventListener("input", e => { iocSearch = e.target.value.toLowerCase(); renderIocs(); });
  const iocTypeSel = $("#ioc-type-filter");
  if (iocTypeSel) iocTypeSel.addEventListener("change", e => {
    iocTypeFilter = e.target.value;
    localStorage.setItem("apjti.iocTypeFilter", iocTypeFilter);
    renderIocs();
  });
  const sectorSel = $("#sector-filter");
  if (sectorSel) sectorSel.addEventListener("change", e => {
    sectorFilter = e.target.value;
    localStorage.setItem("apjti.sectorFilter", sectorFilter);
    renderRw();
  });
}

/* ---------------- Init ---------------- */
async function renderAll(){
  renderRw();
  renderRansomwareNews();
  renderTelegram();
  renderVulnerabilities();
  renderIocs();
  renderSnapshot();
  renderKev();
  makeBrief();
  buildDashboard();
}

async function init(){
  $("#today").textContent = new Date().toLocaleDateString(undefined, { weekday:"long", year:"numeric", month:"long", day:"numeric" });
  document.querySelectorAll("[data-t]").forEach(x => x.setAttribute("aria-pressed", String(parseInt(x.dataset.t, 10) === rangeDays)));
  document.querySelectorAll("[data-rwf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.rwf === rwFilter)));
  document.querySelectorAll("[data-tgf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.tgf === tgFilter)));
  document.querySelectorAll("[data-af]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.af === actorFilter)));
  document.querySelectorAll("[data-vf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.vf === vulnFilter)));
  document.querySelectorAll("[data-iocf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.iocf === iocFilter)));
  renderActors();
  wireActions();
  wireApt();
  wireIpCheck();
  wireNavToggle();
  wireThemeToggle();
  wireTabs();
  const startTab = TAB_IDS.includes(location.hash.slice(1)) ? location.hash.slice(1) : (localStorage.getItem("apjti.tab") || "brief");
  showTab(startTab, { skipHash: true });

  try {
    await loadData();
    renderAll();
  } catch (e){
    showError("Could not load /api/data (" + e.message + "). Is the Worker deployed and has the scheduled collector run at least once? Try POST /api/refresh.");
  }

  setInterval(async () => {
    try { await loadData(); renderAll(); } catch (e){ /* keep showing last-good data */ }
  }, REFRESH_POLL_MS);
}
init();
