"use strict";
/**
 * Threat Intelligence — standalone frontend. Global, filterable by region, with a per-country page.
 * Pulls pre-tagged, pre-aggregated data from /api/data (populated by the Worker's
 * scheduled collector — see src/worker.js). No client-side fetching, no API keys,
 * no MCP bridge: this runs anywhere as static files behind that one endpoint.
 */

const APP_VERSION = "standalone-v1";
const REFRESH_POLL_MS = 5 * 60 * 1000; // re-poll /api/data every 5 min to pick up the cron's updates

// Every country the app places in a region — mirrors REGION_CC in src/worker.js (keep them in sync).
// Anything not listed, and every claim with no country, is "other".
const REGION_CC = {
  apj: "IN JP CN KR KP TW AU NZ SG VN TH ID MY PH BD LK NP PK MM KH HK MO LA BN MN MV BT AF KZ UZ KG TJ TM PG FJ TL",
  eu: "GB IE FR DE ES PT IT NL BE LU CH AT SE NO DK FI IS PL CZ SK HU RO BG GR HR SI RS BA ME MK AL XK EE LV LT UA BY MD RU CY MT LI MC AD SM GE AM AZ",
  na: "US CA MX GT HN SV NI CR PA BZ CU DO HT JM TT BS BB PR",
  sa: "BR AR CO CL PE VE EC BO PY UY GY SR",
  me: "TR SA AE IL IR IQ JO LB SY KW QA BH OM YE EG PS",
  af: "ZA NG KE MA DZ TN LY GH ET TZ UG SN CI CM AO ZW ZM MZ RW SD SS SO NA BW MU MG CD BF"
};
const CC_REGION = {};
for (const [rg, list] of Object.entries(REGION_CC)) for (const cc of list.split(" ")) CC_REGION[cc] = rg;
function ccRegion(cc){ return CC_REGION[String(cc || "").toUpperCase()] || "other"; }
const GEO_KEYS = ["apj", "eu", "na", "sa", "me", "af"];
// Labels + the categorical colour each region gets on the map, ticker, trend chart and chips. These
// are the DarkGrid palette's literals (like the rest of drawMap()), not severity colours.
const REGION_META = {
  all:   { label: "All regions" },
  apj:   { label: "APJ",         color: "#ff5b3a" },
  eu:    { label: "Europe",      color: "#7aa2d6" },
  na:    { label: "N. America",  color: "#ffb454" },
  sa:    { label: "S. America",  color: "#5fd3b0" },
  me:    { label: "Middle East", color: "#c58cf0" },
  af:    { label: "Africa",      color: "#e8d27a" },
  other: { label: "Unplaced",    color: "#8ea0b1" }
};
function regionLabel(key){ return (REGION_META[key] || REGION_META.other).label; }
function regionColor(key){ return (REGION_META[key] || REGION_META.other).color; }

const CENTROIDS = {
  IN:[20,78], JP:[36,138], CN:[35,105], KR:[36,128], TW:[23,121], AU:[-25,133], NZ:[-41,174],
  SG:[1.3,103.8], VN:[16,108], TH:[15,101], ID:[-5,120], MY:[4,102], PH:[13,122], BD:[24,90],
  LK:[7,81], NP:[28,84], PK:[30,70], MM:[21,96], KH:[12,105], HK:[22.3,114.2], MO:[22.2,113.5],
  US:[39,-98], CA:[56,-106], MX:[23,-102], BR:[-10,-55], AR:[-34,-64], CO:[4,-72], CL:[-30,-71],
  PE:[-10,-76], CR:[9.7,-83.7], GB:[54,-2], DE:[51,10], FR:[46,2], ES:[40,-4], PT:[39.5,-8],
  IT:[43,12], NL:[52,5], BE:[50.5,4.5], CH:[47,8], SE:[62,15], NO:[61,9], DK:[56,10], FI:[64,26],
  PL:[52,19], CZ:[49.8,15.5], AT:[47.5,14.5], IE:[53,-8], RU:[61,105], UA:[49,32], TR:[39,35],
  ZA:[-29,24], EG:[26,30], SA:[24,45], AE:[24,54], IL:[31,35], IR:[32,53], NG:[9,8],
  LU:[49.8,6.1], MT:[35.9,14.4], CY:[35,33], PR:[18.2,-66.5], TT:[10.4,-61.3]
};

// Map scope per region key ("all" = the whole world). Country lists come from REGION_CC.
const REGIONS = Object.assign({ all: { countries: null } },
  Object.fromEntries(GEO_KEYS.map(k => [k, { countries: REGION_CC[k].split(" ") }])));
// Region keys stored by the old India-first UI ("world", "in", "apac") → the current ones.
function normGeo(key){
  const k = String(key || "").toLowerCase();
  if (REGIONS[k]) return k;
  return { world: "all", in: "apj", apac: "apj" }[k] || "all";
}

/* ---------------- Actor baseline (curated) ---------------- */
// `geo` is who each actor is known to target, from its `targets` text: region keys (lowercase),
// country codes (uppercase), or "global" for actors that hit every region. It drives the region
// filter and the Geo Intel page — keep it in step with `targets` when editing a profile.
// `rels` are typed relationships ([name, type, note?], types in REL_LABEL): put a name under "alias"
// only when sources treat it as the same group; vendor clusters that partly overlap go under
// "overlap". `ttps` are [ATT&CK id, official ATT&CK name, behaviour it's mapped from] — use the name
// attack.mitre.org gives, not a paraphrase. `type` drives the badge and filter; `sectors` the filter;
// `match` adds extra spellings for report mentions. Bump ACTORS_EDITED when editing.
const ACTORS = [
  { name:"Transparent Tribe", geo:["IN"], type:"Espionage", rels:[["APT36","alias"],["Earth Karkaddan","alias"]], origin:"Pakistan-nexus", motive:"Espionage", sectors:["government","defense","education"], p:"P1",
    conf:"Attributed with high confidence to a Pakistan-nexus threat actor.",
    overview:"Long-running espionage cluster focused on Indian government, defense, and education sectors. Extensive use of Crimson RAT and ElizaRAT delivered via spearphishing and cloned government portals.",
    targets:"Indian military/defense, government, education",
    ttps:[["T1566.001","Phishing: Spearphishing Attachment","Lure documents delivering Crimson RAT / ElizaRAT"],["T1204.002","User Execution: Malicious File","Victim opens the lure attachment"],["T1105","Ingress Tool Transfer","Second-stage RAT download"],["T1071.001","Application Layer Protocol: Web Protocols","HTTP(S) command and control"]],
    mit:"App & API Protector for portal spoofing/web delivery; Akamai MFA against credential phishing; EAA to reduce exposed access surface." },
  { name:"SideCopy", geo:["IN","AF"], type:"Espionage", rels:[["Transparent Tribe","overlap"]], origin:"Pakistan-nexus", motive:"Espionage", sectors:["defense","government","transport","energy"], p:"P1",
    conf:"Assessed with medium-high confidence as Pakistan-nexus; overlaps with Transparent Tribe.",
    overview:"Targets Indian defense, government, Railways, and Oil & Gas entities, mimicking SideWinder TTPs (hence the name); shifted from HTA to MSI staging with reflective DLL loading. 'Operation XENOFISCAL' (mid-2026) extended targeting to Afghanistan's Ministry of Finance via XenoRAT.",
    targets:"Indian defense, government, Railways, Oil & Gas; Afghan MoF (XENOFISCAL)",
    ttps:[["T1566.002","Phishing: Spearphishing Link","Links to HTA/MSI staging payloads"],["T1218.005","System Binary Proxy Execution: Mshta","HTA staging via mshta"],["T1036","Masquerading","Mimics SideWinder lures and file names"]],
    mit:"App & API Protector WAF; Client-Side Protection & Compliance for injected script detection; Akamai MFA." },
  { name:"RedEcho", geo:["IN"], type:"Espionage", rels:[["APT41","association","shared infrastructure reported"]], origin:"China-nexus", motive:"Espionage / Pre-positioning", sectors:["energy","critical infrastructure","transport"], p:"P1",
    conf:"Attributed with medium confidence to a China-nexus actor (Recorded Future reporting).",
    overview:"Targeted Indian power sector and critical infrastructure with ShadowPad implants — assessed as strategic pre-positioning rather than immediate disruption.",
    targets:"Indian power grid, ports, critical infrastructure",
    ttps:[["T1133","External Remote Services","Access via exposed remote services"],["T1071","Application Layer Protocol","ShadowPad command and control"],["T1105","Ingress Tool Transfer","ShadowPad implant delivery"]],
    mit:"Guardicore Segmentation to contain lateral movement in OT-adjacent networks; EAA for third-party access; Security Services IR Retainer." },
  { name:"APT41", geo:["apj","IN"], type:"Espionage", rels:[["Wicked Panda","alias"],["Brass Typhoon","alias"],["Winnti","overlap","some vendors track Winnti Group separately"]], origin:"China-nexus", motive:"Espionage + Financial", sectors:["telecom","healthcare","technology","gaming"], p:"P2",
    conf:"Attributed with high confidence to a China-nexus threat actor.",
    overview:"Dual-mission group conducting state espionage and financially motivated intrusions. Known for software supply-chain compromises, web-facing app exploitation, and web shells across APJ.",
    targets:"Telecom, healthcare, software, gaming across APJ incl. India",
    ttps:[["T1195.002","Supply Chain Compromise: Compromise Software Supply Chain","Trojanised software updates"],["T1190","Exploit Public-Facing Application","Web-facing application exploitation"],["T1505.003","Server Software Component: Web Shell","Web shells for persistence"]],
    mit:"App & API Protector against edge exploitation; Guardicore Segmentation; Client-Side Protection & Compliance for supply-chain script risk." },
  { name:"CL-STA-1062", geo:["apj","TW"], type:"Espionage", rels:[["UAT-7237","overlap","vendor clusters reported to overlap"]], origin:"China-nexus", motive:"Espionage (possible IAB)", sectors:["energy","government","defense","technology"], p:"P2",
    conf:"Attributed with high confidence to a China-nexus threat actor; initial-access-broker role assessed with low confidence.",
    overview:"State-sponsored espionage cluster active since at least March 2022. Uses the TinyRCT backdoor, web shells, and credential theft; expanded in 2026 from Taiwan web-hosting infrastructure into Southeast Asian electricity/water utilities and government/military targets via SoftEther VPN and Mimikatz.",
    targets:"Southeast Asian energy infrastructure, government",
    ttps:[["T1505.003","Server Software Component: Web Shell","Web shells on hosting infrastructure"],["T1003","OS Credential Dumping","Mimikatz"],["T1190","Exploit Public-Facing Application","Initial access via exposed services"]],
    mit:"App & API Protector WAF; Guardicore Segmentation; Akamai MFA; Security Services IR Retainer." },
  { name:"Lazarus Group", geo:["global","IN","KR"], type:"Espionage", rels:[["Hidden Cobra","alias","US government umbrella name"],["Diamond Sleet","overlap","Microsoft tracks a subset"]], match:["Lazarus"], origin:"DPRK", motive:"Financial + Espionage", sectors:["finance","crypto","defense"], p:"P2",
    conf:"Attributed with high confidence to the DPRK.",
    overview:"Prolific DPRK operator: cryptocurrency theft, bank intrusions (incl. 2018 Cosmos Bank ATM cashout in India), supply-chain attacks, and defense-sector espionage across APJ. 2026 watering-hole campaign exploited a South Korean banking-software zero-day (AnySign4PC) via 15 compromised legitimate sites, affecting 70+ organizations.",
    targets:"Financial services, crypto exchanges, defense — APJ-wide incl. India",
    ttps:[["T1195","Supply Chain Compromise","Software supply-chain delivery"],["T1566","Phishing","Fake job-offer lures"],["T1189","Drive-by Compromise","2026 watering-hole campaign via compromised sites"]],
    mit:"Akamai MFA (phish-proof); App & API Protector for exchange/API abuse; Client-Side Protection & Compliance for skimming." },
  { name:"Kimsuky", geo:["apj","KR","JP"], type:"Espionage", rels:[["Emerald Sleet","alias"],["APT43","overlap","Mandiant cluster overlapping Kimsuky activity"]], origin:"DPRK", motive:"Espionage", sectors:["government","education","think tanks"], p:"P2",
    conf:"Attributed with high confidence to the DPRK.",
    overview:"Credential-harvesting and spearphishing specialist targeting think tanks, academia, and government policy circles in Korea, Japan, and wider APJ, incl. India-focused policy targets. 2026 campaign compromised South Korean groupware vendors' mail servers to pivot into customer credentials via new Gomir-family backdoor variants.",
    targets:"Think tanks, academia, government policy — KR/JP/APJ",
    ttps:[["T1598.003","Phishing for Information: Spearphishing Link","Credential-harvesting links"],["T1078","Valid Accounts","Reuse of harvested credentials"],["T1114","Email Collection","Mailbox access after compromise"]],
    mit:"Akamai MFA; EAA for identity-aware access; App & API Protector." },
  { name:"Mustang Panda", geo:["apj"], type:"Espionage", rels:[["Earth Preta","alias"],["Stately Taurus","alias"]], origin:"China-nexus", motive:"Espionage", sectors:["government","ngo","transport"], p:"P2",
    conf:"Attributed with high confidence to a China-nexus threat actor.",
    overview:"Espionage operator heavily active against Southeast Asian governments; signature PlugX/Korplug delivery via phishing and infected USB media.",
    targets:"SEA governments, NGOs, shipping",
    ttps:[["T1566.002","Phishing: Spearphishing Link","Links to PlugX archives"],["T1091","Replication Through Removable Media","Infected USB media"],["T1574.001","Hijack Execution Flow: DLL","PlugX DLL side-loading (merged into T1574.001 in ATT&CK v17)"]],
    mit:"Guardicore Segmentation; EAA; App & API Protector." },
  { name:"Mysterious Team Bangladesh", geo:["IN"], type:"Hacktivist DDoS", rels:[["MTB","alias"]], origin:"Bangladesh (hacktivist)", motive:"Ideological — DDoS", sectors:["government","finance","aviation"], p:"P1",
    conf:"Self-attributed hacktivist collective; claims assessed with medium confidence.",
    overview:"Hacktivist DDoS collective repeatedly targeting Indian government, financial, and airline web properties with Layer 7 floods and defacements, typically announced on Telegram.",
    targets:"Indian gov portals, BFSI, aviation",
    ttps:[["T1498","Network Denial of Service","Volumetric floods (claimed)"],["T1499.002","Endpoint Denial of Service: Service Exhaustion Flood","Layer 7 HTTP floods against web portals"],["T1491","Defacement","Website defacements"]],
    mit:"App & API Protector + rate controls for L7 floods; Prolexic-class network-layer defense; bot visibility." },
  { name:"NoName057(16)", geo:["eu","JP","IT"], type:"Hacktivist DDoS", rels:[["ServerKillers","association","joint campaigns reported"]], match:["NoName057"], origin:"Russia-aligned (hacktivist)", motive:"Ideological — DDoS", sectors:["government","transport","finance","media"], p:"P2",
    conf:"Self-attributed pro-Russia collective; high confidence in DDoS activity, low in membership claims.",
    overview:"Crowdsourced 'DDoSia' Layer 7 attack platform; the single most prolific hacktivist DDoS brand by claim volume, generating an estimated 40.5% of all recorded hacktivist DDoS claims in H1 2026. Primarily targets Europe (incl. a Feb 2026 campaign against Italian government sites tied to the Milano Cortina Winter Olympics) but launched a sustained #OpJapan campaign in Aug 2026 against Japanese transport, government, shipping, insurance, and media targets — a useful bellwether for hacktivist DDoS tradecraft reaching APJ.",
    targets:"Government, transport, BFSI web properties",
    ttps:[["T1499.002","Endpoint Denial of Service: Service Exhaustion Flood","DDoSia HTTP request floods against web pages"],["T1498.001","Network Denial of Service: Direct Network Flood","DDoSia TCP SYN floods"],["T1583.005","Acquire Infrastructure: Botnet","Volunteer-run DDoSia clients"]],
    mit:"App & API Protector; edge rate controls; upstream network-layer scrubbing." },
  { name:"Keymous+", geo:["global","IN"], type:"Hacktivist DDoS", rels:[["EliteStress","affiliate","affiliated DDoS-for-hire platform"],["DieNet","association","joint campaigns reported"]], match:["Keymous"], origin:"Self-described North Africa-based; DDoS-as-a-service", motive:"Ideological (claimed) / commercial DDoS-for-hire", sectors:["government","healthcare"], p:"P1",
    conf:"Self-attributed hacktivist brand; analysts assess a dual hacktivist/commercial-DaaS identity with medium confidence — claimed attack volumes are largely self-reported and unverified.",
    overview:"Emerged 2023, ramping sharply through 2025 with 700+ claimed DDoS attacks (249 independently confirmed). Became the most aggressive DDoS actor against Indian public healthcare during the 2025-26 India-Pakistan tension period, repeatedly flooding AIIMS and Safdarjung Hospital web infrastructure; no confirmed data breach.",
    targets:"Indian government and public healthcare portals (AIIMS, Safdarjung); opportunistic global targeting",
    ttps:[["T1498","Network Denial of Service","Volumetric floods (claimed)"],["T1499.002","Endpoint Denial of Service: Service Exhaustion Flood","Layer 7 floods against hospital and government portals"],["T1583.005","Acquire Infrastructure: Botnet","DDoS-for-hire infrastructure"]],
    mit:"App & API Protector + rate controls for L7 floods; Prolexic-class network-layer defense; bot visibility." },
  { name:"RuskiNet", geo:["US","CA","IL","GB","TR","IN"], type:"Hacktivist DDoS", rels:[], origin:"Russia-aligned hacktivist (Eastern Europe)", motive:"Ideological — geopolitical", sectors:["government","critical infrastructure"], p:"P2",
    conf:"Self-attributed pro-Russia hacktivist collective; not yet assessed as state-linked. Confidence in claimed scale/impact is low.",
    overview:"Blends DDoS, data leaks, and phishing against government and critical-infrastructure targets, opportunistically tying campaigns (incl. 'Operation Trinetara') to geopolitical flashpoints. India named among its targets alongside the US, Canada, Israel, UK, and Turkey; activity trend assessed as declining since mid-2026.",
    targets:"Government and critical infrastructure — US, Canada, Israel, UK, Turkey, India",
    ttps:[["T1498","Network Denial of Service","DDoS claims"],["T1566","Phishing","Phishing campaigns"],["T1567","Exfiltration Over Web Service","Data-leak claims"]],
    mit:"App & API Protector + rate controls; Akamai MFA against credential phishing; Guardicore Segmentation." }
];
const ACTOR_META = {
  "Transparent Tribe": ["2026-07-11"], "SideCopy": ["2026-06-30"], "RedEcho": ["2025-11-15"],
  "APT41": ["2026-06-10"], "CL-STA-1062": ["2026-07-15"], "Lazarus Group": ["2026-07-30"],
  "Kimsuky": ["2026-07-24"], "Mustang Panda": ["2026-05-28"], "Mysterious Team Bangladesh": ["2026-04-10"],
  "NoName057(16)": ["2026-08-20"], "Keymous+": ["2026-05-15"], "RuskiNet": ["2026-03-01"]
};
const GLOBAL_ACTORS = [
  { name:"Qilin", geo:["global","IN"], type:"Ransomware", rels:[["Agenda","alias","original ransomware name"]], origin:"Russia-aligned RaaS", motive:"Ransomware", sectors:["cross-sector"], p:"P2", last:"2026-08-10",
    conf:"RaaS operation; affiliate attribution varies. Assessed with high confidence as the dominant ransomware brand by victim volume.",
    overview:"Ransomware-as-a-service operation leading leak-site victim counts (2,100+ claimed victims) amid ecosystem consolidation. Strong Linux/ESXi capability; actively exploiting Palo Alto PAN-OS auth-bypass flaws for initial access; recurring Indian victims.",
    targets:"Cross-sector, global — recurring Indian victims",
    ttps:[["T1486","Data Encrypted for Impact","Windows and Linux/ESXi encryptors"],["T1567","Exfiltration Over Web Service","Data theft before encryption"],["T1078","Valid Accounts","Affiliate use of stolen credentials"]],
    mit:"Guardicore Segmentation to limit blast radius; Akamai MFA against affiliate credential access; Security Services IR Retainer." },
  { name:"DragonForce", geo:["global","IN"], type:"Ransomware", rels:[], origin:"RaaS cartel", motive:"Ransomware", sectors:["cross-sector","manufacturing"], p:"P2", last:"2026-07-14",
    conf:"Self-styled ransomware 'cartel'; affiliate structure assessed with medium confidence.",
    overview:"Aggressive RaaS/cartel model absorbing affiliates from disrupted brands. Active APJ + Indian manufacturing claims.",
    targets:"Cross-sector, global + APJ incl. India",
    ttps:[["T1486","Data Encrypted for Impact","Encryption payload"],["T1133","External Remote Services","Access via exposed remote services"],["T1567.002","Exfiltration Over Web Service: Exfiltration to Cloud Storage","Data staged to cloud storage"]],
    mit:"Guardicore Segmentation; EAA to replace exposed remote access; IR Retainer." },
  { name:"Cl0p", geo:["global","IN"], type:"Ransomware", rels:[["TA505","association","reported link; not the same group"]], match:["Clop"], origin:"Russia-nexus eCrime", motive:"Extortion (mass exploitation)", sectors:["cross-sector","healthcare"], p:"P2", last:"2026-07-20",
    conf:"Attributed with high confidence to a Russia-nexus eCrime group.",
    overview:"Specialist in mass exploitation of managed file transfer and enterprise software zero-days (MOVEit, Oracle EBS, and a 2026 PTC Windchill/FlexPLM RCE campaign) rather than individual intrusions; each campaign has produced hundreds of claimed victims. Cumulative totals differ widely by tracker and counting rule (campaign vs leak-site posts), so none is quoted here — see the measured claim counts on the Activity trends tab. Claimed Indian healthcare victims.",
    targets:"Enterprises via file-transfer/ERP zero-days — global incl. India",
    ttps:[["T1190","Exploit Public-Facing Application","Mass exploitation of file-transfer and ERP zero-days"],["T1567","Exfiltration Over Web Service","Bulk data theft for extortion"]],
    mit:"App & API Protector WAF with rapid virtual-patch rules on MFT/ERP CVEs; Guardicore Segmentation." },
  { name:"Scattered Spider", geo:["na","eu","US","GB"], type:"Extortion", rels:[["UNC3944","alias"],["Octo Tempest","alias"],["ShinyHunters","overlap","ecosystem overlap reported"]], origin:"eCrime (native-English)", motive:"Extortion", sectors:["retail","insurance","aviation","technology"], p:"P1", last:"2026-07-02",
    conf:"High confidence in TTP cluster; loose membership (The Com) complicates attribution.",
    overview:"Social-engineering-led intrusions: helpdesk impersonation, MFA-reset abuse, SIM swap, then SaaS data theft and ESXi ransomware deployment with RaaS partners. Core UK/US members have faced arrests, extraditions, and guilty pleas through mid-2026 (incl. the TfL breach), though the loose 'The Com' membership model limits disruption impact.",
    targets:"Retail, insurance, aviation, SaaS-heavy enterprises",
    ttps:[["T1656","Impersonation","Help-desk impersonation"],["T1621","Multi-Factor Authentication Request Generation","MFA fatigue and reset abuse"],["T1078.004","Valid Accounts: Cloud Accounts","Abuse of SaaS and cloud identities"]],
    mit:"Akamai MFA (phish-proof FIDO2); EAA identity-aware access; helpdesk verification playbooks + IR Retainer." },
  { name:"ShinyHunters", geo:["global"], type:"Extortion", rels:[["UNC6040","overlap"],["Scattered Spider","overlap","ecosystem overlap reported (“SLSH”)"]], origin:"eCrime collective", motive:"Data-theft extortion", sectors:["technology","cross-sector"], p:"P1", last:"2026-07-14",
    conf:"Cluster overlaps with Scattered Spider ecosystem; assessed with medium confidence.",
    overview:"Large-scale SaaS data-theft extortion via vishing, malicious connected apps, and OAuth token abuse; 2026 activity includes Oracle PeopleSoft PeopleTools zero-day exploitation and growing ecosystem overlap with Scattered Spider and Lapsus$ (tracked by some vendors as 'SLSH').",
    targets:"Salesforce/SaaS tenants of global enterprises",
    ttps:[["T1566.004","Phishing: Spearphishing Voice","Vishing of SaaS users"],["T1528","Steal Application Access Token","Malicious connected apps and OAuth tokens"],["T1530","Data from Cloud Storage","Bulk SaaS data export"]],
    mit:"Akamai MFA; Client-Side Protection & Compliance; SaaS OAuth-app governance." },
  { name:"Sandworm", geo:["eu","UA","US"], type:"Destructive", rels:[["APT44","alias"],["Seashell Blizzard","alias"]], origin:"Russia (GRU)", motive:"Espionage + Disruption", sectors:["critical infrastructure","energy","government"], p:"P1", last:"2026-07-13",
    conf:"Attributed with high confidence to Russia's GRU.",
    overview:"Destructive and espionage operations against critical infrastructure; known for exploiting vulnerable and misconfigured edge routers.",
    targets:"Critical infrastructure, energy, government — primarily Europe/US, tradecraft globally relevant",
    ttps:[["T1190","Exploit Public-Facing Application","Exploitation of edge devices and routers"],["T1542.001","Pre-OS Boot: System Firmware","Firmware implants on network devices (e.g. Cyclops Blink)"],["T1485","Data Destruction","Wiper deployment"]],
    mit:"Guardicore Segmentation; hardened edge via App & API Protector; DNS posture review." },
  { name:"Salt Typhoon", geo:["global","US","SG"], type:"Espionage", rels:[["Earth Estries","overlap"],["GhostEmperor","overlap"]], origin:"China-nexus", motive:"Espionage", sectors:["telecom"], p:"P2", last:"2026-05-15",
    conf:"Attributed with high confidence to a China-nexus threat actor.",
    overview:"Telecom-focused espionage penetrating carrier core networks and lawful-intercept systems across multiple countries, including APJ operators (Singapore's four national carriers confirmed compromised, per Feb 2026 national assessments). Suspected — not formally confirmed — in a Feb 2026 breach of the FBI's DCSNet wiretap system.",
    targets:"Telecom carriers and ISPs, global incl. APJ",
    ttps:[["T1190","Exploit Public-Facing Application","Carrier edge-device exploitation"],["T1078","Valid Accounts","Use of captured credentials"],["T1020","Automated Exfiltration","Bulk collection from carrier systems"]],
    mit:"Guardicore Segmentation of management planes; EAA for vendor access; App & API Protector." },
  { name:"TheGentlemen", geo:["global","IN"], type:"Ransomware", rels:[["Qilin","association","reportedly emerged from a former Qilin affiliate"]], match:["The Gentlemen"], origin:"eCrime (RaaS)", motive:"Ransomware", sectors:["healthcare","manufacturing","education"], p:"P1", last:"2026-08-10",
    conf:"Emerging group; assessed with medium confidence as an affiliate-driven RaaS with deliberate India targeting.",
    overview:"Newer leak-site operation (emerged Aug 2025 from a former Qilin affiliate), now the #2 most prolific ransomware brand globally by published victim count, with a striking India concentration across healthcare, manufacturing, and education victims spanning 60+ countries.",
    targets:"Indian healthcare, manufacturing, education; wider Asia",
    ttps:[["T1486","Data Encrypted for Impact","Encryption payload"],["T1490","Inhibit System Recovery","Backup and shadow-copy deletion"]],
    mit:"Guardicore Segmentation; Akamai MFA; Security Services IR Retainer; leak-site monitoring." }
];
/* ---------------- Selected groups (curated context, self-reported/leak-site volumes — not confirmed counts, not a ranking) ---------------- */
const RANSOMWARE_RANK = [
  { name:"Qilin", stat:"~1,300–2,100+ claimed victims all-time (source-dependent); 50+ countries", note:"Dominant RaaS brand by leak-site volume through most of 2026; recurring Indian victims." },
  { name:"Akira", stat:"1,400+ claimed victims all-time; $245M+ ransom collected", note:"Consistently top-2–3 on the leaderboard; strong Linux/ESXi capability." },
  { name:"Cl0p", stat:"Hundreds of claimed victims per mass-exploitation campaign", note:"MOVEit, Oracle EBS and 2026 PTC Windchill/FlexPLM campaigns. Cumulative totals differ by tracker and counting rule, so none is quoted." },
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
// Curated context lists, deliberately unnumbered: their figures come from different reports, periods
// and counting rules, so ordering them would imply a comparison the data can't support. Measured
// rankings live on the Activity trends tab (renderAcTrends()).
function renderRankings(){
  const rEl = $("#rank-ransomware"), dEl = $("#rank-ddos");
  const rowHtml = g => '<div class="ac-sel-row"><div class="ac-sel-name">' + esc(g.name) + '</div><div class="ac-sel-stat">' + esc(g.stat) + '</div><div class="rw-dnote">' + esc(g.note) + "</div></div>";
  if (rEl) rEl.innerHTML = RANSOMWARE_RANK.map(rowHtml).join("");
  if (dEl) dEl.innerHTML = DDOS_RANK.map(rowHtml).join("");
}
const ACTORS_EDITED = "2026-10-05"; // bump when ACTORS / GLOBAL_ACTORS are edited
// Relationship types for `rels` ([name, type, note?]). Only "alias" names count as the same group
// (search, ransomware.live matching, report mentions); the rest are shown, never merged.
const REL_LABEL = { alias: "Alias / historical name", overlap: "Partially overlapping activity", affiliate: "Subgroup or affiliate", association: "Reported association", disputed: "Disputed mapping" };
// URL id for #actors/<id>: "NoName057(16)" → "noname057-16".
function actorSlug(name){ return String(name).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""); }
function mergedActors(){
  return ACTORS.map(a => Object.assign({}, a, { last: (ACTOR_META[a.name] || ["2025-01-01"])[0] }))
    .concat(GLOBAL_ACTORS.map(a => Object.assign({}, a)))
    .map(a => Object.assign(a, { id: actorSlug(a.name), aka: (a.rels || []).filter(r => r[1] === "alias").map(r => r[0]).join(" · ") || "—" }))
    .sort((a,b) => String(b.last).localeCompare(String(a.last)));
}
function actorTargetsRegion(a, key){
  if (key === "all") return true;
  return (a.geo || []).some(g => g === "global" || g === key || CC_REGION[g] === key);
}
function actorScopeLabel(a){
  const g = a.geo || [];
  if (g.includes("global")) return "Global";
  const regions = [...new Set(g.map(x => x === x.toUpperCase() ? CC_REGION[x] : x).filter(Boolean))];
  if (regions.length === 1){
    const ccs = g.filter(x => x === x.toUpperCase());
    return ccs.length === 1 && !g.includes(regions[0]) ? ccName(ccs[0]) : regionLabel(regions[0]);
  }
  return regions.map(regionLabel).join(" · ");
}
// Group names as leak sites and profiles write them differ in case/spacing ("Cl0p" / "clop").
function groupKey(name){ return String(name || "").toLowerCase().replace(/[^a-z0-9]/g, "").replace(/0/g, "o"); }

/* ---------------- State ---------------- */
let allItems = [];
let rwVictims = [];
let telegramItems = [];
let rwNewsItems = [];
let vulnItems = [];
let iocItems = [];
let DATA = { generated: null, vulnGenerated: null, infocon: "green", items: [], victims: [], telegram: [], ransomwareNews: [], iocs: [], vulnerabilities: [], ddosTelemetry: null, sourceStatus: {} };
let tgFilter = localStorage.getItem("apjti.tgFilter") || "all";
let rangeDays = parseInt(localStorage.getItem("apjti.range") || "30", 10);
let vulnFilter = localStorage.getItem("apjti.vulnFilter") || "all";
let vulnSearch = "";
let iocFilter = localStorage.getItem("apjti.iocFilter") || "all";
let iocTypeFilter = localStorage.getItem("apjti.iocTypeFilter") || "all";
let iocSearch = "";
// One region filter shared by every tab (header segment) and the map's region tabs. The old UI kept
// the map's region under apjti.region, so that's the fallback on first load.
let geo = normGeo(localStorage.getItem("apjti.geo") || localStorage.getItem("apjti.region"));
let currentRegion = geo; // the map's scope; same value, kept as its own name for the map code
let cpCC = null; // Geo Intel selection: a country code, or null for the world/region overview
let CURRENT_ACTORS = [];

/* ---------------- Tab navigation (one section visible at a time) ---------------- */
const TAB_IDS = ["brief", "country", "ransomware", "vulnerabilities", "telegram", "actors", "iocs"];
// "#country" is the Geo Intel overview, "#country/IN" its India profile; every other hash is a bare
// tab id. "#map" is the old Map tab, which Geo Intel absorbed — old links land on the overview.
// "#actors/apt41" opens that curated profile (id = actorSlug(name)).
function parseHash(h){
  let [id, arg] = String(h || "").replace(/^#/, "").split("/");
  if (id === "map") id = "country";
  return { id, cc: id === "country" && /^[A-Za-z]{2}$/.test(arg || "") ? arg.toUpperCase() : null, actor: id === "actors" && arg ? decodeURIComponent(arg).toLowerCase() : null };
}
let activeTab = "brief";
function showTab(id, opts){
  if (id === "map") id = "country"; // a stored apjti.tab from before the merge
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
  if (!(opts && opts.skipHash)) history.replaceState(null, "", "#" + id + (id === "country" && cpCC ? "/" + cpCC : ""));
  if (id === "vulnerabilities" && chartVulnMatrixInst) chartVulnMatrixInst.resize();
  if (id === "ransomware" && rwTrendInst) rwTrendInst.resize();
  closeDrawer(); // the side drawer belongs to the tab that opened it
  syncFlowAnimation(); // the Brief globe only animates while the Brief is showing
  document.body.classList.toggle("map-mode", id === "country"); // before syncView(): sizes depend on layout
  if (id === "country"){
    // Chart.js sized these canvases while their container was display:none (0×0) on first load —
    // recompute now that the section actually has layout dimensions.
    [chartTrendInst, chartGroupsInst, chartSectorsInst].forEach(c => c && c.resize());
    if (typeof rwVictims !== "undefined" && rwVictims.length) buildDashboard(); // also starts the visible view
  } else if (cpGlobe) cpGlobe.pauseAnimation();
  // Header bits that only mean something on some tabs (e.g. the Brief's tagline and Markdown
  // export) carry data-only-tabs="brief ..." and are hidden everywhere else.
  document.querySelectorAll("[data-only-tabs]").forEach(el => { el.hidden = !el.dataset.onlyTabs.split(/\s+/).includes(id); });
  if (id === "actors" || id === "country") loadApt();
  syncThemeToggle();
}
function wireTabs(){
  document.querySelectorAll(".nav-links a[href^='#']").forEach(a => {
    const id = a.getAttribute("href").slice(1);
    if (!TAB_IDS.includes(id)) return;
    a.addEventListener("click", e => { e.preventDefault(); showTab(id); });
  });
  window.addEventListener("hashchange", () => {
    const { id, cc, actor } = parseHash(location.hash);
    if (!TAB_IDS.includes(id)) return;
    if (id === "country" && cc !== cpCC && (cc || activeTab === "country")){ setCountry(cc, { skipRender: id !== activeTab }); window.scrollTo(0, 0); }
    if (id !== activeTab) showTab(id, { skipHash: true }); // closes any open drawer (and resets #actors/x)
    if (actor && rwDrawerKey !== "actor:" + actor) openActor(actor);
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
// Region filter predicates. Items carry cc/rg from the worker's geoTag(); loadData() backfills them
// for blobs written before country tagging existed.
function victimInGeo(v, key = geo){ return key === "all" || ccRegion(v.cc) === key; }
function itemInGeo(i, key = geo){ return key === "all" || (i.rg || []).includes(key); }
function geoLabel(key = geo){ return key === "all" ? "Global" : regionLabel(key); }
// Country names for an item's cc tags, each linking to that country's page.
function ccLinks(ccs, max){
  const list = (ccs || []).slice(0, max || 3);
  if (!list.length) return "";
  return list.map(cc => '<a class="tag tag-outline cc-tag" href="#country/' + esc(cc) + '">' + esc(ccName(cc)) + "</a>").join("") +
    ((ccs || []).length > list.length ? '<span class="tag tag-neutral">+' + ((ccs || []).length - list.length) + "</span>" : "");
}
// ransomware.live partially redacts some victim names (e.g. "vi***in") — commonly done for an
// ongoing negotiation or a legal request on their end, not a data quality issue on ours. Flagged
// wherever a victim name renders, so it doesn't read as broken data.
function victimNameHtml(name){
  return /\*/.test(name)
    ? '<span title="Victim name partially redacted by the source (ransomware.live) — commonly done for an ongoing negotiation or a legal request, not a data error.">' + esc(name) + "</span>"
    : esc(name);
}

/* ---------------- Data loading ---------------- */
// Parses the date and makes sure every item has cc/rg arrays. Blobs written before the worker's
// country tagging only have india/apj booleans; those map to IN / APJ until the next collection
// re-tags them from their text.
function normItem(i){
  const out = Object.assign({}, i, { date: i.date ? new Date(i.date) : null });
  if (!Array.isArray(out.cc)) out.cc = i.india ? ["IN"] : [];
  if (!Array.isArray(out.rg)) out.rg = (i.india || i.apj) ? ["apj"] : [];
  return out;
}
async function loadData(){
  const res = await fetch("/api/data");
  if (!res.ok) throw new Error("HTTP " + res.status);
  const json = await res.json();
  DATA = json;
  allItems = (json.items || []).map(normItem);
  rwVictims = (json.victims || []).slice().sort((a,b) => String(b.date||"").localeCompare(String(a.date||"")));
  telegramItems = (json.telegram || []).map(normItem);
  rwNewsItems = (json.ransomwareNews || []).map(normItem);
  vulnItems = (json.vulnerabilities || []).map(i => Object.assign({}, i, { date: i.date ? new Date(i.date) : null }));
  iocItems = (json.iocs || []).map(i => Object.assign({}, i, { firstSeen: i.firstSeen ? new Date(i.firstSeen) : null }));

  const statusEntries = Object.entries(json.sourceStatus || {});
  // Per-source tiles: count on success, the upstream error on failure. The backend doesn't keep a
  // per-source fetch time, so freshness is shown per collection job (full cycle vs CVE/RSS rotation),
  // not invented per feed.
  const tileHtml = (name, ok, detail, title) =>
    '<span class="srcpill ' + (ok ? "ok" : "fail") + '"' + (title ? ' title="' + esc(title) + '"' : "") + "><b>" + esc(name) + "</b><small>" + esc(detail) + "</small></span>";
  const failed = statusEntries.filter(([, s]) => !s.ok);
  // Newer collections record the two ransomware.live fetches themselves; older blobs don't, so fall
  // back to a tile derived from the stored claim count.
  const hasRwStatus = statusEntries.some(([name]) => name.startsWith("ransomware.live"));
  const fresh = [
    json.generated ? "Full collection " + relTime(json.generated) + " (every 30 min)" : "",
    json.vulnGenerated ? "CVE + RSS rotation " + relTime(json.vulnGenerated) + " (every 10 min)" : ""
  ].filter(Boolean).join(" · ");
  $("#srcbar").innerHTML = (fresh ? '<div class="src-fresh">' + esc(fresh) + "</div>" : "") +
    [...failed, ...statusEntries.filter(([, s]) => s.ok)].map(([name, s]) =>
      tileHtml(name, s.ok, s.ok ? s.count + " items" : (String(s.error || "unavailable").slice(0, 40)), s.ok ? name : name + " — " + (s.error || "unavailable"))
    ).join("") + (hasRwStatus ? "" : tileHtml("ransomware.live", !!rwVictims.length, rwVictims.length + " claims stored"));
  const okCount = statusEntries.filter(([,s]) => s.ok).length + (hasRwStatus ? 0 : (rwVictims.length ? 1 : 0));
  const totalCount = statusEntries.length + (hasRwStatus ? 0 : 1);
  const srcSummary = $("#srcsummary");
  if (srcSummary) srcSummary.textContent = "Sources · " + okCount + "/" + totalCount + " ok";
  // Colour of the summary dot: all ok / a few down / a quarter or more down.
  const srcDetails = srcSummary && srcSummary.closest(".src-details");
  const failCount = totalCount - okCount;
  if (srcDetails) srcDetails.dataset.health = !failCount ? "ok" : (failCount / totalCount < 0.25 ? "warn" : "bad");

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

function relTime(iso){
  const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (isNaN(m)) return "at an unknown time";
  if (m < 1) return "just now";
  if (m < 60) return m + " min ago";
  if (m < 48 * 60) return Math.round(m / 60) + " h ago";
  return Math.round(m / 1440) + " days ago";
}
function fmtDate(d){ if (!d) return ""; return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }); }

/* ---------------- Ransomware page: claims table, evidence, watchlist, drawers ----------------
   All client-side over /api/data's `victims` (leak-site claims from ransomware.live). A claim is the
   group's own post: evidence labels only ever add to that — "reported" when a vetted feed item or a
   press link names the organization, "social" when a non-mirror community post does. Leak-tracker
   bots that just repost the leak listing (Ransomlook, ransomwatch, ransomware.ninja, RedPacket
   Security, Hackmanac alerts) are the same claim repeated, so they never count as corroboration. */
const RW_PAGE_SIZE = 30;
let rwF = { q: "", group: "", cc: "", sector: "", ev: "", watch: false, day: "" };
try { const s = localStorage.getItem("apjti.sectorFilter"); if (s && s !== "all") rwF.sector = s; } catch (_){}
let rwPage = 0, rwRows = [], rwSigTab = "reports", rwTrendInst = null, rwDrawerReturn = null, rwDrawerKey = null;

function claimKey(v){ return (v.victim + "|" + v.group).toLowerCase(); }
function isoDay(d){ const t = d instanceof Date ? d : new Date(d); return isNaN(t) ? "" : t.toISOString().slice(0, 10); }
function rwWindow(){
  const a = maxDate(rwVictims.map(v => v.date));
  return a ? { end: a.getTime(), start: a.getTime() - rangeDays * 86400000 } : null;
}
function rwInWin(v, w){ return !w || !v.date || new Date(v.date).getTime() >= w.start; }
function rwScoped(w){ return rwVictims.filter(v => victimInGeo(v) && rwInWin(v, w)); }

// --- name/domain matching between claims and feed/social text (normalized, whole-word) ---
const RW_SUFFIX = /\b(inc|incorporated|llc|llp|ltd|limited|corp|corporation|co|company|gmbh|ag|sa|srl|spa|bv|nv|plc|pty|pvt|sas|sarl|ab|oy|kk|group|holdings?)\b/g;
const RW_GENERIC = new Set(["unknown", "hospital", "school", "university", "bank", "government", "city", "county", "company", "services", "solutions", "construction", "international"]);
function normText(s){ return " " + String(s || "").toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, " ").trim() + " "; }
function orgNorm(name){ return normText(name).replace(RW_SUFFIX, " ").replace(/\s+/g, " ").trim(); }
function claimPhrases(v){
  const out = [];
  const n = orgNorm(String(v.victim).replace(/^www\./i, ""));
  // Short single words ("Apex", "Nova") match far too much unrelated text to count as evidence.
  if (n && !/\*/.test(v.victim) && !RW_GENERIC.has(n) && (n.includes(" ") ? n.length >= 7 : n.length >= 9)) out.push(n);
  if (v.domain){ const d = normText(v.domain).trim(); if (d.includes(" ") && !out.includes(d)) out.push(d); }
  return out;
}
const RW_MIRROR = /\bnew (?:post|victim)s?\b|ransom group blog posts?|\bpost title:|\bgroup name:|ransomware victim:|redpacketsecurity|cyber alert|ransomlook|ransomware\.live|ransomwatch|ransomware\.ninja|victims? claimed|\bleak ?site\b/i;
function isMirrorPost(i){ return i.src === "Mastodon ransomwatch" || RW_MIRROR.test((i.title || "") + " " + (i.desc || "")); }
let rwIdx = null; // { src, ev: Map claimKey → {reports, social, mirrors}, itemClaims: Map item → [claim] }
function rwIndex(){
  if (rwIdx && rwIdx.src === rwVictims && rwIdx.items === allItems && rwIdx.social === rwNewsItems) return rwIdx;
  const byFirst = new Map();
  for (const v of rwVictims) for (const p of claimPhrases(v)){
    const f = p.split(" ")[0];
    if (!byFirst.has(f)) byFirst.set(f, []);
    byFirst.get(f).push({ p, v });
  }
  const ev = new Map(), itemClaims = new Map();
  const bucket = k => { if (!ev.has(k)) ev.set(k, { reports: [], social: [], mirrors: [] }); return ev.get(k); };
  const scan = (list, kind) => list.forEach(i => {
    const t = normText((i.title || "") + " " + (i.desc || ""));
    const hits = new Map();
    for (const tok of new Set(t.trim().split(" "))) for (const c of byFirst.get(tok) || []){
      if (!hits.has(claimKey(c.v)) && t.includes(" " + c.p + " ")) hits.set(claimKey(c.v), c);
    }
    if (!hits.size) return;
    itemClaims.set(i, [...hits.values()].map(c => c.v));
    const k = kind === "reports" ? "reports" : (isMirrorPost(i) ? "mirrors" : "social");
    hits.forEach((c, key) => bucket(key)[k].push({ item: i, on: c.p === (c.v.domain && normText(c.v.domain).trim()) ? "domain" : "name" }));
  });
  scan(allItems, "reports");
  scan([...rwNewsItems, ...telegramItems], "social");
  rwIdx = { src: rwVictims, items: allItems, social: rwNewsItems, ev, itemClaims };
  return rwIdx;
}
function claimEvidence(v){
  const e = rwIndex().ev.get(claimKey(v)) || { reports: [], social: [], mirrors: [] };
  const reported = e.reports.length + (v.press || []).length;
  return { e, reported, social: e.social.length, level: reported ? "reported" : e.social.length ? "social" : "claim" };
}

// --- watchlist (this browser only) ---
function loadWatch(){
  try { const w = JSON.parse(localStorage.getItem("apjti.rwWatch") || "{}"); return { domains: w.domains || [], names: w.names || [], sectors: w.sectors || [], countries: w.countries || [] }; }
  catch (_){ return { domains: [], names: [], sectors: [], countries: [] }; }
}
let rwWatch = loadWatch();
function watchEmpty(){ return !rwWatch.domains.length && !rwWatch.names.length && !rwWatch.sectors.length && !rwWatch.countries.length; }
// Each match says how it matched, so an uncertain name hit isn't read as a confirmed one.
function watchMatches(v){
  const out = [];
  const d = (v.domain || "").toLowerCase();
  if (d) for (const w of rwWatch.domains){
    if (d === w) out.push({ kind: "Domain", term: w, how: "exact domain" });
    else if (d.endsWith("." + w)) out.push({ kind: "Domain", term: w, how: "subdomain of " + w });
  }
  const n = orgNorm(v.victim);
  for (const w of rwWatch.names){
    const wn = orgNorm(w);
    if (!wn) continue;
    if (n === wn) out.push({ kind: "Organization", term: w, how: "same name (normalized)" });
    else if ((" " + n + " ").includes(" " + wn + " ")) out.push({ kind: "Organization", term: w, how: "uncertain — name contains “" + w + "”" });
  }
  if (v.sector && rwWatch.sectors.includes(v.sector)) out.push({ kind: "Sector", term: v.sector, how: "sector label from the source" });
  if (v.cc && rwWatch.countries.includes(v.cc)) out.push({ kind: "Country", term: ccName(v.cc), how: "victim country from the source" });
  return out;
}

// --- filtering ---
function rwFiltered(scoped){
  const q = rwF.q.trim().toLowerCase();
  return scoped.filter(v =>
    (!q || String(v.victim).toLowerCase().includes(q) || (v.domain || "").includes(q)) &&
    (!rwF.group || v.group === rwF.group) &&
    (!rwF.cc || v.cc === rwF.cc) &&
    (!rwF.sector || v.sector === rwF.sector) &&
    (!rwF.day || isoDay(v.date) === rwF.day) &&
    (!rwF.ev || claimEvidence(v).level === rwF.ev) &&
    (!rwF.watch || watchMatches(v).length));
}
function fillSelect(sel, values, current, allLabel, label){
  if (!sel) return;
  sel.innerHTML = '<option value="">' + esc(allLabel) + "</option>" +
    values.map(([val, n]) => '<option value="' + esc(val) + '">' + esc(label ? label(val) : val) + " (" + n + ")</option>").join("");
  sel.value = values.some(([val]) => val === current) ? current : "";
}
function rwChips(){
  const el = $("#rw-chips");
  const chip = (k, label) => '<button type="button" class="rw-chip" data-clear="' + k + '" aria-label="Remove filter ' + esc(label) + '">' + esc(label) + ' <span aria-hidden="true">×</span></button>';
  const evLabel = { claim: "Actor claim only", reported: "Independently reported", social: "Social mention" };
  const chips = [
    rwF.q && chip("q", "Search: " + rwF.q),
    rwF.group && chip("group", "Group: " + rwF.group),
    rwF.cc && chip("cc", "Country: " + ccName(rwF.cc)),
    rwF.sector && chip("sector", "Sector: " + rwF.sector),
    rwF.day && chip("day", "Day: " + rwF.day),
    rwF.ev && chip("ev", "Evidence: " + evLabel[rwF.ev]),
    rwF.watch && chip("watch", "Watchlist only")
  ].filter(Boolean);
  el.innerHTML = chips.length ? chips.join("") + '<button type="button" class="btn btn-ghost" data-clear="all">Clear filters</button>' : "";
}

// --- render ---
function renderRw(){
  const el = $("#rw");
  if (!el) return;
  const w = rwWindow();
  const scoped = rwScoped(w);
  const windowLabel = (geo === "all" ? "worldwide" : "in " + geoLabel()) + ", last " + rangeDays + " days";

  fillSelect($("#rw-f-group"), countByKey(scoped, "group"), rwF.group, "All groups");
  fillSelect($("#rw-f-cc"), countByKey(scoped, "cc"), rwF.cc, "All countries", cc => ccName(cc) + " · " + cc);
  fillSelect($("#sector-filter"), countByKey(scoped, "sector"), rwF.sector, "All sectors");
  $("#rw-f-group").value = rwF.group; $("#rw-f-cc").value = rwF.cc; $("#sector-filter").value = rwF.sector;
  $("#rw-f-ev").value = rwF.ev; $("#rw-f-watch").checked = rwF.watch;
  if ($("#rw-q").value !== rwF.q) $("#rw-q").value = rwF.q;
  rwChips();

  renderRwFresh();
  renderRwKpis(scoped, w);
  renderRwTrend(scoped, w);
  renderRwGroups(scoped);

  rwRows = rwFiltered(scoped);
  const pages = Math.max(1, Math.ceil(rwRows.length / RW_PAGE_SIZE));
  rwPage = Math.min(rwPage, pages - 1);
  const from = rwPage * RW_PAGE_SIZE, page = rwRows.slice(from, from + RW_PAGE_SIZE);
  $("#rw-count").innerHTML = rwRows.length
    ? "Showing <b>" + (from + 1) + "–" + (from + page.length) + "</b> of <b>" + rwRows.length + "</b> matching claims" +
      (rwRows.length !== scoped.length ? ' <span class="rw-dim">· ' + scoped.length + " " + esc(windowLabel) + "</span>" : ' <span class="rw-dim">· ' + esc(windowLabel) + "</span>")
    : "";
  $("#rw-pager").innerHTML = pages > 1
    ? '<button type="button" class="btn btn-secondary" data-page="-1"' + (rwPage ? "" : " disabled") + ' aria-label="Previous page">‹</button>' +
      '<span class="rw-dim">Page ' + (rwPage + 1) + " of " + pages + "</span>" +
      '<button type="button" class="btn btn-secondary" data-page="1"' + (rwPage < pages - 1 ? "" : " disabled") + ' aria-label="Next page">›</button>'
    : "";
  $("#rw-export").disabled = !rwRows.length;

  const stored = rwVictims.filter(v => victimInGeo(v));
  const oldest = stored.filter(v => v.date).reduce((m, v) => (!m || v.date < m) ? v.date : m, "");
  $("#rw-cov").textContent = rwVictims.length
    ? "Retained coverage: " + stored.length + " claims" + (geo !== "all" ? " in " + geoLabel() : "") + (oldest ? ", oldest " + String(oldest).slice(0, 10) : "") +
      ". Each region keeps only its newest claims (North America and Europe 500, APJ 400, smaller regions less), and most countries are back-filled from full history only every few hours — counts here are what this app retained, not every claim posted."
    : "";

  if (!page.length){
    el.innerHTML = '<tr><td colspan="6" class="empty">' + (scoped.length
      ? "No claims match these filters. <button type=\"button\" class=\"btn btn-ghost\" data-clear=\"all\">Clear filters</button>"
      : "No claims " + esc(windowLabel) + " — widen the time window or pick another region.") + "</td></tr>";
    return;
  }
  el.innerHTML = page.map(v => {
    const ev = claimEvidence(v), wm = watchMatches(v), k = esc(claimKey(v));
    return '<tr data-k="' + k + '"' + (wm.length ? ' class="rw-watched"' : "") + ">" +
      '<td data-label="Organization"><button type="button" class="rw-org" data-k="' + k + '">' + victimNameHtml(v.victim) + "</button>" +
        (wm.length ? ' <span class="tag tag-accent" title="' + esc(wm.map(m => m.kind + ": " + m.how).join("; ")) + '">Watchlist</span>' : "") +
        (v.domain && orgNorm(v.domain) !== orgNorm(v.victim) ? '<div class="rw-domain">' + esc(v.domain) + "</div>" : "") + "</td>" +
      '<td data-label="Sector" class="rw-sec">' + esc(v.sector || "—") + "</td>" +
      '<td data-label="Group"><button type="button" class="rw-grp" data-g="' + esc(v.group) + '">' + esc(v.group) + "</button></td>" +
      '<td data-label="Country">' + (v.cc ? '<a class="cc-link" href="#country/' + esc(v.cc) + '"><span class="rw-iso">' + esc(v.cc) + "</span> " + esc(ccName(v.cc)) + "</a>" : '<span class="rw-sec">Unknown</span>') + "</td>" +
      '<td data-label="Posted" class="rw-date">' + (v.date ? esc(isoDay(v.date)) : "—") + "</td>" +
      '<td data-label="Evidence">' + evidenceTags(ev) + "</td>" +
    "</tr>";
  }).join("");
}
function evidenceTags(ev){
  return '<span class="tag tag-neutral" title="The group\'s own leak-site post">Actor claim</span>' +
    (ev.reported ? ' <span class="tag tag-outline" title="Named in vetted news/advisory feeds or press links">Reported · ' + ev.reported + "</span>" : "") +
    (ev.social ? ' <span class="tag tag-neutral rw-tag-soft" title="Named in community posts that are not leak-tracker mirrors">Social · ' + ev.social + "</span>" : "");
}
function renderRwFresh(){
  const el = $("#rw-fresh");
  if (!el) return;
  const st = Object.entries(DATA.sourceStatus || {}).filter(([n]) => n.startsWith("ransomware.live"));
  const recent = st.find(([n]) => n === "ransomware.live · recent");
  const backfill = st.filter(([n]) => n !== "ransomware.live · recent").map(([n, s]) => n.split("· ")[1] + (s.ok ? "" : " (failed)"));
  el.innerHTML = [
    DATA.generated ? "Collected " + esc(relTime(DATA.generated)) + " · every 30 min" : "Not collected yet",
    recent ? (recent[1].ok ? "Latest worldwide feed: " + recent[1].count + " posts" : '<span class="rw-warn">Latest worldwide feed failed: ' + esc(String(recent[1].error || "").slice(0, 60)) + "</span>") : "",
    backfill.length ? "Full-history back-fill this cycle: " + esc(backfill.join(", ")) : ""
  ].filter(Boolean).join(" · ");
}
function renderRwKpis(scoped, w){
  const el = $("#rw-kpis");
  if (!el) return;
  const orgs = new Map();
  scoped.forEach(v => { const k = v.domain || orgNorm(v.victim); if (!orgs.has(k)) orgs.set(k, new Set()); orgs.get(k).add(v.group); });
  const multi = [...orgs.values()].filter(s => s.size > 1).length;
  const groups = countByKey(scoped, "group");
  let delta = "";
  if (w){
    const span = rangeDays * 86400000, prev = w.start - span;
    const since = rwCompleteSince(geo === "all" ? [...GEO_KEYS, "other"] : [geo]);
    if (since !== null && since <= prev){
      const n = rwVictims.filter(v => { const t = new Date(v.date).getTime(); return victimInGeo(v) && t >= prev && t < w.start; }).length;
      const d = scoped.length - n;
      delta = '<div class="d">' + (d > 0 ? "▲ " + d : d < 0 ? "▼ " + Math.abs(d) : "No change") + " vs previous " + rangeDays + " days</div>";
    } else delta = '<div class="d" title="The retained claims don\'t reach back a full previous period for this scope, so a comparison would undercount it.">No comparison — earlier period not fully retained</div>';
  }
  const watched = watchEmpty() ? null : scoped.filter(v => watchMatches(v).length).length;
  const tile = (label, value, sub, extra, attrs) => '<div class="kpi"' + (attrs || "") + '><div class="l">' + esc(label) + '</div><div class="v">' + value + '</div><div class="s">' + sub + "</div>" + (extra || "") + "</div>";
  el.innerHTML =
    tile("New claims", String(scoped.length), "Leak-site posts, last " + rangeDays + " days · " + esc(geoLabel()), delta) +
    tile("Unique organizations", String(orgs.size), multi ? multi + " claimed by more than one group" : "By domain, else normalized name") +
    tile("Active groups", String(groups.length), groups.length ? "Most posts: " + esc(groups[0][0]) + " (" + groups[0][1] + ")" : "—") +
    (watched === null
      ? tile("Watchlist matches", "—", '<button type="button" class="btn btn-ghost rw-watch-open">Set up a watchlist</button>')
      : tile("Watchlist matches", String(watched), watched ? '<button type="button" class="btn btn-ghost rw-watch-show">Show matches</button>' : "None in this period", "", watched ? ' style="border-left:4px solid var(--color-accent)"' : ""));
}
function renderRwTrend(scoped, w){
  const canvas = $("#rw-trend");
  if (!canvas || typeof Chart === "undefined" || !w) return;
  const days = [];
  for (let t = w.end; t >= w.start; t -= 86400000) days.unshift(isoDay(new Date(t)));
  const counts = Object.fromEntries(days.map(d => [d, 0]));
  scoped.forEach(v => { const d = isoDay(v.date); if (d in counts) counts[d]++; });
  const since = rwCompleteSince(geo === "all" ? [...GEO_KEYS, "other"] : [geo]);
  const gapDay = since !== null && since > w.start ? isoDay(new Date(since)) : null;
  const accent = cssToken("--color-accent"), dim = cssToken("--color-neutral-500"), sel = cssToken("--color-accent-800");
  const colors = days.map(d => d === rwF.day ? sel : (gapDay && d < gapDay ? hexA(dim, .55) : hexA(accent, .75)));
  $("#rw-trend-sub").textContent = "Observed claims within retained coverage · select a day to filter";
  $("#rw-trend-note").textContent = gapDay
    ? "Before " + gapDay + " the retained data for this scope is incomplete (grey bars undercount). Apparent changes can also reflect source availability, not attacker activity."
    : "Counts are by the day ransomware.live discovered each post. Apparent changes can reflect source availability, not only attacker activity.";
  const grid = cssToken("--color-divider"), tick = cssToken("--color-neutral-700");
  const data = { labels: days, datasets: [{ data: days.map(d => counts[d]), backgroundColor: colors, borderRadius: 2, maxBarThickness: 18 }] };
  if (rwTrendInst){ rwTrendInst.data = data; rwTrendInst.options.scales.x.ticks.color = tick; rwTrendInst.options.scales.y.ticks.color = tick; rwTrendInst.options.scales.y.grid.color = grid; rwTrendInst.update("none"); return; }
  rwTrendInst = new Chart(canvas, {
    type: "bar", data,
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => c.parsed.y + " claims" } } },
      scales: {
        x: { grid: { display: false }, ticks: { color: tick, maxRotation: 0, autoSkip: true, maxTicksLimit: 7, font: { family: "IBM Plex Mono", size: 11 }, callback(v){ return this.getLabelForValue(v).slice(5); } } },
        y: { beginAtZero: true, grid: { color: grid }, ticks: { color: tick, precision: 0, font: { family: "IBM Plex Mono", size: 11 } } }
      },
      onHover: (e, els) => { e.native.target.style.cursor = els.length ? "pointer" : "default"; },
      onClick: (e, els) => {
        if (!els.length) return;
        const d = rwTrendInst.data.labels[els[0].index];
        rwF.day = rwF.day === d ? "" : d; rwPage = 0; renderRw();
      }
    }
  });
}
function renderRwGroups(scoped){
  const el = $("#rw-groups");
  if (!el) return;
  const top = countByKey(scoped, "group").slice(0, 8);
  if (!top.length){ el.innerHTML = '<div class="empty">No claims in this period.</div>'; return; }
  const max = top[0][1];
  el.innerHTML = top.map(([g, n]) =>
    '<button type="button" class="rw-bar" data-fg="' + esc(g) + '" aria-pressed="' + (rwF.group === g) + '">' +
      '<span class="rw-bar-n">' + esc(g) + '</span><span class="rw-bar-track"><i style="width:' + Math.max(4, Math.round(n / max * 100)) + '%"></i></span><span class="rw-bar-v">' + n + "</span></button>"
  ).join("");
}

// --- reporting: corroborating reports / community signals ---
// Mastodon's RSS splits each link as "https:// " + shown part + " " + hidden rest, so drop the
// trailing path chunk too (only when it looks like one: contains - or /).
function cleanPost(s){ return String(s || "").replace(/https?:\/\/ ?\S+(?: [\w.\/?=&%~+-]*[-\/][\w.\/?=&%~+-]*)?/g, "").replace(/#\s+(\w)/g, "#$1").replace(/\s+/g, " ").trim(); }
function postAuthor(link){
  const m = /^https?:\/\/([^/]+)\/@([^/]+)/.exec(link || "");
  return m ? "@" + m[2] + "@" + m[1] : (/t\.me\//.test(link || "") ? "Telegram" : "");
}
function renderRansomwareNews(){
  const el = $("#rw-news-list");
  if (!el) return;
  document.querySelectorAll("[data-rwtab]").forEach(b => { const on = b.dataset.rwtab === rwSigTab; b.setAttribute("aria-pressed", String(on)); b.setAttribute("aria-selected", String(on)); });
  const idx = rwIndex(), w = rwWindow();
  const scopedKeys = new Set(rwScoped(w).map(claimKey));
  const claimBtn = v => '<button type="button" class="rw-org rw-inline" data-k="' + esc(claimKey(v)) + '">' + esc(v.victim) + " · " + esc(v.group) + "</button>";
  if (rwSigTab === "reports"){
    $("#rw-news-note").textContent = "Vetted news and advisory feeds that name an organization with a claim in this period (whole-word match on its name or domain, so check the article). This is independent reporting, not the organization's own confirmation.";
    const ia = maxDate(allItems.map(i => i.date));
    const rows = allItems.filter(i => idx.itemClaims.has(i) && (!ia || inWindow(i.date, ia.getTime())))
      .map(i => [i, idx.itemClaims.get(i).filter(v => scopedKeys.has(claimKey(v)))]).filter(([, cs]) => cs.length);
    rows.sort((a, b) => (b[0].date ? b[0].date.getTime() : 0) - (a[0].date ? a[0].date.getTime() : 0));
    el.innerHTML = rows.length ? rows.slice(0, 30).map(([i, cs]) =>
      '<div class="rw-signal"><div class="rw-signal-main"><a href="' + esc(i.link) + '" target="_blank" rel="noopener">' + esc(i.title) + "</a>" +
      '<div class="rw-signal-meta">' + esc(i.src) + (i.date ? " · " + esc(fmtDate(i.date)) : "") + "</div>" +
      '<div class="rw-signal-about">Mentions ' + cs.slice(0, 3).map(claimBtn).join(", ") + (cs.length > 3 ? " +" + (cs.length - 3) : "") + "</div></div></div>"
    ).join("") : '<div class="empty">No vetted report names a claimed organization in this period. Most leak-site claims never get independent coverage.</div>';
    return;
  }
  $("#rw-news-note").textContent = "Mastodon #ransomware and Telegram posts — unmoderated. Repeats of the same post or the same claim are collapsed into one entry; leak-tracker mirrors only restate the leak listing.";
  const sa = maxDate(rwNewsItems.map(i => i.date));
  const groups = new Map();
  rwNewsItems.filter(i => !sa || inWindow(i.date, sa.getTime())).forEach(i => {
    const cs = idx.itemClaims.get(i) || [];
    const inGeo = cs.length ? cs.some(v => victimInGeo(v)) : itemInGeo(i);
    if (!inGeo) return;
    const key = cs.length ? "c:" + cs.map(claimKey).sort().join(",") : "t:" + normText(cleanPost(i.desc || i.title)).trim().slice(0, 90);
    if (!groups.has(key)) groups.set(key, { posts: [], claims: cs });
    groups.get(key).posts.push(i);
  });
  const list = [...groups.values()].map(g => { g.posts.sort((a, b) => (b.date ? b.date.getTime() : 0) - (a.date ? a.date.getTime() : 0)); return g; })
    .sort((a, b) => (b.posts[0].date ? b.posts[0].date.getTime() : 0) - (a.posts[0].date ? a.posts[0].date.getTime() : 0));
  if (!list.length){ el.innerHTML = '<div class="empty">No community posts' + (geo === "all" ? "" : " about " + esc(geoLabel())) + " in the last " + rangeDays + " days.</div>"; return; }
  el.innerHTML = list.slice(0, 25).map(g => {
    const p = g.posts[0], text = cleanPost((p.desc || "").length > (p.title || "").length ? p.desc : p.title);
    const mirror = g.posts.every(isMirrorPost);
    return '<div class="rw-signal"><div class="rw-signal-main">' +
      '<p class="rw-signal-text">' + esc(text.length > 280 ? text.slice(0, 279) + "…" : text) + "</p>" +
      '<div class="rw-signal-meta">' + esc(postAuthor(p.link) || p.src) + (p.date ? " · " + esc(relTime(p.date)) : "") +
        ' · <a href="' + esc(p.link) + '" target="_blank" rel="noopener">Open post</a>' +
        (mirror ? ' · <span class="tag tag-neutral">Leak-tracker mirror</span>' : "") + "</div>" +
      (g.claims.length ? '<div class="rw-signal-about">About ' + g.claims.slice(0, 3).map(claimBtn).join(", ") + "</div>" : "") +
      (g.posts.length > 1 ? '<details class="rw-more"><summary>' + (g.posts.length - 1) + " similar post" + (g.posts.length > 2 ? "s" : "") + "</summary>" +
        g.posts.slice(1, 8).map(x => '<a href="' + esc(x.link) + '" target="_blank" rel="noopener">' + esc(postAuthor(x.link) || x.src) + (x.date ? " · " + esc(fmtDate(x.date)) : "") + "</a>").join("") + "</details>" : "") +
    "</div></div>";
  }).join("");
}

// --- drawers ---
function openDrawer(kicker, title, bodyHtml){
  const d = $("#rw-drawer");
  if (d.hidden) rwDrawerReturn = document.activeElement;
  $("#rw-drawer-kicker").textContent = kicker;
  $("#rw-drawer-title").textContent = title;
  $("#rw-drawer-body").innerHTML = bodyHtml;
  $("#rw-drawer-body").scrollTop = 0;
  d.hidden = false; $("#rw-drawer-back").hidden = false;
  document.body.classList.add("rw-drawer-open");
  $("#rw-drawer-close").focus();
}
function closeDrawer(){
  const d = $("#rw-drawer");
  if (!d || d.hidden) return;
  d.hidden = true; $("#rw-drawer-back").hidden = true;
  document.body.classList.remove("rw-drawer-open");
  rwDrawerKey = null;
  if (activeTab === "actors" && /^#actors\//.test(location.hash)) history.replaceState(null, "", "#actors");
  // Focus goes back to the row/button that opened it; the table itself was never re-rendered or scrolled.
  if (rwDrawerReturn && document.contains(rwDrawerReturn)) rwDrawerReturn.focus({ preventScroll: true });
  rwDrawerReturn = null;
}
function fmtStamp(iso){ return iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : ""; }
function dRow(label, value, note){ return "<dt>" + esc(label) + "</dt><dd>" + value + (note ? '<div class="rw-dnote">' + note + "</div>" : "") + "</dd>"; }
function loadNotes(){ try { return JSON.parse(localStorage.getItem("apjti.rwNotes") || "{}"); } catch (_){ return {}; } }
function openClaim(key){
  const v = rwVictims.find(x => claimKey(x) === key);
  if (!v) return;
  rwDrawerKey = key;
  const ev = claimEvidence(v), wm = watchMatches(v);
  const orgK = v.domain || orgNorm(v.victim);
  const others = rwVictims.filter(x => x !== v && ((v.domain && x.domain === v.domain) || orgNorm(x.victim) === orgNorm(v.victim)) && orgK);
  const sectors = [...new Set([v, ...others].map(x => x.sector).filter(Boolean))];
  const srcLink = v.link || "https://www.ransomware.live/group/" + encodeURIComponent(v.group);
  const itemLi = (x, on) => '<li><a href="' + esc(x.link) + '" target="_blank" rel="noopener">' + esc(cleanPost(x.title).slice(0, 140)) + '</a><span class="rw-dnote">' + esc(x.src) + (x.date ? " · " + esc(fmtDate(x.date)) : "") + (on ? " · matched on " + on : "") + "</span></li>";
  const note = loadNotes()[key] || "";
  openDrawer("Leak-site claim", v.victim,
    '<dl class="rw-dl">' +
      dRow("Domain", v.domain ? '<span class="mono">' + esc(v.domain) + "</span>" : '<span class="rw-dim">Not provided by the source</span>') +
      dRow("Claiming group", '<button type="button" class="rw-grp" data-g="' + esc(v.group) + '">' + esc(v.group) + "</button>") +
      dRow("Country", v.cc ? '<a class="cc-link" href="#country/' + esc(v.cc) + '"><span class="rw-iso">' + esc(v.cc) + "</span> " + esc(ccName(v.cc)) + "</a>" : "Unknown") +
      dRow("Sector", esc(v.sector || "—"), sectors.length > 1 ? "Sources label this organization differently: " + esc(sectors.join(" / ")) + "." : "Enrichment by ransomware.live; may be wrong.") +
    "</dl>" +
    '<h4 class="rw-h">Timeline</h4><dl class="rw-dl">' +
      dRow("Posted by group", v.claimed ? '<span class="mono">' + esc(fmtStamp(v.claimed)) + "</span>" : '<span class="rw-dim">Not provided separately</span>') +
      dRow("Discovered by ransomware.live", v.date ? '<span class="mono">' + esc(fmtStamp(v.date)) + "</span>" : "—") +
      dRow("First observed here", v.seen ? '<span class="mono">' + esc(fmtStamp(v.seen)) + "</span>" : '<span class="rw-dim">Before this app tracked it</span>') +
      dRow("Last listed by source", v.checked ? '<span class="mono">' + esc(fmtStamp(v.checked)) + "</span>" : '<span class="rw-dim">Unknown</span>',
        "When a collection last saw this claim. A claim that stops appearing does not mean it was resolved or a ransom paid.") +
    "</dl>" +
    '<p class="rw-dnote">None of these is the incident date. The intrusion usually happened days or weeks before the post, and the post rarely says when.</p>' +
    (v.desc ? '<h4 class="rw-h">Source description</h4><p class="rw-desc">' + esc(v.desc) + '</p><p class="rw-dnote">From ransomware.live; some descriptions are machine-generated.</p>' : "") +
    '<h4 class="rw-h">Evidence</h4><ul class="rw-ev">' +
      '<li><span class="tag tag-neutral">Actor claim</span> The group listed this organization on its leak site. <a href="' + esc(srcLink) + '" target="_blank" rel="noopener">' + (v.link ? "ransomware.live record" : "Group page on ransomware.live") + "</a></li>" +
      (ev.reported ? '<li><span class="tag tag-outline">Reported</span> Named in ' + ev.reported + " independent source" + (ev.reported > 1 ? "s" : "") + ":<ul>" +
        (v.press || []).map(u => '<li><a href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(u.replace(/^https:\/\//, "").slice(0, 70)) + '</a><span class="rw-dnote">press link from ransomware.live</span></li>').join("") +
        ev.e.reports.slice(0, 6).map(r => itemLi(r.item, r.on)).join("") + "</ul></li>" : "") +
      (ev.social ? '<li><span class="tag tag-neutral rw-tag-soft">Social</span> Mentioned in ' + ev.social + " community post" + (ev.social > 1 ? "s" : "") + ":<ul>" + ev.e.social.slice(0, 5).map(r => itemLi(r.item, r.on)).join("") + "</ul></li>" : "") +
      (ev.e.mirrors.length ? '<li><span class="rw-dim">' + ev.e.mirrors.length + " leak-tracker mirror post" + (ev.e.mirrors.length > 1 ? "s repeat" : " repeats") + " the same listing — counted as one claim, not as corroboration.</span></li>" : "") +
      '<li><span class="rw-dim">Organization statements are not tracked by this app — check the organization\'s own channels.</span></li>' +
    "</ul>" +
    (others.length ? '<h4 class="rw-h">Other claims on this organization</h4><ul class="rw-ev">' + others.slice(0, 6).map(x => '<li><button type="button" class="rw-org rw-inline" data-k="' + esc(claimKey(x)) + '">' + esc(x.group) + "</button> · " + esc(isoDay(x.date)) + "</li>").join("") + "</ul>" : "") +
    '<h4 class="rw-h">Watchlist</h4>' + (wm.length
      ? '<ul class="rw-ev">' + wm.map(m => "<li><b>" + esc(m.kind) + ":</b> " + esc(m.term) + ' <span class="rw-dim">— ' + esc(m.how) + "</span></li>").join("") + "</ul>"
      : '<p class="rw-dim">No watchlist match. <button type="button" class="btn btn-ghost rw-watch-open">Edit watchlist</button></p>') +
    '<h4 class="rw-h">Analyst notes</h4><textarea class="input rw-notes" id="rw-note" rows="4" placeholder="Triage notes, owner, ticket…" data-k="' + esc(key) + '">' + esc(note) + '</textarea><p class="rw-dnote">Saved in this browser only.</p>'
  );
}
function actorForGroup(g){
  const k = groupKey(g);
  return mergedActors().find(a => groupKey(a.name) === k || String(a.aka || "").split("·").some(t => groupKey(t) === k));
}
function openGroup(g){
  rwDrawerKey = null;
  const w = rwWindow(), all = rwVictims.filter(v => v.group === g), inWin = all.filter(v => rwInWin(v, w));
  const scopedWin = inWin.filter(v => victimInGeo(v));
  const bar = list => { const max = list.length ? list[0][1] : 1; return list.slice(0, 6).map(([k, n]) => '<div class="rw-mini"><span>' + esc(k) + '</span><span class="rw-bar-track"><i style="width:' + Math.round(n / max * 100) + '%"></i></span><b>' + n + "</b></div>").join(""); };
  const a = actorForGroup(g);
  openDrawer("Ransomware group", g,
    '<dl class="rw-dl">' +
      dRow("Claims, last " + rangeDays + " days", "<b>" + inWin.length + "</b> worldwide" + (geo !== "all" ? " · " + scopedWin.length + " in " + esc(geoLabel()) : "")) +
      dRow("Retained claims", String(all.length) + (all.length ? ' <span class="rw-dim">· ' + esc(isoDay(all[all.length - 1].date)) + " to " + esc(isoDay(all[0].date)) + "</span>" : "")) +
    "</dl>" +
    (inWin.length ? '<h4 class="rw-h">Sectors targeted</h4>' + bar(countByKey(inWin, "sector")) + '<h4 class="rw-h">Countries</h4>' + bar(countByKey(inWin, "cc").map(([cc, n]) => [ccName(cc), n])) : "") +
    '<h4 class="rw-h">Recent claims</h4><ul class="rw-ev">' + all.slice(0, 8).map(x => '<li><button type="button" class="rw-org rw-inline" data-k="' + esc(claimKey(x)) + '">' + esc(x.victim) + '</button> <span class="rw-dim">· ' + esc(x.cc || "?") + " · " + esc(isoDay(x.date)) + "</span></li>").join("") + "</ul>" +
    '<p><button type="button" class="btn btn-secondary rw-filter-group" data-g="' + esc(g) + '">Filter table to ' + esc(g) + "</button></p>" +
    '<h4 class="rw-h">Profile</h4>' + (a
      ? '<p class="rw-desc">' + esc(a.overview) + '</p><dl class="rw-dl">' + dRow("Also known as", esc(a.aka || "—")) + dRow("Origin / motive", esc(a.origin + " · " + a.motive)) +
        dRow("Techniques (ATT&CK)", a.ttps.map(t => '<span class="mono">' + esc(t[0]) + "</span> " + esc(t[1])).join("<br>")) + dRow("Mitigation (general)", esc(a.mit)) + "</dl>" +
        '<p class="rw-dnote">' + esc(a.conf) + " Curated by hand; latest reported activity " + esc(fmtLast(a.last)) + '.</p><p><a href="#actors/' + esc(a.id) + '">Full actor profile →</a></p>'
      : '<p class="rw-dim">No curated profile for this group yet.</p>') +
    '<p class="rw-links"><a href="https://www.ransomware.live/group/' + esc(encodeURIComponent(g)) + '" target="_blank" rel="noopener">ransomware.live group page</a>' +
      ' · <a href="https://www.cisa.gov/stopransomware/resources" target="_blank" rel="noopener">CISA #StopRansomware advisories</a>' +
      ' · <button type="button" class="btn btn-ghost rw-apt" data-g="' + esc(g) + '">Search the Actors directory</button></p>'
  );
}
function openWatchlist(){
  rwDrawerKey = null;
  const sectors = [...new Set(rwVictims.map(v => v.sector).filter(Boolean))].sort();
  openDrawer("Watchlist", "Watched organizations",
    '<p class="rw-dnote">Claims matching any entry are flagged in the table and counted in the header. Each match says how it matched — a name match is only a hint. Saved in this browser only.</p>' +
    '<label class="rw-lbl" for="rw-w-domains">Domains <span class="rw-dim">— one per line; also matches subdomains</span></label>' +
    '<textarea class="input" id="rw-w-domains" rows="4" placeholder="example.com">' + esc(rwWatch.domains.join("\n")) + "</textarea>" +
    '<label class="rw-lbl" for="rw-w-names">Organization names <span class="rw-dim">— one per line; customers, suppliers, aliases</span></label>' +
    '<textarea class="input" id="rw-w-names" rows="4" placeholder="Acme Logistics">' + esc(rwWatch.names.join("\n")) + "</textarea>" +
    '<label class="rw-lbl" for="rw-w-countries">Countries <span class="rw-dim">— ISO codes or names, comma-separated</span></label>' +
    '<input class="input" id="rw-w-countries" value="' + esc(rwWatch.countries.join(", ")) + '" placeholder="IN, Singapore, AU">' +
    '<fieldset class="rw-sectors"><legend class="rw-lbl">Sectors</legend>' + sectors.map(s => '<label class="rw-check"><input type="checkbox" value="' + esc(s) + '"' + (rwWatch.sectors.includes(s) ? " checked" : "") + "> " + esc(s) + "</label>").join("") + "</fieldset>" +
    '<p class="rw-dnote" id="rw-w-msg" aria-live="polite"></p>' +
    '<p><button type="button" class="btn btn-primary" id="rw-w-save">Save watchlist</button></p>'
  );
}
function saveWatchlist(){
  const lines = id => [...new Set($(id).value.split(/[\n,]/).map(s => s.trim()).filter(Boolean))];
  const domains = lines("#rw-w-domains").map(d => d.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, ""));
  const ccIn = lines("#rw-w-countries"), countries = [], bad = [];
  ccIn.forEach(c => { const cc = resolveCountry(c, true); cc ? countries.push(cc) : bad.push(c); });
  rwWatch = { domains, names: lines("#rw-w-names"), countries: [...new Set(countries)], sectors: [...document.querySelectorAll(".rw-sectors input:checked")].map(x => x.value) };
  try { localStorage.setItem("apjti.rwWatch", JSON.stringify(rwWatch)); } catch (_){}
  $("#rw-w-msg").textContent = "Saved." + (bad.length ? " Not recognized as countries: " + bad.join(", ") + "." : "");
  renderRw();
}
function rwCsv(){
  // Victim names and descriptions are attacker-written: neutralize spreadsheet formulas.
  const cell = x => { let s = String(x == null ? "" : x); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  const head = ["organization", "domain", "group", "country_code", "country", "sector", "posted_by_group", "discovered_by_ransomware_live", "first_observed_here", "last_listed_by_source", "evidence", "independent_reports", "watchlist_match", "source_record", "exported_at"];
  const now = new Date().toISOString();
  const rows = rwRows.map(v => { const ev = claimEvidence(v); return [v.victim, v.domain, v.group, v.cc, v.cc ? ccName(v.cc) : "", v.sector, v.claimed, v.date, v.seen, v.checked,
    ev.level === "reported" ? "actor claim + independent reporting" : ev.level === "social" ? "actor claim + social mention" : "actor claim only", ev.reported,
    watchMatches(v).map(m => m.kind + ": " + m.how).join("; "), v.link || "https://www.ransomware.live/group/" + encodeURIComponent(v.group), now]; });
  const csv = [head, ...rows].map(r => r.map(cell).join(",")).join("\r\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob(["﻿" + csv], { type: "text/csv" }));
  a.download = "ransomware-claims-" + (geo === "all" ? "global" : geo) + "-" + rangeDays + "d-" + now.slice(0, 10) + ".csv";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function wireRw(){
  const sec = $("#ransomware");
  if (!sec) return;
  const set = (k, v) => { rwF[k] = v; rwPage = 0; if (k === "sector") try { localStorage.setItem("apjti.sectorFilter", v || "all"); } catch (_){} renderRw(); };
  let t = null;
  $("#rw-q").addEventListener("input", e => { clearTimeout(t); t = setTimeout(() => set("q", e.target.value), 150); });
  $("#rw-f-group").addEventListener("change", e => set("group", e.target.value));
  $("#rw-f-cc").addEventListener("change", e => set("cc", e.target.value));
  $("#sector-filter").addEventListener("change", e => set("sector", e.target.value));
  $("#rw-f-ev").addEventListener("change", e => set("ev", e.target.value));
  $("#rw-f-watch").addEventListener("change", e => set("watch", e.target.checked));
  $("#rw-export").addEventListener("click", rwCsv);
  $("#rw-watch-btn").addEventListener("click", openWatchlist);
  $("#rw-drawer-close").addEventListener("click", closeDrawer);
  $("#rw-drawer-back").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });
  $("#rw-drawer").addEventListener("input", e => {
    if (e.target.id !== "rw-note") return;
    const n = loadNotes();
    if (e.target.value.trim()) n[e.target.dataset.k] = e.target.value; else delete n[e.target.dataset.k];
    try { localStorage.setItem("apjti.rwNotes", JSON.stringify(n)); } catch (_){}
  });
  const onClick = e => {
    const b = e.target.closest("button, tr[data-k]");
    if (!b) return;
    if (b.matches("[data-clear]")){
      const k = b.dataset.clear;
      if (k === "all") rwF = { q: "", group: "", cc: "", sector: "", ev: "", watch: false, day: "" }; else rwF[k] = k === "watch" ? false : "";
      if (k === "all" || k === "sector") try { localStorage.setItem("apjti.sectorFilter", "all"); } catch (_){}
      rwPage = 0; renderRw(); return;
    }
    if (b.matches("[data-page]")){ rwPage += parseInt(b.dataset.page, 10); renderRw(); $("#rw-count").scrollIntoView({ block: "nearest" }); return; }
    if (b.matches("[data-fg]")){ set("group", rwF.group === b.dataset.fg ? "" : b.dataset.fg); return; }
    if (b.matches("[data-rwtab]")){ rwSigTab = b.dataset.rwtab; renderRansomwareNews(); return; }
    if (b.matches(".rw-filter-group")){ closeDrawer(); set("group", b.dataset.g); $("#rw-chips").scrollIntoView({ block: "center" }); return; }
    if (b.matches(".rw-watch-open")){ openWatchlist(); return; }
    if (b.matches(".rw-watch-show")){ closeDrawer(); set("watch", true); return; }
    if (b.id === "rw-w-save"){ saveWatchlist(); return; }
    if (b.matches(".rw-apt")){
      closeDrawer();
      const s = $("#apt-search");
      if (s){ s.value = b.dataset.g; aptSearch = b.dataset.g.toLowerCase(); }
      showTab("actors"); renderApt(); window.scrollTo(0, 0); return;
    }
    if (b.matches(".rw-grp")){ openGroup(b.dataset.g); return; }
    if (b.matches(".rw-org") || (b.matches("tr[data-k]") && !e.target.closest("a"))){ openClaim(b.dataset.k); return; }
  };
  sec.addEventListener("click", onClick);
  $("#rw-drawer").addEventListener("click", onClick);
}

/* ---------------- Rendering: Telegram bot feed ---------------- */
function visibleTelegram(){
  let items = telegramItems.slice();
  if (tgFilter === "claims") items = items.filter(i => i.claim);
  else if (tgFilter !== "all") items = items.filter(i => i.channel === tgFilter);
  const anchor = maxDate(telegramItems.map(i => i.date));
  if (anchor) items = items.filter(i => inWindow(i.date, anchor.getTime()));
  items = items.filter(i => itemInGeo(i));
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
    el.innerHTML = '<div class="empty">No Telegram posts match this view' + (geo === "all" ? "" : " (mentioning " + esc(geoLabel()) + ")") + ' in the last ' + rangeDays + ' days.</div>';
    return;
  }
  el.innerHTML = items.map(i =>
    '<div class="card elev-sm feed-card">' +
      '<div class="feed-card-tags">' +
        '<span class="tag tag-neutral">' + esc(i.channel) + "</span>" + ccLinks(i.cc) +
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
/* ---------------- Actors page: tracked profiles, alias directory, activity trends ----------------
   Profiles are the hand-curated ACTORS/GLOBAL_ACTORS above; everything "live" on a profile (report
   mentions, leak-site claims, CVEs named alongside, IOCs) is matched from /api/data at render time
   by actorNames() — a mention is shown as a mention, never as attribution. Profiles open in the
   shared side drawer at #actors/<id> (id = actorSlug(name)), so they can be linked to. */
const ACTOR_NAME_STOP = new Set(["agenda"]); // aliases that are ordinary words
let acTab = (() => { try { const t = localStorage.getItem("apjti.acTab"); return ["tracked", "directory", "trends"].includes(t) ? t : "tracked"; } catch (_){ return "tracked"; } })();
let acQ = "", acF = { type: "", sector: "", ttp: "", recent: false, follow: false };
let aptPage = 0;
const APT_PAGE_SIZE = 25;
function loadFollow(){ try { const f = JSON.parse(localStorage.getItem("apjti.actorFollow") || "[]"); return Array.isArray(f) ? f : []; } catch (_){ return []; } }
let acFollow = loadFollow();
function actorById(id){ return mergedActors().find(a => a.id === id); }
function actorNames(a){
  return [...new Set([a.name, ...(a.rels || []).filter(r => r[1] === "alias").map(r => r[0]), ...(a.match || [])])]
    .filter(n => n.length >= 4 && !ACTOR_NAME_STOP.has(n.toLowerCase()));
}
function nameRe(n){ return new RegExp("(^|[^a-z0-9])" + n.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "[\\s_-]?") + "(?![a-z0-9])", "i"); }
let acIdx = null;
// Per actor: feed/social items naming it, its leak-site claims, and IOCs tagged with its names.
function actorIndex(){
  if (acIdx && acIdx.items === allItems && acIdx.victims === rwVictims && acIdx.iocs === iocItems) return acIdx;
  const map = new Map();
  for (const a of mergedActors()){
    const res = actorNames(a).map(nameRe);
    const hit = t => res.some(r => r.test(t));
    const keys = new Set([a.name, ...(a.rels || []).filter(r => r[1] === "alias").map(r => r[0]), ...(a.match || [])].map(groupKey));
    map.set(a.id, {
      news: allItems.filter(i => hit((i.title || "") + " " + (i.desc || ""))),
      social: [...telegramItems, ...rwNewsItems].filter(i => hit((i.title || "") + " " + (i.desc || ""))),
      claims: rwVictims.filter(v => keys.has(groupKey(v.group))),
      iocs: iocItems.filter(i => hit((i.threat || "") + " " + (i.tags || []).join(" ")))
    });
  }
  acIdx = { items: allItems, victims: rwVictims, iocs: iocItems, map };
  return acIdx;
}
function acRecent(list, days, field = "date"){
  const from = Date.now() - days * 86400000;
  return list.filter(x => { const d = x[field]; const t = d instanceof Date ? d.getTime() : Date.parse(d); return !isNaN(t) && t >= from; });
}
// Which name or field a search matched, so a hit on an alias or malware family says so.
function acSearchHit(a, q){
  if (!q) return { field: "" };
  const has = s => String(s || "").toLowerCase().includes(q);
  if (has(a.name)) return { field: "name" };
  const rel = (a.rels || []).find(r => has(r[0]));
  if (rel) return { field: REL_LABEL[rel[1]].toLowerCase(), text: rel[0] };
  const g = aptMatch(a);
  if (g){
    // Say when the hit comes from the sheet row this profile is filed under (e.g. RedEcho → Winnti Group).
    const via = g.name.toLowerCase() !== a.name.toLowerCase() ? ", filed under " + g.name : "";
    const al = (g.aliases || []).find(x => has(x.n));
    if (al) return { field: "vendor name (sheet" + via + ")", text: al.n + (al.v ? " · " + al.v : "") };
    if (has(g.malware)) return { field: "malware (sheet" + via + ")", text: String(g.malware).split(/[,;]/).map(s => s.trim()).find(has) || g.malware };
    const op = (g.ops || []).find(has);
    if (op) return { field: "operation (sheet" + via + ")", text: op };
  }
  if (has(a.overview)) return { field: "summary" };
  if ((a.ttps || []).some(t => has(t[0]) || has(t[1]))) return { field: "technique" };
  return null;
}
const AC_TYPE_CLASS = { "Espionage": "esp", "Ransomware": "rw", "Hacktivist DDoS": "hk", "Extortion": "ex", "Destructive": "ds" };
function acTypeBadge(a){ return '<span class="ac-type ac-type-' + (AC_TYPE_CLASS[a.type] || "x") + '">' + esc(a.type || a.motive) + "</span>"; }
function visibleActors(){
  const idx = actorIndex().map, q = acQ.trim().toLowerCase();
  return mergedActors().map(a => ({ a, hit: acSearchHit(a, q) })).filter(({ a, hit }) =>
    hit && (q || actorTargetsRegion(a, geo)) &&
    (!acF.type || a.type === acF.type) &&
    (!acF.sector || (a.sectors || []).includes(acF.sector)) &&
    (!acF.ttp || (a.ttps || []).some(t => t[0] === acF.ttp || t[0].startsWith(acF.ttp + "."))) &&
    (!acF.recent || acRecent([...idx.get(a.id).news, ...idx.get(a.id).social], 30).length) &&
    (!acF.follow || acFollow.includes(a.id)));
}
function renderActors(){
  CURRENT_ACTORS = mergedActors().filter(a => actorTargetsRegion(a, geo));
  renderTopTtps();
  renderRankings();
  if (!$("#actors-list")) return;
  document.querySelectorAll("[data-actab]").forEach(b => { const on = b.dataset.actab === acTab; b.setAttribute("aria-pressed", String(on)); b.setAttribute("aria-selected", String(on)); });
  ["tracked", "directory", "trends"].forEach(t => { const el = $("#ac-" + t); if (el) el.hidden = t !== acTab; });
  const all = mergedActors();
  const fill = (sel, values, cur, label) => { const el = $(sel); if (!el) return; el.innerHTML = '<option value="">' + label + "</option>" + values.map(v => '<option value="' + esc(v[0]) + '">' + esc(v[1]) + "</option>").join(""); el.value = cur; };
  fill("#ac-f-type", [...new Set(all.map(a => a.type))].sort().map(t => [t, t]), acF.type, "All types");
  fill("#ac-f-sector", [...new Set(all.flatMap(a => a.sectors || []))].sort().map(s => [s, s[0].toUpperCase() + s.slice(1)]), acF.sector, "All targeted sectors");
  const ttps = new Map(); all.forEach(a => (a.ttps || []).forEach(t => ttps.set(t[0], t[1])));
  fill("#ac-f-ttp", [...ttps].sort((x, y) => x[0].localeCompare(y[0])).map(([id, n]) => [id, id + " · " + n]), acF.ttp, "All techniques");
  $("#ac-f-recent").checked = acF.recent; $("#ac-f-follow").checked = acF.follow;
  renderAcFresh(); renderAcKpis();
  if (acTab === "tracked") renderAcTracked();
  else if (acTab === "directory") renderApt();
  else renderAcTrends();
}
function renderAcFresh(){
  const el = $("#ac-fresh");
  if (!el) return;
  el.innerHTML = mergedActors().length + " curated profiles, edited by hand (list last edited " + esc(fmtDay(ACTORS_EDITED)) + ")" +
    (aptGroups ? " · alias directory checked " + esc(fmtDay(aptMeta && aptMeta.checkedAt)) : "") +
    (DATA.generated ? " · report mentions from feeds collected " + esc(relTime(DATA.generated)) : "");
}
function renderAcKpis(){
  const el = $("#ac-kpis");
  if (!el) return;
  const idx = actorIndex().map, scope = mergedActors().filter(a => actorTargetsRegion(a, geo));
  const recent = scope.filter(a => Date.parse(a.last) >= Date.now() - 90 * 86400000).length;
  const mentioned = scope.filter(a => acRecent([...idx.get(a.id).news, ...idx.get(a.id).social], 7).length);
  const followed = acFollow.map(actorById).filter(Boolean);
  const fMentioned = followed.filter(a => acRecent([...idx.get(a.id).news, ...idx.get(a.id).social], 7).length);
  const tile = (label, value, sub) => '<div class="kpi"><div class="l">' + esc(label) + '</div><div class="v">' + value + '</div><div class="s">' + sub + "</div></div>";
  el.innerHTML =
    tile("Tracked profiles", String(scope.length), (geo === "all" ? "All regions" : "Targeting " + esc(geoLabel())) + " · of " + mergedActors().length + " curated") +
    tile("Recent reported activity", String(recent), "Profiles whose latest reported activity is within 90 days") +
    tile("Named in new reports", String(mentioned.length), "Tracked actors mentioned in feeds or Telegram, last 7 days") +
    (followed.length
      ? tile("Followed actors", String(fMentioned.length) + "<small>of " + followed.length + "</small>", "Followed and mentioned in the last 7 days")
      : tile("Followed actors", "—", "Use Follow on a profile to track it here"));
}
function acCardHtml({ a, hit }){
  const im = actorIndex().map.get(a.id);
  const rep30 = acRecent([...im.news, ...im.social], 30).length, cl30 = acRecent(im.claims, 30).length;
  const followed = acFollow.includes(a.id);
  return '<article class="card ac-card" data-acid="' + esc(a.id) + '">' +
    '<div class="ac-card-hd"><h3 class="ac-name">' + esc(a.name) + "</h3>" + acTypeBadge(a) + "</div>" +
    (hit && hit.text ? '<div class="ac-hit">Matched ' + esc(hit.field) + ": <b>" + esc(hit.text) + "</b></div>" : hit && hit.field && hit.field !== "name" ? '<div class="ac-hit">Matched in ' + esc(hit.field) + "</div>" : "") +
    '<dl class="ac-facts"><dt>Assessed affiliation</dt><dd>' + esc(a.origin) + "</dd><dt>Reported targets</dt><dd>" + esc(a.targets) + "</dd></dl>" +
    '<p class="ac-sum">' + esc(a.overview) + "</p>" +
    '<div class="ac-meta"><span>Latest reported activity: <b>' + esc(fmtLast(a.last)) + "</b></span><span>" + esc(actorScopeLabel(a)) + "</span></div>" +
    '<div class="ac-live">' +
      (rep30 ? '<span class="tag tag-outline">' + rep30 + " report" + (rep30 > 1 ? "s" : "") + " · 30 days</span>" : '<span class="tag tag-neutral">No reports · 30 days</span>') +
      (im.claims.length ? '<span class="tag tag-outline">' + cl30 + " leak-site claims · 30 days</span>" : "") +
    "</div>" +
    '<div class="ac-actions"><button type="button" class="btn btn-ghost ac-follow" data-acid="' + esc(a.id) + '" aria-pressed="' + followed + '">' + (followed ? "★ Following" : "☆ Follow") + "</button>" +
    '<button type="button" class="btn btn-secondary ac-open" data-acid="' + esc(a.id) + '">View profile →</button></div>' +
  "</article>";
}
function renderAcTracked(){
  const list = visibleActors(), total = mergedActors().filter(a => acQ || actorTargetsRegion(a, geo)).length;
  $("#ac-count").textContent = list.length + " of " + total + " profiles" + (acQ ? " matching “" + acQ + "” (all regions)" : geo === "all" ? "" : " targeting " + geoLabel()) + " · newest reported activity first";
  $("#actors-list").innerHTML = list.length ? list.map(acCardHtml).join("")
    : '<div class="empty">No curated profile matches.' + (acQ ? ' Try the <button type="button" class="btn btn-ghost" data-actab="directory">alias directory</button>, which covers ' + (aptGroups ? aptGroups.length : "hundreds of") + " records." : "") + "</div>";
}
function attackUrl(id){ return "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/"; }
function openActor(id){
  const a = actorById(id);
  if (!a) return;
  const im = actorIndex().map.get(a.id), g = aptMatch(a);
  if (activeTab === "actors") history.replaceState(null, "", "#actors/" + a.id);
  rwDrawerKey = "actor:" + a.id;
  const reports = newest([...im.news, ...im.social]).slice(0, 8);
  const cves = [...new Set(im.news.flatMap(i => ((i.title || "") + " " + (i.desc || "")).toUpperCase().match(/CVE-\d{4}-\d{4,7}/g) || []))].slice(0, 10);
  const claims30 = acRecent(im.claims, rangeDays);
  const tg = newest(im.social.filter(i => i.channel));
  const followed = acFollow.includes(a.id);
  const relGroups = Object.keys(REL_LABEL).map(t => [t, (a.rels || []).filter(r => r[1] === t)]).filter(([, l]) => l.length);
  const itemLi = i => '<li><a href="' + esc(i.link) + '" target="_blank" rel="noopener">' + esc(String(i.title || "").slice(0, 140)) + '</a><span class="rw-dnote">' + esc(i.channel ? "Telegram · " + i.channel : i.src) + (i.date ? " · " + esc(fmtDate(i.date)) : "") + "</span></li>";
  const layers = [...new Set((a.ttps || []).map(t => t[0].startsWith("T1498") ? "L3/L4 network floods (T1498)" : t[0].startsWith("T1499") ? "L7 application floods (T1499)" : "").filter(Boolean))];
  const targetCcs = (a.geo || []).filter(x => /^[A-Z]{2}$/.test(x));
  openDrawer("Actor profile · " + (a.type || a.motive), a.name,
    '<p class="ac-dhead">' + acTypeBadge(a) + ' <button type="button" class="btn btn-ghost ac-follow" data-acid="' + esc(a.id) + '" aria-pressed="' + followed + '">' + (followed ? "★ Following" : "☆ Follow") + '</button> <span class="rw-dim">Link: <a href="#actors/' + esc(a.id) + '">#actors/' + esc(a.id) + "</a></span></p>" +
    '<h4 class="rw-h">Overview</h4><p class="rw-desc ac-body">' + esc(a.overview) + "</p>" +
    '<p class="rw-dnote">Curated summary. Statements aren\'t individually sourced yet; reference material is listed under Sources.</p>' +
    '<dl class="rw-dl">' +
      dRow("Assessed affiliation", esc(a.origin)) +
      dRow("Attribution confidence", esc(a.conf)) +
      dRow("Motivation", esc(a.motive)) +
      dRow("Reported targets", esc(a.targets) + '<div class="rw-dnote">Scope: ' + esc(actorScopeLabel(a)) + "</div>") +
      dRow("Latest reported activity", esc(fmtLast(a.last)) + '<div class="rw-dnote">Curated date of the most recent activity in public reporting, not a collection date.</div>') +
      dRow("Profile list last edited", esc(fmtDay(ACTORS_EDITED))) +
    "</dl>" +
    '<h4 class="rw-h">Names and relationships</h4>' +
    (relGroups.length ? relGroups.map(([t, l]) => '<div class="ac-rel"><span class="ac-rel-t">' + esc(REL_LABEL[t]) + "</span>" + l.map(r => "<b>" + esc(r[0]) + "</b>" + (r[2] ? ' <span class="rw-dim">(' + esc(r[2]) + ")</span>" : "")).join(", ") + "</div>").join("") : '<p class="rw-dim">No aliases or relationships recorded.</p>') +
    (g ? '<div class="ac-rel"><span class="ac-rel-t">Vendor names · community sheet' + (g.name.toLowerCase() !== a.name.toLowerCase() ? " (filed under " + esc(g.name) + ")" : "") + "</span>" + esc(aptAliasText(g, 14) || "—") +
      (g.overlaps ? '<div class="rw-dnote">Sheet\'s reported overlaps: ' + esc(g.overlaps) + "</div>" : "") +
      '<div class="rw-dnote">The sheet lists names vendors use for related activity; some are partial overlaps, not the same group.</div></div>' : "") +
    '<h4 class="rw-h">Techniques (MITRE ATT&amp;CK)</h4><ul class="rw-ev">' + (a.ttps || []).map(t =>
      '<li><a class="mono" href="' + esc(attackUrl(t[0])) + '" target="_blank" rel="noopener">' + esc(t[0]) + "</a> " + esc(t[1]) + (t[2] ? '<div class="rw-dnote">Mapped from: ' + esc(t[2]) + "</div>" : "") + "</li>").join("") + "</ul>" +
    '<p class="rw-dnote">Curated mapping from the behaviour described above, using ATT&amp;CK\'s official names. No per-technique report is attached yet.</p>' +
    (a.type === "Hacktivist DDoS" ? '<h4 class="rw-h">DDoS profile</h4><dl class="rw-dl">' +
      dRow("Claimed (self-reported)", tg.length ? tg.length + " Telegram post" + (tg.length > 1 ? "s name" : " names") + " this group" + (tg.filter(i => i.claim).length ? ", " + tg.filter(i => i.claim).length + " flagged as claims" : "") + '<ul class="rw-ev ac-mini">' + tg.slice(0, 4).map(itemLi).join("") + "</ul>" : '<span class="rw-dim">No posts naming this group in the collected Telegram channels.</span>') +
      dRow("Observed (measured)", 'Measured attack traffic can\'t be attributed to a group. Cloudflare Radar telemetry for its reported targets: ' + (targetCcs.length ? targetCcs.map(cc => '<a href="#country/' + esc(cc) + '">' + esc(ccName(cc)) + "</a>").join(", ") : '<a href="#country">Geo Intel</a>')) +
      dRow("Attack layers (mapped)", layers.length ? esc(layers.join(" · ")) : "—") +
      dRow("Targeted services", esc(a.targets)) +
    "</dl>" + '<p class="rw-dnote">Infrastructure overlaps are time-bound: shared IPs or similar traffic patterns alone don\'t establish attribution.</p>' : "") +
    '<h4 class="rw-h">Recent activity in this app\'s data</h4>' +
    (reports.length ? '<ul class="rw-ev">' + reports.map(itemLi).join("") + "</ul>" : '<p class="rw-dim">No collected report or post names this actor or its aliases.</p>') +
    '<p class="rw-dnote">Whole-word matches on the name and aliases; dates are publication dates, not incident dates.</p>' +
    (im.claims.length ? '<h4 class="rw-h">Leak-site claims</h4><p>' + claims30.length + " in the last " + rangeDays + " days, " + im.claims.length + ' retained in total. <button type="button" class="rw-grp" data-g="' + esc(im.claims[0].group) + '">Open group activity</button></p>' +
      '<ul class="rw-ev">' + newest(im.claims.map(v => Object.assign({}, v, { date: v.date ? new Date(v.date) : null }))).slice(0, 5).map(v => '<li><button type="button" class="rw-org rw-inline" data-k="' + esc(claimKey(v)) + '">' + esc(v.victim) + '</button> <span class="rw-dim">· ' + esc(v.cc || "?") + " · " + esc(isoDay(v.date)) + "</span></li>").join("") + "</ul>" : "") +
    (cves.length ? '<h4 class="rw-h">CVEs named in the same reports</h4><p>' + cves.map(c => vulnItems.some(v => v.cveId === c) ? '<button type="button" class="rw-org rw-inline vn-cve mono" data-cve="' + esc(c) + '">' + esc(c) + "</button>" : '<a class="mono" href="https://nvd.nist.gov/vuln/detail/' + esc(c) + '" target="_blank" rel="noopener">' + esc(c) + "</a>").join(", ") + '</p><p class="rw-dnote">Co-mentioned in a report that names this actor. That does not establish the actor exploits them.</p>' : "") +
    (im.iocs.length ? '<h4 class="rw-h">Indicators tagged with this name</h4><p>' + im.iocs.length + ' indicator' + (im.iocs.length > 1 ? "s" : "") + ' from abuse.ch / MISP carry this actor\'s name in their threat or tags. <a href="#iocs">Open IOCs</a></p>' : "") +
    '<h4 class="rw-h">Mitigation considerations</h4><p class="rw-desc ac-body">' + esc(a.mit) + '</p><p class="rw-dnote">General guidance for the techniques above, not evidence about this actor.</p>' +
    '<h4 class="rw-h">Sources</h4><ul class="rw-ev">' +
      (g && g.mitre ? '<li>MITRE ATT&amp;CK group ' + aptMitreLink(g.mitre) + "</li>" : "") +
      (g && g.links && g.links.length ? "<li>Community sheet references: " + aptLinksHtml(g.links, 6) + "</li>" : "") +
      (a.type === "Ransomware" ? '<li><a href="https://www.ransomware.live/group/' + esc(encodeURIComponent(groupKey(a.name))) + '" target="_blank" rel="noopener">ransomware.live group page</a></li>' : "") +
      (!g && a.type !== "Ransomware" ? '<li class="rw-dim">No reference material linked yet.</li>' : "") +
    "</ul>"
  );
}
function setFollow(id){
  acFollow = acFollow.includes(id) ? acFollow.filter(x => x !== id) : [...acFollow, id];
  try { localStorage.setItem("apjti.actorFollow", JSON.stringify(acFollow)); } catch (_){}
  document.querySelectorAll('.ac-follow[data-acid="' + id + '"]').forEach(b => { const on = acFollow.includes(id); b.setAttribute("aria-pressed", String(on)); b.textContent = on ? "★ Following" : "☆ Follow"; });
  renderAcKpis();
}
function renderAcTrends(){
  const w = rwWindow(), scoped = rwScoped(w), top = countByKey(scoped, "group").slice(0, 10);
  $("#ac-rw-sub").textContent = "Last " + rangeDays + " days · " + geoLabel();
  $("#ac-rw-rank").innerHTML = top.length ? top.map(([g, n]) => '<button type="button" class="rw-bar rw-grp" data-g="' + esc(g) + '"><span class="rw-bar-n">' + esc(g) + '</span><span class="rw-bar-track"><i style="width:' + Math.max(4, Math.round(n / top[0][1] * 100)) + '%"></i></span><span class="rw-bar-v">' + n + "</span></button>").join("") : '<div class="empty">No claims in this period.</div>';
  $("#ac-rw-note").textContent = "Source: ransomware.live leak-site posts kept by this app (deduplicated per organization and group; " + scoped.length + " claims in scope). Retained coverage is capped per region, so long windows undercount. See the Ransomware tab.";
  const idx = actorIndex().map;
  const men = mergedActors().map(a => [a, acRecent([...idx.get(a.id).news, ...idx.get(a.id).social], rangeDays).length]).filter(x => x[1]).sort((x, y) => y[1] - x[1]).slice(0, 10);
  $("#ac-men-sub").textContent = "Last " + rangeDays + " days · all regions";
  $("#ac-men-rank").innerHTML = men.length ? men.map(([a, n]) => '<button type="button" class="rw-bar ac-open" data-acid="' + esc(a.id) + '"><span class="rw-bar-n">' + esc(a.name) + '</span><span class="rw-bar-track"><i style="width:' + Math.max(4, Math.round(n / men[0][1] * 100)) + '%"></i></span><span class="rw-bar-v">' + n + "</span></button>").join("") : '<div class="empty">No tracked actor named in collected reports in this period.</div>';
}
function wireActors(){
  const sec = $("#actors");
  if (!sec) return;
  let t = null;
  $("#ac-q").addEventListener("input", e => { clearTimeout(t); t = setTimeout(() => { acQ = e.target.value.trim(); aptSearch = acQ.toLowerCase(); aptPage = 0; renderActors(); }, 150); });
  const f = (sel, key, prop = "value") => $(sel).addEventListener("change", e => { acF[key] = e.target[prop]; renderActors(); });
  f("#ac-f-type", "type"); f("#ac-f-sector", "sector"); f("#ac-f-ttp", "ttp"); f("#ac-f-recent", "recent", "checked"); f("#ac-f-follow", "follow", "checked");
  const onClick = e => {
    const b = e.target.closest("button, .ac-card");
    if (!b) return;
    if (b.matches("[data-actab]")){ acTab = b.dataset.actab; try { localStorage.setItem("apjti.acTab", acTab); } catch (_){} if (acTab === "directory") loadApt(); renderActors(); return; }
    if (b.matches(".ac-follow")){ setFollow(b.dataset.acid); return; }
    if (b.matches("[data-aptpage]")){ aptPage += parseInt(b.dataset.aptpage, 10); renderApt(); $("#apt-count").scrollIntoView({ block: "nearest" }); return; }
    if (b.matches(".ac-open") || (b.matches(".ac-card") && !e.target.closest("a"))){ openActor(b.dataset.acid); return; }
    if (b.matches(".rw-grp")){ openGroup(b.dataset.g); return; }
  };
  sec.addEventListener("click", onClick);
  $("#rw-drawer").addEventListener("click", e => { const b = e.target.closest(".ac-follow, .ac-open"); if (b) onClick({ target: b }); });
}

/* ---------------- Actors: APT Groups & Operations community sheet (/api/actors) ---------------- */
// Loaded lazily the first time the Actors tab opens (~200KB, changes at most daily), not with
// /api/data. Also enriches the curated cards above with each group's vendor names from the sheet.
let aptGroups = null, aptChanges = [], aptMeta = null, aptBaseline = null, aptIndex = new Map(), aptLoading = false;
let aptTab = localStorage.getItem("apjti.aptTab") || "all";
let aptSearch = "", aptOpen = null;
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
    // Snapshots parsed before target-country tagging (worker APT_SCHEMA < 2) only have india/apj.
    aptGroups = (d.groups || []).map(g => Object.assign(g, {
      cc: g.cc || (g.india ? ["IN"] : []), rg: g.rg || ((g.india || g.apj) ? ["apj"] : []),
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
  renderGeoBody();
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
  sel.innerHTML = '<option value="all">All sheet tabs</option>' + tabs.map(t => '<option value="' + esc(t) + '">' + esc(t) + "</option>").join("");
  sel.value = aptTab;
}
function visibleApt(){
  let list = aptGroups || [];
  // A search looks across every group — "Fancy Bear" shouldn't come back empty just because a
  // region is picked. The country-tab filter still applies.
  if (aptSearch) list = list.filter(g => g._hay.includes(aptSearch));
  else if (geo !== "all") list = list.filter(g => g.rg.includes(geo));
  if (aptTab !== "all") list = list.filter(g => g.tab === aptTab);
  return list.slice().sort((a, b) => (a.label || a.name).localeCompare(b.label || b.name));
}
function fmtDay(iso){ return iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "—"; }
function renderApt(){
  const el = $("#apt-list");
  if (!el) return;
  const metaEl = $("#apt-meta"), chEl = $("#apt-changes");
  if (!aptGroups){ return; }
  const st = (aptMeta && aptMeta.status) || {};
  if (metaEl) metaEl.textContent = aptGroups.length
    ? aptGroups.length + " directory records" + (geo !== "all" ? " · " + aptGroups.filter(g => g.rg.includes(geo)).length + " target " + geoLabel() : "") + " · checked " + fmtDay(aptMeta && aptMeta.checkedAt) + (st.ok === false ? " · last check failed: " + st.error : "")
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
  const pages = Math.max(1, Math.ceil(list.length / APT_PAGE_SIZE));
  aptPage = Math.min(aptPage, pages - 1);
  const from = aptPage * APT_PAGE_SIZE, page = list.slice(from, from + APT_PAGE_SIZE);
  const countEl = $("#apt-count"), pagerEl = $("#apt-pager");
  if (countEl) countEl.innerHTML = list.length ? "Showing <b>" + (from + 1) + "–" + (from + page.length) + "</b> of <b>" + list.length + "</b> records" + (aptSearch ? " matching \u201c" + esc(aptSearch) + "\u201d" : "") : "";
  if (pagerEl) pagerEl.innerHTML = pages > 1 ? '<button type="button" class="btn btn-secondary" data-aptpage="-1"' + (aptPage ? "" : " disabled") + ' aria-label="Previous page">‹</button><span class="rw-dim">Page ' + (aptPage + 1) + " of " + pages + '</span><button type="button" class="btn btn-secondary" data-aptpage="1"' + (aptPage < pages - 1 ? "" : " disabled") + ' aria-label="Next page">›</button>' : "";
  if (!list.length){ el.innerHTML = '<tr><td colspan="5" class="empty">' + (aptGroups.length ? "No records match this view." : "No data yet.") + "</td></tr>"; return; }
  // The same group name filed under several country tabs is one name, several records.
  const tabsByName = new Map();
  aptGroups.forEach(x => { const k = String(x.name).toLowerCase(); if (!/^\?+$/.test(k)) tabsByName.set(k, [...(tabsByName.get(k) || []), x.tab]); });
  const curatedBy = new Map(mergedActors().map(a => [aptMatch(a), a]).filter(([x]) => x));
  const rows = page.map(g => {
    const other = (tabsByName.get(String(g.name).toLowerCase()) || []).filter(t => t !== g.tab);
    const cur = curatedBy.get(g);
    const row = '<tr class="apt-row" data-id="' + esc(g.id) + '">' +
      '<td data-label="Group"><b>' + esc(g.label || g.name) + "</b>" + (g.label ? ' <span class="apt-alias">(' + esc(g.name) + ")</span>" : "") +
        (other.length ? '<div class="rw-dnote">Also a record under: ' + esc([...new Set(other)].join(", ")) + "</div>" : "") +
        (cur ? '<div><button type="button" class="btn btn-ghost ac-open" data-acid="' + esc(cur.id) + '">Curated profile: ' + esc(cur.name) + " →</button></div>" : "") +
        "</td>" +
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
      f("Reported overlaps (sheet)", esc(g.overlaps)) +
      f("Comment", esc(g.comment)) +
      f("Sources", aptLinksHtml(g.links, 12)) +
      "</td></tr>";
  }).join("");
  el.innerHTML = rows;
}
function wireApt(){
  const sel = $("#apt-tab-filter");
  if (sel) sel.addEventListener("change", e => { aptTab = e.target.value; localStorage.setItem("apjti.aptTab", aptTab); aptPage = 0; renderApt(); });
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
  el.classList.remove("bempty"); // the "Loading…" placeholder style
  const anchor = maxDate(allItems.map(i => i.date));
  const items = anchor ? allItems.filter(i => inWindow(i.date, anchor.getTime())) : allItems;
  const rwAnchor = maxDate(rwVictims.map(v => v.date));
  const rw = rwAnchor ? rwVictims.filter(v => inWindow(v.date, rwAnchor.getTime())) : rwVictims;
  // Per region: leak-site claims against it and news items naming it, each with its own bar scaled
  // to that column's max, so both read correctly and the two counts are never mixed. Ordered by
  // claims (the complete-coverage signal); the selected region is pinned first and highlighted.
  const rows = GEO_KEYS.map(k => ({ k, news: items.filter(i => i.rg.includes(k)).length, claims: rw.filter(v => ccRegion(v.cc) === k).length }))
    .sort((a, b) => (b.k === geo) - (a.k === geo) || b.claims - a.claims || b.news - a.news);
  const maxC = Math.max(1, ...rows.map(r => r.claims)), maxN = Math.max(1, ...rows.map(r => r.news));
  const bar = (n, max) => '<span class="snap-num">' + n + '</span><div class="apj-barcell"><div class="apj-barfill" style="width:' + Math.round(n / max * 100) + '%"></div></div>';
  const tagged = items.filter(i => i.rg.length).length;
  const lens = items.filter(i => i.lens && itemInGeo(i)).length;
  el.innerHTML = '<div class="snap-grid">' +
    '<span class="snap-h">Region</span><span class="snap-h" title="Ransomware leak-site claims against the region">Claims</span><span class="snap-h" title="Feed items naming a country in the region">News</span>' +
    rows.map(r => '<span class="snap-rg' + (r.k === geo ? " on" : "") + '"><span class="rg-dot" style="--rc:' + regionColor(r.k) + '"></span>' + esc(regionLabel(r.k)) + "</span>" +
      '<span class="snap-cell">' + bar(r.claims, maxC) + "</span>" + '<span class="snap-cell">' + bar(r.news, maxN) + "</span>").join("") +
    "</div>" +
    '<div class="snap-foot"><span>DDoS / AppSec lens items' + (geo === "all" ? "" : " · " + esc(geoLabel())) + "</span><b>" + lens + "</b></div>" +
    '<p class="text-muted" style="font-size:11.5px;margin:6px 0 0">Last ' + rangeDays + " days. " + rw.length + " claims, " + items.length + " feed items — " + tagged +
      " of them name a country (most of the rest are CVE and IOC feeds, which carry no geography).</p>";
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
  el.classList.remove("bempty"); // the "Loading…" placeholder style; would otherwise italicise every row
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

/* ---------------- Vulnerabilities: severity colour classes (also used by the Brief) ---------------- */
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
/* ---------------- Vulnerabilities page: priority queue, KEV strip, CVE drawer, product watchlist ----------------
   Over /api/data's `vulnerabilities` (NVD CVSS 7+, GitHub Advisories, CISA KEV, merged by CVE in the
   worker, with `vx` enrichment — see the comment above cvssSourceName() in src/worker.js). Priority is
   a transparent tier policy (vulnPriority()), spelled out on the page under "How prioritization works";
   keep the two in step. EPSS_LIKELY is the one EPSS line used by the tiers, the filter and the matrix. */
const EPSS_LIKELY = 0.1;
const VN_PAGE_SIZE = 25;
const VN_TIERS = { 1: "Act now", 2: "Likely exploited", 3: "Severe", 4: "Monitor" };
let vnDays = (() => { try { const d = parseInt(localStorage.getItem("apjti.vnDays"), 10); return [0, 7, 30, 90].includes(d) ? d : 0; } catch (_){ return 0; } })();
let vnDateField = (() => { try { return localStorage.getItem("apjti.vnDateField") || "activity"; } catch (_){ return "activity"; } })();
let vnSort = "priority", vnPage = 0, vnRows = [];
if (!["all", "kev", "likely", "critical", "watch", "waf"].includes(vulnFilter)) vulnFilter = "all";

function vxOf(v){ return v.vx || {}; }
function vnTime(s){ const t = s ? Date.parse(s) : NaN; return isNaN(t) ? null : t; }
function vnDates(v){
  const vx = vxOf(v);
  return {
    published: vnTime(vx.published) || (v.kev ? null : (v.date ? v.date.getTime() : null)),
    modified: vnTime(vx.modified),
    kev: vnTime(vx.kevAdded) || (v.kev && v.date ? v.date.getTime() : null),
    seen: vnTime(v.seen)
  };
}
function vnDateOf(v, field){
  const d = vnDates(v);
  return field === "activity" ? Math.max(d.published || 0, d.modified || 0, d.kev || 0) || null : d[field];
}
function fmtIsoDay(t){ return t ? new Date(t).toISOString().slice(0, 10) : ""; }
function vnProducts(v){ return (vxOf(v).products || []).filter(p => p.product); }
// "Cisco" + "Cisco Catalyst SD-WAN Manager" → just the product.
function vnProdName(p){
  const first = String(p.vendor || "").split(/\s+/)[0].toLowerCase();
  return first && String(p.product).toLowerCase().startsWith(first) ? p.product : [p.vendor, p.product].filter(Boolean).join(" ");
}
function vnProductLabel(v){
  const p = vnProducts(v)[0];
  return p ? vnProdName(p) : "";
}
// Titles from NVD are just "CVE-… (CVSS n)"; KEV and GitHub carry a real name.
function vnShortTitle(v){
  const t = String(v.title || "").replace(/^GHSA-[\w-]+ \(CVE-[\d-]+\): /, "");
  if (t && !/^CVE-\d+-\d+( \(CVSS [\d.]+\))?$/.test(t)) return t;
  const d = String(v.desc || "").replace(/^CVSS [\d.]+\. |^Severity: \w+\. /, "");
  const s = d.split(/(?<=\.)\s/)[0] || d;
  return s.length > 140 ? s.slice(0, 139) + "…" : s;
}

// --- product watchlist (this browser) ---
function loadVnWatch(){ try { const w = JSON.parse(localStorage.getItem("apjti.vulnWatch") || "[]"); return Array.isArray(w) ? w : []; } catch (_){ return []; } }
let vnWatch = loadVnWatch();
function vnNorm(s){ return " " + String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim() + " "; }
// A product match says nothing about the version in use — the drawer shows the affected ranges.
function vnWatchMatches(v){
  if (!vnWatch.length) return [];
  const out = [];
  const prods = vnProducts(v).length ? vnProducts(v) : (v.vendor || v.product ? [{ vendor: v.vendor, product: v.product, src: "CISA KEV" }] : []);
  for (const w of vnWatch){
    const wn = vnNorm(w).trim();
    if (!wn) continue;
    const p = prods.find(p => vnNorm((p.vendor || "") + " " + p.product).includes(" " + wn + " ") || vnNorm(p.product).includes(" " + wn + " "));
    if (p) out.push({ term: w, product: vnProdName(p), inferred: p.src === "inferred" });
  }
  return out;
}

// --- browser-local assessment ---
function loadVnAssess(){ try { return JSON.parse(localStorage.getItem("apjti.vulnAssess") || "{}"); } catch (_){ return {}; } }
const VN_STATUS = { "": "Not assessed", affected: "Affected", not_affected: "Not affected", mitigated: "Mitigated", fixed: "Fixed" };
const VN_EDGE_ASSESS = { "": "Not tested", validated: "Rule validated in our environment", ineffective: "Rule not effective / not applicable here" };

// --- priority ---
function vnExploitSignals(v){
  const vx = vxOf(v), out = [];
  if (v.kev) out.push({ k: "kev", text: "Known exploited · CISA KEV" + (vx.kevAdded ? ", added " + vx.kevAdded : "") });
  if (vx.ssvc === "active") out.push({ k: "active", text: "CISA SSVC: exploitation active" });
  if (vx.maturity === "ATTACKED") out.push({ k: "active", text: "CNA reports attacks (CVSS 4.0 E:A)" });
  if (vx.refs && vx.refs.exploit) out.push({ k: "poc", text: "Public exploit referenced (NVD tag)" });
  if (vx.maturity === "PROOF_OF_CONCEPT") out.push({ k: "poc", text: "Proof of concept reported by CNA (E:P)" });
  if (vx.ssvc === "poc") out.push({ k: "poc", text: "CISA SSVC: proof of concept" });
  return out;
}
function vulnPriority(v){
  const ex = vnExploitSignals(v), vx = vxOf(v), reasons = [];
  const watched = vnWatchMatches(v);
  let tier = 4;
  if (ex.some(e => e.k === "kev" || e.k === "active")) tier = 1;
  else if ((v.epss != null && v.epss >= EPSS_LIKELY) || ex.some(e => e.k === "poc")) tier = 2;
  else if (v.cvssScore != null && v.cvssScore >= 9) tier = 3;
  ex.forEach(e => reasons.push({ text: e.text, hot: e.k !== "poc" }));
  if (vx.kevRansomware) reasons.push({ text: "Known ransomware use", hot: true });
  if (watched.length) reasons.push({ text: "Watched product: " + watched[0].product + (watched[0].inferred ? " (inferred)" : ""), watch: true });
  if (v.epss != null && v.epss >= EPSS_LIKELY) reasons.push({ text: "EPSS " + (v.epss * 100).toFixed(1) + "%" + (v.epssPercentile != null ? " · top " + Math.max(1, Math.round((1 - v.epssPercentile) * 100)) + "%" : "") });
  if (v.cvssScore != null && v.cvssScore >= 9) reasons.push({ text: "CVSS " + v.cvssScore.toFixed(1) + " critical" });
  return { tier, label: VN_TIERS[tier], reasons, watched: watched.length > 0 };
}
function vnFixInfo(v){
  const vx = vxOf(v);
  const fixed = vnProducts(v).map(p => p.fixed).filter(Boolean);
  if (fixed.length) return { cls: "fix", text: "Fixed in " + fixed[0].split(", ")[0] + (fixed.length > 1 || /,/.test(fixed[0]) ? " +" : "") };
  if (vx.refs && vx.refs.patch) return { cls: "fix", text: "Patch referenced" };
  if (vx.refs && vx.refs.advisory) return { cls: "adv", text: "Vendor advisory" };
  if (vx.kevAction) return { cls: "adv", text: "CISA action set" };
  return { cls: "none", text: "Not stated" };
}
const VN_EDGE = { documented: "Documented rule", potential: "Potential", na: "Not applicable", unknown: "Unknown" };
function vnEdge(v){ return (vxOf(v).edge) || { cls: "unknown", why: "Not classified yet" }; }

// --- scope + filters ---
function vnScoped(){
  if (!vnDays) return vulnItems.slice();
  const from = Date.now() - vnDays * 86400000;
  return vulnItems.filter(v => { const t = vnDateOf(v, vnDateField); return t != null && t >= from; });
}
function visibleVulns(){
  let list = vnScoped();
  if (vulnFilter === "critical") list = list.filter(v => v.cvssScore != null && v.cvssScore >= 9);
  else if (vulnFilter === "kev") list = list.filter(v => vulnPriority(v).tier === 1);
  else if (vulnFilter === "likely") list = list.filter(v => vulnPriority(v).tier === 2);
  else if (vulnFilter === "watch") list = list.filter(v => vnWatchMatches(v).length);
  else if (vulnFilter === "waf") list = list.filter(v => ["potential", "documented"].includes(vnEdge(v).cls));
  if (vulnSearch) list = list.filter(v => (v.cveId + " " + v.title + " " + vnProducts(v).map(p => p.vendor + " " + p.product).join(" ") + " " + (v.vendor || "") + " " + (v.product || "") + " " + (v.desc || "")).toLowerCase().includes(vulnSearch));
  const num = x => x == null ? -1 : x;
  const P = new Map(list.map(v => [v, vulnPriority(v)]));
  const byDate = f => (a, b) => num(vnDateOf(b, f)) - num(vnDateOf(a, f));
  const sorts = {
    priority: (a, b) => (P.get(a).tier - P.get(b).tier) || (Number(P.get(b).watched) - Number(P.get(a).watched)) || (num(b.epss) - num(a.epss)) || (num(b.cvssScore) - num(a.cvssScore)) || byDate("activity")(a, b),
    cvss: (a, b) => (num(b.cvssScore) - num(a.cvssScore)) || (num(b.epss) - num(a.epss)),
    epss: (a, b) => (num(b.epss) - num(a.epss)) || (num(b.cvssScore) - num(a.cvssScore)),
    published: byDate("published"), modified: byDate("modified"), kev: byDate("kev")
  };
  return list.sort(sorts[vnSort] || sorts.priority);
}
function vnPeriodLabel(){
  const f = { activity: "latest activity", published: "published", modified: "last updated", kev: "added to KEV" }[vnDateField];
  return vnDays ? f + " in the last " + vnDays + " days" : "all " + vulnItems.length + " retained CVEs";
}

// --- render ---
function cvssCell(v){
  if (v.cvssScore == null) return '<span class="rw-dim" title="No CVSS score published yet">Not scored</span>';
  const sev = v.cvssScore >= 9 ? "Critical" : v.cvssScore >= 7 ? "High" : v.cvssScore >= 4 ? "Medium" : "Low";
  return '<span class="cvss-badge ' + cvssClass(v.cvssScore) + '" title="CVSS ' + esc(vxOf(v).cvssVer || "") + " base score, " + sev.toLowerCase() + ' severity">' + v.cvssScore.toFixed(1) + '</span><div class="vn-sub">' + sev + (vxOf(v).cvssVer ? " · v" + esc(vxOf(v).cvssVer) : "") + "</div>";
}
function epssCell(v){
  if (v.epss == null) return '<span class="rw-dim">—</span>';
  return '<span class="vn-epss' + (v.epss >= EPSS_LIKELY ? " vn-epss-hi" : "") + '" title="Probability of exploitation activity in the next 30 days (FIRST EPSS' + (v.epssDate ? ", scored " + esc(v.epssDate) : "") + ')">' + (v.epss * 100).toFixed(v.epss < 0.01 ? 2 : 1) + "%</span>" +
    (v.epssPercentile != null ? '<div class="vn-sub">' + Math.round(v.epssPercentile * 100) + "th pct</div>" : "");
}
function exploitCell(v){
  const ex = vnExploitSignals(v);
  if (v.kev) return '<span class="tag vn-kev-tag">Known exploited</span><div class="vn-sub">CISA KEV' + (vxOf(v).kevRansomware ? " · ransomware use" : "") + "</div>";
  if (ex.some(e => e.k === "active")) return '<span class="tag vn-kev-tag">Exploitation reported</span><div class="vn-sub">' + esc(ex.find(e => e.k === "active").text.split(" (")[0]) + "</div>";
  if (ex.length) return '<span class="tag tag-outline">Public PoC / exploit</span>';
  return '<span class="rw-dim">No evidence collected</span>';
}
function renderVulnerabilities(){
  const el = $("#vuln-list");
  if (!el) return;
  document.querySelectorAll("[data-vf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.vf === vulnFilter)));
  document.querySelectorAll("[data-vd]").forEach(x => x.setAttribute("aria-pressed", String(parseInt(x.dataset.vd, 10) === vnDays)));
  const fieldSel = $("#vn-date-field"); if (fieldSel) fieldSel.value = vnDateField;
  const sortSel = $("#vn-sort"); if (sortSel) sortSel.value = vnSort;
  const scoped = vnScoped();
  $("#vn-scope").textContent = scoped.length + " CVEs · " + vnPeriodLabel();
  renderVnFresh(); renderVnKpis(scoped); renderVnKev(scoped); renderVnChanges();

  vnRows = visibleVulns();
  const pages = Math.max(1, Math.ceil(vnRows.length / VN_PAGE_SIZE));
  vnPage = Math.min(vnPage, pages - 1);
  const from = vnPage * VN_PAGE_SIZE, page = vnRows.slice(from, from + VN_PAGE_SIZE);
  $("#vn-count").innerHTML = vnRows.length ? "Showing <b>" + (from + 1) + "–" + (from + page.length) + "</b> of <b>" + vnRows.length + "</b> CVEs" + (vnRows.length !== scoped.length ? ' <span class="rw-dim">· ' + scoped.length + " in period</span>" : "") : "";
  $("#vn-pager").innerHTML = pages > 1
    ? '<button type="button" class="btn btn-secondary" data-vpage="-1"' + (vnPage ? "" : " disabled") + ' aria-label="Previous page">‹</button><span class="rw-dim">Page ' + (vnPage + 1) + " of " + pages + '</span><button type="button" class="btn btn-secondary" data-vpage="1"' + (vnPage < pages - 1 ? "" : " disabled") + ' aria-label="Next page">›</button>'
    : "";
  const covEl = $("#vuln-cov");
  if (covEl){
    const noProd = vulnItems.filter(v => !vnProducts(v).some(p => p.src !== "inferred")).length;
    covEl.textContent = vulnItems.length
      ? "Retained: " + vulnItems.length + " CVEs. Every KEV entry added in the last year is kept, then likely-exploited CVEs, then CVSS 9+, then the newest. NVD's feed here covers CVSS 7+ published in the last two days of each run, so older lower-severity CVEs are not tracked. " +
        noProd + " have no structured product data yet; KEV and GitHub-only CVEs are filled from NVD a few at a time."
      : "";
  }
  if (chartVulnMatrixInst || ($("#vn-analysis") && $("#vn-analysis").open)) renderVulnMatrix(vnRows);
  if (!page.length){ el.innerHTML = '<tr><td colspan="7" class="empty">No CVEs match this view' + (vnDays ? " — try a longer period." : ".") + "</td></tr>"; return; }
  const assess = loadVnAssess();
  el.innerHTML = page.map(v => {
    const pr = vulnPriority(v), fx = vnFixInfo(v), ed = vnEdge(v), prod = vnProductLabel(v), inferred = vnProducts(v)[0] && vnProducts(v)[0].src === "inferred";
    const a = assess[v.cveId];
    return '<tr data-cve="' + esc(v.cveId) + '"' + (pr.watched ? ' class="rw-watched"' : "") + ">" +
      '<td data-label="Vulnerability"><button type="button" class="rw-org vn-cve" data-cve="' + esc(v.cveId) + '">' + esc(v.cveId) + "</button>" +
        (a && a.status ? ' <span class="tag tag-neutral" title="Your assessment">' + esc(VN_STATUS[a.status]) + "</span>" : "") +
        '<div class="vn-title">' + esc(vnShortTitle(v)) + "</div>" +
        '<div class="vn-prod">' + (prod ? esc(prod) + (inferred ? ' <span class="rw-dim" title="Pattern-matched from the description, not a structured field">· inferred</span>' : "") : '<span class="rw-dim">Product not yet mapped</span>') + "</div></td>" +
      '<td data-label="Priority"><span class="vn-tier vn-t' + pr.tier + '">' + esc(pr.label) + "</span>" +
        (pr.reasons.length ? '<div class="vn-reasons">' + pr.reasons.slice(0, 2).map(r => esc(r.text)).join("<br>") + (pr.reasons.length > 2 ? ' <span class="rw-dim">+' + (pr.reasons.length - 2) + "</span>" : "") + "</div>" : "") + "</td>" +
      '<td data-label="CVSS">' + cvssCell(v) + "</td>" +
      '<td data-label="EPSS">' + epssCell(v) + "</td>" +
      '<td data-label="Exploitation">' + exploitCell(v) + "</td>" +
      '<td data-label="Fix"><span class="vn-fix vn-fix-' + fx.cls + '">' + esc(fx.text) + "</span></td>" +
      '<td data-label="Edge"><span class="vn-edge vn-edge-' + ed.cls + '" title="' + esc(ed.why) + '">' + esc(VN_EDGE[ed.cls]) + "</span>" +
        (a && a.edge ? '<div class="vn-sub">' + (a.edge === "validated" ? "Validated here" : "Not effective here") + "</div>" : "") + "</td>" +
    "</tr>";
  }).join("");
}
function renderVnFresh(){
  const el = $("#vn-fresh");
  if (!el) return;
  const st = DATA.sourceStatus || {};
  const bad = ["NVD (High/Critical)", "GitHub Advisories", "CISA KEV", "EPSS"].filter(n => st[n] && !st[n].ok);
  const epssDay = vulnItems.map(v => v.epssDate).filter(Boolean).sort().pop();
  el.innerHTML = [
    DATA.vulnGenerated ? "Sources checked " + esc(relTime(DATA.vulnGenerated)) + " · every 10 min" : "",
    epssDay ? "EPSS scores dated " + esc(epssDay) : "",
    st["NVD backfill"] ? "NVD backfill: " + (st["NVD backfill"].ok ? st["NVD backfill"].count + " CVEs this run" : "failed") : "",
    bad.length ? '<span class="rw-warn">Failed this run: ' + esc(bad.join(", ")) + "</span>" : ""
  ].filter(Boolean).join(" · ");
}
function renderVnKpis(scoped){
  const el = $("#vn-kpis");
  if (!el) return;
  const kev = scoped.filter(v => v.kev);
  const kevDays = vnDays || 7;
  const newKev = vulnItems.filter(v => { const t = vnDates(v).kev; return v.kev && t != null && t >= Date.now() - kevDays * 86400000; });
  const watched = vnWatch.length ? scoped.filter(v => vnWatchMatches(v).length) : null;
  const noProd = scoped.filter(v => !vnProducts(v).some(p => p.src !== "inferred")).length, noCvss = scoped.filter(v => v.cvssScore == null).length;
  const tile = (label, value, sub, extra) => '<div class="kpi"><div class="l">' + esc(label) + '</div><div class="v">' + value + '</div><div class="s">' + sub + "</div>" + (extra || "") + "</div>";
  el.innerHTML =
    tile("Known exploited", String(kev.length), "CISA KEV entries in this view · " + kev.filter(v => vxOf(v).kevRansomware).length + " with ransomware use") +
    tile("Newly added to KEV", String(newKev.length), "Last " + kevDays + " days" + (newKev.length ? ' · <button type="button" class="btn btn-ghost" data-vf-go="kev">Review</button>' : "")) +
    (watched === null
      ? tile("Watched-product matches", "—", '<button type="button" class="btn btn-ghost vn-watch-open">Choose products to watch</button>')
      : tile("Watched-product matches", String(watched.length), (watched.length ? '<button type="button" class="btn btn-ghost" data-vf-go="watch">Show matches</button> · ' : "") + "product name only, not your version")) +
    tile("Missing enrichment", String(noProd), "No structured product · " + noCvss + " without CVSS");
}
function renderVnKev(scoped){
  const el = $("#vn-kev");
  if (!el) return;
  const kev = scoped.filter(v => v.kev).sort((a, b) => (vnDates(b).kev || 0) - (vnDates(a).kev || 0));
  if (!kev.length){ el.innerHTML = '<div class="vn-kev-head"><b>Known exploited</b><span class="rw-dim">No CISA KEV additions in this period.</span></div>'; return; }
  const today = Date.now();
  el.innerHTML = '<div class="vn-kev-head"><b>Known exploited: review regardless of EPSS</b><span class="rw-dim">' + kev.length + " in this period. EPSS and CVSS don't lower the priority of a CVE that is already being exploited.</span></div>" +
    '<div class="vn-kev-list">' + kev.slice(0, 6).map(v => {
      const vx = vxOf(v), due = vnTime(vx.kevDue), w = vnWatchMatches(v).length;
      return '<button type="button" class="vn-kev-item vn-cve" data-cve="' + esc(v.cveId) + '">' +
        '<span class="vn-kev-id">' + esc(v.cveId) + (w ? ' <span class="tag tag-accent">Watched</span>' : "") + "</span>" +
        '<span class="vn-kev-prod">' + esc(vnProductLabel(v) || vnShortTitle(v)) + "</span>" +
        '<span class="vn-sub">Added ' + esc(vx.kevAdded || fmtIsoDay(vnDates(v).kev)) + (due ? " · CISA due " + esc(vx.kevDue) + (due < today ? " (passed)" : "") : "") + (vx.kevRansomware ? " · ransomware use" : "") + "</span></button>";
    }).join("") + "</div>" +
    (kev.length > 6 ? '<button type="button" class="btn btn-ghost" data-vf-go="kev">Show all ' + kev.length + " in the queue</button>" : "");
}
function renderVnChanges(){
  const el = $("#vn-changes");
  if (!el) return;
  const days = vnDays || 7, from = Date.now() - days * 86400000;
  $("#vn-changes-sub").textContent = "Last " + days + " days · from source timestamps; record contents aren't compared between runs yet";
  const ev = [];
  vulnItems.forEach(v => {
    const d = vnDates(v), pr = vulnPriority(v);
    if (v.kev && d.kev && d.kev >= from) ev.push({ t: d.kev, kind: "Added to CISA KEV", v, hot: true });
    else if (d.modified && d.modified >= from && (!d.published || d.modified - d.published > 2 * 86400000) && (pr.tier === 1 || pr.watched)) ev.push({ t: d.modified, kind: "Record updated", v });
    // A PoC flag alone is common on small web-app CVEs, so new arrivals only list here when they matter.
    else if (d.seen && d.seen >= from && !v.kev && (pr.watched || (v.epss != null && v.epss >= EPSS_LIKELY))) ev.push({ t: d.seen, kind: pr.watched ? "Newly tracked · watched" : "Newly tracked · EPSS " + (v.epss * 100).toFixed(0) + "%", v });
  });
  ev.sort((a, b) => b.t - a.t);
  el.innerHTML = ev.length ? ev.slice(0, 15).map(e =>
    '<div class="rw-signal vn-change"><span class="vn-change-kind' + (e.hot ? " hot" : "") + '">' + esc(e.kind) + "</span>" +
    '<button type="button" class="rw-org rw-inline vn-cve" data-cve="' + esc(e.v.cveId) + '">' + esc(e.v.cveId) + "</button> " +
    '<span class="vn-change-what">' + esc(vnProductLabel(e.v) || vnShortTitle(e.v)) + '</span><span class="rw-dim vn-change-t">' + esc(fmtIsoDay(e.t)) + "</span></div>"
  ).join("") : '<div class="empty">No KEV additions, updates to exploited or watched CVEs, or new CVEs with EPSS ≥ 10% in the last ' + days + " days.</div>";
}

// --- CVE drawer ---
const VN_SRC_LABEL = { CNA: "CVE record (CNA)", "NVD CPE": "NVD CPE", GitHub: "GitHub advisory", "CISA KEV": "CISA KEV (no versions)", inferred: "Inferred from description — unverified" };
function vnVector(vec){
  const m = {}; String(vec || "").split("/").forEach(p => { const [k, val] = p.split(":"); if (k && val) m[k] = val; });
  return m;
}
function vnRefList(urls){ return (urls || []).map(u => '<li><a href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(u.replace(/^https:\/\//, "").slice(0, 80)) + "</a></li>").join(""); }
function openVuln(id){
  const v = vulnItems.find(x => x.cveId === id);
  if (!v) return;
  const vx = vxOf(v), pr = vulnPriority(v), ed = vnEdge(v), d = vnDates(v), vec = vnVector(vx.vec), refs = vx.refs || {};
  const a = loadVnAssess()[id] || {};
  const related = allItems.filter(i => i.src !== "NVD" && i.src !== "GitHub Advisories" && ((i.title || "") + " " + (i.desc || "")).toUpperCase().includes(id)).slice(0, 6);
  const prods = vnProducts(v);
  const opt = (map, cur) => Object.entries(map).map(([k, l]) => '<option value="' + k + '"' + (k === (cur || "") ? " selected" : "") + ">" + esc(l) + "</option>").join("");
  const prereq = [vec.AV && ({ N: "Network", A: "Adjacent network", L: "Local", P: "Physical" }[vec.AV] + " attack vector"),
    vec.PR && ({ N: "no privileges", L: "low privileges", H: "high privileges" }[vec.PR] + " required"),
    vec.UI && ({ N: "no user interaction", R: "user interaction required", P: "passive user interaction", A: "active user interaction" }[vec.UI]),
    vec.AC === "H" || vec.AT === "P" ? "special conditions required" : ""].filter(Boolean);
  openDrawer("CVE · " + pr.label, id,
    (String(v.desc || "").includes(vnShortTitle(v).replace(/…$/, "")) ? "" : '<p class="rw-desc"><b>' + esc(vnShortTitle(v)) + "</b></p>") +
    (pr.reasons.length ? '<ul class="vn-why">' + pr.reasons.map(r => '<li class="' + (r.hot ? "hot" : r.watch ? "watch" : "") + '">' + esc(r.text) + "</li>").join("") + "</ul>" : '<p class="rw-dim">No exploitation or severity signal beyond being tracked.</p>') +
    (v.desc ? '<p class="rw-desc">' + esc(String(v.desc).replace(/^CVSS [\d.]+\. |^Severity: \w+\. /, "")) + (String(v.desc).length >= 280 ? " …" : "") + '</p>' : "") +
    '<p class="rw-links"><a href="https://nvd.nist.gov/vuln/detail/' + esc(id) + '" target="_blank" rel="noopener">NVD record</a>' + (v.link && !/nvd\.nist/.test(v.link) ? ' · <a href="' + esc(v.link) + '" target="_blank" rel="noopener">Source advisory</a>' : "") + ' · <a href="https://www.cve.org/CVERecord?id=' + esc(id) + '" target="_blank" rel="noopener">CVE.org</a></p>' +

    '<h4 class="rw-h">Affected products</h4>' + (prods.length
      ? '<ul class="rw-ev">' + prods.map(p => "<li><b>" + esc(vnProdName(p)) + "</b>" +
          (p.versions ? '<div class="vn-sub">Affected: <span class="mono">' + esc(p.versions) + "</span></div>" : "") +
          (p.fixed ? '<div class="vn-sub">Fixed: <span class="mono">' + esc(p.fixed) + "</span></div>" : "") +
          '<div class="rw-dnote">Source: ' + esc(VN_SRC_LABEL[p.src] || p.src) + ' · <button type="button" class="btn btn-ghost vn-watch-add" data-term="' + esc(vnProdName(p)) + '">Watch ' + esc(vnProdName(p)) + "</button></div></li>").join("") + "</ul>" +
        (vnWatchMatches(v).length ? '<p class="rw-dnote">Matches your watched products by name. Whether your installed version is affected isn\'t checked.</p>' : "")
      : '<p class="rw-dim">Product not yet mapped by any source. NVD analysis often adds it within days.</p>') +

    '<h4 class="rw-h">Exploitation evidence</h4><ul class="rw-ev">' +
      (v.kev ? '<li><span class="tag vn-kev-tag">CISA KEV</span> Added ' + esc(vx.kevAdded || fmtIsoDay(d.kev)) + (vx.kevDue ? " · due " + esc(vx.kevDue) + ' <span class="rw-dim">(US federal deadline)</span>' : "") + (vx.kevRansomware ? " · known ransomware use" : "") +
        (vx.kevNotes ? ' · <a href="' + esc(vx.kevNotes) + '" target="_blank" rel="noopener">CISA notes</a>' : "") + "</li>" : "") +
      (vx.ssvc ? "<li>CISA SSVC exploitation: <b>" + esc(vx.ssvc) + "</b></li>" : "") +
      (vx.maturity ? "<li>CVSS 4.0 exploit maturity (from the CNA): <b>" + esc(vx.maturity.toLowerCase().replace(/_/g, " ")) + "</b></li>" : "") +
      (refs.exploit ? "<li>Exploit references (NVD tag):<ul>" + vnRefList(refs.exploit) + "</ul></li>" : "") +
      (!v.kev && !vx.ssvc && !vx.maturity && !refs.exploit ? '<li class="rw-dim">No exploitation evidence collected. Absence here is not evidence of safety.</li>' : "") +
      (v.epss != null ? "<li>EPSS <b>" + (v.epss * 100).toFixed(2) + "%</b> probability of exploitation activity in the next 30 days" + (v.epssPercentile != null ? " · " + Math.round(v.epssPercentile * 100) + "th percentile" : "") + (v.epssDate ? " · scored " + esc(v.epssDate) : "") +
        '<div class="rw-dnote">A population-level estimate from FIRST, not a measure of whether your organization will be targeted or compromised.</div></li>' : "") +
    "</ul>" +

    '<h4 class="rw-h">Remediation</h4><ul class="rw-ev">' +
      (prods.some(p => p.fixed) ? "<li>Fixed versions: " + prods.filter(p => p.fixed).map(p => esc(p.product) + ' <span class="mono">' + esc(p.fixed) + "</span>").join("; ") + "</li>" : "") +
      (vx.kevAction ? "<li>CISA required action: " + esc(vx.kevAction) + "</li>" : "") +
      (refs.patch ? "<li>Patches:<ul>" + vnRefList(refs.patch) + "</ul></li>" : "") +
      (refs.advisory ? "<li>Vendor advisories:<ul>" + vnRefList(refs.advisory) + "</ul></li>" : "") +
      (refs.mitigation ? "<li>Mitigations:<ul>" + vnRefList(refs.mitigation) + "</ul></li>" : "") +
      (refs.thirdParty ? "<li>Third-party advisories:<ul>" + vnRefList(refs.thirdParty) + "</ul></li>" : "") +
      (!prods.some(p => p.fixed) && !vx.kevAction && !refs.patch && !refs.advisory && !refs.mitigation ? '<li class="rw-dim">No fix or advisory stated by the sources yet.</li>' : "") +
      (refs.other ? '<li>Other references:<ul>' + vnRefList(refs.other) + "</ul></li>" : "") +
    "</ul>" +

    '<h4 class="rw-h">Edge / WAF applicability</h4>' +
    '<p><span class="vn-edge vn-edge-' + ed.cls + '">' + esc(VN_EDGE[ed.cls]) + "</span> " + esc(ed.why) + (ed.cls === "potential" ? " — preliminary classification." : "") + "</p>" +
    (ed.cls === "potential" || ed.cls === "documented" ? '<dl class="rw-dl">' +
      dRow("Protocol", "HTTP(S), assumed from the weakness class") +
      dRow("Endpoint", ed.path ? '<span class="mono">' + esc(ed.path) + "</span>" : '<span class="rw-dim">Not stated</span>') +
      dRow("Parameter", ed.param ? '<span class="mono">' + esc(ed.param) + "</span>" : '<span class="rw-dim">Not stated</span>') +
      (ed.component ? dRow("Component", esc(ed.component)) : "") +
      dRow("Prerequisites", prereq.length ? esc(prereq.join(", ")) : '<span class="rw-dim">No CVSS vector</span>') +
      dRow("Rule reference", ed.ref ? '<a href="' + esc(ed.ref) + '" target="_blank" rel="noopener">' + esc(ed.ref.replace(/^https:\/\//, "").slice(0, 60)) + "</a>" : '<span class="rw-dim">None found in the references</span>') +
    "</dl>" + '<p class="rw-dnote">Limits: a signature rule reduces exposure but doesn\'t fix the flaw. Encodings, authenticated paths, non-standard ports and traffic that bypasses the edge can all evade it. Patch regardless.</p>' : "") +

    '<h4 class="rw-h">Scores and dates</h4><dl class="rw-dl">' +
      dRow("CVSS", v.cvssScore != null ? "<b>" + v.cvssScore.toFixed(1) + "</b> · v" + esc(vx.cvssVer || "?") + " · scored by " + esc(vx.cvssSrc || "unknown") : '<span class="rw-dim">Not scored yet</span>') +
      (vx.vec ? dRow("Vector", '<span class="mono vn-vec">' + esc(vx.vec.replace(/\/[A-Z]{1,3}:X/g, "")) + "</span>") : "") +
      (vx.cwes && vx.cwes.length ? dRow("Weakness", vx.cwes.map(c => '<a href="https://cwe.mitre.org/data/definitions/' + esc(c.slice(4)) + '.html" target="_blank" rel="noopener">' + esc(c) + "</a>").join(", ")) : "") +
      dRow("Published", d.published ? '<span class="mono">' + esc(fmtIsoDay(d.published)) + "</span>" : '<span class="rw-dim">Not known here</span>') +
      dRow("Last updated", d.modified ? '<span class="mono">' + esc(fmtIsoDay(d.modified)) + "</span>" : '<span class="rw-dim">Not known here</span>') +
      (v.kev ? dRow("Added to KEV", '<span class="mono">' + esc(vx.kevAdded || fmtIsoDay(d.kev)) + "</span>") : "") +
      dRow("First seen here", d.seen ? '<span class="mono">' + esc(fmtIsoDay(d.seen)) + "</span>" : '<span class="rw-dim">Before tracking began</span>') +
      dRow("NVD status", vx.status ? esc(vx.status) + (vx.nvdAt ? ' <span class="rw-dim">· read ' + esc(fmtIsoDay(vnTime(vx.nvdAt))) + "</span>" : "") : '<span class="rw-dim">Not read from NVD yet</span>') +
    "</dl>" +

    (related.length ? '<h4 class="rw-h">Related reporting</h4><ul class="rw-ev">' + related.map(i => '<li><a href="' + esc(i.link) + '" target="_blank" rel="noopener">' + esc(i.title) + '</a><span class="rw-dnote">' + esc(i.src) + (i.date ? " · " + esc(fmtDate(i.date)) : "") + "</span></li>").join("") + "</ul>" : "") +

    '<h4 class="rw-h">Your assessment</h4>' +
    '<label class="rw-lbl" for="vn-a-status">Status</label><select class="input" id="vn-a-status" data-cve="' + esc(id) + '">' + opt(VN_STATUS, a.status) + "</select>" +
    '<label class="rw-lbl" for="vn-a-edge">Edge rule</label><select class="input" id="vn-a-edge" data-cve="' + esc(id) + '">' + opt(VN_EDGE_ASSESS, a.edge) + "</select>" +
    '<label class="rw-lbl" for="vn-a-notes">Notes</label><textarea class="input rw-notes" id="vn-a-notes" rows="3" data-cve="' + esc(id) + '" placeholder="Owner, exposure, ticket…">' + esc(a.notes || "") + "</textarea>" +
    '<p class="rw-dnote">Saved in this browser only.</p>'
  );
}
function saveVnAssess(id, key, val){
  const all = loadVnAssess(), cur = Object.assign({}, all[id]);
  if (val) cur[key] = val; else delete cur[key];
  if (Object.keys(cur).length) all[id] = cur; else delete all[id];
  try { localStorage.setItem("apjti.vulnAssess", JSON.stringify(all)); } catch (_){}
}
function openVnWatch(){
  openDrawer("Watched products", "Your technology stack",
    '<p class="rw-dnote">One product or vendor per line, e.g. <span class="mono">FortiOS</span>, <span class="mono">Confluence</span>, <span class="mono">Microsoft Exchange</span>. Matches are by name against each CVE\'s products. They don\'t confirm that your version is affected; the CVE panel shows the affected ranges. Saved in this browser only.</p>' +
    '<textarea class="input" id="vn-w-list" rows="10" placeholder="FortiOS&#10;Citrix NetScaler&#10;nginx">' + esc(vnWatch.join("\n")) + "</textarea>" +
    '<p class="rw-dnote" id="vn-w-msg" aria-live="polite"></p><p><button type="button" class="btn btn-primary" id="vn-w-save">Save</button></p>');
}
function setVnWatch(list){
  vnWatch = [...new Set(list.map(s => s.trim()).filter(Boolean))];
  try { localStorage.setItem("apjti.vulnWatch", JSON.stringify(vnWatch)); } catch (_){}
  renderVulnerabilities();
}
function wireVulns(){
  const sec = $("#vulnerabilities");
  if (!sec) return;
  let t = null;
  $("#vuln-search").addEventListener("input", e => { clearTimeout(t); t = setTimeout(() => { vulnSearch = e.target.value.trim().toLowerCase(); vnPage = 0; renderVulnerabilities(); }, 150); });
  $("#vn-sort").addEventListener("change", e => { vnSort = e.target.value; vnPage = 0; renderVulnerabilities(); });
  $("#vn-date-field").addEventListener("change", e => { vnDateField = e.target.value; try { localStorage.setItem("apjti.vnDateField", vnDateField); } catch (_){} vnPage = 0; renderVulnerabilities(); });
  $("#vn-watch-btn").addEventListener("click", openVnWatch);
  const analysis = $("#vn-analysis");
  if (analysis) analysis.addEventListener("toggle", () => { if (analysis.open) renderVulnMatrix(vnRows); });
  const onClick = e => {
    const b = e.target.closest("button, tr[data-cve]");
    if (!b) return;
    if (b.matches("[data-vf]")){ vulnFilter = b.dataset.vf; try { localStorage.setItem("apjti.vulnFilter", vulnFilter); } catch (_){} vnPage = 0; renderVulnerabilities(); return; }
    if (b.matches("[data-vf-go]")){ closeDrawer(); vulnFilter = b.dataset.vfGo; vnPage = 0; renderVulnerabilities(); $(".vn-filters").scrollIntoView({ block: "start" }); return; }
    if (b.matches("[data-vd]")){ vnDays = parseInt(b.dataset.vd, 10); try { localStorage.setItem("apjti.vnDays", String(vnDays)); } catch (_){} vnPage = 0; renderVulnerabilities(); return; }
    if (b.matches("[data-vpage]")){ vnPage += parseInt(b.dataset.vpage, 10); renderVulnerabilities(); $("#vn-count").scrollIntoView({ block: "nearest" }); return; }
    if (b.matches(".vn-watch-open")){ openVnWatch(); return; }
    if (b.id === "vn-w-save"){ setVnWatch($("#vn-w-list").value.split("\n")); $("#vn-w-msg").textContent = "Saved · " + vnWatch.length + " product" + (vnWatch.length === 1 ? "" : "s") + "."; return; }
    if (b.matches(".vn-watch-add")){ setVnWatch([...vnWatch, b.dataset.term]); b.textContent = "Watching " + b.dataset.term; b.disabled = true; return; }
    if (b.matches(".vn-cve") || (b.matches("tr[data-cve]") && !e.target.closest("a"))){ openVuln(b.dataset.cve); return; }
  };
  sec.addEventListener("click", onClick);
  $("#rw-drawer").addEventListener("click", onClick);
  $("#rw-drawer").addEventListener("change", e => {
    if (e.target.id === "vn-a-status") saveVnAssess(e.target.dataset.cve, "status", e.target.value);
    else if (e.target.id === "vn-a-edge") saveVnAssess(e.target.dataset.cve, "edge", e.target.value);
    else return;
    renderVulnerabilities();
  });
  $("#rw-drawer").addEventListener("input", e => { if (e.target.id === "vn-a-notes") saveVnAssess(e.target.dataset.cve, "notes", e.target.value.trim() ? e.target.value : ""); });
}

/* ---------------- Vulnerabilities: CVSS × EPSS triage matrix ---------------- */
// Scatter of the rows currently visible in the table (same filter + search), so it answers "which of
// these are severe AND likely to be exploited" at a glance. EPSS is on a log axis: almost every score
// is under 1%, and a linear axis would pile them all onto the floor. Colours come from the theme
// tokens, so the chart is re-rendered on theme toggle (wireThemeToggle) and resized on tab open.
const EPSS_MIN = 0.0001;
const MATRIX_CVSS_LINE = 9, MATRIX_EPSS_LINE = EPSS_LIKELY; // CVSS "critical"; = EPSS_LIKELY, the priority tiers' line
// CVEs with EPSS but no CVSS go in a lane left of the CVSS axis instead of being dropped: CISA KEV
// entries arrive without a CVSS score, so without this lane the chart would hide every
// actively-exploited CVE — the ones it matters most to see. Points are spread across the lane by a
// stable per-CVE offset so they don't stack into one column.
const MATRIX_LANE = [-1.7, -0.3];
function laneX(id){
  let h = 0;
  for (const c of String(id)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return MATRIX_LANE[0] + 0.15 + (h % 1000) / 1000 * (MATRIX_LANE[1] - MATRIX_LANE[0] - 0.3);
}
let chartVulnMatrixInst = null;
// = VICTIM_CAPS in src/worker.js: each region keeps its newest N claims.
const VICTIM_CAPS = { na: 500, eu: 500, apj: 400, sa: 150, me: 150, af: 100, other: 200 };
// Earliest time from which the stored claims for these regions are complete: a region whose bucket
// is full has lost everything older than its oldest kept claim; one below its cap hasn't (back to
// the oldest claim collected at all). Used so period-over-period deltas never compare against a
// period the cache only partly covers.
function rwCompleteSince(regions){
  let since = -Infinity, oldest = Infinity;
  for (const r of regions){
    const times = rwVictims.filter(v => ccRegion(v.cc) === r).map(v => new Date(v.date).getTime()).filter(t => !isNaN(t));
    if (!times.length) continue;
    const min = Math.min(...times);
    oldest = Math.min(oldest, min);
    if (times.length >= VICTIM_CAPS[r]) since = Math.max(since, min);
  }
  return oldest === Infinity ? null : Math.max(since, oldest);
}
// Read from <html>, not <body>: body.map-mode forces the dark tokens while the Map tab is open, and the
// matrix can re-render then (5-min poll, theme toggle) — it would keep dark colours in light theme.
function cssToken(name){ return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
function hexA(hex, a){
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || "");
  if (!m) return hex;
  const n = parseInt(m[1], 16);
  return "rgba(" + (n >> 16) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
}
function renderVulnMatrix(list){
  const canvas = document.getElementById("chartVulnMatrix");
  const note = $("#vuln-matrix-note");
  if (!canvas || typeof Chart === "undefined") return;
  const pts = list.filter(v => v.epss != null).map(v => ({
    x: v.cvssScore != null ? v.cvssScore : laneX(v.cveId), y: Math.max(EPSS_MIN, v.epss), v
  }));
  const hot = pts.filter(p => p.v.cvssScore != null && p.x >= MATRIX_CVSS_LINE && p.v.epss >= MATRIX_EPSS_LINE).length;
  // Fit the CVSS axis to the data: the lane only when something is in it, and start one point below the
  // lowest score (production is NVD CVSS 7+ only, so a fixed 0–10 axis squeezed every point into the
  // right third). Never start above the CVSS 9 guide, so the severe corner is always on screen.
  const hasLane = pts.some(p => p.v.cvssScore == null);
  const scored = pts.filter(p => p.v.cvssScore != null).map(p => p.x);
  const cvssFloor = scored.length ? Math.max(0, Math.min(MATRIX_CVSS_LINE - 1, Math.floor(Math.min(...scored)) - 1)) : 0;
  // Lane width scales with the visible CVSS span so it stays about 15% of the plot.
  const laneW = (10 - cvssFloor) * 0.16;
  const lane = [cvssFloor - laneW - 0.2, cvssFloor - 0.2];
  if (hasLane) pts.forEach(p => { if (p.v.cvssScore == null) p.x = lane[0] + (p.x - MATRIX_LANE[0]) / (MATRIX_LANE[1] - MATRIX_LANE[0]) * laneW; });
  const laneHot = pts.filter(p => p.v.cvssScore == null && p.v.epss >= MATRIX_EPSS_LINE).length;
  if (note) note.textContent = pts.length
    ? pts.length + " plotted of " + list.length + " in view (needs an EPSS score) · " + hot + " in the shaded corner" +
      (laneHot ? " · " + laneHot + " more above 10% EPSS with no CVSS" : "") +
      (pts.some(p => p.v.kev) ? " · red points are known exploited wherever they sit" : "")
    : "Nothing to plot — no CVE in this view has an EPSS score.";
  const red = cssToken("--lvl-red"), accent = cssToken("--color-accent"), text = cssToken("--color-text"),
    muted = cssToken("--color-neutral-700"), line = cssToken("--color-divider"), mono = "'IBM Plex Mono', ui-monospace, monospace";
  const datasets = [
    { label: "Known exploited (CISA KEV)", data: pts.filter(p => p.v.kev), backgroundColor: hexA(red, .8), borderColor: red, pointRadius: 5, pointHoverRadius: 7 },
    { label: "No known exploitation", data: pts.filter(p => !p.v.kev), backgroundColor: hexA(accent, .45), borderColor: accent, pointRadius: 3.5, pointHoverRadius: 6 }
  ];
  const tick = { color: muted, font: { family: mono, size: 10 } };
  const options = {
    responsive: true, maintainAspectRatio: false, animation: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: cssToken("--color-panel"), borderColor: line, borderWidth: 1, titleColor: text, bodyColor: muted,
        titleFont: { family: mono, size: 11 }, bodyFont: { family: mono, size: 10.5 }, padding: 10, cornerRadius: 8,
        callbacks: {
          title: items => items[0].raw.v.cveId + (items[0].raw.v.kev ? "  · known exploited (KEV)" : ""),
          label: item => {
            const v = item.raw.v;
            return [
              "CVSS " + (v.cvssScore != null ? v.cvssScore.toFixed(1) : "not scored"),
              "EPSS probability " + (v.epss * 100).toFixed(2) + "% (next 30 days)",
              v.epssPercentile != null ? "EPSS percentile " + Math.round(v.epssPercentile * 100) + "th" : "",
              v.epssDate ? "EPSS scored " + v.epssDate : "",
              vnProductLabel(v).slice(0, 60)
            ].filter(Boolean);
          }
        }
      }
    },
    scales: {
      x: { min: hasLane ? lane[0] : cvssFloor, max: 10, title: { display: true, text: "CVSS severity →", color: muted, font: { family: mono, size: 10 } },
        afterBuildTicks: ax => { ax.ticks = Array.from({ length: 11 - cvssFloor }, (_, i) => ({ value: cvssFloor + i })); },
        ticks: { ...tick }, grid: { color: hexA(line, .6) }, border: { display: false } },
      y: { type: "logarithmic", min: EPSS_MIN, max: 1, title: { display: true, text: "EPSS probability (log scale) →", color: muted, font: { family: mono, size: 10 } },
        ticks: { ...tick, callback: val => [0.0001, 0.001, 0.01, 0.1, 1].includes(val) ? (val * 100) + "%" : null }, grid: { color: hexA(line, .6) }, border: { display: false } }
    },
    onHover: (e, els) => { e.native.target.style.cursor = els.length ? "pointer" : "default"; },
    // Clicking a point opens that CVE's panel.
    onClick: (e, els, chart) => {
      if (!els.length) return;
      openVuln(chart.data.datasets[els[0].datasetIndex].data[els[0].index].v.cveId);
    }
  };
  // Quadrant guides: CVSS 9 / EPSS 10%, with the severe-and-likely corner shaded. The plugin is bound
  // once at chart creation, so per-render values (theme colours, lane position) are read from
  // chart.$matrix rather than closed over — a closure would keep the first render's theme and lane.
  const matrixState = { hasLane, lane, red, muted, mono };
  const quadrants = {
    id: "vulnQuadrants",
    beforeDatasetsDraw(chart){
      if (!chart.$matrix) return; // first draw happens inside new Chart(), before $matrix is attached
      const { hasLane, lane, red, muted, mono } = chart.$matrix;
      const { ctx, chartArea: a, scales: { x, y } } = chart;
      const qx = x.getPixelForValue(MATRIX_CVSS_LINE), qy = y.getPixelForValue(MATRIX_EPSS_LINE);
      ctx.save();
      if (hasLane){
        const l0 = x.getPixelForValue(lane[0]), l1 = x.getPixelForValue(lane[1]);
        ctx.fillStyle = hexA(muted, .08); ctx.fillRect(l0, a.top, l1 - l0, a.bottom - a.top);
        ctx.fillStyle = muted; ctx.font = "600 9.5px " + mono; ctx.textAlign = "center"; ctx.textBaseline = "top";
        ctx.fillText("NO CVSS", (l0 + l1) / 2, a.bottom + 6);
      }
      ctx.fillStyle = hexA(red, .07); ctx.fillRect(qx, a.top, a.right - qx, qy - a.top);
      ctx.strokeStyle = hexA(red, .45); ctx.setLineDash([4, 4]); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(qx, a.top); ctx.lineTo(qx, a.bottom); ctx.moveTo(a.left, qy); ctx.lineTo(a.right, qy); ctx.stroke();
      ctx.setLineDash([]); ctx.fillStyle = hexA(red, .85); ctx.font = "600 10px " + mono; ctx.textAlign = "right"; ctx.textBaseline = "top";
      ctx.fillText("CVSS ≥ 9 · EPSS ≥ 10%", a.right - 6, a.top + 6);
      ctx.restore();
    }
  };
  if (chartVulnMatrixInst){
    chartVulnMatrixInst.$matrix = matrixState;
    chartVulnMatrixInst.data.datasets = datasets;
    chartVulnMatrixInst.options = options;
    chartVulnMatrixInst.update();
  } else {
    chartVulnMatrixInst = new Chart(canvas, { type: "scatter", data: { datasets }, options, plugins: [quadrants] });
    chartVulnMatrixInst.$matrix = matrixState;
    chartVulnMatrixInst.update();
  }
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
  const list = mergedActors().filter(a => actorTargetsRegion(a, geo));
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

/* ---------------- Rendering: header KPI row ---------------- */
// Four headline numbers shown above every tab except Map (which has its own KPI strip). All derived
// from the /api/data payload; the ransomware count follows the header time window like renderSnapshot().
function renderKpis(){
  const el = $("#kpis");
  if (!el) return;
  const level = String(DATA.infocon || "green").toLowerCase();
  const labelMap = { green: "Low", yellow: "Elevated", orange: "High", red: "Severe" };
  const rwAnchor = maxDate(rwVictims.map(v => v.date));
  const rw = rwAnchor ? rwVictims.filter(v => inWindow(v.date, rwAnchor.getTime())) : rwVictims;
  const rwScope = rw.filter(v => victimInGeo(v)).length;
  const kevWeek = (DATA.kev || []).filter(k => { const a = daysAgo(k.dateAdded); return a !== null && a <= 7; });
  const kevRw = kevWeek.filter(k => k.ransomware).length;
  // Change vs the previous period of equal length — only when the stored data reaches back that far,
  // otherwise it would report a fake drop (see rwCompleteSince()). kev is capped at 100 the same way.
  let rwDelta = null, kevDelta = null;
  if (rwAnchor){
    const span = rangeDays * 86400000, cur = rwAnchor.getTime() - span, prev = cur - span;
    const since = rwCompleteSince(geo === "all" ? [...GEO_KEYS, "other"] : [geo]);
    if (since !== null && since <= prev){
      const prevN = rwVictims.filter(v => { const t = new Date(v.date).getTime(); return victimInGeo(v) && t >= prev && t < cur; }).length;
      rwDelta = [rwScope - prevN, "vs previous " + rangeDays + " days"];
    }
  }
  const kevAges = (DATA.kev || []).map(k => daysAgo(k.dateAdded)).filter(a => a !== null);
  if (kevAges.length && Math.max(...kevAges) >= 14){
    kevDelta = [kevWeek.length - kevAges.filter(a => a > 7 && a <= 14).length, "vs previous 7 days"];
  }
  // Neutral colour on purpose: more claims isn't "good" or "bad" in a way a green/red arrow would imply.
  const deltaHtml = d => !d ? "" : '<div class="d">' + (d[0] > 0 ? "▲ " + d[0] : d[0] < 0 ? "▼ " + Math.abs(d[0]) : "No change") + " " + esc(d[1]) + "</div>";
  const epssHigh = vulnItems.filter(v => v.epss != null && v.epss >= 0.5).length;
  const tile = (cls, label, value, small, sub, delta) =>
    '<div class="kpi ' + cls + '"><div class="l">' + (cls.includes("infocon") ? '<span class="dot" aria-hidden="true"></span>' : "") + esc(label) + "</div>" +
    '<div class="v">' + esc(String(value)) + (small ? "<small>" + esc(small) + "</small>" : "") + "</div>" +
    '<div class="s">' + esc(sub) + "</div>" + deltaHtml(delta) + "</div>";
  el.innerHTML =
    tile("infocon lvl-" + level, "INFOCON", labelMap[level] || level, "", "SANS Internet Storm Center level") +
    tile("", (geo === "all" ? "" : geoLabel() + " ") + "ransomware claims", rwScope, geo === "all" ? "" : "of " + rw.length + " worldwide", "Leak-site claims, last " + rangeDays + " days — unconfirmed", rwDelta) +
    tile("", "KEV added", kevWeek.length, kevRw ? kevRw + " with ransomware use" : "", "CISA Known Exploited, last 7 days", kevDelta) +
    tile("", "EPSS ≥ 50%", epssHigh, "/ " + vulnItems.length + " CVEs tracked", "Likely exploited within 30 days (FIRST.org)");
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
// Brief sections, shared by the page and the Markdown export. With a region picked it leads with that
// region; with "All" it leads with the newest developments, then a per-region pulse.
function briefSections(pool, victims){
  const scoped = pool.filter(i => itemInGeo(i));
  const rw = victims.filter(v => victimInGeo(v));
  const lens = scoped.filter(i => i.lens);
  if (geo === "all"){
    const pulse = GEO_KEYS.map(k => {
      const its = pool.filter(i => i.rg.includes(k));
      return { k, items: its, claims: victims.filter(v => ccRegion(v.cc) === k).length };
    }).filter(r => r.items.length || r.claims);
    return { lead: { title: "Key developments", items: pool }, rw, lens, pulse, rest: null };
  }
  return { lead: { title: geoLabel() + " — priority", items: scoped }, rw, lens, pulse: null,
    rest: { title: "Elsewhere — key developments", items: pool.filter(i => !itemInGeo(i)) } };
}
function renderStructuredBrief(pool, victims){
  const b = briefSections(pool, victims);
  function newsBullets(list, max){
    if (!list.length) return '<div class="bempty">Nothing notable in this window.</div>';
    return '<ul class="blist">' + list.slice(0, max || 6).map(i => bulletLi(null, i.title + (i.desc ? " — " + i.desc.slice(0,140) : ""), [i])).join("") + "</ul>";
  }
  function rwBullets(list){
    if (!list.length) return '<div class="bempty">No claims in this window.</div>';
    return '<ul class="blist">' + list.map(v =>
      "<li><b>" + esc(v.group) + ":</b> claims " + esc(v.victim) + (v.sector ? " (" + esc(v.sector) + ")" : "") + " — " +
      (v.cc ? '<a class="cc-link" href="#country/' + esc(v.cc) + '">' + esc(ccName(v.cc)) + "</a>" : "unknown country") + (v.date ? ", " + esc(String(v.date).slice(0,10)) : "") + "</li>"
    ).join("") + "</ul>";
  }
  let html = "";
  html += '<div class="bsec pri"><div class="bhdr"><span class="n">1</span> ' + esc(b.lead.title) + "</div>" + newsBullets(b.lead.items, 8) + "</div>";
  html += '<div class="bsec"><div class="bhdr">Ransomware Watch' + (geo === "all" ? "" : " — " + esc(geoLabel())) + "</div>" + rwBullets(b.rw.slice(0, 8)) + "</div>";
  html += '<div class="bsec"><div class="bhdr">DDoS &amp; AppSec Lens</div>' + newsBullets(b.lens, 6) + "</div>";
  if (b.pulse) html += '<div class="bsec"><div class="bhdr">Regional pulse</div>' + (b.pulse.length ? '<ul class="blist">' + b.pulse.map(r =>
    '<li><b><span class="rg-dot" style="--rc:' + regionColor(r.k) + '"></span> ' + esc(regionLabel(r.k)) + ":</b> " + r.items.length + " items, " + r.claims + " ransomware claims" +
      (r.items[0] ? " — latest: " + esc(r.items[0].title) + srcLinks([r.items[0]]) : "") + "</li>").join("") + "</ul>" : '<div class="bempty">No regional signal yet.</div>') + "</div>";
  if (b.rest) html += '<div class="bsec"><div class="bhdr">' + esc(b.rest.title) + "</div>" + newsBullets(b.rest.items, 6) + "</div>";
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

/* ---------------- Brief: DDoS attack flows (Cloudflare Radar) ----------------
   Drawn from the `ddosTelemetry` KV field collectDdosTelemetry() already stores (7-day window, no new
   fetches): `l7Pairs` (source → target country share of mitigated HTTP DDoS traffic) as arcs, and
   `l3Targets` / `l3Origins` as country fills. Equal Earth projection on filled country shapes from the
   same world-atlas file Geo Intel loads. The default view is a night-Earth globe (globe.gl, already
   used by Geo Intel) with a drifting particle field behind it; the flat SVG map is the fallback when
   WebGL or the CDN is unavailable.
   Everything is a percentage of attack traffic over the week — not individual attacks, not live, and a
   "source" country is where the traffic came from (botnets, proxies), not who ordered it. */
const FLOW_ARCS = 24;
let flowMode = (() => { try { const m = localStorage.getItem("apjti.flowMode"); return ["flows", "targets", "origins"].includes(m) ? m : "flows"; } catch (_){ return "flows"; } })();
let flowGeo = null, flowGeoState = "idle", flowHover = null;
let flowGlobe = null, flowGlobeState = "idle", flowModel = null, flowVisible = true, flowAimedGeo = null;
function equalEarth(lon, lat){
  const A1 = 1.340264, A2 = -0.081106, A3 = 0.000893, A4 = 0.003796, M = Math.sqrt(3) / 2;
  const l = lon * Math.PI / 180, th = Math.asin(M * Math.sin(lat * Math.PI / 180)), t2 = th * th, t6 = t2 * t2 * t2;
  return [l * Math.cos(th) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2))), th * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))];
}
const FLOW_W = 1000, FLOW_K = FLOW_W / (2 * 2.7066), FLOW_LAT_MIN = -56;
function flowXY(lon, lat){ const p = equalEarth(lon, lat); return [FLOW_W / 2 + p[0] * FLOW_K, -p[1] * FLOW_K]; }
async function loadFlowGeo(){
  if (flowGeoState !== "idle") return;
  flowGeoState = "loading";
  try {
    if (typeof topojson === "undefined") throw new Error("topojson-client not loaded");
    const topo = await (await fetch(WORLD_ATLAS_URL)).json();
    const byName = {};
    if (regionNames) for (let a = 65; a <= 90; a++) for (let b = 65; b <= 90; b++){
      const code = String.fromCharCode(a, b);
      try { const n = regionNames.of(code); if (n && n !== code) byName[n.toLowerCase()] = code; } catch (_){}
    }
    const shapes = [], centroid = {};
    for (const f of topojson.feature(topo, topo.objects.countries).features){
      const num = f.id == null ? "" : String(f.id).padStart(3, "0");
      if (num === "010" || !f.geometry) continue; // Antarctica
      const cc = ISO_NUM[num] || byName[String((f.properties && f.properties.name) || "").toLowerCase()] || null;
      const polys = f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates;
      let d = "", best = null;
      for (const poly of polys) poly.forEach((ring, ri) => {
        let prevLon = null, seg = "";
        const pts = ring.map(([lon, lat]) => flowXY(lon, Math.max(lat, FLOW_LAT_MIN - 4)));
        ring.forEach(([lon], k) => {
          // Rings that cross the antimeridian jump ~360°; start a new subpath instead of drawing across the map.
          const jump = prevLon !== null && Math.abs(lon - prevLon) > 180;
          seg += (k === 0 || jump ? "M" : "L") + pts[k][0].toFixed(1) + " " + pts[k][1].toFixed(1);
          prevLon = lon;
        });
        d += seg + "Z";
        if (ri === 0 && cc){
          let A = 0, cx = 0, cy = 0;
          for (let i = 0, j = pts.length - 1; i < pts.length; j = i++){ const c = pts[j][0] * pts[i][1] - pts[i][0] * pts[j][1]; A += c; cx += (pts[j][0] + pts[i][0]) * c; cy += (pts[j][1] + pts[i][1]) * c; }
          if (A && (!best || Math.abs(A) > best.a)) best = { a: Math.abs(A), x: cx / (3 * A), y: cy / (3 * A) };
        }
      });
      shapes.push({ cc, d });
      if (cc && best) centroid[cc] = [best.x, best.y];
    }
    flowGeo = { shapes, centroid };
    flowGeoState = "ready";
  } catch (e){
    flowGeoState = "failed";
    console.warn("Attack flows: world atlas unavailable", e);
  }
  if (flowModel && flowGlobeState === "failed") renderFlatFlows(flowModel);
}
function flowPoint(cc){
  if (flowGeo && flowGeo.centroid[cc]) return flowGeo.centroid[cc];
  const c = CENTROIDS[cc];
  return c ? flowXY(c[1], c[0]) : null;
}
function flowPct(p){ return p >= 10 ? p.toFixed(0) + "%" : p >= 1 ? p.toFixed(1) + "%" : p.toFixed(2) + "%"; }
function renderFlows(){
  const mapEl = $("#flows-map");
  if (!mapEl) return;
  document.querySelectorAll("[data-flowmode]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.flowmode === flowMode)));
  const t = DATA.ddosTelemetry;
  if (!t || !(t.l7Pairs || []).length && !(t.l3Targets || []).length){
    mapEl.innerHTML = '<div class="empty">No measured DDoS data yet.</div>'; // needs the CF_RADAR_TOKEN secret and one full collection
    mapEl.hidden = false; $("#flows-globe").hidden = true;
    ["#flows-list", "#flows-stats"].forEach(s => { $(s).innerHTML = ""; });
    $("#flows-sub").textContent = ""; $("#flows-note").textContent = ""; $("#flows-list-h").textContent = "";
    return;
  }
  if (flowGlobeState === "idle") initFlowGlobe();
  const inGeo = cc => geo === "all" || ccRegion(cc) === geo;
  $("#flows-sub").textContent = "Where mitigated DDoS traffic came from and went, as a share of the week's total. Updated " + relTime(t.generated) + (geo === "all" ? "." : "; showing flows that touch " + geoLabel() + ".");

  // Country fills: L3 target or source share; in flow mode, the share of L7 traffic each country received.
  const fill = {};
  if (flowMode === "flows") (t.l7Pairs || []).forEach(p => { fill[p.to] = (fill[p.to] || 0) + p.pct; });
  else (flowMode === "targets" ? t.l3Targets : t.l3Origins || []).forEach(r => { fill[r.cc] = r.pct; });
  const fmax = Math.max(0.0001, ...Object.values(fill));
  const shade = cc => fill[cc] ? Math.min(.85, .12 + .73 * Math.sqrt(fill[cc] / fmax)) : 0;

  const pairs = (t.l7Pairs || []).filter(p => inGeo(p.from) || inGeo(p.to));
  const arcs = pairs.filter(p => p.from !== p.to).slice(0, FLOW_ARCS);
  const amax = Math.max(0.0001, ...arcs.map(p => p.pct));
  flowModel = { fill, fmax, shade, pairs, arcs, amax };
  if (flowGlobe && flowAimedGeo !== geo) aimFlowGlobe();
  flowAimedGeo = geo;
  if (flowGlobeState === "failed") renderFlatFlows(flowModel); else updateFlowGlobe();

  // Ranked list for the active mode.
  let rows;
  if (flowMode === "flows"){
    $("#flows-list-h").textContent = "Top HTTP flows · source → target";
    rows = pairs.slice(0, 10).map(p => { const i = arcs.indexOf(p); return '<li' + (i >= 0 ? ' data-fi="' + i + '"' : "") + ' tabindex="0"><span class="fl-cc">' + (p.from === p.to ? esc(ccName(p.to)) + ' <span class="rw-dim">(within)</span>' : esc(ccName(p.from)) + ' <span class="fl-to">→</span> ' + esc(ccName(p.to))) + '</span><b>' + flowPct(p.pct) + "</b></li>"; });
  } else {
    const list = ((flowMode === "targets" ? t.l3Targets : t.l3Origins) || []).filter(r => inGeo(r.cc));
    $("#flows-list-h").textContent = (flowMode === "targets" ? "Most targeted" : "Largest sources") + " · L3/L4" + (geo === "all" ? "" : " · " + geoLabel());
    rows = list.slice(0, 10).map(r => '<li><a class="fl-cc" href="#country/' + esc(r.cc) + '">' + esc(ccName(r.cc)) + "</a><b>" + flowPct(r.pct) + "</b></li>");
  }
  $("#flows-list").innerHTML = rows.length ? rows.join("") : '<li class="rw-dim">Nothing for ' + esc(geoLabel()) + " in the top 50 flows.</li>";

  const top = (l, f) => (l && l.length) ? f(l[0]) : "—";
  const long = (t.duration || []).find(d => /> ?3 ?h/.test(d.label));
  $("#flows-stats").innerHTML =
    '<div><span>Most common L3/L4 vector</span><b>' + esc(top((t.l3 || {}).global, x => x.label + " · " + flowPct(x.pct))) + "</b></div>" +
    '<div><span>Most targeted industry (L7)</span><b>' + esc(top(t.l7Industries, x => x.label + " · " + flowPct(x.pct))) + "</b></div>" +
    '<div><span title="Share of mitigated L3/L4 attack traffic that came from attacks lasting more than 3 hours, not the share of attacks">L3/L4 traffic from attacks over 3 h</span><b>' + (long ? flowPct(long.pct) : "—") + "</b></div>";
  $("#flows-note").innerHTML = "Shares of mitigated DDoS traffic, worldwide, over the last 7 days, not individual attacks and not live. " +
    "A source country is where attack traffic came from (often botnets or proxies), not who is behind it. Arcs show the top " + arcs.length + " HTTP flows between different countries; traffic within one country is ringed. " +
    // Attribution is a condition of the data's CC BY-NC 4.0 licence; keep this credit.
    'Per-country detail is on <a href="#country">Geo Intel</a>. <span class="flows-credit">Data: <a href="https://radar.cloudflare.com/security/network-layer" target="_blank" rel="noopener">Cloudflare Radar</a>, CC BY-NC 4.0.</span>';
}
// Fallback 2D map (no WebGL / CDN): Equal Earth SVG with arcs or country fills.
function renderFlatFlows(m){
  const mapEl = $("#flows-map");
  mapEl.hidden = false; $("#flows-globe").hidden = true;
  if (flowGeoState === "idle"){ loadFlowGeo(); }
  const { fill, shade, pairs, arcs, amax } = m;
  const y0 = flowXY(0, 84)[1], y1 = flowXY(0, FLOW_LAT_MIN)[1];
  const land = flowGeo ? flowGeo.shapes.map(s => '<path class="fl-land' + (s.cc && fill[s.cc] ? " on" : "") + '"' + (s.cc && fill[s.cc] ? ' style="fill-opacity:' + shade(s.cc).toFixed(2) + '"' : "") + ' d="' + s.d + '"><title>' + esc(s.cc ? ccName(s.cc) + (fill[s.cc] ? " · " + flowPct(fill[s.cc]) : "") : "") + "</title></path>").join("") : "";
  let arcSvg = "", dots = "";
  if (flowMode === "flows"){
    arcs.forEach((p, i) => {
      const a = flowPoint(p.from), b = flowPoint(p.to);
      if (!a || !b) return;
      const dx = b[0] - a[0], dy = b[1] - a[1], dist = Math.hypot(dx, dy) || 1;
      const lift = Math.min(160, dist * .32); // bow each arc upward (screen-space normal pointing up)
      const nx = -dy / dist, ny = dx / dist, s = ny > 0 ? -1 : 1;
      const cx = (a[0] + b[0]) / 2 + nx * lift * s, cy = (a[1] + b[1]) / 2 + ny * lift * s;
      const w = (0.8 + 4.2 * Math.sqrt(p.pct / amax)).toFixed(2);
      arcSvg += '<path class="fl-arc" data-fi="' + i + '" style="stroke-width:' + w + 'px" d="M' + a[0].toFixed(1) + " " + a[1].toFixed(1) + "Q" + cx.toFixed(1) + " " + cy.toFixed(1) + " " + b[0].toFixed(1) + " " + b[1].toFixed(1) + '"><title>' + esc(ccName(p.from) + " → " + ccName(p.to) + " · " + flowPct(p.pct)) + "</title></path>";
    });
    const tgt = {}, src = {};
    arcs.forEach(p => { tgt[p.to] = (tgt[p.to] || 0) + p.pct; src[p.from] = (src[p.from] || 0) + p.pct; });
    pairs.filter(p => p.from === p.to).forEach(p => { tgt[p.to] = (tgt[p.to] || 0) + p.pct; });
    Object.keys(src).forEach(cc => { const q = flowPoint(cc); if (q && !tgt[cc]) dots += '<circle class="fl-src" cx="' + q[0].toFixed(1) + '" cy="' + q[1].toFixed(1) + '" r="2.6"></circle>'; });
    const tmax = Math.max(0.0001, ...Object.values(tgt));
    Object.entries(tgt).forEach(([cc, v]) => { const q = flowPoint(cc); if (q) dots += '<circle class="fl-tgt" cx="' + q[0].toFixed(1) + '" cy="' + q[1].toFixed(1) + '" r="' + (3 + 9 * Math.sqrt(v / tmax)).toFixed(1) + '"><title>' + esc(ccName(cc) + " received " + flowPct(v) + " of the listed flows") + "</title></circle>"; });
  }
  mapEl.innerHTML = '<svg class="fl-svg' + (flowMode === "flows" ? " is-flows" : "") + '" viewBox="0 ' + y0.toFixed(0) + " " + FLOW_W + " " + (y1 - y0).toFixed(0) + '" role="img" aria-label="' +
    esc(flowMode === "flows" ? "World map of the top source-to-target country flows of HTTP DDoS traffic, last 7 days" : "World map shaded by share of network-layer DDoS traffic " + (flowMode === "targets" ? "targeting" : "originating in") + " each country, last 7 days") + '">' +
    '<g class="fl-lands">' + land + "</g>" + '<g class="fl-arcs">' + arcSvg + "</g><g>" + dots + "</g></svg>";

}
function setFlowHover(i){
  flowHover = i;
  if (flowGlobe) flowGlobe.arcColor(flowGlobe.arcColor()); // re-evaluates colours against flowHover
  const svg = $("#flows-map svg");
  if (svg) svg.classList.toggle("has-hover", i != null);
  document.querySelectorAll("#flows [data-fi]").forEach(el => el.classList.toggle("hi", i != null && el.dataset.fi === String(i)));
}
// Night-Earth globe, styled after a dark "hero" header: pink→violet arcs for HTTP flows with rings
// pulsing on targets, or columns for L3/L4 target/source shares. Rendered only while the Brief is
// the active tab and the card is on screen.
const FLOW_ARC_COLORS = ["rgba(255,79,216,0.15)", "rgba(255,79,216,0.95)", "rgba(140,107,255,0.95)"];
async function initFlowGlobe(){
  if (flowGlobeState !== "idle") return;
  const el = $("#flows-globe");
  if (!el || !webglOk()){ flowGlobeState = "failed"; if (flowModel) renderFlatFlows(flowModel); return; }
  flowGlobeState = "loading";
  try {
    if (typeof Globe === "undefined") await loadScript(GLOBE_JS, GLOBE_SRI);
    loadAtlas(); // centroids for countries missing from CENTROIDS
    const g = new Globe(el, { animateIn: !REDUCED_MOTION })
      .backgroundColor("rgba(0,0,0,0)")
      .globeImageUrl(GLOBE_TEXTURE)
      .showAtmosphere(true).atmosphereColor("#5b8cff").atmosphereAltitude(0.24)
      .width(el.clientWidth).height(el.clientHeight)
      .arcStartLat("sLat").arcStartLng("sLng").arcEndLat("eLat").arcEndLng("eLng")
      .arcColor(d => flowHover == null || String(d.i) === String(flowHover) ? FLOW_ARC_COLORS : ["rgba(255,79,216,0.04)", "rgba(255,79,216,0.12)"])
      .arcStroke(d => d.w)
      .arcAltitudeAutoScale(0.3)
      .arcDashLength(0.5).arcDashGap(0.9).arcDashInitialGap(d => d.i * 0.13 % 1)
      .arcDashAnimateTime(REDUCED_MOTION ? 0 : 3200)
      .arcLabel(d => '<div class="flows-tip"><b>' + esc(ccName(d.from)) + " → " + esc(ccName(d.to)) + "</b><br>" + flowPct(d.pct) + " of HTTP DDoS traffic</div>")
      .onArcHover(d => setFlowHover(d ? d.i : null))
      .ringLat("lat").ringLng("lng")
      .ringColor(() => t => "rgba(255,120,220," + (1 - t).toFixed(2) + ")")
      .ringMaxRadius(d => d.r).ringPropagationSpeed(1.6).ringRepeatPeriod(REDUCED_MOTION ? 0 : 1400)
      .pointLat("lat").pointLng("lng").pointAltitude("alt").pointRadius("rad").pointColor("color")
      .pointLabel(d => '<div class="flows-tip"><b>' + esc(ccName(d.cc)) + "</b><br>" + esc(d.label) + "</div>")
      .pointsMerge(false);
    const ctl = g.controls();
    ctl.enableZoom = false; // keep page scroll working over the globe
    ctl.autoRotate = !REDUCED_MOTION; ctl.autoRotateSpeed = 0.35;
    if (window.ResizeObserver) new ResizeObserver(() => { if (el.clientWidth) g.width(el.clientWidth).height(el.clientHeight); }).observe(el);
    if (window.IntersectionObserver) new IntersectionObserver(es => { flowVisible = es[0].isIntersecting; syncFlowAnimation(); }).observe(el);
    flowGlobe = g;
    flowGlobeState = "ready";
    el.hidden = false; $("#flows-map").hidden = true;
    aimFlowGlobe(0); flowAimedGeo = geo;
    updateFlowGlobe();
    syncFlowAnimation();
    startFlowParticles();
  } catch (e){
    flowGlobeState = "failed";
    console.warn("Attack flows globe unavailable, using the flat map", e);
    if (flowModel) renderFlatFlows(flowModel);
  }
}
function aimFlowGlobe(ms){
  if (!flowGlobe) return;
  const b = REGION_VIEW[geo] || REGION_VIEW.all;
  flowGlobe.pointOfView(geo === "all" ? { lat: 22, lng: -45, altitude: 2.35 } : { lat: (b[2] + b[3]) / 2, lng: (b[0] + b[1]) / 2, altitude: 2.1 }, REDUCED_MOTION ? 0 : (ms == null ? 1200 : ms));
}
function updateFlowGlobe(){
  if (!flowGlobe || !flowModel) return;
  const { fill, fmax, pairs, arcs, amax } = flowModel;
  if (flowMode === "flows"){
    flowGlobe.arcsData(arcs.map((p, i) => { const a = posOf(p.from), b = posOf(p.to); return a && b ? { i, sLat: a[0], sLng: a[1], eLat: b[0], eLng: b[1], from: p.from, to: p.to, pct: p.pct, w: 0.25 + 1.1 * Math.sqrt(p.pct / amax) } : null; }).filter(Boolean));
    const tgt = {};
    pairs.forEach(p => { tgt[p.to] = (tgt[p.to] || 0) + p.pct; });
    const tmax = Math.max(0.0001, ...Object.values(tgt));
    flowGlobe.ringsData(Object.entries(tgt).slice(0, 12).map(([cc, v]) => { const q = posOf(cc); return q ? { lat: q[0], lng: q[1], r: 2 + 6 * Math.sqrt(v / tmax) } : null; }).filter(Boolean));
    flowGlobe.pointsData(Object.entries(tgt).map(([cc, v]) => { const q = posOf(cc); return q ? { cc, lat: q[0], lng: q[1], alt: 0.01, rad: 0.25 + 0.9 * Math.sqrt(v / tmax), color: "#ff8ae2", label: "Received " + flowPct(v) + " of the listed HTTP flows" } : null; }).filter(Boolean));
  } else {
    flowGlobe.arcsData([]); flowGlobe.ringsData([]);
    const tag = flowMode === "targets" ? "of L3/L4 attack traffic targeted here" : "of L3/L4 attack traffic came from here";
    flowGlobe.pointsData(Object.entries(fill).map(([cc, v]) => { const q = posOf(cc); return q ? { cc, lat: q[0], lng: q[1], alt: 0.02 + 0.55 * Math.sqrt(v / fmax), rad: 0.55, color: flowMode === "targets" ? "#ff6fd8" : "#8c6bff", label: flowPct(v) + " " + tag } : null; }).filter(Boolean));
  }
}
function syncFlowAnimation(){
  if (!flowGlobe) return;
  const on = activeTab === "brief" && flowVisible && !document.hidden;
  if (on) flowGlobe.resumeAnimation(); else flowGlobe.pauseAnimation();
  flowParticlesOn = on && !REDUCED_MOTION;
  if (flowParticlesOn) requestAnimationFrame(drawFlowParticles);
}
// Background "constellation": slow drifting dots joined by faint lines when close.
let flowParticles = [], flowParticlesOn = false, flowParticleT = 0;
function startFlowParticles(){
  const c = $("#flows-particles");
  if (!c) return;
  // Resizing a canvas clears it, so redraw a still frame right away (matters while paused).
  const size = () => { const r = c.getBoundingClientRect(), dpr = Math.min(2, window.devicePixelRatio || 1); c.width = r.width * dpr; c.height = r.height * dpr; c.getContext("2d").setTransform(dpr, 0, 0, dpr, 0, 0); if (flowParticles.length) drawFlowParticles(0, true); };
  size();
  if (window.ResizeObserver) new ResizeObserver(size).observe(c);
  flowParticles = Array.from({ length: 70 }, () => ({ x: Math.random(), y: Math.random(), vx: (Math.random() - .5) * .00012, vy: (Math.random() - .5) * .00012, r: Math.random() * 1.4 + .4, pink: Math.random() < .3 }));
  drawFlowParticles(0, true);
}
function drawFlowParticles(ts, once){
  const c = $("#flows-particles");
  if (!c || (!flowParticlesOn && !once)) return;
  const ctx = c.getContext("2d"), w = c.clientWidth, h = c.clientHeight;
  const dt = flowParticleT ? Math.min(50, ts - flowParticleT) : 16;
  flowParticleT = ts;
  ctx.clearRect(0, 0, w, h);
  for (const p of flowParticles){
    if (!once){ p.x = (p.x + p.vx * dt + 1) % 1; p.y = (p.y + p.vy * dt + 1) % 1; }
  }
  ctx.lineWidth = 0.6;
  for (let i = 0; i < flowParticles.length; i++) for (let j = i + 1; j < flowParticles.length; j++){
    const a = flowParticles[i], b = flowParticles[j], dx = (a.x - b.x) * w, dy = (a.y - b.y) * h, d = Math.hypot(dx, dy);
    if (d < 90){ ctx.strokeStyle = "rgba(140,160,255," + (0.18 * (1 - d / 90)).toFixed(3) + ")"; ctx.beginPath(); ctx.moveTo(a.x * w, a.y * h); ctx.lineTo(b.x * w, b.y * h); ctx.stroke(); }
  }
  for (const p of flowParticles){
    ctx.fillStyle = p.pink ? "rgba(255,120,220,0.85)" : "rgba(150,175,255,0.7)";
    ctx.beginPath(); ctx.arc(p.x * w, p.y * h, p.r, 0, Math.PI * 2); ctx.fill();
  }
  if (flowParticlesOn && !once) requestAnimationFrame(drawFlowParticles);
}
function wireFlows(){
  const el = $("#flows");
  if (!el) return;
  el.addEventListener("click", e => {
    const b = e.target.closest("[data-flowmode]");
    if (b){ flowMode = b.dataset.flowmode; try { localStorage.setItem("apjti.flowMode", flowMode); } catch (_){} renderFlows(); }
  });
  const over = e => { const t = e.target.closest("[data-fi]"); setFlowHover(t ? t.dataset.fi : null); };
  el.addEventListener("mouseover", over);
  el.addEventListener("focusin", over);
  el.addEventListener("mouseleave", () => setFlowHover(null));
  document.addEventListener("visibilitychange", syncFlowAnimation);
}

/* ---------------- Markdown export ---------------- */
function buildMarkdown(){
  const pool = allItems.slice().sort((a,b) => (b.date?b.date.getTime():0) - (a.date?a.date.getTime():0));
  const b = briefSections(pool, rwVictims);
  const lines = [];
  lines.push("# Threat Intelligence Brief — " + (geo === "all" ? "" : geoLabel() + " — ") + new Date().toISOString().slice(0,10));
  lines.push("");
  lines.push("Scope: " + (geo === "all" ? "global" : geoLabel()) + ". INFOCON: " + (DATA.infocon || "green").toUpperCase() + " (SANS ISC).");
  lines.push("");
  lines.push("## " + b.lead.title);
  b.lead.items.slice(0,10).forEach(i => lines.push("- **" + i.title + "** (" + i.src + (i.link ? ", " + i.link : "") + ")"));
  lines.push("");
  lines.push("## Ransomware Watch");
  b.rw.slice(0,10).forEach(v => lines.push("- **" + v.group + "**: " + v.victim + (v.sector ? " (" + v.sector + ")" : "") + " — " + (v.cc ? ccName(v.cc) : "unknown country") + (v.date ? ", " + String(v.date).slice(0,10) : "")));
  lines.push("");
  lines.push("## DDoS / AppSec Lens");
  b.lens.slice(0,8).forEach(i => lines.push("- " + i.title + " (" + i.src + ")"));
  lines.push("");
  if (b.pulse){
    lines.push("## Regional pulse");
    b.pulse.forEach(r => lines.push("- **" + regionLabel(r.k) + "**: " + r.items.length + " items, " + r.claims + " ransomware claims" + (r.items[0] ? " — latest: " + r.items[0].title : "")));
    lines.push("");
  }
  if (b.rest){
    lines.push("## " + b.rest.title);
    b.rest.items.slice(0,8).forEach(i => lines.push("- " + i.title + " (" + i.src + ")"));
    lines.push("");
  }
  lines.push("_Generated " + new Date().toISOString() + " from open-source collection. Ransomware entries are leak-site claims, not confirmed breaches._");
  return lines.join("\n");
}
function downloadMarkdown(){
  const md = buildMarkdown();
  const blob = new Blob([md], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "threat-brief-" + (geo === "all" ? "global" : geo) + "-" + new Date().toISOString().slice(0,10) + ".md";
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ---------------- DarkGrid: dot-matrix claim map + live ticker + locate ---------------- */
let chartGroupsInst = null, chartTrendInst = null, chartSectorsInst = null;

// Daily counts of feed items per series (each { key, test(item) }) over the window, capped at 60 days.
function buildTrendSeries(series){
  const anchor = maxDate(allItems.map(i => i.date)) || new Date();
  const days = Math.max(1, Math.min(rangeDays, 60)); // cap buckets so the chart stays readable at wide windows
  const buckets = [];
  for (let i = days - 1; i >= 0; i--){
    const d = new Date(anchor.getTime() - i * 86400000);
    buckets.push(Object.assign({ key: d.toISOString().slice(0,10) }, Object.fromEntries(series.map(x => [x.key, 0]))));
  }
  const byKey = Object.fromEntries(buckets.map(b => [b.key, b]));
  allItems.forEach(i => {
    if (!i.date) return;
    const b = byKey[i.date.toISOString().slice(0,10)];
    if (!b) return;
    series.forEach(x => { if (x.test(i)) b[x.key]++; }); // an item naming two regions counts in both
  });
  return { buckets, capped: days < rangeDays };
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
  all: [-160, 182, -56, 76], apj: [58, 182, -48, 55], na: [-168, -55, 5, 72],
  sa: [-95, -30, -56, 14], eu: [-25, 45, 34, 71], me: [22, 66, 10, 44], af: [-20, 55, -36, 38]
};
// Map dots/pings are coloured by the victim country's region (REGION_META), as [r, g, b].
const hexRgb = h => [1, 3, 5].map(i => parseInt(h.slice(i, i + 2), 16));
const MAP_COLORS = Object.fromEntries(Object.keys(REGION_META).filter(k => k !== "all").map(k => [k, hexRgb(regionColor(k))]));
const ARC_PALETTE = ["#ff5b3a", "#ffb454", "#e8d27a", "#7aa2d6", "#c58cf0", "#5fd3b0", "#f07fa8", "#9aa3b5"];
const REDUCED_MOTION = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const regionNames = (() => { try { return new Intl.DisplayNames(["en"], { type: "region" }); } catch (_){ return null; } })();
function ccName(cc){
  if (!cc) return "Unknown";
  try { return (regionNames && regionNames.of(cc)) || cc; } catch (_){ return cc; }
}
function ccCategory(cc){ return ccRegion(cc); }
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

// Claims in view on the Geo Intel page: the header time window, then a country or a region.
function scopePool(regionKey, focusCC){
  const pool = windowedClaims();
  if (focusCC) return pool.filter(v => v.cc === focusCC);
  const scope = REGIONS[regionKey] && REGIONS[regionKey].countries;
  return scope ? pool.filter(v => scope.includes(v.cc)) : pool;
}
// With a country selected, the map/globe/ranking still show its surroundings: the current region
// if the country is in it, otherwise the whole world.
function contextRegion(focusCC){
  if (!focusCC) return currentRegion;
  return currentRegion === "all" || ccRegion(focusCC) === currentRegion ? currentRegion : "all";
}
function buildMapScene(focusCC, regionKey){
  const ctx = scopePool(regionKey || contextRegion(focusCC), null); // heat, pings, ranking
  const pool = focusCC ? ctx.filter(v => v.cc === focusCC) : ctx;   // arcs, groups, bursts
  const counts = {};
  ctx.forEach(v => { if (v.cc) counts[v.cc] = (counts[v.cc] || 0) + 1; });
  const max = Math.max(1, ...Object.values(counts));
  const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const pings = ranked.map(([cc, n], i) => {
    const p = posOf(cc);
    return p ? { cc, n, lat: p[0], lon: p[1], phase: i * 0.83, label: i < 6 || cc === focusCC } : null;
  }).filter(Boolean);

  // Arcs connect countries claimed by the same group — the group's busiest in-scope country (or the
  // focused country) to the other countries it has claimed anywhere. Deliberately not "attack
  // origin": leak-site data carries no origin, and the actor tracker is careful about attribution.
  const byGroup = {};
  pool.forEach(v => { byGroup[v.group] = (byGroup[v.group] || 0) + 1; });
  const topGroups = Object.entries(byGroup).sort((a, b) => b[1] - a[1]).slice(0, 7).map(([g]) => g);
  const arcs = [], everyClaim = windowedClaims();
  topGroups.forEach((g, gi) => {
    const inScope = {}, everywhere = {};
    pool.forEach(v => { if (v.group === g && v.cc) inScope[v.cc] = (inScope[v.cc] || 0) + 1; });
    everyClaim.forEach(v => { if (v.group === g && v.cc) everywhere[v.cc] = (everywhere[v.cc] || 0) + 1; });
    const hub = focusCC || (Object.entries(inScope).sort((a, b) => b[1] - a[1])[0] || [])[0];
    if (!hub || !posOf(hub)) return;
    Object.entries(everywhere).filter(([cc]) => cc !== hub && posOf(cc)).sort((a, b) => b[1] - a[1]).slice(0, 5)
      .forEach(([cc, n], k) => arcs.push({ from: hub, to: cc, n, group: g, color: ARC_PALETTE[gi % ARC_PALETTE.length],
        speed: 0.12 + ((gi * 7 + k * 3) % 10) / 70, off: ((gi * 13 + k * 29) % 100) / 100 }));
  });

  mapScene = { counts, max, pings, arcs, focus: focusCC || null, pool, ranked,
    groups: topGroups.map((g, i) => ({ g, n: byGroup[g], color: ARC_PALETTE[i % ARC_PALETTE.length] })) };
  mapBursts = pool.filter(v => v.cc && posOf(v.cc)).slice().sort((a, b) => String(b.date || "").localeCompare(String(a.date || ""))).slice(0, 30);
  mapBurstIdx = 0;
  const scopeEl = $("#dg-scope");
  if (scopeEl) scopeEl.textContent = "SCOPE · " + (focusCC ? ccName(focusCC) : (currentRegion === "all" ? "World" : regionLabel(currentRegion))).toUpperCase();
  renderMapSide(ranked, ctx.length, focusCC);
  mapDirty = true;
}
function renderMapSide(ranked, total, focusCC){
  const rankEl = $("#dg-rank");
  if (!rankEl) return;
  const top = ranked.slice(0, 10), max = Math.max(1, ...top.map(r => r[1]));
  // Keep the selected country visible in the list even when it's outside the top 10.
  if (focusCC && !top.some(([cc]) => cc === focusCC)) top.push([focusCC, (ranked.find(([cc]) => cc === focusCC) || [focusCC, 0])[1]]);
  $("#dg-rank-meta").textContent = total + " claims";
  rankEl.innerHTML = top.length ? top.map(([cc, n]) => {
    const i = ranked.findIndex(([c]) => c === cc);
    return '<li><button type="button" class="dg-rank-row' + (focusCC === cc ? " on" : "") + '" style="--rc:' + regionColor(ccRegion(cc)) + '" data-cc="' + esc(cc) + '">' +
      '<span class="rk">' + (i < 0 ? "—" : String(i + 1).padStart(2, "0")) + '</span><span class="nm">' + esc(ccName(cc)) + '</span>' +
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
  ctx.strokeStyle = "rgba(234,241,246,.045)"; ctx.lineWidth = 1;
  ctx.beginPath();
  for (let lon = -180; lon <= 360; lon += 30){ const x = toXY(0, lon, g).x; if (x >= 0 && x <= g.w){ ctx.moveTo(x, 0); ctx.lineTo(x, g.h); } }
  for (let lat = -60; lat <= 90; lat += 30){ const y = toXY(lat, 0, g).y; if (y >= 0 && y <= g.h){ ctx.moveTo(0, y); ctx.lineTo(g.w, y); } }
  ctx.stroke();
  if (!landMask) return;
  const styles = maskCountries.map(c => {
    const n = c.cc ? (mapScene.counts[c.cc] || 0) : 0;
    const hover = mapHover && c.cc === mapHover, focus = mapScene.focus && c.cc === mapScene.focus;
    if (!n) return hover ? "rgba(234,241,246,.5)" : "rgba(142,160,177,.22)";
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
      const st = id === 65535 ? "rgba(142,160,177,.22)" : styles[id - 1];
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
  if (!canvas || activeTab !== "country" || geoView !== "flat"){ mapLoopOn = false; return; }
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
  ctx.font = "500 10px 'IBM Plex Mono', ui-monospace, monospace";
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
    ctx.fillStyle = "rgba(246,250,253,.9)"; ctx.beginPath(); ctx.arc(q.x, q.y, Math.max(1.2, r * 0.32), 0, Math.PI * 2); ctx.fill();
    if (pg.cc === mapScene.focus || pg.cc === mapHover){
      ctx.beginPath(); ctx.arc(q.x, q.y, r + 5, 0, Math.PI * 2); ctx.strokeStyle = "#f6fafd"; ctx.lineWidth = 1.3; ctx.stroke();
    }
    if (pg.label || pg.cc === mapHover){
      const label = ccName(pg.cc).toUpperCase() + "  " + pg.n;
      ctx.fillStyle = "rgba(10,15,20,.72)";
      const tw = ctx.measureText(label).width;
      ctx.fillRect(q.x + r + 6, q.y - 8, tw + 10, 16);
      ctx.fillStyle = rgba(col, 1); ctx.fillRect(q.x + r + 6, q.y - 8, 2, 16);
      ctx.fillStyle = "#eaf1f6"; ctx.fillText(label, q.x + r + 12, q.y + 0.5);
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
      ctx.font = "600 10.5px 'IBM Plex Mono', ui-monospace, monospace";
      const w1 = ctx.measureText(l1).width;
      ctx.font = "400 9.5px 'IBM Plex Mono', ui-monospace, monospace";
      const bw = Math.max(w1, ctx.measureText(l2).width) + 20, bh = 38;
      let bx = q.x + 18, by = q.y - 46 - (1 - Math.min(1, k * 6)) * 6;
      if (bx + bw > g.w - 8) bx = q.x - 18 - bw;
      if (by < 8) by = q.y + 16;
      ctx.globalAlpha = alpha;
      ctx.strokeStyle = rgba(col, 0.7); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(q.x, q.y); ctx.lineTo(bx < q.x ? bx + bw : bx, by + bh / 2); ctx.stroke();
      ctx.fillStyle = "rgba(13,21,28,.92)"; ctx.fillRect(bx, by, bw, bh);
      ctx.strokeRect(bx + 0.5, by + 0.5, bw - 1, bh - 1);
      ctx.fillStyle = rgba(col, 1); ctx.fillRect(bx, by, 3, bh);
      ctx.font = "600 10.5px 'IBM Plex Mono', ui-monospace, monospace"; ctx.fillStyle = "#f6fafd"; ctx.fillText(l1, bx + 11, by + 13);
      ctx.font = "400 9.5px 'IBM Plex Mono', ui-monospace, monospace"; ctx.fillStyle = "#8ea0b1"; ctx.fillText(l2, bx + 11, by + 27);
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
  const all = windowedClaims().filter(v => v.cc === cc);
  const groups = {};
  all.forEach(v => { groups[v.group] = (groups[v.group] || 0) + 1; });
  const topG = Object.entries(groups).sort((a, b) => b[1] - a[1]).slice(0, 3);
  const sectors = {};
  all.forEach(v => { if (v.sector) sectors[v.sector] = (sectors[v.sector] || 0) + 1; });
  const topS = Object.entries(sectors).sort((a, b) => b[1] - a[1])[0];
  tip.innerHTML = '<div class="tip-hd" style="--rc:' + regionColor(ccRegion(cc)) + '"><span>' + esc(ccName(cc)) + '</span><b>' + all.length + '</b></div>' +
    (all.length ? '<div class="tip-row"><span>Top groups</span>' + topG.map(([g2, n]) => esc(g2) + " <i>" + n + "</i>").join(" · ") + '</div>' +
      (topS ? '<div class="tip-row"><span>Top sector</span>' + esc(topS[0]) + '</div>' : "") + '<div class="tip-foot">Click for its profile</div>'
      : '<div class="tip-row"><span>No leak-site claims in this window</span></div><div class="tip-foot">Click for its profile</div>');
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
    if (cc) setCountry(cc);
  });
  const rank = $("#dg-rank");
  if (rank) rank.addEventListener("click", e => { const b = e.target.closest("[data-cc]"); if (b) setCountry(b.dataset.cc); });
}
function tickClock(){
  const el = $("#dg-clock");
  if (el) el.textContent = new Date().toISOString().slice(11, 19);
}
// `singleCC` narrows to exactly one country — distinct from `regionKey`, which scopes to one of the
// named multi-country REGIONS groups.
function buildTicker(regionKey, singleCC){
  const track = $("#dg-ticker");
  if (!track) return;
  const pool = scopePool(regionKey || currentRegion, singleCC);
  const items = pool.slice(0, 24).map(v => {
    const tag = v.cc || "??";
    return '<div class="tk-item"><span class="tk-tag" style="--rc:' + regionColor(ccRegion(v.cc)) + '">' + esc(tag) + '</span><div class="tk-body"><b>' + esc(v.group.toUpperCase()) +
      '</b> <span class="tk-arrow">▸</span> ' + victimNameHtml(v.victim) + '<div class="tk-meta">' + (v.sector ? esc(v.sector) + " · " : "") +
      esc(String(v.date).slice(0,10)) + "</div></div></div>";
  });
  track.innerHTML = items.length ? (items.join("") + items.join("")) : '<div class="tk-item tk-none">No claims' + (singleCC ? " for this country" : " in this region") + " in the last " + rangeDays + " days.</div>";
  track.classList.toggle("static", items.length < 6);
  $("#dg-feed-count").textContent = pool.length + " in scope";
}
function renderBanner(){
  const level = String(DATA.infocon || "green").toLowerCase();
  const el = $("#dg-banner");
  if (!el) return;
  el.className = "dg-banner lvl-" + level;
  const labelMap = { green: "LOW", yellow: "ELEVATED", orange: "HIGH", red: "SEVERE" };
  const cveSet = new Set();
  allItems.forEach(i => { const m = (i.title + " " + (i.desc||"")).match(/CVE-\d{4}-\d{4,7}/gi); if (m) m.forEach(c => cveSet.add(c.toUpperCase())); });
  const scopeSignals = cpCC
    ? allItems.filter(i => i.cc.includes(cpCC)).length + rwVictims.filter(v => v.cc === cpCC).length
    : allItems.filter(i => itemInGeo(i)).length + rwVictims.filter(v => victimInGeo(v)).length;
  const where = cpCC ? "for " + esc(ccName(cpCC)) : geo === "all" ? "worldwide" : "in " + esc(geoLabel());
  $("#dg-banner-text").innerHTML = "<b>INFOCON " + esc(level.toUpperCase()) + " · " + (labelMap[level]||"—") + "</b><span class=\"sep\"></span>SANS Internet Storm Center<span class=\"sep\"></span>" +
    scopeSignals + " signals " + where + " · " + cveSet.size + " CVEs tracked <span class=\"dim\">(our own volume heuristic, not an official alert)</span>";
}
// Region tabs: picking the current region again (or its tab while a country is open) goes back to
// that region's overview; picking another one changes the app-wide region filter (setGeo()).
function selectRegion(key){
  key = normGeo(key);
  if (key !== geo){ setGeo(key); return; }
  setCountry(null);
}
/* DDoS intelligence section: three independent signals for the current scope, never merged into one.
   - Claimed: Telegram posts about DDoS (self-reported, from the stored `telegram` array).
   - Measured: Cloudflare Radar attack traffic (percentages of attack traffic, not attack counts).
   - Disrupted: IODA connectivity drops + Radar's verified outage notes (any cause, not just attacks).
   Worldwide/region data comes from the KV blob (ddosTelemetry, outages); a country's comes from
   /api/radar?cc= (loadRadar(), cached per country). */
const RE_DDOS_POST = /\bddos|\bd\.d\.o\.s|denial[- ]of[- ]service|\bddosed\b|taken offline|knocked offline|brought down|\bflood(?:ed|ing)?\b/i;
const IODA_URL = "https://ioda.inetintel.cc.gatech.edu/";
const OUTAGE_CAUSE = { GOVERNMENT_DIRECTED: "Government-directed", CABLE_CUT: "Cable cut", POWER_OUTAGE: "Power outage", TECHNICAL_PROBLEM: "Technical problem", WEATHER: "Weather", MILITARY_ACTION: "Military action", CYBERATTACK: "Cyberattack", MAINTENANCE: "Maintenance", FIRE: "Fire", EARTHQUAKE: "Earthquake", UNKNOWN: "Cause unknown" };
function ddosPosts(rg, cc){
  const a = maxDate(telegramItems.map(i => i.date));
  // NFKC folds the Unicode "bold" letters some channels use in headlines (𝗗𝗗𝗼𝗦) back to ASCII.
  return newest(telegramItems.filter(i => RE_DDOS_POST.test((i.title + " " + (i.desc || "")).normalize("NFKC")) &&
    (cc ? i.cc.includes(cc) : rg === "all" || i.rg.includes(rg)) && (!a || inWindow(i.date, a.getTime()))));
}
function renderDdosTelemetry(){
  const grid = $("#ddos-grid"), trio = $("#ddos-trio");
  if (!grid || !trio) return;
  const cc = cpCC, rg = currentRegion;
  const where = cc ? ccName(cc) : rg === "all" ? "worldwide" : regionLabel(rg);
  $("#ddos-scope").textContent = where + " · last 7 days unless noted";

  const pctTxt = v => v > 0 && v < 0.1 ? "<0.1%" : v.toFixed(1) + "%";
  const pctRow = r => '<div class="radar-row"><span class="radar-label" title="' + esc(r.label) + '">' + esc(r.label) + '</span>' +
    '<span class="radar-bar"><span class="radar-fill" style="width:' + Math.min(100, r.pct) + '%"></span></span>' +
    '<span class="radar-pct">' + pctTxt(r.pct) + "</span></div>";
  // Country rows link to that country's profile; bars scale to the list's own max so small shares stay visible.
  const ccRows = (list, fmt) => { const max = Math.max(...list.map(r => r.pct), 0.001); return list.map(r =>
    '<a class="radar-row radar-link" href="#country/' + esc(r.cc) + '"><span class="radar-label">' + flagEmoji(r.cc) + " " + esc(ccName(r.cc)) + '</span>' +
    '<span class="radar-bar"><span class="radar-fill" style="width:' + (r.pct / max * 100).toFixed(1) + '%"></span></span>' +
    '<span class="radar-pct">' + (fmt ? fmt(r) : pctTxt(r.pct)) + "</span></a>").join(""); };
  const sub = (title, inner) => '<div class="ddos-sub"><div class="radar-col-hd">' + title + "</div>" + inner + "</div>";
  const col = (...panels) => '<div class="ddos-col">' + panels.join("") + "</div>";
  const list = (rows, empty) => rows && rows.length ? rows : '<div class="empty">' + empty + "</div>";
  const panel = (title, meta, inner, cls) => '<div class="dg-achart ' + (cls || "") + '"><h4>' + title + (meta ? " <span>" + meta + "</span>" : "") + "</h4>" + inner + "</div>";
  const tile = (label, value, detail, cls) => '<div class="ddos-tile ' + (cls || "") + '"><div class="l">' + label + '</div><div class="v">' + value + '</div><div class="s">' + detail + "</div></div>";
  const inScope = c => rg === "all" || ccRegion(c) === rg;
  const fmtDay = iso => iso ? new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "";
  const fmtSpan = (s, e) => { const m = Math.round((new Date(e) - new Date(s)) / 60000); return m >= 1440 ? Math.round(m / 1440) + " d" : m >= 60 ? Math.round(m / 60) + " h" : m + " min"; };
  const noToken = '<div class="empty">Cloudflare Radar isn\'t configured — set CF_RADAR_TOKEN (free Account &gt; Radar &gt; Read token).</div>';

  // Claimed — same for both modes, only the scope differs.
  const posts = ddosPosts(rg, cc);
  const postList = posts.length ? '<ul class="cp-list ddos-posts">' + posts.slice(0, 6).map(i =>
    '<li><a href="' + esc(i.link) + '" target="_blank" rel="noopener">' + esc(i.title) + "</a>" +
    '<div class="card-meta">' + esc(i.channel || i.src) + (i.date ? " · " + fmtDate(i.date) : "") + (i.claim ? ' · <span class="tag tag-accent">Actor claim</span>' : "") + "</div></li>").join("") + "</ul>"
    : '<div class="empty">No Telegram posts about DDoS ' + (cc || rg !== "all" ? "name " + esc(where) + " " : "") + "in the last " + rangeDays + " days.</div>";
  const claimsPanel = panel("DDoS claims &amp; chatter", "Telegram · self-reported", postList);
  const claimTile = tile("Claimed", String(posts.length), "Telegram posts about DDoS · " + rangeDays + "d", "hot");

  if (cc){
    const r = radarCache.get(cc);
    if (!r || r === "loading"){
      trio.innerHTML = claimTile + tile("Measured", "…", "Cloudflare Radar") + tile("Disrupted", "…", "IODA");
      grid.innerHTML = claimsPanel + '<div class="dg-achart"><div class="empty">Loading attack traffic and outage data for ' + esc(where) + "…</div></div>";
      loadRadar(cc);
      return;
    }
    if (r.error){
      trio.innerHTML = claimTile + tile("Measured", "—", "unavailable") + tile("Disrupted", "—", "unavailable");
      grid.innerHTML = claimsPanel + '<div class="dg-achart"><div class="empty">' + esc(r.error) + "</div></div>";
      $("#ddos-note").innerHTML = ddosSourcesNote();
      return;
    }
    const d = r.data;
    const configured = !(d.radar && d.radar.configured === false);
    const series = d.series || [];
    const peak = series.reduce((m, p) => (!m || p.v > m.v ? p : m), null);
    // This country's share of worldwide L3/L4 attack traffic, from the stored top-50 list; below the
    // 50th entry all we can say is "less than the 50th".
    const targets = (DATA.ddosTelemetry && DATA.ddosTelemetry.l3Targets) || [];
    const worldShare = targets.find(t => t.cc === cc), floor = targets[targets.length - 1];
    const measured = !configured ? ["—", "Radar not configured"]
      : worldShare ? [worldShare.pct.toFixed(1) + "%", "of worldwide L3/L4 attack traffic targeted " + esc(where)]
      : floor ? ["&lt;" + Math.max(floor.pct, 0.1).toFixed(1) + "%","of worldwide L3/L4 attack traffic · outside the top 50"]
      : ["—", "worldwide ranking collected on the next cycle"];
    const ioda = d.ioda || { events: [], networks: [] };
    const outages = d.outages || [];
    const lastEv = ioda.events[0];
    trio.innerHTML = claimTile +
      tile("Measured", measured[0], measured[1]) +
      tile("Disrupted", String(ioda.events.length), ioda.events.length ? "IODA connectivity drops · 28d · last " + fmtDay(lastEv.start) : "no IODA connectivity drops in 28 days");

    const bars = series.length ? '<div class="ddos-spark" role="img" aria-label="Daily L3/L4 attack traffic targeting ' + esc(where) + ', last 28 days, peak ' + esc(peak ? peak.d : "") + '">' +
      series.map(p => '<i style="height:' + Math.max(3, p.v * 100).toFixed(0) + '%"' + (p === peak ? ' class="pk"' : "") + ' title="' + esc(p.d) + " · " + Math.round(p.v * 100) + '% of the 28-day peak"></i>').join("") + "</div>" +
      '<div class="ddos-spark-axis"><span>' + esc(fmtDay(series[0].d)) + "</span><span>peak " + esc(fmtDay(peak.d)) + "</span><span>" + esc(fmtDay(series[series.length - 1].d)) + "</span></div>" : "";
    const outageNotes = outages.length ? '<ul class="cp-list ddos-posts">' + outages.slice(0, 4).map(o => "<li>" + (o.link ? '<a href="' + esc(o.link) + '" target="_blank" rel="noopener">' + esc(o.desc || "Outage") + "</a>" : esc(o.desc || "Outage")) +
      '<div class="card-meta">' + esc(OUTAGE_CAUSE[o.cause] || o.cause) + " · " + esc(fmtDay(o.start)) + (o.end ? " · " + esc(fmtSpan(o.start, o.end)) : "") + "</div></li>").join("") + "</ul>" : "";

    const originsPanel = configured ? panel("Where attacks on " + esc(where) + " come from", "Cloudflare Radar",
        sub("L3/L4 · share of attack traffic by source", list(ccRows(d.l3Origins || []), "No L3/L4 attack traffic recorded.")) +
        sub("L7 (HTTP) · share of attack traffic by source", list(ccRows(d.l7Origins || []), "No L7 attack traffic recorded.")) +
        '<p class="cp-note">Where Cloudflare saw the traffic come from. L3/L4 source addresses are often spoofed, and either kind can be relayed through other countries.</p>')
        : panel("Measured attack traffic", "Cloudflare Radar", noToken);
    const targetPanel = configured ? panel("Attacks targeting " + esc(where), "L3/L4 · Cloudflare Radar",
        (bars ? sub("Daily volume · 28 days, relative to its peak", bars) : "") +
        sub("Attack vectors", list((d.l3 || []).map(pctRow).join(""), "No L3/L4 attack traffic recorded.")) +
        '<div class="ddos-two">' + sub("Size · share of traffic", list((d.bitrate || []).map(pctRow).join(""), "—")) + sub("Duration · share of traffic", list((d.duration || []).map(pctRow).join(""), "—")) + "</div>") : "";
    const outagePanel = panel("Internet disruptions in " + esc(where), "IODA · Radar outage notes",
        sub("Connectivity drops · last 28 days", ioda.events.length ? '<ul class="cp-list ddos-posts">' + ioda.events.slice(0, 6).map(e =>
          "<li>" + esc(new Date(e.start).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" })) + " UTC · " + esc(fmtSpan(e.start, e.end)) +
          '<div class="card-meta">seen in ' + esc(e.sources.join(", ")) + "</div></li>").join("") + "</ul>"
          : '<div class="empty">' + (ioda.ok === false ? "IODA didn't answer — try again later." : "No country-wide connectivity drops.") + "</div>") +
        (ioda.networks.length ? sub("Networks with drops · last 7 days", '<ul class="cp-list ddos-posts">' + ioda.networks.slice(0, 6).map(n =>
          "<li>" + esc(n.name) + '<div class="card-meta">' + n.events + " event" + (n.events === 1 ? "" : "s") + "</div></li>").join("") + "</ul>") : "") +
        (outageNotes ? sub("Verified by Cloudflare Radar · 28 days", outageNotes) : "") +
        '<p class="cp-note">A drop says a network went dark, not why. Check the cause before tying one to a claim. <a href="' + IODA_URL + "country/" + esc(cc) + '" target="_blank" rel="noopener">IODA dashboard for ' + esc(where) + " ↗</a></p>");
    grid.innerHTML = col(claimsPanel, outagePanel) + col(originsPanel) + col(targetPanel);
    $("#ddos-note").innerHTML = ddosSourcesNote();
    return;
  }

  // Overview (world or region): the stored worldwide lists, narrowed to the region.
  const dt = DATA.ddosTelemetry;
  const og = DATA.outages || {};
  const targets = ((dt && dt.l3Targets) || []).filter(t => inScope(t.cc));
  const pairs = ((dt && dt.l7Pairs) || []).filter(p => inScope(p.to) || inScope(p.from));
  const iodaRows = (og.ioda || []).filter(e => /^[A-Z]{2}$/.test(e.code) && inScope(e.code));
  const radarOut = (og.radar || []).filter(o => rg === "all" ? true : o.cc.some(inScope));
  const top = targets[0];
  trio.innerHTML = claimTile +
    tile("Measured", top ? flagEmoji(top.cc) + " " + esc(ccName(top.cc)) : "—", top ? "most targeted · " + top.pct.toFixed(1) + "% of worldwide L3/L4 attack traffic"
      : !dt ? "Radar not configured" : !dt.l3Targets ? "ranking collected on the next 30-min cycle" : "no country in scope in Radar's top 50") +
    tile("Disrupted", DATA.outages ? String(iodaRows.length) : "—", DATA.outages ? "countries with IODA connectivity drops · 7d" : "collected on the next 30-min cycle");
  const maxEvents = Math.max(...iodaRows.map(e => e.events), 1);
  const wherePanel = dt && dt.l3Targets ? panel("Most attacked countries", "L3/L4 · share of worldwide attack traffic",
      list(ccRows(targets.slice(0, 8)), "No country in scope is in Radar's top 50 targets.") +
      sub("Top L7 attack routes · source → target", pairs.length ? pairs.slice(0, 6).map(p =>
        '<div class="radar-row radar-route"><span class="radar-label">' + flagEmoji(p.from) + " " + esc(ccName(p.from)) + ' <span class="tk-arrow">→</span> ' + flagEmoji(p.to) + " " + esc(ccName(p.to)) + '</span><span class="radar-pct">' + p.pct.toFixed(1) + "%</span></div>").join("") : '<div class="empty">No top route touches ' + esc(where) + ".</div>"))
      : panel("Measured attack traffic", "Cloudflare Radar", dt ? '<div class="empty">Collected before this panel existed — fills in on the next 30-min cycle.</div>' : noToken);
  const whatPanel = dt ? panel("What the attacks look like", "worldwide · Cloudflare Radar",
      '<div class="ddos-two">' + sub("L3/L4 vectors", list(((dt.l3 && dt.l3.global) || []).slice(0, 6).map(pctRow).join(""), "—")) + sub("L7 HTTP methods", list(((dt.l7 && dt.l7.global) || []).slice(0, 6).map(pctRow).join(""), "—")) + "</div>" +
      (dt.bitrate && dt.bitrate.length ? '<div class="ddos-two">' + sub("Size · share of traffic", dt.bitrate.map(pctRow).join("")) + sub("Duration · share of traffic", (dt.duration || []).map(pctRow).join("")) + "</div>" : "") +
      (dt.l7Industries && dt.l7Industries.length ? sub("Most targeted industries · L7", dt.l7Industries.slice(0, 6).map(pctRow).join("")) : "")) : "";
  const outagePanel = panel("Internet disruptions", "IODA · Radar outage notes",
      sub("Countries with connectivity drops · 7 days", iodaRows.length ? iodaRows.slice(0, 8).map(e =>
        '<a class="radar-row radar-link" href="#country/' + esc(e.code) + '"><span class="radar-label">' + flagEmoji(e.code) + " " + esc(ccName(e.code)) + '</span>' +
        '<span class="radar-bar"><span class="radar-fill" style="width:' + (e.events / maxEvents * 100).toFixed(1) + '%"></span></span>' +
        '<span class="radar-pct">' + e.events + " ev</span></a>").join("") : '<div class="empty">' + (DATA.outages ? "No drops recorded in " + esc(where) + "." : "Collected on the next 30-min cycle.") + "</div>") +
      (radarOut.length ? sub("Verified by Cloudflare Radar · 28 days", '<ul class="cp-list ddos-posts">' + radarOut.slice(0, 5).map(o => "<li>" +
        (o.link ? '<a href="' + esc(o.link) + '" target="_blank" rel="noopener">' + esc(o.desc || "Outage") + "</a>" : esc(o.desc || "Outage")) +
        '<div class="card-meta">' + esc(OUTAGE_CAUSE[o.cause] || o.cause) + (o.cc.length ? " · " + o.cc.map(c => esc(ccName(c))).join(", ") : "") + " · " + esc(fmtDay(o.start)) + "</div></li>").join("") + "</ul>") : "") +
      '<p class="cp-note">Ordered by IODA\'s severity score; bars and "ev" show the number of drop events. A drop has many possible causes. Pick a country to see its timeline.</p>');
  grid.innerHTML = col(claimsPanel, outagePanel) + col(wherePanel) + col(whatPanel);
  $("#ddos-note").innerHTML = ddosSourcesNote();
}
function ddosSourcesNote(){
  const t = DATA.ddosTelemetry && DATA.ddosTelemetry.generated, o = DATA.outages && DATA.outages.generated;
  return 'Sources: <a href="https://radar.cloudflare.com/" target="_blank" rel="noopener">Cloudflare Radar</a> (shares of attack traffic Cloudflare mitigated, not attack counts)' +
    (t ? ", updated " + esc(new Date(t).toLocaleString()) : "") + ' · <a href="' + IODA_URL + '" target="_blank" rel="noopener">IODA</a>, Georgia Tech Research Corporation (connectivity drops, any cause)' +
    (o ? ", updated " + esc(new Date(o).toLocaleString()) : "") + " · Telegram (self-reported). Country views are cached for 6 hours.";
}
function renderDashStats(regionKey, focusCC){
  const el = $("#dg-stats");
  if (!el) return;
  const pool = scopePool(regionKey || currentRegion, focusCC);
  const groups = new Set(pool.map(v => v.group));
  const stat = ([l, v, sub, cls], i) => '<div class="dg-stat ' + (cls || "") + '" style="--i:' + i + '"><div class="l">' + esc(l) + '</div><div class="v">' + esc(String(v)) +
    '</div><div class="s" title="' + esc(sub) + '">' + esc(sub) + "</div></div>";
  if (focusCC){
    const stored = rwVictims.filter(v => v.cc === focusCC);
    const top = countByKey(pool, "group")[0];
    const { news, social } = countryMentions(focusCC);
    const last = stored.slice().sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")))[0];
    el.innerHTML = [
      ["Claims · " + rangeDays + "d", pool.length, stored.length > pool.length ? "of " + stored.length + " stored" : "leak-site, unconfirmed", "hot"],
      ["Active groups", groups.size, top ? "top: " + top[0] : "none in this window"],
      ["News mentions", news.length, "feed items naming " + ccName(focusCC)],
      ["Social mentions", social.length, "Telegram + Mastodon"],
      ["Latest claim", last ? String(last.date || "").slice(0, 10) : "—", last ? last.group + " ▸ " + last.victim : "none stored"]
    ].map(stat).join("");
    return;
  }
  const countries = new Set(pool.map(v => v.cc).filter(Boolean));
  const byCc = {};
  pool.forEach(v => { if (v.cc) byCc[v.cc] = (byCc[v.cc] || 0) + 1; });
  const [topCc, topN] = Object.entries(byCc).sort((a, b) => b[1] - a[1])[0] || [null, 0];
  const cutoff = Date.now() - 7 * 86400000;
  const last7 = pool.filter(v => v.date && new Date(v.date).getTime() >= cutoff).length;
  const pct = pool.length ? Math.round(topN / pool.length * 100) : 0;
  const news = allItems.filter(i => itemInGeo(i, regionKey || currentRegion) && inWindow(i.date, (maxDate(allItems.map(x => x.date)) || new Date()).getTime())).length;
  el.innerHTML = [
    ["Claims · " + rangeDays + "d", pool.length, last7 + " in the last 7 days", ""],
    ["Most targeted", topCc ? ccName(topCc) : "—", topCc ? topN + " claims · " + pct + "% of scope" : "no claims in scope", "hot"],
    ["Countries hit", countries.size, "victim countries", ""],
    ["Active groups", groups.size, "posting to leak sites", ""],
    ["News mentions", news, (regionKey || currentRegion) === "all" ? "feed items naming a country" : "feed items naming " + regionLabel(regionKey || currentRegion), ""]
  ].map(stat).join("");
}
function wireRegionTabs(){
  document.querySelectorAll(".dg-rtab").forEach(t => {
    if (t._wired) return;
    t._wired = true;
    t.addEventListener("click", () => selectRegion(t.dataset.region));
  });
}
// World › Region › Country breadcrumb above the stage; the ✕ drops back to the region overview.
function renderCrumb(){
  const el = $("#geo-crumb");
  if (!el) return;
  const rg = cpCC ? contextRegion(cpCC) : currentRegion;
  const parts = ['<button type="button" data-crumb="all">World</button>'];
  const ownRg = cpCC ? ccRegion(cpCC) : rg;
  if (ownRg !== "all" && ownRg !== "other") parts.push(cpCC ? '<button type="button" data-crumb="' + ownRg + '">' + esc(regionLabel(ownRg)) + "</button>" : "<b>" + esc(regionLabel(ownRg)) + "</b>");
  if (cpCC) parts.push("<b>" + flagEmoji(cpCC) + " " + esc(ccName(cpCC)) + '</b><button type="button" class="x" data-crumb="clear" aria-label="Back to the overview">✕ overview</button>');
  el.innerHTML = parts.join("<span>›</span>");
  if (!el._wired){
    el._wired = true;
    el.addEventListener("click", e => {
      const b = e.target.closest("[data-crumb]");
      if (!b) return;
      const k = b.dataset.crumb;
      if (k === "clear") setCountry(null);
      else if (k === geo) setCountry(null);
      else setGeo(k);
    });
  }
}
// Globe / Flat toggle — two renderings of the same selection; only the visible one animates.
let geoView = (() => { try { return localStorage.getItem("apjti.geoView") === "flat" ? "flat" : "globe"; } catch (_){ return "globe"; } })();
function setView(v){
  geoView = v === "flat" ? "flat" : "globe";
  try { localStorage.setItem("apjti.geoView", geoView); } catch (_){}
  syncView();
}
function syncView(){
  const wrap = $("#dg-map-wrap");
  if (wrap) wrap.dataset.view = geoView;
  document.querySelectorAll("[data-view]").forEach(b => { if (b.tagName === "BUTTON") b.setAttribute("aria-pressed", String(b.dataset.view === geoView)); });
  showMapTip(null);
  if (activeTab !== "country") return;
  if (geoView === "flat"){
    if (cpGlobe) cpGlobe.pauseAnimation();
    resizeMap();
    startMapLoop();
  } else {
    if (globeState === "idle") initGlobe();
    else if (cpGlobe){ cpGlobe.resumeAnimation(); const el = $("#cp-globe"); if (el.clientWidth) cpGlobe.width(el.clientWidth).height(el.clientHeight); updateGlobe(); }
  }
}
function wireViewToggle(){
  document.querySelectorAll(".dg-viewtog [data-view]").forEach(b => {
    if (b._wired) return;
    b._wired = true;
    b.addEventListener("click", () => setView(b.dataset.view));
  });
}
// Where the flat map and globe should be looking: the selected country, else the region.
let lastAim = null;
function aimViews(){
  const key = cpCC ? "cc:" + cpCC : "rg:" + currentRegion;
  if (key === lastAim && mapTarget) return;
  lastAim = key;
  const c = cpCC && posOf(cpCC);
  if (c){
    const span = ["US","CA","RU","CN","BR","AU"].includes(cpCC) ? 70 : 34;
    setMapTarget([c[1] - span, c[1] + span, c[0] - span * 0.42, c[0] + span * 0.42]);
  } else setMapTarget(REGION_VIEW[currentRegion] || REGION_VIEW.all);
  if (cpGlobe) aimGlobe();
}
// The Geo Intel page renderer: overview (world/region) or a country profile, both views, all panels.
function buildDashboard(){
  const dates = rwVictims.map(v => v.date).filter(Boolean).sort();
  const focus = cpCC;

  renderDashStats(currentRegion, focus);
  renderDdosTelemetry();
  renderBanner();
  renderKpis();
  renderCrumb();
  document.querySelectorAll(".dg-rtab").forEach(t => t.classList.toggle("active", !focus && t.dataset.region === currentRegion));
  const legend = $("#dg-legend-regions");
  if (legend) legend.innerHTML = [...GEO_KEYS, "other"].map(k => '<span><i class="lg-rg" style="--rc:' + regionColor(k) + '"></i>' + esc(regionLabel(k)) + "</span>").join("");

  $("#dg-updated").textContent = rwVictims.length + " leak-site claims stored · latest " + (dates.length ? String(dates[dates.length-1]).slice(0,10) : "n/a") + " · panels follow the " + rangeDays + "-day window";
  $("#dash-cov").textContent = "Coverage " + (dates[0] ? String(dates[0]).slice(0,10) : "n/a") + " → " + (dates.length ? String(dates[dates.length-1]).slice(0,10) : "n/a") + " · leak-site claims, not confirmed breaches · refreshed every 30 min server-side";

  buildMapScene(focus, contextRegion(focus));
  buildTicker(currentRegion, focus);
  aimViews();
  wireMap();
  wireRegionTabs();
  wireViewToggle();
  loadAtlas();
  syncView();
  if (!tickClock._on){ tickClock._on = true; tickClock(); setInterval(tickClock, 1000); }
  renderCountryChips();
  renderGeoBody();
  if (cpGlobe) updateGlobe();

  const scoped = scopePool(currentRegion, focus);
  const topGroups = countByKey(scoped, "group").slice(0, 8);
  const topSectors = countByKey(scoped, "sector").slice(0, 8);

  if (typeof Chart === "undefined") return;
  const mono = "'IBM Plex Mono', ui-monospace, monospace";
  const gridColor = "rgba(234,241,246,.06)";
  const tick = { color: "#8ea0b1", font: { size: 10, family: mono } };
  const tooltip = { backgroundColor: "#0d151c", borderColor: "#2c3e4f", borderWidth: 1, titleColor: "#eaf1f6", bodyColor: "#c3d0db",
    titleFont: { family: mono, size: 11 }, bodyFont: { family: mono, size: 10.5 }, padding: 10, cornerRadius: 8, boxPadding: 4 };
  const fade = (ctx, hex) => {
    const area = ctx.chart.chartArea;
    if (!area) return hex + "33";
    const g = ctx.chart.ctx.createLinearGradient(0, area.top, 0, area.bottom);
    g.addColorStop(0, hex + "55"); g.addColorStop(1, hex + "00");
    return g;
  };

  const ctxT = document.getElementById("chartTrend");
  if (ctxT){
    // Overview: one line per region (the selected one drawn on top). Country: that country vs its region.
    const rgOf = focus ? ccRegion(focus) : null;
    const series = focus
      ? [{ key: "cc", label: ccName(focus), color: regionColor(rgOf), test: i => i.cc.includes(focus) },
         ...(rgOf !== "other" ? [{ key: "rg", label: regionLabel(rgOf) + " (all)", color: "#8ea0b1", test: i => i.rg.includes(rgOf), dim: true }] : [])]
      : GEO_KEYS.map(k => ({ key: k, label: regionLabel(k), color: regionColor(k), test: i => i.rg.includes(k), dim: geo !== "all" && k !== geo }));
    const { buckets, capped } = buildTrendSeries(series);
    if (chartTrendInst) chartTrendInst.destroy();
    const line = x => ({ label: x.label, data: buckets.map(b => b[x.key]), borderColor: x.dim ? x.color + "66" : x.color,
      backgroundColor: c => x.dim ? "transparent" : fade(c, x.color), fill: !x.dim && (!!focus || geo !== "all"), order: x.dim ? 1 : 0,
      pointRadius: 0, pointHoverRadius: 3, borderWidth: x.dim ? 1.1 : 1.8, tension: 0.35 });
    chartTrendInst = new Chart(ctxT, {
      type: "line",
      data: { labels: buckets.map(b => b.key.slice(5)), datasets: series.map(line) },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: { display: false }, tooltip },
        scales: {
          x: { ticks: { ...tick, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 }, grid: { display: false }, border: { color: "#2c3e4f" } },
          y: { beginAtZero: true, ticks: { ...tick, precision: 0, maxTicksLimit: 5 }, grid: { color: gridColor }, border: { display: false } }
        }
      }
    });
    const h4 = ctxT.closest(".dg-achart").querySelector("h4");
    if (h4) h4.title = capped ? "Capped to the last 60 days for readability." : "";
    const title = $("#trend-title");
    if (title) title.textContent = focus ? "News mentions · " + ccName(focus) + " vs region" : "News volume by region";
    const legendEl = $("#trend-legend");
    if (legendEl) legendEl.innerHTML = series.map(x => '<span class="sw" style="--rc:' + x.color + '">' + esc(x.label) + "</span>").join("");
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
          y: { ticks: { ...tick, color: "#c3d0db" }, grid: { display: false }, border: { color: "#2c3e4f" } }
        }
      }
    });
  };
  const ctxG = document.getElementById("chartGroups");
  if (ctxG) chartGroupsInst = hbar(ctxG, chartGroupsInst, topGroups, i => ARC_PALETTE[i % ARC_PALETTE.length]);
  const ctxS = document.getElementById("chartSectors");
  if (ctxS) chartSectorsInst = hbar(ctxS, chartSectorsInst, topSectors, i => i === 0 ? "#ff5b3a" : (i < 3 ? "#ffb454" : "#6f8294"));
  // Chart.js measures axis labels at creation; if IBM Plex Mono arrives afterwards the wider glyphs
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
  if (meta) meta.content = (dark || onMap) ? "#0a0f14" : "#f4f6f8";
}
function wireThemeToggle(){
  const btn = $("#theme-toggle");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("apjti.theme", next); } catch (_){}
    syncThemeToggle();
    if (chartVulnMatrixInst) renderVulnMatrix(vnRows); // reads theme tokens
    if (rwTrendInst) renderRw(); // trend bar colours are read from theme tokens too
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
  document.querySelectorAll("[data-t]").forEach(c => c.addEventListener("click", () => {
    rangeDays = parseInt(c.dataset.t, 10);
    localStorage.setItem("apjti.range", String(rangeDays));
    document.querySelectorAll("[data-t]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.t === c.dataset.t)));
    renderRw(); renderRansomwareNews(); renderTelegram(); renderSnapshot(); renderActors(); buildDashboard();
  }));
  document.querySelectorAll("[data-geo]").forEach(c => c.addEventListener("click", () => setGeo(c.dataset.geo)));
  document.querySelectorAll("[data-tgf]").forEach(c => c.addEventListener("click", () => {
    tgFilter = c.dataset.tgf;
    localStorage.setItem("apjti.tgFilter", tgFilter);
    renderTelegram();
  }));
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
}

/* ---------------- Geo Intel page: world / region overview, or everything held for one country ----------------
   Pure client-side view over /api/data (claims by victim country, items/posts by the worker's cc/rg
   tags), plus two lazy extras: the APT sheet (/api/actors, groups whose Targets name a country) and
   Cloudflare Radar's measured attack traffic per country (/api/radar?cc=, edge-cached). The page
   frame (stats, map/globe, ticker, charts, Radar) is buildDashboard(); this section is the country
   selection, the panels under the stage (renderGeoBody()) and the globe. */
const radarCache = new Map(); // cc → { data } | { error } | "loading"
function flagEmoji(cc){
  return /^[A-Z]{2}$/.test(cc || "") ? String.fromCodePoint(...[...cc].map(c => 127397 + c.charCodeAt(0))) : "🌐";
}
function knownCountries(){
  const set = new Set(Object.keys(CC_REGION));
  rwVictims.forEach(v => v.cc && set.add(v.cc));
  allItems.forEach(i => i.cc.forEach(c => set.add(c)));
  return [...set].filter(cc => /^[A-Z]{2}$/.test(cc)).map(cc => [cc, ccName(cc)]).sort((a, b) => a[1].localeCompare(b[1]));
}
function resolveCountry(q, fuzzy){
  q = String(q || "").trim().toLowerCase();
  if (!q) return null;
  const list = knownCountries();
  const hit = list.find(([cc, name]) => cc.toLowerCase() === q || name.toLowerCase() === q) ||
    (fuzzy && (list.find(([, name]) => name.toLowerCase().startsWith(q)) || (q.length > 2 && list.find(([, name]) => name.toLowerCase().includes(q)))));
  return hit ? hit[0] : null;
}
function windowedClaims(){
  const a = maxDate(rwVictims.map(v => v.date));
  return a ? rwVictims.filter(v => inWindow(v.date, a.getTime())) : rwVictims;
}
function claimsByCountry(list){
  const by = {};
  list.forEach(v => { if (v.cc) by[v.cc] = (by[v.cc] || 0) + 1; });
  return Object.entries(by).sort((a, b) => b[1] - a[1]);
}
function countByKey(list, key){
  const by = {};
  list.forEach(x => { const k = x[key]; if (k) by[k] = (by[k] || 0) + 1; });
  return Object.entries(by).sort((a, b) => b[1] - a[1]);
}
function newest(list){ return list.slice().sort((a, b) => (b.date ? b.date.getTime() : 0) - (a.date ? a.date.getTime() : 0)); }
// Feed items and Telegram/Mastodon posts naming a country, inside the window.
function countryMentions(cc){
  const ia = maxDate(allItems.map(i => i.date)), sa = maxDate([...telegramItems, ...rwNewsItems].map(i => i.date));
  return {
    news: newest(allItems.filter(i => i.cc.includes(cc) && (!ia || inWindow(i.date, ia.getTime())))),
    social: newest([...telegramItems, ...rwNewsItems].filter(i => i.cc.includes(cc) && (!sa || inWindow(i.date, sa.getTime()))))
  };
}
function renderCountryChips(){
  const el = $("#cp-chips");
  if (!el) return;
  const rg = contextRegion(cpCC);
  const top = claimsByCountry(scopePool(rg, null)).slice(0, 16);
  el.innerHTML = top.length ? '<span class="apj-eyebrow" style="align-self:center;margin-right:4px">Most claimed · ' + esc(rg === "all" ? "world" : regionLabel(rg)) + " · " + rangeDays + " days</span>" + top.map(([cc, n]) =>
    '<a class="cp-chip" href="#country/' + esc(cc) + '"' + (cc === cpCC ? ' aria-current="true"' : "") + '><i style="--rc:' + regionColor(ccRegion(cc)) + '"></i>' + esc(ccName(cc)) + "<b>" + n + "</b></a>").join("") : "";
  const dl = $("#cp-countries");
  if (dl && dl.options.length !== knownCountries().length) dl.innerHTML = knownCountries().map(([, name]) => '<option value="' + esc(name) + '">').join("");
}
// null → back to the world/region overview.
function setCountry(cc, opts){
  cc = cc ? String(cc).toUpperCase() : null;
  if (cc && !/^[A-Z]{2}$/.test(cc)) return;
  if (cc !== cpCC) claimsExpanded = false;
  cpCC = cc;
  if (activeTab === "country") history.replaceState(null, "", "#country" + (cc ? "/" + cc : ""));
  const input = $("#cp-search");
  if (input && document.activeElement !== input) input.value = "";
  if (!(opts && opts.skipRender)) buildDashboard();
}
const CLAIMS_PREVIEW = 12;
let claimsExpanded = false;
function renderGeoBody(){
  const body = $("#cp-body");
  if (!body) return;
  if (!rwVictims.length && !allItems.length){ body.innerHTML = '<div class="empty">Loading…</div>'; return; }
  const card = (kicker, sub, inner) => '<div class="card elev-sm cp-card"><div class="card-kicker">' + kicker +
    (sub ? ' <span class="text-muted" style="font-weight:400;text-transform:none;letter-spacing:normal">· ' + sub + "</span>" : "") + "</div>" + inner + "</div>";
  const newsList = (list, max, withChannel) => list.length ? '<ul class="cp-list">' + list.slice(0, max).map(i =>
    '<li><a href="' + esc(i.link) + '" target="_blank" rel="noopener">' + esc(i.title) + "</a>" +
    '<div class="card-meta">' + esc(withChannel && i.channel ? i.channel : i.src) + (i.date ? " · " + fmtDate(i.date) : "") +
      (i.claim ? ' · <span class="tag tag-accent">Actor claim</span>' : "") + (i.lens ? ' · <span class="tag tag-neutral">DDoS · AppSec</span>' : "") + "</div></li>").join("") + "</ul>" : "";
  const actorRow = a => '<li><a href="#actors/' + esc(a.id) + '"><b>' + esc(a.name) + '</b></a> <span class="text-muted">· ' + esc(a.motive) + " · " + esc(a.origin) + "</span>" +
    '<div class="card-meta">' + esc(a.targets) + "</div></li>";

  if (!cpCC){
    // Overview: what's being said about the region (or anywhere), and who targets it.
    const rg = currentRegion, label = rg === "all" ? "any country" : regionLabel(rg);
    const ia = maxDate(allItems.map(i => i.date)), sa = maxDate([...telegramItems, ...rwNewsItems].map(i => i.date));
    const inRg = i => rg === "all" ? i.rg.length > 0 : i.rg.includes(rg);
    const news = newest(allItems.filter(i => inRg(i) && (!ia || inWindow(i.date, ia.getTime()))));
    const social = newest([...telegramItems, ...rwNewsItems].filter(i => inRg(i) && (!sa || inWindow(i.date, sa.getTime()))));
    const actors = mergedActors().filter(a => actorTargetsRegion(a, rg));
    const sheetN = (aptGroups || []).filter(g => rg === "all" ? g.cc.length : g.rg.includes(rg)).length;
    body.innerHTML = '<div class="cp-grid"><div class="cp-col">' +
      card("In the news", "items naming " + esc(label) + ", last " + rangeDays + " days", newsList(news, 14) || '<div class="bempty">No feed items name ' + esc(label) + " in this window.</div>") +
      '</div><div class="cp-col">' +
      card("Threat actors" + (rg === "all" ? "" : " targeting " + esc(label)), "curated profiles",
        (actors.length ? '<ul class="cp-list">' + actors.slice(0, 8).map(actorRow).join("") + "</ul>" : '<div class="bempty">No curated profile targets ' + esc(label) + ".</div>") +
        (aptGroups ? '<p class="cp-note">' + sheetN + ' community-sheet groups list targets ' + (rg === "all" ? "by country" : "here") + ' — see the <a href="#actors">Actors</a> directory.</p>' : "")) +
      card("Telegram &amp; community", "unmoderated — claims, not confirmed", newsList(social, 8, true) || '<div class="bempty">No posts name ' + esc(label) + " in this window.</div>") +
      "</div></div>";
    return;
  }

  const cc = cpCC, name = ccName(cc);
  const claims = scopePool(null, cc);
  const stored = rwVictims.filter(v => v.cc === cc);
  const { news, social } = countryMentions(cc);
  const shown = claimsExpanded ? claims : claims.slice(0, CLAIMS_PREVIEW);
  const claimRows = shown.map(v => "<tr>" +
    '<td data-label="Organization">' + victimNameHtml(v.victim) + "</td>" +
    '<td data-label="Sector" class="text-muted">' + esc(v.sector || "—") + "</td>" +
    '<td data-label="Group">' + esc(v.group) + "</td>" +
    '<td data-label="Claimed" class="text-muted">' + (v.date ? esc(String(v.date).slice(0, 10)) : "—") + "</td></tr>").join("");
  const claimsCard = card("Ransomware claims · " + esc(name), "ransomware.live leak sites, newest first",
    claims.length ? '<div class="table-wrap"><table class="table"><thead><tr><th>Organization</th><th>Sector</th><th>Group</th><th>Claimed</th></tr></thead><tbody>' + claimRows + "</tbody></table></div>" +
      (claims.length > CLAIMS_PREVIEW ? '<button type="button" class="btn btn-secondary cp-more" data-act="more-claims">' + (claimsExpanded ? "Show fewer" : "Show all " + claims.length) + "</button>" : "")
    : '<div class="bempty">No claims against ' + esc(name) + " in the last " + rangeDays + " days" + (stored.length ? " (" + stored.length + " older ones stored — widen the window)." : ".") + "</div>");

  // Curated profiles that name this country, plus "targets everywhere" ones actually claiming here.
  const claimGroups = new Set(stored.map(v => groupKey(v.group)));
  const curated = mergedActors().filter(a => (a.geo || []).includes(cc) || ((a.geo || []).includes("global") && claimGroups.has(groupKey(a.name))));
  const sheet = (aptGroups || []).filter(g => g.cc.includes(cc)).sort((a, b) => (a.label || a.name).localeCompare(b.label || b.name));
  const actorsCard = card("Threat actors", "",
    (curated.length ? '<ul class="cp-list">' + curated.map(actorRow).join("") + "</ul>" : '<div class="bempty">No curated profile targets ' + esc(name) + ".</div>") +
    '<div class="card-kicker" style="margin-top:var(--space-5)">Community sheet · groups whose targets name ' + esc(name) + "</div>" +
    (aptGroups === null ? '<div class="bempty">Loading the APT groups sheet…</div>'
      : sheet.length ? '<ul class="cp-list">' + sheet.slice(0, 15).map(g => "<li><b>" + esc(g.label || g.name) + '</b> <span class="text-muted">· ' + esc(g.tab) + (g.mitre ? " · " : "") + "</span>" + (g.mitre ? aptMitreLink(g.mitre) : "") +
          (g.aliases && g.aliases.length ? '<div class="card-meta">' + esc(aptAliasText(g, 4)) + "</div>" : "") + "</li>").join("") + "</ul>" +
          (sheet.length > 15 ? '<p class="cp-note">+' + (sheet.length - 15) + ' more — search the directory on the <a href="#actors">Actors</a> tab.</p>' : "")
        : '<div class="bempty">No sheet group lists ' + esc(name) + " among its targets.</div>") +
    '<p class="cp-note">Attribution is the sources\' call, not this app\'s — see each profile\'s confidence note on the Actors tab.</p>');

  body.innerHTML = '<div class="cp-grid"><div class="cp-col">' + claimsCard +
    card("In the news", "items naming " + esc(name) + ", its cities or country-specific terms", newsList(news, 14) || '<div class="bempty">No feed items mention ' + esc(name) + " in the last " + rangeDays + " days.</div>") +
    '</div><div class="cp-col">' + actorsCard +
    card("Telegram &amp; community", "unmoderated — claims, not confirmed", newsList(social, 10, true) || '<div class="bempty">No Telegram or Mastodon posts mention ' + esc(name) + " in the last " + rangeDays + " days.</div>") +
    "</div></div>";
}
async function loadRadar(cc){
  if (radarCache.has(cc)) return;
  radarCache.set(cc, "loading");
  try {
    const r = await fetch("/api/radar?cc=" + encodeURIComponent(cc));
    const d = await r.json();
    radarCache.set(cc, d.error ? { error: d.error } : { data: d });
  } catch (e){
    radarCache.set(cc, { error: "Radar lookup failed (" + e.message + ")." });
  }
  if (cpCC === cc) renderDdosTelemetry();
}

/* Geo Intel globe view — globe.gl (three.js), loaded the first time the Globe view is shown since it's
   ~1.9MB. Night-side Earth texture from three-globe's examples; badges = claims per victim country
   in the window (CSS2D elements), the selected country as a large highlighted badge with a card;
   the flat map's same-group arcs are drawn as animated arcs. Without WebGL or the CDN the page
   falls back to the flat view. */
const GLOBE_JS = "https://cdn.jsdelivr.net/npm/globe.gl@2.46.2/dist/globe.gl.min.js";
const GLOBE_SRI = "sha384-1uolMBZ25k3zJcNwCLEv49+L+m2dZudqAzsoSAJfQTzDCSBxJzrMuZ2dkp/5JKiT";
const GLOBE_TEXTURE = "https://cdn.jsdelivr.net/npm/three-globe@2.45.2/example/img/earth-night.jpg";
const GLOBE_BADGES = 22;
let cpGlobe = null, globeState = "idle";
function loadScript(src, integrity){
  return new Promise((resolve, reject) => {
    const el = document.createElement("script");
    el.src = src; el.async = true; el.crossOrigin = "anonymous";
    if (integrity) el.integrity = integrity;
    el.onload = resolve; el.onerror = () => reject(new Error("could not load " + src));
    document.head.appendChild(el);
  });
}
function webglOk(){
  try { const c = document.createElement("canvas"); return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl"))); } catch (_){ return false; }
}
async function initGlobe(){
  if (globeState !== "idle") return;
  const el = $("#cp-globe");
  if (!el || !webglOk()){ globeState = "failed"; setView("flat"); return; }
  globeState = "loading";
  try {
    if (typeof Globe === "undefined") await loadScript(GLOBE_JS, GLOBE_SRI);
    loadAtlas(); // country lookup for globe clicks + centroids for countries missing from CENTROIDS
    const g = new Globe(el, { animateIn: !REDUCED_MOTION })
      .backgroundColor("rgba(0,0,0,0)")
      .globeImageUrl(GLOBE_TEXTURE)
      .atmosphereColor("#4a8cff")
      .atmosphereAltitude(0.2)
      .width(el.clientWidth).height(el.clientHeight)
      .htmlLat("lat").htmlLng("lng").htmlAltitude(0.012)
      .htmlElement(d => d.el)
      .htmlTransitionDuration(0)
      .arcStartLat("sLat").arcStartLng("sLng").arcEndLat("eLat").arcEndLng("eLng")
      .arcColor(d => [d.color + "10", d.color])
      .arcStroke(0.45)
      .arcAltitudeAutoScale(0.35)
      .arcDashLength(0.45).arcDashGap(1.2)
      .arcDashAnimateTime(REDUCED_MOTION ? 0 : 2600)
      .arcLabel(d => esc(d.group) + ": " + esc(ccName(d.from)) + " → " + esc(ccName(d.to)))
      .onGlobeClick(({ lat, lng }) => {
        const id = maskAt(lat, lng);
        const cc = id && id !== 65535 ? maskCountries[id - 1].cc : null;
        if (cc) setCountry(cc);
      });
    const ctl = g.controls();
    ctl.enableZoom = false; // page scroll must keep working over the stage
    ctl.autoRotate = false;
    if (window.ResizeObserver) new ResizeObserver(() => { if (el.clientWidth) g.width(el.clientWidth).height(el.clientHeight); }).observe(el);
    cpGlobe = g;
    globeState = "ready";
    if (activeTab !== "country" || geoView !== "globe") g.pauseAnimation();
    aimGlobe(0);
    updateGlobe();
  } catch (e){
    globeState = "failed";
    console.warn("Geo Intel globe unavailable", e);
    setView("flat");
  }
}
function aimGlobe(ms){
  if (!cpGlobe) return;
  const dur = REDUCED_MOTION ? 0 : (ms == null ? 1400 : ms);
  const p = cpCC && posOf(cpCC);
  // A country is centred with latitude eased toward the equator so polar countries don't tip the
  // globe over; a region is centred on its REGION_VIEW box.
  if (p) cpGlobe.pointOfView({ lat: p[0] * 0.7, lng: p[1], altitude: 1.7 }, dur);
  else {
    const b = REGION_VIEW[currentRegion] || REGION_VIEW.all;
    cpGlobe.pointOfView(currentRegion === "all" ? { lat: 22, lng: 40, altitude: 2.2 } : { lat: (b[2] + b[3]) / 2, lng: (b[0] + b[1]) / 2, altitude: 1.6 }, dur);
  }
}
function updateGlobe(){
  if (!cpGlobe) return;
  const cc = cpCC;
  const counts = mapScene.ranked || [];
  const top = counts.slice(0, GLOBE_BADGES);
  if (cc && !top.some(([c]) => c === cc)) top.push([cc, (counts.find(([c]) => c === cc) || [cc, 0])[1]]);
  const claimsHere = cc ? scopePool(null, cc) : [];
  const topGroup = countByKey(claimsHere, "group")[0];
  const data = top.map(([c, n]) => {
    const p = posOf(c);
    if (!p) return null;
    const wrap = document.createElement("div");
    const b = document.createElement("button");
    b.type = "button"; b.className = "gb-badge"; b.textContent = n;
    b.style.setProperty("--rc", regionColor(ccRegion(c)));
    b.title = ccName(c) + " · " + n + " claims, last " + rangeDays + " days";
    b.addEventListener("click", e => { e.stopPropagation(); setCountry(c); });
    if (c === cc){
      wrap.className = "gb-sel";
      const cardEl = document.createElement("div");
      cardEl.className = "gb-card";
      cardEl.innerHTML = '<span class="k">' + esc(regionLabel(ccRegion(c))) + "</span><b>" + flagEmoji(c) + " " + esc(ccName(c)) + "</b>" +
        (claimsHere.length ? claimsHere.length + " leak-site claims in " + rangeDays + " days" + (topGroup ? "<br>Most active: " + esc(topGroup[0]) + " (" + topGroup[1] + ")" : "") : "No claims in this window");
      wrap.appendChild(cardEl);
    }
    wrap.appendChild(b);
    return { lat: p[0], lng: p[1], el: wrap };
  }).filter(Boolean);
  cpGlobe.htmlElementsData(data);
  cpGlobe.arcsData((mapScene.arcs || []).map(a => {
    const f = posOf(a.from), t = posOf(a.to);
    return f && t ? { sLat: f[0], sLng: f[1], eLat: t[0], eLng: t[1], color: a.color, group: a.group, from: a.from, to: a.to } : null;
  }).filter(Boolean));
}
function wireCountry(){
  const form = $("#cp-form"), input = $("#cp-search");
  if (form) form.addEventListener("submit", e => {
    e.preventDefault();
    const cc = resolveCountry(input.value, true);
    if (cc){ setCountry(cc); input.value = ""; input.blur(); }
  });
  // Picking from the datalist fills the exact name — switch right away, but not on every keystroke.
  if (input) input.addEventListener("input", () => {
    const cc = resolveCountry(input.value, false);
    if (cc && ccName(cc).toLowerCase() === input.value.trim().toLowerCase()){ setCountry(cc); input.value = ""; }
  });
  const body = $("#cp-body");
  if (body) body.addEventListener("click", e => {
    if (!e.target.closest('[data-act="more-claims"]')) return;
    claimsExpanded = !claimsExpanded;
    renderGeoBody();
  });
}

/* ---------------- Region filter (header segment + map region tabs) ---------------- */
function syncGeoUi(){
  document.querySelectorAll("[data-geo]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.geo === geo)));
  const eyebrow = $("#scope-eyebrow");
  if (eyebrow) eyebrow.textContent = geo === "all" ? "Global · all regions" : "Region · " + geoLabel();
}
function setGeo(key){
  geo = normGeo(key);
  currentRegion = geo;
  try { localStorage.setItem("apjti.geo", geo); } catch (_){}
  syncGeoUi();
  cpCC = null; // a new region goes back to its overview on Geo Intel
  claimsExpanded = false;
  if (activeTab === "country") history.replaceState(null, "", "#country");
  renderActors();
  renderApt();
  renderAll();
}

/* ---------------- Init ---------------- */
async function renderAll(){
  renderRw();
  renderActors();
  renderRansomwareNews();
  renderTelegram();
  renderVulnerabilities();
  renderIocs();
  renderSnapshot();
  renderKev();
  makeBrief();
  renderFlows();
  buildDashboard();
}

async function init(){
  $("#today").textContent = new Date().toLocaleDateString(undefined, { weekday:"long", year:"numeric", month:"long", day:"numeric" });
  document.querySelectorAll("[data-t]").forEach(x => x.setAttribute("aria-pressed", String(parseInt(x.dataset.t, 10) === rangeDays)));
  document.querySelectorAll("[data-tgf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.tgf === tgFilter)));
  syncGeoUi();
  document.querySelectorAll("[data-vf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.vf === vulnFilter)));
  document.querySelectorAll("[data-iocf]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.iocf === iocFilter)));
  renderActors();
  wireActions();
  wireApt();
  wireRw();
  wireVulns();
  wireActors();
  wireFlows();
  wireIpCheck();
  wireNavToggle();
  wireThemeToggle();
  wireTabs();
  wireCountry();
  const h = parseHash(location.hash);
  if (h.cc) cpCC = h.cc;
  if (h.actor) acTab = "tracked";
  const startTab = TAB_IDS.includes(h.id) ? h.id : (localStorage.getItem("apjti.tab") || "brief");
  // Rewrite the hash only when it doesn't already name this view (e.g. an old "#map" link).
  showTab(startTab, { skipHash: location.hash === "#" + startTab + (h.cc ? "/" + h.cc : "") || !!h.actor });

  try {
    await loadData();
    renderAll();
    if (h.actor && activeTab === "actors") openActor(h.actor);
  } catch (e){
    showError("Could not load /api/data (" + e.message + "). Is the Worker deployed and has the scheduled collector run at least once? Try POST /api/refresh.");
  }

  setInterval(async () => {
    try { await loadData(); renderAll(); } catch (e){ /* keep showing last-good data */ }
  }, REFRESH_POLL_MS);
}
init();
