/**
 * Threat Intelligence — Cloudflare Worker backend (global, filterable by region and country).
 *
 * - `scheduled()` runs on a cron trigger, fetches OSINT feeds + ransomware.live
 *   server-side (no CORS restrictions here, unlike a browser), tags items,
 *   merges with the accumulated history in KV, and writes the result back.
 * - `fetch()` serves /api/data (cached JSON) and /api/refresh (manual trigger).
 *   Everything else is served as a static asset from /public (see wrangler.toml).
 */

const SOURCES = [
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { name: "The Hacker News",  url: "https://thehackernews.com/feeds/posts/default?alt=rss" },
  { name: "SANS ISC",         url: "https://isc.sans.edu/rssfeed_full.xml" },
  { name: "Infosecurity Mag", url: "https://www.infosecurity-magazine.com/rss/news/" },
  { name: "Akamai Blog",      url: "https://feeds.feedburner.com/akamai/blog" },
  { name: "JPCERT/CC",        url: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf" },
  { name: "Unit 42",          url: "https://unit42.paloaltonetworks.com/feed/" },
  { name: "Talos",            url: "https://blog.talosintelligence.com/rss/" },
  { name: "Securelist",       url: "https://securelist.com/feed/" },
  { name: "CISA Advisories",  url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { name: "Krebs on Security",url: "https://krebsonsecurity.com/feed/" },
  { name: "Dark Reading",     url: "https://www.darkreading.com/rss.xml" },
  { name: "Cyble",            url: "https://cyble.com/feed/" },
  { name: "NCSC UK",          url: "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml" },
  // Government CERTs
  { name: "ACSC",             url: "https://www.cyber.gov.au/rss/news" },
  { name: "CERT-FR",          url: "https://www.cert.ssi.gouv.fr/feed/" },
  // Vendor threat research
  { name: "Check Point Research", url: "https://research.checkpoint.com/feed/" },
  { name: "CrowdStrike",      url: "https://www.crowdstrike.com/en-us/blog/feed" },
  { name: "ESET WeLiveSecurity", url: "https://feeds.feedburner.com/eset/blog" },
  { name: "GreyNoise",        url: "https://www.greynoise.io/blog/rss.xml" },
  { name: "Group-IB",         url: "https://www.group-ib.com/feed/blogfeed/" },
  { name: "Intel 471",        url: "https://www.intel471.com/blog/feed" },
  { name: "Malwarebytes",     url: "https://www.malwarebytes.com/blog/feed/index.xml" },
  { name: "Microsoft Security", url: "https://www.microsoft.com/en-us/security/blog/feed/" },
  { name: "Proofpoint",       url: "https://www.proofpoint.com/us/threat-insight-blog.xml" },
  { name: "Project Zero",     url: "https://projectzero.google/feed.xml" },
  { name: "Rapid7",           url: "https://www.rapid7.com/rss.xml" },
  { name: "Recorded Future",  url: "https://www.recordedfuture.com/feed" },
  { name: "Red Canary",       url: "https://redcanary.com/feed/" },
  { name: "SentinelLabs",     url: "https://www.sentinelone.com/labs/feed/" },
  { name: "The DFIR Report",  url: "https://thedfirreport.com/feed/" },
  { name: "Volexity",         url: "https://www.volexity.com/feed/" },
  { name: "Zscaler ThreatLabz", url: "https://www.zscaler.com/blogs/feeds/security-research" },
  // News / research journalism
  { name: "Citizen Lab",      url: "https://citizenlab.ca/feed/" },
  { name: "Help Net Security", url: "https://www.helpnetsecurity.com/feed/" },
  { name: "Risky Business",   url: "https://risky.biz/feeds/risky-business-news/" },
  { name: "SecurityWeek",     url: "https://www.securityweek.com/feed/" },
  { name: "The Record",       url: "https://therecord.media/feed" }
];
// Mastodon (Fediverse) hashtag/account URLs natively support a `.rss` suffix for a plain public
// feed — no login/API key/scraping trick needed, unlike Telegram's HTML preview or X's dead ends.
// Routed to their own topic surface (the Ransomware page's "Community & social signal" list, via
// parseItems() + ransomwareNews below) rather than the general Feed, since these are unmoderated
// hashtag firehoses / a single account mirror, not vetted news. Only the two ransomware-topic ones
// were wired in; mastodon_tag_threatintel/cve/cybersecurity weren't — there's no obvious existing
// page to route generic threat-intel or CVE content to yet, so add them once that's decided rather
// than dumping them into the general Feed by default.
const RANSOMWARE_NEWS_SOURCES = [
  { name: "Mastodon #ransomware", url: "https://mastodon.social/tags/ransomware.rss" },
  { name: "Mastodon ransomwatch", url: "https://infosec.exchange/@ransomwatch.rss" }
];
const RW_RECENT = "https://api.ransomware.live/v2/recentvictims";
// recentvictims is only the newest ~100 claims worldwide (a few days, a third of them US), so each
// full cycle also pulls the complete claim history for RW_COUNTRIES_PER_RUN countries, rotating
// through RW_COUNTRY_ROTATION by wall clock (no state to keep) — every listed country is refreshed
// about every 6.5 h. This used to be India alone, every cycle. Only countries whose full history is
// under ~450KB are listed: the US (7MB), UK, Canada and Germany (700KB+) are too big to JSON.parse
// inside a Worker's CPU budget, and they dominate recentvictims anyway.
const RW_COUNTRY_URL = "https://api.ransomware.live/v2/countryvictims/";
const RW_COUNTRY_ROTATION = ["IN","AU","JP","BR","FR","IT","MX","ES","SG","AE","SA","ZA","IL","TR","ID","MY","KR","TW","TH","NL","AR","CO","PH","NZ","CL","EG"];
const RW_COUNTRIES_PER_RUN = 2;
function rwCountriesForNow(now = Date.now()){
  const slot = Math.floor(now / 1800000) * RW_COUNTRIES_PER_RUN;
  return Array.from({ length: RW_COUNTRIES_PER_RUN }, (_, i) => RW_COUNTRY_ROTATION[(slot + i) % RW_COUNTRY_ROTATION.length]);
}
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
// EPSS (Exploit Prediction Scoring System, FIRST.org) — probability a CVE is exploited in the wild
// in the next 30 days, independent of CVSS severity. Free, no API key, no rate-limit docs published.
// Its `cve=` param supports comma-batching, but a request past ~135 CVE IDs in one URL silently
// returns zero matches (200 OK, empty `data`) rather than an error — looks like an unpublished ~2048
// char URL-length cap on their end, found empirically. Batch well under that.
const EPSS_URL = "https://api.first.org/data/v1/epss";
const EPSS_BATCH_SIZE = 100;

// Cloudflare Radar — real, measured DDoS attack traffic (not a claim) from Cloudflare's own network,
// the "confirmed" counterweight to leak-site/Telegram attack claims elsewhere in this app. Gated
// behind env.CF_RADAR_TOKEN (a free Account > Radar > Read API token — https://developers.cloudflare.com/fundamentals/api/get-started/create-token/),
// same optional-source pattern as ABUSECH_AUTH_KEY. Data is a normalized PERCENTAGE distribution
// (e.g. "34% of L3 attack traffic targeting India was UDP flood this week"), not raw attack counts or
// per-victim confirmation — Radar has no concept of "this specific claimed attack landed," only
// internet-wide attack-traffic composition, so treat this as ambient real-attack context alongside
// the claims, not a literal verifier of any one claim.
const RADAR_API_BASE = "https://api.cloudflare.com/client/v4/radar";
// L7 has no VECTOR dimension (that's an L3/L4 concept) — HTTP_METHOD is its closest analog for "what
// did the attack traffic look like."
const RADAR_L3_DIMENSION = "VECTOR";
const RADAR_L7_DIMENSION = "HTTP_METHOD";

// Structured JSON sources (not RSS) — same India/APJ/DDoS-AppSec tagging, different fetch/parse shape.
const GITHUB_ADVISORIES_URL = "https://api.github.com/advisories?per_page=30&sort=published&direction=desc";
const NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const VULN_CAP = 400; // all KEV entries (≤100) always fit; see dedupeVulnerabilities()
const NVD_MIN_CVSS = 7.0; // High/Critical only — NVD's raw firehose is too high-volume/low-relevance otherwise
const OPENPHISH_URL = "https://openphish.com/feed.txt"; // redirects to the public community feed mirror
// Must match the second entry in wrangler.toml's [triggers] crons exactly — scheduled() branches on
// event.cron to run the fast CVE-only job instead of the full ~25-source cycle on this schedule.
// Offset from :00/:10/:20/:30/:40/:50 deliberately — see the comment in wrangler.toml's [triggers]
// for why running this at the same minute as the 30-min collect() job caused a KV read-modify-write
// race that intermittently wiped iocs/telegram/ransomwareNews/ddosTelemetry on scheduled runs.
const CVE_ONLY_CRON = "5,15,25,35,45,55 * * * *";

// Public Telegram channels, scraped via the unauthenticated https://t.me/s/<handle> web preview
// (server-rendered HTML, no login/API key/bot token needed — same trick OSINT tooling generally
// uses for public channels). Verify a handle actually resolves to the right channel AND check its
// actual recent posts before adding it here — channel names get squatted (e.g. the obvious
// "falconfeedsio" guess currently hosts a phishing-kit spam channel, not FalconFeeds), some
// channels disable the /s/ preview entirely (DarkFeed, ransomwatcher, databreach all redirect /s/
// away and need the Telegram app), and some verified-legitimate channels still aren't worth
// including — vx-underground was dropped after a production sample showed it running almost
// entirely off-topic personal/political commentary rather than malware research; cveNotify (a
// real, working CVE-alert bot) was considered and skipped as redundant/too high-volume next to
// the NVD CVSS≥7 source already in SOURCES. cybdetective (OSINT tooling), avleonovnews (vuln
// management news digest), and hackmanac_cybernews (structured per-incident breach-claim alerts —
// country/threat-actor/sector fields per post, drives real India/APJ tags) were all checked
// against live content and are dense, on-topic, no-spam.
//
// `actorChannel: true` marks a channel run by a hacktivist/threat-actor group itself (as opposed
// to a third-party researcher/aggregator) — every post from it is treated as a self-claim (see
// parseTelegramChannel) rather than relying on CLAIM_KW phrase matching, and its parsed items never
// link out to whatever raw file-hosting/leak URL the actor posted (always links to the Telegram
// post itself instead). Hacktivist channels get banned/rebranded/migrated constantly, so a handle
// that resolves and looks plausible can still be a long-dead squat — verify actual recent post
// content (subscriber count, post dates, post content matching the group's known activity), not
// just an HTTP 200. Nation of Saviors and Akatsuki Cyber Team were requested alongside Ummah Sec
// but every handle found for them (via web search and BlackSwarm's source list) was either a
// near-empty squat (2–12 subscribers, only a "Channel created"/rename message) or preview-disabled
// — skipped rather than guessed; add them once a current, verified handle is known.
const TELEGRAM_CHANNELS = [
  { name: "CTI Now", handle: "ctinow" },
  { name: "Cyber Detective", handle: "cybdetective" },
  { name: "AVLeonov", handle: "avleonovnews" },
  { name: "Ummah Sec", handle: "UmmahSecurity", actorChannel: true },
  { name: "Hackmanac", handle: "hackmanac_cybernews" }
];
// Every Telegram post must clear this relevance bar (or already be DDoS/AppSec-lens-tagged) to be
// kept at all — these channels are unmoderated, unlike the RSS/JSON sources, so filtering out
// off-topic noise (personal chatter, unrelated news) happens here rather than trusting the source.
const CTI_RELEVANCE_KW = ["malware","ransomware","breach","hack","hacked","hacker","exploit","exploited","vulnerability","vulnerabilities","cve","phishing","apt","threat actor","backdoor","botnet","ddos","leak","leaked","cyberattack","cyber attack","cybercrime","cyber fraud","zero-day","zero day","rce","remote code execution","spyware","trojan","infostealer","stealer","credential","supply chain","incident response","compromise","compromised","scam","security flaw","patch","advisory","c2","command and control","osint","forensics","pentest","penetration test","dark web","data breach","data leak","threat intelligence","vulnerability management","misconfiguration","unauthorized access","privilege escalation","sql injection","cross-site scripting","injection","mitre att&ck","ioc","indicators of compromise","cybersecurity","infosec","apk","otp fraud","sim swap","identity theft"];
// Heuristic keyword flag for posts where an actor/group is claiming or confirming a specific
// compromise (breach, ransomware, DDoS) rather than just reporting news generally.
const CLAIM_KW = ["claims responsibility","claimed responsibility","takes responsibility","confirms breach","confirmed breach","claims to have hacked","claims to have breached","claims to have compromised","hacked by","breached by","leaked by","attacked by","targeted by","ddos attack on","ddosed","knocked offline","taken offline","brought down","defaced by","added to their victim list","listed as a victim","new victim","database leaked","selling access","ransomware attack on","compromised by","breach confirmed"];
// Actor-operational channels (see TELEGRAM_CHANNELS' actorChannel flag) sometimes dox rival
// hackers or researchers by name — posts matching this are dropped outright, unconditionally,
// regardless of channel type. This app reports on attack claims, not a private individual's PII.
const DOX_KW = ["date of birth","d.o.b","d.o.b.","home address","doxed","doxxed","doxing","dox3d","phone number:","personal information leaked","real name:","full name:","aadhaar number","passport number","national id number"];
// abuse.ch (URLhaus/ThreatFox/MalwareBazaar) require a free Auth-Key as of their 2024 API lockdown —
// register at https://auth.abuse.ch/ and set ABUSECH_AUTH_KEY as a secret to enable these.
const ABUSECH_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/";
const ABUSECH_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/";
const ABUSECH_MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/";
// Raw indicators kept per feed per cycle for the IOCs tab, on top of the one-line summary item
// each feed also contributes to `items` — capped so a single feed's firehose (URLhaus/ThreatFox can
// return hundreds of rows per pull) can't dominate the shared 500-entry rolling `iocs` window.
const ABUSECH_IOC_CAP = 50;

// MISP — CIRCL's public OSINT feed (no auth, no MISP instance needed): a daily-updated manifest of
// MISP "events" at feed-osint, each a JSON file of real indicators. Recent events are entirely
// Maltrail-sourced daily aggregates. Event file size is wildly inconsistent day to day (observed
// 20KB up to 9MB for the same feed) — MISP_MAX_EVENT_BYTES skips oversized ones via Content-Length
// before parsing rather than risking a multi-MB JSON.parse in a Worker's CPU budget; skipped days
// just yield fewer IOCs, self-healing the next day/next smaller event.
const MISP_MANIFEST_URL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json";
const MISP_EVENT_BASE_URL = "https://www.circl.lu/doc/misp/feed-osint/";
const MISP_MAX_EVENT_BYTES = 2000000;
const MISP_EVENT_LIMIT = 5; // how many of the most recent manifest entries to try
const MISP_EVENTS_TO_KEEP = 3; // stop once this many (under-size) events have contributed IOCs
const MISP_IOC_CAP = 50; // matches ABUSECH_IOC_CAP
// Deliberately excludes "url" — every url-type attribute observed in this feed's Maltrail-sourced
// events was a citation/reference link (a GitHub commit, a tweet, a VirusTotal GUI page) pointing at
// evidence for an indicator, not a malicious URL itself, unlike abuse.ch's URLhaus where url really
// is the indicator. Only types confirmed to be real indicators in sample data are kept.
const MISP_IOC_TYPES = new Set(["ip-dst", "ip-src", "domain", "hostname", "md5", "sha1", "sha256"]);

// Every country the app can place on the map or tag, by region. Keep in sync with REGION_CC in
// public/app.js. Regions are the filter set used across the UI (APJ, Europe, N. America — incl.
// Central America and the Caribbean — S. America, Middle East, Africa); anything not listed (and
// every victim with no country) falls into "other".
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

// Country keyword lists for tagging free text (news, Telegram, Mastodon, APT-sheet targets). First
// entry is the display name. Word-boundary, case-insensitive, longest match first — so "north
// korean" tags KP rather than also tripping KR's "korean", and "latin american" doesn't count as US.
// Ambiguous names are left out on purpose (Georgia the US state, Jordan, Chad, Niger, Mali, Guinea);
// only their unambiguous cities/demonyms are listed. Keywords ending in punctuation lose it ("u.s"
// not "u.s.") because \b can't follow a "." before a space. A mention is a mention: "Chinese
// hackers" tags CN the same way it used to tag APJ — it means "relevant to", not "victim in".
// India keeps its extra non-name keywords (CERT-In, Aadhaar, UPI, India-targeting groups) from the
// old India-first lists. Add a country here and to REGION_CC to make it taggable.
const GEO_KW = {
  IN: ["India","indian","cert-in","aadhaar","upi","npci","rbi","sebi","bharat","mumbai","new delhi","delhi","bengaluru","bangalore","hyderabad","chennai","kolkata","pune","transparent tribe","apt36","apt-36","sidecopy","side-copy","patchwork","donot team","bitter apt","sidewinder"],
  JP: ["Japan","japanese","tokyo","osaka","jpcert","nihon"],
  CN: ["China","chinese","beijing","shanghai","shenzhen","prc"],
  KR: ["South Korea","south korean","korean","seoul","republic of korea"],
  KP: ["North Korea","north korean","dprk","pyongyang","lazarus","kimsuky"],
  TW: ["Taiwan","taiwanese","taipei"],
  AU: ["Australia","australian","sydney","melbourne","canberra","acsc"],
  NZ: ["New Zealand","auckland"],
  SG: ["Singapore","singaporean"],
  VN: ["Vietnam","vietnamese","viet nam","hanoi"],
  TH: ["Thailand","thai","bangkok"],
  ID: ["Indonesia","indonesian","jakarta"],
  MY: ["Malaysia","malaysian","kuala lumpur"],
  PH: ["Philippines","philippine","filipino","manila"],
  BD: ["Bangladesh","bangladeshi","dhaka"],
  LK: ["Sri Lanka","sri lankan"],
  NP: ["Nepal","nepalese","nepali","kathmandu"],
  PK: ["Pakistan","pakistani","islamabad","karachi","balochistan"],
  MM: ["Myanmar","burma","burmese"],
  KH: ["Cambodia","cambodian","phnom penh"],
  HK: ["Hong Kong"],
  MO: ["Macau","macao"],
  LA: ["Laos","lao pdr"],
  BN: ["Brunei"],
  MN: ["Mongolia","mongolian"],
  MV: ["Maldives"],
  BT: ["Bhutan"],
  AF: ["Afghanistan","afghan","kabul"],
  KZ: ["Kazakhstan","kazakh"],
  UZ: ["Uzbekistan","uzbek"],
  KG: ["Kyrgyzstan"],
  TJ: ["Tajikistan"],
  TM: ["Turkmenistan"],
  PG: ["Papua New Guinea"],
  FJ: ["Fiji"],
  TL: ["Timor-Leste","east timor"],
  GB: ["United Kingdom","british","britain","england","scotland","wales","london","u.k","ncsc uk"],
  IE: ["Ireland","irish","dublin"],
  FR: ["France","french","paris","anssi","cert-fr"],
  DE: ["Germany","german","berlin"],
  ES: ["Spain","spanish","madrid"],
  PT: ["Portugal","portuguese","lisbon"],
  IT: ["Italy","italian","rome","milan"],
  NL: ["Netherlands","dutch","amsterdam","the hague"],
  BE: ["Belgium","belgian","brussels"],
  LU: ["Luxembourg"],
  CH: ["Switzerland","swiss","zurich","geneva"],
  AT: ["Austria","austrian","vienna"],
  SE: ["Sweden","swedish","stockholm"],
  NO: ["Norway","norwegian","oslo"],
  DK: ["Denmark","danish","copenhagen"],
  FI: ["Finland","finnish","helsinki"],
  IS: ["Iceland","icelandic"],
  PL: ["Poland","polish","warsaw"],
  CZ: ["Czechia","czech republic","czech","prague"],
  SK: ["Slovakia","slovak"],
  HU: ["Hungary","hungarian","budapest"],
  RO: ["Romania","romanian","bucharest"],
  BG: ["Bulgaria","bulgarian"],
  GR: ["Greece","greek","athens"],
  HR: ["Croatia","croatian"],
  SI: ["Slovenia","slovenian"],
  RS: ["Serbia","serbian","belgrade"],
  BA: ["Bosnia and Herzegovina","bosnia"],
  ME: ["Montenegro"],
  MK: ["North Macedonia","macedonia"],
  AL: ["Albania","albanian"],
  XK: ["Kosovo"],
  EE: ["Estonia","estonian"],
  LV: ["Latvia","latvian"],
  LT: ["Lithuania","lithuanian"],
  UA: ["Ukraine","ukrainian","kyiv","kiev","cert-ua"],
  BY: ["Belarus","belarusian"],
  MD: ["Moldova","moldovan"],
  RU: ["Russia","russian","moscow","kremlin"],
  CY: ["Cyprus"],
  MT: ["Malta","maltese"],
  GE: ["Georgia","tbilisi"],
  AM: ["Armenia","armenian"],
  AZ: ["Azerbaijan","azerbaijani","baku"],
  US: ["United States","u.s","usa","american","americans"],
  CA: ["Canada","canadian","ottawa","toronto"],
  MX: ["Mexico","mexican"],
  GT: ["Guatemala"], HN: ["Honduras"], SV: ["El Salvador"], NI: ["Nicaragua"], CR: ["Costa Rica"],
  PA: ["Panama","panamanian"], BZ: ["Belize"], CU: ["Cuba","cuban"], DO: ["Dominican Republic"],
  HT: ["Haiti"], JM: ["Jamaica"], TT: ["Trinidad and Tobago","trinidad"], BS: ["Bahamas"], BB: ["Barbados"], PR: ["Puerto Rico"],
  BR: ["Brazil","brazilian","são paulo","sao paulo"],
  AR: ["Argentina","argentine","argentinian","buenos aires"],
  CO: ["Colombia","colombian","bogota","bogotá"],
  CL: ["Chile","chilean"],
  PE: ["Peru","peruvian"],
  VE: ["Venezuela","venezuelan"],
  EC: ["Ecuador","ecuadorian"],
  BO: ["Bolivia"], PY: ["Paraguay"], UY: ["Uruguay"], GY: ["Guyana"], SR: ["Suriname"],
  TR: ["Türkiye","turkey","turkiye","turkish","istanbul","ankara"],
  SA: ["Saudi Arabia","saudi","riyadh"],
  AE: ["United Arab Emirates","emirati","uae","dubai","abu dhabi"],
  IL: ["Israel","israeli","tel aviv"],
  IR: ["Iran","iranian","tehran"],
  IQ: ["Iraq","iraqi"],
  JO: ["Jordan","jordanian","amman"],
  LB: ["Lebanon","lebanese"],
  SY: ["Syria","syrian"],
  KW: ["Kuwait"], QA: ["Qatar","qatari","doha"], BH: ["Bahrain"], OM: ["Oman","omani"],
  YE: ["Yemen","yemeni","houthi"],
  EG: ["Egypt","egyptian","cairo"],
  PS: ["Palestine","palestinian","gaza","west bank"],
  ZA: ["South Africa","south african","johannesburg"],
  NG: ["Nigeria","nigerian","lagos"],
  KE: ["Kenya","kenyan","nairobi"],
  MA: ["Morocco","moroccan"],
  DZ: ["Algeria","algerian"],
  TN: ["Tunisia","tunisian"],
  LY: ["Libya","libyan"],
  GH: ["Ghana","ghanaian"],
  ET: ["Ethiopia","ethiopian"],
  TZ: ["Tanzania"], UG: ["Uganda"], SN: ["Senegal"], CI: ["Côte d'Ivoire","ivory coast","cote d'ivoire"],
  CM: ["Cameroon"], AO: ["Angola"], ZW: ["Zimbabwe"], ZM: ["Zambia"], MZ: ["Mozambique"], RW: ["Rwanda"],
  SD: ["Sudan","sudanese"], SS: ["South Sudan"], SO: ["Somalia"], NA: ["Namibia"], BW: ["Botswana"],
  MU: ["Mauritius"], MG: ["Madagascar"], CD: ["DR Congo","democratic republic of the congo","drc"], BF: ["Burkina Faso"]
};
// The display name is also a keyword — except where the name itself is the ambiguous word
// (Georgia, Jordan): those match only on their unambiguous entries.
const GEO_NAME_ONLY = new Set(["GE", "JO"]);
// Region-level vocabulary that names no single country.
const REGION_KW = {
  apj: ["apac","apj","asia-pacific","asia pacific","southeast asia","south asia","east asia","asean","indo-pacific","mustang panda","apt41","apt-41","salt typhoon","volt typhoon"],
  eu: ["europe","european","european union","enisa","europol","nordic","baltic","balkans"],
  na: ["north america","north american","central america","central american","caribbean"],
  sa: ["south america","south american","latin america","latin american","latam"],
  me: ["middle east","middle eastern","gulf states","gcc","mena"],
  af: ["africa","african","sub-saharan"]
};
// Acronyms that are only country names in capitals ("US" vs "us") — matched case-sensitively.
const GEO_CASED = { US: "US", USA: "US", UK: "GB", EU: "eu" };
// Feeds that are about one country by definition, whatever the headline says.
const SOURCE_CC = { "JPCERT/CC": "JP", "ACSC": "AU", "CERT-FR": "FR", "NCSC UK": "GB", "CISA Advisories": "US" };
const COUNTRY_NAME = Object.fromEntries(Object.entries(GEO_KW).map(([cc, kw]) => [cc, kw[0]]));
const GEO_KW_MAP = new Map();
for (const [cc, kw] of Object.entries(GEO_KW)) kw.slice(GEO_NAME_ONLY.has(cc) ? 1 : 0).forEach(k => GEO_KW_MAP.set(k.toLowerCase(), cc));
for (const [rg, kw] of Object.entries(REGION_KW)) kw.forEach(k => GEO_KW_MAP.set(k, rg));
const reEsc = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const RE_GEO = new RegExp("\\b(" + [...GEO_KW_MAP.keys()].sort((a, b) => b.length - a.length).map(reEsc).join("|") + ")\\b", "g");
const RE_GEO_CASED = new RegExp("\\b(" + Object.keys(GEO_CASED).join("|") + ")\\b(?![$€£])", "g");
// → { cc: ["IN","PK"], rg: ["apj"] }. Region keys are lowercase, country codes uppercase.
function geoTag(hay, srcName){
  const cc = new Set(), rg = new Set();
  const add = t => { if (!t) return; if (t === t.toUpperCase()){ cc.add(t); if (CC_REGION[t]) rg.add(CC_REGION[t]); } else rg.add(t); };
  add(SOURCE_CC[srcName]);
  const text = String(hay || "");
  for (const m of text.toLowerCase().matchAll(RE_GEO)) add(GEO_KW_MAP.get(m[1]));
  for (const m of text.matchAll(RE_GEO_CASED)) add(GEO_CASED[m[1]]);
  return { cc: [...cc].slice(0, 8), rg: [...rg] };
}

const LENS_KW = ["ddos","denial of service","denial-of-service","botnet","mirai","waf","web application firewall","api","apis","bot","bots","layer 7","layer 3","layer 4","l7","l3","l4","application-layer","credential stuffing","account takeover","web shell","webshell","scraping","scraper","volumetric","amplification","reflection attack","http flood","rate limiting","sql injection","injection","xss","cross-site scripting","rce","remote code execution","cdn"];
// CVE weakness classes an edge WAF/virtual-patch rule can typically mitigate (request-shape blocking),
// as opposed to e.g. a memory-corruption or local-privilege-escalation bug a WAF has no visibility into.
// CWE IDs come from NVD's `weaknesses` field and GitHub Advisories' `cwes` field when present; the
// keyword list below (WAF_KW, matched via the same kwRegex() used for IN/APJ/LENS) is the fallback for
// sources without structured CWE data (CISA KEV, or NVD/GHSA entries missing a weaknesses classification).
const WAF_CWE = new Set(["CWE-89","CWE-79","CWE-78","CWE-77","CWE-94","CWE-95","CWE-98","CWE-611","CWE-918","CWE-22","CWE-434","CWE-502","CWE-352","CWE-601","CWE-444","CWE-113"]);
const WAF_KW = ["sql injection","cross-site scripting","xss","remote code execution","command injection","os command injection","code injection","path traversal","directory traversal","server-side request forgery","ssrf","xml external entity","xxe","deserialization","insecure deserialization","arbitrary file upload","unrestricted file upload","open redirect","request smuggling","response splitting","server-side template injection","ssti","local file inclusion","remote file inclusion","lfi","rfi"];

function kwRegex(list){ return new RegExp("\\b(" + list.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")\\b", "i"); }
const RE_LENS = kwRegex(LENS_KW), RE_CLAIM = kwRegex(CLAIM_KW), RE_RELEVANT = kwRegex(CTI_RELEVANCE_KW), RE_DOX = kwRegex(DOX_KW), RE_WAF = kwRegex(WAF_KW);

function isWafApplicable(cwes, text){
  if ((cwes || []).some(c => WAF_CWE.has(String(c).toUpperCase()))) return true;
  return RE_WAF.test(String(text || "").toLowerCase());
}

function decode(s){
  return String(s || "")
    .replace(/<!\[CDATA\[/g, "").replace(/\]\]>/g, "")
    // Unescape entities before stripping tags, not after — most feeds wrap HTML in a CDATA block
    // (literal "<p>", stripped fine either order), but Mastodon XML-escapes it instead ("&lt;p&gt;"),
    // which the old tag-strip-then-unescape order left as literal "<p>" text in the output.
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&nbsp;/g, " ")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(n))
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ").trim();
}
function tag(xml, name){
  const m = xml.match(new RegExp("<" + name + "[^>]*>([\\s\\S]*?)<\\/" + name + ">", "i"));
  return m ? m[1].trim() : "";
}

// Country codes, regions, and the DDoS/AppSec lens for one item's text. See geoTag() above.
function tagFlags(hay, srcName){
  return Object.assign(geoTag(hay, srcName), { lens: RE_LENS.test(hay.toLowerCase()) });
}
// Items stored before country tagging existed only carry the old india/apj flags — tag them from
// their text on the next merge so the whole rolling window is filterable by region and country.
function withGeo(i){
  if (Array.isArray(i.cc)) return i;
  const t = tagFlags((i.title || "") + " " + (i.desc || ""), i.channel ? "" : i.src);
  const out = Object.assign({}, i, { cc: t.cc, rg: t.rg });
  delete out.india; delete out.apj;
  return out;
}

function parseItems(xml, srcName){
  const out = [];
  // <entry> is Atom (e.g. Project Zero) — without it every Atom-only feed silently parsed to 0 items.
  const re = /<(item|entry)[\s>][\s\S]*?<\/\1>/gi;
  let m;
  while ((m = re.exec(xml)) !== null && out.length < 60){
    const block = m[0];
    let link = decode(tag(block, "link"));
    if (!link){ const g = block.match(/rdf:about="([^"]+)"/); if (g) link = g[1]; }
    // Atom links are self-closing <link href="..."/>; prefer rel="alternate", else the first href.
    if (!link){
      const links = block.match(/<link\b[^>]*>/gi) || [];
      const href = l => { const g = l.match(/href=["']([^"']+)["']/i); return g ? g[1] : ""; };
      const alt = links.find(l => /rel=["']alternate["']/i.test(l)) || links.find(l => !/rel=/i.test(l)) || links[0];
      if (alt) link = decode(href(alt));
    }
    const dateRaw = tag(block, "pubDate") || tag(block, "dc:date") || tag(block, "published") || tag(block, "updated") || "";
    const rawDesc = decode(tag(block, "description") || tag(block, "summary") || tag(block, "content"));
    // Microblog-style feeds (Mastodon) have no <title> at all — the whole post is the description.
    const title = decode(tag(block, "title")) || rawDesc.slice(0, 140);
    const desc = rawDesc.slice(0, 300);
    if (!title) continue;
    const d = dateRaw ? new Date(decode(dateRaw)) : null;
    // Some feeds (observed: Dark Reading's "[Virtual Event] ..." listings) put the event's future
    // date in <pubDate> rather than a real publish date. A single such item becomes the max date
    // across every item once merged, which anchors the frontend's trend chart/rolling windows into
    // the future — past every item with a real date — making those charts look broken rather than
    // just missing one bad item. +1 day allows for ordinary clock skew between feed and Worker.
    const dateValid = d && !isNaN(d) && d.getTime() <= Date.now() + FUTURE_DATE_CUTOFF_MS;
    out.push(Object.assign({
      src: srcName, title, link, desc,
      date: dateValid ? d.toISOString() : null
    }, tagFlags(title + " " + desc, srcName)));
  }
  return out;
}

/* ---- CVE enrichment for the Vulnerabilities page ----
   Every CVE record can carry a `vx` object with what its sources state in structured form, so the
   page can say where each fact came from instead of guessing:
     cvssVer/vec/cvssSrc  the CVSS score's version, vector and who scored it (NVD, a CNA, GitHub)
     products             [{ vendor, product, versions, fixed, src }] — src is "CNA" (the CVE record's
                          own affected data), "NVD CPE", "GitHub", "CISA KEV", or "inferred" (pattern
                          match on the description; dropped as soon as any structured source exists)
     refs                 reference URLs by NVD tag: advisory, patch, exploit, mitigation, thirdParty,
                          virtualPatch (a WAF vendor's rule/virtual-patch page), other (untagged)
     maturity / ssvc      CVSS 4.0 exploit maturity (E:) and CISA's SSVC "exploitation" decision point
     published/modified/status/cna, kevAdded/kevDue/kevAction/kevNotes/kevRansomware, cwes
     nvdAt                when NVD's record was last read (parseNvdCves() or the backfill)
     edge                 classifyEdge(): { cls: documented|potential|na|unknown, why, path, param, component }
   None of it is the user's own assessment — that stays in the browser (see public/app.js). */
const WAF_CWE_NAME = { "CWE-89": "SQL injection", "CWE-79": "cross-site scripting", "CWE-78": "OS command injection", "CWE-77": "command injection", "CWE-94": "code injection", "CWE-95": "eval injection", "CWE-98": "file inclusion", "CWE-611": "XML external entity", "CWE-918": "server-side request forgery", "CWE-22": "path traversal", "CWE-434": "unrestricted file upload", "CWE-502": "insecure deserialization", "CWE-352": "cross-site request forgery", "CWE-601": "open redirect", "CWE-444": "request smuggling", "CWE-113": "response splitting" };
// WAF_KW minus "remote code execution": that's an outcome, not a request-shape bug class, and most
// KEV RCEs are memory corruption an edge rule can't reliably match.
const RE_EDGE_KW = kwRegex(WAF_KW.filter(k => k !== "remote code execution"));
const RE_NOT_EDGE = /\bsandbox (?:escape|bypass)|escape (?:the|a|its) sandbox|\blocal (?:user|attacker)s?\b|\blocally\b|physical access|command[- ]line|\bcli\b|privileged (?:user|account|cli)/i;
const RE_NON_HTTP = /\b(smb|rdp|ssh|snmp|ldap|dns|ntp|mqtt|modbus|telnet|imap|smtp|ftp|bluetooth|usb|kernel|driver|firmware)\b/i;
const RE_VPATCH_URL = /(cloudflare|akamai|imperva|f5|fortinet|fortiguard|radware|barracuda|fastly|coreruleset|modsecurity)[^ ]*(waf|virtual[-_]?patch|managed[-_]?rule|signature|crs|rule)/i;
const VX_REF_CAP = 3;

function cvssSourceName(s){
  s = String(s || "");
  if (s === "nvd@nist.gov") return "NVD";
  if (s === "security-advisories@github.com") return "GitHub";
  if (s.includes("@")) return s.split("@")[1];
  return s ? "CISA ADP" : "";
}
// Prefers v3.1 (what most tools show), then 4.0, 3.0, 2.0; within a version the Primary (NVD) score.
function nvdCvss(metrics){
  for (const k of ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"]){
    const arr = (metrics || {})[k];
    if (!arr || !arr.length) continue;
    const m = arr.find(x => x.type === "Primary") || arr[0];
    const d = m.cvssData || {};
    if (typeof d.baseScore === "number") return { score: d.baseScore, ver: d.version || "", vec: d.vectorString || "", src: cvssSourceName(m.source) };
  }
  return null;
}
function capList(list, n){ return list.length > n ? list.slice(0, n).join(", ") + " +" + (list.length - n) : list.join(", "); }
function cnaProducts(affected){
  const out = new Map();
  for (const a of affected || []) for (const p of a.affectedData || []){
    if (!p.product || p.product === "n/a") continue;
    const key = (p.vendor + "|" + p.product).toLowerCase();
    if (out.has(key) || out.size >= 4) continue;
    const vs = p.versions || [];
    const ranges = vs.filter(v => v.status === "affected").map(v => {
      const from = v.version && !/^(0|\*|n\/a)$/i.test(v.version) ? v.version : "";
      if (v.lessThan) return (from ? from + " to " : "") + "< " + v.lessThan;
      if (v.lessThanOrEqual) return (from ? from + " to " : "") + "≤ " + v.lessThanOrEqual;
      return from;
    }).filter(Boolean);
    const fixed = new Set();
    vs.forEach(v => {
      (v.changes || []).forEach(c => { if (c.status === "unaffected" && c.at) fixed.add(c.at); });
      if (v.status === "affected" && v.lessThan && /\d/.test(v.lessThan)) fixed.add(v.lessThan); // "< 6.5.4" means fixed in 6.5.4
    });
    // VulDB-style records list the fixed release as a lone "unaffected" version after the affected ones.
    const unaff = vs.filter(v => v.status === "unaffected" && !v.lessThan && /\d/.test(v.version || ""));
    if (!fixed.size && unaff.length === 1 && vs.indexOf(unaff[0]) > 0) fixed.add(unaff[0].version);
    out.set(key, { vendor: p.vendor && p.vendor !== "n/a" ? p.vendor : "", product: p.product, versions: capList(ranges, 3), fixed: capList([...fixed], 3), src: "CNA" });
  }
  return [...out.values()];
}
function cpeProducts(configurations){
  const by = new Map();
  for (const conf of configurations || []) for (const node of conf.nodes || []) for (const m of node.cpeMatch || []){
    if (!m.vulnerable) continue;
    const parts = String(m.criteria || "").split(":");
    if (parts.length < 6) continue;
    const vendor = parts[3].replace(/_/g, " "), product = parts[4].replace(/_/g, " ");
    const key = vendor + "|" + product;
    if (!by.has(key)){ if (by.size >= 4) continue; by.set(key, { vendor, product, r: [], fixed: new Set() }); }
    const e = by.get(key);
    const ver = parts[5] && !/^[*-]$/.test(parts[5]) ? parts[5] : "";
    const from = m.versionStartIncluding ? m.versionStartIncluding + " to " : m.versionStartExcluding ? "> " + m.versionStartExcluding + " to " : "";
    if (m.versionEndExcluding){ e.r.push(from + "< " + m.versionEndExcluding); e.fixed.add(m.versionEndExcluding); }
    else if (m.versionEndIncluding) e.r.push(from + "≤ " + m.versionEndIncluding);
    else if (ver) e.r.push(ver);
  }
  return [...by.values()].map(e => ({ vendor: e.vendor, product: e.product, versions: capList([...new Set(e.r)], 3), fixed: capList([...e.fixed], 3), src: "NVD CPE" }));
}
// Last resort, labelled "inferred": the CNA phrasing VulDB and many others use ("…found in Ahsay
// AhsayCBS up to 10.3.2", "…in Foo Bar before 2.1").
function inferProduct(desc){
  const m = /\b(?:found|identified|discovered|detected|exists|was|is) in ([A-Z0-9][\w.+-]*(?: [A-Za-z0-9][\w.+-]*){0,4}?) (up to |before |through |prior to |versions? |v)?(\d[\w.-]*\d|\d)\b/.exec(String(desc || ""));
  if (!m) return [];
  const op = (m[2] || "").trim();
  const versions = /^(up to|through)$/.test(op) ? "≤ " + m[3] : /^(before|prior to)$/.test(op) ? "< " + m[3] : m[3];
  return [{ vendor: "", product: m[1], versions, fixed: "", src: "inferred" }];
}
function inferEndpoint(desc){
  const s = String(desc || "");
  const path = /\b(?:of the file|in the file|the file|endpoint|path|URL|route)\s+[`'"]?(\/?[\w.-]+\/[\w./%{}:~-]*|\/?[\w-]+\.(?:php|asp|aspx|jsp|do|action|cgi|html?))\b/i.exec(s);
  const param = /\bargument\s+[`'"]?([\w\[\].:-]+)/i.exec(s) || /\bparameter\s+[`'"]?([\w\[\].:-]+)/i.exec(s);
  const comp = /\bcomponent\s+([\w ./-]{2,40}?)(?=[.,]| leads| is| of\b)/i.exec(s);
  return { path: path ? path[1].replace(/[.,]$/, "") : "", param: param ? param[1] : "", component: comp ? comp[1].trim() : "" };
}
function classifyRefs(refs){
  const out = {};
  const add = (k, u) => { const l = out[k] || (out[k] = []); if (l.length < VX_REF_CAP && !l.includes(u)) l.push(u); };
  for (const r of refs || []){
    const u = typeof r === "string" ? r : r && r.url;
    if (!/^https:\/\//.test(u || "")) continue;
    const t = typeof r === "string" ? "" : (r.tags || []).join(" ");
    if (RE_VPATCH_URL.test(u)) add("virtualPatch", u);
    if (/Exploit/.test(t)) add("exploit", u);
    if (/Patch/.test(t) || (!t && /\/commit\/|\/pull\/\d/.test(u))) add("patch", u);
    if (/Mitigation/.test(t)) add("mitigation", u);
    if (/Vendor Advisory/.test(t)) add("advisory", u);
    else if (/Third Party Advisory/.test(t)) add("thirdParty", u);
    if (!t && !/\/commit\/|\/pull\/\d/.test(u)) add("other", u);
  }
  return out;
}
// Later (lower-priority) sources only fill gaps; products and refs are unioned.
function mergeVx(a, b){
  if (!a) return b ? Object.assign({}, b) : undefined;
  if (!b) return a;
  const out = Object.assign({}, b, a);
  const prods = [...(a.products || []), ...(b.products || [])];
  const seen = new Set(), structured = prods.some(p => p.src !== "inferred");
  out.products = prods.filter(p => { const k = (p.vendor + "|" + p.product).toLowerCase(); if (seen.has(k) || (structured && p.src === "inferred")) return false; seen.add(k); return true; }).slice(0, 5);
  const refs = {};
  for (const src of [a.refs, b.refs]) for (const [k, l] of Object.entries(src || {})) refs[k] = [...new Set([...(refs[k] || []), ...l])].slice(0, VX_REF_CAP);
  out.refs = refs;
  out.cwes = [...new Set([...(a.cwes || []), ...(b.cwes || [])])];
  if (a.nvdAt || b.nvdAt) out.nvdAt = [a.nvdAt, b.nvdAt].filter(Boolean).sort().pop();
  return out;
}
// Edge (WAF / virtual patch) applicability, from evidence rather than a keyword hit alone:
//   documented — a WAF vendor's rule / virtual-patch page is among the references
//   potential  — a request-shape weakness (CWE or description) on a network attack vector; preliminary
//   na         — the CVSS vector or description says it isn't reachable through a web edge
//   unknown    — nothing establishes either way
// "Validated in your environment" is the user's call, recorded in their browser, never here.
function classifyEdge(rec){
  const vx = rec.vx || {}, text = (rec.title || "") + " " + (rec.desc || "");
  const ep = inferEndpoint(rec.desc);
  const vp = (vx.refs && vx.refs.virtualPatch) || [];
  if (vp.length) return Object.assign({ cls: "documented", why: "A WAF vendor rule or virtual-patch page is referenced", ref: vp[0] }, ep);
  const av = /\/AV:([NALP])/.exec(vx.vec || "");
  if (av && av[1] !== "N") return { cls: "na", why: "CVSS attack vector is " + { A: "adjacent network", L: "local", P: "physical" }[av[1]] + ", so it isn't reached through a web edge" };
  const ne = RE_NOT_EDGE.exec(text);
  if (ne) return { cls: "na", why: "Description points to a non-web path (“" + ne[0] + "”)" };
  const cwe = (vx.cwes || []).find(c => WAF_CWE.has(String(c).toUpperCase()));
  const kw = cwe ? null : RE_EDGE_KW.exec(text);
  if (!cwe && !kw) return { cls: "unknown", why: "No web-request weakness class identified" };
  const np = RE_NON_HTTP.exec(text);
  if (np) return { cls: "unknown", why: "Web-type weakness, but the description mentions " + np[1] + ", so it may not be HTTP" };
  return Object.assign({ cls: "potential", why: (cwe ? cwe + " (" + WAF_CWE_NAME[cwe] + ")" : "Description says “" + kw[0] + "”") + (av ? " on a network attack vector" : "; attack vector not scored yet") }, ep);
}
// Records stored before `vx` existed get one here, with an inferred product from their description.
function finalizeVuln(rec){
  rec.vx = rec.vx || {};
  if (!(rec.vx.products || []).length){
    rec.vx.products = rec.vendor || rec.product ? [{ vendor: rec.vendor || "", product: rec.product || "", versions: "", fixed: "", src: "CISA KEV" }] : inferProduct(String(rec.desc || "").replace(/^CVSS [\d.]+\. |^Severity: \w+\. /, ""));
  }
  if (!rec.vendor || !rec.product){ const p = rec.vx.products.find(x => x.src !== "inferred"); if (p){ rec.vendor = rec.vendor || p.vendor; rec.product = rec.product || p.product; } }
  rec.vx.edge = classifyEdge(rec);
  rec.waf = rec.vx.edge.cls === "potential" || rec.vx.edge.cls === "documented";
  return rec;
}

function parseGithubAdvisories(json){
  const list = Array.isArray(json) ? json : [];
  return list.slice(0, 30).map(a => {
    const title = (a.ghsa_id || "") + (a.cve_id ? " (" + a.cve_id + ")" : "") + (a.summary ? ": " + a.summary : "");
    const desc = (a.severity ? "Severity: " + a.severity + ". " : "") + String(a.description || "").replace(/\r?\n+/g, " ").slice(0, 280);
    const d = a.published_at ? new Date(a.published_at) : null;
    const cwes = (a.cwes || []).map(c => c.cwe_id).filter(Boolean);
    const sev = a.cvss_severities || {};
    // An unscored version comes back as { score: 0, vector_string: null } — not a real 0.0.
    const scored = x => x && typeof x.score === "number" && x.score > 0 ? x : null;
    const pick = scored(sev.cvss_v3) || scored(sev.cvss_v4) || scored(a.cvss);
    const cvssScore = pick ? pick.score : null;
    const vec = pick ? (pick.vector_string || "") : "";
    const vx = {
      cvssVer: (/^CVSS:(\d\.\d)/.exec(vec) || [])[1] || "", vec, cvssSrc: pick ? "GitHub" : "",
      products: (a.vulnerabilities || []).filter(x => x.package && x.package.name).slice(0, 4).map(x => ({
        vendor: x.package.ecosystem || "", product: x.package.name, versions: x.vulnerable_version_range || "", fixed: x.first_patched_version || "", src: "GitHub" })),
      refs: Object.assign(classifyRefs(a.references), a.html_url ? { advisory: [a.html_url] } : {}),
      cwes, published: a.published_at || null, modified: a.updated_at || null
    };
    return Object.assign({
      src: "GitHub Advisories", title, link: a.html_url || a.url || "", desc,
      date: (d && !isNaN(d)) ? d.toISOString() : null,
      cveId: a.cve_id || null, cvssScore, waf: isWafApplicable(cwes, title + " " + desc), kev: false, vx
    }, tagFlags(title + " " + desc, "GitHub Advisories"));
  });
}

// minCvss: the 2-day window keeps only High/Critical; the per-CVE backfill passes 0 to take any record.
function parseNvdCves(json, minCvss = NVD_MIN_CVSS, nowIso = new Date().toISOString()){
  const vulns = (json && json.vulnerabilities) || [];
  const out = [];
  for (const v of vulns){
    const c = v.cve;
    if (!c || !c.id) continue;
    const metrics = c.metrics || {};
    const cv = nvdCvss(metrics);
    const score = cv ? cv.score : null;
    if (minCvss > 0 && (typeof score !== "number" || score < minCvss)) continue; // keep it high/critical-only, not a raw firehose
    const descEn = (c.descriptions || []).find(d => d.lang === "en");
    const desc = ((score != null ? "CVSS " + score + ". " : "") + (descEn ? descEn.value : "")).slice(0, 300);
    const title = c.id + (score != null ? " (CVSS " + score + ")" : "");
    const d = c.published ? new Date(c.published) : null;
    const cwes = [...new Set((c.weaknesses || []).flatMap(w => (w.description || []).filter(x => x.lang === "en").map(x => x.value)).filter(x => /^CWE-\d+$/.test(x)))];
    const v4 = (metrics.cvssMetricV40 || []).map(m => m.cvssData && m.cvssData.exploitMaturity).find(x => x && x !== "NOT_DEFINED");
    const ssvc = ((metrics.ssvcV203 || [])[0] || {}).ssvcData;
    const ssvcExp = ssvc && ((ssvc.options || []).find(o => o.exploitation) || {}).exploitation;
    let products = cnaProducts(c.affected);
    if (!products.length) products = cpeProducts(c.configurations);
    if (!products.length) products = inferProduct(descEn && descEn.value);
    const vx = {
      cvssVer: cv ? cv.ver : "", vec: cv ? cv.vec : "", cvssSrc: cv ? cv.src : "",
      products, refs: classifyRefs(c.references), cwes,
      published: c.published || null, modified: c.lastModified || null, status: c.vulnStatus || "", cna: cvssSourceName(c.sourceIdentifier),
      maturity: v4 || "", ssvc: ssvcExp || "", nvdAt: nowIso
    };
    if (c.cisaExploitAdd){ vx.kevAdded = c.cisaExploitAdd; vx.kevDue = c.cisaActionDue || ""; vx.kevAction = c.cisaRequiredAction || ""; }
    out.push(Object.assign({
      src: "NVD", title, link: "https://nvd.nist.gov/vuln/detail/" + c.id, desc,
      date: (d && !isNaN(d)) ? d.toISOString() : null,
      cveId: c.id, cvssScore: score, waf: isWafApplicable(cwes, title + " " + desc), kev: !!c.cisaExploitAdd, vx
    }, tagFlags(title + " " + desc, "NVD")));
  }
  return out;
}

function parseOpenPhish(text, cycleIso){
  const urls = String(text || "").split(/\r?\n/).map(s => s.trim()).filter(u => /^https?:\/\//i.test(u));
  if (!urls.length) return [];
  const day = cycleIso.slice(0, 10);
  const hosts = urls.slice(0, 6).map(u => { try { return new URL(u).hostname; } catch (_){ return null; } }).filter(Boolean);
  return [{
    src: "OpenPhish", title: "OpenPhish community feed: " + urls.length + " active phishing URLs tracked",
    link: OPENPHISH_URL + "#" + day,
    desc: hosts.length ? "Sample impersonated/hosting domains: " + hosts.join(", ") : "",
    date: cycleIso, cc: [], rg: [], lens: false
  }];
}

// Parses the server-rendered https://t.me/s/<handle> preview page. Each post is a
// "tgme_widget_message_wrap" block; regex over the raw markup follows the same convention as
// parseItems()'s RSS parsing above rather than a DOM parser (Workers have none built in).
function parseTelegramChannel(html, channelName, opts){
  const actorChannel = !!(opts && opts.actorChannel);
  const out = [];
  const blocks = String(html || "").split('<div class="tgme_widget_message_wrap').slice(1);
  for (const block of blocks){
    const postMatch = block.match(/data-post="([^"]+)"/);
    if (!postMatch) continue;
    const tgLink = "https://t.me/" + postMatch[1];

    const dateMatch = block.match(/<time datetime="([^"]+)"/);
    const d = dateMatch ? new Date(dateMatch[1]) : null;

    const textMatch = block.match(/<div class="tgme_widget_message_text[^"]*"[^>]*>([\s\S]*?)<\/div>/);
    const text = textMatch ? decode(textMatch[1]) : "";

    const previewLinkMatch = block.match(/<a class="tgme_widget_message_link_preview"[^>]*href="([^"]+)"/);
    const titleMatch = block.match(/<div class="link_preview_title"[^>]*>([\s\S]*?)<\/div>/);
    const descMatch = block.match(/<div class="link_preview_description"[^>]*>([\s\S]*?)<\/div>/);
    const previewTitle = titleMatch ? decode(titleMatch[1]) : "";
    const previewDesc = descMatch ? decode(descMatch[1]) : "";

    const title = (previewTitle || text.slice(0, 140) || "").trim();
    if (!title) continue;
    // When there's a link-preview title, the message text is usually just that title + the bare
    // URL again — using the preview's own description avoids restating the title as the desc.
    const desc = previewTitle ? previewDesc : (text.length > title.length ? text : "");
    // Actor-operational channels frequently link straight to leak/paste-hosted stolen data in the
    // post text (Telegram auto-generates a link-preview card for it) — always point out to the
    // Telegram post itself instead of following that link, so this app never becomes a direct
    // conduit to a breach download.
    const link = actorChannel ? tgLink : (previewLinkMatch ? previewLinkMatch[1] : tgLink);
    const hay = title + " " + text + " " + desc;
    const hayLower = hay.toLowerCase();
    // Never surface a post doxxing a private individual — unconditional, applies to every channel
    // regardless of type. Seen in practice on actor-operational channels doxxing rival hackers.
    if (RE_DOX.test(hayLower)) continue;
    const tags = tagFlags(hay, channelName);
    // Unmoderated news/research channels post plenty of off-topic chatter — require relevance. A
    // country mention alone doesn't count (it used to, for India/APJ, when those were the priority);
    // with every country taggable that would wave through any off-topic post naming a place.
    // Actor-operational channels are exempt: everything posted there is inherently an attack/leak
    // claim (often just a target name + emoji, with none of the usual CTI vocabulary) and is
    // always tagged as a claim below rather than relying on CLAIM_KW phrase matching.
    if (!actorChannel && !(tags.lens || RE_RELEVANT.test(hayLower))) continue;

    out.push(Object.assign({
      src: "Telegram · " + channelName, telegram: true, channel: channelName,
      title, link, tgLink, desc: desc.slice(0, 300),
      date: (d && !isNaN(d)) ? d.toISOString() : null
    }, tags, { claim: actorChannel || RE_CLAIM.test(hayLower) }));
  }
  return out.slice(0, 30);
}

// Fields kept per claim. Deliberately not kept: claim_url/post_url (the leak site itself — this app
// must never become a path to stolen data) and screenshot (leak-page captures can show data samples).
// `date` is when ransomware.live discovered the post; `claimed` is the actor's own post date where
// the source has one (attackdate/published). Neither is the incident date, which is rarely known.
const RW_DESC_MAX = 240;
function rwDomain(s){
  const d = String(s || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) ? d : "";
}
function parseRwJson(data, forceCc, now = new Date().toISOString()){
  let arr = data;
  if (!Array.isArray(arr)) arr = data.victims || data.data || [];
  return arr.map(v => {
    const cc = String(v.country || forceCc || "").toUpperCase();
    const name = v.victim || v.post_title || "unknown";
    let desc = String(v.description || "").replace(/\s+/g, " ").trim();
    // recentvictims often puts just the country name here; the country feed has "[AI generated] N/A".
    if (/^(\[ai generated\]\s*)?n\/?a$/i.test(desc) || desc === (COUNTRY_NAME[cc] || "\u0000") || desc === name) desc = "";
    if (desc.length > RW_DESC_MAX) desc = desc.slice(0, RW_DESC_MAX - 1).trimEnd() + "\u2026";
    const out = {
      victim: name,
      group: v.group || v.group_name || "unknown",
      cc,
      country: COUNTRY_NAME[cc] || cc || "\u2014",
      sector: (v.activity && v.activity !== "Not Found") ? v.activity : "",
      date: v.discovered || v.attackdate || null,
      seen: now,
      checked: now
    };
    const claimed = v.attackdate || v.published;
    // recentvictims' attackdate is usually within seconds of discovery — only keep a real difference.
    if (claimed && out.date && Math.abs(new Date(claimed) - new Date(out.date)) >= 3600000) out.claimed = claimed;
    const domain = rwDomain(v.domain || v.website || (/\./.test(name) ? name : ""));
    if (domain) out.domain = domain;
    if (desc) out.desc = desc;
    if (typeof v.url === "string" && v.url.startsWith("https://www.ransomware.live/")) out.link = v.url;
    const press = (Array.isArray(v.press) ? v.press : []).map(p => typeof p === "string" ? p : p && (p.url || p.link)).filter(u => /^https:\/\//.test(u || "")).slice(0, 3);
    if (press.length) out.press = press;
    return out;
  });
}

const UA = "Mozilla/5.0 (compatible; ThreatIntelBot/1.0; +https://github.com/)";

// collect() awaits ~25 sources sequentially with no concurrency — a single upstream host that
// accepts the connection but never sends a response (rather than erroring, which try/catch would
// already handle) blocks every source after it indefinitely. AbortController bounds each request
// so one hung source degrades to a single failed sourceStatus entry instead of stalling the whole
// cycle (and, on the cron path, silently freezing every source's data at its last-good state).
const FETCH_TIMEOUT_MS = 20000;
async function fetchWithTimeout(url, init){
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, Object.assign({}, init, { signal: controller.signal }));
  } finally {
    clearTimeout(timer);
  }
}
async function fetchText(url){
  const r = await fetchWithTimeout(url, { headers: { "User-Agent": UA, "Accept": "*/*" }, cf: { cacheTtl: 0 } });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return await r.text();
}
async function fetchJson(url){
  const r = await fetchWithTimeout(url, { headers: { "User-Agent": UA, "Accept": "application/json" }, cf: { cacheTtl: 0 } });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return await r.json();
}
async function postJson(url, headers, body){
  const r = await fetchWithTimeout(url, { method: "POST", headers: Object.assign({ "User-Agent": UA, "Accept": "application/json" }, headers || {}), body, cf: { cacheTtl: 0 } });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return await r.json();
}

// abuse.ch date fields come back as "YYYY-MM-DD HH:MM:SS" (URLhaus/MalwareBazaar) or
// "YYYY-MM-DD HH:MM:SS UTC" (ThreatFox) — never proper ISO 8601. Blindly appending "Z" after
// swapping the space for "T" broke on the ThreatFox shape (produced "...13:36:27 UTCZ", an
// invalid date, which threw inside .map() and failed the whole feed) — strip a trailing " UTC"
// first, and never throw: an unparseable date just yields a null firstSeen (rendered as "—")
// rather than dropping the entire feed's indicators for one bad date.
function parseAbusechDate(s){
  if (!s) return null;
  const d = new Date(String(s).trim().replace(/\s+UTC$/i, "").replace(" ", "T") + "Z");
  return isNaN(d) ? null : d.toISOString();
}

// abuse.ch raw-indicator parsers, one per feed, mapped to a common shape for the IOCs tab:
// { source, type, value, threat, tags, firstSeen, link, confidence }. Kept separate from the
// summary-item builders below so a feed's response shape only has to be understood in one place.
function parseUrlhausIocs(urls){
  return urls.slice(0, ABUSECH_IOC_CAP).map(u => ({
    source: "URLhaus", type: "url", value: u.url || "",
    threat: u.threat || "malware_download",
    tags: (u.tags || []).filter(Boolean).slice(0, 6),
    firstSeen: parseAbusechDate(u.date_added),
    link: u.urlhaus_reference || "https://urlhaus.abuse.ch/", confidence: null
  })).filter(i => i.value);
}
function parseThreatfoxIocs(iocs){
  return iocs.slice(0, ABUSECH_IOC_CAP).map(i => ({
    source: "ThreatFox", type: i.ioc_type || "ioc", value: i.ioc || i.ioc_value || "",
    threat: i.malware_printable || i.malware || i.threat_type_desc || i.threat_type || "",
    tags: (i.tags || []).filter(Boolean).slice(0, 6),
    firstSeen: parseAbusechDate(i.first_seen),
    link: i.reference || "https://threatfox.abuse.ch/", confidence: typeof i.confidence_level === "number" ? i.confidence_level : null
  })).filter(i => i.value);
}
function parseMalwareBazaarIocs(samples){
  return samples.slice(0, ABUSECH_IOC_CAP).map(s => ({
    source: "MalwareBazaar", type: "sha256", value: s.sha256_hash || "",
    threat: s.signature || s.file_type || "",
    tags: (s.tags || []).filter(Boolean).slice(0, 6),
    firstSeen: parseAbusechDate(s.first_seen),
    link: "https://bazaar.abuse.ch/sample/" + (s.sha256_hash || ""), confidence: null
  })).filter(i => i.value);
}

// abuse.ch (URLhaus/ThreatFox/MalwareBazaar) — gated behind a free Auth-Key (env.ABUSECH_AUTH_KEY).
// Two outputs per feed: one aggregated summary item per cycle (pushed onto the returned array, and
// from there into the shared `items` feed — hundreds of raw indicators a cycle would flood that feed
// with no narrative value) AND up to ABUSECH_IOC_CAP raw indicators per feed (pushed onto `iocsOut`,
// which the caller merges into the separate `iocs` array/KV field for the dedicated IOCs tab).
async function collectAbuseCh(env, cycleIso, sourceStatus, iocsOut){
  if (!env.ABUSECH_AUTH_KEY) return [];
  const out = [];
  const day = cycleIso.slice(0, 10);
  const authHeaders = { "Auth-Key": env.ABUSECH_AUTH_KEY };

  try {
    const j = await (async () => {
      const r = await fetchWithTimeout(ABUSECH_URLHAUS_URL, { headers: Object.assign({ "User-Agent": UA }, authHeaders), cf: { cacheTtl: 0 } });
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })();
    const urls = (j.urls || []);
    if (urls.length){
      const tags = [...new Set(urls.flatMap(u => u.tags || []))].slice(0, 6);
      out.push({ src: "abuse.ch URLhaus", title: "URLhaus: " + urls.length + " recent malware-hosting URLs", link: "https://urlhaus.abuse.ch/browse/#" + day, desc: tags.length ? "Top tags: " + tags.join(", ") : "", date: cycleIso, cc: [], rg: [], lens: false });
      iocsOut.push(...parseUrlhausIocs(urls));
    }
    sourceStatus["abuse.ch URLhaus"] = { ok: true, count: urls.length };
  } catch (e){ sourceStatus["abuse.ch URLhaus"] = { ok: false, error: String(e.message || e) }; }

  try {
    const j = await postJson(ABUSECH_THREATFOX_URL, authHeaders, JSON.stringify({ query: "get_iocs", days: 1 }));
    const iocs = Array.isArray(j.data) ? j.data : [];
    if (iocs.length){
      const families = [...new Set(iocs.map(i => i.malware_printable || i.malware).filter(Boolean))].slice(0, 6);
      out.push({ src: "abuse.ch ThreatFox", title: "ThreatFox: " + iocs.length + " new IOCs in the last 24h", link: "https://threatfox.abuse.ch/browse/#" + day, desc: families.length ? "Malware families: " + families.join(", ") : "", date: cycleIso, cc: [], rg: [], lens: false });
      iocsOut.push(...parseThreatfoxIocs(iocs));
    }
    sourceStatus["abuse.ch ThreatFox"] = { ok: true, count: iocs.length };
  } catch (e){ sourceStatus["abuse.ch ThreatFox"] = { ok: false, error: String(e.message || e) }; }

  try {
    // MalwareBazaar's endpoint reads a classic PHP $_POST array — unlike ThreatFox (which
    // json_decode()s the raw body regardless of content-type), it needs an explicit
    // application/x-www-form-urlencoded header or the body never gets parsed server-side
    // (query_status: "missing_query" despite a 200). fetch() with a plain string body does
    // NOT set this automatically the way curl -d does, so it must be passed explicitly.
    const j = await postJson(ABUSECH_MALWAREBAZAAR_URL, Object.assign({ "Content-Type": "application/x-www-form-urlencoded" }, authHeaders), "query=get_recent&selector=time");
    const samples = Array.isArray(j.data) ? j.data : [];
    if (samples.length){
      const sigs = [...new Set(samples.map(s => s.signature).filter(Boolean))].slice(0, 6);
      out.push({ src: "abuse.ch MalwareBazaar", title: "MalwareBazaar: " + samples.length + " new malware samples", link: "https://bazaar.abuse.ch/browse/#" + day, desc: sigs.length ? "Signatures: " + sigs.join(", ") : "", date: cycleIso, cc: [], rg: [], lens: false });
      iocsOut.push(...parseMalwareBazaarIocs(samples));
    }
    sourceStatus["abuse.ch MalwareBazaar"] = { ok: true, count: samples.length };
  } catch (e){ sourceStatus["abuse.ch MalwareBazaar"] = { ok: false, error: String(e.message || e) }; }

  return out;
}

// Maps one MISP event's Attribute array to the common IOC shape (see abuse.ch parsers above) —
// filtered to MISP_IOC_TYPES (see its comment for why "url" is excluded). `comment` on a Maltrail-
// sourced attribute is the malware/campaign family label (e.g. "lummac2", "0ktapus"); attribute-level
// Tag entries here are almost entirely MISP housekeeping (tlp:*, misp:*), so those prefixes are
// dropped rather than surfaced as if they were meaningful classification tags.
function parseMispEvent(eventJson){
  const ev = eventJson && eventJson.Event;
  if (!ev) return [];
  const attrs = ev.Attribute || [];
  return attrs
    .filter(a => MISP_IOC_TYPES.has(a.type) && a.value)
    .map(a => ({
      source: "MISP", type: a.type, value: a.value,
      threat: a.comment || "",
      tags: (a.Tag || []).map(t => t.name).filter(n => n && !n.startsWith("tlp:") && !n.startsWith("misp:")).slice(0, 6),
      firstSeen: a.timestamp ? new Date(parseInt(a.timestamp, 10) * 1000).toISOString() : (ev.date ? new Date(ev.date + "T00:00:00Z").toISOString() : null),
      link: MISP_EVENT_BASE_URL + ev.uuid, confidence: null
    }));
}

// Fetches one MISP event, but bails via Content-Length before parsing if it's over
// MISP_MAX_EVENT_BYTES (see the constant's comment) — returns { skipped: true } rather than the
// parsed body in that case, and cancels the unread body so the Worker isn't left holding the stream.
async function fetchMispEvent(uuid){
  const r = await fetchWithTimeout(MISP_EVENT_BASE_URL + uuid + ".json", { headers: { "User-Agent": UA, "Accept": "application/json" }, cf: { cacheTtl: 0 } });
  if (!r.ok) throw new Error("HTTP " + r.status);
  const len = parseInt(r.headers.get("content-length") || "0", 10);
  if (len && len > MISP_MAX_EVENT_BYTES){
    if (r.body && r.body.cancel) { try { await r.body.cancel(); } catch (e){} }
    return { skipped: true, bytes: len };
  }
  return { skipped: false, json: await r.json() };
}

// No auth, no gating — unlike abuse.ch this feed is entirely public. Tries the MISP_EVENT_LIMIT
// most recent manifest entries concurrently (each independently bounded by fetchWithTimeout), keeps
// the first MISP_EVENTS_TO_KEEP that come in under the size cap, and stops accumulating IOCs at
// MISP_IOC_CAP.
async function collectMisp(sourceStatus, iocsOut){
  try {
    const manifest = await fetchJson(MISP_MANIFEST_URL);
    const events = Object.entries(manifest)
      .map(([uuid, meta]) => ({ uuid, date: String((meta && meta.date) || "") }))
      .sort((a, b) => b.date.localeCompare(a.date))
      .slice(0, MISP_EVENT_LIMIT);

    const results = await Promise.all(events.map(({ uuid }) =>
      fetchMispEvent(uuid).catch(e => ({ skipped: true, error: String(e.message || e) }))
    ));

    let kept = 0, skippedOversized = 0, totalIocs = 0;
    for (const result of results){
      if (kept >= MISP_EVENTS_TO_KEEP || totalIocs >= MISP_IOC_CAP) break;
      if (!result || result.skipped || !result.json){ if (result && result.bytes) skippedOversized++; continue; }
      const parsed = parseMispEvent(result.json).slice(0, MISP_IOC_CAP - totalIocs);
      iocsOut.push(...parsed);
      totalIocs += parsed.length;
      kept++;
    }
    sourceStatus["MISP (CIRCL OSINT)"] = { ok: true, count: totalIocs };
  } catch (e){
    sourceStatus["MISP (CIRCL OSINT)"] = { ok: false, error: String(e.message || e) };
  }
}

function parseKev(data){
  const arr = (data && data.vulnerabilities) || [];
  return arr.map(v => ({
    cveId: v.cveID || "",
    name: v.vulnerabilityName || "",
    vendor: v.vendorProject || "",
    product: v.product || "",
    dateAdded: v.dateAdded || null,
    dueDate: v.dueDate || null,
    ransomware: v.knownRansomwareCampaignUse === "Known",
    desc: v.shortDescription || "",
    action: v.requiredAction || "",
    notes: (String(v.notes || "").match(/https:\/\/[^\s;]+/) || [""])[0],
    cwes: Array.isArray(v.cwes) ? v.cwes.filter(x => /^CWE-\d+$/.test(x)) : [],
    // KEV's JSON doesn't carry a CWE/CVSS field consistently, so this is keyword-only (no CWE input).
    waf: isWafApplicable(null, (v.vulnerabilityName || "") + " " + (v.shortDescription || ""))
  }));
}

// parseItems() already rejects future dates on fresh parses (see its comment), but that alone isn't
// enough: an item that ages out of a feed's own rolling RSS window stops being freshly re-parsed and
// from then on only survives via `prev.items` passthrough in the merge — never revisited, so a
// bad date already written to KV before that fix existed (or from a source not yet caught) would
// persist indefinitely. Renormalizing here, on every merge, catches both origins uniformly.
const FUTURE_DATE_CUTOFF_MS = 86400000; // 1 day of allowed clock skew, matching parseItems()
// Rolling cap on the main `items` feed. Shared by collect() and collectVulnerabilitiesOnly() — if they
// differ, the 10-min CVE job re-trims whatever the 30-min job kept. Raised from 500 when the RSS list
// grew to ~38 feeds: one cycle alone yields ~800 items, so 500 cut history to a few weeks.
const ITEMS_CAP = 1500;
function dedupeItems(items){
  const seen = new Set(), out = [];
  const futureCap = Date.now() + FUTURE_DATE_CUTOFF_MS;
  for (const i0 of items){
    const key = (i0.link || i0.title || "").toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    const i = (i0.date && new Date(i0.date).getTime() > futureCap) ? Object.assign({}, i0, { date: null }) : i0;
    out.push(withGeo(i));
  }
  out.sort((a, b) => (b.date || "").localeCompare(a.date || ""));
  return out;
}
// Per-region retention caps for ransomware victims, applied by capVictims() after dedupe + the
// 365-day cutoff. One shared cap on a date sort lets the busiest region (the US is ~a third of all
// leak-site claims) push every smaller region's history out within weeks, so each region keeps its
// own newest N. "other" is mostly claims ransomware.live couldn't place in a country. public/app.js's
// VICTIM_CAPS mirrors this (for the "vs previous period" KPI) — keep them in sync.
const VICTIM_CAPS = { na: 500, eu: 500, apj: 400, sa: 150, me: 150, af: 100, other: 200 };
// Input is dedupeVictims() output (newest first), so each region keeps its newest.
function capVictims(victims, caps = VICTIM_CAPS){
  const n = {};
  return victims.filter(v => { const b = ccRegion(v.cc); n[b] = (n[b] || 0) + 1; return n[b] <= caps[b]; });
}
// Input is [this cycle's parse, ...prev.victims], so the first copy of a claim is the freshest. Later
// (older) copies only fill fields the fresh one lacks — e.g. a claim seen first in a country feed
// (with a description) and later in recentvictims (without) keeps its description — and `seen`
// (when this app first observed the claim) keeps the earliest value, so it survives every re-fetch;
// `checked` is the latest time any source still listed it.
function dedupeVictims(victims){
  const byKey = new Map();
  for (const v0 of victims){
    const key = (v0.victim + "|" + v0.group).toLowerCase();
    const cur = byKey.get(key);
    if (cur){
      for (const k of Object.keys(v0)) if (k !== "seen" && k !== "checked" && (cur[k] == null || cur[k] === "")) cur[k] = v0[k];
      // A stored copy without `seen` predates first-observed tracking: "" means "unknown, earlier".
      cur.seen = !v0.seen || !cur.seen ? "" : (v0.seen < cur.seen ? v0.seen : cur.seen);
      if (v0.checked && (!cur.checked || v0.checked > cur.checked)) cur.checked = v0.checked;
      continue;
    }
    const v = Object.assign({}, v0);
    // Older stored claims carry an apj flag from the India-first schema; region now comes from cc.
    if ("apj" in v){ delete v.apj; if (COUNTRY_NAME[v.cc]) v.country = COUNTRY_NAME[v.cc]; }
    byKey.set(key, v);
  }
  const out = [...byKey.values()];
  out.sort((a, b) => String(b.date || "").localeCompare(String(a.date || "")));
  return out;
}
function dedupeKev(list){
  const seen = new Set(), out = [];
  for (const k of list){
    const key = (k.cveId || "").toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(k);
  }
  out.sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || "")));
  return out;
}
// Unlike RSS items, a repost on Telegram is a genuinely new post (distinct tgLink/post ID) but
// with identical text — dedupeItems()'s link-based key wouldn't catch that, so this keys on the
// normalized (channel, title) pair instead.
function dedupeTelegram(list){
  const seen = new Set(), out = [];
  for (const i of list){
    const key = (i.channel + "|" + i.title).toLowerCase().trim();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(withGeo(i));
  }
  out.sort((a, b) => (b.date || "").localeCompare(a.date || ""));
  return out;
}

// Keyed on (source, type, value) rather than value alone — the same string can legitimately appear
// as a different IOC type across feeds (e.g. a domain in ThreatFox and a URL substring in URLhaus).
function dedupeIocs(list){
  const seen = new Set(), out = [];
  for (const i of list){
    const key = (i.source + "|" + i.type + "|" + i.value).toLowerCase();
    if (!i.value || seen.has(key)) continue;
    seen.add(key);
    out.push(i);
  }
  out.sort((a, b) => String(b.firstSeen || "").localeCompare(String(a.firstSeen || "")));
  return out;
}

// Builds the unified vulnerabilities list from three already-collected structured sources (NVD
// CVSS≥7, GitHub Advisories, CISA KEV) rather than a new fetch — all three carry a real cveId, so this
// merges same-CVE records across sources (e.g. a CVE both scored by NVD and listed in KEV), keeping
// the highest CVSS and unioning `vx` enrichment (earlier inputs win on conflicts). Records without a
// cveId are ignored.
//
// Ordering decides what survives mergeVulnData()'s cap: every KEV entry first (they arrive without a
// CVSS score, and a CVSS-first sort used to push all but the few NVD also scored past the cap), then
// likely-exploited (EPSS ≥ 10%, exploit reference, PoC maturity), then CVSS ≥ 9, then the rest —
// newest first within each.
function vulnKeepRank(v){
  if (v.kev) return 0;
  const vx = v.vx || {};
  if ((v.epss != null && v.epss >= 0.1) || (vx.refs && vx.refs.exploit) || /ATTACKED|PROOF_OF_CONCEPT/.test(vx.maturity || "") || /active|poc/.test(vx.ssvc || "")) return 1;
  if (v.cvssScore != null && v.cvssScore >= 9) return 2;
  return 3;
}
function dedupeVulnerabilities(list){
  const byId = new Map();
  for (const v of list){
    if (!v.cveId) continue;
    const key = String(v.cveId).toUpperCase();
    const prev = byId.get(key);
    if (!prev){
      byId.set(key, {
        cveId: key, title: v.title || key, desc: v.desc || "",
        link: v.link || ("https://nvd.nist.gov/vuln/detail/" + key),
        date: v.date || null, cvssScore: (typeof v.cvssScore === "number") ? v.cvssScore : null,
        waf: !!v.waf, kev: !!v.kev, vendor: v.vendor || "", product: v.product || "", dueDate: v.dueDate || null,
        lens: !!v.lens, vx: v.vx ? Object.assign({}, v.vx) : undefined,
        seen: v.seen, epss: v.epss, epssPercentile: v.epssPercentile, epssDate: v.epssDate
      });
      continue;
    }
    if (typeof v.cvssScore === "number" && (prev.cvssScore === null || v.cvssScore > prev.cvssScore)){
      prev.cvssScore = v.cvssScore;
      if (v.vx && v.vx.vec) prev.vx = Object.assign({}, prev.vx, { cvssVer: v.vx.cvssVer, vec: v.vx.vec, cvssSrc: v.vx.cvssSrc });
    }
    prev.vx = mergeVx(prev.vx, v.vx);
    prev.waf = prev.waf || !!v.waf;
    prev.kev = prev.kev || !!v.kev;
    prev.lens = prev.lens || !!v.lens;
    if (!prev.desc && v.desc) prev.desc = v.desc;
    // NVD's title is just "CVE-… (CVSS n)"; KEV and GitHub carry a real name.
    if (/^CVE-\d+-\d+( \(CVSS [\d.]+\))?$/.test(prev.title) && v.title && !/^CVE-\d+-\d+( \(CVSS [\d.]+\))?$/.test(v.title)) prev.title = v.title;
    if (!prev.vendor && v.vendor) prev.vendor = v.vendor;
    if (!prev.product && v.product) prev.product = v.product;
    if (!prev.dueDate && v.dueDate) prev.dueDate = v.dueDate;
    if (v.seen && (!prev.seen || v.seen < prev.seen)) prev.seen = v.seen;
    if (prev.epss == null && v.epss != null){ prev.epss = v.epss; prev.epssPercentile = v.epssPercentile; prev.epssDate = v.epssDate; }
    if (v.date && (!prev.date || v.date > prev.date)) prev.date = v.date;
  }
  const out = [...byId.values()].map(finalizeVuln);
  out.sort((a, b) => (vulnKeepRank(a) - vulnKeepRank(b)) || String(b.date || "").localeCompare(String(a.date || "")));
  return out;
}

// Shared by collect() (part of the full 30-min cycle) and collectVulnerabilitiesOnly() (the
// faster CVE-only cron below) — the three structured CVE sources fetch independently of
// everything else, so pulling them into one helper avoids running this fetch/parse logic twice.
async function fetchVulnSources(){
  const sourceStatus = {};
  let nvdItems = [], ghsaItems = [], kev = [];
  const tasks = [];

  tasks.push((async () => {
    try {
      const parsed = parseGithubAdvisories(await fetchJson(GITHUB_ADVISORIES_URL));
      ghsaItems = parsed;
      sourceStatus["GitHub Advisories"] = { ok: true, count: parsed.length };
    } catch (e){
      sourceStatus["GitHub Advisories"] = { ok: false, error: String(e.message || e) };
    }
  })());

  tasks.push((async () => {
    try {
      const start = new Date(Date.now() - 2 * 86400000).toISOString().replace(/\.\d+Z$/, ".000");
      const end = new Date().toISOString().replace(/\.\d+Z$/, ".000");
      const parsed = parseNvdCves(await fetchJson(NVD_CVE_URL + "?resultsPerPage=200&pubStartDate=" + start + "&pubEndDate=" + end));
      nvdItems = parsed;
      sourceStatus["NVD (High/Critical)"] = { ok: true, count: parsed.length };
    } catch (e){
      sourceStatus["NVD (High/Critical)"] = { ok: false, error: String(e.message || e) };
    }
  })());

  tasks.push((async () => {
    try {
      kev = parseKev(await fetchJson(KEV_URL));
      sourceStatus["CISA KEV"] = { ok: true, count: kev.length };
    } catch (e){
      sourceStatus["CISA KEV"] = { ok: false, error: String(e.message || e) };
    }
  })());

  await Promise.all(tasks);
  return { nvdItems, ghsaItems, kev, sourceStatus };
}

// `vx` only matters on the vulnerabilities list (which carries it forward itself); the NVD/GitHub
// copies in the main `items` feed would just double its size in KV.
function withoutVx(i){ if (!i.vx) return i; const o = Object.assign({}, i); delete o.vx; return o; }
// The unified vulnerabilities list for one cycle: CVE-bearing feed items (NVD, GitHub Advisories) plus
// the KEV entries, merged by dedupeVulnerabilities(). Shared by collect() and the 10-min job so the
// merge, carry-forward and cap rules can't drift between them.
function buildVulnList(mergedItems, mergedKev, prev, nowIso){
  const kevAsVulns = mergedKev.map(k => ({
    cveId: k.cveId, title: k.name || k.cveId, desc: k.desc,
    link: "https://nvd.nist.gov/vuln/detail/" + k.cveId, date: k.dateAdded,
    cvssScore: null, waf: k.waf, kev: true, vendor: k.vendor, product: k.product, dueDate: k.dueDate,
    cc: [], rg: [], lens: false,
    vx: { products: k.product ? [{ vendor: k.vendor || "", product: k.product, versions: "", fixed: "", src: "CISA KEV" }] : [], cwes: k.cwes || [],
      kevAdded: k.dateAdded, kevDue: k.dueDate || "", kevAction: k.action || "", kevNotes: k.notes || "", kevRansomware: !!k.ransomware }
  }));
  // The previous list is the lowest-priority input: it carries what only it has (the NVD backfill's
  // fields for KEV/GitHub CVEs, `seen`, the last EPSS score for the keep-ranking) for CVEs that are
  // still in today's sources, and never resurrects a CVE that has dropped out of them.
  const current = [...mergedItems.filter(i => (i.src === "NVD" || i.src === "GitHub Advisories") && i.cveId), ...kevAsVulns];
  const ids = new Set(current.map(v => String(v.cveId).toUpperCase()));
  const carried = (prev.vulnerabilities || []).filter(v => v.cveId && ids.has(String(v.cveId).toUpperCase()));
  return dedupeVulnerabilities([...current, ...carried]).slice(0, VULN_CAP)
    .map(v => v.seen ? v : Object.assign(v, { seen: nowIso }));
}

// Builds the merged/deduped { items, kev, vulnerabilities } trio from freshly fetched NVD/GHSA/KEV
// records plus whatever was already in KV — used by both collect() and collectVulnerabilitiesOnly()
// so the merge/window/cap rules can't drift between the two jobs.
function mergeVulnData(nvdItems, ghsaItems, kev, prev, extraItems = [], nowIso = new Date().toISOString()){
  const cutoff = Date.now() - 365 * 86400000;
  const mergedItems = dedupeItems([...extraItems, ...ghsaItems, ...nvdItems, ...prev.items]).filter(i => !i.date || new Date(i.date).getTime() >= cutoff).slice(0, ITEMS_CAP);
  const mergedKev = dedupeKev([...kev, ...(prev.kev || [])]).filter(k => !k.dateAdded || new Date(k.dateAdded).getTime() >= cutoff).slice(0, 100);
  const mergedVulnerabilities = buildVulnList(mergedItems, mergedKev, prev, nowIso);
  return { mergedItems, mergedKev, mergedVulnerabilities };
}

// Fetches EPSS scores for a batch of CVE IDs, chunked to stay under the ~135-ID URL-length cliff
// noted above. A batch that errors (network/HTTP) just leaves those CVE IDs unscored rather than
// failing the whole enrichment — same never-block-the-cycle philosophy as the other sources.
async function fetchEpssScores(cveIds){
  const ids = [...new Set(cveIds)];
  const scores = new Map();
  const batches = [];
  for (let i = 0; i < ids.length; i += EPSS_BATCH_SIZE) batches.push(ids.slice(i, i + EPSS_BATCH_SIZE));
  await Promise.all(batches.map(async batch => {
    try {
      const j = await fetchJson(EPSS_URL + "?cve=" + batch.join(",") + "&limit=" + batch.length);
      for (const row of (j.data || [])){
        const epss = parseFloat(row.epss);
        const percentile = parseFloat(row.percentile);
        if (!isNaN(epss)) scores.set(String(row.cve).toUpperCase(), { epss, percentile: isNaN(percentile) ? null : percentile, date: row.date || null });
      }
    } catch (e){ /* leave this batch's CVEs unscored; self-heals next cycle */ }
  }));
  return scores;
}

// Enriches a finished vulnerabilities list with `epss`/`epssPercentile` fields, and records an
// "EPSS" sourceStatus entry alongside the other sources. Always overwrites rather than falling back
// to a stale prior score — this runs on the full current CVE list every cycle (both crons), so a
// transient miss for one CVE just resolves itself on the next cycle 10-30 min later.
async function enrichEpss(vulnerabilities, sourceStatus){
  const ids = vulnerabilities.map(v => v.cveId).filter(Boolean);
  if (!ids.length){ sourceStatus["EPSS"] = { ok: true, count: 0 }; return vulnerabilities; }
  const scores = await fetchEpssScores(ids);
  sourceStatus["EPSS"] = { ok: true, count: scores.size };
  return vulnerabilities.map(v => {
    const s = v.cveId && scores.get(String(v.cveId).toUpperCase());
    return Object.assign({}, v, { epss: s ? s.epss : null, epssPercentile: s ? s.percentile : null, epssDate: s ? s.date : null });
  });
}

// Fetches one Radar summary-by-dimension breakdown (e.g. L3 attack vectors targeting a country this
// week, or worldwide when location is null) and returns it as a plain { label: percentage } object, sorted descending, top 8 — the
// dimension cardinality here is small (a handful of vector/HTTP-method values) so no pagination is
// needed. `result.summary_0` is Radar's map of dimension-value -> percentage string; parsed to numbers
// here so the frontend doesn't need to. Returns null (not throw) on any failure so one bad call
// doesn't take down its sibling in collectDdosTelemetry()'s / radarForCountry()'s Promise.all.
// One Radar API call → its `result` object, or null on any failure (never throws), so one bad call
// doesn't take down its siblings in a Promise.all.
async function radarGet(token, path, params){
  const url = RADAR_API_BASE + "/" + path + "?" + new URLSearchParams(Object.assign({ format: "json" }, params)).toString();
  try {
    const r = await fetchWithTimeout(url, { headers: { "Authorization": "Bearer " + token, "User-Agent": UA } });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const j = await r.json();
    if (!j.success) throw new Error((j.errors && j.errors[0] && j.errors[0].message) || "Radar API error");
    return j.result || null;
  } catch (e){ return null; }
}
// `summary_0` → [{ label, pct }]. With `order` (bucketed dimensions like bitrate/duration) rows keep
// that order and get readable labels; otherwise they're sorted by share, top 8.
function parseRadarSummary(result, order){
  if (!result) return null;
  const rows = Object.entries(result.summary_0 || {}).map(([label, pct]) => ({ label, pct: parseFloat(pct) })).filter(r => !isNaN(r.pct));
  if (order) return Object.keys(order).map(k => ({ label: order[k], pct: (rows.find(r => r.label === k) || { pct: 0 }).pct }));
  return rows.sort((a, b) => b.pct - a.pct).slice(0, 8);
}
// top/locations/{origin,target} and top/attacks rows → { cc, pct } or { from, to, pct }.
function parseRadarTop(result){
  if (!result) return null;
  return (result.top_0 || []).map(r => {
    const pct = parseFloat(r.value);
    if (r.originCountryAlpha2 && r.targetCountryAlpha2) return { from: r.originCountryAlpha2, to: r.targetCountryAlpha2, pct };
    return { cc: r.targetCountryAlpha2 || r.originCountryAlpha2, pct };
  }).filter(r => !isNaN(r.pct) && (r.cc || r.from));
}
function parseRadarIndustries(result){
  if (!result) return null;
  return (result.top_0 || []).map(r => ({ label: r.name, pct: parseFloat(r.value) })).filter(r => r.label && !isNaN(r.pct));
}
// Daily timeseries → [{ d: "YYYY-MM-DD", v }]. Radar min-max normalises it (0..1), so it shows shape
// over time — which days were worst — not volume.
function parseRadarSeries(result){
  if (!result || !result.serie_0) return null;
  const s = result.serie_0;
  return (s.timestamps || []).map((t, i) => ({ d: String(t).slice(0, 10), v: parseFloat(s.values[i]) })).filter(p => !isNaN(p.v));
}
// Radar's hand-verified outage annotations (cause, scope, affected countries).
function parseRadarOutages(result){
  if (!result) return null;
  return (result.annotations || []).map(a => ({
    start: a.startDate || null, end: a.endDate || null,
    desc: String(a.description || "").slice(0, 300),
    cause: (a.outage && a.outage.outageCause) || "UNKNOWN",
    scope: (a.outage && a.outage.outageType) || null,
    cc: (a.locations || []).filter(c => /^[A-Z]{2}$/.test(c)),
    asns: (a.asns || []).length,
    link: a.linkedUrl || null
  }));
}
const RADAR_BITRATE = { UNDER_500_MBPS: "< 500 Mbps", _500_MBPS_TO_1_GBPS: "0.5–1 Gbps", _1_GBPS_TO_10_GBPS: "1–10 Gbps", _10_GBPS_TO_100_GBPS: "10–100 Gbps", OVER_100_GBPS: "> 100 Gbps" };
const RADAR_DURATION = { UNDER_10_MINS: "< 10 min", _10_MINS_TO_20_MINS: "10–20 min", _20_MINS_TO_40_MINS: "20–40 min", _40_MINS_TO_1_HOUR: "40–60 min", _1_HOUR_TO_3_HOURS: "1–3 h", OVER_3_HOURS: "> 3 h" };

// Kept for the named exports; the same call collectDdosTelemetry() makes for the vector/method breakdowns.
async function fetchRadarSummary(token, layer, dimension, location){
  const params = { dateRange: "7d", direction: "TARGET" };
  if (location) params.location = location;
  return parseRadarSummary(await radarGet(token, "attacks/" + layer + "/summary/" + dimension, params));
}

// Real (measured, not claimed) DDoS attack traffic from Cloudflare Radar — see the constants above
// for the claimed-vs-confirmed caveat. Gated behind env.CF_RADAR_TOKEN; returns null (not an empty
// object) when unset or when every call fails, so collect() can fall back to the previous cycle's KV.
// Worldwide only (8 subrequests); per-country views come from GET /api/radar?cc= (radarForCountry()).
// Location lists are fetched deep (limit 50) so the frontend can narrow them to one region.
//
// Direction semantics differ by layer, checked against the API: for L3, `location` is the TARGET
// country. For L7 it's the SOURCE of the mitigated requests and `direction` is ignored, so L7 per-
// country questions ("who attacks X") have to go through top/attacks with limitDirection=TARGET.
async function collectDdosTelemetry(env, sourceStatus){
  if (!env.CF_RADAR_TOKEN) return null;
  const t = env.CF_RADAR_TOKEN, wk = { dateRange: "7d" };
  const [l3, l7, targets, origins, pairs, industries, bitrate, duration] = await Promise.all([
    radarGet(t, "attacks/layer3/summary/" + RADAR_L3_DIMENSION, wk).then(r => parseRadarSummary(r)),
    radarGet(t, "attacks/layer7/summary/" + RADAR_L7_DIMENSION, wk).then(r => parseRadarSummary(r)),
    radarGet(t, "attacks/layer3/top/locations/target", Object.assign({ limit: 50 }, wk)).then(parseRadarTop),
    radarGet(t, "attacks/layer3/top/locations/origin", Object.assign({ limit: 50 }, wk)).then(parseRadarTop),
    radarGet(t, "attacks/layer7/top/attacks", Object.assign({ limit: 50 }, wk)).then(parseRadarTop),
    radarGet(t, "attacks/layer7/top/industry", Object.assign({ limit: 8 }, wk)).then(parseRadarIndustries),
    radarGet(t, "attacks/layer3/summary/bitrate", wk).then(r => parseRadarSummary(r, RADAR_BITRATE)),
    radarGet(t, "attacks/layer3/summary/duration", wk).then(r => parseRadarSummary(r, RADAR_DURATION))
  ]);
  const parts = [l3, l7, targets, origins, pairs, industries, bitrate, duration];
  const ok = parts.filter(Boolean).length;
  sourceStatus["Cloudflare Radar"] = { ok: ok > 0, count: ok + "/" + parts.length + " breakdowns" };
  if (!ok) return null;
  return {
    generated: new Date().toISOString(),
    l3: { global: l3 || [] },
    l7: { global: l7 || [] },
    l3Targets: targets || [], l3Origins: origins || [], l7Pairs: pairs || [],
    l7Industries: industries || [], bitrate: bitrate || [], duration: duration || []
  };
}

// IODA (Internet Outage Detection and Analysis, Georgia Tech) — free, no key. Detects connectivity
// drops per country / region / network from BGP, active probing and darknet traffic. It says a network
// went dark, not why — power cuts, shutdowns and cable faults look the same as a successful DDoS — so
// it's shown next to claims as "was anything actually disrupted", never as confirmation of an attack.
// Data © Georgia Tech Research Corporation; the UI attributes and links it.
const IODA_API_BASE = "https://api.ioda.inetintel.cc.gatech.edu/v2";
async function iodaGet(path, params){
  try {
    const j = await fetchJson(IODA_API_BASE + "/" + path + "?" + new URLSearchParams(params).toString());
    return j && !j.error ? j.data : null;
  } catch (e){ return null; }
}
// outages/summary rows → [{ code, name, events, score }], worst first. `score` is IODA's unitless
// severity; the UI only uses it to rank and scale bars.
function parseIodaSummary(data){
  if (!Array.isArray(data)) return null;
  return data.map(e => ({
    code: String((e.entity && e.entity.code) || ""), name: String((e.entity && e.entity.name) || ""),
    events: e.event_cnt || 0, score: Math.round((e.scores && e.scores.overall) || 0)
  })).filter(e => e.code).sort((a, b) => b.score - a.score);
}
// outages/events rows → one entry per incident. IODA reports the same drop once per datasource (BGP,
// active probing, darknet), so events that start within 30 min of each other are merged.
const IODA_SOURCE = { "bgp": "BGP", "ping-slash24": "active probing", "merit-nt": "darknet", "gtr": "Google traffic", "gtr-norm": "Google traffic" };
function parseIodaEvents(data){
  if (!Array.isArray(data)) return null;
  const rows = data.map(e => ({ start: e.start * 1000, end: (e.start + (e.duration || 0)) * 1000, src: IODA_SOURCE[e.datasource] || e.datasource }))
    .filter(e => e.start).sort((a, b) => a.start - b.start);
  const merged = [];
  for (const e of rows){
    const last = merged[merged.length - 1];
    if (last && e.start - last.start <= 1800000){ last.end = Math.max(last.end, e.end); if (!last.sources.includes(e.src)) last.sources.push(e.src); }
    else merged.push({ start: e.start, end: e.end, sources: [e.src] });
  }
  return merged.reverse().map(e => ({ start: new Date(e.start).toISOString(), end: new Date(e.end).toISOString(), sources: e.sources }));
}
const unixNow = () => Math.floor(Date.now() / 1000);

// Worldwide internet-disruption picture for the Geo Intel overview: IODA's worst-hit countries this
// week (no key, 1 subrequest) plus Radar's verified outage annotations with their cause (token-gated,
// 1 subrequest). A failed half comes back null; collect() falls back to the previous cycle's copy.
async function collectOutages(env, sourceStatus){
  const now = unixNow();
  const [iodaData, radarRes] = await Promise.all([
    iodaGet("outages/summary", { from: now - 7 * 86400, until: now, entityType: "country", limit: 60 }),
    env.CF_RADAR_TOKEN ? radarGet(env.CF_RADAR_TOKEN, "annotations/outages", { dateRange: "28d", limit: 40 }) : Promise.resolve(null)
  ]);
  const ioda = parseIodaSummary(iodaData);
  const radar = parseRadarOutages(radarRes);
  sourceStatus["IODA"] = ioda ? { ok: true, count: ioda.length } : { ok: false, error: "no data" };
  if (env.CF_RADAR_TOKEN) sourceStatus["Cloudflare Radar · outages"] = radar ? { ok: true, count: radar.length } : { ok: false, error: "no data" };
  return { generated: new Date().toISOString(), ioda, radar };
}
function mergeOutages(fresh, prev){
  const f = fresh || {}, p = prev || {};
  const ioda = f.ioda || p.ioda || null, radar = f.radar || p.radar || null;
  if (!ioda && !radar) return null;
  return { generated: (f.ioda || f.radar) ? f.generated : (p.generated || null), ioda: ioda || [], radar: radar || [] };
}

// GET /api/radar?cc=XX — the DDoS view for one country: Radar's attack breakdowns targeting it (when
// the token is set) plus IODA disruptions (always). Public endpoint, so the country code is validated
// and each answer is cached at the edge (Cache API, no KV writes) for RADAR_CC_CACHE_S, like
// /api/ip-check. Up to 11 subrequests, only on a cache miss.
const RADAR_CC_CACHE_S = 6 * 3600;
async function radarForCountry(env, cc, ctx){
  const out = (obj, status, cacheS) => new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": cacheS ? "public, max-age=" + cacheS : "no-store" }
  });
  if (!/^[A-Z]{2}$/.test(cc)) return out({ error: "Pass a two-letter country code, e.g. ?cc=IN." }, 400);
  const cacheKey = new Request("https://radar.internal/v2/" + cc);
  const cached = await caches.default.match(cacheKey);
  if (cached) return cached;
  const t = env.CF_RADAR_TOKEN, now = unixNow();
  const wk = { dateRange: "7d", location: cc };
  const radar = (path, params, parse) => t ? radarGet(t, path, params).then(parse) : Promise.resolve(null);
  const [l3, l7, l3Origins, l7Pairs, bitrate, duration, series, outages, iodaCountry, iodaEvents, iodaNets] = await Promise.all([
    radar("attacks/layer3/summary/" + RADAR_L3_DIMENSION, Object.assign({ direction: "TARGET" }, wk), r => parseRadarSummary(r)),
    // L7 `location` = source of the attack traffic (see collectDdosTelemetry()), so this is "from cc".
    radar("attacks/layer7/summary/" + RADAR_L7_DIMENSION, wk, r => parseRadarSummary(r)),
    radar("attacks/layer3/top/locations/origin", Object.assign({ limit: 8 }, wk), parseRadarTop),
    radar("attacks/layer7/top/attacks", Object.assign({ limit: 8, limitDirection: "TARGET" }, wk), parseRadarTop),
    radar("attacks/layer3/summary/bitrate", Object.assign({ direction: "TARGET" }, wk), r => parseRadarSummary(r, RADAR_BITRATE)),
    radar("attacks/layer3/summary/duration", Object.assign({ direction: "TARGET" }, wk), r => parseRadarSummary(r, RADAR_DURATION)),
    radar("attacks/layer3/timeseries", { dateRange: "28d", aggInterval: "1d", location: cc, direction: "TARGET" }, parseRadarSeries),
    radar("annotations/outages", { dateRange: "28d", location: cc, limit: 20 }, parseRadarOutages),
    iodaGet("outages/summary", { from: now - 7 * 86400, until: now, entityType: "country", entityCode: cc }).then(parseIodaSummary),
    iodaGet("outages/events", { from: now - 28 * 86400, until: now, entityType: "country", entityCode: cc, limit: 60, format: "codf" }).then(parseIodaEvents),
    iodaGet("outages/summary", { from: now - 7 * 86400, until: now, entityType: "asn", relatedTo: "country/" + cc, limit: 8 }).then(parseIodaSummary)
  ]);
  const radarOk = [l3, l7, l3Origins, l7Pairs, bitrate, duration, series, outages].some(Boolean);
  const iodaOk = [iodaCountry, iodaEvents, iodaNets].some(Boolean);
  if (!radarOk && !iodaOk) return out({ error: "Neither Cloudflare Radar nor IODA returned data for " + cc + "." }, 502);
  const res = out({
    cc, generated: new Date().toISOString(),
    radar: t ? { configured: true, ok: radarOk } : { configured: false },
    l3: l3 || [], l7From: l7 || [], l3Origins: l3Origins || [],
    l7Origins: (l7Pairs || []).filter(p => p.to === cc).map(p => ({ cc: p.from, pct: p.pct })),
    bitrate: bitrate || [], duration: duration || [], series: series || [], outages: outages || [],
    ioda: { ok: iodaOk, country: (iodaCountry || [])[0] || null, events: iodaEvents || [], networks: iodaNets || [] }
  }, 200, RADAR_CC_CACHE_S);
  ctx.waitUntil(caches.default.put(cacheKey, res.clone()));
  return res;
}

// Fetches one slice of the RSS `SOURCES`. Cloudflare's free plan caps a single Worker invocation at
// 50 subrequests (redirect hops count too), and collect()'s other ~30 sources plus 38 RSS feeds
// blew past it — the overflow failed with "Too many subrequests", silently knocking out whichever
// sources happened to start last (Telegram, Mastodon, abuse.ch). So RSS rotates through the 10-min
// job instead: RSS_BATCH_SIZE feeds per run, slot chosen from the wall clock (no state to keep), so
// every feed is refreshed about every ceil(38/13)=3 runs = 30 min — the same freshness as before.
// If SOURCES grows, raise the batch size only as far as (50 - that job's other subrequests) allows.
const RSS_BATCH_SIZE = 13;
function rssBatchForNow(now = Date.now()){
  const batches = Math.ceil(SOURCES.length / RSS_BATCH_SIZE);
  const slot = Math.floor(now / 600000) % batches;
  return SOURCES.slice(slot * RSS_BATCH_SIZE, (slot + 1) * RSS_BATCH_SIZE);
}
async function fetchRssBatch(sources){
  const items = [];
  const sourceStatus = {};
  let infocon = null;
  await Promise.all(sources.map(async src => {
    try {
      const xml = await fetchText(src.url);
      const parsed = parseItems(xml, src.name);
      items.push(...parsed);
      sourceStatus[src.name] = { ok: true, count: parsed.length };
      if (src.name === "SANS ISC"){
        const m = xml.match(/InfoCON:\s*(\w+)/i);
        if (m) infocon = m[1].toLowerCase();
      }
    } catch (e){
      sourceStatus[src.name] = { ok: false, error: String(e.message || e) };
    }
  }));
  return { items, sourceStatus, infocon };
}

// The 2-day NVD window only covers newly published CVEs, so KEV entries (usually older CVEs) and
// GitHub-only ones would never get NVD's CVSS, products or tagged references. Each 10-min run reads
// NVD_BACKFILL_PER_RUN of them one at a time from NVD's per-CVE API — KEV first, newest first — and
// re-reads records NVD hadn't analysed yet once they're NVD_RECHECK_MS old. ~18/hour clears the
// 400-record list in about a day, then stays near zero. Unauthenticated NVD allows 5 requests per
// 30 s; this job makes 1 window query + 3 here.
const NVD_BACKFILL_PER_RUN = 3;
const NVD_RECHECK_MS = 3 * 86400000;
async function nvdBackfill(vulns, sourceStatus, nowIso = new Date().toISOString()){
  const now = Date.parse(nowIso);
  const due = v => { const vx = v.vx || {}; return !vx.nvdAt || (/Received|Awaiting|Undergoing|Deferred/i.test(vx.status || "") && now - Date.parse(vx.nvdAt) > NVD_RECHECK_MS); };
  const pick = vulns.filter(due).sort((a, b) => (Number(b.kev) - Number(a.kev)) || String(b.date || "").localeCompare(String(a.date || ""))).slice(0, NVD_BACKFILL_PER_RUN);
  if (!pick.length) return vulns;
  const got = new Map();
  let failed = 0, lastErr = "";
  await Promise.all(pick.map(async v => {
    try {
      const rec = parseNvdCves(await fetchJson(NVD_CVE_URL + "?cveId=" + encodeURIComponent(v.cveId)), 0, nowIso)[0];
      got.set(v.cveId, rec || { vx: { nvdAt: nowIso, status: "Not in NVD" } });
    } catch (e){ failed++; lastErr = String(e.message || e); }
  }));
  sourceStatus["NVD backfill"] = failed === pick.length ? { ok: false, error: lastErr } : { ok: true, count: got.size };
  return vulns.map(v => {
    const r = got.get(v.cveId);
    if (!r) return v;
    const out = Object.assign({}, v, { vx: mergeVx(r.vx, v.vx) });
    if (r.vx && r.vx.vec && (out.cvssScore == null || r.cvssScore >= out.cvssScore)){ out.cvssScore = r.cvssScore; Object.assign(out.vx, { cvssVer: r.vx.cvssVer, vec: r.vx.vec, cvssSrc: r.vx.cvssSrc }); }
    if (r.vx && r.vx.status) out.vx.status = r.vx.status;
    out.vx.nvdAt = nowIso;
    return finalizeVuln(out);
  });
}

// Dedicated fast cron (see CVE_ONLY_CRON / wrangler.toml) that refreshes the CVE-bearing sources —
// NVD, GitHub Advisories, CISA KEV — plus one rotating slice of the RSS feeds (see rssBatchForNow()).
// Everything else in the cached blob (victims, telegram, ransomwareNews, iocs) is passed
// through untouched from the previous cycle.
async function collectVulnerabilitiesOnly(env){
  const nowIso = new Date().toISOString();
  const [{ nvdItems, ghsaItems, kev, sourceStatus }, rss] = await Promise.all([fetchVulnSources(), fetchRssBatch(rssBatchForNow())]);
  Object.assign(sourceStatus, rss.sourceStatus);

  const prevRaw = await env.THREAT_DATA.get("latest");
  const prev = prevRaw ? JSON.parse(prevRaw) : { items: [], victims: [], kev: [], telegram: [], ransomwareNews: [], iocs: [], vulnerabilities: [], infocon: "green", sourceStatus: {} };

  const { mergedItems, mergedKev, mergedVulnerabilities } = mergeVulnData(nvdItems, ghsaItems, kev, prev, rss.items, nowIso);
  const enrichedVulnerabilities = await enrichEpss(mergedVulnerabilities, sourceStatus);
  const backfilled = await nvdBackfill(enrichedVulnerabilities, sourceStatus, nowIso);

  const data = Object.assign({}, prev, {
    items: mergedItems.map(withoutVx),
    kev: mergedKev,
    vulnerabilities: backfilled,
    vulnGenerated: nowIso,
    infocon: rss.infocon || prev.infocon || "green",
    sourceStatus: Object.assign({}, prev.sourceStatus, sourceStatus)
  });
  await env.THREAT_DATA.put("latest", JSON.stringify(data));
  return data;
}

async function collect(env){
  const items = [];
  let infocon = null;
  const sourceStatus = {};
  const nowIso = new Date().toISOString();
  const telegram = [];
  const ransomwareNews = [];
  const victims = [];
  const iocs = [];
  let kev = [];
  let ddosTelemetry = null;

  // Every source below is independent, so fetch them all concurrently rather than one at a time —
  // ~25 sequential awaits meant a single slow/rate-limited host delayed every source after it in
  // the list (observed: a few Telegram fetches running long pushed the whole cycle well past two
  // minutes). Firing them together bounds total wall time to roughly the single slowest source's
  // FETCH_TIMEOUT_MS instead of the sum of all of them. Plain array pushes / sourceStatus[key] =
  // assignments below are safe across these concurrent tasks — JS has no real threads, so there's
  // no torn-write risk, just interleaved I/O waits.
  const tasks = [];

  // RSS `SOURCES` are deliberately NOT fetched here — they rotate through the 10-min job instead
  // (see rssBatchForNow()), to keep this invocation under the free plan's 50-subrequest cap.

  let nvdItems = [], ghsaItems = [];
  tasks.push((async () => {
    const fetched = await fetchVulnSources();
    nvdItems = fetched.nvdItems; ghsaItems = fetched.ghsaItems; kev = fetched.kev;
    items.push(...ghsaItems, ...nvdItems);
    Object.assign(sourceStatus, fetched.sourceStatus);
  })());

  tasks.push((async () => {
    try {
      const openPhishText = await fetchText(OPENPHISH_URL);
      const parsed = parseOpenPhish(openPhishText, nowIso);
      items.push(...parsed);
      sourceStatus["OpenPhish"] = { ok: true, count: openPhishText.split(/\r?\n/).filter(Boolean).length };
    } catch (e){
      sourceStatus["OpenPhish"] = { ok: false, error: String(e.message || e) };
    }
  })());

  tasks.push((async () => {
    try {
      items.push(...await collectAbuseCh(env, nowIso, sourceStatus, iocs));
    } catch (e){ /* collectAbuseCh tracks its own per-feed sourceStatus; keep going */ }
  })());

  tasks.push((async () => {
    try {
      ddosTelemetry = await collectDdosTelemetry(env, sourceStatus);
    } catch (e){ /* collectDdosTelemetry tracks its own sourceStatus; keep going */ }
  })());

  let outages = null;
  tasks.push((async () => {
    try {
      outages = await collectOutages(env, sourceStatus);
    } catch (e){ /* collectOutages tracks its own sourceStatus; keep going */ }
  })());

  tasks.push((async () => {
    try {
      await collectMisp(sourceStatus, iocs);
    } catch (e){ /* collectMisp tracks its own sourceStatus; keep going */ }
  })());

  for (const ch of TELEGRAM_CHANNELS){
    tasks.push((async () => {
      const key = "Telegram · " + ch.name;
      try {
        const html = await fetchText("https://t.me/s/" + ch.handle);
        const parsed = parseTelegramChannel(html, ch.name, { actorChannel: ch.actorChannel });
        telegram.push(...parsed);
        sourceStatus[key] = { ok: true, count: parsed.length };
      } catch (e){
        sourceStatus[key] = { ok: false, error: String(e.message || e) };
      }
    })());
  }

  for (const src of RANSOMWARE_NEWS_SOURCES){
    tasks.push((async () => {
      try {
        const xml = await fetchText(src.url);
        const parsed = parseItems(xml, src.name);
        ransomwareNews.push(...parsed);
        sourceStatus[src.name] = { ok: true, count: parsed.length };
      } catch (e){
        sourceStatus[src.name] = { ok: false, error: String(e.message || e) };
      }
    })());
  }

  // Recorded in sourceStatus like every other source — these used to fail silently, and the frontend's
  // stored-claim count kept reporting ransomware.live as healthy regardless.
  const rwFetches = [["ransomware.live · recent", RW_RECENT, undefined],
    ...rwCountriesForNow().map(cc => ["ransomware.live · " + cc, RW_COUNTRY_URL + cc, cc])];
  for (const [name, url, cc] of rwFetches){
    tasks.push((async () => {
      try {
        const parsed = parseRwJson(await fetchJson(url), cc);
        victims.push(...parsed);
        sourceStatus[name] = { ok: true, count: parsed.length };
      } catch (e){
        sourceStatus[name] = { ok: false, error: String(e.message || e) };
      }
    })());
  }

  await Promise.all(tasks);

  const prevRaw = await env.THREAT_DATA.get("latest");
  const prev = prevRaw ? JSON.parse(prevRaw) : { items: [], victims: [], kev: [], telegram: [], ransomwareNews: [], iocs: [], ddosTelemetry: null, infocon: "green" };

  const cutoff = Date.now() - 365 * 86400000;
  const mergedItems = dedupeItems([...items, ...prev.items]).filter(i => !i.date || new Date(i.date).getTime() >= cutoff).slice(0, ITEMS_CAP);
  const mergedVictims = capVictims(dedupeVictims([...victims, ...prev.victims]).filter(v => !v.date || new Date(v.date).getTime() >= cutoff));
  const mergedKev = dedupeKev([...kev, ...(prev.kev || [])]).filter(k => !k.dateAdded || new Date(k.dateAdded).getTime() >= cutoff).slice(0, 100);
  const mergedIocs = dedupeIocs([...iocs, ...(prev.iocs || [])]).filter(i => !i.firstSeen || new Date(i.firstSeen).getTime() >= cutoff).slice(0, 500);
  // Drop archived posts from channels that have since been removed from TELEGRAM_CHANNELS (e.g.
  // vx-underground) immediately, rather than letting them linger for days until the 300-item cap
  // or 365-day cutoff naturally pushes them out.
  const activeChannelNames = new Set(TELEGRAM_CHANNELS.map(c => c.name));
  const prevTelegram = (prev.telegram || []).filter(i => activeChannelNames.has(i.channel));
  const mergedTelegram = dedupeTelegram([...telegram, ...prevTelegram]).filter(i => !i.date || new Date(i.date).getTime() >= cutoff).slice(0, 300);
  const mergedRansomwareNews = dedupeItems([...ransomwareNews, ...(prev.ransomwareNews || [])]).filter(i => !i.date || new Date(i.date).getTime() >= cutoff).slice(0, 150);

  // Critical Vulnerabilities tab: reuse the CVE-bearing items already merged above (NVD, GitHub
  // Advisories) plus the full KEV catalog, rather than fetching a fourth source — see dedupeVulnerabilities().
  const mergedVulnerabilities = buildVulnList(mergedItems, mergedKev, prev, nowIso);
  const enrichedVulnerabilities = await enrichEpss(mergedVulnerabilities, sourceStatus);

  // RSS feeds are fetched by the 10-min job, not here — carry their last status (and that job's
  // timestamp) forward so each full cycle doesn't blank them. Without this the source-health badge
  // flipped between ~19 and ~32 sources and the "CVE + RSS rotation" freshness line vanished for up to
  // 10 min after every collect(). Only feeds still in SOURCES carry over, so a removed feed drops out.
  const rssNames = new Set(SOURCES.map(src => src.name));
  const carriedRss = Object.fromEntries(Object.entries(prev.sourceStatus || {}).filter(([name]) => rssNames.has(name)));
  const data = {
    generated: nowIso,
    vulnGenerated: prev.vulnGenerated || null,
    infocon: infocon || prev.infocon || "green",
    sourceStatus: Object.assign(carriedRss, sourceStatus),
    items: mergedItems.map(withoutVx),
    victims: mergedVictims,
    kev: mergedKev,
    telegram: mergedTelegram,
    ransomwareNews: mergedRansomwareNews,
    iocs: mergedIocs,
    vulnerabilities: enrichedVulnerabilities,
    ddosTelemetry: ddosTelemetry || prev.ddosTelemetry || null,
    outages: mergeOutages(outages, prev.outages)
  };
  await env.THREAT_DATA.put("latest", JSON.stringify(data));
  return data;
}

// ---------------------------------------------------------------------------------------------
// APT Groups & Operations sheet (Florian Roth / @cyb3rops, CC BY 4.0) — community alias map of
// ~410 actor groups across per-country tabs, each tab public as CSV via /export?format=csv&gid=.
// Runs on its own daily cron (APT_SHEET_CRON) and writes its own KV keys, never "latest", so it
// can't join the collect()/collectVulnerabilitiesOnly() read-modify-write race. 10 subrequests.
// The sheet changes a few times a year at most (newest reference link as of Sep 2026: Oct 2024),
// so the common path is cheap on purpose: fetch → SHA-1 each tab → compare with the small meta
// key → stop. Parsing, diffing, and the ~200KB write only happen when a tab's bytes changed.
// ---------------------------------------------------------------------------------------------
const APT_SHEET_CRON = "17 3 * * *"; // must match the third entry in wrangler.toml's crons
const APT_SHEET_ID = "1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU";
const APT_SHEET_TABS = [
  { tab: "China", gid: "361554658" }, { tab: "Russia", gid: "1636225066" },
  { tab: "North Korea", gid: "1905351590" }, { tab: "Iran", gid: "376438690" },
  { tab: "Israel", gid: "300065512" }, { tab: "NATO", gid: "2069598202" },
  { tab: "Middle East", gid: "574287636" }, { tab: "Others", gid: "438782970" },
  { tab: "Unknown", gid: "1121522397" }
];
const APT_MS_TAXONOMY_GID = "856560690"; // Microsoft 2023 weather-name renaming table
const APT_KEY = "apt_groups", APT_META_KEY = "apt_groups_meta";
// Bumped when parseAptTab()'s output shape changes, so the next run re-parses an unchanged sheet
// instead of serving the old shape until someone edits it (v2: cc/rg target countries replaced the
// india/apj flags).
const APT_SCHEMA = 2;
// The country a tab's groups are attributed to — see the target-country note in parseAptTab().
const APT_TAB_CC = { "China": "CN", "Russia": "RU", "North Korea": "KP", "Iran": "IR", "Israel": "IL" };
const APT_CHANGES_CAP = 200, APT_LINKS_CAP = 12, APT_TEXT_CAP = 600;
const aptCsvUrl = gid => "https://docs.google.com/spreadsheets/d/" + APT_SHEET_ID + "/export?format=csv&gid=" + gid;

// RFC 4180 CSV (quoted fields, "" escapes, newlines inside quotes) in one pass.
function parseCsv(text){
  const rows = []; let row = [], field = "", q = false;
  for (let i = 0; i < text.length; i++){
    const c = text[i];
    if (q){
      if (c === '"'){ if (text[i + 1] === '"'){ field += '"'; i++; } else q = false; }
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ","){ row.push(field); field = ""; }
    else if (c === "\n"){ row.push(field); rows.push(row); row = []; field = ""; }
    else if (c !== "\r") field += c;
  }
  if (field || row.length){ row.push(field); rows.push(row); }
  return rows;
}

const clip = s => s.length > APT_TEXT_CAP ? s.slice(0, APT_TEXT_CAP - 1) + "…" : s;
// Header names drift between tabs ("MITRE AT&CK", "Crowdstrike", "Link  1", blank columns), so
// columns are classified by pattern; anything unrecognised is a vendor/alias name column.
function aptColumnKind(h){
  if (!h) return null;
  if (h === "Common Name") return "name";
  if (/^MITRE AT/i.test(h)) return "mitre";
  if (/^Operation\b/i.test(h)) return "op";
  if (/^Toolset/i.test(h)) return "malware";
  if (h === "Targets") return "targets";
  if (h === "Modus Operandi") return "modus";
  if (h === "Origin") return "origin";
  if (/^Overlaps/i.test(h)) return "overlaps";
  if (h === "Comment") return "comment";
  if (/^Link\b/i.test(h)) return "link";
  if (/^Other Names?\b/i.test(h)) return "other";
  return "vendor";
}
function parseAptTab(csvText, tab){
  const rows = parseCsv(csvText);
  const hi = rows.findIndex(r => (r[0] || "").trim() === "Common Name");
  if (hi < 0) return [];
  const cols = rows[hi].map(h => { const t = h.trim(); return { h: t, kind: aptColumnKind(t) }; });
  const out = [];
  const seen = new Map();
  for (const r of rows.slice(hi + 1)){
    const name = (r[0] || "").trim();
    if (!name) continue;
    // Ids must be unique per tab for the diff: the sheet repeats names ("Unit 8200" twice, "Platinum"
    // vs "PLATINUM") and uses "?"/"???" for groups known only by an operation, so later repeats get
    // a #n suffix. (Fragile only if two same-named rows swap order upstream — rare, and harmless.)
    const base = (tab + ":" + name).toLowerCase();
    const n = (seen.get(base) || 0) + 1; seen.set(base, n);
    const g = { id: n > 1 ? base + "#" + n : base, name, tab, aliases: [], mitre: "", ops: [], malware: "", targets: "", modus: "", origin: "", overlaps: "", comment: "", links: [] };
    cols.forEach((c, i) => {
      const v = (r[i] || "").trim();
      if (!v || !c.kind || c.kind === "name") return;
      if (c.kind === "vendor" || c.kind === "other"){
        // A cell can hold several names ("GIF89a, ShadyRAT, Shanghai Group"); split, drop prose.
        v.split(/[,;\n]|\s\/\s/).map(s => s.trim()).filter(s => s && s.length <= 60 && s.toLowerCase() !== name.toLowerCase())
          .forEach(n => { if (!g.aliases.some(a => a.n.toLowerCase() === n.toLowerCase())) g.aliases.push({ v: c.kind === "vendor" ? c.h : "", n }); });
      }
      else if (c.kind === "op") g.ops.push(v);
      else if (c.kind === "link"){ if (/^https?:\/\//i.test(v) && g.links.length < APT_LINKS_CAP) g.links.push(v); }
      else if (c.kind === "mitre") g.mitre = (v.match(/G\d{4}/) || [""])[0];
      else g[c.kind] = clip(v);
    });
    // Target countries come from who/where it targets — not from the tab or group name, or every
    // China-tab group would be tagged CN by its own label. Modus operandi and comment prose count too
    // (SideCopy's and SideWinder's Targets cells never name India; their comments do), minus the tab's
    // own country, since that prose routinely says "Chinese"/"Russian" about the group itself.
    const tgt = geoTag(g.targets), prose = geoTag(g.modus + " " + g.comment);
    const cc = new Set([...tgt.cc, ...prose.cc.filter(c => c !== APT_TAB_CC[tab])]);
    g.cc = [...cc];
    g.rg = [...new Set([...tgt.rg, ...g.cc.map(c => CC_REGION[c]).filter(Boolean)])];
    // "?"-named rows: show the first alias/operation instead (the raw name is kept for the id).
    if (/^\?+$/.test(name)) g.label = (g.aliases[0] && g.aliases[0].n) || g.ops[0] || "Unnamed group";
    // Drop empty fields — roughly a third of the stored/served payload was "" and [].
    for (const k of Object.keys(g)) if (g[k] === "" || (Array.isArray(g[k]) && !g[k].length)) delete g[k];
    out.push(g);
  }
  return out;
}
// Adds Microsoft's 2023 weather names (e.g. "Mint Sandstorm") as aliases. The table's "Other
// names" column mixes group and malware names, so a row is applied only when its names resolve
// to exactly one group — an ambiguous match is skipped rather than guessed.
function applyMsTaxonomy(groups, csvText){
  const index = new Map();
  groups.forEach(g => [g.name, ...(g.aliases || []).map(a => a.n)].forEach(n => {
    const k = n.toLowerCase(); if (!index.has(k)) index.set(k, new Set()); index.get(k).add(g);
  }));
  let applied = 0;
  for (const r of parseCsv(csvText)){
    for (const off of [1, 6]){ // the tab holds two side-by-side tables
      const prevName = (r[off] || "").trim(), newName = (r[off + 1] || "").trim();
      if (!newName || prevName === "Previous name") continue;
      const names = [prevName, newName, ...(r[off + 3] || "").split(",")].map(s => s.trim().toLowerCase()).filter(Boolean);
      const hits = new Set(); names.forEach(n => (index.get(n) || []).forEach(g => hits.add(g)));
      if (hits.size !== 1) continue;
      const g = [...hits][0];
      g.aliases = g.aliases || [];
      for (const [v, n] of [["Microsoft", newName], ["Microsoft (pre-2023)", prevName]]){
        if (n && n.toLowerCase() !== g.name.toLowerCase() && !g.aliases.some(a => a.n.toLowerCase() === n.toLowerCase())) g.aliases.push({ v, n });
      }
      applied++;
    }
  }
  return applied;
}
// Human-readable diff between two snapshots of the group list.
function diffAptGroups(prevGroups, groups, dateIso){
  const before = new Map(prevGroups.map(g => [g.id, g]));
  const changes = [];
  const added = (a = [], b = []) => b.filter(x => !a.includes(x));
  const names = g => (g.aliases || []).map(a => a.n);
  const label = g => g.label ? g.label + " (" + g.name + ")" : g.name;
  for (const g of groups){
    const p = before.get(g.id);
    before.delete(g.id);
    if (!p){ changes.push({ date: dateIso, id: g.id, name: label(g), tab: g.tab, kind: "added", detail: [] }); continue; }
    const d = [];
    added(names(p), names(g)).forEach(n => d.push("new alias: " + n));
    added(p.ops, g.ops).forEach(o => d.push("new operation: " + o));
    const nl = added(p.links, g.links).length; if (nl) d.push(nl + " new reference link" + (nl > 1 ? "s" : ""));
    for (const k of ["mitre", "malware", "targets", "modus", "origin", "overlaps", "comment"]) if ((p[k] || "") !== (g[k] || "")) d.push(k === "mitre" ? "MITRE ID: " + (g.mitre || "removed") : k + " updated");
    if (d.length) changes.push({ date: dateIso, id: g.id, name: label(g), tab: g.tab, kind: "updated", detail: d.slice(0, 8) });
  }
  for (const p of before.values()) changes.push({ date: dateIso, id: p.id, name: label(p), tab: p.tab, kind: "removed", detail: [] });
  return changes;
}
async function sha1Hex(text){
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function collectAptSheet(env, opts){
  const force = !!(opts && opts.force);
  const nowIso = new Date().toISOString();
  const metaRaw = await env.THREAT_DATA.get(APT_META_KEY);
  const meta = metaRaw ? JSON.parse(metaRaw) : { hashes: {} };
  const gids = [...APT_SHEET_TABS.map(t => t.gid), APT_MS_TAXONOMY_GID];
  let texts;
  try {
    texts = await Promise.all(gids.map(gid => fetchText(aptCsvUrl(gid))));
  } catch (e){
    const m = Object.assign({}, meta, { checkedAt: nowIso, status: { ok: false, error: String(e.message || e) } });
    await env.THREAT_DATA.put(APT_META_KEY, JSON.stringify(m));
    return m;
  }
  const hashes = {};
  (await Promise.all(texts.map(sha1Hex))).forEach((h, i) => { hashes[gids[i]] = h; });
  const changed = gids.some(g => meta.hashes[g] !== hashes[g]) || meta.schema !== APT_SCHEMA;
  if (!changed && !force){
    const m = Object.assign({}, meta, { checkedAt: nowIso, status: { ok: true, changed: false } });
    await env.THREAT_DATA.put(APT_META_KEY, JSON.stringify(m));
    return m;
  }

  const groups = [];
  const perTab = {};
  APT_SHEET_TABS.forEach((t, i) => { const g = parseAptTab(texts[i], t.tab); perTab[t.tab] = g.length; groups.push(...g); });
  const msApplied = applyMsTaxonomy(groups, texts[texts.length - 1]);

  const prevRaw = await env.THREAT_DATA.get(APT_KEY);
  const prev = prevRaw ? JSON.parse(prevRaw) : null;
  // Sanity guard: an empty tab or a sudden large drop means Google served something unexpected
  // (layout change, error page, sheet unpublished) — keep the last good snapshot instead of
  // logging hundreds of false "removed" entries. Hashes aren't saved, so it retries next run.
  const emptyTab = Object.entries(perTab).find(([, n]) => n === 0);
  if (emptyTab || (prev && groups.length < prev.groups.length * 0.8)){
    const m = Object.assign({}, meta, { checkedAt: nowIso, status: { ok: false, error: emptyTab ? "tab " + emptyTab[0] + " parsed to 0 groups" : "group count fell from " + prev.groups.length + " to " + groups.length + " — kept previous snapshot" } });
    await env.THREAT_DATA.put(APT_META_KEY, JSON.stringify(m));
    return m;
  }
  // First run is the baseline: nothing to diff against, so no change entries.
  const newChanges = prev ? diffAptGroups(prev.groups, groups, nowIso) : [];
  const data = {
    updatedAt: nowIso,
    baselineAt: prev ? prev.baselineAt : nowIso,
    source: "https://docs.google.com/spreadsheets/d/" + APT_SHEET_ID,
    groups,
    changes: [...newChanges, ...((prev && prev.changes) || [])].slice(0, APT_CHANGES_CAP)
  };
  await env.THREAT_DATA.put(APT_KEY, JSON.stringify(data));
  const m = { hashes, schema: APT_SCHEMA, checkedAt: nowIso, changedAt: nowIso, status: { ok: true, changed: true, groups: groups.length, perTab, msApplied, newChanges: newChanges.length } };
  await env.THREAT_DATA.put(APT_META_KEY, JSON.stringify(m));
  return m;
}

// On-demand AbuseIPDB lookup for the IP box on the IOCs tab (optional,
// env.ABUSEIPDB_API_KEY). Public endpoint on a 1,000-checks/day free key, so: strict IP validation,
// and each IP's answer is cached at the edge (Cache API — no KV writes) for IPCHECK_CACHE_S, so
// repeat lookups of the same IP don't spend quota.
const IPCHECK_CACHE_S = 6 * 3600;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6_RE = /^[0-9a-f:]+$/i;
function isIpLiteral(ip){
  return IPV4_RE.test(ip) || (ip.length <= 39 && ip.includes(":") && IPV6_RE.test(ip));
}
async function checkIp(env, ip, ctx){
  const ipJson = (obj, status, cacheS) => new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": cacheS ? "public, max-age=" + cacheS : "no-store" }
  });
  if (!isIpLiteral(ip)) return ipJson({ error: "Enter a valid IPv4 or IPv6 address." }, 400);
  if (!env.ABUSEIPDB_API_KEY) return ipJson({ error: "IP lookup isn't configured (ABUSEIPDB_API_KEY not set)." }, 503);
  const cacheKey = new Request("https://ip-check.internal/" + ip.toLowerCase());
  const cached = await caches.default.match(cacheKey);
  if (cached) return cached;
  let r;
  try {
    r = await fetchWithTimeout("https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + encodeURIComponent(ip), { headers: { "Key": env.ABUSEIPDB_API_KEY, "Accept": "application/json" } });
  } catch (e){ return ipJson({ error: "AbuseIPDB didn't respond (" + String(e.message || e) + "). Try again." }, 502); }
  if (r.status === 429) return ipJson({ error: "Daily AbuseIPDB lookup quota reached — try again tomorrow." }, 429);
  if (!r.ok) return ipJson({ error: "AbuseIPDB returned HTTP " + r.status + "." }, 502);
  const d = (await r.json()).data || {};
  const res = ipJson({
    ip: d.ipAddress || ip, score: d.abuseConfidenceScore, reports: d.totalReports, users: d.numDistinctUsers,
    lastReportedAt: d.lastReportedAt || null, country: d.countryCode || "", isp: d.isp || "", domain: d.domain || "",
    usageType: d.usageType || "", hostnames: (d.hostnames || []).slice(0, 3), isTor: !!d.isTor, isPublic: d.isPublic !== false,
    isWhitelisted: !!d.isWhitelisted, checkedAt: new Date().toISOString()
  }, 200, IPCHECK_CACHE_S);
  ctx.waitUntil(caches.default.put(cacheKey, res.clone()));
  return res;
}

function json(obj, status){
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=120" }
  });
}

// Named exports are unused by the Worker runtime but make these functions easy to unit test.
export { decode, tag, geoTag, ccRegion, withGeo, parseItems, parseRwJson, parseKev, parseGithubAdvisories, parseNvdCves, parseOpenPhish, parseTelegramChannel, parseAbusechDate, parseUrlhausIocs, parseThreatfoxIocs, parseMalwareBazaarIocs, dedupeItems, dedupeVictims, capVictims, dedupeKev, dedupeTelegram, dedupeIocs, dedupeVulnerabilities, isWafApplicable, fetchEpssScores, enrichEpss, fetchRadarSummary, radarGet, parseRadarSummary, parseRadarTop, parseRadarIndustries, parseRadarSeries, parseRadarOutages, collectDdosTelemetry, parseIodaSummary, parseIodaEvents, collectOutages, mergeOutages, radarForCountry, rwCountriesForNow, parseMispEvent, fetchMispEvent, collectMisp, collect, fetchVulnSources, mergeVulnData, collectVulnerabilitiesOnly, nvdBackfill, classifyEdge, cnaProducts, cpeProducts, inferProduct, mergeVx, fetchRssBatch, rssBatchForNow, parseCsv, parseAptTab, applyMsTaxonomy, diffAptGroups, collectAptSheet, isIpLiteral };

export default {
  async fetch(request, env, ctx){
    const url = new URL(request.url);

    if (url.pathname === "/api/data"){
      const raw = await env.THREAT_DATA.get("latest");
      if (!raw) return json({ generated: null, vulnGenerated: null, infocon: "green", items: [], victims: [], kev: [], telegram: [], ransomwareNews: [], iocs: [], vulnerabilities: [], ddosTelemetry: null, outages: null, note: "No data yet — the first scheduled collection hasn't run. POST /api/refresh to trigger one manually." });
      return json(JSON.parse(raw));
    }

    if (url.pathname === "/api/refresh" && request.method === "POST"){
      if (env.REFRESH_KEY){
        const auth = request.headers.get("x-refresh-key");
        if (auth !== env.REFRESH_KEY) return json({ error: "unauthorized" }, 401);
      }
      const data = await collect(env);
      return json({ ok: true, generated: data.generated, items: data.items.length, victims: data.victims.length, telegram: data.telegram.length, ransomwareNews: data.ransomwareNews.length, iocs: data.iocs.length, infocon: data.infocon, sourceStatus: data.sourceStatus });
    }

    if (url.pathname === "/api/refresh-vulnerabilities" && request.method === "POST"){
      if (env.REFRESH_KEY){
        const auth = request.headers.get("x-refresh-key");
        if (auth !== env.REFRESH_KEY) return json({ error: "unauthorized" }, 401);
      }
      const data = await collectVulnerabilitiesOnly(env);
      return json({ ok: true, vulnGenerated: data.vulnGenerated, vulnerabilities: data.vulnerabilities.length, kev: data.kev.length, sourceStatus: data.sourceStatus });
    }

    // Actors-page directory: served straight from the two KV strings without JSON.parse — the
    // payload is ~200KB and changes at most daily, so there's no reason to spend CPU on it.
    if (url.pathname === "/api/actors"){
      const [raw, metaRaw] = await Promise.all([env.THREAT_DATA.get(APT_KEY), env.THREAT_DATA.get(APT_META_KEY)]);
      const body = '{"meta":' + (metaRaw || "null") + ',"data":' + (raw || "null") + "}";
      return new Response(body, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=3600" } });
    }

    if (url.pathname === "/api/radar" && request.method === "GET"){
      return radarForCountry(env, (url.searchParams.get("cc") || "").trim().toUpperCase(), ctx);
    }

    if (url.pathname === "/api/ip-check" && request.method === "GET"){
      return checkIp(env, (url.searchParams.get("ip") || "").trim(), ctx);
    }

    if (url.pathname === "/api/refresh-actors" && request.method === "POST"){
      if (env.REFRESH_KEY){
        const auth = request.headers.get("x-refresh-key");
        if (auth !== env.REFRESH_KEY) return json({ error: "unauthorized" }, 401);
      }
      return json(await collectAptSheet(env, { force: url.searchParams.get("force") === "1" }));
    }

    return json({ error: "not found" }, 404);
  },

  async scheduled(event, env, ctx){
    // A second, faster cron (see CVE_ONLY_CRON / wrangler.toml) refreshes just the CVE-bearing
    // sources; the slower one runs the full ~25-source cycle. Falls back to the full cycle for any
    // other cron string (belt-and-suspenders if wrangler.toml's cron list changes later).
    if (event.cron === APT_SHEET_CRON) return ctx.waitUntil(collectAptSheet(env));
    ctx.waitUntil(event.cron === CVE_ONLY_CRON ? collectVulnerabilitiesOnly(env) : collect(env));
  }
};
