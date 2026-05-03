"""
5verflow Blue Team – Flask 대시보드 메인 앱
페이지:  /          ← Suricata 실시간 알럿 대시보드 (eve.json)
         /network   ← API 취약점 전파 네트워크 그래프
         /scan      ← 취약점 스캔 결과
REST:    /api/alerts, /api/stats, /api/timeline
         /api/network, /api/propagation/<src>
         /api/scan/run, /api/scan/results
         /api/report
"""
import json
import threading
import time
from flask import Flask, jsonify, render_template_string, request
from flask_cors import CORS
from log_parser import LogParser
from propagation import get_network_data, simulate_propagation, get_all_propagations
from scanner import run_scan
from report import generate_report
from validation import validate_detection

app = Flask(__name__)
CORS(app)

log_parser = LogParser()

# 스캔 결과 캐시 (백그라운드 실행 지원)
_scan_cache: dict = {}
_scan_lock = threading.Lock()


# ════════════════════════════════════════════════════════════════════════════
# 공통 CSS / JS 스니펫
# ════════════════════════════════════════════════════════════════════════════

_BASE_STYLE = """
<style>
:root {
  --bg:#0d1117; --panel:#161b22; --border:#30363d;
  --text:#e6edf3; --muted:#8b949e;
  --red:#f85149; --orange:#d29922; --green:#3fb950; --blue:#58a6ff;
  --purple:#bc8cff;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;padding:20px;}
a{color:var(--blue);text-decoration:none;}
a:hover{text-decoration:underline;}
nav{display:flex;gap:20px;margin-bottom:24px;border-bottom:1px solid var(--border);padding-bottom:14px;}
nav a{font-size:0.9rem;color:var(--muted);}nav a.active{color:var(--text);font-weight:600;}
h1{font-size:1.5rem;margin-bottom:6px;}
.subtitle{color:var(--muted);font-size:0.85rem;margin-bottom:24px;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px;}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:18px;}
.card-label{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;}
.card-value{font-size:2rem;font-weight:700;margin-top:6px;}
.sev1{color:var(--red);}.sev2{color:var(--orange);}.sev3{color:var(--green);}.blue{color:var(--blue);}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;}
@media(max-width:768px){.charts{grid-template-columns:1fr;}}
.chart-box,.full-width{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:18px;margin-bottom:16px;}
.chart-title{font-size:.9rem;font-weight:600;margin-bottom:12px;}
svg{width:100%;overflow:visible;}
table{width:100%;border-collapse:collapse;font-size:.85rem;}
th{text-align:left;padding:8px 10px;color:var(--muted);font-size:.75rem;border-bottom:1px solid var(--border);}
td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top;}
tr:last-child td{border-bottom:none;}
.badge{display:inline-block;border-radius:4px;padding:2px 8px;font-size:.75rem;font-weight:600;}
.badge-1{background:rgba(248,81,73,.2);color:var(--red);}
.badge-2{background:rgba(210,153,34,.2);color:var(--orange);}
.badge-3{background:rgba(63,185,80,.2);color:var(--green);}
.badge-ok{background:rgba(63,185,80,.15);color:var(--green);}
.badge-fail{background:rgba(248,81,73,.15);color:var(--red);}
.refresh-note{color:var(--muted);font-size:.75rem;margin-top:12px;text-align:right;}
.bar{cursor:default;}.bar:hover{opacity:.8;}
.tooltip{position:fixed;background:#1c2128;border:1px solid var(--border);border-radius:6px;
  padding:8px 12px;font-size:.8rem;pointer-events:none;opacity:0;transition:opacity .15s;z-index:999;}
button{background:var(--blue);color:#0d1117;border:none;border-radius:6px;
  padding:8px 18px;font-size:.85rem;font-weight:600;cursor:pointer;}
button:hover{opacity:.85;}
button:disabled{opacity:.4;cursor:not-allowed;}
.btn-secondary{background:var(--panel);color:var(--text);border:1px solid var(--border);}
.impact-bar-wrap{background:#21262d;border-radius:4px;height:8px;margin-top:4px;}
.impact-bar{height:8px;border-radius:4px;background:var(--red);}
</style>
"""

_NAV = """
<nav>
  <a href="/" id="nav-home">🛡️ 실시간 알럿</a>
  <a href="/network" id="nav-network">🕸️ API 전파 분석</a>
  <a href="/scan" id="nav-scan">🔍 취약점 스캔</a>
</nav>
<script>
  const path = location.pathname;
  if(path==='/') document.getElementById('nav-home').classList.add('active');
  else if(path==='/network') document.getElementById('nav-network').classList.add('active');
  else if(path==='/scan') document.getElementById('nav-scan').classList.add('active');
</script>
"""


# ════════════════════════════════════════════════════════════════════════════
# 페이지 1: / — 실시간 알럿 대시보드
# ════════════════════════════════════════════════════════════════════════════

_PAGE_HOME = """<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>🛡️ Blue Team Dashboard</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
""" + _BASE_STYLE + """
</head><body>
<div class="tooltip" id="tip"></div>
""" + _NAV + """
<h1>🛡️ Suricata 실시간 알럿 대시보드</h1>
<p class="subtitle">crAPI 공격 탐지 모니터링 | 5초마다 자동 갱신</p>

<div class="grid">
  <div class="card"><div class="card-label">전체 알럿</div><div class="card-value" id="total">–</div></div>
  <div class="card"><div class="card-label">긴급 Sev 1</div><div class="card-value sev1" id="sev1">–</div></div>
  <div class="card"><div class="card-label">높음 Sev 2</div><div class="card-value sev2" id="sev2">–</div></div>
  <div class="card"><div class="card-label">낮음 Sev 3</div><div class="card-value sev3" id="sev3">–</div></div>
  <div class="card"><div class="card-label">위험도 점수</div><div class="card-value blue" id="risk">–</div></div>
</div>

<div class="charts">
  <div class="chart-box"><div class="chart-title">📊 공격 카테고리</div><svg id="cat" height="230"></svg></div>
  <div class="chart-box"><div class="chart-title">⏱️ 시간대별 타임라인</div><svg id="tl" height="230"></svg></div>
</div>
<div class="full-width"><div class="chart-title">🌐 상위 공격자 IP</div><svg id="ip" height="160"></svg></div>
<div class="full-width">
  <div class="chart-title">🚨 최근 알럿</div>
  <table><thead><tr><th>시각</th><th>심각도</th><th>출발 IP</th><th>카테고리</th><th>시그니처</th></tr></thead>
  <tbody id="tbl"></tbody></table>
</div>
<p class="refresh-note" id="upd"></p>

<script>
const SEV={1:"긴급",2:"높음",3:"낮음"};
const PAL=["#58a6ff","#3fb950","#d29922","#f85149","#bc8cff","#79c0ff","#56d364","#ffa657","#ff7b72","#a5d6ff"];
const tip=document.getElementById("tip");
function showTip(h,e){tip.innerHTML=h;tip.style.left=(e.clientX+14)+"px";tip.style.top=(e.clientY-30)+"px";tip.style.opacity=1;}
function hideTip(){tip.style.opacity=0;}

function drawBar(sel,data,mL,H,colorFn){
  const entries=Object.entries(data).sort((a,b)=>b[1]-a[1]);
  const svg=d3.select(sel);svg.selectAll("*").remove();
  const W=svg.node().getBoundingClientRect().width||400;
  const mR=50,mT=8,mB=8,iW=W-mL-mR,iH=H-mT-mB;
  const g=svg.append("g").attr("transform",`translate(${mL},${mT})`);
  const x=d3.scaleLinear().domain([0,d3.max(entries,d=>d[1])||1]).range([0,iW]);
  const y=d3.scaleBand().domain(entries.map(d=>d[0])).range([0,iH]).padding(.25);
  g.selectAll(".bar").data(entries).enter().append("rect").attr("class","bar")
    .attr("x",0).attr("y",d=>y(d[0])).attr("height",y.bandwidth()).attr("width",d=>x(d[1]))
    .attr("fill",(d,i)=>colorFn?colorFn(d,i):PAL[i%PAL.length])
    .on("mousemove",(e,d)=>showTip(`<b>${d[0]}</b>: ${d[1]}건`,e)).on("mouseleave",hideTip);
  g.selectAll(".lbl").data(entries).enter().append("text")
    .attr("x",-6).attr("y",d=>y(d[0])+y.bandwidth()/2).attr("dy","0.35em")
    .attr("text-anchor","end").attr("fill","#e6edf3").attr("font-size","11px")
    .text(d=>d[0].length>22?d[0].slice(0,20)+"…":d[0]);
  g.selectAll(".val").data(entries).enter().append("text")
    .attr("x",d=>x(d[1])+4).attr("y",d=>y(d[0])+y.bandwidth()/2).attr("dy","0.35em")
    .attr("fill","#8b949e").attr("font-size","11px").text(d=>d[1]);
}

function drawTimeline(data){
  const entries=Object.entries(data).sort((a,b)=>a[0].localeCompare(b[0]));
  const svg=d3.select("#tl");svg.selectAll("*").remove();
  const W=svg.node().getBoundingClientRect().width||400,H=230,mL=36,mR=16,mT=8,mB=32;
  const iW=W-mL-mR,iH=H-mT-mB;
  const g=svg.append("g").attr("transform",`translate(${mL},${mT})`);
  const x=d3.scalePoint().domain(entries.map(d=>d[0])).range([0,iW]).padding(.5);
  const y=d3.scaleLinear().domain([0,d3.max(entries,d=>d[1])||1]).range([iH,0]);
  g.append("g").attr("transform",`translate(0,${iH})`).call(d3.axisBottom(x).tickSize(3))
    .selectAll("text").attr("fill","#8b949e").attr("font-size","10px");
  g.append("g").call(d3.axisLeft(y).ticks(4).tickSize(3))
    .selectAll("text").attr("fill","#8b949e").attr("font-size","10px");
  svg.selectAll(".domain,.tick line").attr("stroke","#30363d");
  // area fill
  g.append("path").datum(entries)
    .attr("fill","rgba(88,166,255,.12)").attr("stroke","none")
    .attr("d",d3.area().x(d=>x(d[0])).y0(iH).y1(d=>y(d[1])).curve(d3.curveMonotoneX));
  g.append("path").datum(entries)
    .attr("fill","none").attr("stroke","#58a6ff").attr("stroke-width",2)
    .attr("d",d3.line().x(d=>x(d[0])).y(d=>y(d[1])).curve(d3.curveMonotoneX));
  g.selectAll(".dot").data(entries).enter().append("circle")
    .attr("cx",d=>x(d[0])).attr("cy",d=>y(d[1])).attr("r",4)
    .attr("fill","#58a6ff").attr("stroke","#0d1117").attr("stroke-width",2)
    .on("mousemove",(e,d)=>showTip(`${d[0]}: ${d[1]}건`,e)).on("mouseleave",hideTip);
}

function renderTable(alerts){
  const tbody=document.getElementById("tbl");tbody.innerHTML="";
  alerts.slice(0,50).forEach(a=>{
    const ts=(a.timestamp||"").replace("T"," ").slice(0,19);
    const sev=a.severity||3;
    const tr=document.createElement("tr");
    tr.innerHTML=`<td style="color:#8b949e;white-space:nowrap;font-size:.8rem">${ts}</td>
      <td><span class="badge badge-${sev}">${SEV[sev]||sev}</span></td>
      <td style="font-family:monospace">${a.src_ip||""}</td>
      <td style="color:#8b949e">${a.category||""}</td>
      <td>${a.signature||""}</td>`;
    tbody.appendChild(tr);
  });
}

async function refresh(){
  try{
    const [sr,ar]=await Promise.all([fetch("/api/stats"),fetch("/api/alerts")]);
    const s=await sr.json(), a=await ar.json();
    document.getElementById("total").textContent=s.total??0;
    document.getElementById("sev1").textContent=s.severity?.["1"]??0;
    document.getElementById("sev2").textContent=s.severity?.["2"]??0;
    document.getElementById("sev3").textContent=s.severity?.["3"]??0;
    document.getElementById("risk").textContent=s.risk_score??0;
    if(s.category) drawBar("#cat",s.category,165,230);
    if(s.timeline) drawTimeline(s.timeline);
    if(s.top_ips)  drawBar("#ip",Object.fromEntries(s.top_ips),115,160,()=>"#58a6ff");
    renderTable(a);
    document.getElementById("upd").textContent="마지막 갱신: "+new Date().toLocaleTimeString("ko-KR");
  }catch(e){console.error(e);}
}
refresh(); setInterval(refresh,5000);
</script></body></html>"""


# ════════════════════════════════════════════════════════════════════════════
# 페이지 2: /network — API 전파 분석 (D3 Force Graph)
# ════════════════════════════════════════════════════════════════════════════

_PAGE_NETWORK = """<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>🕸️ API 전파 분석</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
""" + _BASE_STYLE + """
<style>
.node circle{stroke:#30363d;stroke-width:2px;cursor:pointer;}
.node text{font-size:12px;fill:#e6edf3;pointer-events:none;font-weight:600;}
.node .sub{font-size:10px;fill:#8b949e;font-weight:400;}
.link{stroke:#30363d;stroke-opacity:.8;}
.link.highlight{stroke:#f85149;stroke-opacity:1;stroke-width:3;}
.node circle.highlight{stroke:#f85149;stroke-width:3px;}
#graph-wrap{background:var(--panel);border:1px solid var(--border);border-radius:8px;
  margin-bottom:16px;overflow:hidden;}
#propagation-panel{background:var(--panel);border:1px solid var(--border);
  border-radius:8px;padding:18px;margin-bottom:16px;display:none;}
#propagation-panel.visible{display:block;}
.chain-step{display:flex;align-items:flex-start;gap:12px;margin-bottom:12px;
  padding:10px;background:#21262d;border-radius:6px;}
.step-num{background:var(--red);color:#fff;border-radius:50%;
  width:24px;height:24px;display:flex;align-items:center;justify-content:center;
  font-size:11px;font-weight:700;flex-shrink:0;}
.step-num.ok{background:var(--blue);}
.rec-item{padding:10px;background:#21262d;border-radius:6px;margin-bottom:8px;}
</style>
</head><body>
<div class="tooltip" id="tip"></div>
""" + _NAV + """
<h1>🕸️ API 취약점 전파 분석</h1>
<p class="subtitle">노드를 클릭하면 해당 API 해킹 시 공격 전파 경로를 시뮬레이션합니다.</p>

<div class="grid" id="summary-cards"></div>

<div id="graph-wrap"><svg id="graph" height="420"></svg></div>

<div id="propagation-panel">
  <div class="chart-title" id="prop-title">📡 전파 시뮬레이션 결과</div>
  <div id="prop-body"></div>
</div>

<div class="full-width">
  <div class="chart-title">📋 전체 API 취약점 목록</div>
  <table><thead><tr><th>API</th><th>취약점</th><th>CVE</th><th>CVSS</th><th>심각도</th></tr></thead>
  <tbody id="vuln-table"></tbody></table>
</div>

<script>
const tip=document.getElementById("tip");
function showTip(h,e){tip.innerHTML=h;tip.style.left=(e.clientX+14)+"px";tip.style.top=(e.clientY-30)+"px";tip.style.opacity=1;}
function hideTip(){tip.style.opacity=0;}

const SEV_COLOR={"1":"#f85149","2":"#d29922","3":"#3fb950"};
const SEV_LABEL={"1":"🔴 긴급","2":"🟠 높음","3":"🟡 낮음"};

let networkData=null;

async function init(){
  const r=await fetch("/api/network");
  networkData=await r.json();
  renderSummaryCards(networkData.nodes);
  drawForceGraph(networkData);
  renderVulnTable(networkData.nodes);
}

function renderSummaryCards(nodes){
  const el=document.getElementById("summary-cards");
  el.innerHTML=nodes.map(n=>`
    <div class="card" style="cursor:pointer" onclick="loadPropagation('${n.id}')">
      <div class="card-label">${n.name}</div>
      <div style="font-size:1.1rem;font-weight:700;margin-top:6px;color:${SEV_COLOR[n.max_severity]||'#58a6ff'}">
        취약점 ${n.vuln_count}개
      </div>
      <div style="font-size:.75rem;color:#8b949e;margin-top:4px">${n.tech}</div>
      <div class="impact-bar-wrap"><div class="impact-bar" style="width:${Math.min(n.risk_score*2,100)}%"></div></div>
    </div>`).join("");
}

function drawForceGraph(data){
  const svg=d3.select("#graph");
  svg.selectAll("*").remove();
  const W=svg.node().getBoundingClientRect().width||800, H=420;

  const sim=d3.forceSimulation(data.nodes)
    .force("link",d3.forceLink(data.links).id(d=>d.id).distance(160))
    .force("charge",d3.forceManyBody().strength(-400))
    .force("center",d3.forceCenter(W/2,H/2))
    .force("collide",d3.forceCollide(60));

  const g=svg.append("g");

  // arrow marker
  svg.append("defs").selectAll("marker").data(["arr"]).enter().append("marker")
    .attr("id","arr").attr("viewBox","0 -5 10 10").attr("refX",28).attr("refY",0)
    .attr("markerWidth",6).attr("markerHeight",6).attr("orient","auto")
    .append("path").attr("d","M0,-5L10,0L0,5").attr("fill","#58a6ff");

  const link=g.append("g").selectAll("line").data(data.links).enter().append("line")
    .attr("class","link").attr("stroke-width",2)
    .attr("stroke",d=>d.call_type==="internal"?"#bc8cff":"#58a6ff")
    .attr("marker-end","url(#arr)")
    .on("mousemove",(e,d)=>showTip(`<b>${d.source.id||d.source}</b> → <b>${d.target.id||d.target}</b><br>${d.description}`,e))
    .on("mouseleave",hideTip);

  const node=g.append("g").selectAll(".node").data(data.nodes).enter().append("g")
    .attr("class","node")
    .call(d3.drag().on("start",(e,d)=>{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;})
      .on("drag",(e,d)=>{d.fx=e.x;d.fy=e.y;})
      .on("end",(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}))
    .on("click",(e,d)=>loadPropagation(d.id));

  node.append("circle").attr("r",36)
    .attr("fill",d=>SEV_COLOR[d.max_severity]+"33")
    .attr("stroke",d=>SEV_COLOR[d.max_severity]||"#30363d");
  node.append("text").attr("text-anchor","middle").attr("dy","-6px").text(d=>d.name);
  node.append("text").attr("class","sub").attr("text-anchor","middle").attr("dy","10px")
    .text(d=>`포트 ${d.port}`);
  node.append("text").attr("class","sub").attr("text-anchor","middle").attr("dy","24px")
    .text(d=>`취약점 ${d.vuln_count}개`);

  sim.on("tick",()=>{
    link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
        .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
    node.attr("transform",d=>`translate(${d.x},${d.y})`);
  });

  // 줌
  svg.call(d3.zoom().scaleExtent([.5,3]).on("zoom",e=>g.attr("transform",e.transform)));
}

async function loadPropagation(apiId){
  const panel=document.getElementById("propagation-panel");
  const body=document.getElementById("prop-body");
  const title=document.getElementById("prop-title");
  panel.classList.add("visible");
  body.innerHTML="<p style='color:#8b949e'>분석 중…</p>";
  title.textContent="📡 전파 시뮬레이션: "+apiId;

  const r=await fetch("/api/propagation/"+apiId);
  const d=await r.json();

  const impactColor=d.impact_percent>=100?"#f85149":d.impact_percent>=66?"#d29922":"#3fb950";

  let html=`
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">
      <div class="card" style="flex:1;min-width:160px">
        <div class="card-label">영향받는 API</div>
        <div class="card-value" style="color:${impactColor}">${d.affected_count} / ${d.total_apis}</div>
      </div>
      <div class="card" style="flex:1;min-width:160px">
        <div class="card-label">시스템 영향도</div>
        <div class="card-value" style="color:${impactColor}">${d.impact_percent}%</div>
      </div>
    </div>
    <div style="background:#21262d;border-radius:6px;padding:12px;margin-bottom:16px;font-size:.85rem;line-height:1.6">
      📝 ${d.scenario}
    </div>
    <div class="chart-title">⛓️ 공격 체인</div>`;

  (d.attack_chain||[]).forEach(step=>{
    const s=step.vulnerabilities?.[0];
    html+=`<div class="chain-step">
      <div class="step-num">${step.step}</div>
      <div>
        <div style="font-weight:600">${step.name} <span style="color:#8b949e;font-size:.8rem">${step.edge_type}</span></div>
        <div style="font-size:.8rem;color:#8b949e;margin-top:2px">노출 데이터: ${step.data_exposed}</div>
        ${s?`<div style="font-size:.8rem;color:var(--red);margin-top:4px">⚠️ ${s.type} (${s.cve})</div>`:""}
      </div></div>`;
  });

  html+=`<div class="chart-title" style="margin-top:16px">🔧 보안 권고</div>`;
  (d.recommendations||[]).forEach(r=>{
    html+=`<div class="rec-item">
      <div style="font-weight:600">${r.priority} – ${r.api}</div>
      <div style="font-size:.8rem;color:#8b949e;margin-top:4px">${r.action}</div>
      <div style="font-size:.75rem;color:#58a6ff;margin-top:4px">${r.roi}</div>
    </div>`;
  });

  body.innerHTML=html;
  panel.scrollIntoView({behavior:"smooth"});
}

function renderVulnTable(nodes){
  const tbody=document.getElementById("vuln-table");
  tbody.innerHTML="";
  nodes.forEach(n=>{
    (n.vulnerabilities||[]).forEach((v,i)=>{
      const tr=document.createElement("tr");
      tr.innerHTML=`
        ${i===0?`<td rowspan="${n.vuln_count||1}" style="font-weight:600">${n.name}</td>`:""}
        <td>${v.type}</td>
        <td style="font-family:monospace;font-size:.8rem">${v.cve||""}</td>
        <td style="color:${SEV_COLOR[v.severity]||"#8b949e"}">${v.cvss??""}</td>
        <td><span class="badge badge-${v.severity}">${SEV_LABEL[v.severity]||""}</span></td>`;
      tbody.appendChild(tr);
    });
  });
}

init();
</script></body></html>"""


# ════════════════════════════════════════════════════════════════════════════
# 페이지 3: /scan — 취약점 스캔 결과
# ════════════════════════════════════════════════════════════════════════════

_PAGE_SCAN = """<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>🔍 취약점 스캔</title>
""" + _BASE_STYLE + """
</head><body>
""" + _NAV + """
<h1>🔍 취약점 자동 스캐너</h1>
<p class="subtitle">JWT 우회 / SQL 인젝션 / BFLA / 민감정보 노출 자동 테스트</p>

<div style="display:flex;gap:12px;margin-bottom:20px;align-items:center">
  <button id="btn-scan" onclick="runScan()">▶ 스캔 시작</button>
  <button class="btn-secondary" onclick="runValidation()">🧪 탐지 검증</button>
  <button class="btn-secondary" onclick="loadResults()">↻ 결과 새로고침</button>
  <a href="/api/report" target="_blank"><button class="btn-secondary">📄 리포트 다운로드</button></a>
  <span id="scan-status" style="color:#8b949e;font-size:.85rem"></span>
</div>

<div class="grid" id="summary-cards"></div>

<div id="results-wrap"></div>
<div id="validation-wrap"></div>

<script>
const SEV_COLOR={"1":"#f85149","2":"#d29922","3":"#3fb950"};

async function runScan(){
  const btn=document.getElementById("btn-scan");
  const status=document.getElementById("scan-status");
  btn.disabled=true; status.textContent="스캔 실행 중…";
  try{
    const r=await fetch("/api/scan/run",{method:"POST"});
    const d=await r.json();
    if(d.status==="started"||d.status==="ok"){
      status.textContent="스캔 완료! 결과 로딩 중…";
      await new Promise(r=>setTimeout(r,800));
      await loadResults();
    }
  }catch(e){ status.textContent="스캔 실패: "+e; }
  btn.disabled=false;
}

async function runValidation(){
  const status=document.getElementById("scan-status");
  status.textContent="탐지 검증 실행 중…";
  try{
    const r=await fetch("/api/validation");
    if(!r.ok){
      const err=await r.json();
      status.textContent="검증 실패: "+(err.error||"unknown error");
      return;
    }
    const d=await r.json();
    renderValidation(d);
    status.textContent=`탐지 커버리지 ${d.summary.coverage_percent}% (${d.summary.detected}/${d.summary.total_vulnerabilities})`;
  }catch(e){
    status.textContent="검증 실패: "+e;
  }
}

async function loadResults(){
  const r=await fetch("/api/scan/results");
  if(!r.ok){
    document.getElementById("results-wrap").innerHTML=
      '<p style="color:#8b949e;padding:20px">스캔 결과 없음. 스캔을 먼저 실행하세요.</p>';
    return;
  }
  const d=await r.json();
  renderSummary(d.summary);
  renderResults(d.results);
  document.getElementById("scan-status").textContent=
    `완료 (${d.scan_duration_sec}초 소요) | ${d.scan_time}`;
}

function renderSummary(s){
  if(!s) return;
  document.getElementById("summary-cards").innerHTML=`
    <div class="card"><div class="card-label">전체 테스트</div>
      <div class="card-value blue">${s.total_tests}</div></div>
    <div class="card"><div class="card-label">취약점 발견</div>
      <div class="card-value sev1">${s.vulnerabilities_found}</div></div>
    <div class="card"><div class="card-label">긴급 (Sev 1)</div>
      <div class="card-value sev1">${s.critical}</div></div>
    ${Object.entries(s.by_api||{}).map(([api,cnt])=>`
    <div class="card"><div class="card-label">${api}</div>
      <div class="card-value" style="color:${cnt>0?"#f85149":"#3fb950"}">${cnt}개 발견</div></div>`).join("")}`;
}

function renderResults(results){
  if(!results){document.getElementById("results-wrap").innerHTML="";return;}
  let html="";
  for(const [api,tests] of Object.entries(results)){
    html+=`<div class="full-width">
      <div class="chart-title">🔎 ${api}</div>
      <table><thead><tr><th>테스트</th><th>CVE</th><th>결과</th><th>상세</th></tr></thead><tbody>`;
    tests.forEach(t=>{
      const ok=t.passed;
      html+=`<tr>
        <td style="font-weight:600">${t.test}</td>
        <td style="font-family:monospace;font-size:.8rem">${t.cve||""}</td>
        <td><span class="badge ${ok?"badge-fail":"badge-ok"}">${ok?"⚠️ 취약":"✅ 안전"}</span></td>
        <td style="font-size:.8rem;color:#8b949e;max-width:400px;word-break:break-all">${t.detail||""}</td>
      </tr>`;
    });
    html+="</tbody></table></div>";
  }
  document.getElementById("results-wrap").innerHTML=html;
}

function renderValidation(data){
  if(!data || !data.summary){
    document.getElementById("validation-wrap").innerHTML="";
    return;
  }

  const s=data.summary;
  const rows=(data.findings||[]).map(f=>`
    <tr>
      <td style="font-weight:600">${f.api}</td>
      <td>${f.test}</td>
      <td style="font-family:monospace;font-size:.8rem">${f.cve||""}</td>
      <td><span class="badge ${f.detected?"badge-ok":"badge-fail"}">${f.detected?"✅ 탐지":"❌ 미탐지"}</span></td>
      <td style="color:#8b949e">${f.matched_alerts}</td>
      <td style="font-size:.8rem;color:#8b949e">${(f.match_keywords||[]).join(", ")}</td>
    </tr>
  `).join("");

  document.getElementById("validation-wrap").innerHTML=`
    <div class="full-width">
      <div class="chart-title">🧪 탐지 검증 결과</div>
      <div class="grid" style="margin-bottom:14px">
        <div class="card"><div class="card-label">탐지 커버리지</div><div class="card-value blue">${s.coverage_percent}%</div></div>
        <div class="card"><div class="card-label">탐지됨</div><div class="card-value sev3">${s.detected}</div></div>
        <div class="card"><div class="card-label">미탐지</div><div class="card-value sev1">${s.undetected}</div></div>
        <div class="card"><div class="card-label">분석한 알럿 수</div><div class="card-value">${s.alerts_analyzed}</div></div>
      </div>
      <table>
        <thead><tr><th>API</th><th>취약점</th><th>CVE</th><th>탐지 여부</th><th>매칭 알럿 수</th><th>키워드</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" style="color:#8b949e">발견된 취약점이 없습니다.</td></tr>'}</tbody>
      </table>
    </div>
  `;
}

// 페이지 로드 시 캐시된 결과 표시
loadResults();
</script></body></html>"""


# ════════════════════════════════════════════════════════════════════════════
# Flask 라우트
# ════════════════════════════════════════════════════════════════════════════

@app.route("/")
def page_home():
    return render_template_string(_PAGE_HOME)


@app.route("/network")
def page_network():
    return render_template_string(_PAGE_NETWORK)


@app.route("/scan")
def page_scan():
    return render_template_string(_PAGE_SCAN)


# ── 알럿 API ──────────────────────────────────────────────────────────────

@app.route("/api/alerts")
def api_alerts():
    return jsonify(log_parser.parse())


@app.route("/api/stats")
def api_stats():
    return jsonify(log_parser.get_stats())


@app.route("/api/timeline")
def api_timeline():
    return jsonify(log_parser.get_stats()["timeline"])


# ── 네트워크 / 전파 API ────────────────────────────────────────────────────

@app.route("/api/network")
def api_network():
    data = get_network_data()
    # vulnerabilities 필드를 nodes에 포함
    from propagation import _NODE_MAP
    for node in data["nodes"]:
        node["vulnerabilities"] = [v for v in _NODE_MAP[node["id"]].vulnerabilities]
    return jsonify(data)


@app.route("/api/propagation/<source>")
def api_propagation(source: str):
    return jsonify(simulate_propagation(source))


@app.route("/api/propagation")
def api_propagation_all():
    return jsonify(get_all_propagations())


# ── 스캔 API ──────────────────────────────────────────────────────────────

@app.route("/api/scan/run", methods=["POST"])
def api_scan_run():
    """백그라운드에서 스캔 실행 후 즉시 응답."""

    def _do_scan():
        try:
            result = run_scan()
            with _scan_lock:
                _scan_cache.update(result)
                _scan_cache["_done"] = True
        finally:
            with _scan_lock:
                _scan_cache["_running"] = False

    # 이미 실행 중이면 상태만 반환
    with _scan_lock:
        if _scan_cache.get("_running"):
            return jsonify({"status": "started", "message": "기존 스캔이 아직 실행 중입니다."})
        _scan_cache.clear()
        _scan_cache["_running"] = True
        _scan_cache["_done"] = False

    t = threading.Thread(target=_do_scan, daemon=True)
    t.start()
    t.join(timeout=15)  # 최대 15초 대기

    with _scan_lock:
        if _scan_cache.get("_done"):
            return jsonify({"status": "ok", **_scan_cache})
    return jsonify({"status": "started", "message": "스캔이 백그라운드에서 실행 중입니다."})


@app.route("/api/scan/results")
def api_scan_results():
    with _scan_lock:
        if not _scan_cache.get("_done"):
            return jsonify({"error": "스캔 결과 없음"}), 404
    return jsonify({k: v for k, v in _scan_cache.items() if k not in ("_done", "_running")})


@app.route("/api/validation")
def api_validation():
    """최근 스캔 결과와 Suricata 알럿을 연결해 탐지 커버리지 계산."""
    with _scan_lock:
        if not _scan_cache.get("_done"):
            return jsonify({"error": "스캔 결과가 없습니다. 먼저 /api/scan/run 을 실행하세요."}), 400
        scan_data = {k: v for k, v in _scan_cache.items() if k not in ("_done", "_running")}

    alerts = log_parser.parse()
    return jsonify(validate_detection(scan_data, alerts))


# ── 리포트 API ────────────────────────────────────────────────────────────

@app.route("/api/report")
def api_report():
  with _scan_lock:
    scan_data = {k: v for k, v in _scan_cache.items() if k not in ("_done", "_running")}

  if not scan_data:
    scan_data = {"results": {}, "summary": {}}

  report = generate_report(scan_data)
  return jsonify(report)


# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
