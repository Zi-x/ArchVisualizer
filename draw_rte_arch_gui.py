import os
import re
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from collections import defaultdict
import configparser

# ===================== 【核心功能类】 =====================
class RTEAnalyzer:
    def __init__(self):
        self.src_root = ""
        self.puml_out = "./rte_architecture.puml"
        self.target_modules = []
        self.display_mode = "related"  # "all": 显示所有, "only": 仅目标模块, "related": 目标+关联模块
        self.merge_multi_signal = True
        self.only_alphabet_module = True
        # 最终边集
        self.edge_signals = defaultdict(set)
        self.all_components = set()
        # 正则表达式
        self.pat_read = re.compile(
            r'#\s*define\s+Rte_Read_([a-zA-Z0-9]+)_([a-zA-Z0-9_]+)\(data\)\s*\(\s*\*\(data\)\s*=\s*Rte_([a-zA-Z0-9]+)_([a-zA-Z0-9_]+)\s*,\s*\(\(Std_ReturnType\)RTE_E_OK\)\s*\)'
        )
        self.pat_write = re.compile(
            r'#\s*define\s+Rte_Write_[a-zA-Z0-9]+_[a-zA-Z0-9_]+\(data\)\s*\(\s*Rte_([a-zA-Z0-9]+)_([a-zA-Z0-9_]+)\s*=\s*\(data\)\s*,\s*\(\(Std_ReturnType\)RTE_E_OK\)\s*\)'
        )
        # 数据结构
        self.write_map = defaultdict(set)
        self.signal_to_writers = defaultdict(set)
        self.signal_to_readers = defaultdict(set)

    def is_file_need_skip(self, filename: str) -> bool:
        if filename.startswith("Rte_") and filename.endswith(".h"):
            if filename.endswith("_Type.h"):
                return True
        return False

    def get_module_from_filename(self, filename: str) -> str:
        return filename.removeprefix("Rte_").removesuffix(".h")

    def is_module_name_only_alphabet(self, mod_name: str) -> bool:
        return mod_name.isalpha()

    def is_file_module_allowed(self, mod_name: str) -> bool:
        if not self.target_modules:
            return True
        return mod_name in self.target_modules

    def scan_header_file(self, filepath: str, filename: str):
        current_mod = self.get_module_from_filename(filename)
        if self.only_alphabet_module and not self.is_module_name_only_alphabet(current_mod):
            return
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    # 匹配 Rte_Read
                    m = self.pat_read.search(line)
                    if m:
                        recv_comp, sig, send_comp, sig2 = m.groups()
                        if sig != sig2:
                            continue
                        self.signal_to_readers[sig].add(current_mod)
                        continue
                    # 匹配 Rte_Write
                    mw = self.pat_write.search(line)
                    if mw:
                        mod, sig = mw.groups()
                        self.signal_to_writers[sig].add(mod)
                        self.write_map[mod].add(sig)
        except Exception as e:
            print(f"跳过异常文件 {filepath}: {e}")

    def traverse_dir(self, root: str, callback=None):
        # 重置数据结构
        self.edge_signals.clear()
        self.all_components.clear()
        self.write_map.clear()
        self.signal_to_writers.clear()
        self.signal_to_readers.clear()

        parse_cnt = skip_type = skip_alpha = 0
        total_files = 0
        # 统计总数
        for _, _, filenames in os.walk(root):
            for fname in filenames:
                if fname.startswith("Rte_") and fname.endswith(".h") and not self.is_file_need_skip(fname):
                    total_files += 1

        processed = 0
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                if self.is_file_need_skip(fname):
                    skip_type += 1
                    continue
                if fname.startswith("Rte_") and fname.endswith(".h"):
                    mod = self.get_module_from_filename(fname)
                    if self.only_alphabet_module and not self.is_module_name_only_alphabet(mod):
                        skip_alpha += 1
                        continue
                    self.scan_header_file(os.path.join(dirpath, fname), fname)
                    parse_cnt += 1
                    processed += 1
                    if callback:
                        callback(processed, total_files)
        return parse_cnt, skip_type, skip_alpha

    def build_edges(self):
        """根据收集的信号关系构建最终边集（双向确认）"""
        self.edge_signals.clear()
        self.all_components.clear()
        
        temp_edges = defaultdict(set)
        
        # 情况1: 显示所有模块
        if self.display_mode == "all":
            for sig, writers in self.signal_to_writers.items():
                readers = self.signal_to_readers.get(sig, set())
                for writer in writers:
                    for reader in readers:
                        if writer == reader:
                            continue
                        temp_edges[(writer, reader)].add(sig)
                        self.all_components.add(writer)
                        self.all_components.add(reader)
            
            for sig, readers in self.signal_to_readers.items():
                writers = self.signal_to_writers.get(sig, set())
                for reader in readers:
                    for writer in writers:
                        if writer == reader:
                            continue
                        temp_edges[(writer, reader)].add(sig)
                        self.all_components.add(writer)
                        self.all_components.add(reader)
        
        # 情况2: 仅显示目标模块
        elif self.display_mode == "only":
            if not self.target_modules:
                # 如果没有目标模块，显示所有
                for sig, writers in self.signal_to_writers.items():
                    readers = self.signal_to_readers.get(sig, set())
                    for writer in writers:
                        for reader in readers:
                            if writer == reader:
                                continue
                            temp_edges[(writer, reader)].add(sig)
                            self.all_components.add(writer)
                            self.all_components.add(reader)
            else:
                # 只保留目标模块之间的边
                target_set = set(self.target_modules)
                for sig, writers in self.signal_to_writers.items():
                    readers = self.signal_to_readers.get(sig, set())
                    for writer in writers:
                        for reader in readers:
                            if writer == reader:
                                continue
                            # 只有两端都在目标模块中才保留
                            if writer in target_set and reader in target_set:
                                temp_edges[(writer, reader)].add(sig)
                                self.all_components.add(writer)
                                self.all_components.add(reader)
        
        # 情况3: 显示目标模块及关联模块（默认）
        else:  # "related"
            if not self.target_modules:
                # 如果没有目标模块，显示所有
                for sig, writers in self.signal_to_writers.items():
                    readers = self.signal_to_readers.get(sig, set())
                    for writer in writers:
                        for reader in readers:
                            if writer == reader:
                                continue
                            temp_edges[(writer, reader)].add(sig)
                            self.all_components.add(writer)
                            self.all_components.add(reader)
            else:
                target_set = set(self.target_modules)
                # 先收集所有与目标模块相关的边
                for sig, writers in self.signal_to_writers.items():
                    readers = self.signal_to_readers.get(sig, set())
                    for writer in writers:
                        for reader in readers:
                            if writer == reader:
                                continue
                            # 只要有一端在目标模块中就保留
                            if writer in target_set or reader in target_set:
                                temp_edges[(writer, reader)].add(sig)
                                self.all_components.add(writer)
                                self.all_components.add(reader)
        
        self.edge_signals = temp_edges

    def generate_mermaid(self):
        lines = [
            '%%{init: {"flowchart": {"defaultRenderer": "elk", "useMaxWidth": false, "nodeSpacing": 80, "rankSpacing": 100}, "theme": "default", "themeVariables": {"fontSize": "14px"}}}%%',
            "graph TD",
            ""
        ]
        used = set()
        for s, r in self.edge_signals.keys():
            used.add(s)
            used.add(r)
        for comp in sorted(used):
            lines.append(f'{comp}["{comp}"]')
        lines.append("")
        total_edge = 0
        for (s, r), sigs in self.edge_signals.items():
            if self.merge_multi_signal:
                lines.append(f'{s} -->|{", ".join(sorted(sigs))}| {r}')
            else:
                for sig in sorted(sigs):
                    lines.append(f'{s} -->|{sig}| {r}')
            total_edge += 1
        out = self.puml_out.replace(".puml", ".mmd")
        with open(out, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return out, len(used), total_edge, sum(len(v) for v in self.edge_signals.values())

    def generate_interactive_html(self, mermaid_file: str):
        with open(mermaid_file, 'r', encoding='utf-8') as f:
            mermaid_content = f.read()

        nodes_data = {}
        edges_data = []
        for m in re.finditer(r'(\w+)\[(["\w]+)\]', mermaid_content):
            nid, nlabel = m.group(1), m.group(2).strip('"')
            nodes_data[nid] = {'id': nid, 'label': nlabel, 'inputs': [], 'outputs': []}
        for m in re.finditer(r'(\w+)\s*-->\|([^|]+)\|\s*(\w+)', mermaid_content):
            src, lbl, tgt = m.group(1), m.group(2), m.group(3)
            edges_data.append({'source': src, 'target': tgt, 'label': lbl, 'id': f"{src}-{tgt}"})
            if src in nodes_data:
                nodes_data[src]['outputs'].append(tgt)
            if tgt in nodes_data:
                nodes_data[tgt]['inputs'].append(src)

        nodes_json = json.dumps(nodes_data, ensure_ascii=False)
        edges_json = json.dumps(edges_data, ensure_ascii=False)
        target_modules_json = json.dumps(self.target_modules, ensure_ascii=False)

        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>RTE架构交互式可视化</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:linear-gradient(135deg,#667eea 0%,#764ba2 100%); min-height:100vh; overflow:hidden; }}
        .container {{ display:flex; height:100vh; }}
        .sidebar {{ width:320px; min-width:320px; background:rgba(255,255,255,0.95); backdrop-filter:blur(10px); box-shadow:2px 0 15px rgba(0,0,0,0.1); padding:20px; overflow-y:auto; z-index:100; display:flex; flex-direction:column; }}
        .sidebar h2 {{ color:#333; margin-bottom:20px; font-size:1.5em; border-bottom:2px solid #667eea; padding-bottom:10px; }}
        .search-box {{ margin-bottom:15px; }}
        .search-box input {{ width:100%; padding:10px; border:2px solid #ddd; border-radius:8px; font-size:14px; transition:border-color 0.3s; }}
        .search-box input:focus {{ outline:none; border-color:#667eea; }}
        
        /* 小开关样式 */
        .switch-container {{
            display:flex;
            align-items:center;
            justify-content:space-between;
            padding:8px 12px;
            background:#f0f0f0;
            border-radius:8px;
            margin-bottom:12px;
            font-size:12px;
            color:#555;
        }}
        .switch-label {{
            display:flex;
            align-items:center;
            gap:6px;
        }}
        .switch {{
            position:relative;
            width:40px;
            height:22px;
            background:#ccc;
            border-radius:11px;
            cursor:pointer;
            transition:all 0.3s;
            flex-shrink:0;
        }}
        .switch.active {{
            background:#667eea;
        }}
        .switch .slider {{
            position:absolute;
            top:2px;
            left:2px;
            width:18px;
            height:18px;
            background:white;
            border-radius:50%;
            transition:all 0.3s;
            box-shadow:0 1px 3px rgba(0,0,0,0.3);
        }}
        .switch.active .slider {{
            left:20px;
        }}
        
        .node-list {{ flex:1; overflow-y:auto; margin-bottom:15px; }}
        .node-item {{ display:flex; align-items:center; justify-content:space-between; padding:10px; margin:5px 0; background:#f8f9fa; border-radius:8px; cursor:pointer; transition:all 0.3s; border:2px solid transparent; }}
        .node-item:hover {{ background:#e9ecef; transform:translateX(5px); }}
        .node-item.active {{ background:linear-gradient(135deg,#667eea 0%,#764ba2 100%); color:white; border-color:#667eea; }}
        .node-item .info {{ flex:1; }}
        .node-item .info strong {{ display:block; }}
        .node-item .stats {{ font-size:0.85em; color:#6c757d; margin-top:5px; }}
        .node-item.active .stats {{ color:rgba(255,255,255,0.8); }}
        .node-item .detail-btn {{ background:none; border:none; font-size:1.2em; cursor:pointer; padding:0 5px; color:#667eea; transition:color 0.3s; }}
        .node-item.active .detail-btn {{ color:white; }}
        .main-content {{ flex:1; padding:20px; display:flex; flex-direction:column; overflow:hidden; }}
        .toolbar {{ background:white; padding:15px; border-radius:10px; margin-bottom:20px; box-shadow:0 2px 10px rgba(0,0,0,0.1); display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
        .btn {{ padding:10px 20px; border:none; border-radius:8px; cursor:pointer; font-size:14px; font-weight:500; transition:all 0.3s; display:flex; align-items:center; gap:5px; white-space:nowrap; }}
        .btn-primary {{ background:linear-gradient(135deg,#667eea 0%,#764ba2 100%); color:white; }}
        .btn-primary:hover {{ transform:translateY(-2px); box-shadow:0 5px 15px rgba(102,126,234,0.4); }}
        .btn-info {{ background:linear-gradient(135deg,#17a2b8,#138496); color:white; }}
        .btn-info:hover {{ transform:translateY(-2px); box-shadow:0 5px 15px rgba(23,162,184,0.4); }}
        .btn-secondary {{ background:#6c757d; color:white; }}
        .btn-secondary:hover {{ background:#5a6268; transform:translateY(-2px); }}
        .zoom-controls {{ display:flex; align-items:center; gap:5px; margin-left:auto; }}
        .zoom-level {{ font-size:14px; color:#6c757d; min-width:50px; text-align:center; font-weight:bold; }}
        .canvas-container {{ flex:1; background:white; border-radius:15px; box-shadow:0 5px 20px rgba(0,0,0,0.1); overflow:hidden; position:relative; cursor:grab; }}
        .canvas-container:active {{ cursor:grabbing; }}
        .canvas-container.dragging {{ cursor:grabbing; }}
        .mermaid-wrapper {{ transform-origin:0 0; padding:30px; position:absolute; top:0; left:0; }}
        .mermaid {{ display:inline-block; }}
        .info-panel {{ position:fixed; top:80px; right:20px; background:rgba(255,255,255,0.98); border-radius:10px; padding:20px; box-shadow:0 5px 20px rgba(0,0,0,0.3); max-width:380px; max-height:500px; overflow-y:auto; display:none; z-index:1000; backdrop-filter:blur(10px); }}
        .info-panel.show {{ display:block; animation:slideIn 0.3s ease; }}
        @keyframes slideIn {{ from {{ opacity:0; transform:translateX(20px); }} to {{ opacity:1; transform:translateX(0); }} }}
        .info-panel h3 {{ color:#333; margin-bottom:15px; border-bottom:2px solid #ffd700; padding-bottom:10px; }}
        .info-panel .close-btn {{ position:absolute; top:10px; right:15px; background:none; border:none; font-size:1.5em; cursor:pointer; color:#999; }}
        .info-panel .close-btn:hover {{ color:#333; }}
        .info-panel .connections {{ font-size:14px; }}
        .info-panel .connection-group {{ margin-bottom:15px; }}
        .info-panel .connection-title {{ font-weight:bold; margin-bottom:5px; }}
        .info-panel ul {{ list-style:none; padding-left:10px; }}
        .info-panel li {{ padding:3px 0; font-size:13px; }}
        .legend {{ padding:15px; background:#f8f9fa; border-radius:8px; margin-top:auto; }}
        .legend h3 {{ font-size:1em; margin-bottom:10px; color:#333; }}
        .legend-item {{ display:flex; align-items:center; margin:5px 0; font-size:0.85em; }}
        .legend-color {{ width:20px; height:20px; border-radius:4px; margin-right:10px; }}
        .statistics {{ margin:10px 0; padding:10px; background:#e9ecef; border-radius:8px; font-size:0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <h2>📦 模块列表</h2>
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="🔍 过滤模块..." onkeyup="filterNodes()">
            </div>
            <div class="switch-container">
                <span class="switch-label">🔗 显示关联</span>
                <div class="switch active" id="modeSwitch" onclick="toggleMode()">
                    <div class="slider"></div>
                </div>
                <span class="switch-label">📌 仅目标模块</span>
            </div>
            <div class="statistics">
                <div>📊 总模块数: <strong>{len(nodes_data)}</strong></div>
                <div>🔗 总连接数: <strong>{len(edges_data)}</strong></div>
            </div>
            <div class="node-list" id="nodeList"></div>
            <div class="legend">
                <h3>📖 图例</h3>
                <div class="legend-item"><div class="legend-color" style="background:#ffd700;border:2px solid #ff8c00;"></div><span>选中模块（金色）</span></div>
                <div class="legend-item"><div class="legend-color" style="background:#4caf50;"></div><span>输入模块（绿色）</span></div>
                <div class="legend-item"><div class="legend-color" style="background:#f44336;"></div><span>输出模块（红色）</span></div>
                <div class="legend-item"><div class="legend-color" style="background:#9c27b0;"></div><span>双向模块（紫色）</span></div>
            </div>
        </div>
        <div class="main-content">
            <div class="toolbar">
                <button class="btn btn-primary" onclick="resetHighlight()">🔄 重置视图</button>
                <button class="btn btn-info" onclick="exportToPNG()">🖼️ 导出图片</button>
                <button class="btn btn-info" onclick="exportToSVG()">📐 导出SVG</button>
                <button class="btn btn-secondary" onclick="toggleFullscreen()">🖥️ 全屏</button>
                <div class="zoom-controls">
                    <button class="btn btn-secondary" onclick="zoomOut()">➖</button>
                    <span class="zoom-level" id="zoomLevel">100%</span>
                    <button class="btn btn-secondary" onclick="zoomIn()">➕</button>
                    <button class="btn btn-secondary" onclick="zoomReset()">🔄</button>
                    <button class="btn btn-secondary" onclick="zoomFit()">📐</button>
                </div>
            </div>
            <div class="canvas-container" id="canvasContainer">
                <div class="mermaid-wrapper" id="mermaidWrapper">
                    <div class="mermaid" id="mermaidDiagram">
{mermaid_content}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="info-panel" id="infoPanel">
        <button class="close-btn" onclick="hideInfoPanel()">&times;</button>
        <h3 id="infoTitle"></h3>
        <div class="connections" id="infoConnections"></div>
    </div>

    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11.15.0/dist/mermaid.esm.min.mjs';
        import elkLayouts from 'https://cdn.jsdelivr.net/npm/@mermaid-js/layout-elk@0.1.7/dist/mermaid-layout-elk.esm.min.mjs';
        mermaid.registerLayoutLoaders(elkLayouts);
        window.mermaid = mermaid;

        mermaid.initialize({{
            startOnLoad: false,
            theme: 'default',
            securityLevel: 'loose',
            flowchart: {{ useMaxWidth: false, htmlLabels: true, curve: 'basis', defaultRenderer: 'elk' }}
        }});

        const diagramDiv = document.getElementById('mermaidDiagram');
        mermaid.run({{ nodes: [diagramDiv] }}).then(() => {{
            console.log('Mermaid 渲染完成');
            onMermaidReady();
        }});

        const nodesData = {nodes_json};
        const edgesData = {edges_json};
        const targetModules = {target_modules_json};
        let selectedNode = null;
        let currentZoom = 1;
        let isDragging = false;
        let startX = 0, startY = 0;
        let translateX = 0, translateY = 0;
        const ZOOM_STEP = 0.2, MIN_ZOOM = 0.2, MAX_ZOOM = 5;
        let showOnlyTarget = true;  // true: 仅目标模块, false: 显示关联模块

        function generateNodeList() {{
            const nl = document.getElementById('nodeList');
            nl.innerHTML = '';
            Object.values(nodesData).sort((a,b)=>a.label.localeCompare(b.label)).forEach(node => {{
                const div = document.createElement('div');
                div.className = 'node-item';
                div.id = `node-item-${{node.id}}`;
                div.innerHTML = `
                    <div class="info" onclick="highlightNode('${{node.id}}')">
                        <strong>${{node.label}}</strong>
                        <div class="stats">输入: ${{node.inputs.length}} | 输出: ${{node.outputs.length}}</div>
                    </div>
                    <button class="detail-btn" onclick="showNodeDetail(event, '${{node.id}}')" title="查看详情">ℹ️</button>
                `;
                nl.appendChild(div);
            }});
            
            // 应用当前模式
            applyMode(showOnlyTarget);
        }}

        function applyMode(onlyTarget) {{
            const nodeItems = document.querySelectorAll('.node-item');
            const searchInput = document.getElementById('searchInput');
            const searchText = searchInput ? searchInput.value.toLowerCase() : '';
            
            if (onlyTarget && targetModules && targetModules.length > 0) {{
                // 仅显示目标模块
                nodeItems.forEach(item => {{
                    const label = item.querySelector('strong').textContent;
                    const shouldShow = targetModules.includes(label);
                    item.style.display = shouldShow ? 'flex' : 'none';
                }});
            }} else {{
                // 显示所有模块
                nodeItems.forEach(item => {{
                    item.style.display = 'flex';
                }});
                // 如果有搜索文本，应用搜索过滤
                if (searchText) {{
                    nodeItems.forEach(item => {{
                        const text = item.textContent.toLowerCase();
                        item.style.display = text.includes(searchText) ? 'flex' : 'none';
                    }});
                }}
            }}
        }}

        function updateTransform() {{
            const w = document.getElementById('mermaidWrapper');
            if (w) w.style.transform = `translate(${{translateX}}px, ${{translateY}}px) scale(${{currentZoom}})`;
        }}

        function setZoom(zoom, cx, cy) {{
            const old = currentZoom;
            currentZoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, zoom));
            if (cx !== undefined && cy !== undefined) {{
                const s = currentZoom / old;
                translateX = cx - s * (cx - translateX);
                translateY = cy - s * (cy - translateY);
            }}
            updateTransform();
            document.getElementById('zoomLevel').textContent = Math.round(currentZoom*100)+'%';
        }}

        window.zoomIn = () => {{ const c = document.getElementById('canvasContainer'); const r = c.getBoundingClientRect(); setZoom(currentZoom+ZOOM_STEP, r.width/2, r.height/2); }};
        window.zoomOut = () => {{ const c = document.getElementById('canvasContainer'); const r = c.getBoundingClientRect(); setZoom(currentZoom-ZOOM_STEP, r.width/2, r.height/2); }};
        window.zoomReset = () => {{ translateX=0; translateY=0; setZoom(1); }};
        window.zoomFit = () => {{
            const c = document.getElementById('canvasContainer');
            const w = document.getElementById('mermaidWrapper');
            if (!c || !w) return;
            const cw = c.clientWidth-40, ch = c.clientHeight-40;
            const sw = w.scrollWidth, sh = w.scrollHeight;
            const s = Math.min(cw/sw, ch/sh, 1);
            translateX = (cw - sw*s)/2;
            translateY = (ch - sh*s)/2;
            setZoom(s);
        }};

        function initWheelZoom() {{
            document.getElementById('canvasContainer').addEventListener('wheel', e => {{
                e.preventDefault();
                const r = e.currentTarget.getBoundingClientRect();
                const mx = e.clientX - r.left, my = e.clientY - r.top;
                if (e.deltaY < 0) setZoom(currentZoom+ZOOM_STEP*0.5, mx, my);
                else setZoom(currentZoom-ZOOM_STEP*0.5, mx, my);
            }}, {{passive:false}});
        }}

        function initDrag() {{
            const c = document.getElementById('canvasContainer');
            c.addEventListener('mousedown', e => {{
                if (e.target.closest('.node') || e.target.closest('.edgeLabel')) return;
                isDragging = true;
                startX = e.clientX - translateX;
                startY = e.clientY - translateY;
                c.classList.add('dragging');
                e.preventDefault();
            }});
            document.addEventListener('mousemove', e => {{
                if (!isDragging) return;
                translateX = e.clientX - startX;
                translateY = e.clientY - startY;
                updateTransform();
            }});
            document.addEventListener('mouseup', () => {{ isDragging = false; c.classList.remove('dragging'); }});
            c.addEventListener('selectstart', e => {{ if (isDragging) e.preventDefault(); }});
        }}

        function annotateNodes() {{
            const svg = document.querySelector('.mermaid svg');
            if (!svg) return;
            const nodeGroups = svg.querySelectorAll('g.node');
            nodeGroups.forEach(g => {{
                let label = '';
                const textEl = g.querySelector('text');
                if (textEl) {{
                    label = textEl.textContent.trim();
                }} else {{
                    const fo = g.querySelector('foreignObject');
                    if (fo) {{
                        const div = fo.querySelector('div');
                        if (div) label = div.textContent.trim();
                    }}
                }}
                if (!label) return;
                for (const [id, data] of Object.entries(nodesData)) {{
                    if (data.label === label || id === label) {{
                        g.setAttribute('data-node-id', id);
                        break;
                    }}
                }}
            }});
        }}

        function applyHighlightCSS(nodeId) {{
            const svg = document.querySelector('.mermaid svg');
            if (!svg) return;

            const old = document.getElementById('highlight-style');
            if (old) old.remove();

            const relatedEdges = edgesData.filter(e => e.source === nodeId || e.target === nodeId);
            const relatedNodeIds = new Set([nodeId]);
            relatedEdges.forEach(e => {{ relatedNodeIds.add(e.source); relatedNodeIds.add(e.target); }});

            const incoming = new Set(relatedEdges.filter(e => e.target === nodeId).map(e => e.source));
            const outgoing = new Set(relatedEdges.filter(e => e.source === nodeId).map(e => e.target));

            let css = '';
            // 1. 选中节点本身：金色
            css += `g.node[data-node-id="${{nodeId}}"] rect, g.node[data-node-id="${{nodeId}}"] circle, g.node[data-node-id="${{nodeId}}"] polygon {{ fill: #ffd700 !important; stroke: #ff8c00 !important; stroke-width: 3px !important; }}`;
            css += `g.node[data-node-id="${{nodeId}}"] text {{ fill: #000 !important; font-weight: bold; }}`;

            // 2. 相关节点（排除自身）
            relatedNodeIds.forEach(id => {{
                if (id === nodeId) return;
                const isIn = incoming.has(id);
                const isOut = outgoing.has(id);
                let color = '', darkColor = '';
                if (isIn && isOut) {{
                    color = '#9c27b0';   // 紫色
                    darkColor = '#6a1b9a';
                }} else if (isIn) {{
                    color = '#4caf50';   // 绿色
                    darkColor = '#2e7d32';
                }} else if (isOut) {{
                    color = '#f44336';   // 红色
                    darkColor = '#c62828';
                }}
                if (color) {{
                    css += `g.node[data-node-id="${{id}}"] rect, g.node[data-node-id="${{id}}"] circle, g.node[data-node-id="${{id}}"] polygon {{ fill: ${{color}} !important; stroke: ${{darkColor}} !important; stroke-width: 2px !important; }}`;
                    css += `g.node[data-node-id="${{id}}"] text {{ fill: #fff !important; font-weight: bold; }}`;
                }}
            }});

            const styleEl = document.createElementNS('http://www.w3.org/2000/svg', 'style');
            styleEl.id = 'highlight-style';
            styleEl.textContent = css;
            svg.appendChild(styleEl);
        }}

        window.highlightNode = function(nodeId) {{
            if (selectedNode === nodeId) return;
            if (selectedNode) resetHighlight();
            selectedNode = nodeId;
            const node = nodesData[nodeId];
            if (!node) return;

            document.querySelectorAll('.node-item').forEach(i => i.classList.remove('active'));
            const item = document.getElementById(`node-item-${{nodeId}}`);
            if (item) item.classList.add('active');

            applyHighlightCSS(nodeId);
        }};

        window.showNodeDetail = function(event, nodeId) {{
            event.stopPropagation();
            const node = nodesData[nodeId];
            if (!node) return;

            const relatedEdges = edgesData.filter(e => e.source === nodeId || e.target === nodeId);
            const panel = document.getElementById('infoPanel');
            document.getElementById('infoTitle').textContent = `📋 ${{node.label}}`;
            let h = '<div class="connection-group">';
            h += '<div class="connection-title" style="color:#4caf50;">📥 输入连接</div>';
            const ins = relatedEdges.filter(e => e.target === node.id);
            if (ins.length) {{
                h += '<ul>';
                ins.forEach(e => h += `<li><strong>${{nodesData[e.source]?.label || e.source}}</strong> → ${{e.label}}</li>`);
                h += '</ul>';
            }} else h += '<p style="color:#999;font-size:12px;">无输入连接</p>';
            h += '<div class="connection-title" style="color:#ff9800;margin-top:10px;">📤 输出连接</div>';
            const outs = relatedEdges.filter(e => e.source === node.id);
            if (outs.length) {{
                h += '<ul>';
                outs.forEach(e => h += `<li>${{e.label}} → <strong>${{nodesData[e.target]?.label || e.target}}</strong></li>`);
                h += '</ul>';
            }} else h += '<p style="color:#999;font-size:12px;">无输出连接</p>';
            h += '</div>';
            document.getElementById('infoConnections').innerHTML = h;
            panel.classList.add('show');
        }};

        window.hideInfoPanel = function() {{
            document.getElementById('infoPanel').classList.remove('show');
        }};

        window.resetHighlight = function() {{
            selectedNode = null;
            document.querySelectorAll('.node-item').forEach(i => i.classList.remove('active'));
            const svg = document.querySelector('.mermaid svg');
            if (svg) {{
                const style = svg.getElementById('highlight-style');
                if (style) style.remove();
            }}
            document.getElementById('infoPanel').classList.remove('show');
            document.getElementById('searchInput').value = '';
            // 重置搜索后重新应用模式
            applyMode(showOnlyTarget);
        }};

        window.filterNodes = function() {{
            const s = document.getElementById('searchInput').value.toLowerCase();
            const nodeItems = document.querySelectorAll('.node-item');
            
            // 先应用模式过滤，再应用搜索过滤
            nodeItems.forEach(item => {{
                const label = item.querySelector('strong').textContent;
                let shouldShow = true;
                
                // 如果是"仅目标模块"模式，先检查是否为目标模块
                if (showOnlyTarget && targetModules && targetModules.length > 0) {{
                    if (!targetModules.includes(label)) {{
                        shouldShow = false;
                    }}
                }}
                
                // 如果通过了模式过滤，再检查搜索文本
                if (shouldShow && s) {{
                    const text = item.textContent.toLowerCase();
                    shouldShow = text.includes(s);
                }}
                
                item.style.display = shouldShow ? 'flex' : 'none';
            }});
        }};

        // ===== 模式切换功能 =====
        window.toggleMode = function() {{
            const switchEl = document.getElementById('modeSwitch');
            showOnlyTarget = !showOnlyTarget;
            switchEl.classList.toggle('active');
            
            console.log('切换模式:', showOnlyTarget ? '仅目标模块' : '显示关联');
            console.log('目标模块列表:', targetModules);
            
            // 清空搜索框
            document.getElementById('searchInput').value = '';
            
            // 应用模式
            applyMode(showOnlyTarget);
            
            // 重置高亮
            window.resetHighlight();
            setTimeout(window.zoomFit, 100);
        }};
        // =========================

        document.addEventListener('keydown', e => {{
            if (e.key === 'Escape') {{
                if (document.getElementById('infoPanel').classList.contains('show')) {{
                    hideInfoPanel();
                }} else {{
                    window.resetHighlight();
                }}
            }}
        }});

        window.exportToPNG = function() {{
            const svgEl = document.querySelector('.mermaid svg');
            if (!svgEl) {{ alert('图表未加载'); return; }}
            const hadSel = selectedNode !== null;
            if (hadSel) resetHighlight();
            setTimeout(() => {{
                const clone = svgEl.cloneNode(true);
                const bbox = svgEl.getBBox();
                clone.setAttribute('width', bbox.width*2);
                clone.setAttribute('height', bbox.height*2);
                const canvas = document.createElement('canvas');
                canvas.width = bbox.width*2;
                canvas.height = bbox.height*2;
                const ctx = canvas.getContext('2d');
                ctx.fillStyle = 'white';
                ctx.fillRect(0,0,canvas.width,canvas.height);
                const img = new Image();
                img.onload = () => {{
                    ctx.drawImage(img,0,0,canvas.width,canvas.height);
                    const a = document.createElement('a');
                    a.download = 'rte_architecture.png';
                    a.href = canvas.toDataURL('image/png');
                    a.click();
                    if (hadSel && selectedNode) highlightNode(selectedNode);
                }};
                const svgData = new XMLSerializer().serializeToString(clone);
                img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
            }}, 200);
        }};

        window.exportToSVG = function() {{
            const svgEl = document.querySelector('.mermaid svg');
            if (!svgEl) {{ alert('图表未加载'); return; }}
            const clone = svgEl.cloneNode(true);
            const style = clone.getElementById('highlight-style');
            if (style) style.remove();
            const svgData = new XMLSerializer().serializeToString(clone);
            const blob = new Blob([svgData], {{type: 'image/svg+xml'}});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'rte_architecture.svg';
            a.click();
            URL.revokeObjectURL(url);
        }};

        window.toggleFullscreen = function() {{
            const c = document.querySelector('.canvas-container');
            if (!document.fullscreenElement) c.requestFullscreen();
            else document.exitFullscreen();
        }};

        function onMermaidReady() {{
            console.log('Mermaid渲染完成，开始初始化...');
            console.log('目标模块:', targetModules);
            generateNodeList();
            initDrag();
            initWheelZoom();
            
            setTimeout(() => {{
                annotateNodes();
                window.zoomFit();
            }}, 100);
        }}

        window.addEventListener('resize', () => {{ if (currentZoom===1 && translateX===0 && translateY===0) window.zoomFit(); }});
    </script>
</body>
</html>'''

        html_out = self.puml_out.replace(".puml", "_interactive.html")
        with open(html_out, 'w', encoding='utf-8') as f:
            f.write(html)
        return html_out


# ===================== 【配置管理类】 =====================
class ConfigManager:
    CONFIG_FILE = "rte_analyzer_config.ini"
    
    @classmethod
    def save_config(cls, config_data):
        config = configparser.ConfigParser()
        config['Settings'] = {
            'src_root': config_data.get('src_root', ''),
            'puml_out': config_data.get('puml_out', './rte_architecture.puml'),
            'target_modules': ','.join(config_data.get('target_modules', [])),
            'display_mode': config_data.get('display_mode', 'related'),
            'merge_multi_signal': str(config_data.get('merge_multi_signal', True)),
            'only_alphabet_module': str(config_data.get('only_alphabet_module', True))
        }
        with open(cls.CONFIG_FILE, 'w', encoding='utf-8') as f:
            config.write(f)
    
    @classmethod
    def load_config(cls):
        config = configparser.ConfigParser()
        if not os.path.exists(cls.CONFIG_FILE):
            return None
        try:
            config.read(cls.CONFIG_FILE, encoding='utf-8')
            if 'Settings' not in config:
                return None
            settings = config['Settings']
            return {
                'src_root': settings.get('src_root', ''),
                'puml_out': settings.get('puml_out', './rte_architecture.puml'),
                'target_modules': [m.strip() for m in settings.get('target_modules', '').split(',') if m.strip()],
                'display_mode': settings.get('display_mode', 'related'),
                'merge_multi_signal': settings.getboolean('merge_multi_signal', True),
                'only_alphabet_module': settings.getboolean('only_alphabet_module', True)
            }
        except Exception:
            return None


# ===================== 【GUI主窗口】 =====================
class RTEAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AUTOSAR 组件架构分析工具")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        self.analyzer = RTEAnalyzer()
        self.loaded_config = ConfigManager.load_config()
        
        self.create_widgets()
        if self.loaded_config:
            self.apply_config_to_ui(self.loaded_config)
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_label = ttk.Label(main_frame, text="AUTOSAR 组件架构分析工具", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 15))
        
        config_frame = ttk.LabelFrame(main_frame, text="⚙️ 配置参数", padding="10")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        row1 = ttk.Frame(config_frame)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="📁 输入文件:", width=15).pack(side=tk.LEFT)
        self.src_root_var = tk.StringVar()
        self.src_entry = ttk.Entry(row1, textvariable=self.src_root_var)
        self.src_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(row1, text="浏览...", command=self.browse_src_folder).pack(side=tk.RIGHT)
        
        row2 = ttk.Frame(config_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="📄 输出文件:", width=15).pack(side=tk.LEFT)
        self.puml_out_var = tk.StringVar()
        self.puml_entry = ttk.Entry(row2, textvariable=self.puml_out_var)
        self.puml_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(row2, text="浏览...", command=self.browse_output_file).pack(side=tk.RIGHT)
        
        row3 = ttk.Frame(config_frame)
        row3.pack(fill=tk.X, pady=2)
        ttk.Label(row3, text="🎯 目标模块:", width=15).pack(side=tk.LEFT)
        self.modules_var = tk.StringVar()
        self.modules_entry = ttk.Entry(row3, textvariable=self.modules_var)
        self.modules_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(row3, text="📂 导入", command=self.import_module_list).pack(side=tk.RIGHT)
        
        hint_label = ttk.Label(config_frame, text="💡 目标模块用英文逗号(,)分隔", foreground="gray", font=("Arial", 8))
        hint_label.pack(anchor=tk.W, pady=(2, 0))
        
        checkbox_frame = ttk.Frame(config_frame)
        checkbox_frame.pack(fill=tk.X, pady=(5, 0))
        
        # 显示模式选择
        mode_frame = ttk.Frame(checkbox_frame)
        mode_frame.pack(anchor=tk.W, pady=(0, 5))
        ttk.Label(mode_frame, text="📊 显示模式:").pack(side=tk.LEFT, padx=(0, 10))
        
        self.display_mode_var = tk.StringVar(value="related")
        ttk.Radiobutton(mode_frame, text="所有模块", variable=self.display_mode_var, 
                       value="all").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(mode_frame, text="仅目标模块", variable=self.display_mode_var, 
                       value="only").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(mode_frame, text="目标+关联模块", variable=self.display_mode_var, 
                       value="related").pack(side=tk.LEFT)
        
        self.merge_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(checkbox_frame, text="合并多信号", variable=self.merge_var).pack(side=tk.LEFT, padx=(0, 15))
        
        self.alphabet_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(checkbox_frame, text="仅分析纯字母模块的文件", variable=self.alphabet_var).pack(side=tk.LEFT)
        
        status_frame = ttk.LabelFrame(main_frame, text="📊 状态", padding="10")
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        progress_bar_frame = ttk.Frame(status_frame)
        progress_bar_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(progress_bar_frame, text="进度:").pack(side=tk.LEFT)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_bar_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        self.progress_label = ttk.Label(progress_bar_frame, text="0%")
        self.progress_label.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.status_label = ttk.Label(status_frame, text="就绪", foreground="gray")
        self.status_label.pack(anchor=tk.W)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(button_frame, text="🚀 开始分析", command=self.start_analysis, style="Accent.TButton").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="💾 保存配置", command=self.save_config).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="📂 打开结果文件夹", command=self.open_output_folder).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="🌐 打开HTML", command=self.open_html).pack(side=tk.LEFT)
        
        log_frame = ttk.LabelFrame(main_frame, text="📋 日志", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(log_frame, height=12, wrap=tk.WORD, font=("Consolas", 9))
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        style = ttk.Style()
        style.configure("Accent.TButton", font=("Arial", 10, "bold"))
    
    def browse_src_folder(self):
        folder = filedialog.askdirectory(title="选择组件文件夹（包含Rte_*.h文件）")
        if folder:
            self.src_root_var.set(folder)
            self.log(f"已选择文件夹: {folder}")
    
    def browse_output_file(self):
        file_path = filedialog.asksaveasfilename(
            title="保存为",
            defaultextension=".puml",
            filetypes=[("PlantUML文件", "*.puml"), ("所有文件", "*.*")]
        )
        if file_path:
            self.puml_out_var.set(file_path)
            self.log(f"输出文件: {file_path}")
    
    def import_module_list(self):
        file_path = filedialog.askopenfilename(
            title="导入模块列表",
            filetypes=[("文本文件", "*.txt"), ("CSV文件", "*.csv"), ("所有文件", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                modules = re.split(r'[,\s\n]+', content)
                modules = [m.strip() for m in modules if m.strip()]
                self.modules_var.set(', '.join(modules))
                self.log(f"已导入 {len(modules)} 个模块: {', '.join(modules[:5])}{'...' if len(modules) > 5 else ''}")
            except Exception as e:
                messagebox.showerror("错误", f"导入失败: {str(e)}")
    
    def apply_config_to_ui(self, config):
        if config.get('src_root'):
            self.src_root_var.set(config['src_root'])
        if config.get('puml_out'):
            self.puml_out_var.set(config['puml_out'])
        if config.get('target_modules'):
            self.modules_var.set(', '.join(config['target_modules']))
        if 'display_mode' in config:
            self.display_mode_var.set(config['display_mode'])
        if 'merge_multi_signal' in config:
            self.merge_var.set(config['merge_multi_signal'])
        if 'only_alphabet_module' in config:
            self.alphabet_var.set(config['only_alphabet_module'])
        self.log("已加载上次的配置")
    
    def get_config_from_ui(self):
        modules_text = self.modules_var.get().strip()
        modules_text = modules_text.replace('，', ',')
        target_modules = [m.strip() for m in modules_text.split(',') if m.strip()]
        return {
            'src_root': self.src_root_var.get().strip(),
            'puml_out': self.puml_out_var.get().strip() or './rte_architecture.puml',
            'target_modules': target_modules,
            'display_mode': self.display_mode_var.get(),
            'merge_multi_signal': self.merge_var.get(),
            'only_alphabet_module': self.alphabet_var.get()
        }
    
    def save_config(self):
        config = self.get_config_from_ui()
        if not config['src_root']:
            messagebox.showwarning("警告", "请先选择组件文件夹")
            return
        ConfigManager.save_config(config)
        self.log("✅ 配置已保存")
        messagebox.showinfo("成功", "配置已保存!")
    
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_progress(self, current, total):
        if total > 0:
            progress = (current / total) * 100
            self.progress_var.set(progress)
            self.progress_label.config(text=f"{int(progress)}%")
        self.root.update_idletasks()
    
    def start_analysis(self):
        config = self.get_config_from_ui()
        
        if not config['src_root']:
            messagebox.showwarning("警告", "请先选择组件文件夹")
            return
        if not os.path.exists(config['src_root']):
            messagebox.showerror("错误", "组件文件夹不存在!")
            return
        
        self.analyzer.src_root = config['src_root']
        self.analyzer.puml_out = config['puml_out']
        self.analyzer.target_modules = config['target_modules']
        self.analyzer.display_mode = config['display_mode']
        self.analyzer.merge_multi_signal = config['merge_multi_signal']
        self.analyzer.only_alphabet_module = config['only_alphabet_module']
        
        self.log("=" * 50)
        self.log(f"📁 组件目录: {config['src_root']}")
        self.log(f"📄 输出文件: {config['puml_out']}")
        self.log(f"🎯 目标模块: {len(config['target_modules'])} 个")
        
        mode_names = {
            "all": "显示所有模块",
            "only": "仅显示目标模块",
            "related": "显示目标模块及关联模块"
        }
        self.log(f"📊 显示模式: {mode_names.get(config['display_mode'], '目标+关联模块')}")
        self.log("-" * 50)
        self.log("开始扫描...")
        
        self.root.config(cursor="watch")
        
        try:
            parse_cnt, skip_type, skip_alpha = self.analyzer.traverse_dir(
                config['src_root'],
                self.update_progress
            )
            self.log(f"📊 扫描完成: 解析 {parse_cnt} 个文件, 跳过Type {skip_type}, 非字母 {skip_alpha}")
            
            # 构建边集
            self.analyzer.build_edges()
            edge_count = len(self.analyzer.edge_signals)
            self.log(f"🔗 生成 {edge_count} 条连接")
            
            # 检查连线数量限制
            if edge_count > 1000:
                self.log("⚠️ 连线数量超过 1000 条，停止生成结果")
                messagebox.showwarning("连线数量超限", 
                    f"检测到 {edge_count} 条连线，超过 1000 条限制。\n"
                    "请使用目标模块过滤或缩小分析范围。")
                self.status_label.config(text="连线过多，未生成", foreground="orange")
                return
            
            if edge_count == 0:
                self.log("⚠️ 未发现任何信号连接，请检查配置!")
                self.root.config(cursor="")
                return
            
            # 生成Mermaid
            self.log("生成Mermaid图表...")
            mmd_file, node_count, _, signal_count = self.analyzer.generate_mermaid()
            self.log(f"✅ Mermaid已生成: {mmd_file}")
            self.log(f"📊 组件: {node_count} | 连线: {edge_count} | 信号: {signal_count}")
            
            # 生成HTML
            self.log("生成交互式HTML...")
            html_file = self.analyzer.generate_interactive_html(mmd_file)
            self.log(f"✅ HTML已生成: {html_file}")
            
            self.log("🎉 分析完成!")
            self.status_label.config(text=f"完成: {node_count} 个组件, {edge_count} 条连接", foreground="green")
            
            messagebox.showinfo("完成", 
                f"分析完成!\n\n"
                f"📊 组件: {node_count}\n"
                f"🔗 连接: {edge_count}\n"
                f"📡 信号: {signal_count}\n\n"
                f"结果文件已保存。")
            
            ConfigManager.save_config(config)
            
        except Exception as e:
            self.log(f"❌ 错误: {str(e)}")
            import traceback
            self.log(traceback.format_exc())
            messagebox.showerror("错误", f"分析失败:\n{str(e)}")
            self.status_label.config(text="错误", foreground="red")
        finally:
            self.root.config(cursor="")
            self.progress_var.set(0)
            self.progress_label.config(text="0%")
    
    def open_output_folder(self):
        config = self.get_config_from_ui()
        output_path = config['puml_out']
        if output_path:
            folder = os.path.dirname(output_path)
            if folder and os.path.exists(folder):
                os.startfile(folder)
            else:
                messagebox.showwarning("警告", "输出文件路径无效")
        else:
            messagebox.showwarning("警告", "请先设置输出文件路径")
    
    def open_html(self):
        config = self.get_config_from_ui()
        html_file = config['puml_out'].replace(".puml", "_interactive.html")
        if os.path.exists(html_file):
            os.startfile(html_file)
        else:
            messagebox.showwarning("警告", f"HTML文件不存在:\n{html_file}\n请先运行分析")


# ===================== 【主入口】 =====================
if __name__ == "__main__":
    root = tk.Tk()
    app = RTEAnalyzerGUI(root)
    
    if app.loaded_config and app.loaded_config.get('src_root'):
        app.log(f"📂 已加载配置，组件目录: {app.loaded_config.get('src_root')}")
    
    root.mainloop()