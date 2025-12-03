# core/report_generator.py
import html
import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any


class ReportGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
        os.makedirs(output_dir, exist_ok=True)

    def _get_timestamp(self) -> str:
        """获取当前时间戳"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_html_logs(self, log_entries: List[Any], output_path: str, raw_log_entries: List[Dict[str, Any]] = None) -> str:
        """生成HTML格式的日志报告 - 已拆分为分析页和原文页"""
        try:
            # 准备路径信息
            output_dir = os.path.dirname(output_path)
            os.makedirs(output_dir, exist_ok=True)
            
            filename = os.path.basename(output_path)
            name_without_ext = os.path.splitext(filename)[0]
            raw_filename = f"{name_without_ext}_raw.html"
            raw_output_path = os.path.join(output_dir, raw_filename)

            if raw_log_entries is None:
                raw_log_entries = log_entries

            self.logger.info(f"生成HTML报告，主文件: {output_path}，原文文件: {raw_output_path}，日志条目数: {len(log_entries)}")

            # 收集所有出现的报文类型 (逻辑保持不变)
            all_msg_types = set()
            for entry in raw_log_entries:
                for seg in entry.get('segments', []):
                    if seg.get('kind') == 'msg_type':
                        mt = seg.get('text', '').strip()
                        if mt:
                            all_msg_types.add(mt)
            sorted_msg_types = sorted(list(all_msg_types))

            entry_id_map = {id(entry): i for i, entry in enumerate(raw_log_entries)}

            abnormal_items = self._collect_abnormal_items(log_entries)
            abnormal_items_json = json.dumps(abnormal_items, ensure_ascii=False).replace('</', '<\\/')

            def get_raw_anchor(entry_obj):
                """辅助函数：根据对象找到原文页面的锚点ID"""
                if entry_obj is None: return ""
                raw_idx = entry_id_map.get(id(entry_obj))
                # 如果找到了索引，返回 log_123；如果没找到，默认返回空或由逻辑决定
                return f"log_{raw_idx}" if raw_idx is not None else ""



            # =================================================================
            # 1. 生成主分析页面 (Index Page)
            # =================================================================
            with open(output_path, 'w', encoding='utf-8') as f:
                # 写入HTML头部 (样式和JS完全保留原版，仅移除未使用的部分)
                f.write(f"""<!DOCTYPE html>
            <html>
            <head>
                <title>日志分析报告</title>
                <script>
                    (function() {
                        const ALL_MESSAGE_TYPES = {sorted_msg_types};
                        const ABNORMAL_ITEMS = {abnormal_items_json} || [];
                        let selectedMsgTypes = new Set();

                        function init() {
                            const input = document.getElementById('msgTypeInput');
                            const dropdown = document.getElementById('msgTypeDropdown');

                            if (input && dropdown) {
                                input.addEventListener('focus', () => {
                                    renderDropdown(input.value);
                                    dropdown.style.display = 'block';
                                });

                                input.addEventListener('input', (e) => {
                                    renderDropdown(e.target.value);
                                    dropdown.style.display = 'block';
                                });

                                document.addEventListener('click', (e) => {
                                    if (!e.target.closest('.msg-type-container')) {
                                        dropdown.style.display = 'none';
                                    }
                                });
                            }

                            renderTags();
                            applyFilter();
                            renderAbnormalNav();
                        }

                        function renderDropdown(filterText) {
                            const dropdown = document.getElementById('msgTypeDropdown');
                            if (!dropdown) return;
                            dropdown.innerHTML = '';

                            const lowerFilter = (filterText || '').toLowerCase();
                            const filtered = ALL_MESSAGE_TYPES.filter(mt =>
                                mt.toLowerCase().includes(lowerFilter) && !selectedMsgTypes.has(mt)
                            );

                            if (filtered.length === 0) {
                                const div = document.createElement('div');
                                div.className = 'msg-type-option';
                                div.style.color = '#9ca3af';
                                div.style.cursor = 'default';
                                div.textContent = '无匹配项';
                                dropdown.appendChild(div);
                                return;
                            }

                            filtered.forEach(mt => {
                                const div = document.createElement('div');
                                div.className = 'msg-type-option';
                                div.textContent = mt;
                                div.onclick = () => addMsgType(mt);
                                dropdown.appendChild(div);
                            });
                        }

                        function addMsgType(mt) {
                            selectedMsgTypes.add(mt);
                            renderTags();
                            const inputEl = document.getElementById('msgTypeInput');
                            const dropdown = document.getElementById('msgTypeDropdown');
                            if (inputEl) inputEl.value = '';
                            if (dropdown) dropdown.style.display = 'none';
                            applyFilter();
                        }

                        function removeMsgType(mt) {
                            selectedMsgTypes.delete(mt);
                            renderTags();
                            applyFilter();
                        }

                        function renderTags() {
                            const container = document.getElementById('selectedTags');
                            if (!container) return;
                            container.innerHTML = '';
                            selectedMsgTypes.forEach(mt => {
                                const tag = document.createElement('div');
                                tag.className = 'tag';
                                tag.innerHTML = `
                                ${mt}
                                <span class="tag-remove" onclick="removeMsgType('${mt}')">×</span>
                            `;
                                container.appendChild(tag);
                            });
                        }

                        function applyFilter() {
                            const qRaw = (document.getElementById('filterInput')?.value || '').trim();
                            const errBox = document.getElementById('filterError');
                            if (errBox) errBox.textContent = '';

                            let re = null;
                            if (qRaw) {
                                if (qRaw.startsWith('/') && qRaw.lastIndexOf('/') > 0) {
                                    const last = qRaw.lastIndexOf('/');
                                    const body = qRaw.slice(1, last);
                                    const flags = qRaw.slice(last + 1) || 'i';
                                    try { re = new RegExp(body, flags); } catch (e) { re = null; }
                                } else {
                                    try { re = new RegExp(qRaw, 'i'); } catch (e) { re = null; }
                                }
                                if (!re && errBox) errBox.textContent = '正则表达式无效';
                            }

                            const startTimeStr = (document.getElementById('startTime')?.value || '').trim();
                            const endTimeStr = (document.getElementById('endTime')?.value || '').trim();
                            const startTime = startTimeStr ? parseTime(startTimeStr) : null;
                            const endTime = endTimeStr ? parseTime(endTimeStr) : null;
                            const timeOnlyMode = (startTime !== null && startTime < 0) || (endTime !== null && endTime < 0);

                            const rows = document.querySelectorAll('.timestamp');
                            rows.forEach((r) => {
                                let show = true;

                                if (re) {
                                    const text = (r.textContent || '');
                                    if (!re.test(text)) show = false;
                                }

                                if (show && (startTime || endTime)) {
                                    const rowTimestamp = parseInt(r.getAttribute('data-timestamp') || '0', 10);
                                    if (rowTimestamp > 0) {
                                        if (timeOnlyMode) {
                                            const rowDate = new Date(rowTimestamp);
                                            const rowTimeOfDay = rowDate.getHours() * 3600000 +
                                                              rowDate.getMinutes() * 60000 +
                                                              rowDate.getSeconds() * 1000 +
                                                              rowDate.getMilliseconds();
                                            if (startTime && startTime < 0 && rowTimeOfDay < -startTime) show = false;
                                            if (endTime && endTime < 0 && rowTimeOfDay > -endTime) show = false;
                                        } else {
                                            if (startTime && startTime > 0 && rowTimestamp < startTime) show = false;
                                            if (endTime && endTime > 0 && rowTimestamp > endTime) show = false;
                                        }
                                    }
                                }

                                if (show && selectedMsgTypes.size > 0) {
                                    const mtSpan = r.querySelector('.seg-msgtype');
                                    if (!mtSpan) {
                                        show = false;
                                    } else {
                                        const mt = mtSpan.textContent.trim();
                                        if (!selectedMsgTypes.has(mt)) show = false;
                                    }
                                }

                                r.style.display = show ? '' : 'none';
                            });
                        }

                        function parseTime(str) {
                            if (!str || !str.trim()) return null;
                            let trimmed = str.trim();
                            trimmed = trimmed.replace('T', ' ');

                            const match1 = trimmed.match(/^(\\d{4})-(\\d{1,2})-(\\d{1,2})\\s+(\\d{1,2}):(\\d{1,2})(?::(\\d{1,2})(?:\\.(\\d{1,3}))?)?$/);
                            if (match1) {
                                const year = parseInt(match1[1], 10);
                                const month = parseInt(match1[2], 10);
                                const day = parseInt(match1[3], 10);
                                const hour = parseInt(match1[4], 10);
                                const minute = parseInt(match1[5], 10);
                                const second = match1[6] ? parseInt(match1[6], 10) : 0;
                                const ms = match1[7] ? parseInt(match1[7], 10) : 0;
                                return new Date(year, month - 1, day, hour, minute, second, ms).getTime();
                            }

                            const match2 = trimmed.match(/^(\\d{1,2})-(\\d{1,2})\\s+(\\d{1,2}):(\\d{1,2})(?::(\\d{1,2})(?:\\.(\\d{1,3}))?)?$/);
                            if (match2) {
                                const currentYear = new Date().getFullYear();
                                const month = parseInt(match2[1], 10);
                                const day = parseInt(match2[2], 10);
                                const hour = parseInt(match2[3], 10);
                                const minute = parseInt(match2[4], 10);
                                const second = match2[5] ? parseInt(match2[5], 10) : 0;
                                const ms = match2[6] ? parseInt(match2[6], 10) : 0;
                                return new Date(currentYear, month - 1, day, hour, minute, second, ms).getTime();
                            }

                            const match3 = trimmed.match(/^(\\d{1,2}):(\\d{1,2})(?::(\\d{1,2})(?:\\.(\\d{1,3}))?)?$/);
                            if (match3) {
                                const hour = parseInt(match3[1], 10);
                                const minute = parseInt(match3[2], 10);
                                const second = match3[3] ? parseInt(match3[3], 10) : 0;
                                const ms = match3[4] ? parseInt(match3[4], 10) : 0;
                                return -(hour * 3600000 + minute * 60000 + second * 1000 + ms);
                            }
                            return null;
                        }

                        function clearFilter() {
                            const filterInput = document.getElementById('filterInput');
                            const startEl = document.getElementById('startTime');
                            const endEl = document.getElementById('endTime');
                            if (filterInput) filterInput.value = '';
                            if (startEl) startEl.value = '';
                            if (endEl) endEl.value = '';
                            selectedMsgTypes.clear();
                            renderTags();
                            applyFilter();
                        }

                        function filterKey(e) { if (e.key === 'Enter') applyFilter(); }

                        function highlightTransaction(groupId) {
                            if (!groupId) return;
                            const elements = document.querySelectorAll(`[data-trans-group="${groupId}"]`);
                            elements.forEach(el => el.classList.add('trans-highlight'));
                        }

                        function clearHighlight() {
                            const elements = document.querySelectorAll('.trans-highlight');
                            elements.forEach(el => el.classList.remove('trans-highlight'));
                        }

                        function focusAbnormalAnchor(anchor) {
                            if (!anchor) return;
                            const target = document.getElementById(anchor);
                            if (!target) return;
                            document.querySelectorAll('.flash-highlight').forEach(el => el.classList.remove('flash-highlight'));
                            target.classList.add('flash-highlight');
                            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        }

                        function toggleAbnormalNav() {
                            document.body.classList.toggle('nav-open');
                        }

                        function closeAbnormalNav() {
                            document.body.classList.remove('nav-open');
                        }

                        function renderAbnormalNav() {
                            const list = document.getElementById('abnormalList');
                            const empty = document.getElementById('abnormalEmpty');
                            const badge = document.getElementById('abnormalCount');
                            if (badge) badge.textContent = ABNORMAL_ITEMS.length;
                            if (!list) return;
                            list.innerHTML = '';
                            if (!ABNORMAL_ITEMS.length) {
                                if (empty) empty.style.display = 'block';
                                return;
                            }
                            if (empty) empty.style.display = 'none';

                            ABNORMAL_ITEMS.forEach((item) => {
                                const div = document.createElement('div');
                                div.className = 'abnormal-item';
                                const fieldsText = (item.fields || []).join('、') || '未记录字段';
                                div.innerHTML = `
                                <div class="abnormal-item__top">
                                    <span class="abnormal-time">${item.time || ''}</span>
                                    <span class="abnormal-count">×${item.count || 0}</span>
                                </div>
                                <div class="abnormal-item__meta">
                                    <span class="abnormal-type">${item.msgType || '未知报文'}</span>
                                    <span class="abnormal-fields">${fieldsText}</span>
                                </div>
                            `;
                                div.title = (item.details || []).join('\n');
                                div.onclick = () => {
                                    focusAbnormalAnchor(item.anchor);
                                    closeAbnormalNav();
                                };
                                list.appendChild(div);
                            });
                        }

                        window.applyFilter = applyFilter;
                        window.clearFilter = clearFilter;
                        window.filterKey = filterKey;
                        window.addMsgType = addMsgType;
                        window.removeMsgType = removeMsgType;
                        window.toggleAbnormalNav = toggleAbnormalNav;
                        window.closeAbnormalNav = closeAbnormalNav;
                        window.focusAbnormalAnchor = focusAbnormalAnchor;

                        if (document.readyState === 'loading') {
                            window.addEventListener('DOMContentLoaded', init, { once: true });
                        } else {
                            init();
                        }
                    })();
                </script>
                <style>
                    body {{
                        font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                        margin: 20px;
                        background-color: #f0f2f5;
                        color: #1f2937;
                    }}
                    .timestamp {{
                        display: flex;
                        align-items: center;
                        padding: 8px 12px;
                        margin: 4px 0;
                        background-color: #ffffff;
                        border-radius: 8px;
                        cursor: text;
                        font-size: 14px;
                        scroll-margin-top: 140px;
                        transition: all 0.2s;
                        border: 1px solid transparent;
                        flex-wrap: wrap;
                        gap: 4px 8px;
                    }}
                    .timestamp:hover {{
                        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                        border-color: #e5e7eb;
                    }}
                    /* 原有的所有 segment 样式 */
                    .seg-fixed {{ display: inline-block; box-sizing: border-box; padding: 2px 8px; margin: 0 2px; border-radius: 6px; vertical-align: middle; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 13px; white-space: nowrap; }}
                    .seg-ts {{ width: 170px; font-weight: 500; }}
                    .seg-dir {{ width: 80px; text-align: center; font-weight: 600; }}
                    .seg-node {{ width: 60px; text-align: center; }}
                    .seg-msgtype {{ width: 160px; text-align: center; font-weight: 600; letter-spacing: 0.5px; }}
                    .seg-ver {{ width: 60px; text-align: center; opacity: 0.8; }}
                    .seg-node-sm {{ width: 50px; text-align: center; }}
                    .seg-msgtype-sm {{ width: 120px; text-align: center; }}
                    .seg-ver-sm {{ width: 50px; text-align: center; }}
                    .seg-pid {{ width: 140px; text-align: center; }}
                    .seg-free {{ display: inline-block; padding: 2px 8px; margin: 0 2px; border-radius: 6px; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 13px; white-space: nowrap; }}
                    
                    /* 筛选栏和下拉框样式保持不变 */
                    #filterBar {{
                        position: sticky;
                        top: 10px;
                        background: rgba(255, 255, 255, 0.95);
                        backdrop-filter: blur(12px);
                        padding: 12px 20px;
                        margin-bottom: 24px;
                        border-radius: 16px;
                        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.01);
                        display: flex;
                        flex-wrap: wrap;
                        gap: 16px;
                        align-items: center;
                        z-index: 100;
                        border: 1px solid rgba(255, 255, 255, 0.6);
                    }}
                    
                    .filter-group {{
                        display: flex;
                        align-items: center;
                        gap: 10px;
                        background: #f9fafb;
                        padding: 6px 12px;
                        border-radius: 10px;
                        border: 1px solid #e5e7eb;
                        transition: all 0.2s;
                    }}
                    .filter-group:focus-within {{
                        background: #fff;
                        border-color: #bfdbfe;
                        box-shadow: 0 0 0 3px rgba(191, 219, 254, 0.3);
                    }}
                    
                    .filter-label {{
                        font-size: 12px;
                        color: #6b7280;
                        font-weight: 600;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                    }}
                    
                    .crystal-input {{
                        height: 32px;
                        padding: 0 8px;
                        border: none;
                        background: transparent;
                        font-size: 13px;
                        outline: none;
                        color: #1f2937;
                        font-family: inherit;
                    }}
                    .crystal-input::placeholder {{ color: #9ca3af; }}
                    
                    .msg-type-container {{ position: relative; min-width: 240px; }}
                    
                    .msg-type-dropdown {{
                        position: absolute;
                        top: calc(100% + 8px);
                        left: 0;
                        width: 300px;
                        background: rgba(255, 255, 255, 0.98);
                        backdrop-filter: blur(16px);
                        border: 1px solid #e5e7eb;
                        border-radius: 12px;
                        max-height: 320px;
                        overflow-y: auto;
                        display: none;
                        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
                        z-index: 50;
                        padding: 6px;
                    }}
                    
                    .msg-type-option {{
                        padding: 8px 12px;
                        cursor: pointer;
                        font-size: 13px;
                        color: #374151;
                        border-radius: 6px;
                        transition: all 0.15s;
                    }}
                    
                    .msg-type-option:hover {{ background: #eff6ff; color: #1d4ed8; }}
                    
                    .selected-tags {{ display: flex; flex-wrap: wrap; gap: 6px; max-width: 400px; }}
                    
                    .tag {{
                        background: #eff6ff;
                        border: 1px solid #bfdbfe;
                        color: #1e40af;
                        padding: 2px 8px;
                        border-radius: 6px;
                        font-size: 12px;
                        font-weight: 500;
                        display: flex;
                        align-items: center;
                        gap: 6px;
                        transition: all 0.2s;
                    }}
                    .tag:hover {{ background: #dbeafe; }}

                    .tag-remove {{ cursor: pointer; font-size: 14px; opacity: 0.6; line-height: 1; }}
                    .tag-remove:hover {{ opacity: 1; color: #1e3a8a; }}

                    .tag-abnormal {{
                        background: #fef2f2;
                        border: 1px solid #fecdd3;
                        color: #b91c1c;
                    }}

                    .nav-toggle {{
                        position: fixed;
                        left: 10px;
                        top: 20px;
                        z-index: 160;
                        display: inline-flex;
                        align-items: center;
                        gap: 8px;
                        padding: 8px 12px;
                        border-radius: 12px;
                        border: 1px solid #e5e7eb;
                        background: #ffffff;
                        color: #111827;
                        box-shadow: 0 10px 25px -10px rgba(0,0,0,0.2);
                        cursor: pointer;
                        font-weight: 600;
                        transition: all 0.2s;
                    }}
                    .nav-toggle:hover {{
                        box-shadow: 0 20px 35px -10px rgba(0,0,0,0.25);
                        transform: translateY(-1px);
                    }}
                    .nav-badge {{
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        min-width: 22px;
                        height: 22px;
                        padding: 0 6px;
                        border-radius: 999px;
                        background: #fee2e2;
                        color: #991b1b;
                        font-size: 12px;
                        font-weight: 700;
                        border: 1px solid #fecdd3;
                    }}

                    .side-nav {{
                        position: fixed;
                        left: -360px;
                        top: 20px;
                        bottom: 20px;
                        width: 320px;
                        background: #ffffff;
                        border-radius: 16px;
                        box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);
                        border: 1px solid #e5e7eb;
                        padding: 16px;
                        z-index: 150;
                        overflow-y: auto;
                        transition: all 0.3s ease;
                    }}
                    body.nav-open .side-nav {{ left: 20px; }}
                    body.nav-open .nav-toggle {{ left: 350px; }}

                    body.nav-open #filterBar {{ margin-left: 340px; transition: margin-left 0.3s ease; }}
                    body.nav-open #timestamps {{ margin-left: 340px; transition: margin-left 0.3s ease; }}

                    .side-nav__header {{
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        gap: 8px;
                        margin-bottom: 12px;
                    }}
                    .side-nav__title {{
                        font-size: 16px;
                        font-weight: 700;
                        color: #111827;
                    }}
                    .side-nav__subtitle {{
                        font-size: 12px;
                        color: #6b7280;
                        margin-top: 2px;
                    }}
                    .nav-empty {{
                        padding: 12px;
                        border: 1px dashed #e5e7eb;
                        border-radius: 10px;
                        color: #6b7280;
                        background: #f9fafb;
                        font-size: 13px;
                    }}
                    .abnormal-item {{
                        border: 1px solid #e5e7eb;
                        border-radius: 12px;
                        padding: 10px 12px;
                        margin-bottom: 10px;
                        background: #fdf2f8;
                        cursor: pointer;
                        transition: all 0.2s;
                    }}
                    .abnormal-item:hover {{
                        border-color: #f472b6;
                        box-shadow: 0 4px 12px -6px rgba(244, 114, 182, 0.45);
                    }}
                    .abnormal-item__top {{
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        margin-bottom: 6px;
                        gap: 6px;
                    }}
                    .abnormal-time {{
                        font-size: 13px;
                        color: #4b5563;
                    }}
                    .abnormal-count {{
                        background: #fee2e2;
                        color: #991b1b;
                        border: 1px solid #fecdd3;
                        border-radius: 8px;
                        padding: 2px 8px;
                        font-size: 12px;
                        font-weight: 700;
                    }}
                    .abnormal-item__meta {{
                        display: flex;
                        flex-wrap: wrap;
                        gap: 6px;
                        align-items: center;
                        color: #111827;
                        font-weight: 600;
                    }}
                    .abnormal-type {{
                        background: #eef2ff;
                        color: #4338ca;
                        border: 1px solid #c7d2fe;
                        border-radius: 8px;
                        padding: 2px 8px;
                        font-size: 12px;
                    }}
                    .abnormal-fields {{
                        color: #6b7280;
                        font-size: 12px;
                    }}

                    .flash-highlight {{
                        animation: flash-animation 2.4s ease-out forwards;
                        position: relative;
                        border-color: #ef4444 !important;
                    }}
                    @keyframes flash-animation {{
                        0% {{ background-color: #fee2e2; box-shadow: 0 0 0 4px rgba(239, 68, 68, 0.35); }}
                        50% {{ background-color: #fff1f2; box-shadow: 0 0 0 2px rgba(239, 68, 68, 0.25); }}
                        100% {{ background-color: #ffffff; box-shadow: none; }}
                    }}

                    .btn {{ 
                        height: 36px; 
                        padding: 0 20px; 
                        border: 1px solid rgba(209, 213, 219, 0.8); 
                        border-radius: 8px; 
                        background: white; 
                        cursor: pointer; 
                        font-size: 13px; 
                        font-weight: 600; 
                        transition: all 0.2s;
                        color: #4b5563;
                        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
                    }}
                    .btn:hover {{ 
                        transform: translateY(-1px); 
                        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); 
                        color: #111827;
                    }}
                    
                    .btn-primary {{ 
                        background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); 
                        border: none; 
                        color: white; 
                        box-shadow: 0 4px 6px -1px rgba(37, 99, 235, 0.2);
                    }}
                    .btn-primary:hover {{ 
                        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); 
                        color: white;
                        box-shadow: 0 6px 8px -1px rgba(37, 99, 235, 0.3);
                    }}
                    
                    .jump-btn {{ 
                        height: 24px; 
                        padding: 0 12px; 
                        border-radius: 9999px; 
                        font-size: 12px;
                        background: #eff6ff;
                        color: #2563eb;
                        border: 1px solid #bfdbfe;
                        margin-left: auto;
                        text-decoration: none;
                        display: flex;
                        align-items: center;
                    }}
                    .jump-btn:hover {{
                        background: #2563eb;
                        color: white;
                        border-color: #2563eb;
                    }}

                    .filter-error {{ color: #ef4444; font-size: 12px; padding: 2px 8px; font-weight: 500; }}
                    
                    /* Tooltip styles */
                    .seg-msgtype {{ position: relative; cursor: help; }}
                    .seg-msgtype:hover::after {{
                        content: attr(data-title);
                        position: absolute;
                        bottom: 100%;
                        left: 50%;
                        transform: translateX(-50%);
                        background-color: rgba(17, 24, 39, 0.9);
                        color: #fff;
                        padding: 6px 12px;
                        border-radius: 6px;
                        font-size: 12px;
                        white-space: nowrap;
                        z-index: 20;
                        pointer-events: none;
                        margin-bottom: 8px;
                        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
                        backdrop-filter: blur(4px);
                        border: 1px solid rgba(255,255,255,0.1);
                        font-weight: 500;
                    }}
                    
                    /* Visual Pairing Highlight */
                    .trans-highlight {{
                        background-color: #f0f9ff !important; /* Light Blue */
                        border-left-color: #3b82f6 !important; /* Blue Border */
                        box-shadow: 0 2px 8px rgba(59, 130, 246, 0.15) !important;
                    }}
                    
                    /* Badges and Tree Connectors */
                    .badge-req {{
                        display: inline-block;
                        padding: 1px 4px;
                        background-color: #dbeafe; /* Blue 100 */
                        color: #1e40af; /* Blue 800 */
                        border-radius: 4px;
                        font-size: 11px;
                        font-weight: bold;
                        margin-right: 6px;
                        border: 1px solid #bfdbfe;
                        vertical-align: middle;
                    }}
                    .badge-resp {{
                        display: inline-block;
                        padding: 1px 4px;
                        background-color: #dcfce7; /* Green 100 */
                        color: #166534; /* Green 800 */
                        border-radius: 4px;
                        font-size: 11px;
                        font-weight: bold;
                        margin-right: 6px;
                        border: 1px solid #bbf7d0;
                        vertical-align: middle;
                    }}
                    .tree-connector {{
                        display: inline-block;
                        width: 20px;
                        text-align: right;
                        color: #9ca3af;
                        margin-right: 4px;
                        font-family: monospace;
                        font-weight: bold;
                        user-select: none;
                    }}
                    .resp-container {{
                        margin-left: 0px; /* Aligned with parent */
                        padding-left: 0px;
                        display: flex;
                        align-items: center;
                    }}
                </style>
                <script>
                    let selectedMsgTypes = new Set();
                    
                    function init() {{
                        // Initialize UI components
                        const input = document.getElementById('msgTypeInput');
                        const dropdown = document.getElementById('msgTypeDropdown');
                        
                        if(input && dropdown) {{
                            input.addEventListener('focus', () => {{
                                renderDropdown(input.value);
                                dropdown.style.display = 'block';
                            }});
                            
                            input.addEventListener('input', (e) => {{
                                renderDropdown(e.target.value);
                                dropdown.style.display = 'block';
                            }});
                            
                            document.addEventListener('click', (e) => {{
                                if (!e.target.closest('.msg-type-container')) {{
                                    dropdown.style.display = 'none';
                                }}
                            }});
                        }}

                        renderAbnormalNav();
                    }}
                    
                    // 保留原有的筛选和时间解析逻辑，不做修改
                    function renderDropdown(filterText) {{
                        const dropdown = document.getElementById('msgTypeDropdown');
                        dropdown.innerHTML = '';
                        
                        const lowerFilter = filterText.toLowerCase();
                        const filtered = ALL_MESSAGE_TYPES.filter(mt => 
                            mt.toLowerCase().includes(lowerFilter) && !selectedMsgTypes.has(mt)
                        );
                        
                        if (filtered.length === 0) {{
                            const div = document.createElement('div');
                            div.className = 'msg-type-option';
                            div.style.color = '#9ca3af';
                            div.style.cursor = 'default';
                            div.textContent = '无匹配项';
                            dropdown.appendChild(div);
                            return;
                        }}
                        
                        filtered.forEach(mt => {{
                            const div = document.createElement('div');
                            div.className = 'msg-type-option';
                            div.textContent = mt;
                            div.onclick = () => addMsgType(mt);
                            dropdown.appendChild(div);
                        }});
                    }}
                    
                    function addMsgType(mt) {{
                        selectedMsgTypes.add(mt);
                        renderTags();
                        document.getElementById('msgTypeInput').value = '';
                        document.getElementById('msgTypeDropdown').style.display = 'none';
                        applyFilter();
                    }}
                    
                    function removeMsgType(mt) {{
                        selectedMsgTypes.delete(mt);
                        renderTags();
                        applyFilter();
                    }}
                    
                    function renderTags() {{
                        const container = document.getElementById('selectedTags');
                        container.innerHTML = '';
                        selectedMsgTypes.forEach(mt => {{
                            const tag = document.createElement('div');
                            tag.className = 'tag';
                            tag.innerHTML = `
                                ${mt}
                                <span class="tag-remove" onclick="removeMsgType('${mt}')">×</span>
                            `;
                            container.appendChild(tag);
                        }});
                    }}

                    function applyFilter() {{
                        // 1. Text Filter
                        var qRaw = document.getElementById('filterInput').value.trim();
                        var errBox = document.getElementById('filterError');
                        if (errBox) errBox.textContent = '';
                        
                        var re = null;
                        if (qRaw) {{
                            if (qRaw.startsWith('/') && qRaw.lastIndexOf('/') > 0) {{
                                var last = qRaw.lastIndexOf('/');
                                var body = qRaw.slice(1, last);
                                var flags = qRaw.slice(last + 1) || 'i';
                                try {{ re = new RegExp(body, flags); }} catch (e) {{ re = null; }}
                            }} else {{
                                try {{ re = new RegExp(qRaw, 'i'); }} catch (e) {{ re = null; }}
                            }}
                            if (!re && errBox) errBox.textContent = '正则表达式无效';
                        }}
                        
                        // 2. Time Filter
                        var startTimeStr = document.getElementById('startTime').value.trim();
                        var endTimeStr = document.getElementById('endTime').value.trim();
                        var startTime = startTimeStr ? parseTime(startTimeStr) : null;
                        var endTime = endTimeStr ? parseTime(endTimeStr) : null;
                        var timeOnlyMode = (startTime !== null && startTime < 0) || (endTime !== null && endTime < 0);
                        
                        // 3. Message Type Filter
                        var rows = document.querySelectorAll('.timestamp');
                        for (var i = 0; i < rows.length; i++) {{
                            var r = rows[i];
                            var show = true;
                            
                            // Check Text
                            if (re) {{
                                var text = (r.textContent || '');
                                // 注意：此处已移除对 log-entry pre 的检查，因为原文不在当前页面了
                                if (!re.test(text)) show = false;
                            }}
                            
                            // Check Time
                            if (show && (startTime || endTime)) {{
                                var rowTimestamp = parseInt(r.getAttribute('data-timestamp') || '0', 10);
                                if (rowTimestamp > 0) {{
                                    if (timeOnlyMode) {{
                                        var rowDate = new Date(rowTimestamp);
                                        var rowTimeOfDay = rowDate.getHours() * 3600000 + 
                                                          rowDate.getMinutes() * 60000 + 
                                                          rowDate.getSeconds() * 1000 + 
                                                          rowDate.getMilliseconds();
                                        if (startTime && startTime < 0 && rowTimeOfDay < -startTime) show = false;
                                        if (endTime && endTime < 0 && rowTimeOfDay > -endTime) show = false;
                                    }} else {{
                                        if (startTime && startTime > 0 && rowTimestamp < startTime) show = false;
                                        if (endTime && endTime > 0 && rowTimestamp > endTime) show = false;
                                    }}
                                }}
                            }}
                            
                            // Check Message Type
                            if (show && selectedMsgTypes.size > 0) {{
                                var mtSpan = r.querySelector('.seg-msgtype');
                                if (!mtSpan) {{
                                    show = false;
                                }} else {{
                                    var mt = mtSpan.textContent.trim();
                                    if (!selectedMsgTypes.has(mt)) show = false;
                                }}
                            }}
                            
                            r.style.display = show ? '' : 'none';
                        }}
                    }}
                    
                    function parseTime(str) {{
                        if (!str || !str.trim()) return null;
                        var trimmed = str.trim();
                        trimmed = trimmed.replace('T', ' ');
                        
                        var match1 = trimmed.match(/^(\\d{{4}})-(\\d{{1,2}})-(\\d{{1,2}})\\s+(\\d{{1,2}}):(\\d{{1,2}})(?::(\\d{{1,2}})(?:\\.(\\d{{1,3}}))?)?$/);
                        if (match1) {{
                            var year = parseInt(match1[1], 10);
                            var month = parseInt(match1[2], 10);
                            var day = parseInt(match1[3], 10);
                            var hour = parseInt(match1[4], 10);
                            var minute = parseInt(match1[5], 10);
                            var second = match1[6] ? parseInt(match1[6], 10) : 0;
                            var ms = match1[7] ? parseInt(match1[7], 10) : 0;
                            return new Date(year, month - 1, day, hour, minute, second, ms).getTime();
                        }}
                        
                        var match2 = trimmed.match(/^(\\d{{1,2}})-(\\d{{1,2}})\\s+(\\d{{1,2}}):(\\d{{1,2}})(?::(\\d{{1,2}})(?:\\.(\\d{{1,3}}))?)?$/);
                        if (match2) {{
                            var currentYear = new Date().getFullYear();
                            var month = parseInt(match2[1], 10);
                            var day = parseInt(match2[2], 10);
                            var hour = parseInt(match2[3], 10);
                            var minute = parseInt(match2[4], 10);
                            var second = match2[5] ? parseInt(match2[5], 10) : 0;
                            var ms = match2[6] ? parseInt(match2[6], 10) : 0;
                            return new Date(currentYear, month - 1, day, hour, minute, second, ms).getTime();
                        }}
                        
                        var match3 = trimmed.match(/^(\\d{{1,2}}):(\\d{{1,2}})(?::(\\d{{1,2}})(?:\\.(\\d{{1,3}}))?)?$/);
                        if (match3) {{
                            var hour = parseInt(match3[1], 10);
                            var minute = parseInt(match3[2], 10);
                            var second = match3[3] ? parseInt(match3[3], 10) : 0;
                            var ms = match3[4] ? parseInt(match3[4], 10) : 0;
                            return -(hour * 3600000 + minute * 60000 + second * 1000 + ms);
                        }}
                        return null;
                    }}
                    
                    function clearFilter() {{
                        document.getElementById('filterInput').value = '';
                        document.getElementById('startTime').value = '';
                        document.getElementById('endTime').value = '';
                        selectedMsgTypes.clear();
                        renderTags();
                        applyFilter();
                    }}
                    
                    function filterKey(e) {{ if (e.key === 'Enter') applyFilter(); }}

                    // Visual Pairing Logic
                    // Visual Pairing Logic
                    function highlightTransaction(groupId) {{
                        if (!groupId) return;
                        const elements = document.querySelectorAll(`[data-trans-group="${groupId}"]`);
                        elements.forEach(el => el.classList.add('trans-highlight'));
                    }}

                    function clearHighlight() {{
                        const elements = document.querySelectorAll('.trans-highlight');
                        elements.forEach(el => el.classList.remove('trans-highlight'));
                    }}

                    function focusAbnormalAnchor(anchor) {{
                        if (!anchor) return;
                        const target = document.getElementById(anchor);
                        if (!target) return;
                        document.querySelectorAll('.flash-highlight').forEach(el => el.classList.remove('flash-highlight'));
                        target.classList.add('flash-highlight');
                        target.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                    }}

                    function toggleAbnormalNav() {{
                        document.body.classList.toggle('nav-open');
                    }}

                    function closeAbnormalNav() {{
                        document.body.classList.remove('nav-open');
                    }}

                    function renderAbnormalNav() {{
                        const list = document.getElementById('abnormalList');
                        const empty = document.getElementById('abnormalEmpty');
                        const badge = document.getElementById('abnormalCount');
                        if (badge) badge.textContent = ABNORMAL_ITEMS.length;
                        if (!list) return;
                        list.innerHTML = '';
                        if (!ABNORMAL_ITEMS.length) {{
                            if (empty) empty.style.display = 'block';
                            return;
                        }}
                        if (empty) empty.style.display = 'none';

                        ABNORMAL_ITEMS.forEach((item) => {{
                            const div = document.createElement('div');
                            div.className = 'abnormal-item';
                            const fieldsText = (item.fields || []).join('、') || '未记录字段';
                            div.innerHTML = `
                                <div class="abnormal-item__top">
                                    <span class="abnormal-time">${item.time || ''}</span>
                                    <span class="abnormal-count">×${item.count || 0}</span>
                                </div>
                                <div class="abnormal-item__meta">
                                    <span class="abnormal-type">${item.msgType || '未知报文'}</span>
                                    <span class="abnormal-fields">${fieldsText}</span>
                                </div>
                            `;
                            div.title = (item.details || []).join('\n');
                            div.onclick = () => {{
                                focusAbnormalAnchor(item.anchor);
                                closeAbnormalNav();
                            }};
                            list.appendChild(div);
                        }});
                    }}

                    window.addEventListener('DOMContentLoaded', init);
                </script>
            </head>
            <body>
                <button id="navToggle" class="nav-toggle" onclick="toggleAbnormalNav()">
                    异常报错
                    <span id="abnormalCount" class="nav-badge">0</span>
                </button>
                <div id="sideNav" class="side-nav">
                    <div class="side-nav__header">
                        <div>
                            <div class="side-nav__title">异常报错</div>
                            <div class="side-nav__subtitle">解析中命中的异常转义</div>
                        </div>
                        <button class="btn" onclick="closeAbnormalNav()">收起</button>
                    </div>
                    <div id="abnormalEmpty" class="nav-empty" style="display:none;">暂无异常报错</div>
                    <div id="abnormalList"></div>
                </div>
                <div id="filterBar">
                    <div class="filter-group" style="flex: 1; min-width: 200px;">
                        <span class="filter-label">内容搜索</span>
                        <input id="filterInput" class="crystal-input" style="width: 100%;" type="text" placeholder="支持正则，如 (?=.*INPUT)(?=.*OKAY)" onkeydown="filterKey(event)" />
                    </div>
                    
                    <div class="filter-group" style="flex-direction: column; align-items: flex-start; gap: 6px;">
                        <span class="filter-label">时间范围</span>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <input id="startTime" class="crystal-input" style="width: 180px;" type="datetime-local" step="1" />
                            <span style="color:#9ca3af">-</span>
                            <input id="endTime" class="crystal-input" style="width: 180px;" type="datetime-local" step="1" />
                        </div>
                        <div style="font-size: 11px; color: #6b7280; margin-top: -2px;">
                            点击输入框选择日期时间，或手动输入格式：2024-11-24 19:40:10
                        </div>
                    </div>
                    
                    <div class="filter-group msg-type-container">
                        <span class="filter-label">报文类型</span>
                        <div class="selected-tags" id="selectedTags"></div>
                        <input id="msgTypeInput" class="crystal-input" style="width: 120px;" type="text" placeholder="选择或输入..." />
                        <div id="msgTypeDropdown" class="msg-type-dropdown"></div>
                    </div>
                    
                    <div style="display:flex; gap:8px; margin-left:auto;">
                        <button class="btn btn-primary" onclick="applyFilter()">筛选</button>
                        <button class="btn" onclick="clearFilter()">重置</button>
                    </div>
                    <span id="filterError" class="filter-error"></span>
                </div>
                
                <div id="timestamps">\n""")

                # 写入时间戳索引（BS结构，左侧）
                for index, item in enumerate(log_entries):
                    # 判断是普通日志条目还是事务对象
                    is_transaction = hasattr(item, 'requests') and hasattr(item, 'response')
                    
                    # 准备要渲染的主条目
                    if is_transaction:
                        # 事务模式：主条目是最新请求
                        main_entry = item.latest_request
                        if not main_entry: # 理论上不应发生，除非是孤立回复被错误封装
                            continue
                        retry_count = len(item.requests) - 1
                        has_response = item.response is not None
                    else:
                        # 普通模式
                        main_entry = item
                        retry_count = 0
                        has_response = False # 普通日志不涉及此标记（或者是孤立回复）

                    # 渲染主条目
                    log_id = f"log_{index}"
                    trans_group_id = f"trans_{index}" if is_transaction else ""
                    trans_attr = f'data-trans-group="{trans_group_id}" onmouseover="highlightTransaction(\'{trans_group_id}\')" onmouseout="clearHighlight()"' if is_transaction else ""
                    
                    # 辅助函数：渲染单行 HTML
                    def render_line_content(entry, extra_badges=""):
                        segs = entry.get('segments') or []
                        palette = ['#e3f2fd', '#e8f5e9', '#fff3e0', '#ede7f6', '#e0f7fa']
                        parts = []
                        block_map = {'ts': '', 'dir': '', 'node': '', 'msg_type': '', 'ver': '', 'pid': '', 'pid_msg1': '', 'pid_msg2': ''}
                        for s in segs:
                            k = s.get('kind')
                            if k in block_map and not block_map[k]:
                                block_map[k] = s.get('text', '')
                        nbsp = '&nbsp;'
                        has_dir = bool(block_map['dir'])
                        
                        ts_text_display = block_map['ts'] or nbsp
                        if ts_text_display != nbsp and entry.get('timestamp'):
                            ts_text_display = entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                        
                        if has_dir:
                            dir_text = block_map['dir'] or nbsp
                            node_text = block_map['node'] or nbsp
                            msgtype_text = block_map['msg_type'] or nbsp
                            ver_text = block_map['ver'] or nbsp
                            
                            parts.append(f'<span class="seg-fixed seg-ts" style="background:#e3f2fd;color:#1b1f23;">{ts_text_display}</span>')
                            dlow = str(block_map['dir']).lower()
                            bg_color = '#ede7f6'
                            if dlow.startswith('input'): bg_color = '#d1fae5'
                            elif dlow.startswith('output'): bg_color = '#fee2e2'
                            parts.append(f'<span class="seg-fixed seg-dir" style="background:{bg_color};color:#1b1f23;">{dir_text}</span>')
                            parts.append(f'<span class="seg-fixed seg-node-sm" style="background:#e8f5e9;color:#1b1f23;">{node_text}</span>')
                            parts.append(':')
                            
                            msg_desc = ""
                            for s in segs:
                                if s.get('kind') == 'msg_type':
                                    msg_desc = s.get('description', '')
                                    break
                            
                            title_attr = f'data-title="{html.escape(msg_desc)}:{ver_text}"' if msg_desc else ''
                            parts.append(f'<span class="seg-fixed seg-msgtype-sm seg-msgtype" {title_attr} style="background:#fff3e0;color:#1b1f23;">{msgtype_text}</span>')
                        else:
                            pid_text = (block_map['pid'] or '').strip()
                            node_text = (block_map['node'] or '').strip()
                            parts.append(f'<span class="seg-fixed seg-ts" style="background:#e3f2fd;color:#1b1f23;">{ts_text_display}</span>')
                            if pid_text: parts.append(f'<span class="seg-fixed seg-pid" style="background:#fde68a;color:#1b1f23;">{pid_text}</span>')
                            if node_text: parts.append(f'<span class="seg-fixed seg-node-sm" style="background:#e8f5e9;color:#1b1f23;">{node_text}</span>')
                            msg1 = (block_map['pid_msg1'] or '').strip()
                            msg2 = (block_map['pid_msg2'] or '').strip()
                            if msg1: parts.append(f'<span class="seg-free" style="background:#e3f2fd;color:#1b1f23;">{msg1}</span>')
                            if msg2: parts.append(f'<span class="seg-free" style="background:#e8f5e9;color:#1b1f23;">{msg2}</span>')

                        if has_dir:
                            for s in segs:
                                if s.get('kind') != 'field': continue
                                idx = int(s.get('idx', 0))
                                bg = palette[idx % len(palette)]
                                parts.append(f'<span class="seg-free" style="background:{bg};color:#1b1f23;">{s.get("text", "")}</span>')

                        return ''.join(parts) + extra_badges

                    def append_abnormal_badge(entry, badges=""):
                        if entry.get('escape_hits'):
                            badges = f"{badges} <span class=\"tag tag-abnormal\" title=\"包含异常报错转义\">异常报错</span>"
                        return badges

                    # 构建主行内容
                    extra_badges = ""
                    prefix_html = ""
                    
                    if is_transaction:
                        prefix_html = '<span class="badge-req">发送</span>'
                        if retry_count > 0:
                            extra_badges += f' <span class="tag" style="background:#fee2e2;color:#991b1b;cursor:pointer;" onclick="toggleRetries(\'{log_id}\')">◀ 重试 x{retry_count}</span>'
                        if not has_response:
                            extra_badges += ' <span class="tag" style="background:#f3f4f6;color:#6b7280;">[无回复]</span>'

                    extra_badges = append_abnormal_badge(main_entry, extra_badges)
                    line_html = prefix_html + render_line_content(main_entry, extra_badges)
                    timestamp_ms = int(main_entry['timestamp'].timestamp() * 1000) if main_entry.get('timestamp') else 0
                    
                    # 写入主行
                    f.write(f"""        <div class="timestamp" id="ts_{index}" data-id="{log_id}" data-timestamp="{timestamp_ms}" {trans_attr}>
                                {line_html}
                                <a class="btn btn-primary jump-btn" href="{raw_filename}#{get_raw_anchor(main_entry)}" target="_blank" title="查看原文">查看原文</a>
                            </div>\n""")

                    # 如果是事务且有重试，写入隐藏的重试行
                    if is_transaction and retry_count > 0:
                        f.write(f'<div id="retries_{log_id}" style="display:none; margin-left: 20px; border-left: 2px solid #e5e7eb; padding-left: 10px;">\n')
                        # 遍历旧请求（除了最后一个）
                        for r_idx, req in enumerate(item.requests[:-1]):
                            r_html = render_line_content(req, append_abnormal_badge(req))
                            f.write(f"""            <div class="timestamp" style="border:none; padding: 4px 0;">
                                    <span style="color:#9ca3af; margin-right:8px;">├─ 重试 {r_idx+1}</span>
                                    {r_html}
                                    <a class="btn btn-primary jump-btn" href="{raw_filename}#{get_raw_anchor(req)}" target="_blank" title="查看原文">查看原文</a>
                                </div>\n""")
                        f.write('</div>\n')

                    # 如果有回复，写入回复行 (作为独立行但视觉上连接)
                    if is_transaction and has_response:
                        resp_entry = item.response
                        resp_html = render_line_content(resp_entry, append_abnormal_badge(resp_entry))
                        # 使用 tree-connector 连接
                        f.write(f"""        <div class="timestamp" id="ts_{index}_resp" data-timestamp="{timestamp_ms}" {trans_attr} style="border-top:none; margin-top:-1px; padding-top:4px;">
                                <div class="resp-container">
                                    <span class="tree-connector">└──</span>
                                    <span class="badge-resp">回复</span>
                                    {resp_html}
                                </div>
                                <a class="btn btn-primary jump-btn" href="{raw_filename}#{get_raw_anchor(resp_entry)}" target="_blank" title="查看原文">查看原文</a>
                            </div>\n""")

                f.write("""    </div>
                <script>
                    function toggleRetries(id) {
                        var el = document.getElementById('retries_' + id);
                        if (el) {
                            el.style.display = el.style.display === 'none' ? 'block' : 'none';
                        }
                    }
                </script>
</body>
</html>""")


            # =================================================================
            # 2. 生成原文页面 (Raw Page)
            # =================================================================
            with open(raw_output_path, 'w', encoding='utf-8') as f_raw:
                f_raw.write(f"""<!DOCTYPE html>
            <html>
            <head>
                <title>日志原文 - {filename}</title>
                <style>
                    body {{
                        font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                        margin: 20px;
                        background-color: #f0f2f5;
                        color: #1f2937;
                    }}
                    .log-entry {{
                        margin: 10px 0;
                        padding: 16px;
                        background-color: white;
                        border-radius: 8px;
                        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
                        /* 移除 scroll-margin-top，因为这里不需要避让 sticky header */
                        border: 1px solid #e5e7eb;
                    }}
                    .log-entry pre {{
                        white-space: pre-wrap;
                        word-wrap: break-word;
                        font-family: 'JetBrains Mono', Consolas, monospace;
                        font-size: 13px;
                        line-height: 1.5;
                        margin: 0;
                        padding: 0;
                        color: #374151;
                    }}
                    
                    @keyframes flash-animation {{
                        0% {{ background-color: #fee2e2; box-shadow: 0 0 0 4px rgba(220, 38, 38, 0.6); transform: scale(1.01); z-index: 10; }}
                        20% {{ background-color: #fee2e2; box-shadow: 0 0 0 4px rgba(220, 38, 38, 0.6); transform: scale(1.01); z-index: 10; }}
                        100% {{ background-color: #ffffff; box-shadow: none; transform: scale(1); z-index: 1; }}
                    }}
                    .flash-highlight {{
                        animation: flash-animation 3s ease-out forwards;
                        position: relative;
                        border-color: #dc2626 !important;
                    }}
                </style>
                <script>
                    // 自动跳转并居中显示的核心逻辑
                    window.addEventListener('DOMContentLoaded', function() {{
                        if(location.hash) {{
                            var id = location.hash.replace('#','');
                            var el = document.getElementById(id);
                            if(el) {{
                                // block: 'center' 确保元素在可视区域正中间
                                el.scrollIntoView({{behavior: 'smooth', block: 'center'}});
                                el.classList.add('flash-highlight');
                            }}
                        }}
                    }});
                </script>
            </head>
            <body>
            """)
                
                # 写入纯日志条目 (无按钮，无上下文链接)
                for index, entry in enumerate(raw_log_entries):
                    log_id = f"log_{index}"
                    raw_text = f"{entry['original_line1']}\n{entry['original_line2']}"
                    f_raw.write(f"""    <div class="log-entry" id="{log_id}">
        <pre>{html.escape(raw_text)}</pre>
    </div>\n""")
                
                f_raw.write("</body>\n</html>")

            self.logger.info(f"HTML报告生成完成: {output_path} 及 {raw_output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"生成HTML报告失败: {str(e)}")
            return None

    def _extract_msg_type(self, entry: Dict[str, Any]) -> str:
        try:
            if entry.get('message_type'):
                return str(entry.get('message_type', '')).strip()
            for seg in entry.get('segments', []):
                if seg.get('kind') == 'msg_type':
                    return str(seg.get('text', '')).strip()
        except Exception:
            pass
        return ''

    def _extract_timestamp_text(self, entry: Dict[str, Any]) -> str:
        try:
            ts = entry.get('timestamp')
            if ts:
                return ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            for seg in entry.get('segments', []):
                if seg.get('kind') == 'ts':
                    return str(seg.get('text', '')).strip()
        except Exception:
            pass
        return ''

    def _build_abnormal_item(self, entry: Dict[str, Any], index: int, suffix: str = '') -> Dict[str, Any]:
        hits = entry.get('escape_hits') or []
        fields = sorted({(hit.get('field') or '').strip() for hit in hits if hit.get('field')})
        details = []
        for hit in hits:
            field_name = hit.get('field', '')
            disp = hit.get('display') or hit.get('value') or ''
            details.append(f"{field_name}={disp}")
        return {
            'anchor': f"ts_{index}{suffix}",
            'time': self._extract_timestamp_text(entry),
            'msgType': self._extract_msg_type(entry) or '未知报文',
            'fields': fields,
            'count': len(hits),
            'details': details,
        }

    def _collect_abnormal_items(self, log_entries: List[Any]) -> List[Dict[str, Any]]:
        abnormal_items: List[Dict[str, Any]] = []

        for index, item in enumerate(log_entries):
            is_transaction = hasattr(item, 'requests') and hasattr(item, 'response')
            if is_transaction:
                main_entry = item.latest_request
                if main_entry and main_entry.get('escape_hits'):
                    abnormal_items.append(self._build_abnormal_item(main_entry, index))
                resp_entry = getattr(item, 'response', None)
                if resp_entry and resp_entry.get('escape_hits'):
                    abnormal_items.append(self._build_abnormal_item(resp_entry, index, '_resp'))
            else:
                if item.get('escape_hits'):
                    abnormal_items.append(self._build_abnormal_item(item, index))

        return abnormal_items

    def _parse_filename_info(self, filename: str) -> Dict[str, str]:
        """从文件名中解析分析信息"""
        try:
            # 移除扩展名
            name_without_ext = os.path.splitext(filename)[0]
            parts = name_without_ext.split('_')

            info = {
                'title': filename.replace('_', ' '),
                'filename': filename
            }

            if len(parts) >= 4:
                info['type'] = parts[0]  # 单节点/多节点
                info['factory'] = parts[1]
                info['system'] = parts[2]
                info['scope'] = parts[3]  # 节点信息
                info['timestamp'] = parts[4] if len(parts) > 4 else '未知'

            return info

        except Exception as e:
            self.logger.error(f"解析文件名信息失败: {str(e)}")
            return {'title': filename}