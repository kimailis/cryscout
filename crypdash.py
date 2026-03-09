#!/usr/bin/env python3
import curses
import time
import os
import json
import sqlite3
import subprocess
import sys
from db_manager import get_connection, get_stats as get_db_stats

# CONFIGURATION
STATUS_FILE = 'service_status.json'
SIGNAL_FILE = 'service_signal.txt'

def get_service_info():
    if not os.path.exists(STATUS_FILE):
        return {"running": False, "current_task": "Stopped", "cpu_usage": 0, "ram_usage": 0, "logs": []}
    
    try:
        with open(STATUS_FILE, 'r') as f:
            status = json.load(f)
            # Check for stale status
            if time.time() - status.get('last_heartbeat', 0) > 10:
                status['running'] = False
                status['current_task'] = "Not Responding"
            return status
    except:
        return {"running": False, "current_task": "Error", "cpu_usage": 0, "ram_usage": 0, "logs": []}

def get_stats():
    # Mapping for dashboard
    db_stats = get_db_stats()
    return {
        "Total": db_stats['total'],
        "Analyzed": db_stats['analyzed'],
        "Dormant": db_stats['dormant']
    }

def get_potential_targets():
    targets = []
    try:
        conn = get_connection()
        cursor = conn.cursor()
        query = '''
        SELECT address, COALESCE(current_balance, balance, 0) as bal, 
               CASE WHEN potential_weakness != 'None Identified' THEN potential_weakness ELSE accessibility END as reason
        FROM addresses
        WHERE accessibility = 'Unspent/Lost Keys?' OR potential_weakness != 'None Identified'
        ORDER BY rank ASC
        LIMIT 20
        '''
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            targets.append({
                "Address": row[0],
                "Balance": f"{row[1]:.4f} BTC" if row[1] else "N/A",
                "Reason": row[2]
            })
        conn.close()
    except Exception as e:
        targets.append({"Address": "Error", "Balance": "N/A", "Reason": str(e)})
    return targets

def send_signal(sig):
    with open(SIGNAL_FILE, 'w') as f:
        f.write(sig)

def start_service():
    subprocess.Popen([sys.executable, "crypservice.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def reset_analysis():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE addresses SET analyzed = 0")
        conn.commit()
        conn.close()
        return True
    except: pass
    return False

def draw_dashboard(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(1)
    stdscr.timeout(1000)
    
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK) # Running
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)   # Stopped
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Warning
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)  # Info
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)   # Log Header

    mode = "MAIN" 

    while True:
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        
        info = get_service_info()
        stats = get_stats()
        
        title = " CRYPDASH - Research Analysis Monitor "
        stdscr.addstr(0, max(0, (width - len(title)) // 2), title, curses.A_REVERSE | curses.A_BOLD)
        
        if mode == "MAIN":
            is_running = info.get('running', False)
            status_text = "RUNNING" if is_running else "STOPPED"
            color = curses.color_pair(1) if is_running else curses.color_pair(2)
            if info.get('current_task') == "Not Responding":
                color = curses.color_pair(3)
                status_text = "NOT RESPONDING"
                
            stdscr.addstr(2, 2, "Service Status: ")
            stdscr.addstr(status_text, color | curses.A_BOLD)
            stdscr.addstr(f" (PID: {info.get('pid', 'N/A')})")
            stdscr.addstr(3, 2, f"Current Task:   {info.get('current_task', 'N/A')}")
            
            stdscr.addstr(5, 2, "Progress Overview:", curses.A_UNDERLINE)
            stdscr.addstr(6, 4, f"Total Addresses Tracked: {stats['Total']}")
            stdscr.addstr(7, 4, f"Addresses Analyzed:      {stats['Analyzed']}")
            stdscr.addstr(8, 4, f"Dormant Targets:         {stats['Dormant']}")
            
            if stats['Total'] > 0:
                percent = (stats['Analyzed'] / stats['Total']) * 100
                bar_len = min(width - 20, 50)
                filled = int((percent / 100) * bar_len)
                bar = "[" + "=" * filled + " " * (bar_len - filled) + "]"
                stdscr.addstr(10, 4, f"Progress: {bar} {percent:.1f}%")
            
            cpu_val = info.get('cpu_usage', 0)
            ram_val = info.get('ram_usage', 0)
            stdscr.addstr(12, 2, "System Constraints:", curses.A_UNDERLINE)
            stdscr.addstr(13, 4, f"CPU Load: {cpu_val}%")
            stdscr.addstr(14, 4, f"RAM Use:  {ram_val}%")
            
            controls = "[S] Start | [T] Stop | [R] Restart | [A] Re-Analyze | [P] Potential | [Q] Quit"
            stdscr.addstr(height - 2, max(0, (width - len(controls)) // 2), controls, curses.A_BOLD)

        elif mode == "POTENTIAL":
            stdscr.addstr(2, 2, "Potential Targets (High Probability of Access):", curses.A_UNDERLINE | curses.color_pair(4))
            targets = get_potential_targets()
            if not targets:
                stdscr.addstr(4, 4, "No targets identified yet.")
            else:
                stdscr.addstr(4, 4, f"{'Address':<40} {'Balance':<15} {'Reason'}")
                stdscr.addstr(5, 4, "-" * (width - 8))
                for i, target in enumerate(targets):
                    if i + 6 >= height - 12: break # Leave room for logs
                    stdscr.addstr(i + 6, 4, f"{target['Address']:<40} {target['Balance']:<15} {target['Reason']}")
            
            controls = "[B] Back to Main | [A] Re-Analyze | [Q] Quit"
            stdscr.addstr(height - 2, max(0, (width - len(controls)) // 2), controls, curses.A_BOLD)

        # LIVE LOG PANE (Visible in both modes)
        log_start_y = height - 12
        stdscr.addstr(log_start_y, 2, " Live Activity Log ", curses.color_pair(5) | curses.A_BOLD)
        log_msgs = info.get('logs', [])
        for i, msg in enumerate(log_msgs):
            if log_start_y + 1 + i < height - 2:
                stdscr.addstr(log_start_y + 1 + i, 4, msg[:width-6])

        stdscr.refresh()
        
        c = stdscr.getch()
        if c == ord('q') or c == ord('Q'): break
        elif c == ord('s') or c == ord('S'):
            if not info.get('running', False): start_service()
        elif c == ord('t') or c == ord('T'): send_signal('STOP')
        elif c == ord('r') or c == ord('R'):
            send_signal('STOP')
            time.sleep(1)
            start_service()
        elif c == ord('a') or c == ord('A'):
            reset_analysis()
        elif c == ord('p') or c == ord('P'): mode = "POTENTIAL"
        elif c == ord('b') or c == ord('B'): mode = "MAIN"

if __name__ == "__main__":
    curses.wrapper(draw_dashboard)
