#!/usr/bin/env python3
import time
import os
import json
import sqlite3
import subprocess
import sys
from db_manager import get_connection, get_stats as get_db_stats

try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    CURSES_AVAILABLE = False

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
            if time.time() - status.get('last_heartbeat', 0) > 30:
                status['running'] = False
                status['current_task'] = "Not Responding"
            return status
    except:
        return {"running": False, "current_task": "Error", "cpu_usage": 0, "ram_usage": 0, "logs": []}

def get_stats():
    # Mapping for dashboard
    db_stats = get_db_stats()
    
    # Add worker counts if possible
    active_workers = 0
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM worker_status WHERE last_heartbeat > datetime('now', '-30 seconds')")
        active_workers = c.fetchone()[0]
        conn.close()
    except: pass
    
    return {
        "Total": db_stats['total'],
        "Analyzed": db_stats['analyzed'],
        "Dormant": db_stats['dormant'],
        "Recovered": db_stats['keys_recovered'],
        "Workers": active_workers
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
        ORDER BY bal DESC
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

def get_recovered_keys():
    keys = []
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT address, privkey_hex, method FROM recovered_keys ORDER BY id DESC LIMIT 20")
        rows = c.fetchall()
        for r in rows:
            keys.append({
                "Address": r[0],
                "Key": r[1][:26] + "..." if r[1] else "Unknown",
                "Method": r[2]
            })
        conn.close()
    except Exception as e:
        keys.append({"Address": "Error", "Key": "N/A", "Method": str(e)})
    return keys

def send_signal(sig):
    with open(SIGNAL_FILE, 'w') as f:
        f.write(sig)

def start_service():
    # Execute detached
    try:
        subprocess.Popen([sys.executable, "cryshub.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except:
        subprocess.Popen([sys.executable, "cryshub.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)   # Running
    curses.init_pair(2, curses.COLOR_RED, -1)     # Stopped
    curses.init_pair(3, curses.COLOR_YELLOW, -1)  # Warning
    curses.init_pair(4, curses.COLOR_CYAN, -1)    # Info
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE) # Log Header
    curses.init_pair(6, curses.COLOR_MAGENTA, -1) # Keys found

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
            stdscr.addstr(9, 4, f"Keys Recovered:          {stats['Recovered']}", curses.color_pair(1) if stats['Recovered']>0 else curses.A_NORMAL)
            stdscr.addstr(10, 4, f"Active Workers:          {stats['Workers']}", curses.color_pair(4) if stats['Workers']>0 else curses.A_NORMAL)
            
            percent = (stats['Analyzed'] / stats['Total']) * 100
            bar_len = min(width - 20, 50)
            filled = int((percent / 100) * bar_len)
            bar = "[" + "=" * filled + " " * (bar_len - filled) + "]"
            stdscr.addstr(11, 4, f"Progress: {bar} {percent:.1f}%")
            
            # LIVE WORKER FLEET SECTION
            worker_list = info.get('workers_detailed', [])
            stdscr.addstr(13, 2, "Live Worker Fleet:", curses.A_UNDERLINE | curses.color_pair(4))
            if not worker_list:
                stdscr.addstr(14, 4, "No active workers detected.")
            else:
                stdscr.addstr(14, 4, f"{'Worker ID':<20} {'Current Task / Activity':<40} {'CPU':<6} {'RAM'}")
                stdscr.addstr(15, 4, "-" * (width - 10))
                for i, w in enumerate(worker_list):
                    if i + 16 >= height - 12: break
                    y = 16 + i
                    wid = w.get('id', 'N/A')
                    task = w.get('task', 'N/A')
                    cpu = f"{w.get('cpu', 0):.1f}%"
                    ram = f"{w.get('ram', 0):.1f}%"
                    
                    # Highlight 'STRIKING' workers
                    style = curses.A_BOLD if "STRIKING" in task.upper() or "FLAGGED" in task.upper() else curses.A_NORMAL
                    stdscr.addstr(y, 4, f"{wid[:19]:<20} {task[:39]:<40} {cpu:<6} {ram}", style)

            controls = "[S] Start | [T] Stop | [R] Restart | [A] Re-Analyze | [P] Potential | [K] Keys | [Q] Quit"
            stdscr.addstr(height - 2, max(0, (width - len(controls)) // 2), controls, curses.A_BOLD)

        elif mode == "POTENTIAL":
            stdscr.addstr(2, 2, "Potential Targets (High Probability of Access):", curses.A_UNDERLINE | curses.color_pair(4))
            targets = get_potential_targets()
            if not targets:
                stdscr.addstr(4, 4, "No targets identified yet.")
            else:
                stdscr.addstr(4, 4, f"{'Address':<35} {'Balance':<15} {'Reason'}")
                stdscr.addstr(5, 4, "-" * (width - 8))
                for i, target in enumerate(targets):
                    if i + 6 >= height - 12: break # Leave room for logs
                    stdscr.addstr(i + 6, 4, f"{target['Address'][:34]:<35} {target['Balance']:<15} {target['Reason'][:30]}")
            
            controls = "[B] Back to Main | [Q] Quit"
            stdscr.addstr(height - 2, max(0, (width - len(controls)) // 2), controls, curses.A_BOLD)

        elif mode == "KEYS":
            stdscr.addstr(2, 2, "RECOVERED KEYS (SUCCESS!):", curses.A_UNDERLINE | curses.color_pair(1))
            keys = get_recovered_keys()
            if not keys:
                stdscr.addstr(4, 4, "No keys recovered yet. Keep scanning...", curses.color_pair(3))
            else:
                stdscr.addstr(4, 4, f"{'Address':<35} {'Private Key':<30} {'Method'}")
                stdscr.addstr(5, 4, "-" * (width - 8))
                for i, k in enumerate(keys):
                    if i + 6 >= height - 12: break
                    stdscr.addstr(i + 6, 4, f"{k['Address'][:34]:<35} {k['Key'][:29]:<30} {k['Method'][:25]}", curses.color_pair(1))
            
            controls = "[B] Back to Main | [Q] Quit"
            stdscr.addstr(height - 2, max(0, (width - len(controls)) // 2), controls, curses.A_BOLD)

        # LIVE LOG PANE (Visible in all modes)
        log_start_y = height - 10
        if log_start_y > 10:  # Ensures screen is tall enough for logs
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
            time.sleep(1.5)
            start_service()
        elif c == ord('a') or c == ord('A'):
            reset_analysis()
        elif c == ord('p') or c == ord('P'): mode = "POTENTIAL"
        elif c == ord('k') or c == ord('K'): mode = "KEYS"
        elif c == ord('b') or c == ord('B'): mode = "MAIN"

def draw_text_dashboard():
    """Fallback text dashboard for environments without curses."""
    print("CRYPDASH - Text Mode Monitor (Press Ctrl+C to quit)\n")
    mode = "MAIN"
    last_logs_len = 0
    
    while True:
        info = get_service_info()
        stats = get_stats()
        
        # We only print the full status periodically or when logs change
        os.system('cls' if os.name == 'nt' else 'clear')
        
        is_running = info.get('running', False)
        status_text = "RUNNING" if is_running else "STOPPED"
        if info.get('current_task') == "Not Responding":
            status_text = "NOT RESPONDING"
            
        print("===" * 20)
        print(f"Service Status: {status_text} (PID: {info.get('pid', 'N/A')})")
        print(f"Current Task:   {info.get('current_task', 'N/A')}")
        print("---")
        print(f"Total Addresses Tracked: {stats['Total']}")
        print(f"Addresses Analyzed:      {stats['Analyzed']}")
        print(f"Dormant Targets:         {stats['Dormant']}")
        print(f"Keys Recovered:          {stats['Recovered']}")
        print(f"Active Workers:          {stats['Workers']}")
        print("---")
        print("Live Worker Fleet:")
        worker_list = info.get('workers_detailed', [])
        if not worker_list:
            print("  No active workers.")
        else:
            print(f"  {'Worker ID':<20} {'Current Task / Activity':<40} {'CPU':<6} {'RAM'}")
            for w in worker_list:
                wid = w.get('id', 'N/A')
                task = w.get('task', 'N/A')
                cpu = f"{w.get('cpu', 0):.1f}%"
                ram = f"{w.get('ram', 0):.1f}%"
                print(f"  {wid[:19]:<20} {task[:39]:<40} {cpu:<6} {ram}")
        
        print(f"\nOverall CPU: {info.get('cpu_usage', 0)}%  |  RAM Use: {info.get('ram_usage', 0)}%")
        print("===" * 20)
        print(" Live Activity Log:")
        
        logs = info.get('logs', [])
        for p in logs[-15:]:
            print(f"  {p}")
            
        print("\nControls: [S] Start | [T] Stop | [R] Restart | [Q] Quit  (Press keys without pressing Enter)")
        
        # Interactive delay loop to catch keystrokes without curses
        for _ in range(20):
            if os.name == 'nt':
                import msvcrt
                if msvcrt.kbhit():
                    c = msvcrt.getch().lower()
                    if c == b'q':
                        return
                    elif c == b's' and not info.get('running', False):
                        start_service()
                    elif c == b't':
                        send_signal('STOP')
                    elif c == b'r':
                        send_signal('STOP')
                        time.sleep(1.5)
                        start_service()
                    break # exit the delay loop to refresh
            else:
                import select
                if select.select([sys.stdin], [], [], 0)[0]:
                    c = sys.stdin.read(1).lower()
                    if c == 'q':
                        return
                    elif c == 's' and not info.get('running', False):
                        start_service()
                    elif c == 't':
                        send_signal('STOP')
                    break
            time.sleep(0.1)

if __name__ == "__main__":
    if CURSES_AVAILABLE:
        try:
            curses.wrapper(draw_dashboard)
        except curses.error:
            # If the terminal size is too small or messes up, fallback
            draw_text_dashboard()
    else:
        try:
            draw_text_dashboard()
        except KeyboardInterrupt:
            print("\nExiting dashboard.")
