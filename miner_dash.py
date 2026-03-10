#!/usr/bin/env python3
import curses
import time
import os
import json
import sys

STATUS_FILE = 'miner_status.json'

def get_miner_status():
    if not os.path.exists(STATUS_FILE):
        return {"running": False, "hashrate": 0, "shares_found": 0, "cpu_usage": 0, "ram_usage": 0, "uptime": 0}
    try:
        with open(STATUS_FILE, 'r') as f:
            status = json.load(f)
            if time.time() - status.get('last_heartbeat', 0) > 10:
                status['running'] = False
            return status
    except:
        return {"running": False, "hashrate": 0, "shares_found": 0, "cpu_usage": 0, "ram_usage": 0, "uptime": 0}

def draw_dash(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(1)
    stdscr.timeout(1000)
    
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)

    while True:
        stdscr.clear()
        height, width = stdscr.getmaxyx()
        
        status = get_miner_status()
        
        title = " BITCOIN MINER SERVICE DASHBOARD "
        stdscr.addstr(0, max(0, (width - len(title)) // 2), title, curses.A_REVERSE | curses.A_BOLD)
        
        is_running = status.get('running', False)
        status_text = "RUNNING" if is_running else "OFFLINE"
        color = curses.color_pair(1) if is_running else curses.color_pair(2)
        
        stdscr.addstr(2, 2, "Status: ")
        stdscr.addstr(status_text, color | curses.A_BOLD)
        
        stdscr.addstr(4, 2, f"Pool:           {status.get('pool', 'N/A')}")
        stdscr.addstr(5, 2, f"Workers:        {status.get('workers', 0)}")
        
        hashrate = status.get('hashrate', 0)
        h_text = f"{hashrate:.2f} H/s"
        if hashrate > 1000: h_text = f"{hashrate/1000:.2f} KH/s"
        
        stdscr.addstr(7, 2, "Performance:", curses.A_UNDERLINE)
        stdscr.addstr(8, 4, f"Hashrate:     {h_text}", curses.color_pair(3))
        stdscr.addstr(9, 4, f"Shares Found: {status.get('shares_found', 0)}", curses.A_BOLD)
        
        uptime = status.get('uptime', 0)
        m, s = divmod(uptime, 60)
        h, m = divmod(m, 60)
        stdscr.addstr(10, 4, f"Uptime:       {h:02d}:{m:02d}:{s:02d}")
        
        stdscr.addstr(12, 2, "Resources:", curses.A_UNDERLINE)
        cpu = status.get('cpu_usage', 0)
        ram = status.get('ram_usage', 0)
        stdscr.addstr(13, 4, f"CPU Load:     {cpu}%")
        stdscr.addstr(14, 4, f"RAM Use:      {ram}%")
        
        controls = "[Q] Quit Dashboard | (Miner runs in background if started)"
        stdscr.addstr(height - 2, max(0, (width - len(controls)) // 2), controls)
        
        stdscr.refresh()
        c = stdscr.getch()
        if c == ord('q') or c == ord('Q'): break

if __name__ == "__main__":
    curses.wrapper(draw_dash)
