import curses
from dataclasses import dataclass
from datetime import datetime
from cls.dbl import UserManager, User

from typing import List, Optional
from cls.typeclass import pkt,Hello,Host,cmd, ConnectionParam

@dataclass
class User:
    user_id: Optional[int]
    username: str
    email: str
    password_hash: str
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    full_name: Optional[str] = ""


def display_user_list(stdscr, user_manager):
    stdscr.clear()
    stdscr.box()
    users = user_manager.GetList()
    
    # Display header
    stdscr.addstr(0, 2, "User List (Press 'q' to quit)", curses.A_BOLD)
    stdscr.addstr(2, 2, "ID   Full Name          Username         Last Login")
    
    for idx, user in enumerate(users):
        stdscr.addstr(idx + 3, 2, f"{user.user_id:<4} {user.full_name:<20} {user.username:<20} {user.last_login}")
    
    stdscr.refresh()
    
    # Wait for user selection
    while True:
        key = stdscr.getch()
        if key == ord('q') or key==27:
            break
        elif ord('1') <= key <= ord('8'):
            user_id = key - ord('1') + 1
            nw=curses.newwin(10,60,5,20)
            display_user_details(nw, user_manager, user_id)
            del nw
            stdscr.touchwin()
            stdscr.refresh()

def display_user_details(stdscr, user_manager, user_id):
    stdscr.clear()
    stdscr.box()
    stdscr.bkgd(' ', curses.color_pair(1) | curses.A_BOLD | curses.A_REVERSE)
    user = user_manager.Get(user_id)
    
    if user:
        stdscr.addstr(0, 2, f"User Details for {user.username} (Press 'b' to go back)", curses.A_BOLD)
        stdscr.addstr(2, 2, f"ID: {user.user_id}")
        stdscr.addstr(3, 2, f"Full Name: {user.full_name}")
        stdscr.addstr(4, 2, f"Email: {user.email}")
        stdscr.addstr(5, 2, f"Created At: {user.created_at}")
        stdscr.addstr(6, 2, f"Last Login: {user.last_login}")
    else:
        stdscr.addstr(2, 2, "User not found.")
    
    stdscr.refresh()
    
    while True:
        key = stdscr.getch()
        if key == ord('b') or key==27:
            break

def main(stdscr):

    cnn = ConnectionParam(
    	dbname="postgres",
    	user="asgu",
    	password="asgu",
    	host="localhost"
    )

    user_manager = UserManager(cnn)

    display_user_list(stdscr, user_manager)

    user_manager.Close()

if __name__ == "__main__":
    curses.wrapper(main)
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
