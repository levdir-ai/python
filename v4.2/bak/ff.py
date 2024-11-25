import curses

def login_window(stdscr):
    # Clear screen
    stdscr.clear()
    
    # Get screen height and width
    height, width = stdscr.getmaxyx()
    
    # Create a window for the login box
    login_win = curses.newwin(10, 40, height//2 - 5, width//2 - 20)
    login_win.box()
    
    # Add text to the window
    login_win.addstr(1, 1, "Login", curses.A_BOLD)
    login_win.addstr(3, 1, "Username: ")
    login_win.addstr(5, 1, "Password: ")
    
    # Refresh the window to show the text
    login_win.refresh()
    
    # Create a subwindow for user input
    username_win = login_win.subwin(1, 20, height//2 - 2, width//2 - 10)
    password_win = login_win.subwin(1, 20, height//2, width//2 - 10)
    
    # Enable cursor for user input
    curses.curs_set(1)
    
    # Get user input
    username = username_win.getstr().decode('utf-8')
    password = password_win.getstr().decode('utf-8')
    
    # Disable cursor after input
    curses.curs_set(0)
    
    # Clear the screen and display the entered username and password
    stdscr.clear()
    stdscr.addstr(height//2, width//2 - 10, f"Username: {username}")
    stdscr.addstr(height//2 + 1, width//2 - 10, f"Password: {password}")
    stdscr.refresh()
    
    # Wait for user to press a key before exiting
    stdscr.getch()

# Initialize curses
curses.wrapper(login_window)
