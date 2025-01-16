# tmux commands

## With proper tmux.conf modifications

```shell
tmux
tmux <session_name>
tmux new -s <session_name>

# rename session
Ctrl + Q + <$>

# detach from session
Ctrl + Q + D

# reattach to a session
tmux a -t <session_name>

# new session from an existing session
Ctrl + Q + :new

# kill session
Ctrl + Q + <+>

# new window
Ctrl + Q + C
# kill window
Ctrl + Q + <->
# kill pane
Ctrl + Q + <=>
# rename window
Ctrl + Q + <,>

## Move around windows
Shift + <directional_arrows>

Ctrl + Q + <windows_number>

## List windows
Ctrl + Q + W


## Split windows (create sub-pane)
# vertically
Ctrl + Q + %
# horizontally
Ctrl + Q + <\">

## Move around panes
Ctrl + Q + <directional_arrows>

## enlarge current pane (to resize it just re type it)
Ctrl + Q + Z
## Send current pane to new window
Ctrl + Q + !
## Send current pane to be a new pane on target window (could be selected a wind numb or name)
Ctrl + Q + S
## Bring pane from another window to current window
Ctrl + Q + J
## reorganize pane layouts
Ctrl + Q + Spacebar

## kill tmux server (all)
tmux Kill-Server


## Moving around mode
# enter in it (press "q" to exit)
Ctrl + Q + <[>
# move up
Ctrl + U
# move down
Ctrl + D
# search forward
/<key_word>
##hit 'n' for next occurrency match
## hit 'N' for previous occurrence
# search backwards
?<key_word>

# copy-mode (while in moving mode) select text
V
# from now on is vim syntax to move around and copy
# copy previously selected text
Y
```