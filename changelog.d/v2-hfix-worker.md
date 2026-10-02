Run the ESP-IDF crypto worker at its Owner's priority (1 by default), so it
progresses alongside forwarding and above IDLE. Wait for crypto completion
or protocol deadlines instead of polling its result, including when a
blocked authority carrier awaits the link job. A full TX scheduler no longer
publishes an elapsed advertisement deadline that keeps Owner runnable.
Detach and replace the singleton worker's completion context safely.
Worker stack size, mailbox capacity, authentication and protocol deadlines
are unchanged.
