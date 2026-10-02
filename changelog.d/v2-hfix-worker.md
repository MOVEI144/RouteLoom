Run the ESP-IDF crypto worker at priority 1, above IDLE, so IDF's idle hook
does not consume its protocol deadline budget. The default priority-1 Owner
and crypto worker share preemptive time slices. Worker stack size, mailbox
capacity, authentication and protocol deadlines are unchanged.
