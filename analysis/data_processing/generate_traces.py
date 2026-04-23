def log_entry_to_bytes(nr_event, type, drop_count, address_space, page_index, pid_self, pid_next):
    return (nr_event.to_bytes(8, 'little') +
            type.to_bytes(4, 'little') +
            drop_count.to_bytes(4, 'little') +
            address_space.to_bytes(8, 'little') +
            page_index.to_bytes(8, 'little') +
            pid_self.to_bytes(4, 'little') +
            pid_next.to_bytes(4, 'little'))

with open('ref2.log', 'wb') as f:
    for i in range(200):
        entry_bytes = log_entry_to_bytes(i, 0, 0, 0, i, 1, 1)
        f.write(entry_bytes)
        
with open('pred2.log', 'wb') as f:
    for i in range(200):
        entry_bytes = log_entry_to_bytes(i, 0, 0, 0, i, 1, 1)
        f.write(entry_bytes)